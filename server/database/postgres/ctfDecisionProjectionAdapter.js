'use strict';
// Caller owns the CTF transaction. No pool/provider/identity callback is accepted.
const {validateDecisionEvent,buildDecisionReceipt,validateDecisionReceipt}=require('../../services/ctfDecisionProjectionContract');
const {resolveAttemptRegistrationLocator}=require('./ctfAttemptRegistrationLocator');
const {stageDigest}=require('../../agent-runtime/ctfStageJudge');
const one=async(c,sql,args)=>(await c.query(sql,args)).rows[0];
const drift=()=>{throw new Error('CTF_DECISION_PROJECTION_DRIFT');};
async function applyCtfDecisionProjection(client,rawEvent){
 const event=validateDecisionEvent(rawEvent),d=event.decision,f=event.facts,e=event.evidence,s=event.command.scope;
 await client.query('SELECT pg_advisory_xact_lock(1886610804,44)');
 const cursor=await one(client,'SELECT * FROM ctf.projection_cursor WHERE singleton FOR UPDATE');if(!cursor?.initialized)throw new Error('CTF_PROJECTION_UNINITIALIZED');
 const prior=await one(client,'SELECT * FROM ctf.projection_receipts WHERE operation_id=$1 OR sequence=$2',[d.decisionId,event.sequence]);
 if(prior){if(prior.operation_id!==d.decisionId||String(prior.sequence)!==event.sequence||prior.command_hash!==event.commandHash)drift();return validateDecisionReceipt(event,prior.canonical_result,prior.result_hash);}
 if(BigInt(event.sequence)!==BigInt(cursor.applied_sequence)+1n)throw new Error('CTF_PROJECTION_OUT_OF_ORDER');
 const scopes=(await client.query('SELECT * FROM ctf.projection_scopes WHERE scope_key=ANY($1::text[])',[['global','stage:'+d.stageId,'owner:'+d.ownerId]])).rows;
 const scope=new Map(scopes.map(x=>[x.scope_key,x]));
 if(String(scope.get('global')?.revision)!==s.globalRevision||String(scope.get('stage:'+d.stageId)?.revision)!==s.stageRevision||String(scope.get('owner:'+d.ownerId)?.owner_generation)!==d.ownerGeneration)drift();
 const participant=await one(client,'SELECT * FROM ctf.ctf_participants WHERE id=$1 AND user_id=$2 FOR UPDATE',[d.participantId,d.ownerId]);
 const progress=await one(client,'SELECT * FROM ctf.ctf_progress WHERE id=$1 AND participant_id=$2 AND stage_id=$3 FOR UPDATE',[d.progressId,d.participantId,d.stageId]);
 const stage=await one(client,'SELECT * FROM ctf.ctf_stages WHERE id=$1 FOR UPDATE',[d.stageId]);
 if(!stage||stageDigest(stage)!==d.stageDigest)drift();
 if(!participant||participant.is_active!==1||!progress||progress.status!=='in_progress')drift();
 for(const [column,key] of [['attempts_count','attemptsCount'],['failed_attempts','failedAttempts'],['successful_attempts','successfulAttempts'],['hints_used','hintsUsed'],['hint_penalty_total','hintPenaltyTotal']])if(progress[column]!==f[key])drift();
 if(await one(client,'SELECT run_id FROM ctf.ctf_judgments WHERE run_id=$1 OR decision_id=$2',[d.runId,d.decisionId]))drift();
 const locator=await resolveAttemptRegistrationLocator(client,s,f.teachingSessionToken);
 const attempt=await one(client,`INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,ai_response,was_successful,response_time,session_id,technique_tag,technique_confidence,blocked,block_reason,payload_hash,attempt_timestamp,decision_id,admission_operation_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,[d.participantId,d.stageId,f.attemptNumber,e.payload,e.visibleResponse,d.accepted?1:0,f.responseTime,locator,e.techniqueTag,f.techniqueConfidence,d.verdict==='blocked'?1:0,d.verdict==='blocked'?'identity_adaptive_conflict':null,e.payloadHash,d.authorizedAt,d.decisionId,d.admissionId]);
 const failed=f.failedAttempts+(!d.accepted&&!f.failedCounterIncrement?1:0),successful=f.successfulAttempts+(d.accepted?1:0);
 const techniques=JSON.parse(progress.techniques_used||'[]');if(!Array.isArray(techniques)||techniques.some(x=>typeof x!=='string'))drift();if(d.accepted&&!techniques.includes(e.techniqueTag))techniques.push(e.techniqueTag);
 await client.query(`UPDATE ctf.ctf_progress SET status=$1,completed_at=$2,completion_time=$3,final_payload=$4,successful_attempts=$5,failed_attempts=$6,techniques_used=$7,updated_at=$8,authorized_level_score=$9,authorized_decision_id=$11 WHERE id=$10`,[d.accepted?'completed':'in_progress',d.accepted?d.authorizedAt:null,d.completionTimeMs,d.accepted?e.payload:progress.final_payload,successful,failed,JSON.stringify(techniques),d.authorizedAt,d.accepted?f.stageScore:null,d.progressId,d.accepted?d.decisionId:null]);
 if(f.techniqueAdded&&(await client.query('INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag,first_used_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[d.participantId,d.stageId,e.techniqueTag,d.authorizedAt])).rowCount!==1)drift();
 if(f.payloadAdded&&(await client.query('INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id,first_won_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',[d.stageId,e.payloadHash,e.normalizedPayload,d.participantId,d.authorizedAt])).rowCount!==1)drift();
 if(f.matchedPayloadHash!==null&&(await client.query('UPDATE ctf.ctf_payload_blocklist SET hit_count=hit_count+1 WHERE stage_id=$1 AND payload_hash=$2',[d.stageId,f.matchedPayloadHash])).rowCount!==1)drift();
 await client.query('INSERT INTO ctf.ctf_judgments(run_id,attempt_id,participant_id,stage_id,progress_id,stage_digest,verdict,accepted,metadata,created_at,decision_id,authority_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,\'identity-ctf-v1\')',[d.runId,attempt.id,d.participantId,d.stageId,d.progressId,d.stageDigest,d.verdict,d.accepted?1:0,JSON.stringify({rubricVersion:e.judgment.rubricVersion,judgeVersion:e.judgment.judgeVersion,provider:e.judgment.provider,model:e.judgment.model,evidenceSummary:JSON.parse(e.judgeReceipt).evidenceSummary,guardian:e.guardian,stale:false,evidenceHash:event.evidenceHash,factsHash:event.factsHash,authorizedAt:d.authorizedAt}),d.authorizedAt,d.decisionId]);
 if(d.accepted)await client.query("INSERT INTO ctf.ctf_events(event_type,participant_id,stage_id,event_data,is_public,timestamp) VALUES('stage_complete',$1,$2,$3,1,$4)",[d.participantId,d.stageId,JSON.stringify({stage_name:f.stageName,username:participant.username,completion_time:Number(d.completionTimeMs),attempts:f.attemptNumber}),d.authorizedAt]);
 await client.query('UPDATE ctf.ctf_participants SET last_activity=GREATEST(last_activity,$1::timestamptz) WHERE id=$2',[d.authorizedAt,d.participantId]);
 // Dedicated function preserves ranking rules while using authorization score
 // snapshots for new completions and existing stage score for legacy progress.
 await client.query('SELECT ctf.refresh_authorized_leaderboard($1::timestamptz)',[d.authorizedAt]);
 const receipt=buildDecisionReceipt(event,{decisionId:d.decisionId,runId:d.runId,admissionId:d.admissionId,evidenceHash:event.evidenceHash,factsHash:event.factsHash,attemptId:String(attempt.id),participantId:d.participantId,progressId:d.progressId,stageId:d.stageId,accepted:d.accepted,verdict:d.verdict,status:d.accepted?'completed':'in_progress',attemptsCount:f.attemptsCount,failedAttempts:failed,successfulAttempts:successful,hintsUsed:f.hintsUsed,hintPenaltyTotal:d.hintPenaltyTotal,completedAt:d.accepted?d.authorizedAt:null,completionTimeMs:d.completionTimeMs,techniqueAdded:f.techniqueAdded,payloadAdded:f.payloadAdded,payloadHitIncremented:f.matchedPayloadHash!==null});
 await client.query("INSERT INTO ctf.projection_receipts(sequence,operation_id,kind,command_hash,canonical_result,result_hash) VALUES($1,$2,'decision',$3,$4,$5)",[event.sequence,d.decisionId,event.commandHash,receipt.canonicalResult,receipt.resultHash]);
 await client.query('UPDATE ctf.projection_cursor SET applied_sequence=$1,last_operation_id=$2 WHERE singleton',[event.sequence,d.decisionId]);
 return receipt;
}
module.exports={applyCtfDecisionProjection};
