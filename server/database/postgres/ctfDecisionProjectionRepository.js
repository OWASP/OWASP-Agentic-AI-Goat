'use strict';
// Transaction-client helpers for identity only. Caller releases this client
// before acquiring the CTF store; never invoke from a CTF mutation callback.
const {createHash}=require('node:crypto');
const {validateDecisionEvent,validateDecisionReceipt}=require('../../services/ctfDecisionProjectionContract');
async function readCtfDecisionEvent(client,outbox){
 const row=(await client.query(`SELECT o.sequence::text,o.canonical_command,o.command_hash,f.canonical_facts,f.facts_hash,p.canonical_evidence,d.evidence_hash,
 jsonb_build_object('decisionId',d.decision_id,'proposalId',d.proposal_id,'runId',d.run_id,'admissionId',p.admission_operation_id,'ownerId',d.owner_id::text,'sessionId',d.session_id::text,'ownerGeneration',d.owner_generation::text,'participantId',d.participant_id::text,'progressId',d.progress_id::text,'stageId',d.stage_id::text,'stageDigest',d.stage_digest,'accepted',d.accepted,'verdict',d.verdict,'authorizedAt',to_char(d.authorized_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'completionTimeMs',d.completion_time_ms::text,'hintPenaltyTotal',d.hint_penalty_total) AS decision
 FROM identity.ctf_outbox o JOIN identity.ctf_decisions d ON d.decision_id=o.decision_id AND d.sequence=o.sequence
 JOIN identity.ctf_decision_proposals p ON p.proposal_id=d.proposal_id AND p.run_id=d.run_id AND p.owner_id=d.owner_id AND p.session_id=d.session_id AND p.evidence_hash=d.evidence_hash
 JOIN identity.ctf_decision_inputs i ON i.admission_id=p.admission_operation_id AND i.run_id=d.run_id AND i.owner_id=d.owner_id AND i.session_id=d.session_id
 JOIN identity.ctf_attempt_admissions a ON a.operation_id=i.admission_id AND a.owner_id=d.owner_id AND a.owner_generation=d.owner_generation AND a.participant_id=d.participant_id AND a.progress_id=d.progress_id AND a.stage_id=d.stage_id
 JOIN identity.ctf_decision_projection_facts f ON f.decision_id=d.decision_id AND f.sequence=d.sequence AND f.evidence_hash=d.evidence_hash
 WHERE o.operation_id=$1 AND o.sequence=$2 AND o.kind='decision' AND o.actor_id=d.owner_id AND o.session_id=d.session_id AND o.operation_id=d.decision_id`,[outbox.operation_id,String(outbox.sequence)])).rows[0];
 if(!row)throw new Error('CTF_DECISION_FACTS_RECOVERY_REQUIRED');
 if(row.command_hash!==outbox.command_hash||row.canonical_command!==outbox.canonical_command)throw new Error('CTF_DECISION_OUTBOX_MISMATCH');
 return validateDecisionEvent({sequence:row.sequence,encoding:'postgres-jsonb-text-v1',canonicalCommand:row.canonical_command,commandHash:row.command_hash,canonicalFacts:row.canonical_facts,factsHash:row.facts_hash,canonicalEvidence:row.canonical_evidence,evidenceHash:row.evidence_hash,decision:row.decision});
}
async function acknowledgeCtfDecision(client,event,receipt){
 const value=validateDecisionReceipt(event,receipt.canonicalResult,receipt.resultHash);
 return (await client.query('SELECT * FROM identity.ack_ctf_decision_projection($1,$2,$3,$4,$5)',[event.decision.decisionId,event.sequence,event.commandHash,value.canonicalResult,value.resultHash])).rows[0];
}
async function claimCtfProjectionInput(client,{actorId,sessionId,rawToken,canonicalInput,inputHash,stageSnapshot}){
 if(typeof rawToken!=='string'||!rawToken.isWellFormed()||!rawToken.length||rawToken.length>16384)throw new TypeError('Canonical admitted session required');
 const tokenHash=createHash('sha256').update(rawToken,'utf8').digest('hex');
 return (await client.query('SELECT identity.claim_ctf_projection_input($1,$2,$3,$4,$5,$6) AS capture',[actorId,sessionId,tokenHash,canonicalInput,inputHash,stageSnapshot])).rows[0].capture;
}
function createCtfProjectionDecisionRepository(pool){
 const base=require('./ctfDecisionRepository').createCtfDecisionRepository(pool);
 const {withCtfTransaction}=require('./ctfLifecycleRepository');
 return Object.freeze({...base,capture({session,canonicalInput,inputHash,stageSnapshot},options){return withCtfTransaction(pool,client=>claimCtfProjectionInput(client,{...session,canonicalInput,inputHash,stageSnapshot}),options);}});
}
module.exports={readCtfDecisionEvent,acknowledgeCtfDecision,claimCtfProjectionInput,createCtfProjectionDecisionRepository};
