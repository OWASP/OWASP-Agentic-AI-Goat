'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {readCtfDecisionEvent}=require('./ctfDecisionProjectionRepository');
const {formatCtfCurrentAttemptResponse}=require('../../services/ctfCurrentAttemptResponse');
const fail=()=>{throw Object.assign(Error('CTF current attempt response unavailable'),{code:'CTF_ATTEMPT_RESPONSE_UNAVAILABLE',statusCode:409});};
function createCtfCurrentAttemptResponseRepository(pool){
 return Object.freeze({read({decisionId,session},options){
  session=structuredClone(session);
  if(typeof decisionId!=='string'||!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(decisionId)||typeof session?.rawToken!=='string'||!session.rawToken.isWellFormed()||!session.rawToken.length||session.rawToken.length>16384||session.rawToken.includes('\0'))fail();
  const params=[decisionId,session.actorId,session.sessionId,createHash('sha256').update(session.rawToken).digest('hex')];
  return withCtfTransaction(pool,async client=>{
   // Authenticates original session and locks current global/stage/owner scope.
   // No second pool lease. Runtime must authorize LAST again after private build.
   const grant=(await client.query('SELECT identity.authorize_ctf_current_publication($1,$2,$3,$4) AS publication',params)).rows[0]?.publication;
   if(grant?.decisionId!==decisionId||typeof grant.currentCompletion!=='boolean')fail();
   const row=(await client.query("SELECT * FROM identity.ctf_outbox WHERE operation_id=$1 AND kind='decision'",[decisionId])).rows[0];
   if(!row||row.state!=='applied'||String(row.actor_id)!==String(session.actorId)||String(row.session_id)!==String(session.sessionId))fail();
   const event=await readCtfDecisionEvent(client,row);
   if(event.decision.decisionId!==decisionId||event.decision.accepted!==grant.currentCompletion||event.evidenceHash!==grant.evidenceHash)fail();
   const metadata=(await client.query(`SELECT rd.canonical_diagnostics,rd.diagnostics_hash FROM identity.ctf_response_diagnostics rd
 JOIN identity.ctf_decision_proposals p ON p.proposal_id=rd.proposal_id AND p.evidence_hash=rd.evidence_hash
 JOIN identity.ctf_decision_inputs i ON i.admission_id=rd.admission_id AND i.input_hash=rd.input_hash AND i.admission_id=p.admission_operation_id AND i.run_id=p.run_id AND i.owner_id=p.owner_id AND i.session_id=p.session_id
 WHERE rd.proposal_id=$1 AND rd.evidence_hash=$2 AND p.owner_id=$3 AND p.session_id=$4`,[event.decision.proposalId,event.evidenceHash,session.actorId,session.sessionId])).rows[0];
   if(!metadata)fail();
   const config=(await client.query('SELECT show_technique_feedback,hint_gating_attempts FROM identity.ctf_config_binding WHERE singleton')).rows[0];
   if(!config)fail();
   // A clear deletes its selected kind. Shared clear_revision also increments
   // on clearing the OTHER kind; equality would wrongly hide retained rows.
   const techniques=(await client.query("SELECT technique_tag FROM identity.ctf_adaptive_memory WHERE kind='technique' AND owner_id=$1 AND owner_generation=$2 AND stage_id=$3 ORDER BY memory_id LIMIT 257",[event.decision.ownerId,event.decision.ownerGeneration,event.decision.stageId])).rows.map(x=>x.technique_tag);
   return formatCtfCurrentAttemptResponse({event,receipt:{canonicalResult:row.canonical_result,resultHash:row.result_hash},diagnostics:{canonicalDiagnostics:metadata.canonical_diagnostics,diagnosticsHash:metadata.diagnostics_hash},config:{showFeedback:config.show_technique_feedback,hintGatingAttempts:config.hint_gating_attempts},usedTechniques:techniques});
  },options);
 }});
}
module.exports={createCtfCurrentAttemptResponseRepository};
