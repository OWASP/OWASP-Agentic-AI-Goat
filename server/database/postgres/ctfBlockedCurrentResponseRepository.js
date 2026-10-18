'use strict';
const {hasAdminLevel}=require('../../middleware/postgresAdminAuth');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {createHash}=require('node:crypto');
const {validateCtfLifecycleCommand,canonicalCtfJson}=require('../../services/ctfLifecycleCommands');
const {validateCtfProjectionResult}=require('../../services/ctfProjectionResults');
const unavailable=()=>{throw Object.assign(Error('CTF blocked publication unavailable'),{code:'CTF_BLOCKED_PUBLICATION_UNAVAILABLE',statusCode:409});};
// Default closed. Later complete activation supplies a canonical finalized
// checkpoint predicate; bootstrap PREPARED alone must never enable this reader.
function createCtfBlockedCurrentResponseRepository(pool,{readiness=async()=>false}={}){
 return Object.freeze({readAuthorized({runId,session},options){
  session=structuredClone(session);
  if(typeof session?.rawToken!=='string'||!session.rawToken.isWellFormed()||!session.rawToken.length||session.rawToken.length>16384)unavailable();
  return withCtfTransaction(pool,async client=>{
  const claim=(await client.query('SELECT * FROM identity.ctf_predefense_claims WHERE run_id=$1',[runId])).rows[0];
  if(!claim||String(claim.owner_id)!==String(session.actorId)||String(claim.session_id)!==String(session.sessionId))unavailable();
  try{await client.query('SELECT identity.lock_ctf_blocked_publication($1,$2,$3,$4)',[runId,session.actorId,session.sessionId,createHash('sha256').update(session.rawToken).digest('hex')]);}
  catch(error){if(error.code==='28000')throw Object.assign(Error('SESSION_REVOKED'),{code:'SESSION_REVOKED'});throw error;}
  const b=claim.input.binding;
  const scopes={};for(const [key,value] of [['global','global'],['stage','stage:'+b.stageId],['owner','owner:'+b.ownerId]])scopes[key]=(await client.query('SELECT * FROM identity.ctf_authority WHERE scope_key=$1',[value])).rows[0];
  const owner=(await client.query('SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1',['["CTF","'+b.ownerId+'"]'])).rows[0];
  const run=(await client.query('SELECT * FROM graph_runtime.runs WHERE run_id=$1',[runId])).rows[0];
  if(!Object.values(scopes).every(x=>x?.lifecycle_state==='ready')||String(scopes.global.revision)!==b.globalRevision||String(scopes.stage.revision)!==b.stageRevision||String(scopes.owner.revision)!==b.ownerRevision||String(scopes.owner.owner_generation)!==b.ownerGeneration||owner?.generation!==b.ownerGeneration||!run||run.owner_key!=='["CTF","'+b.ownerId+'"]'||String(run.generation)!==b.ownerGeneration||!['running','completed'].includes(run.status))unavailable();
  const current=(await client.query(`SELECT p.active,p.banned,pr.status,pr.progress_id::text,pr.participant_id::text,st.stage_number,st.stage_digest,st.active AS stage_active,st.feedback_mode,cfg.enabled,cfg.visible_to_students,cfg.time_limit_ms,extract(epoch FROM clock_timestamp()-p.registered_at)*1000 AS elapsed_ms,u.role,u.admin_level
 FROM identity.ctf_participant_bindings p JOIN identity.ctf_progress_bindings pr ON pr.owner_id=p.owner_id AND pr.owner_generation=p.owner_generation AND pr.participant_id=p.participant_id JOIN identity.ctf_stage_bindings st ON st.stage_id=pr.stage_id CROSS JOIN identity.ctf_config_binding cfg JOIN identity.users u ON u.id=p.owner_id
 WHERE p.owner_id=$1 AND p.owner_generation=$2 AND st.stage_id=$3 AND cfg.singleton`,[b.ownerId,b.ownerGeneration,b.stageId])).rows[0];
  if(!current||!current.active||current.banned||scopes.owner.banned||!current.stage_active||current.stage_digest!==b.stageDigest||current.progress_id!==b.progressId||current.participant_id!==b.participantId||current.status!=='in_progress'||!current.enabled||(!current.visible_to_students&&!hasAdminLevel(current))||(String(current.time_limit_ms)!=='-1'&&Number(current.elapsed_ms)>Number(current.time_limit_ms)))unavailable();
  const consumed=(await client.query('SELECT * FROM identity.ctf_predefense_consumptions WHERE run_id=$1',[runId])).rows[0];
  const outcome=(await client.query('SELECT outcome FROM identity.ctf_predefense_outcomes WHERE run_id=$1',[runId])).rows[0]?.outcome;
  const guarded=(await client.query('SELECT * FROM identity.ctf_predefense_blocked_commands WHERE run_id=$1',[runId])).rows[0];
  if(!consumed||consumed.final_disposition==='continue'||!outcome||!guarded||guarded.operation_id!==claim.blocked_operation_id||consumed.operation_id!==claim.admission_operation_id)unavailable();
  let blocked,admissionReceipt;
  for(const [operationId,kind] of [[claim.admission_operation_id,'admit_attempt'],[claim.blocked_operation_id,'record_blocked_attempt']]){
   const row=(await client.query('SELECT * FROM identity.ctf_outbox WHERE operation_id=$1',[operationId])).rows[0];
   if(!row||row.state!=='applied'||row.kind!==kind||String(row.actor_id)!==b.ownerId||String(row.session_id)!==b.sessionId)unavailable();
   const command=validateCtfLifecycleCommand({...JSON.parse(row.canonical_command),commandHash:row.command_hash});const {commandHash,...content}=command;
   if(canonicalCtfJson(content)!==row.canonical_command||command.operationId!==operationId||command.actorId!==b.ownerId||['ownerId','ownerGeneration','globalRevision','stageRevision','participantId','progressId','stageId'].some(key=>command.scope[key]!==b[key]))unavailable();
   const receipt=validateCtfProjectionResult(command,String(row.sequence),row.canonical_result,row.result_hash).value;
   if(receipt.outcome!=='applied')unavailable();
   if(kind==='admit_attempt'){if(command.body.failed!==consumed.failed)unavailable();admissionReceipt=receipt;}
   if(kind==='record_blocked_attempt'){if(row.command_hash!==guarded.command_hash||command.body.admissionOperationId!==claim.admission_operation_id||receipt.data.admissionOperationId!==claim.admission_operation_id||command.body.matchedPayloadHash!==consumed.matched_payload_hash||command.body.attemptNumber!==admissionReceipt?.data.attemptNumber)unavailable();blocked={command,receipt};}
  }
  if(await readiness(client)!==true)unavailable();
  return{current:true,runId,ownerId:b.ownerId,sessionId:b.sessionId,participantId:b.participantId,stageId:b.stageId,stageNumber:current.stage_number,feedbackMode:current.feedback_mode,disposition:consumed.final_disposition,languageStatus:outcome.languageStatus,...blocked};
 },options);}});
}
module.exports={createCtfBlockedCurrentResponseRepository};
