'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {validateRegistrationLocator}=require('./ctfAttemptRegistrationLocator');
const {inputDocument}=require('../../services/ctfPredefenseContract');
const {stageDigest}=require('../../agent-runtime/ctfStageJudge');
const sha=x=>createHash('sha256').update(x).digest('hex');
const fail=code=>{throw Object.assign(Error(code),{code});};
async function authenticateCtfRead(client,session){
 if(!session||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||!session.rawToken.length||session.rawToken.length>16384)fail('SESSION_REVOKED');
 await client.query('SELECT id FROM identity.users WHERE id=$1 FOR UPDATE',[session.actorId]);
 await client.query('SELECT id FROM identity.user_sessions WHERE id=$1 AND user_id=$2 FOR UPDATE',[session.sessionId,session.actorId]);
 const row=(await client.query(`SELECT u.id FROM identity.users u JOIN identity.user_sessions s ON s.user_id=u.id
 WHERE u.id=$1 AND s.id=$2 AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) AND s.is_active=1 AND s.expires_at>clock_timestamp() AND s.session_token_hash=$3
 AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id)
 AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b WHERE b.owner_key='["CTF","'||u.id||'"]')`,[session.actorId,session.sessionId,sha(session.rawToken)])).rows[0];
 if(!row)fail('SESSION_REVOKED');
}
function createCtfPredefenseRequestLoader({identityPool,ctfPool,request=null}){
 // First-request data is copied once. It confers no authority and is ignored
 // whenever the durable claim exists. Raw prompts never enter graph metadata.
 const captured=request===null?null:structuredClone(request);
 if(captured)captured.registrationToken=validateRegistrationLocator(captured.registrationToken??null);
 if(captured&&(!/^[1-9][0-9]*$/.test(String(captured.stageId))||typeof captured.payload!=='string'||!captured.payload.isWellFormed()||captured.payload.includes('\0')||Buffer.byteLength(captured.payload)>16384))throw TypeError('Invalid initial CTF request');
 return async function loadRequest({runId,session},options){
  const original=structuredClone(session);
  const loaded=await withCtfTransaction(identityPool,async client=>{
   await authenticateCtfRead(client,original);
   const prior=(await client.query('SELECT * FROM identity.ctf_predefense_claims WHERE run_id=$1',[runId])).rows[0];
   if(prior){
    if(String(prior.owner_id)!==String(original.actorId)||String(prior.session_id)!==String(original.sessionId))fail('CTF_PREDEFENSE_ORIGINAL_SESSION_REQUIRED');
    const input=JSON.parse(prior.canonical_input),validated=inputDocument(input,prior.stage_snapshot);
    if(validated.canonicalDocument!==prior.canonical_input||validated.documentHash!==prior.input_hash||input.binding.runId!==runId)fail('CTF_PREDEFENSE_STORED_INPUT_INVALID');
    const stage=Object.fromEntries(JSON.parse(prior.stage_snapshot));
    if(stageDigest(stage)!==input.binding.stageDigest)fail('CTF_PREDEFENSE_STORED_STAGE_INVALID');
    const locator=(await client.query('SELECT registration_token FROM identity.ctf_predefense_registration_locators WHERE run_id=$1',[runId])).rows[0];
    return{binding:input.binding,stage,payload:input.payload,registrationToken:locator?.registration_token??null};
   }
   if(!captured||captured.runId!==runId)fail('CTF_PREDEFENSE_REQUEST_UNAVAILABLE');
   const row=(await client.query(`SELECT g.revision::text AS global_revision,s.revision::text AS stage_revision,o.revision::text AS owner_revision,o.owner_generation::text,p.participant_id::text,pr.progress_id::text,st.stage_id::text,st.stage_digest
 FROM identity.ctf_authority g CROSS JOIN identity.ctf_authority s CROSS JOIN identity.ctf_authority o
 JOIN identity.ctf_participant_bindings p ON o.scope_key='owner:'||p.owner_id AND p.owner_generation=o.owner_generation
 JOIN identity.ctf_progress_bindings pr ON pr.owner_id=p.owner_id AND pr.owner_generation=p.owner_generation AND pr.participant_id=p.participant_id
 JOIN identity.ctf_stage_bindings st ON st.stage_id=pr.stage_id
 JOIN graph_runtime.runs r ON r.run_id=$3 AND r.owner_key='["CTF","'||p.owner_id||'"]' AND r.generation=o.owner_generation AND r.status='running'
 WHERE g.scope_key='global' AND s.scope_key='stage:'||st.stage_id AND p.owner_id=$1 AND st.stage_id=$2 AND g.lifecycle_state='ready' AND s.lifecycle_state='ready' AND o.lifecycle_state='ready' AND p.active AND NOT p.banned AND NOT o.banned AND st.active AND pr.status='in_progress'`,[original.actorId,captured.stageId,runId])).rows[0];
   if(!row)fail('CTF_PREDEFENSE_REQUEST_UNAVAILABLE');
   return{binding:{ownerId:String(original.actorId),sessionId:String(original.sessionId),runId,ownerGeneration:row.owner_generation,globalRevision:row.global_revision,stageRevision:row.stage_revision,ownerRevision:row.owner_revision,participantId:row.participant_id,progressId:row.progress_id,stageId:row.stage_id,stageDigest:row.stage_digest},payload:captured.payload,registrationToken:captured.registrationToken};
  },options);
  if(loaded.stage)return loaded;
  // Identity lease has ended before the isolated CTF stage read. The later
  // atomic claim revalidates all provisional bindings and digest after this gap.
  const stage=await withCtfTransaction(ctfPool,async client=>{const row=(await client.query('SELECT * FROM ctf.ctf_stages WHERE id=$1',[loaded.binding.stageId])).rows[0];if(!row||stageDigest(row)!==loaded.binding.stageDigest)fail('CTF_PREDEFENSE_STAGE_CHANGED');return row;},options);
  return{...loaded,stage};
 };
}
module.exports={createCtfPredefenseRequestLoader,authenticateCtfRead};
