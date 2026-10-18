'use strict';
const {createHash}=require('node:crypto');
const {hasAdminLevel}=require('../../middleware/postgresAdminAuth');
const {withCtfTransaction}=require('./ctfLifecycleRepository');

const stale=(statusCode=409)=>{throw Object.assign(Error('CTF practice no longer available'),{code:'CTF_PRACTICE_STALE',statusCode});};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);

// A read-only lease. Only public stage copy crosses this boundary; the model
// caller cannot obtain the real system prompt, success criterion or secret.
function createCtfFixedPracticeSnapshot({identityPool,ctfPool}){
 if(typeof identityPool?.connect!=='function'||typeof ctfPool?.connect!=='function'||identityPool===ctfPool)throw TypeError('Separate CTF practice stores required');
 const issued=new WeakMap();
 async function identity(session,stageId,signal){
  return withCtfTransaction(identityPool,async c=>{
   await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
   const actor=(await c.query(`SELECT u.id,u.role,COALESCE(u.admin_level,0) AS admin_level
    FROM identity.users u JOIN identity.user_sessions s ON s.user_id=u.id
    WHERE u.id=$1 AND s.id=$2 AND s.session_token_hash=$3 AND u.is_active=1 AND s.is_active=1
    AND s.expires_at>clock_timestamp() AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())
    AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id)
    AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b WHERE b.owner_key='["CTF","'||u.id||'"]')`,[session.actorId,session.sessionId,createHash('sha256').update(session.rawToken).digest('hex')])).rows[0];
   if(!actor)stale(401);
   const scope=(await c.query(`SELECT g.revision::text AS global_revision,g.applied_sequence::text,
    o.revision::text AS owner_revision,o.owner_generation::text,s.revision::text AS stage_revision,
    p.participant_id::text,pr.progress_id::text,st.stage_digest,st.stage_order
    FROM identity.ctf_authority g CROSS JOIN identity.ctf_authority o CROSS JOIN identity.ctf_authority s
    JOIN identity.ctf_participant_bindings p ON p.owner_id=$1 AND p.owner_generation=o.owner_generation
    JOIN identity.ctf_progress_bindings pr ON pr.owner_id=p.owner_id AND pr.owner_generation=p.owner_generation AND pr.participant_id=p.participant_id
    JOIN identity.ctf_stage_bindings st ON st.stage_id=pr.stage_id
    JOIN graph_runtime.owners go ON go.owner_key='["CTF","'||p.owner_id||'"]' AND go.generation=p.owner_generation
    CROSS JOIN identity.ctf_config_binding cfg
    WHERE g.scope_key='global' AND o.scope_key='owner:'||p.owner_id AND s.scope_key='stage:'||st.stage_id
    AND st.stage_id=$2 AND g.lifecycle_state='ready' AND o.lifecycle_state='ready' AND s.lifecycle_state='ready'
    AND p.active AND NOT p.banned AND NOT o.banned AND st.active AND pr.status='in_progress'
    AND cfg.singleton AND cfg.enabled AND (cfg.visible_to_students OR $3::boolean)
    AND (cfg.time_limit_ms=-1 OR extract(epoch FROM clock_timestamp()-p.registered_at)*1000<=cfg.time_limit_ms)`,[session.actorId,stageId,hasAdminLevel(actor)])).rows[0];
   if(!scope)stale(403);
   return Object.freeze({actorId:String(actor.id),...scope});
  },{signal});
 }
 async function publicStage(binding,stageId,signal){
  return withCtfTransaction(ctfPool,async c=>{
   await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
   const cursor=(await c.query('SELECT initialized,applied_sequence::text FROM ctf.projection_cursor WHERE singleton')).rows[0];
   if(!cursor?.initialized||cursor.applied_sequence!==binding.applied_sequence)stale();
   const row=(await c.query(`SELECT s.id,s.stage_name,s.stage_description,s.ai_guardian_name,s.ai_guardian_personality,s.stage_order,
    p.id::text AS participant_id,pr.id::text AS progress_id
    FROM ctf.ctf_stages s JOIN ctf.ctf_progress pr ON pr.stage_id=s.id
    JOIN ctf.ctf_participants p ON p.id=pr.participant_id
    WHERE s.id=$1 AND s.is_active=1 AND p.id=$2 AND p.user_id=$3 AND p.is_active=1
    AND pr.id=$4 AND pr.status='in_progress'`,[stageId,binding.participant_id,binding.actorId,binding.progress_id])).rows[0];
   if(!row||String(row.stage_order)!==String(binding.stage_order))stale();
   return Object.freeze({id:row.id,stageName:row.stage_name,stageDescription:row.stage_description,
    guardianName:row.ai_guardian_name,guardianPersonality:row.ai_guardian_personality});
  },{signal});
 }
 return Object.freeze({async capture({session,stageId,signal}){
  if(!Number.isSafeInteger(stageId)||stageId<1||stageId>2147483647)throw TypeError('Invalid practice stage');
  if(!session||!/^\d+$/.test(String(session.actorId))||!/^\d+$/.test(String(session.sessionId))||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||session.rawToken.length<1||session.rawToken.length>16384)throw TypeError('Canonical practice session required');
  const saved=structuredClone(session);
  const before=await identity(saved,stageId,signal),stage=await publicStage(before,stageId,signal),after=await identity(saved,stageId,signal);
  if(!same(before,after))stale();
  const lease=Object.freeze({});issued.set(lease,Object.freeze({session:saved,stageId,binding:after,stage}));
  return Object.freeze({lease,stage});
 },async revalidate({lease,signal}){
  const saved=issued.get(lease);if(!saved)stale();
  const before=await identity(saved.session,saved.stageId,signal),stage=await publicStage(before,saved.stageId,signal),after=await identity(saved.session,saved.stageId,signal);
  if(!same(before,after)||!same(after,saved.binding)||!same(stage,saved.stage))stale();
  return true;
 }});
}
module.exports={createCtfFixedPracticeSnapshot};
