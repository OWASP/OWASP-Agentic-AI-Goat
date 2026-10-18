'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const fail=()=>{throw Object.assign(Error('CTF canonical request unavailable'),{code:'CTF_REQUEST_UNAVAILABLE'});};
const id=x=>typeof x==='string'&&/^[1-9][0-9]*$/.test(x)&&BigInt(x)<=2147483647n;
function createCtfAuthorityRequestRepository(pool){return Object.freeze({async read({session,ownerId=null,stageId=null,admin=false},options){
 if(!session||!id(session.actorId)||!id(session.sessionId)||typeof session.rawToken!=='string'||!session.rawToken.length||session.rawToken.length>16384||!session.rawToken.isWellFormed()||ownerId!==null&&!id(ownerId)||stageId!==null&&!id(stageId)||typeof admin!=='boolean'||!admin&&ownerId!==null&&ownerId!==session.actorId)fail();
 return withCtfTransaction(pool,async c=>{
  await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
  const actor=(await c.query(`SELECT u.id,u.username,u.email FROM identity.users u JOIN identity.user_sessions s ON s.user_id=u.id WHERE u.id=$1 AND s.id=$2 AND s.session_token_hash=$3 AND u.is_active=1 AND s.is_active=1 AND s.expires_at>clock_timestamp() AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) AND (NOT $4::boolean OR (u.role IN ('admin','super_admin') AND COALESCE(u.admin_level,0)>=1)) AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id) AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b WHERE b.owner_key='["CTF","'||u.id||'"]')`,[session.actorId,session.sessionId,createHash('sha256').update(session.rawToken).digest('hex'),admin])).rows[0];if(!actor)fail();
  const global=(await c.query("SELECT * FROM identity.ctf_authority WHERE scope_key='global'")).rows[0];if(!global||global.lifecycle_state!=='ready')fail();
  const config=(await c.query('SELECT * FROM identity.ctf_config_binding WHERE singleton')).rows[0];if(!config)fail();
  let owner=null,participant=null,stage=null,progress=null;
  if(ownerId){owner=(await c.query(`SELECT u.id,COALESCE(g.generation,0)::text AS generation,a.owner_generation::text AS authority_generation FROM identity.users u LEFT JOIN graph_runtime.owners g ON g.owner_key='["CTF","'||u.id||'"]' LEFT JOIN identity.ctf_authority a ON a.scope_key='owner:'||u.id WHERE u.id=$1 AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id) AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b WHERE b.owner_key='["CTF","'||u.id||'"]')`,[ownerId])).rows[0];if(!owner||owner.authority_generation!==null&&owner.authority_generation!==owner.generation)fail();participant=(await c.query('SELECT * FROM identity.ctf_participant_bindings WHERE owner_id=$1 AND owner_generation=$2',[ownerId,owner.generation])).rows[0]||null;}
  if(stageId){stage=(await c.query(`SELECT b.*,a.revision::text AS authority_revision,a.lifecycle_state AS authority_state FROM identity.ctf_stage_bindings b JOIN identity.ctf_authority a ON a.scope_key='stage:'||b.stage_id WHERE b.stage_id=$1`,[stageId])).rows[0];if(!stage||stage.authority_state!=='ready')fail();if(owner)progress=(await c.query('SELECT * FROM identity.ctf_progress_bindings WHERE owner_id=$1 AND owner_generation=$2 AND stage_id=$3',[ownerId,owner.generation,stageId])).rows[0]||null;}
  return structuredClone({actor,global,config,owner,participant,stage,progress});
 },options);
 }});}
module.exports={createCtfAuthorityRequestRepository};
