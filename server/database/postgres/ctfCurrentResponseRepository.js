'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {validateCtfLifecycleCommand,canonicalCtfJson}=require('../../services/ctfLifecycleCommands');
const {validateCtfProjectionResult}=require('../../services/ctfProjectionResults');
const {stageDigest}=require('../../agent-runtime/ctfStageJudge');
const fail=()=>{throw Object.assign(Error('CTF operation no longer projects current state'),{code:'CTF_RESPONSE_STALE',statusCode:409});};
function createCtfCurrentResponseRepository({identityPool,ctfPool}){
 async function read({operationId,session},options){
  if(!session||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||!session.rawToken.length||session.rawToken.length>16384)fail();
  return withCtfTransaction(identityPool,async c=>{
   await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ WRITE');
   const r=(await c.query('SELECT identity.read_ctf_user_operation($1,$2,$3,$4) AS operation',[operationId,session.actorId,session.sessionId,createHash('sha256').update(session.rawToken).digest('hex')])).rows[0]?.operation;
   if(!r||r.state!=='applied'||r.actorId!==String(session.actorId)||r.sessionId!==String(session.sessionId))fail();
   const command=validateCtfLifecycleCommand({...JSON.parse(r.canonicalCommand),commandHash:r.commandHash});const {commandHash,...content}=command;
   if(command.operationId!==operationId||canonicalCtfJson(content)!==r.canonicalCommand)fail();
   const receipt=validateCtfProjectionResult(command,r.sequence,r.canonicalResult,r.resultHash).value;if(receipt.outcome!=='applied')fail();
   const ev=(await c.query('SELECT owner_generation_after::text FROM identity.ctf_outbox WHERE operation_id=$1',[operationId])).rows[0];if(!ev)fail();
   const global=(await c.query("SELECT * FROM identity.ctf_authority WHERE scope_key='global'")).rows[0];if(!global||global.lifecycle_state!=='ready')fail();
   const {scope,body,kind}=command;
   const localMutation=['catalog_mutation','blocklist_clear'].includes(kind)&&scope.stageId!==null&&!(kind==='catalog_mutation'&&(body.action==='delete'||Object.hasOwn(body.fields,'stage_order')||Object.hasOwn(body.fields,'is_active')));
   const expectedGlobal=BigInt(scope.globalRevision)+(scope.ownerId===null&&!localMutation?1n:0n);
   if(String(global.revision)!==String(expectedGlobal))fail();
   const config=(await c.query('SELECT * FROM identity.ctf_config_binding WHERE singleton')).rows[0];if(!config)fail();
   let owner=null,participant=null,progress=null,stage=null;
   if(scope.ownerId){
    owner=(await c.query(`SELECT a.*,u.username,g.generation::text AS graph_generation FROM identity.ctf_authority a JOIN identity.users u ON a.scope_key='owner:'||u.id JOIN graph_runtime.owners g ON g.owner_key='["CTF","'||u.id||'"]' WHERE u.id=$1 AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id) AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b WHERE b.owner_key=g.owner_key)`,[scope.ownerId])).rows[0];
    if(!owner||owner.lifecycle_state!=='ready'||String(owner.owner_generation)!==ev.owner_generation_after||owner.graph_generation!==ev.owner_generation_after)fail();
    participant=(await c.query('SELECT * FROM identity.ctf_participant_bindings WHERE owner_id=$1 AND owner_generation=$2',[scope.ownerId,ev.owner_generation_after])).rows[0]||null;
    if(['register','start','hint'].includes(kind)&&receipt.outcome==='applied'){
     if(!participant||!participant.active||participant.banned||owner.banned||!config.enabled||String(participant.participant_id)!==String(kind==='register'?receipt.data.participantId:scope.participantId))fail();
     if(!config.visible_to_students){const admin=(await c.query("SELECT 1 FROM identity.users WHERE id=$1 AND (role IN ('admin','super_admin') AND COALESCE(admin_level,0)>=1)",[session.actorId])).rows[0];if(!admin)fail();}
    }
   }
   if(scope.stageId){stage=(await c.query('SELECT * FROM identity.ctf_stage_bindings WHERE stage_id=$1',[scope.stageId])).rows[0]||null;
    const stageAuthority=(await c.query("SELECT * FROM identity.ctf_authority WHERE scope_key=$1",['stage:'+scope.stageId])).rows[0];if(!stageAuthority||stageAuthority.lifecycle_state!=='ready'||String(stageAuthority.revision)!==String(BigInt(scope.stageRevision)+(localMutation?1n:0n)))fail();
    if(['start','hint'].includes(kind)){
     if(!stage||!stage.active)fail();
     progress=(await c.query('SELECT * FROM identity.ctf_progress_bindings WHERE owner_id=$1 AND owner_generation=$2 AND stage_id=$3',[scope.ownerId,ev.owner_generation_after,scope.stageId])).rows[0];
     if(!progress||String(progress.participant_id)!==scope.participantId||String(progress.progress_id)!==String(kind==='start'?receipt.data.progressId:scope.progressId))fail();
     if(kind==='hint'&&(progress.hints_used!==receipt.data.hintsUsed||progress.hint_penalty_total!==receipt.data.hintPenaltyTotal))fail();
    }
   }
   if(['ban','unban'].includes(kind)&&owner.banned!==(kind==='ban'))fail();
   if(kind==='owner_remove'&&participant?.active)fail();
   if(kind==='catalog_mutation'){const currentStage=(await c.query('SELECT * FROM identity.ctf_stage_bindings WHERE stage_id=$1',[receipt.data.stageId])).rows[0];if(!currentStage||currentStage.applied_operation_id!==operationId)fail();}
   if(kind==='blocklist_clear'){const remaining=(await c.query('SELECT EXISTS(SELECT 1 FROM identity.ctf_adaptive_memory WHERE kind=$1 AND ($2::bigint IS NULL OR stage_id=$2)) AS present',[body.memory,scope.stageId])).rows[0];if(!remaining||remaining.present)fail();}
   return {command,receipt,config,owner,participant,progress,stage};
  },options);
 }
 return Object.freeze({read,async readStage({stageId,digest},options){
  return withCtfTransaction(ctfPool,async c=>{await c.query('SET TRANSACTION READ ONLY');const row=(await c.query("SELECT s.*,COALESCE(tc.objective_text, '') AS teaching_objective FROM ctf.ctf_stages s LEFT JOIN ctf.ctf_stage_teaching_content tc ON tc.stage_id=s.id WHERE s.id=$1",[stageId])).rows[0];if(!row)fail();const {teaching_objective,...stage}=row;if(stageDigest(stage)!==digest)fail();return {...stage,teaching_objective};},options);
 }});
}
module.exports={createCtfCurrentResponseRepository};
