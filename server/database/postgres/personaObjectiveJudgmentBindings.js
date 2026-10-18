'use strict';
// Required-persona judgment bindings. Callbacks perform only existing identity SQL
// on the supplied client. Never run a model or another store inside a callback.
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
function fail(code='PERSONA_EVALUATION_UNAVAILABLE'){return Object.assign(Error('Persona evaluation authority unavailable'),{code});}
function id(v){if(!Number.isSafeInteger(v)||v<1)throw fail();return v;}
function uuid(v){if(typeof v!=='string'||!UUID.test(v))throw fail();return v.toLowerCase();}
function version(v){if(typeof v!=='string'||!/^[1-9][0-9]*$/.test(v)||BigInt(v)>9223372036854775807n)throw fail();return v;}
function createPersonaObjectiveJudgmentBindings({pool,personaAuthority}={}){
 if(typeof pool?.connect!=='function'||typeof pool?.query!=='function'||typeof personaAuthority?.capture!=='function')throw TypeError('Candidate dependencies required');
 const tokens=new WeakMap();let readiness;
 const assertReady=()=>readiness ||= pool.query(`SELECT
   EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='workshop_platform'
     AND table_name='objective_judgments' AND column_name='persona_authority_required'
     AND data_type='boolean' AND is_nullable='NO' AND column_default='false') AS marker,
   to_regclass('workshop_platform.persona_evaluation_bindings') IS NOT NULL AS bindings,
   to_regprocedure('workshop_platform.bind_persona_evaluation(integer,uuid,uuid,uuid,uuid,bigint,bigint,integer,uuid,text,bigint)') IS NOT NULL AS binder,
   COALESCE(has_table_privilege(current_user,to_regclass('workshop_platform.persona_evaluation_bindings'),'SELECT'),false) AS can_read,
   COALESCE(has_table_privilege(current_user,to_regclass('workshop_platform.persona_evaluation_bindings'),'INSERT,UPDATE,DELETE,TRUNCATE'),false) AS cannot_write,
   COALESCE(has_function_privilege(current_user,to_regprocedure('workshop_platform.bind_persona_evaluation(integer,uuid,uuid,uuid,uuid,bigint,bigint,integer,uuid,text,bigint)'),'EXECUTE'),false) AS can_bind,
   COALESCE(has_function_privilege(current_user,to_regprocedure('workshop_platform.check_persona_evaluation_binding()'),'EXECUTE'),false) AS cannot_check,
   COALESCE(has_function_privilege(current_user,to_regprocedure('workshop_platform.immutable_persona_evaluation_binding()'),'EXECUTE'),false) AS cannot_mutate`).then(({rows})=>{
     const row=rows[0];
     if(!row?.marker||!row.bindings||!row.binder||!row.can_read||row.cannot_write
         ||!row.can_bind||row.cannot_check||row.cannot_mutate)throw fail();
     return Object.freeze({ready:true});
   });
 const coordinates=input=>Object.freeze({userId:id(input.scope.platformOwnerId),launchId:uuid(input.scope.launchId),scenarioId:uuid(input.scope.scenarioId),generation:id(input.scope.generation),platformSessionId:id(input.scope.platformSessionId),personaId:id(input.personaId),personaSessionId:uuid(input.sessionId),role:input.role,authorityVersion:version(input.authorityVersion)});
 function seal(value){if(!['customer','merchant','admin'].includes(value.role))throw fail();const scope={platformOwnerId:value.userId,launchId:value.launchId,scenarioId:value.scenarioId,generation:value.generation,platformSessionId:value.platformSessionId};const fence=personaAuthority.capture({scope,personaId:value.personaId,sessionId:value.personaSessionId,role:value.role,authorityVersion:value.authorityVersion});if(typeof fence?.assertRemoteAdmission!=='function'||typeof fence?.withCrossStoreEffect!=='function')throw fail();const token=Object.freeze({});tokens.set(token,{value,fence});return token;}
 function captured(token){const result=tokens.get(token);if(!result)throw fail();return result;}
 async function tx(work){const c=await pool.connect();try{await c.query('BEGIN');await c.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");const result=await work(c);await c.query('COMMIT');return result;}catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();}}
 function decode(row,userId,evaluationId){if(!row||typeof row.persona_authority_required!=='boolean')throw fail();if(!row.persona_authority_required){if(row.evaluation_id!=null)throw fail();return null;}if(row.evaluation_id!==evaluationId||Number(row.user_id)!==userId)throw fail();return Object.freeze({originalRunId:uuid(row.original_run_id),...coordinates({scope:{platformOwnerId:Number(row.user_id),launchId:row.platform_launch_id,scenarioId:row.platform_scenario_id,generation:Number(row.platform_launch_generation),platformSessionId:Number(row.platform_session_id)},personaId:Number(row.persona_id),sessionId:row.persona_session_id,role:row.persona_role,authorityVersion:String(row.authority_version)})});}
 async function read(client,userId,evaluationId){userId=id(userId);evaluationId=uuid(evaluationId);const row=(await client.query(`SELECT j.persona_authority_required,b.* FROM workshop_platform.objective_judgments j LEFT JOIN workshop_platform.persona_evaluation_bindings b USING(user_id,evaluation_id) WHERE j.user_id=$1 AND j.evaluation_id=$2`,[userId,evaluationId])).rows[0];return decode(row,userId,evaluationId);}
 async function bind(client,value,evaluationId,runId){await client.query('SELECT workshop_platform.bind_persona_evaluation($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',[value.userId,uuid(evaluationId),uuid(runId),value.launchId,value.scenarioId,value.generation,value.platformSessionId,value.personaId,value.personaSessionId,value.role,value.authorityVersion]);}
 async function guarded(value,work){if(!value)return tx(work);const token=seal(value),{fence}=captured(token);await fence.assertRemoteAdmission();return fence.withCrossStoreEffect(()=>tx(work));}
 return Object.freeze({assertReady,
  async capture(input){await assertReady();const token=seal(coordinates(input));await captured(token).fence.assertRemoteAdmission();return token;},
  async initial({token,evaluationId,runId},write){await assertReady();if(typeof write!=='function')throw fail();const {value,fence}=captured(token);uuid(evaluationId);uuid(runId);await fence.assertRemoteAdmission();return fence.withCrossStoreEffect(()=>tx(async c=>{const result=await write(c,Object.freeze({personaAuthorityRequired:true}));await bind(c,value,evaluationId,runId);return result;}));},
  async inherit({userId,parentEvaluationId,childEvaluationId},write){await assertReady();if(typeof write!=='function')throw fail();id(userId);uuid(parentEvaluationId);if(childEvaluationId!==undefined)uuid(childEvaluationId);const original=await read(pool,userId,parentEvaluationId);return guarded(original,async c=>{const fresh=await read(c,userId,parentEvaluationId);if(JSON.stringify(original)!==JSON.stringify(fresh))throw fail();const result=await write(c,Object.freeze({personaAuthorityRequired:original!==null}));if(original)await bind(c,original,childEvaluationId??result?.receipt?.evaluationId,original.originalRunId);return result;});},
  async commit({userId,evaluationId},write){await assertReady();if(typeof write!=='function')throw fail();const original=await read(pool,userId,evaluationId);return guarded(original,async c=>{const fresh=await read(c,userId,evaluationId);if(JSON.stringify(original)!==JSON.stringify(fresh))throw fail();return write(c);});},
  async check({userId,evaluationId}){await assertReady();const value=await read(pool,userId,evaluationId);if(value)await captured(seal(value)).fence.assertRemoteAdmission();},
  async projectRecoverable({userId,rows}){userId=id(userId);if(!Array.isArray(rows)||rows.length>20)throw fail();
   const eligible=rows.filter(r=>r.canRetry===true),allowed=new Set(),checks=new Map();
   try{await assertReady();if(eligible.length){const ids=eligible.map(r=>uuid(r.evaluationId));const found=(await pool.query(`SELECT j.evaluation_id AS requested_evaluation_id,j.persona_authority_required,b.* FROM workshop_platform.objective_judgments j LEFT JOIN workshop_platform.persona_evaluation_bindings b USING(user_id,evaluation_id) WHERE j.user_id=$1 AND j.evaluation_id=ANY($2::uuid[])`,[userId,ids])).rows;
    const indexed=new Map(found.map(row=>[row.requested_evaluation_id,row]));
    for(const evaluationId of ids){try{const value=decode(indexed.get(evaluationId),userId,evaluationId);if(value){const key=JSON.stringify([value.userId,value.launchId,value.scenarioId,value.generation,value.platformSessionId,value.personaId,value.personaSessionId,value.role,value.authorityVersion]);if(!checks.has(key))checks.set(key,captured(seal(value)).fence.assertRemoteAdmission().then(()=>true,()=>false));if(!await checks.get(key))continue;}allowed.add(evaluationId);}catch{}}
   }}catch{}
   const fields=['evaluationId','runId','workshopKey','objectiveId','family','scenario','evidenceDigest','generation','mode','canonicalMode','verdict','disposition','evaluatedAt','rubricVersion','createdAt','errorCode','childEvaluationId'];
   return Object.freeze(rows.map(row=>Object.freeze({...Object.fromEntries(fields.filter(k=>Object.hasOwn(row,k)).map(k=>[k,row[k]])),canRetry:row.canRetry===true&&allowed.has(uuid(row.evaluationId))})));
  }

 });
}
module.exports={createPersonaObjectiveJudgmentBindings};
