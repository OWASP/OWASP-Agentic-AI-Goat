'use strict';
// Launch-owned persona administration, published only after runtime readiness.
const {createHash}=require('node:crypto');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const ROLES=new Set(['customer','merchant','admin']);
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail=code=>Object.assign(new Error('Bound persona administration unavailable'),{code});
const integer=v=>{if(!Number.isSafeInteger(v)||v<1||v>2147483647)throw fail('INVALID_INPUT');return v;};
const uuid=v=>{if(typeof v!=='string'||!UUID.test(v))throw fail('INVALID_INPUT');return v.toLowerCase();};
const fields=['platform_launch_id','platform_scenario_id','platform_launch_generation','original_platform_owner_id','original_platform_session_id'];
const where=fields.map((f,i)=>`${f}=$${i+1}`).join(' AND ');
// Effective grants are checked individually: PostgreSQL comma-separated
// privilege strings mean ANY, not ALL. This probe does not mutate authority.
async function assertUserAdministrationReadiness(pool) {
 if(typeof pool?.query!=='function')throw new TypeError('User administration runtime pool required');
 const required=[['bound_persona_templates','SELECT'],['bound_actor_identities','SELECT'],['bound_persona_state','SELECT'],
  ['bound_persona_state','INSERT'],['bound_persona_state','UPDATE'],
  ['bound_persona_sessions','SELECT'],['bound_persona_sessions','UPDATE'],
  ['bound_persona_credentials','SELECT'],['bound_persona_admin_operations','SELECT'],
  ['bound_persona_admin_operations','INSERT'],['conversation_generation_retirements','SELECT'],
  ['bound_audit_owner_deletion_receipts','SELECT']];
 const forbidden=[['bound_actor_identities','UPDATE'],['bound_actor_identities','DELETE'],
  ['bound_actor_identities','TRUNCATE'],['bound_persona_admin_operations','UPDATE'],['bound_persona_admin_operations','DELETE'],
  ['bound_persona_admin_operations','TRUNCATE'],['bound_persona_state','DELETE'],['bound_persona_state','TRUNCATE']];
 const specs=[...required.map(([table,privilege])=>({table,privilege,expected:true})),
  ...forbidden.map(([table,privilege])=>({table,privilege,expected:false}))];
 const result=await pool.query(`SELECT x.ordinality::int AS ordinal,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.'||x.table_name),x.privilege),false) AS allowed
  FROM unnest($1::text[],$2::text[]) WITH ORDINALITY AS x(table_name,privilege,ordinality) ORDER BY x.ordinality`,
  [specs.map(x=>x.table),specs.map(x=>x.privilege)]);
 if(result.rows.length!==specs.length||result.rows.some((row,i)=>row.ordinal!==i+1||row.allowed!==specs[i].expected))throw fail('USER_ADMINISTRATION_NOT_READY');
 const functionResult=await pool.query(`SELECT current_user AS runtime_role, COALESCE(has_function_privilege(current_user,
  to_regprocedure('secureshop_agents.revoke_admin_target_api_keys(uuid,uuid,bigint,integer,integer,integer,uuid,integer)'),
  'EXECUTE'),false) AS allowed`);
 if(functionResult.rows[0]?.runtime_role!=='dvaia_secureshop_agents_runtime'||functionResult.rows[0]?.allowed!==true)throw fail('USER_ADMINISTRATION_NOT_READY');
 return Object.freeze({ready:true});
}
function createSecureShopBoundUserAdministrationRepository({pool,auditStore,checkCurrent,registeredRepository}={}){
 if(typeof pool?.connect!=='function'||typeof auditStore?.append!=='function'||typeof checkCurrent!=='function')throw new TypeError('Authority, pool and transactional audit required');
 if(registeredRepository&&['mutate','readOperation','reserveTeachingOperation'].some(name=>typeof registeredRepository[name]!=='function'))throw new TypeError('Registered operation-kind authority required');
 const coordinates=s=>[s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId];
 async function transaction(scope,work){
  await checkCurrent(scope);const c=await pool.connect();
  try{await c.query('BEGIN');
   // Same owner-first order as transactional audit deletion fencing.
   await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`secureshop-bound-audit-owner:${scope.platformOwnerId}`]);
   await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`secureshop-conversation-admission:${scope.launchId}`]);
   const denied=await c.query(`SELECT EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=$1 AND from_generation=$2)
    OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=$3) AS denied`,[scope.launchId,scope.generation,scope.platformOwnerId]);
   if(denied.rows[0]?.denied!==false)throw fail('STALE_AUTHORITY');
   const result=await work(c);await checkCurrent(scope);await c.query('COMMIT');return result;
  }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();}
 }
 async function state(c,s,id){
  const row=(await c.query(`SELECT a.shop_user_id AS id,a.username,COALESCE(st.effective_role,a.base_role) AS role,
   st.banned_at,st.ban_reason,COALESCE(st.authority_version,1)::text AS version
   FROM secureshop_agents.bound_actor_identities a LEFT JOIN secureshop_agents.bound_persona_state st
   ON ${fields.map((f,i)=>`st.${f}=$${i+1}`).join(' AND ')} AND st.shop_user_id=a.shop_user_id
   WHERE a.shop_user_id=$6
     AND secureshop_agents.bound_actor_in_owner(a.shop_user_id,$4)`,[...coordinates(s),id])).rows[0];
  if(!row||!ROLES.has(row.role)||!/^[1-9]\d*$/.test(row.version))throw fail('PERSONA_UNAVAILABLE');return row;
 }
 async function teachingOperation(c,s,op){
  const rows=(await c.query(`SELECT platform_scenario_id AS scenario_id,platform_launch_generation::text AS generation,
   original_platform_owner_id AS owner_id,original_platform_session_id AS execution_session_id,
   actor_id,target_id,request_sha256,result_json FROM secureshop_agents.bound_persona_admin_operations
   WHERE platform_launch_id=$1 AND platform_launch_generation=$2 AND operation_id=$3 LIMIT 2`,[s.launchId,s.generation,op])).rows;
  if(rows.length>1)throw fail('OPERATION_CONFLICT');
  const row=rows[0];
  if(row&&(row.scenario_id!==s.scenarioId||String(row.generation)!==String(s.generation)
    ||row.owner_id!==s.platformOwnerId||row.execution_session_id!==s.platformSessionId))throw fail('OPERATION_CONFLICT');
  return row||null;
 }
 return Object.freeze({
  async checkReadiness(){await assertUserAdministrationReadiness(pool);if(registeredRepository)await registeredRepository.checkReadiness();return Object.freeze({ready:true});},
  async readEffectivePersona({scope,shopUserId}){if(registeredRepository){const registered=await registeredRepository.readEffectivePersona({scope,shopUserId});if(registered)return registered;}const s=createLaunchScope(scope);const id=integer(shopUserId);return transaction(s,async c=>Object.freeze(await state(c,s,id)));},
  async readOperation({scope,actorId,operationId}) {
   const s=createLaunchScope(scope),a=integer(actorId),op=uuid(operationId);
   return transaction(s,async c=>{
    const row=await teachingOperation(c,s,op);
    if(registeredRepository){const receipt=await registeredRepository.readOperation({scope:s,actorId:a,operationId:op},row);if(receipt)return receipt;}
    if(!row)return null;if(row.actor_id!==a)throw fail('ADMIN_REQUIRED');return Object.freeze(row.result_json);
   });
  },
  async mutate({scope,actorId,actorSessionId,actorAuthorityVersion,targetId,operationId,expectedVersion,action,role,reason=null}){
   if(registeredRepository&&await registeredRepository.isRegistered(scope,targetId))return registeredRepository.mutate({scope,actorId,actorSessionId,actorAuthorityVersion,targetId,operationId,expectedVersion,action,role,reason},
    (s,op)=>transaction(s,c=>teachingOperation(c,s,op)));
   const s=createLaunchScope(scope),a=integer(actorId),t=integer(targetId),sid=uuid(actorSessionId),op=uuid(operationId);
   if(typeof expectedVersion!=='string'||!/^[1-9]\d*$/.test(expectedVersion)||BigInt(expectedVersion)>=9007199254740991n
    ||!['set_role','ban'].includes(action)||(action==='set_role'&&(!ROLES.has(role)||reason!==null))
    ||(action==='ban'&&role!==undefined)||(reason!==null&&(typeof reason!=='string'||Buffer.byteLength(reason)>1024)))throw fail('INVALID_INPUT');
   const digest=createHash('sha256').update(JSON.stringify([a,t,action,role??null,reason,expectedVersion])).digest();
   return transaction(s,async c=>{
    const actor=await state(c,s,a);
    const session=(await c.query(`SELECT session_id FROM secureshop_agents.bound_persona_sessions x
     WHERE ${fields.map((f,i)=>`x.${f}=$${i+1}`).join(' AND ')} AND x.shop_user_id=$6 AND x.session_id=$7
     AND x.role='admin' AND x.revoked_at IS NULL AND x.expires_at>clock_timestamp()
     AND x.credential_version=COALESCE((SELECT credential_version FROM secureshop_agents.bound_persona_credentials c
       WHERE ${fields.map((f,i)=>`c.${f}=$${i+1}`).join(' AND ')} AND c.shop_user_id=$6),1)`,[...coordinates(s),a,sid])).rows[0];
    if(!session||actor.role!=='admin'||actor.banned_at)throw fail('ADMIN_REQUIRED');
    const old=await teachingOperation(c,s,op);
    const reserve=()=>registeredRepository?.reserveTeachingOperation({scope:s,actorId:a,targetId:t,operationId:op,digest},old);
    if(old){if(!Buffer.isBuffer(old.request_sha256)||!old.request_sha256.equals(digest))throw fail('OPERATION_CONFLICT');await reserve();return Object.freeze({replayed:true,receipt:old.result_json});}
    const target=await state(c,s,t);if(target.version!==expectedVersion)throw fail('REVISION_CONFLICT');
    await reserve();
    // Delete keys before self-demotion/revocation; this function independently checks actor.
    const keyResult=await c.query('SELECT secureshop_agents.revoke_admin_target_api_keys($1,$2,$3,$4,$5,$6,$7,$8) AS count',[...coordinates(s),a,sid,t]);
    const row=(await c.query(`INSERT INTO secureshop_agents.bound_persona_state
     (${fields.join(',')},shop_user_id,effective_role,banned_at,ban_reason,authority_version)
     VALUES($1,$2,$3,$4,$5,$6,$7,CASE WHEN $8 THEN clock_timestamp() ELSE $9::timestamptz END,$10,$11)
     ON CONFLICT(${fields.join(',')},shop_user_id) DO UPDATE SET effective_role=EXCLUDED.effective_role,
      banned_at=EXCLUDED.banned_at,ban_reason=EXCLUDED.ban_reason,authority_version=EXCLUDED.authority_version
     RETURNING effective_role,banned_at,authority_version::text AS version`,[...coordinates(s),t,action==='set_role'?role:target.role,action==='ban',target.banned_at,action==='ban'?reason:target.ban_reason,(BigInt(expectedVersion)+1n).toString()])).rows[0];
    const revoked=await c.query(`UPDATE secureshop_agents.bound_persona_sessions SET revoked_at=clock_timestamp()
     WHERE ${where} AND shop_user_id=$6 AND revoked_at IS NULL`,[...coordinates(s),t]);
    const receipt={operationId:op,actorId:a,originalActorSessionId:sid,targetId:t,action,role:row.effective_role,
     bannedAt:row.banned_at?new Date(row.banned_at).toISOString():null,version:row.version,revokedSessions:revoked.rowCount,revokedApiKeys:Number(keyResult.rows[0].count)};
    await auditStore.append(c,{eventId:op,scope:s,persona:{id:a,role:'admin'},actor:'admin',action:`persona_admin_${action}`,
     target:String(t),paramsJson:JSON.stringify({targetId:t,role:receipt.role,expectedVersion,resultVersion:row.version,reason}),outcome:'completed',sourceKind:'persona_admin_operation',sourceId:op});
    await c.query(`INSERT INTO secureshop_agents.bound_persona_admin_operations
     (${fields.join(',')},operation_id,actor_id,original_actor_session_id,target_id,request_sha256,result_json)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)`,[...coordinates(s),op,a,sid,t,digest,JSON.stringify(receipt)]);
    return Object.freeze({replayed:false,receipt:Object.freeze(receipt)});
   });
  }
 });
}
module.exports={createSecureShopBoundUserAdministrationRepository,assertUserAdministrationReadiness};
