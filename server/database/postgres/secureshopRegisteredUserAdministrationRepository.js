'use strict';
// Registered account authority belongs to the tenant, never a teaching overlay.
const {createHash}=require('node:crypto');
const {withTransaction}=require('./index');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const fail=code=>Object.assign(Error('Registered user administration unavailable'),{code});
const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
const id=value=>Number.isSafeInteger(value)&&value>0&&value<=2147483647;
const coordinates=s=>[s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId];
function createRegisteredUserAdministrationRepository({pool,checkCurrent,personaAuthority}={}){
 if(typeof pool?.connect!=='function'||typeof pool?.query!=='function'||typeof checkCurrent!=='function'||typeof personaAuthority?.capture!=='function')throw TypeError('Registered authority database required');
 async function target(scope,shopUserId){
  const s=createLaunchScope(scope);if(!id(shopUserId))throw fail('INVALID_INPUT');
  const row=(await pool.query(`SELECT p.principal_id,m.role,m.is_active,m.banned_at,m.ban_reason,
    m.membership_version::text AS version,p.shop_user_id AS id,p.username
    FROM secureshop_auth.principals p LEFT JOIN secureshop_auth.tenants t ON t.owner_id=$1
    LEFT JOIN secureshop_auth.tenant_memberships m ON m.tenant_id=t.tenant_id AND m.principal_id=p.principal_id
    WHERE p.shop_user_id=$2`,[s.platformOwnerId,shopUserId])).rows[0];
  if(row&&!row.version)throw fail('PERSONA_UNAVAILABLE');return row||null;
 }
 async function authority(c,s,actorId){
  const row=(await c.query(`SELECT e.tenant_id,p.principal_id FROM secureshop_auth.execution_sessions e
    JOIN secureshop_auth.sessions a ON a.session_id=e.auth_session_id
    JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id AND p.principal_id=a.principal_id
    JOIN secureshop_auth.tenant_memberships m ON m.tenant_id=e.tenant_id AND m.principal_id=p.principal_id
    JOIN secureshop_auth.session_membership_snapshots v ON v.session_id=a.session_id AND v.tenant_id=m.tenant_id AND v.membership_version=m.membership_version
    JOIN secureshop_auth.tenants t ON t.tenant_id=m.tenant_id
    JOIN identity.secureshop_launches l ON l.platform_session_id=e.session_id
    WHERE l.launch_id=$1 AND l.scenario_id=$2 AND l.generation=$3 AND l.original_platform_owner_id=$4
      AND e.session_id=$5 AND l.original_platform_session_id=$5 AND p.shop_user_id=$6 AND t.owner_id=$4
      AND l.status='active' AND l.expires_at>clock_timestamp()
      AND p.is_active AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
      AND t.is_active AND m.is_active AND m.role='admin' AND e.membership_version=m.membership_version
      AND e.revoked_at IS NULL AND e.expires_at>clock_timestamp()
      AND a.revoked_at IS NULL AND a.expires_at>clock_timestamp()
      AND a.credential_version=p.credential_version AND a.authority_version=p.authority_version
    FOR SHARE OF p,a,m,t,e,l`,[...coordinates(s),actorId])).rows[0];
  if(!row)throw fail('ADMIN_REQUIRED');return row;
 }
 const journalColumns='scenario_id,generation::text AS generation,owner_id,execution_session_id,actor_id,target_id,request_sha256,result_json';
 async function registeredOperation(c,s,op){return(await c.query(`SELECT ${journalColumns} FROM secureshop_auth.tenant_admin_operations
   WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,[s.launchId,s.generation,op])).rows[0]||null;}
 function assertScope(row,s){
  if(row.scenario_id!==s.scenarioId||String(row.generation)!==String(s.generation)||row.owner_id!==s.platformOwnerId
    ||row.execution_session_id!==s.platformSessionId)throw fail('OPERATION_CONFLICT');
 }
 function assertIntent(row,s,intent){
  assertScope(row,s);
  if(row.actor_id!==intent.actorId||row.target_id!==intent.targetId||!Buffer.isBuffer(row.request_sha256)
    ||!row.request_sha256.equals(intent.digest))throw fail('OPERATION_CONFLICT');
 }
 async function readKind(c,s,op){return(await c.query(`SELECT scenario_id,generation::text AS generation,owner_id,execution_session_id,
   operation_kind,actor_id,target_id,request_sha256 FROM secureshop_auth.admin_operation_kinds
   WHERE launch_id=$1 AND generation=$2 AND operation_id=$3`,[s.launchId,s.generation,op])).rows[0]||null;}
 async function reserveKind(c,s,intent,teaching){
  const registered=await registeredOperation(c,s,intent.operationId);
  // Never choose one of two historical effects or rewrite either receipt.
  if(registered&&teaching)throw fail('OPERATION_CONFLICT');
  const prior=registered||teaching;
  if(prior){
   if(intent.kind!==(registered?'registered':'teaching'))throw fail('OPERATION_CONFLICT');
   assertIntent(prior,s,intent);
  }
  await c.query(`INSERT INTO secureshop_auth.admin_operation_kinds
    (launch_id,generation,operation_id,scenario_id,owner_id,execution_session_id,operation_kind,actor_id,target_id,request_sha256)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(launch_id,generation,operation_id) DO NOTHING`,
   [s.launchId,s.generation,intent.operationId,s.scenarioId,s.platformOwnerId,s.platformSessionId,intent.kind,intent.actorId,intent.targetId,intent.digest]);
  // INSERT waits for a competing transaction. A new READ COMMITTED statement
  // then checks its committed winner, including after coordinator-lock loss.
  const claimed=await readKind(c,s,intent.operationId);
  if(!claimed||claimed.operation_kind!==intent.kind)throw fail('OPERATION_CONFLICT');
  assertIntent(claimed,s,intent);return registered;
 }
 const api={
  async checkReadiness(){
   const row=(await pool.query(`SELECT
    has_table_privilege(current_user,'secureshop_auth.session_membership_snapshots','SELECT')
    AND NOT has_table_privilege(current_user,'secureshop_auth.session_membership_snapshots','INSERT,UPDATE,DELETE,TRUNCATE')
    AND has_table_privilege(current_user,'secureshop_auth.tenant_admin_operations','SELECT')
    AND has_table_privilege(current_user,'secureshop_auth.tenant_admin_operations','INSERT')
    AND NOT has_table_privilege(current_user,'secureshop_auth.tenant_admin_operations','UPDATE,DELETE,TRUNCATE')
    AND has_table_privilege(current_user,'secureshop_auth.admin_operation_kinds','SELECT')
    AND has_table_privilege(current_user,'secureshop_auth.admin_operation_kinds','INSERT')
    AND NOT has_table_privilege(current_user,'secureshop_auth.admin_operation_kinds','UPDATE,DELETE,TRUNCATE') AS ready`)).rows[0];
   if(row?.ready!==true)throw fail('USER_ADMINISTRATION_NOT_READY');return Object.freeze({ready:true});
  },
  isRegistered:async(scope,targetId)=>!!await target(scope,targetId),
  async readEffectivePersona({scope,shopUserId}){await checkCurrent(scope);const row=await target(scope,shopUserId);return row&&Object.freeze(row);},
  async readOperation({scope,actorId,operationId},teaching=null){
   const s=createLaunchScope(scope);if(!id(actorId)||!uuid(operationId))throw fail('INVALID_INPUT');
   await checkCurrent(s);return withTransaction(pool,async c=>{
    const row=await registeredOperation(c,s,operationId);
    if(row&&teaching)throw fail('OPERATION_CONFLICT');
    const prior=row||teaching,claim=await readKind(c,s,operationId);
    if(prior){
     assertScope(prior,s);
     if(claim){
      if(claim.operation_kind!==(row?'registered':'teaching'))throw fail('OPERATION_CONFLICT');
      assertIntent(claim,s,{actorId:prior.actor_id,targetId:prior.target_id,digest:prior.request_sha256});
     }
    }else if(claim)assertScope(claim,s);
    if(!row)return null;await authority(c,s,actorId);if(row.actor_id!==actorId)throw fail('ADMIN_REQUIRED');return Object.freeze(row.result_json);
   });
  },
  // Called only after the teaching repository's actor/session/revision checks,
  // while its agents transaction is locked. Committing here reserves intent,
  // not success. An agents rollback must never release this reservation.
  async reserveTeachingOperation({scope,actorId,targetId,operationId,digest},teaching=null){
   const s=createLaunchScope(scope);
   if(!id(actorId)||!id(targetId)||!uuid(operationId)||!Buffer.isBuffer(digest)||digest.length!==32)throw fail('INVALID_INPUT');
   await checkCurrent(s);
   await withTransaction(pool,async c=>{
    await c.query("SET LOCAL lock_timeout='3000ms'");await c.query("SET LOCAL statement_timeout='5000ms'");
    await reserveKind(c,s,{kind:'teaching',actorId,targetId,operationId:operationId.toLowerCase(),digest},teaching);
   });
  },
  async mutate(input,readTeachingOperation){
   const {actorId,targetId,actorSessionId,operationId,expectedVersion,action,role,reason=null}=input;
   const s=createLaunchScope(input.scope);
   if(!id(actorId)||!id(targetId)||!uuid(actorSessionId)||!uuid(operationId)
     ||typeof expectedVersion!=='string'||!/^[1-9]\d*$/.test(expectedVersion)||BigInt(expectedVersion)>=9007199254740991n
     ||!['set_role','ban'].includes(action)||(action==='set_role'&&(!['customer','merchant','admin'].includes(role)||reason!==null))
     ||(action==='ban'&&role!==undefined)||(reason!==null&&(typeof reason!=='string'||Buffer.byteLength(reason)>1024)))throw fail('INVALID_INPUT');
   const digest=createHash('sha256').update(JSON.stringify([actorId,targetId,action,role??null,reason,expectedVersion])).digest();
   if(typeof readTeachingOperation!=='function')throw TypeError('Teaching operation history reader required');
   // Drain any legacy agents writer before entering the persona fence. New
   // writers all reserve their identity-side kind before applying an effect.
   // No second agents connection is acquired while the persona fence is held.
   const teaching=await readTeachingOperation(s,operationId.toLowerCase());
   const fence=personaAuthority.capture({scope:s,personaId:actorId,sessionId:actorSessionId,role:'admin',authorityVersion:input.actorAuthorityVersion});
   if(fence?.binding?.sessionId!==actorSessionId.toLowerCase()||fence.binding.personaId!==actorId
     ||Object.keys(s).some(key=>fence.binding[key]!==s[key])||typeof fence.withCrossStoreEffect!=='function')throw fail('SHOP_AUTH_INVALID');
   await fence.assertRemoteAdmission();
   await checkCurrent(s);
   let effectStarted=false;
   const result=await fence.withCrossStoreEffect(async()=>{try{return await withTransaction(pool,async c=>{
    await c.query("SET LOCAL lock_timeout='3000ms'");await c.query("SET LOCAL statement_timeout='5000ms'");
    // Serialize the tenant's final-admin test before acquiring any member lock.
    await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`secureshop-tenant-administration:${s.platformOwnerId}`]);
    await c.query(`SELECT principal_id FROM secureshop_auth.principals WHERE shop_user_id=ANY($1::integer[]) ORDER BY principal_id FOR SHARE`,[[actorId,targetId]]);
    const actor=await authority(c,s,actorId);
    const old=await reserveKind(c,s,{kind:'registered',actorId,targetId,operationId:operationId.toLowerCase(),digest},teaching);
    if(old){if(!Buffer.isBuffer(old.request_sha256)||!old.request_sha256.equals(digest))throw fail('OPERATION_CONFLICT');return Object.freeze({replayed:true,receipt:old.result_json});}
    const member=(await c.query(`SELECT m.*,m.membership_version::text AS version FROM secureshop_auth.tenant_memberships m
      WHERE m.tenant_id=$1 AND m.shop_user_id=$2 FOR UPDATE`,[actor.tenant_id,targetId])).rows[0];
    if(!member)throw fail('PERSONA_UNAVAILABLE');if(member.version!==expectedVersion)throw fail('REVISION_CONFLICT');
    if(member.is_active&&member.role==='admin'&&(action==='ban'||role!=='admin')){
     const remaining=(await c.query(`SELECT count(*)::integer AS count FROM secureshop_auth.tenant_memberships m
       JOIN secureshop_auth.principals p USING(principal_id) WHERE m.tenant_id=$1 AND m.is_active AND m.role='admin'
       AND p.is_active AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp()) AND m.shop_user_id<>$2`,[actor.tenant_id,targetId])).rows[0];
     if(!remaining||remaining.count<1)throw fail('LAST_TENANT_ADMIN');
    }
    const revoked=(await c.query(`SELECT count(*)::integer AS count FROM secureshop_auth.execution_sessions e
      JOIN identity.secureshop_authority_sessions live ON live.id=e.session_id AND live.is_active=1
      WHERE e.tenant_id=$1 AND e.principal_id=$2 AND e.revoked_at IS NULL AND e.expires_at>clock_timestamp() AND e.membership_version=$3`,[actor.tenant_id,member.principal_id,member.membership_version])).rows[0];
    effectStarted=true;
    const changed=(await c.query(`UPDATE secureshop_auth.tenant_memberships SET role=$3,is_active=CASE WHEN $4 THEN false ELSE is_active END,
      banned_at=CASE WHEN $4 THEN clock_timestamp() ELSE banned_at END,ban_reason=CASE WHEN $4 THEN $5 ELSE ban_reason END,
      membership_version=membership_version+1 WHERE tenant_id=$1 AND shop_user_id=$2
      RETURNING role,banned_at,membership_version::text AS version`,[actor.tenant_id,targetId,action==='set_role'?role:member.role,action==='ban',reason])).rows[0];
    const receipt={operationId:operationId.toLowerCase(),actorId,originalActorSessionId:actorSessionId.toLowerCase(),targetId,action,
      role:changed.role,bannedAt:changed.banned_at?new Date(changed.banned_at).toISOString():null,version:changed.version,
      revokedSessions:revoked.count,revokedApiKeys:0};
    await c.query(`INSERT INTO secureshop_auth.tenant_admin_operations
      (launch_id,scenario_id,generation,owner_id,execution_session_id,operation_id,tenant_id,actor_id,actor_session_id,target_id,request_sha256,result_json)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`,[...coordinates(s),operationId,actor.tenant_id,actorId,actorSessionId,targetId,digest,JSON.stringify(receipt)]);
    return Object.freeze({replayed:false,receipt:Object.freeze(receipt)});
   });}catch(error){
    // These explicit pre-write denials have no cross-store effect. SQL/commit
    // errors and every error after the mutation remain uncertain.
    if(!effectStarted&&['ADMIN_REQUIRED','PERSONA_UNAVAILABLE','REVISION_CONFLICT','OPERATION_CONFLICT','LAST_TENANT_ADMIN'].includes(error?.code))return{denial:error.code};
    throw error;
   }});
   if(result?.denial)throw fail(result.denial);return result;
  }
 };return Object.freeze(api);
}
module.exports={createRegisteredUserAdministrationRepository};
