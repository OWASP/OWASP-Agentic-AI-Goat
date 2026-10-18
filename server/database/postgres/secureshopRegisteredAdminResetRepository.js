'use strict';
// Protected, tenant-scoped reset of standalone principal credentials. The
// agents-store persona overlay is never credential or administrator authority.
const {canonicalDigest}=require('../../services/mcp/protocolContext');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERSION=/^[1-9]\d{0,18}$/;
const fail=code=>Object.assign(Error('Registered administrator reset unavailable'),{code});
const version=value=>typeof value==='string'&&VERSION.test(value)&&BigInt(value)<9007199254740991n;
const safeReceipt=row=>Object.freeze({operationId:row.operationId,targetId:row.targetId,credentialVersion:row.credentialVersion,authorityVersion:row.authorityVersion,receiptSha256:row.receiptSha256,expiresAt:row.expiresAt});
function createRegisteredAdminResetRepository({pool,envelope,now=Date.now,tenantSlug='default'}={}){
 if(typeof pool?.connect!=='function'||typeof envelope?.seal!=='function'||typeof envelope?.open!=='function'||typeof now!=='function'||typeof tenantSlug!=='string'||!/^[a-z][a-z0-9_-]{0,63}$/.test(tenantSlug))throw TypeError('Protected reset repository dependencies required');
 async function transaction(work){const client=await pool.connect();try{await client.query('BEGIN');const value=await work(client);await client.query('COMMIT');return value;}catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}}
 async function authority(client,{tokenHash,targetId}){
  if(typeof tokenHash!=='string'||!/^[a-f0-9]{64}$/.test(tokenHash)||!Number.isSafeInteger(targetId)||targetId<1||targetId>2147483647)throw fail('INVALID_ARGUMENT');
  // Discover identifiers without trusting them; lock both principal rows in
  // deterministic UUID order before any current-session or membership check.
  const actorId=(await client.query(`SELECT principal_id::text AS id FROM secureshop_auth.sessions WHERE token_hash=$1`,[tokenHash])).rows[0]?.id;
  const targetIdValue=(await client.query(`SELECT principal_id::text AS id FROM secureshop_auth.principals WHERE shop_user_id=$1`,[targetId])).rows[0]?.id;
  if(!actorId)throw fail('SHOP_AUTH_INVALID');
  if(!targetIdValue||!UUID.test(targetIdValue)||actorId===targetIdValue)throw fail('REGISTERED_RESET_FORBIDDEN');
  const locked=(await client.query(`SELECT principal_id::text AS id FROM secureshop_auth.principals
    WHERE principal_id=ANY($1::uuid[]) ORDER BY principal_id FOR UPDATE`,[[actorId,targetIdValue]])).rows;
  if(locked.length!==2||locked[0].id!==[actorId,targetIdValue].sort()[0]||locked[1].id!==[actorId,targetIdValue].sort()[1])throw fail('SHOP_AUTH_INVALID');
  const actor=(await client.query(`SELECT p.principal_id::text AS "principalId",p.shop_user_id AS "shopUserId",
      p.authority_version::text AS "authorityVersion",s.session_id AS "authSessionId",
      e.session_id AS "executionSessionId",t.tenant_id::text AS "tenantId",
      m.membership_version::text AS "membershipVersion"
    FROM secureshop_auth.sessions s JOIN secureshop_auth.principals p USING(principal_id)
    JOIN secureshop_auth.tenant_memberships m USING(principal_id)
    JOIN secureshop_auth.tenants t USING(tenant_id)
    JOIN secureshop_auth.execution_sessions e ON e.auth_session_id=s.session_id
      AND e.principal_id=p.principal_id AND e.tenant_id=t.tenant_id
      AND e.membership_version=m.membership_version
    JOIN secureshop_auth.practice_selections selected ON selected.auth_session_id=s.session_id
      AND selected.tenant_id=t.tenant_id AND selected.principal_id=p.principal_id
      AND selected.execution_session_id=e.session_id
    WHERE s.token_hash=$1 AND p.principal_id=$2::uuid AND t.slug=$3
      AND p.is_active AND m.is_active AND m.role='admin' AND t.is_active
      AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
      AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
      AND s.credential_version=p.credential_version AND s.authority_version=p.authority_version
      AND e.revoked_at IS NULL AND e.expires_at>clock_timestamp()
    FOR SHARE OF s,m,t,e`,[tokenHash,actorId,tenantSlug])).rows[0];
  if(!actor)throw fail('SHOP_AUTH_INVALID');
  const target=(await client.query(`SELECT p.principal_id::text AS "principalId",p.shop_user_id AS id,
      p.username,p.email,p.credential_version::text AS "credentialVersion",
      p.authority_version::text AS "authorityVersion",
      m.membership_version::text AS "membershipVersion"
    FROM secureshop_auth.principals p JOIN secureshop_auth.tenant_memberships m USING(principal_id)
    WHERE p.principal_id=$1::uuid AND p.shop_user_id=$2 AND p.is_active
      AND m.tenant_id=$3::uuid AND m.shop_user_id=p.shop_user_id AND m.is_active
    FOR SHARE OF m`,[targetIdValue,targetId,actor.tenantId])).rows[0];
  if(!target)throw fail('REGISTERED_RESET_FORBIDDEN');
  // The credential is global to the principal. A second active tenant would
  // make this tenant's administrator an authority over that other tenant.
  const memberships=(await client.query(`SELECT tenant_id::text AS "tenantId",is_active AS "isActive"
    FROM secureshop_auth.tenant_memberships WHERE principal_id=$1::uuid FOR SHARE`,[target.principalId])).rows;
  if(memberships.some(row=>row.isActive&&row.tenantId!==actor.tenantId))throw fail('REGISTERED_RESET_FORBIDDEN');
  return {actor,target};
 }
 function requestDigest(x,actor,target){return canonicalDigest({version:1,operationId:x.operationId,tenantId:actor.tenantId,
  actorPrincipalId:actor.principalId,actorAuthSessionId:actor.authSessionId,
  actorExecutionSessionId:actor.executionSessionId,actorMembershipVersion:actor.membershipVersion,
  actorAuthorityVersion:actor.authorityVersion,targetPrincipalId:target.principalId,targetId:target.id,
  expectedCredentialVersion:x.expectedCredentialVersion,expectedAuthorityVersion:x.expectedAuthorityVersion,
  expectedMembershipVersion:x.expectedMembershipVersion});}
 async function stored(client,x,actor,target){const row=(await client.query(`SELECT request_sha256,receipt_json
    FROM secureshop_auth.registered_admin_reset_operations WHERE operation_id=$1::uuid`,[x.operationId])).rows[0];
  if(!row)return null;const receipt=row.receipt_json,{receiptSha256,...body}=receipt||{};
  if(!Buffer.isBuffer(row.request_sha256)||row.request_sha256.toString('hex')!==requestDigest(x,actor,target)
    ||receipt.operationId!==x.operationId||receipt.tenantId!==actor.tenantId
    ||receipt.actorPrincipalId!==actor.principalId||receipt.actorAuthSessionId!==actor.authSessionId
    ||receipt.actorExecutionSessionId!==actor.executionSessionId||receipt.actorMembershipVersion!==actor.membershipVersion
    ||receipt.actorAuthorityVersion!==actor.authorityVersion||receipt.targetPrincipalId!==target.principalId
    ||receipt.targetId!==target.id||receiptSha256!==canonicalDigest(body))throw fail('REGISTERED_RESET_CONFLICT');
  return receipt;
 }
 async function recovery(client,operationId){return(await client.query(`SELECT envelope_json,expires_at
   FROM secureshop_auth.registered_admin_reset_recovery WHERE operation_id=$1::uuid`,[operationId])).rows[0];}
 async function secretAvailable(client,receipt,target){if(target.credentialVersion!==receipt.credentialVersion||target.authorityVersion!==receipt.authorityVersion||Date.parse(receipt.expiresAt)<=now())return false;
  const row=await recovery(client,receipt.operationId);if(!row?.envelope_json||new Date(row.expires_at).toISOString()!==receipt.expiresAt)return false;
  try{envelope.open({receipt,envelope:row.envelope_json});return true;}catch{return false;}}
 async function readStored(client,x,actor,target){const row=(await client.query(`SELECT receipt_json FROM secureshop_auth.registered_admin_reset_operations
   WHERE operation_id=$1::uuid`,[x.operationId])).rows[0];if(!row)return null;
  const receipt=row.receipt_json,{receiptSha256,...body}=receipt||{};
  if(receipt.operationId!==x.operationId||receipt.tenantId!==actor.tenantId||receipt.actorPrincipalId!==actor.principalId
   ||receipt.actorAuthSessionId!==actor.authSessionId||receipt.actorExecutionSessionId!==actor.executionSessionId
   ||receipt.actorMembershipVersion!==actor.membershipVersion||receipt.actorAuthorityVersion!==actor.authorityVersion
   ||receipt.targetPrincipalId!==target.principalId||receipt.targetId!==target.id||receiptSha256!==canonicalDigest(body))throw fail('REGISTERED_RESET_FORBIDDEN');
  return receipt;
 }
 const operation=x=>{if(typeof x.operationId!=='string'||!UUID.test(x.operationId))throw fail('INVALID_ARGUMENT');return {...x,operationId:x.operationId.toLowerCase()};};
 return Object.freeze({
  async checkReadiness(){try{const row=(await pool.query(`SELECT
    has_table_privilege(current_user,'secureshop_auth.registered_admin_reset_operations','SELECT')
      AND has_table_privilege(current_user,'secureshop_auth.registered_admin_reset_operations','INSERT') AS operation_write,
    has_table_privilege(current_user,'secureshop_auth.registered_admin_reset_recovery','SELECT')
      AND has_table_privilege(current_user,'secureshop_auth.registered_admin_reset_recovery','INSERT') AS recovery_write,
    has_column_privilege(current_user,'secureshop_auth.registered_admin_reset_recovery','envelope_json','UPDATE') AS recovery_ack,
    has_table_privilege(current_user,'secureshop_auth.registered_admin_reset_operations','UPDATE,DELETE,TRUNCATE') AS operation_mutable,
    has_table_privilege(current_user,'secureshop_auth.registered_admin_reset_recovery','DELETE,TRUNCATE') AS recovery_removable`)).rows[0];
   if(!row?.operation_write||!row?.recovery_write||!row?.recovery_ack||row.operation_mutable||row.recovery_removable)throw fail('REGISTERED_RESET_NOT_READY');
   return Object.freeze({ready:true});
  }catch(error){if(error?.code==='REGISTERED_RESET_NOT_READY')throw error;throw fail('REGISTERED_RESET_NOT_READY');}},
  async preview(x){return transaction(async client=>{const {target}=await authority(client,x);return Object.freeze({id:target.id,username:target.username,email:target.email,
    credentialVersion:target.credentialVersion,authorityVersion:target.authorityVersion,membershipVersion:target.membershipVersion,resetAvailable:true});});},
  async reset(raw){const x=operation(raw);if(![x.expectedCredentialVersion,x.expectedAuthorityVersion,x.expectedMembershipVersion].every(version)
    ||typeof x.passwordHash!=='string'||!/^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/.test(x.passwordHash)
    ||typeof x.secret!=='string'||!/^[A-Za-z0-9_-]{32,128}$/.test(x.secret))throw fail('INVALID_ARGUMENT');
   let attempted=false;try{return await transaction(async client=>{const {actor,target}=await authority(client,x);
    const previous=await stored(client,x,actor,target);if(previous)return Object.freeze({receipt:safeReceipt(previous),secretAvailable:await secretAvailable(client,previous,target),replayed:true});
    if(target.credentialVersion!==x.expectedCredentialVersion||target.authorityVersion!==x.expectedAuthorityVersion||target.membershipVersion!==x.expectedMembershipVersion)throw fail('REGISTERED_RESET_REVISION_CONFLICT');
    const credentialVersion=(BigInt(target.credentialVersion)+1n).toString(),authorityVersion=(BigInt(target.authorityVersion)+1n).toString();
    const body={version:1,operationId:x.operationId,tenantId:actor.tenantId,actorPrincipalId:actor.principalId,
     actorAuthSessionId:actor.authSessionId,actorExecutionSessionId:actor.executionSessionId,
     actorMembershipVersion:actor.membershipVersion,actorAuthorityVersion:actor.authorityVersion,
     targetPrincipalId:target.principalId,targetId:target.id,
     expectedCredentialVersion:x.expectedCredentialVersion,expectedAuthorityVersion:x.expectedAuthorityVersion,
     expectedMembershipVersion:x.expectedMembershipVersion,credentialVersion,authorityVersion,
     expiresAt:new Date(now()+10*60*1000).toISOString()};
    const receipt={...body,receiptSha256:canonicalDigest(body)},sealed=envelope.seal({receipt,secret:x.secret});
    attempted=true;
    const updated=await client.query(`UPDATE secureshop_auth.principals SET password_hash=$2,
      credential_version=credential_version+1,authority_version=authority_version+1,
      failed_login_count=0,locked_until=NULL,updated_at=clock_timestamp()
      WHERE principal_id=$1::uuid AND credential_version=$3::bigint AND authority_version=$4::bigint`,
    [target.principalId,x.passwordHash,x.expectedCredentialVersion,x.expectedAuthorityVersion]);
    if(updated.rowCount!==1)throw fail('REGISTERED_RESET_REVISION_CONFLICT');
    await client.query(`UPDATE secureshop_auth.sessions SET revoked_at=clock_timestamp()
      WHERE principal_id=$1::uuid AND revoked_at IS NULL`,[target.principalId]);
    await client.query(`UPDATE secureshop_auth.execution_sessions SET revoked_at=clock_timestamp()
      WHERE principal_id=$1::uuid AND revoked_at IS NULL`,[target.principalId]);
    await client.query(`INSERT INTO secureshop_auth.registered_admin_reset_operations
      (operation_id,tenant_id,actor_principal_id,actor_auth_session_id,actor_execution_session_id,
       actor_membership_version,actor_authority_version,target_principal_id,target_shop_user_id,
       request_sha256,receipt_json) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6::bigint,$7::bigint,$8::uuid,$9,$10,$11::jsonb)`,
    [x.operationId,actor.tenantId,actor.principalId,actor.authSessionId,actor.executionSessionId,
      actor.membershipVersion,actor.authorityVersion,target.principalId,target.id,
      Buffer.from(requestDigest(x,actor,target),'hex'),JSON.stringify(receipt)]);
    await client.query(`INSERT INTO secureshop_auth.registered_admin_reset_recovery
      (operation_id,envelope_json,expires_at) VALUES($1::uuid,$2::jsonb,$3::timestamptz)`,
    [x.operationId,JSON.stringify(sealed),receipt.expiresAt]);
    return Object.freeze({receipt:safeReceipt(receipt),secretAvailable:true,replayed:false});
   });}catch(error){if(attempted&&!['REGISTERED_RESET_REVISION_CONFLICT','REGISTERED_RESET_CONFLICT'].includes(error?.code)){const uncertain=fail('REGISTERED_RESET_OUTCOME_UNCERTAIN');Object.defineProperty(uncertain,'cause',{value:error});throw uncertain;}throw error;}
  },
  async read(raw){const x=operation(raw);return transaction(async client=>{const {actor,target}=await authority(client,x),receipt=await readStored(client,x,actor,target);return receipt?Object.freeze({receipt:safeReceipt(receipt),secretAvailable:await secretAvailable(client,receipt,target)}):null;});},
  async reveal(raw){const x=operation(raw);return transaction(async client=>{const {actor,target}=await authority(client,x),receipt=await readStored(client,x,actor,target);if(!receipt)throw fail('REGISTERED_RESET_OPERATION_NOT_FOUND');
   if(target.credentialVersion!==receipt.credentialVersion||target.authorityVersion!==receipt.authorityVersion)throw fail('REGISTERED_RESET_RECOVERY_UNAVAILABLE');
   const row=await recovery(client,x.operationId);if(!row?.envelope_json||new Date(row.expires_at).toISOString()!==receipt.expiresAt)throw fail('REGISTERED_RESET_RECOVERY_UNAVAILABLE');
   return Object.freeze({receipt:safeReceipt(receipt),temporaryPassword:envelope.open({receipt,envelope:row.envelope_json})});});},
  async acknowledge(raw){const x=operation(raw);return transaction(async client=>{const {actor,target}=await authority(client,x),receipt=await readStored(client,x,actor,target);if(!receipt)throw fail('REGISTERED_RESET_OPERATION_NOT_FOUND');
   await client.query(`UPDATE secureshop_auth.registered_admin_reset_recovery SET envelope_json=NULL
     WHERE operation_id=$1::uuid AND envelope_json IS NOT NULL`,[x.operationId]);
   return Object.freeze({receipt:safeReceipt(receipt),secretAvailable:false});});},
 });
}
module.exports={createRegisteredAdminResetRepository};
