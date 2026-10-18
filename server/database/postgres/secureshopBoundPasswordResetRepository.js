'use strict';
const {randomBytes}=require('node:crypto'),bcrypt=require('bcryptjs');
const {canonicalDigest}=require('../../services/mcp/protocolContext');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const {writePersonaCredential}=require('./secureshopPersonaCredentialWrite');
const fields=['platform_launch_id','platform_scenario_id','platform_launch_generation','original_platform_owner_id','original_platform_session_id'];
const where=fields.map((k,i)=>`${k}=$${i+1}`).join(' AND '),uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail=code=>Object.assign(Error('Bound password reset unavailable'),{code});
const coords=s=>[s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId];
const version=x=>typeof x==='string'&&/^[1-9]\d*$/.test(x)&&BigInt(x)<9007199254740991n;
function input(raw,reset=false){
 const x=structuredClone(raw);x.scope=createLaunchScope(x.scope);
 if(![x.actorId,x.targetId].every(n=>Number.isSafeInteger(n)&&n>0)||!uuid.test(x.actorSessionId)||!version(x.actorAuthorityVersion)||!uuid.test(x.operationId)||(reset&&(!version(x.expectedCredentialVersion)||!version(x.expectedAuthorityVersion))))throw fail('INVALID_ARGUMENT');
 if(x.actorId===x.targetId)throw fail('SELF_RESET_UNSUPPORTED');return x;
}
function validateFence(x,fence){const b=fence?.binding;if(typeof fence?.withPersonaEffect!=='function'||typeof fence?.assertRemoteAdmission!=='function'||!b||Object.keys(x.scope).some(k=>b[k]!==x.scope[k])||b.personaId!==x.actorId||b.sessionId!==x.actorSessionId||b.authorityVersion!==x.actorAuthorityVersion||b.role!=='admin')throw fail('SHOP_AUTH_INVALID');}
const CHECKS=Object.freeze([
 ['bound_password_reset_operations','password_reset_generation','CHECK ((platform_launch_generation > 0))'],
 ['bound_password_reset_operations','password_reset_owner','CHECK ((original_platform_owner_id > 0))'],
 ['bound_password_reset_operations','password_reset_session','CHECK ((original_platform_session_id > 0))'],
 ['bound_password_reset_operations','password_reset_actor_version','CHECK ((actor_authority_version > 0))'],
 ['bound_password_reset_operations','password_reset_target','CHECK (((target_id > 0) AND (target_id <> actor_id)))'],
 ['bound_password_reset_operations','password_reset_request_digest','CHECK ((octet_length(request_sha256) = 32))'],
 ['bound_password_reset_operations','password_reset_receipt_type',"CHECK ((jsonb_typeof(receipt_json) = 'object'::text))"],
 ['bound_password_reset_operations','password_reset_receipt_bytes','CHECK ((octet_length((receipt_json)::text) <= 4096))'],
 ['bound_password_reset_recovery','password_reset_envelope_type',"CHECK (((envelope_json IS NULL) OR (jsonb_typeof(envelope_json) = 'object'::text)))"],
 ['bound_password_reset_recovery','password_reset_envelope_bytes','CHECK (((envelope_json IS NULL) OR (octet_length((envelope_json)::text) <= 2048)))']
]);
function createBoundPasswordResetRepository({pool,auditStore,envelope,now=Date.now}={}){
 if(typeof pool?.query!=='function'||typeof auditStore?.append!=='function'||typeof envelope?.seal!=='function'||typeof envelope?.open!=='function')throw TypeError('Private reset dependencies required');
 async function effect(x,fence,work,mutating=false){validateFence(x,fence);await fence.assertRemoteAdmission();let completed=false;try{const result=await fence.withPersonaEffect(async c=>{await c.query("SET LOCAL statement_timeout='3000ms'");await c.query("SET LOCAL lock_timeout='3000ms'");await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`secureshop-persona-credential:${x.scope.launchId}:${x.targetId}`]);const value=await work(c);completed=true;return value;});await fence.assertRemoteAdmission();return result;}catch(error){if(mutating&&completed){const e=fail('PERSONA_EFFECT_OUTCOME_UNCERTAIN');Object.defineProperty(e,'cause',{value:error});throw e;}throw error;}}
 async function state(c,x){const s=x.scope;const row=(await c.query(`SELECT t.shop_user_id,COALESCE(st.effective_role,t.role) AS role,st.banned_at,st.ban_reason,COALESCE(st.authority_version,1)::text AS authority_version,COALESCE(cr.credential_version,1)::text AS credential_version
 FROM secureshop_agents.bound_persona_templates t LEFT JOIN secureshop_agents.bound_persona_state st ON ${fields.map((f,i)=>`st.${f}=$${i+1}`).join(' AND ')} AND st.shop_user_id=t.shop_user_id
 LEFT JOIN secureshop_agents.bound_persona_credentials cr ON ${fields.map((f,i)=>`cr.${f}=$${i+1}`).join(' AND ')} AND cr.shop_user_id=t.shop_user_id WHERE t.shop_user_id=$6`,[...coords(s),x.targetId])).rows[0];if(!row)throw fail('PERSONA_UNAVAILABLE');return row;}
 async function stored(c,x){const row=(await c.query(`SELECT * FROM secureshop_agents.bound_password_reset_operations WHERE ${where} AND operation_id=$6`,[...coords(x.scope),x.operationId])).rows[0];if(!row)return null;if(Number(row.actor_id)!==x.actorId||row.original_actor_session_id!==x.actorSessionId||String(row.actor_authority_version)!==x.actorAuthorityVersion||Number(row.target_id)!==x.targetId)throw fail('RESET_CONFLICT');const r=row.receipt_json,{receiptSha256,...body}=r;if(canonicalDigest(body)!==receiptSha256||canonicalDigest(r.scope)!==canonicalDigest(x.scope)||r.operationId!==x.operationId||r.actorId!==x.actorId||r.actorSessionId!==x.actorSessionId||r.actorAuthorityVersion!==x.actorAuthorityVersion||r.targetId!==x.targetId)throw fail('RESET_RECOVERY_UNAVAILABLE');return row;}
 async function recovery(c,x){return(await c.query(`SELECT envelope_json,expires_at FROM secureshop_agents.bound_password_reset_recovery WHERE ${where} AND operation_id=$6`,[...coords(x.scope),x.operationId])).rows[0];}
 async function available(c,x,row){const r=await recovery(c,x),s=await state(c,x);if(!r?.envelope_json||new Date(r.expires_at).getTime()<=now()||s.credential_version!==row.receipt_json.credentialVersion||s.authority_version!==row.receipt_json.authorityVersion)return false;try{envelope.open({receipt:row.receipt_json,envelope:r.envelope_json});return true;}catch{return false;}}
 const api={
  async checkReadiness(){const row=(await pool.query(`SELECT current_user AS role,
    has_table_privilege(current_user,'secureshop_agents.bound_password_reset_operations','SELECT') AND has_table_privilege(current_user,'secureshop_agents.bound_password_reset_operations','INSERT') AND has_table_privilege(current_user,'secureshop_agents.bound_password_reset_recovery','SELECT') AND has_table_privilege(current_user,'secureshop_agents.bound_password_reset_recovery','INSERT') AND has_column_privilege(current_user,'secureshop_agents.bound_password_reset_recovery','envelope_json','UPDATE') AS permitted,
    has_table_privilege(current_user,'secureshop_agents.bound_password_reset_operations','UPDATE,DELETE,TRUNCATE') OR has_table_privilege(current_user,'secureshop_agents.bound_password_reset_recovery','UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(current_user,'secureshop_agents.bound_password_reset_operations','UPDATE') OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='secureshop_agents.bound_password_reset_recovery'::regclass AND a.attnum>0 AND NOT a.attisdropped AND a.attname<>'envelope_json' AND has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE')) AS mutable,
    (SELECT count(*)=6 FROM pg_trigger WHERE tgenabled='O' AND tgqual IS NULL AND NOT tgisinternal AND (tgname,tgrelid,tgfoid,tgtype) IN (
      ('password_reset_operation_insert','secureshop_agents.bound_password_reset_operations'::regclass,'secureshop_agents.guard_bound_persona_admin_insert()'::regprocedure,7),
      ('password_reset_operation_immutable','secureshop_agents.bound_password_reset_operations'::regclass,'secureshop_agents.guard_bound_persona_admin_operation()'::regprocedure,27),
      ('password_reset_recovery_insert','secureshop_agents.bound_password_reset_recovery'::regclass,'secureshop_agents.guard_bound_persona_admin_insert()'::regprocedure,7),
      ('password_reset_recovery_immutable','secureshop_agents.bound_password_reset_recovery'::regclass,'secureshop_agents.guard_password_reset_recovery()'::regprocedure,27),
      ('password_reset_retirement','secureshop_agents.conversation_generation_retirements'::regclass,'secureshop_agents.cleanup_password_reset_recovery()'::regprocedure,5),
      ('password_reset_owner_delete','secureshop_agents.bound_audit_owner_deletion_receipts'::regclass,'secureshop_agents.cleanup_password_reset_recovery()'::regprocedure,5))) AS lifecycle,
    (SELECT count(*)=2 AND bool_and(NOT has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) FROM pg_proc p WHERE p.oid IN('secureshop_agents.guard_password_reset_recovery()'::regprocedure,'secureshop_agents.cleanup_password_reset_recovery()'::regprocedure)) AS private_functions`)).rows[0];if(row?.role!=='dvaia_secureshop_agents_runtime'||row.permitted!==true||row.mutable!==false||row.lifecycle!==true||row.private_functions!==true)throw fail('PASSWORD_RESET_NOT_READY');
   const constraints=(await pool.query(`SELECT c.conname,c.convalidated,c.conenforced,pg_get_constraintdef(c.oid,false) AS definition FROM unnest($1::text[],$2::text[]) expected(rel,name) JOIN pg_constraint c ON c.conrelid=to_regclass('secureshop_agents.'||expected.rel) AND c.conname=expected.name AND c.contype='c'`,[CHECKS.map(r=>r[0]),CHECKS.map(r=>r[1])])).rows;
   const normalize=value=>typeof value==='string'?value.replace(/\s+/g,' ').trim():null;
   if(constraints.length!==CHECKS.length||CHECKS.some(([,name,definition])=>{const c=constraints.find(r=>r.conname===name);return c?.convalidated!==true||c?.conenforced!==true||normalize(c?.definition)!==normalize(definition);}))throw fail('PASSWORD_RESET_NOT_READY');return{ready:true};},
  async versions({scope,targetId},fence){const b=fence?.binding,x={scope:createLaunchScope(scope),targetId,actorId:b?.personaId,actorSessionId:b?.sessionId,actorAuthorityVersion:b?.authorityVersion};if(!Number.isSafeInteger(targetId)||targetId<1)throw fail('INVALID_ARGUMENT');return effect(x,fence,async c=>{const row=await state(c,x);return{credentialVersion:row.credential_version,authorityVersion:row.authority_version};});},
  async reset(raw,fence){const x=input(raw,true);validateFence(x,fence);const digest=Buffer.from(canonicalDigest({scope:x.scope,actorId:x.actorId,actorSessionId:x.actorSessionId,actorAuthorityVersion:x.actorAuthorityVersion,targetId:x.targetId,operationId:x.operationId,expectedCredentialVersion:x.expectedCredentialVersion,expectedAuthorityVersion:x.expectedAuthorityVersion,action:'reset_password'}),'hex');
   const old=await effect(x,fence,c=>stored(c,x));if(old){if(!old.request_sha256.equals(digest))throw fail('RESET_CONFLICT');return{...await api.read(x,fence),replayed:true};}
   const secret=randomBytes(24).toString('base64url'),passwordHash=await bcrypt.hash(secret,10);
   return effect(x,fence,async c=>{const winner=await stored(c,x);if(winner){if(!winner.request_sha256.equals(digest))throw fail('RESET_CONFLICT');return{receipt:winner.receipt_json,replayed:true,secretAvailable:await available(c,x,winner)};}
    const target=await state(c,x);if(target.credential_version!==x.expectedCredentialVersion||target.authority_version!==x.expectedAuthorityVersion)throw fail('REVISION_CONFLICT');
    const credentialVersion=(BigInt(target.credential_version)+1n).toString(),authorityVersion=(BigInt(target.authority_version)+1n).toString();
    await c.query('SELECT secureshop_agents.revoke_admin_target_api_keys($1,$2,$3,$4,$5,$6,$7,$8)',[...coords(x.scope),x.actorId,x.actorSessionId,x.targetId]);
    await writePersonaCredential(c,{scope:x.scope,shopUserId:x.targetId,passwordHash,credentialVersion});
    await c.query(`INSERT INTO secureshop_agents.bound_persona_state (${fields.join(',')},shop_user_id,effective_role,banned_at,ban_reason,authority_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(${fields.join(',')},shop_user_id) DO UPDATE SET authority_version=EXCLUDED.authority_version`,[...coords(x.scope),x.targetId,target.role,target.banned_at,target.ban_reason,authorityVersion]);
    await c.query(`UPDATE secureshop_agents.bound_persona_sessions SET revoked_at=clock_timestamp() WHERE ${where} AND shop_user_id=$6 AND revoked_at IS NULL`,[...coords(x.scope),x.targetId]);
    const body={operationId:x.operationId,scope:x.scope,actorId:x.actorId,actorSessionId:x.actorSessionId,actorAuthorityVersion:x.actorAuthorityVersion,targetId:x.targetId,credentialVersion,authorityVersion,expiresAt:new Date(now()+600000).toISOString()},receipt={...body,receiptSha256:canonicalDigest(body)},sealed=envelope.seal({receipt,secret});
    await c.query(`INSERT INTO secureshop_agents.bound_password_reset_operations (${fields.join(',')},operation_id,actor_id,original_actor_session_id,actor_authority_version,target_id,request_sha256,receipt_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`,[...coords(x.scope),x.operationId,x.actorId,x.actorSessionId,x.actorAuthorityVersion,x.targetId,digest,JSON.stringify(receipt)]);
    await c.query(`INSERT INTO secureshop_agents.bound_password_reset_recovery (${fields.join(',')},operation_id,envelope_json,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`,[...coords(x.scope),x.operationId,JSON.stringify(sealed),receipt.expiresAt]);
    await auditStore.append(c,{eventId:x.operationId,scope:x.scope,persona:{id:x.actorId,role:'admin'},actor:'admin',action:'persona_admin_reset_password',target:String(x.targetId),paramsJson:JSON.stringify({targetId:x.targetId,credentialVersion,authorityVersion}),outcome:'completed',sourceKind:'persona_password_reset',sourceId:x.operationId});
    return{receipt,replayed:false,secretAvailable:true};
   },true);
  },
  async read(raw,fence){const x=input(raw);return effect(x,fence,async c=>{const row=await stored(c,x);return row?{receipt:row.receipt_json,secretAvailable:await available(c,x,row)}:null;});},
  async reveal(raw,fence){const x=input(raw);return effect(x,fence,async c=>{const row=await stored(c,x);if(!row)throw fail('RESET_OPERATION_NOT_FOUND');if(!await available(c,x,row))throw fail('RESET_RECOVERY_UNAVAILABLE');const r=await recovery(c,x);try{return{receipt:row.receipt_json,temporaryPassword:envelope.open({receipt:row.receipt_json,envelope:r.envelope_json})};}catch{throw fail('RESET_RECOVERY_UNAVAILABLE');}});},
  async acknowledge(raw,fence){const x=input(raw);return effect(x,fence,async c=>{const row=await stored(c,x);if(!row)throw fail('RESET_OPERATION_NOT_FOUND');await c.query(`UPDATE secureshop_agents.bound_password_reset_recovery SET envelope_json=NULL WHERE ${where} AND operation_id=$6`,[...coords(x.scope),x.operationId]);return{receipt:row.receipt_json,secretAvailable:false};},true);}
 };return Object.freeze(api);
}
module.exports={createBoundPasswordResetRepository,CHECKS};
