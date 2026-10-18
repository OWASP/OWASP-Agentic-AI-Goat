'use strict';
const {withTransaction}=require('./index');
const {assertCurrentAuditScope}=require('./secureshopAuditQueryRepository');
const {receiptFor,durableSnapshotFor,restoreAdmittedSnapshot}=require('../../services/secureshopOwnedAuditSearchSnapshot');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
// PostgreSQL's parsed CHECK tree, retaining parentheses/operators and constants.
const SNAPSHOT_CHECK = `CHECK (((snapshot_json IS NULL) OR ((jsonb_typeof(snapshot_json) = 'object'::text) AND ((snapshot_json - ARRAY['version'::text, 'sources'::text]) = '{}'::jsonb) AND (snapshot_json ?& ARRAY['version'::text, 'sources'::text]) AND ((snapshot_json -> 'version'::text) = '1'::jsonb) AND (jsonb_typeof((snapshot_json -> 'sources'::text)) = 'array'::text) AND (jsonb_array_length((snapshot_json -> 'sources'::text)) <= 200) AND (octet_length((snapshot_json)::text) <= 16777216))))`;
const normalizeCheck=value=>typeof value==='string'?value.replace(/\s+/g,' ').trim():null;
function createAuditTargetAdmissionRepository({pool}){
 return Object.freeze({
  async checkReadiness(){const row=(await pool.query("SELECT (has_table_privilege(current_user,'identity.secureshop_audit_target_admissions','SELECT') AND has_table_privilege(current_user,'identity.secureshop_audit_target_admissions','INSERT')) AS permitted,has_table_privilege(current_user,'identity.secureshop_audit_target_admissions','UPDATE,DELETE,TRUNCATE') AS mutable,has_any_column_privilege(current_user,'identity.secureshop_audit_target_admissions','UPDATE') AS columns, EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='identity' AND table_name='secureshop_audit_target_admissions' AND column_name='snapshot_json') AS snapshot_ready")).rows[0];if(row?.snapshot_ready!==true||!row?.permitted||row.mutable||row.columns)throw Error('Audit target admission privileges unavailable');
   const integrity=(await pool.query(`SELECT
    (SELECT count(*)=3 FROM (VALUES
      ('identity.secureshop_audit_target_admissions','secureshop_audit_target_snapshot_immutable','identity.guard_secureshop_audit_target_snapshot()',31),
      ('identity.secureshop_launches','redact_audit_target_on_launch','identity.redact_secureshop_audit_target_snapshot()',17),
      ('identity.users','redact_audit_target_on_owner_delete','identity.redact_secureshop_audit_target_snapshot()',9)
    ) expected(rel,name,func,kind) JOIN pg_trigger t ON t.tgrelid=to_regclass(expected.rel) AND t.tgname=expected.name AND t.tgfoid=to_regprocedure(expected.func) AND t.tgtype=expected.kind AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgqual IS NULL) AS triggers_ready,
    (SELECT count(*)=2 AND bool_and(NOT has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) FROM pg_proc p WHERE p.oid IN(to_regprocedure('identity.guard_secureshop_audit_target_snapshot()'),to_regprocedure('identity.redact_secureshop_audit_target_snapshot()'))) AS functions_private`)).rows[0];
   if(integrity?.triggers_ready!==true||integrity?.functions_private!==true)throw Error('Audit target snapshot lifecycle unavailable');
   const constraint=(await pool.query("SELECT convalidated,conenforced,pg_get_constraintdef(oid,false) AS definition FROM pg_constraint WHERE conrelid='identity.secureshop_audit_target_admissions'::regclass AND conname='audit_target_snapshot_shape' AND contype='c'")).rows;
   if(constraint.length!==1||constraint[0].convalidated!==true||constraint[0].conenforced!==true||normalizeCheck(constraint[0].definition)!==normalizeCheck(SNAPSHOT_CHECK))throw Error('Audit target snapshot bound constraint unavailable');} ,
  async readSnapshot({binding:input}){
   const binding=createLaunchScope(input);return withTransaction(pool,async client=>{await assertCurrentAuditScope(client,binding,null);const row=(await client.query('SELECT * FROM identity.secureshop_audit_target_admissions WHERE launch_id=$1 AND generation=$2',[binding.launchId,binding.generation])).rows[0];if(!row)return null;
    if(row.scenario_id!==binding.scenarioId||Number(row.platform_session_id)!==binding.platformSessionId||Number(row.original_platform_owner_id)!==binding.platformOwnerId)throw Error('Audit target admission scope conflict');
    if(row.snapshot_json===null||row.snapshot_json===undefined)throw Object.assign(Error('Original admitted audit snapshot unavailable; retire the target through reset'),{code:'AUDIT_TARGET_SNAPSHOT_UNAVAILABLE'});
    return restoreAdmittedSnapshot({binding,snapshot:row.snapshot_json,sourceSha256:row.source_sha256,payloadSha256:row.payload_sha256});
   });
  },
  async admit({binding:input,sourceSha256,payloadSha256,snapshot}){
   const binding=createLaunchScope(input);if(!/^[a-f0-9]{64}$/.test(sourceSha256)||!/^[a-f0-9]{64}$/.test(payloadSha256))throw TypeError('Verified audit snapshot identity required');
   const receipt=snapshot===undefined?null:receiptFor(snapshot);if(snapshot!==undefined&&(!receipt||JSON.stringify(createLaunchScope(receipt.binding))!==JSON.stringify(binding)||receipt.sourcesSha256!==sourceSha256||receipt.payloadSha256!==payloadSha256))throw TypeError('Verified admitted snapshot required');
   const stored=snapshot===undefined?null:durableSnapshotFor(snapshot);
   return withTransaction(pool,async client=>{await assertCurrentAuditScope(client,binding,null);
    await client.query('INSERT INTO identity.secureshop_audit_target_admissions(launch_id,generation,scenario_id,platform_session_id,user_id,original_platform_owner_id,source_sha256,payload_sha256,snapshot_json) VALUES($1,$2,$3,$4,(SELECT platform_user_id FROM identity.secureshop_authority_owners WHERE id=$5),$5,$6,$7,$8::jsonb) ON CONFLICT(launch_id,generation) DO NOTHING',[binding.launchId,binding.generation,binding.scenarioId,binding.platformSessionId,binding.platformOwnerId,sourceSha256,payloadSha256,stored===null?null:JSON.stringify(stored)]);
    const row=(await client.query('SELECT * FROM identity.secureshop_audit_target_admissions WHERE launch_id=$1 AND generation=$2',[binding.launchId,binding.generation])).rows[0];
    if(row.scenario_id!==binding.scenarioId||Number(row.platform_session_id)!==binding.platformSessionId||Number(row.original_platform_owner_id)!==binding.platformOwnerId||row.source_sha256!==sourceSha256||row.payload_sha256!==payloadSha256)throw Object.assign(Error('Audit target admission conflict'),{code:'AUDIT_TARGET_ADMISSION_CONFLICT'});if(snapshot!==undefined&&(row.snapshot_json===null||row.snapshot_json===undefined))throw Object.assign(Error('Original admitted audit snapshot unavailable; retire the target through reset'),{code:'AUDIT_TARGET_SNAPSHOT_UNAVAILABLE'});if(snapshot!==undefined)restoreAdmittedSnapshot({binding,snapshot:row.snapshot_json,sourceSha256,payloadSha256});return{admitted:true};
   });
  }
 });
}
module.exports={createAuditTargetAdmissionRepository,SNAPSHOT_CHECK};
