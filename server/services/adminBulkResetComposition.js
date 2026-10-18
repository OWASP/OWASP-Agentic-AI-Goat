'use strict';
const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const sql=['0084_admin_bulk_reset_cohort.sql','0085_admin_bulk_xss_replay.sql','0086_admin_bulk_secureshop_replay.sql','0088_admin_bulk_reset_scope_discovery.sql',...(fs.existsSync(path.join(__dirname,'../../db/postgres/identity-migrations/0093_admin_bulk_legacy_file_ssi_replay.sql'))?['0093_admin_bulk_legacy_file_ssi_replay.sql']:[])].map(file=>fs.readFileSync(path.join(__dirname,'../../db/postgres/identity-migrations',file),'utf8')).join('\n');
const expected=new Map([...sql.matchAll(/CREATE (?:OR REPLACE )?FUNCTION identity\.(\w+)\([\s\S]*?\) RETURNS[\s\S]*?\$\$([\s\S]*?)\$\$;/g)].map(m=>[m[1],createHash('sha256').update(m[2]).digest('hex')]));
const signatures=new Map([
 ['assert_bulk_reset_actor',['integer, bigint','void']],
 ['bulk_reset_snapshot',['uuid','jsonb']],
 ['begin_bulk_reset',['uuid, integer, bigint, text, text[]','jsonb']],
 ['claim_bulk_reset_child',['uuid, integer, bigint, integer, uuid, boolean','jsonb']],
 ['finish_bulk_reset_child',['uuid, integer, bigint, integer, uuid, boolean, text','void']],
 ['list_bulk_resets',['integer, bigint','jsonb']],
 ['list_bulk_resets_for_scope',['integer, bigint, text, text','jsonb']],
]);
const publicFunctions=new Set(['begin_bulk_reset','claim_bulk_reset_child','finish_bulk_reset_child','list_bulk_resets','list_bulk_resets_for_scope']);
function unavailable(){return Object.assign(new Error('Durable bulk reset storage is not ready'),{code:'RESET_STORAGE_NOT_READY',statusCode:503});}
async function assertAdminBulkResetReadiness(pool){
 try{
 const rows=(await pool.query(`SELECT p.proname,p.prosrc,p.prosecdef,p.proconfig,r.rolname,oidvectortypes(p.proargtypes) AS argument_types,pg_get_function_result(p.oid) AS result_type,
 has_function_privilege(current_user,p.oid,'EXECUTE') AS executable,
 EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
 WHERE n.nspname='identity' AND p.proname=ANY($1::text[])`,[[...expected.keys()]])).rows;
 if(expected.size!==7||rows.length!==expected.size||rows.some(row=>row.argument_types!==signatures.get(row.proname)?.[0]||row.result_type!==signatures.get(row.proname)?.[1]||createHash('sha256').update(row.prosrc).digest('hex')!==expected.get(row.proname)||!row.prosecdef||row.rolname!=='dvaia_identity_migration'||row.public_execute||row.executable!==publicFunctions.has(row.proname)||JSON.stringify(row.proconfig)!==JSON.stringify(['search_path=pg_catalog'])))throw unavailable();
 const tables=(await pool.query(`SELECT c.relname,has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS direct_access,has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES') AS column_access
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='identity' AND c.relname=ANY($1::text[])`,[['bulk_reset_operations','bulk_reset_children']])).rows;
 if(tables.length!==2||tables.some(t=>t.direct_access||t.column_access))throw unavailable();return true;
 }catch(error){if(error.code==='RESET_STORAGE_NOT_READY')throw error;throw unavailable();}
}
function createAdminBulkResetComposition({pool,identityAdapter,createLeasePool}){
 if(typeof pool?.query!=='function'||typeof identityAdapter?.validateSession!=='function'||typeof createLeasePool!=='function')throw new TypeError('Bulk reset identity and dedicated lease pool required');
 let journal;
 function repository(){if(!journal)journal=require('../database/postgres/adminBulkResetRepository').createAdminBulkResetRepository(pool,{leasePool:createLeasePool()});return journal;}
 return Object.freeze({
 bulkJournal:Object.freeze({async withOperation(operationId,work){await assertAdminBulkResetReadiness(pool);return repository().withOperation(operationId,work);},async listPending(authority,scope){await assertAdminBulkResetReadiness(pool);return repository().listPending(authority,scope);}}),
 async resolveBulkActor(request){
 const token=require('../middleware/bearerToken').readBearerAuthorization(request).token;
 let found;try{found=token&&await identityAdapter.validateSession(token);}catch(error){if(!['JsonWebTokenError','TokenExpiredError','NotBeforeError','AccountLocked'].includes(error.name))throw error;}
 if(!found||String(found.user.id)!==String(request?.user?.id)||String(found.session.id)!==String(request?.identitySession?.id))throw Object.assign(new Error('Current administrator session required'),{code:'BULK_RESET_AUTHORITY_REJECTED',statusCode:401});
 return{actorId:Number(found.user.id),sessionId:String(found.session.id)};
 },assertReady:()=>assertAdminBulkResetReadiness(pool)
 });
}
module.exports={assertAdminBulkResetReadiness,createAdminBulkResetComposition};
