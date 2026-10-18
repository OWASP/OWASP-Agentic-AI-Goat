'use strict';
const {createHash}=require('node:crypto');
const manifest=require('./legacyFileSsiReadinessManifest.json');
const TABLES={identity:{legacy_file_ssi_resets:['status','lease_token','lease_expires_at','failure_code','updated_at','completed_at'],legacy_file_ssi_reset_steps:['status','attempts','failure_code','completed_at'],legacy_file_ssi_reset_authority:null},finflow:{legacy_file_ssi_cleanup_operations:null,legacy_file_ssi_cleanup_receipts:null}};
const REQUIRED_COLUMNS={
 identity:{
  legacy_file_ssi_resets:['operation_id','owner_id','from_generation','to_generation','status','lease_token','lease_expires_at','failure_code','created_at','updated_at','completed_at'],
  legacy_file_ssi_reset_steps:['operation_id','step_key','ordinal','status','attempts','failure_code','completed_at'],
  legacy_file_ssi_reset_authority:['owner_id']
 },
 finflow:{
  legacy_file_ssi_cleanup_operations:['operation_id','owner_id','from_generation','to_generation','created_at'],
  legacy_file_ssi_cleanup_receipts:['operation_id','step_key','owner_id','from_generation','to_generation','completed_at']
 }
};
function unavailable(){return Object.assign(new Error('Legacy file/SSI reset storage is not ready'),{code:'RESET_STORAGE_NOT_READY'});}
// Frozen candidate definition hashes avoid a production dependency on documentation paths.
async function assertLegacyFileSsiDefinitionReadiness(pool,schema){
 try{
  const expected=manifest[schema];if(!expected)throw unavailable();
  const rows=(await pool.query(`SELECT p.proname,p.prosrc,p.prosecdef,p.proconfig,r.rolname,
   oidvectortypes(p.proargtypes) AS argument_types,pg_get_function_result(p.oid) AS result_type,
   has_function_privilege(current_user,p.oid,'EXECUTE') AS executable,
   EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
   FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
   WHERE n.nspname=$1 AND p.proname=ANY($2::text[])`,[schema,expected.map(v=>v.name)])).rows;
  if(rows.length!==expected.length)throw unavailable();
  for(const e of expected){const matches=rows.filter(r=>r.proname===e.name),r=matches[0];if(matches.length!==1||r.argument_types!==e.arguments||r.result_type!==e.result||r.prosecdef!==e.definer||r.rolname!==`dvaia_${schema}_migration`||r.public_execute||r.executable!==e.execute||JSON.stringify(r.proconfig)!==JSON.stringify(e.config)||createHash('sha256').update(r.prosrc).digest('hex')!==e.hash)throw unavailable();}
  const expectedTriggers=manifest.triggers[schema];
  const triggers=(await pool.query(`SELECT t.tgname AS name,t.tgtype AS type,t.tgenabled AS enabled,
   n.nspname||'.'||c.relname AS table_name,pn.nspname||'.'||p.proname AS function_name,
   ARRAY(SELECT a.attname::text FROM unnest(t.tgattr::smallint[]) WITH ORDINALITY u(num,ord) JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=u.num ORDER BY u.ord) AS columns
   FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
   JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace pn ON pn.oid=p.pronamespace
   WHERE t.tgname=ANY($1::text[]) AND NOT t.tgisinternal`,[expectedTriggers.map(v=>v.name)])).rows;
  if(triggers.length!==expectedTriggers.length||expectedTriggers.some(e=>{const r=triggers.find(r=>r.name===e.name);return !r||r.enabled!=='O'||Number(r.type)!==e.type||r.table_name!==e.table||r.function_name!==e.function||JSON.stringify([...r.columns].sort())!==JSON.stringify([...e.columns].sort());}))throw unavailable();
  const tables=TABLES[schema];
  const columns=(await pool.query(`SELECT c.relname,a.attname,
   has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS table_write,
   has_column_privilege(current_user,c.oid,a.attnum,'SELECT') AS readable,
   has_column_privilege(current_user,c.oid,a.attnum,'UPDATE') AS writable,
   has_column_privilege(current_user,c.oid,a.attnum,'INSERT,REFERENCES') AS extra_write
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
   WHERE n.nspname=$1 AND c.relname=ANY($2::text[]) AND a.attnum>0 AND NOT a.attisdropped`,[schema,Object.keys(tables)])).rows;
  if(new Set(columns.map(r=>r.relname)).size!==Object.keys(tables).length)throw unavailable();
  for(const [table,names] of Object.entries(REQUIRED_COLUMNS[schema])){const present=new Set(columns.filter(r=>r.relname===table).map(r=>r.attname));if(names.some(name=>!present.has(name)))throw unavailable();}
  for(const r of columns){const update=tables[r.relname];if(r.table_write||r.extra_write||r.readable!==(update!==null)||r.writable!==(update?.includes(r.attname)===true))throw unavailable();}
  return true;
 }catch(error){if(error.code==='RESET_STORAGE_NOT_READY')throw error;throw unavailable();}
}
module.exports={assertLegacyFileSsiDefinitionReadiness};
