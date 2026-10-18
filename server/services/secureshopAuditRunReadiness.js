'use strict';
const TABLES={
  bound_audit_runs:['run_id','request_id','launch_id','scenario_id','generation','original_platform_owner_id',
    'original_platform_session_id','shop_user_id','owner_key','durable_generation','effect_key','requested_count','row_count','provider','model','summary'],
  bound_audit_run_artifacts:['run_id','artifact','bytes','sha256'],
  bound_audit_run_chunks:['run_id','artifact','ordinal','content'],
  bound_audit_run_publications:['run_id'],
  bound_audit_run_deletion_receipts:[],
};
async function assertSecureShopAuditRunReadiness({pool}={}){
  const unavailable=()=>Object.assign(new Error('Audit run storage is not ready'),{code:'SECURESHOP_AUDIT_RUN_UNAVAILABLE'});
  if(typeof pool?.query!=='function')throw unavailable();
  const role=(await pool.query('SELECT current_user AS role')).rows[0]?.role;
  if(role!=='dvaia_secureshop_agents_runtime')throw unavailable();
  for(const [name,writable] of Object.entries(TABLES)){
    const table=`secureshop_agents.${name}`;
    if(!(await pool.query('SELECT to_regclass($1) AS relation',[table])).rows[0]?.relation)throw unavailable();
    const result=(await pool.query(`SELECT has_table_privilege(current_user,$1,'SELECT') AS readable,
      NOT has_table_privilege(current_user,$1,'UPDATE,DELETE,TRUNCATE')
        AND NOT has_any_column_privilege(current_user,$1,'UPDATE') AS immutable,
      NOT has_table_privilege(current_user,$1,'INSERT') AS restricted_insert,
      NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=to_regclass($1)
        AND a.attnum>0 AND NOT a.attisdropped
        AND has_column_privilege(current_user,$1,a.attname,'INSERT') <> (a.attname=ANY($2::text[]))) AS exact_insert
      `,[table,writable])).rows[0];
    if(!result||Object.values(result).some(value=>value!==true))throw unavailable();
  }
  const fn='secureshop_agents.destroy_bound_audit_runs(integer,uuid)';
  if(!(await pool.query('SELECT to_regprocedure($1) AS routine',[fn])).rows[0]?.routine)throw unavailable();
  const result=(await pool.query(`SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed,
    NOT EXISTS (SELECT 1 FROM pg_proc p,LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
      WHERE p.oid=to_regprocedure($1) AND a.grantee=0 AND a.privilege_type='EXECUTE') AS private,
    EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='secureshop_agents.agent_sessions'::regclass
      AND conname='agent_sessions_conversation_purpose_shape' AND convalidated
      AND position('secureshop_audit_summary' in pg_get_constraintdef(oid))>0) AS purpose`,[fn])).rows[0];
  if(!result||Object.values(result).some(value=>value!==true))throw unavailable();
  const triggers=(await pool.query(`SELECT count(*)::integer AS count FROM pg_trigger t
    JOIN (VALUES
      ('bound_audit_runs','bound_audit_runs_insert','guard_bound_audit_run_insert'),
      ('bound_audit_run_artifacts','bound_audit_artifacts_insert','guard_bound_audit_run_insert'),
      ('bound_audit_run_chunks','bound_audit_chunks_insert','guard_bound_audit_run_insert'),
      ('bound_audit_run_publications','bound_audit_publications_insert','guard_bound_audit_run_insert'),
      ('bound_audit_run_publications','bound_audit_publications_validate','validate_bound_audit_publication')
    ) expected(relation,trigger_name,routine) ON t.tgrelid=to_regclass('secureshop_agents.'||expected.relation)
      AND t.tgname=expected.trigger_name
      AND t.tgfoid=to_regprocedure('secureshop_agents.'||expected.routine||'()')
    WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgtype=7`)).rows[0]?.count;
  if(triggers!==5)throw unavailable();
  return true;
}
module.exports={assertSecureShopAuditRunReadiness};
