'use strict';
const fail=()=>Object.assign(new Error('Bound System rebuild database unavailable'),{code:'SYSTEM_REBUILD_NOT_READY'});
async function assertSystemRebuildReadiness(pool,{policyRebuildEnabled=false}={}){
 if(typeof pool?.query!=='function')throw new TypeError('System rebuild readiness pool required');
 if(typeof policyRebuildEnabled!=='boolean')throw new TypeError('System rebuild readiness option required');
 const role=(await pool.query('SELECT current_user AS role')).rows[0]?.role;
 if(role!=='dvaia_secureshop_review_runtime')throw fail();
 const table='secureshop_review.bound_system_rebuild_operations';
 for(const privilege of ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']){
  const allowed=(await pool.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[table,privilege])).rows[0]?.allowed;
  if(allowed!==(privilege==='SELECT'||privilege==='INSERT'))throw fail();
 }
 const columns=(await pool.query("SELECT attname,has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS writable FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum",[table])).rows;
 if(!columns.some(row=>row.attname==='operation_mode')||!columns.some(row=>row.attname==='base_revision_id'))throw fail();
 const writable=columns.filter(row=>row.writable).map(row=>row.attname).sort();
 const expected=['completed_at','document_count','failure_code','revision_id','started_at','state','vector_sha256','worker_token'].sort();
 if(JSON.stringify(writable)!==JSON.stringify(expected))throw fail();
 const receipt='secureshop_review.bound_system_rebuild_owner_deletion_receipts';
 if((await pool.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[receipt,'SELECT'])).rows[0]?.allowed!==true)throw fail();
 for(const privilege of ['INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])if((await pool.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[receipt,privilege])).rows[0]?.allowed!==false)throw fail();
 const triggers=(await pool.query(`SELECT n.nspname||'.'||c.relname AS relation,t.tgname,t.tgenabled,
   pn.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')' AS function_identity
  FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace pn ON pn.oid=p.pronamespace
  WHERE NOT t.tgisinternal AND n.nspname='secureshop_review'
   AND t.tgname=ANY($1::text[]) ORDER BY t.tgname`,[Object.freeze(['bound_system_rebuild_operation_guard','bound_system_rebuild_owner_receipt_guard','product_target_rebuild_retirement'])])).rows;
 const expectedTriggers=[
  ['secureshop_review.bound_system_rebuild_operations','bound_system_rebuild_operation_guard','secureshop_review.guard_bound_system_rebuild_operation()'],
  ['secureshop_review.bound_system_rebuild_owner_deletion_receipts','bound_system_rebuild_owner_receipt_guard','secureshop_review.guard_bound_system_rebuild_owner_receipt()'],
  ['secureshop_review.product_targets','product_target_rebuild_retirement','secureshop_review.retire_bound_system_rebuild_operations()'],
 ].sort((a,b)=>a[1].localeCompare(b[1]));
 if(triggers.length!==expectedTriggers.length||triggers.some((row,index)=>row.relation!==expectedTriggers[index][0]||row.tgname!==expectedTriggers[index][1]||row.function_identity!==expectedTriggers[index][2]||!['O','A'].includes(row.tgenabled)))throw fail();
 const functions=[
  ['secureshop_review.destroy_bound_audit_owner(integer,uuid)',true],
  ['secureshop_review.initialize_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,jsonb)',true],
  ['secureshop_review.guard_bound_system_rebuild_operation()',false],
  ['secureshop_review.guard_bound_system_rebuild_owner_receipt()',false],
  ['secureshop_review.retire_bound_system_rebuild_operations()',false],
 ];
 for(const [identity,allowed] of functions){
  const row=(await pool.query(`SELECT has_function_privilege(current_user,p.oid,'EXECUTE') AS runtime,
    EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
      WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public
    FROM pg_proc p WHERE p.oid=$1::regprocedure`,[identity])).rows[0];
  if(row?.runtime!==allowed||row?.public!==false)throw fail();
 }
 if(policyRebuildEnabled){
  if(!columns.some(row=>row.attname==='policy_version')||!columns.some(row=>row.attname==='policy_snapshot_sha256'))throw fail();
  for(const policyTable of ['secureshop_review.bound_system_policy_imports','secureshop_review.bound_system_policy_import_documents']){
   for(const privilege of ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']){
    const allowed=(await pool.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[policyTable,privilege])).rows[0]?.allowed;
    if(allowed!==(privilege==='SELECT'||privilege==='INSERT'))throw fail();
   }
  }
  for(const privilege of ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']){
   const allowed=(await pool.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',['secureshop_review.policy_embedding_lineage',privilege])).rows[0]?.allowed;
   if(allowed!==(privilege==='SELECT'))throw fail();
  }
  if((await pool.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',['secureshop_review.product_target_retrieval_documents','DELETE'])).rows[0]?.allowed!==false)throw fail();
  const policyTriggers=(await pool.query(`SELECT n.nspname||'.'||c.relname AS relation,t.tgname,t.tgenabled,
   pn.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')' AS function_identity
  FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace pn ON pn.oid=p.pronamespace
  WHERE NOT t.tgisinternal AND n.nspname='secureshop_review'
   AND t.tgname=ANY($1::text[]) ORDER BY t.tgname`,[Object.freeze(['a_bind_policy_embedding_revision','bound_policy_rebuild_fields_guard','bound_system_policy_import_document_guard','bound_system_policy_import_guard','policy_embedding_lineage_immutable'])])).rows;
  const expectedPolicyTriggers=[
   ['secureshop_review.product_target_embedding_revisions','a_bind_policy_embedding_revision','secureshop_review.bind_policy_embedding_revision()'],
   ['secureshop_review.bound_system_rebuild_operations','bound_policy_rebuild_fields_guard','secureshop_review.guard_bound_policy_rebuild_fields()'],
   ['secureshop_review.bound_system_policy_import_documents','bound_system_policy_import_document_guard','secureshop_review.guard_bound_system_policy_import_document()'],
   ['secureshop_review.bound_system_policy_imports','bound_system_policy_import_guard','secureshop_review.guard_bound_system_policy_import()'],
   ['secureshop_review.policy_embedding_lineage','policy_embedding_lineage_immutable','secureshop_review.guard_product_retrieval_immutable()'],
  ].sort((a,b)=>a[1].localeCompare(b[1]));
  if(policyTriggers.length!==expectedPolicyTriggers.length||policyTriggers.some((row,index)=>row.relation!==expectedPolicyTriggers[index][0]||row.tgname!==expectedPolicyTriggers[index][1]||row.function_identity!==expectedPolicyTriggers[index][2]||!['O','A'].includes(row.tgenabled)))throw fail();
  for(const [identity,allowed] of [
   ['secureshop_review.bound_policy_source_digest(uuid,bigint,jsonb)',true],
   ['secureshop_review.publish_bound_policy_embedding_revision(uuid,uuid,jsonb)',true],
   ['secureshop_review.publish_embedding_with_policy_lineage(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb)',true],
   ['secureshop_review.bind_policy_embedding_revision()',false],
   ['secureshop_review.guard_bound_policy_rebuild_fields()',false],
   ['secureshop_review.guard_bound_system_policy_import()',false],
   ['secureshop_review.guard_bound_system_policy_import_document()',false],
  ]){
   const row=(await pool.query(`SELECT has_function_privilege(current_user,p.oid,'EXECUTE') AS runtime,
    EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
      WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public
    FROM pg_proc p WHERE p.oid=$1::regprocedure`,[identity])).rows[0];
   if(row?.runtime!==allowed||row?.public!==false)throw fail();
  }
 }
 return Object.freeze({ready:true});
}
module.exports={assertSystemRebuildReadiness};
