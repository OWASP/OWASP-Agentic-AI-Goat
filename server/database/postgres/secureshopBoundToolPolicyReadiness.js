'use strict';
const ROLE='dvaia_secureshop_agents_runtime';
const TABLES=Object.freeze({bound_tool_policy_heads:{required:['SELECT','INSERT','UPDATE'],checks:5},bound_tool_policy_overrides:{required:['SELECT','INSERT','UPDATE'],checks:5,foreign:1},bound_tool_policy_operations:{required:['SELECT','INSERT'],checks:10},bound_tool_admissions:{required:['SELECT','INSERT'],checks:14,unique:1},bound_tool_policy_cleanup_receipts:{required:['SELECT'],checks:6},bound_tool_registry_upgrades:{required:['SELECT','INSERT'],checks:11},bound_tool_registry_upgrade_cleanup_receipts:{required:['SELECT'],checks:3}});
const FUNCTIONS=Object.freeze(['guard_bound_tool_policy_write','guard_bound_tool_policy_history','guard_bound_tool_policy_delete','guard_bound_tool_admission_actor','cleanup_bound_tool_policy','guard_bound_tool_registry_upgrade','guard_bound_tool_registry_head','guard_bound_tool_registry_upgrade_commit','cleanup_bound_tool_registry_upgrades']);
const TRIGGERS=Object.freeze([
 ['bound_tool_policy_cleanup_receipts','bound_tool_cleanup_immutable','guard_bound_audit_owner_deletion_receipt',27],
 ...['heads','overrides'].flatMap(name=>[[`bound_tool_policy_${name}`,`a_bound_tool_policy_${name}_fence`,'guard_bound_tool_policy_write',23],[`bound_tool_policy_${name}`,`z_bound_tool_policy_${name}_guard`,'guard_bound_tool_policy_delete',11]]),
 ...['bound_tool_policy_operations','bound_tool_admissions'].flatMap(table=>[[table,`a_${table}_fence`,'guard_bound_tool_policy_write',7],[table,`z_${table}_guard`,'guard_bound_tool_policy_history',27],[table,`b_${table}_actor`,'guard_bound_tool_admission_actor',7]]),
 ['conversation_generation_retirements','cleanup_bound_tool_policy_retirement','cleanup_bound_tool_policy',5],
 ['bound_audit_owner_deletion_receipts','cleanup_bound_tool_policy_owner','cleanup_bound_tool_policy',5],
 ['bound_tool_registry_upgrades','a_bound_tool_registry_upgrade_fence','guard_bound_tool_policy_write',7],
 ['bound_tool_registry_upgrades','b_bound_tool_registry_upgrade_guard','guard_bound_tool_registry_upgrade',31],
 ['bound_tool_registry_upgrades','c_bound_tool_registry_upgrade_commit','guard_bound_tool_registry_upgrade_commit',5],
 ['bound_tool_policy_heads','b_bound_tool_registry_head_guard','guard_bound_tool_registry_head',19],
 ['bound_tool_registry_upgrade_cleanup_receipts','z_bound_tool_registry_upgrade_cleanup_immutable','guard_bound_audit_owner_deletion_receipt',27],
 ['bound_audit_owner_deletion_receipts','cleanup_bound_tool_registry_upgrade_owner','cleanup_bound_tool_registry_upgrades',5],
]);
const SPECS=Object.freeze(Object.entries(TABLES).flatMap(([table,{required}])=>['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'].map(privilege=>Object.freeze({table,privilege,expected:required.includes(privilege)}))));
const fail=()=>Object.assign(new Error('Bound tool policy schema or privileges unavailable'),{code:'BOUND_TOOL_POLICY_NOT_READY'});
const REGISTRY_UPGRADE_DENIAL_LENGTHS=Object.freeze([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,69,70,71,73,74,75,76,77]);
const REGISTRY_UPGRADE_DENIAL_CONSTRAINT=`CHECK (((jsonb_typeof(added_denials) = 'array'::text) AND (jsonb_array_length(added_denials) = ANY (ARRAY[${REGISTRY_UPGRADE_DENIAL_LENGTHS.join(',')}]))))`;
const normalizedConstraint=value=>String(value||'').replace(/\s+/g,'');
async function assertBoundToolPolicyReadiness(pool){
 if(typeof pool?.query!=='function')throw TypeError('Bound tool policy runtime pool required');
 try{
  const identity=await pool.query("SELECT current_user AS runtime_role,has_schema_privilege(current_user,'secureshop_agents','USAGE') AS schema_usage");if(identity.rows.length!==1||identity.rows[0].runtime_role!==ROLE||identity.rows[0].schema_usage!==true)throw fail();
  const grants=await pool.query(`SELECT x.ordinality::int AS ordinal,
   COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.'||x.table_name),x.privilege),false) AS allowed,
   to_regclass('secureshop_agents.'||x.table_name) IS NOT NULL AS present
   FROM unnest($1::text[],$2::text[]) WITH ORDINALITY x(table_name,privilege,ordinality) ORDER BY x.ordinality`,[SPECS.map(x=>x.table),SPECS.map(x=>x.privilege)]);
  if(grants.rows.length!==SPECS.length||grants.rows.some((r,i)=>r.ordinal!==i+1||r.present!==true||r.allowed!==SPECS[i].expected))throw fail();
  const functions=await pool.query(`SELECT x.ordinality::int AS ordinal,p.oid IS NOT NULL AS present,p.prosecdef AS definer,
   COALESCE(has_function_privilege(current_user,p.oid,'EXECUTE'),false) AS runtime_execute,
   EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute,
   replace(array_to_string(p.proconfig,','),' ','')='search_path=pg_catalog,secureshop_agents' AS safe_path
   FROM unnest($1::text[]) WITH ORDINALITY x(name,ordinality)
   LEFT JOIN pg_proc p ON p.oid=to_regprocedure('secureshop_agents.'||x.name||'()') ORDER BY x.ordinality`,[FUNCTIONS]);
  if(functions.rows.length!==FUNCTIONS.length||functions.rows.some((r,i)=>r.ordinal!==i+1||r.present!==true||r.definer!==true||r.runtime_execute!==false||r.public_execute!==false||r.safe_path!==true))throw fail();
  const triggers=await pool.query(`SELECT x.ordinality::int AS ordinal,t.tgenabled,t.tgtype::int AS type,
    t.tgfoid=to_regprocedure('secureshop_agents.'||x.function_name||'()') AS correct_function,
    t.tgqual IS NULL AND t.tgnargs=0 AND NOT t.tgisinternal AS unconditional
    FROM unnest($1::text[],$2::text[],$3::text[]) WITH ORDINALITY x(table_name,trigger_name,function_name,ordinality)
    LEFT JOIN pg_trigger t ON t.tgrelid=to_regclass('secureshop_agents.'||x.table_name) AND t.tgname=x.trigger_name ORDER BY x.ordinality`,[TRIGGERS.map(x=>x[0]),TRIGGERS.map(x=>x[1]),TRIGGERS.map(x=>x[2])]);
  if(triggers.rows.length!==TRIGGERS.length||triggers.rows.some((r,i)=>r.ordinal!==i+1||!['O','A'].includes(r.tgenabled)||r.type!==TRIGGERS[i][3]||r.correct_function!==true||r.unconditional!==true))throw fail();
  const constraints=await pool.query(`SELECT x.ordinality::int AS ordinal,
   count(c.oid) FILTER(WHERE c.contype='c')::int AS checks,count(c.oid) FILTER(WHERE c.contype='p')::int AS primary_keys,
   count(c.oid) FILTER(WHERE c.contype='u')::int AS uniques,count(c.oid) FILTER(WHERE c.contype='f')::int AS foreign_keys,
   COALESCE(bool_and(c.convalidated AND NOT c.condeferrable),false) AS validated
   FROM unnest($1::text[]) WITH ORDINALITY x(table_name,ordinality)
   LEFT JOIN pg_constraint c ON c.conrelid=to_regclass('secureshop_agents.'||x.table_name) AND c.contype IN ('c','p','u','f') GROUP BY x.ordinality ORDER BY x.ordinality`,[Object.keys(TABLES)]);
  const definitions=Object.values(TABLES);
  if(constraints.rows.length!==definitions.length||constraints.rows.some((r,i)=>r.ordinal!==i+1||r.checks!==definitions[i].checks||r.primary_keys!==1||r.uniques!==(definitions[i].unique||0)||r.foreign_keys!==(definitions[i].foreign||0)||r.validated!==true))throw fail();
  const successor=await pool.query(`SELECT
   (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
    FROM pg_constraint c CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY k(attnum,ordinality)
    JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
    WHERE c.conrelid='secureshop_agents.bound_tool_registry_upgrades'::regclass AND c.contype='p') AS primary_columns,
   EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='secureshop_agents.bound_tool_registry_upgrades'::regclass
    AND conname='bound_tool_registry_successor_v36' AND contype='c' AND convalidated) AS successor_constraint,
   (SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='secureshop_agents.bound_tool_registry_upgrades'::regclass
    AND conname='bound_tool_registry_upgrades_added_denials_check' AND contype='c' AND convalidated) AS added_denials_constraint,
   (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc
    WHERE oid=to_regprocedure('secureshop_agents.guard_bound_tool_registry_upgrade()')) AS upgrade_guard_sha256,
   (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc
    WHERE oid=to_regprocedure('secureshop_agents.guard_bound_tool_registry_head()')) AS head_guard_sha256`);
  const row=successor.rows[0];
  if(successor.rows.length!==1||row.successor_constraint!==true
   ||JSON.stringify(row.primary_columns)!==JSON.stringify(['platform_launch_id','platform_scenario_id','platform_launch_generation','original_platform_owner_id','original_platform_session_id','successor_version'])
   ||normalizedConstraint(row.added_denials_constraint)!==normalizedConstraint(REGISTRY_UPGRADE_DENIAL_CONSTRAINT)
   ||row.upgrade_guard_sha256!=='fdc3c3b3e51dfc3e2feb57c8ab53ffdce131c2c42032feba9db8a2fea5b0c9c2'
   ||row.head_guard_sha256!=='6830fb9d9680c1150204c3f3991345be6692008cae800e035b5e06e6b1549d95')throw fail();
  return Object.freeze({ready:true});
 }catch(error){if(error.code==='BOUND_TOOL_POLICY_NOT_READY')throw error;throw fail();}
}
module.exports={assertBoundToolPolicyReadiness};
