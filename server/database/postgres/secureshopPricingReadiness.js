'use strict';

const T = 'secureshop_agents.bound_pricing_';
const C = 'platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id';
const fail = code => Object.assign(new Error('Bound pricing schema unavailable'), {
  code
});
async function assertPricingReadiness(pool) {
  if ((await pool.query('SELECT current_user AS role')).rows[0]?.role !== 'dvaia_secureshop_agents_runtime') throw fail('PRICING_NOT_READY');
  for (const table of ['admissions', 'outcomes', 'cleanup_receipts']) {
    for (const privilege of ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) {
      const allowed = privilege === 'SELECT' || privilege === 'INSERT' && table !== 'cleanup_receipts';
      if ((await pool.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed', [T + table, privilege])).rows[0]?.allowed !== allowed) throw fail('PRICING_NOT_READY');
    }
    if ((await pool.query("SELECT NOT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid=$1::regclass AND a.grantee=0) AS private", [T + table])).rows[0]?.private !== true) throw fail('PRICING_NOT_READY');
    const columns = (await pool.query("SELECT attname,has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS writable FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped", [T + table])).rows;
    if (!columns.length || columns.some(r => r.writable)) throw fail('PRICING_NOT_READY');
  }
  const triggers = [];
  for (const table of ['admissions', 'outcomes']) {
    triggers.push({
      rel: T + table,
      name: `a_pricing_${table}_insert`,
      fn: 'secureshop_agents.guard_bound_persona_admin_insert()',
      kind: 7
    }, {
      rel: T + table,
      name: `b_pricing_${table}_actor`,
      fn: 'secureshop_agents.guard_pricing_actor()',
      kind: 7
    }, {
      rel: T + table,
      name: `pricing_${table}_immutable`,
      fn: 'secureshop_agents.guard_pricing_record()',
      kind: 27
    });
  }
  triggers.push({
    rel: T + 'cleanup_receipts',
    name: 'pricing_cleanup_immutable',
    fn: 'secureshop_agents.guard_bound_audit_owner_deletion_receipt()',
    kind: 27
  }, {
    rel: 'secureshop_agents.conversation_generation_retirements',
    name: 'pricing_retirement',
    fn: 'secureshop_agents.cleanup_pricing_records()',
    kind: 5
  }, {
    rel: 'secureshop_agents.bound_audit_owner_deletion_receipts',
    name: 'pricing_owner_delete',
    fn: 'secureshop_agents.cleanup_pricing_records()',
    kind: 5
  });
  const integrity = (await pool.query(`SELECT count(*)=9 AS ready FROM jsonb_to_recordset($1::jsonb) AS e(rel text,name text,fn text,kind integer) JOIN pg_trigger t ON t.tgrelid=to_regclass(e.rel) AND t.tgname=e.name AND t.tgfoid=to_regprocedure(e.fn) AND t.tgtype=e.kind AND t.tgenabled='O' AND t.tgqual IS NULL AND NOT t.tgisinternal`, [JSON.stringify(triggers)])).rows[0];
  if (integrity?.ready !== true) throw fail('PRICING_NOT_READY');
  const functions = (await pool.query(`SELECT count(*)=3 AND bool_and(p.prosecdef AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=CASE p.proname WHEN 'guard_pricing_record' THEN 'e463b284fd7ba156852001e56cc09a243b05c9eaa4a9639e1a14ddc5f5a4a60d' WHEN 'guard_pricing_actor' THEN '423d612378a6f0307d2664c0923c7e2ee799c327611841ddb999d48050e2452f' WHEN 'cleanup_pricing_records' THEN 'ab0eaf02e15153384d79e28bdd28fd4f3b32c30355aac622144977477905a7a3' END AND p.proconfig=CASE WHEN p.proname='cleanup_pricing_records' THEN ARRAY['search_path=pg_catalog']::text[] ELSE ARRAY['search_path=pg_catalog, secureshop_agents']::text[] END AND NOT has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) AS ready FROM pg_proc p WHERE p.oid IN(to_regprocedure('secureshop_agents.guard_pricing_record()'),to_regprocedure('secureshop_agents.guard_pricing_actor()'),to_regprocedure('secureshop_agents.cleanup_pricing_records()'))`)).rows[0];
  if (functions?.ready !== true) throw fail('PRICING_NOT_READY');
  const scoped = ['platform_launch_generation > 0', 'original_platform_owner_id > 0', 'original_platform_session_id > 0', 'persona_id > 0', "persona_role = ANY (ARRAY['customer'::text, 'merchant'::text])", 'authority_version > 0', 'octet_length(request_sha256) = 32', 'octet_length(binding_sha256) = 32'];
  const checks = {
    admissions: [...scoped, "target_snapshot_json IS NULL OR jsonb_typeof(target_snapshot_json) = 'object'::text AND octet_length(target_snapshot_json::text) <= 131072", "request_json IS NULL OR jsonb_typeof(request_json) = 'object'::text AND octet_length(request_json::text) <= 131072"],
    outcomes: [...scoped, "state = ANY (ARRAY['completed'::text, 'unknown'::text, 'not_executed'::text, 'blocked'::text])", "receipt_json IS NULL OR jsonb_typeof(receipt_json) = 'object'::text AND octet_length(receipt_json::text) <= 524288", 'receipt_sha256 IS NULL OR octet_length(receipt_sha256) = 32', "state = ANY (ARRAY['unknown'::text, 'not_executed'::text]) AND receipt_json IS NULL AND receipt_sha256 IS NULL OR state = 'completed'::text AND receipt_sha256 IS NOT NULL OR state = 'blocked'::text AND receipt_sha256 IS NOT NULL"],
    cleanup_receipts: ["cleanup_kind = ANY (ARRAY['retirement'::text, 'owner_deletion'::text])", 'octet_length(receipt_sha256) = 32']
  };
  const normalize = expression => expression.replace(/'([0-9]+)'::(?:bigint|integer)/g, '$1').replace(/::(?:text|bigint|integer)/g, '').replace(/[()\s]/g, '');
  for (const [table, expected] of Object.entries(checks)) {
    const rows = (await pool.query("SELECT pg_get_expr(conbin,conrelid) AS expression,convalidated AND conenforced AS ready FROM pg_constraint WHERE conrelid=$1::regclass AND contype='c'", [T + table])).rows;
    const actual = rows.map(row => normalize(row.expression)).sort();
    if (rows.some(row => row.ready !== true) || JSON.stringify(actual) !== JSON.stringify(expected.map(normalize).sort())) {
      const error = fail('PRICING_NOT_READY');
      Object.defineProperty(error, 'schemaDiagnostic', {
        value: {
          table,
          actual,
          expected: expected.map(normalize).sort()
        }
      });
      throw error;
    }
  }
  const scopeKey = C.split(',').concat('operation_id');
  for (const table of ['admissions', 'outcomes', 'cleanup_receipts']) {
    const required = table === 'cleanup_receipts' ? ['cleanup_id', 'cleanup_kind', 'original_platform_owner_id', 'admission_count', 'outcome_count', 'receipt_sha256'] : [...scopeKey, 'run_id', 'persona_id', 'persona_session_id', 'persona_role', 'authority_version', 'request_sha256', 'binding_sha256', ...(table === 'outcomes' ? ['state'] : [])];
    const nonnull = (await pool.query("SELECT attname FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped AND attnotnull", [T + table])).rows.map(row => row.attname).sort();
    if (JSON.stringify(nonnull) !== JSON.stringify(required.sort())) throw fail('PRICING_NOT_READY');
    const keys = (await pool.query("SELECT contype,convalidated AND conenforced AS ready,confrelid::regclass::text AS target,ARRAY(SELECT attname::text FROM unnest(conkey) WITH ORDINALITY k(n,ord) JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY ord) AS columns,ARRAY(SELECT attname::text FROM unnest(confkey) WITH ORDINALITY k(n,ord) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.n ORDER BY ord) AS target_columns,confdeltype,confupdtype FROM pg_constraint c WHERE conrelid=$1::regclass AND contype IN ('p','f','u')", [T + table])).rows;
    const primary = keys.filter(row => row.contype === 'p');
    if (primary.length !== 1 || primary[0].ready !== true || JSON.stringify(primary[0].columns) !== JSON.stringify(table === 'cleanup_receipts' ? ['cleanup_id'] : scopeKey)) {
      const error = fail('PRICING_NOT_READY');
      Object.defineProperty(error, 'schemaDiagnostic', {
        value: {
          table,
          keys,
          expectedPrimary: table === 'cleanup_receipts' ? ['cleanup_id'] : scopeKey
        }
      });
      throw error;
    }
    const unique = keys.filter(row => row.contype === 'u');
    if (table === 'admissions' ? unique.length !== 1 || unique[0].ready !== true || JSON.stringify(unique[0].columns) !== JSON.stringify(['target_id']) : unique.length !== 0) throw fail('PRICING_NOT_READY');
    const foreign = keys.filter(row => row.contype === 'f');
    if (table === 'outcomes') {
      if (foreign.length !== 1 || foreign[0].ready !== true || foreign[0].target !== T + 'admissions' || JSON.stringify(foreign[0].columns) !== JSON.stringify(scopeKey) || JSON.stringify(foreign[0].target_columns) !== JSON.stringify(scopeKey) || foreign[0].confdeltype !== 'a' || foreign[0].confupdtype !== 'a') throw fail('PRICING_NOT_READY');
    } else if (foreign.length) throw fail('PRICING_NOT_READY');
  }
  return {
    ready: true,
    schemaVersion: 2
  };
}
module.exports = {
  assertPricingReadiness
};
