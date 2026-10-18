'use strict';

const { createHash } = require('node:crypto');
const RUNTIME_ROLE = 'dvaia_legacy_challenge_runtime';
const OWNER_ROLE = 'dvaia_legacy_challenge_migration';
const SOURCE = 'legacy_challenge.ai_conversations';
const SYNTHETIC = 'legacy_challenge.synthetic_ai_conversations';
// Exact prosrc of the forward-only 0005 replacement. Privileges alone would
// overlook a stale SECURITY DEFINER deletion helper that still reaches source.
const DELETION_BODY_SHA256 = 'cdb851010e0a2d92c1122a3d279feb6c251d0390ff0915ba4e624203c92b22d7';
const PRIVILEGES = ['table_select', 'table_insert', 'table_update', 'table_delete',
  'table_truncate', 'table_references', 'table_trigger', 'column_select',
  'column_insert', 'column_update', 'column_references'];
function unavailable() {
  return Object.assign(new Error('Synthetic AI teaching history is unavailable'), {
    code: 'LEGACY_AI_TEACHING_HISTORY_UNAVAILABLE',
  });
}
async function assertLegacyAiTeachingHistoryReadiness({ pool, expectedDatabase } = {}) {
  if (typeof pool?.query !== 'function' || typeof expectedDatabase !== 'string'
      || !expectedDatabase.length || Buffer.byteLength(expectedDatabase) > 63) throw unavailable();
  try {
    const identity = (await pool.query(`SELECT current_database() AS database,
      current_user AS role,session_user AS session_role,runtime.rolsuper,
      runtime.rolcreaterole,runtime.rolcreatedb,runtime.rolreplication,runtime.rolbypassrls,
      pg_has_role(current_user,'dvaia_legacy_challenge_migration','MEMBER') AS migration_member
      FROM pg_roles runtime WHERE runtime.rolname=current_user`)).rows?.[0];
    if (identity?.database !== expectedDatabase || identity.role !== RUNTIME_ROLE
        || identity.session_role !== RUNTIME_ROLE
        || ['rolsuper','rolcreaterole','rolcreatedb','rolreplication','rolbypassrls','migration_member'].some(key => identity[key] !== false)) throw unavailable();
    const schemas = (await pool.query(`SELECT name,to_regnamespace(name) IS NOT NULL AS present,
      has_schema_privilege(current_user,name,'USAGE') AS runtime_usage,
      has_schema_privilege(current_user,name,'CREATE') AS runtime_create
      FROM unnest($1::text[]) requested(name)`,
    [['legacy_challenge', 'legacy_ai_source_cleanup']])).rows;
    if (!Array.isArray(schemas) || schemas.length !== 2
        || schemas.filter(row => row.name === 'legacy_challenge' && row.present === true
          && row.runtime_usage === true && row.runtime_create === false).length !== 1
        || schemas.filter(row => row.name === 'legacy_ai_source_cleanup' && row.present === true
          && row.runtime_usage === false && row.runtime_create === false).length !== 1) throw unavailable();
    const relations = (await pool.query(`SELECT requested.name,relation.oid IS NOT NULL AS present,
      owner.rolname AS owner,relation.relkind AS kind,
      has_table_privilege(current_user,requested.name,'SELECT') AS table_select,
      has_table_privilege(current_user,requested.name,'INSERT') AS table_insert,
      has_table_privilege(current_user,requested.name,'UPDATE') AS table_update,
      has_table_privilege(current_user,requested.name,'DELETE') AS table_delete,
      has_table_privilege(current_user,requested.name,'TRUNCATE') AS table_truncate,
      has_table_privilege(current_user,requested.name,'REFERENCES') AS table_references,
      has_table_privilege(current_user,requested.name,'TRIGGER') AS table_trigger,
      has_any_column_privilege(current_user,requested.name,'SELECT') AS column_select,
      has_any_column_privilege(current_user,requested.name,'INSERT') AS column_insert,
      has_any_column_privilege(current_user,requested.name,'UPDATE') AS column_update,
      has_any_column_privilege(current_user,requested.name,'REFERENCES') AS column_references
      FROM unnest($1::text[]) requested(name)
      LEFT JOIN pg_class relation ON relation.oid=to_regclass(requested.name)
      LEFT JOIN pg_roles owner ON owner.oid=relation.relowner`, [[SOURCE, SYNTHETIC]])).rows;
    if (!Array.isArray(relations) || relations.length !== 2
        || new Set(relations.map(row => row.name)).size !== 2) throw unavailable();
    for (const name of [SOURCE, SYNTHETIC]) {
      const row = relations.find(value => value.name === name);
      if (row?.present !== true || row.owner !== OWNER_ROLE || row.kind !== 'r'
          || PRIVILEGES.some(key => row[key] !== (name === SYNTHETIC && ['table_select','column_select'].includes(key)))) throw unavailable();
    }
    const sequence = (await pool.query(`SELECT to_regclass($1) IS NOT NULL AS present,
      has_sequence_privilege(current_user,$1,'USAGE') AS runtime_usage,
      has_sequence_privilege(current_user,$1,'SELECT') AS runtime_select,
      has_sequence_privilege(current_user,$1,'UPDATE') AS runtime_update`,
    ['legacy_challenge.ai_conversations_id_seq'])).rows?.[0];
    if (sequence?.present !== true || sequence.runtime_usage !== false
        || sequence.runtime_select !== false || sequence.runtime_update !== false) throw unavailable();
    const fn = (await pool.query(`SELECT fn.oid IS NOT NULL AS present,owner.rolname AS owner,
      fn.prosecdef AS security_definer,fn.proconfig=ARRAY['search_path=pg_catalog']::text[] AS safe_search_path,
      language.lanname AS language,fn.prosrc AS body,
      has_function_privilege(current_user,fn.oid,'EXECUTE') AS runtime_execute,
      EXISTS(SELECT 1 FROM aclexplode(COALESCE(fn.proacl,acldefault('f',fn.proowner))) acl
        WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') AS public_execute
      FROM (SELECT to_regprocedure($1) AS oid) requested
      LEFT JOIN pg_proc fn ON fn.oid=requested.oid
      LEFT JOIN pg_roles owner ON owner.oid=fn.proowner
      LEFT JOIN pg_language language ON language.oid=fn.prolang`,
    ['legacy_challenge.destroy_student_owner(integer,uuid[])'])).rows?.[0];
    if (fn?.present !== true || fn.owner !== OWNER_ROLE || fn.security_definer !== true
        || fn.safe_search_path !== true || fn.language !== 'plpgsql'
        || fn.runtime_execute !== true || fn.public_execute !== false || typeof fn.body !== 'string'
        || createHash('sha256').update(fn.body).digest('hex') !== DELETION_BODY_SHA256) throw unavailable();
    return Object.freeze({ ready: true, database: identity.database,
      runtimeRole: identity.role, sessionRole: identity.session_role });
  } catch { throw unavailable(); }
}
module.exports = { assertLegacyAiTeachingHistoryReadiness, DELETION_BODY_SHA256 };
