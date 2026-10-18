'use strict';

const { createLegacyAiHistoryRepository } = require('../database/postgres/legacyAiHistoryRepository');
const { createLegacyAiHistoryRequestService } = require('./legacyAiHistoryRequestService');
const {
  createLegacyAiProtectedHistoryDraftRouter,
} = require('../routes/legacyAiProtectedHistoryDraftRouter');

const EXPECTED_RUNTIME_ROLE = 'dvaia_identity_runtime';
const REQUIRED_RELATIONS = Object.freeze([
  'legacy_ai_private.owners',
  'legacy_ai_private.history',
  'legacy_ai_private.reset_receipts',
  'legacy_ai_private.deletion_receipts',
  'legacy_ai_private.import_batches',
  'legacy_ai_private.import_archive',
  'legacy_ai_private.import_history_receipts',
  'legacy_ai_private.import_batch_events',
]);
const RUNTIME_FUNCTIONS = Object.freeze([
  'legacy_ai_private.admit_history(integer,bigint)',
  'legacy_ai_private.append_history(integer,bigint,bigint,uuid,text,text,text,text)',
  'legacy_ai_private.list_own_history(integer,bigint,integer,text)',
  'legacy_ai_private.list_admin_history(integer,bigint,integer,text)',
  'legacy_ai_private.reset_history(integer,bigint,bigint,uuid)',
  'legacy_ai_private.cleanup_history_for_student_deletion(uuid,uuid,integer)',
]);
const DENIED_FUNCTIONS = Object.freeze([
  'legacy_ai_private.assert_live_session(integer,bigint)',
  'legacy_ai_private.assert_admin_reader(integer,bigint)',
  'legacy_ai_private.begin_history_import(uuid,text,integer,text)',
  'legacy_ai_private.archive_history_import_row(uuid,bigint,jsonb,text,text,integer)',
  'legacy_ai_private.promote_owned_history_import_row(uuid,bigint,integer,uuid,text,text,text,text,timestamptz,text)',
  'legacy_ai_private.verify_history_import_quarantine(uuid,integer,text)',
]);
const EXPECTED_OWNER_ROLE = 'dvaia_identity_migration';

function unavailable(message = 'Protected legacy AI history is unavailable') {
  return Object.assign(new Error(message), {
    code: 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE',
  });
}

function validPool(pool) {
  return pool && typeof pool.query === 'function' && typeof pool.connect === 'function';
}

function rowsByName(result, expected) {
  if (!Array.isArray(result?.rows) || result.rows.length !== expected.length) return null;
  const rows = new Map();
  for (const row of result.rows) {
    if (!row || typeof row.name !== 'string' || rows.has(row.name)) return null;
    rows.set(row.name, row);
  }
  return expected.every(name => rows.has(name)) ? rows : null;
}

// Runtime authority gate for the registered private schema. Startup migration
// initialization owns ledger verification; this gate independently checks the
// exact database roles, table isolation and callable function privileges.
async function assertLegacyAiProtectedHistoryReadiness({ identityPool, expectedDatabase } = {}) {
  if (!validPool(identityPool) || typeof expectedDatabase !== 'string'
      || !expectedDatabase.length || Buffer.byteLength(expectedDatabase) > 63) {
    throw unavailable('Protected history readiness configuration is invalid');
  }

  try {
    const identity = (await identityPool.query(`SELECT current_database() AS database,
        current_user AS role,session_user AS session_role,runtime.rolsuper,
        runtime.rolcreaterole,runtime.rolcreatedb,runtime.rolreplication,runtime.rolbypassrls,
        pg_has_role(current_user,'dvaia_identity_migration','MEMBER') AS migration_member
      FROM pg_roles runtime WHERE runtime.rolname=current_user`,
    )).rows?.[0];
    if (identity?.database !== expectedDatabase || identity.role !== EXPECTED_RUNTIME_ROLE
        || identity.session_role !== EXPECTED_RUNTIME_ROLE || identity.rolsuper !== false
        || identity.rolcreaterole !== false || identity.rolcreatedb !== false
        || identity.rolreplication !== false || identity.rolbypassrls !== false
        || identity.migration_member !== false) {
      throw unavailable('Protected history runtime identity is not ready');
    }

    const schema = (await identityPool.query(`SELECT
      namespace.oid IS NOT NULL AS present,
      owner.rolname AS owner,
      has_schema_privilege(current_user,$1,'USAGE') AS runtime_usage,
      has_schema_privilege(current_user,$1,'CREATE') AS runtime_create,
      CASE WHEN namespace.oid IS NULL THEN false ELSE EXISTS (
        SELECT 1 FROM aclexplode(COALESCE(namespace.nspacl,acldefault('n',namespace.nspowner))) acl
        WHERE acl.grantee=0 AND acl.privilege_type='USAGE'
      ) END AS public_usage,
      CASE WHEN namespace.oid IS NULL THEN false ELSE EXISTS (
        SELECT 1 FROM aclexplode(COALESCE(namespace.nspacl,acldefault('n',namespace.nspowner))) acl
        WHERE acl.grantee=0 AND acl.privilege_type='CREATE'
      ) END AS public_create
      FROM (SELECT to_regnamespace($1) AS oid) requested
      LEFT JOIN pg_namespace namespace ON namespace.oid=requested.oid
      LEFT JOIN pg_roles owner ON owner.oid=namespace.nspowner`,
    ['legacy_ai_private'])).rows?.[0];
    if (schema?.present !== true || schema.owner !== EXPECTED_OWNER_ROLE
        || schema.runtime_usage !== true || schema.runtime_create !== false
        || schema.public_usage !== false || schema.public_create !== false) {
      throw unavailable('Protected history schema is not ready');
    }

    const relations = rowsByName(await identityPool.query(`SELECT name,
        to_regclass(name) IS NOT NULL AS present,
        has_table_privilege(current_user,name,'SELECT') AS table_select,
        has_table_privilege(current_user,name,'INSERT') AS table_insert,
        has_table_privilege(current_user,name,'UPDATE') AS table_update,
        has_table_privilege(current_user,name,'DELETE') AS table_delete,
        has_table_privilege(current_user,name,'TRUNCATE') AS table_truncate,
        has_table_privilege(current_user,name,'REFERENCES') AS table_references,
        has_table_privilege(current_user,name,'TRIGGER') AS table_trigger,
        has_any_column_privilege(current_user,name,'SELECT') AS column_select,
        has_any_column_privilege(current_user,name,'INSERT') AS column_insert,
        has_any_column_privilege(current_user,name,'UPDATE') AS column_update,
        has_any_column_privilege(current_user,name,'REFERENCES') AS column_references
      FROM unnest($1::text[]) AS requested(name)`, [REQUIRED_RELATIONS]), REQUIRED_RELATIONS);
    if (!relations || [...relations.values()].some(row => row.present !== true
        || row.table_select !== false || row.table_insert !== false
        || row.table_update !== false || row.table_delete !== false
        || row.table_truncate !== false || row.table_references !== false
        || row.table_trigger !== false
        || row.column_select !== false || row.column_insert !== false
        || row.column_update !== false || row.column_references !== false)) {
      throw unavailable('Protected history direct table isolation is not ready');
    }

    const signatures = [...RUNTIME_FUNCTIONS, ...DENIED_FUNCTIONS];
    const functions = rowsByName(await identityPool.query(`SELECT requested.name,
        fn.oid IS NOT NULL AS present,
        CASE WHEN fn.oid IS NULL THEN false
          ELSE has_function_privilege(current_user,fn.oid,'EXECUTE') END AS runtime_execute,
        owner.rolname AS owner,
        fn.prosecdef AS security_definer,
        fn.proconfig=ARRAY['search_path=pg_catalog']::text[] AS safe_search_path,
        CASE WHEN fn.oid IS NULL THEN false ELSE EXISTS (
          SELECT 1 FROM aclexplode(COALESCE(fn.proacl,acldefault('f',fn.proowner))) acl
          WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
        ) END AS public_execute
      FROM unnest($1::text[]) AS requested(name)
      LEFT JOIN pg_proc fn ON fn.oid=to_regprocedure(requested.name)
      LEFT JOIN pg_roles owner ON owner.oid=fn.proowner`,
    [signatures]), signatures);
    if (!functions || RUNTIME_FUNCTIONS.some(name => {
      const row = functions.get(name);
      return row.present !== true || row.runtime_execute !== true || row.public_execute !== false
        || row.owner !== EXPECTED_OWNER_ROLE || row.security_definer !== true
        || row.safe_search_path !== true;
    }) || DENIED_FUNCTIONS.some(name => {
      const row = functions.get(name);
      return row.present !== true || row.runtime_execute !== false || row.public_execute !== false
        || row.owner !== EXPECTED_OWNER_ROLE || row.security_definer !== true
        || row.safe_search_path !== true;
    })) {
      throw unavailable('Protected history function authority is not ready');
    }

    return Object.freeze({
      ready: true,
      database: identity.database,
      runtimeRole: identity.role,
      sessionRole: identity.session_role,
    });
  } catch (error) {
    if (error?.code === 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE') throw error;
    throw unavailable();
  }
}

// This returns an unmounted router only after the private-store authority has
// been checked. The caller cannot substitute a session adapter backed by a
// different pool, and no install/mount operation is exposed here.
async function createLegacyAiProtectedHistoryComposition({
  identityPool,
  identityAdapter,
  expectedDatabase,
  infer,
  issueRequestId,
  experimentAccess,
} = {}) {
  if (!validPool(identityPool) || identityAdapter?.pool !== identityPool
      || typeof identityAdapter?.validateSession !== 'function' || typeof infer !== 'function'
      || typeof experimentAccess !== 'function') {
    throw unavailable('Canonical protected history dependencies are required');
  }
  const readiness = await assertLegacyAiProtectedHistoryReadiness({
    identityPool,
    expectedDatabase,
  });
  const history = createLegacyAiHistoryRepository(identityPool);
  const historyService = createLegacyAiHistoryRequestService({
    history,
    infer,
    ...(issueRequestId === undefined ? {} : { issueRequestId }),
  });
  const router = createLegacyAiProtectedHistoryDraftRouter({ identityAdapter, historyService, experimentAccess });
  return Object.freeze({ readiness, router });
}

module.exports = {
  DENIED_FUNCTIONS,
  EXPECTED_OWNER_ROLE,
  EXPECTED_RUNTIME_ROLE,
  REQUIRED_RELATIONS,
  RUNTIME_FUNCTIONS,
  assertLegacyAiProtectedHistoryReadiness,
  createLegacyAiProtectedHistoryComposition,
};
