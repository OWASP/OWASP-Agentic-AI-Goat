'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  DENIED_FUNCTIONS,
  EXPECTED_OWNER_ROLE,
  EXPECTED_RUNTIME_ROLE,
  REQUIRED_RELATIONS,
  RUNTIME_FUNCTIONS,
  assertLegacyAiProtectedHistoryReadiness,
  createLegacyAiProtectedHistoryComposition,
} = require('../server/services/legacyAiProtectedHistoryComposition');

const DATABASE = 'dvaia_identity_disposable';

function readinessPool(overrides = {}) {
  const calls = [];
  const pool = {
    connect() {},
    async query(sql, values) {
      calls.push({ sql, values });
      if (sql.includes('current_database()')) {
        return { rows: [{ database: overrides.database || DATABASE,
          role: overrides.role || EXPECTED_RUNTIME_ROLE,
          session_role: overrides.sessionRole || EXPECTED_RUNTIME_ROLE,
          rolsuper: overrides.superuser ?? false,
          rolcreaterole: overrides.createRole ?? false,
          rolcreatedb: overrides.createDb ?? false,
          rolreplication: overrides.replication ?? false,
          rolbypassrls: overrides.bypassRls ?? false,
          migration_member: overrides.migrationMember ?? false }] };
      }
      if (sql.includes('to_regnamespace')) {
        return { rows: [{ present: overrides.schemaPresent ?? true,
          owner: overrides.schemaOwner || EXPECTED_OWNER_ROLE,
          runtime_usage: overrides.schemaUsage ?? true,
          runtime_create: overrides.schemaCreate ?? false,
          public_usage: overrides.schemaPublicUsage ?? false,
          public_create: overrides.schemaPublicCreate ?? false }] };
      }
      if (sql.includes('to_regclass')) {
        const names = overrides.relationNames || values[0];
        return { rows: names.map(name => ({ name, present: true,
          table_select: false, table_insert: false, table_update: false, table_delete: false,
          table_truncate: false, table_references: false, table_trigger: false,
          column_select: false, column_insert: false, column_update: false,
          column_references: false,
          ...(overrides.relation?.[name] || {}) })) };
      }
      if (sql.includes('to_regprocedure')) {
        const names = overrides.functionNames || values[0];
        return { rows: names.map(name => ({ name, present: true,
          runtime_execute: RUNTIME_FUNCTIONS.includes(name), public_execute: false,
          owner: EXPECTED_OWNER_ROLE, security_definer: true, safe_search_path: true,
          ...(overrides.function?.[name] || {}) })) };
      }
      throw new Error('Unexpected readiness query');
    },
  };
  return { pool, calls };
}

test('readiness binds the exact identity runtime and denies direct storage authority', async () => {
  const { pool, calls } = readinessPool();
  assert.equal(REQUIRED_RELATIONS.length, 8);
  assert.equal(REQUIRED_RELATIONS.includes('legacy_ai_private.import_archive'), true);
  assert.equal(RUNTIME_FUNCTIONS.includes(
    'legacy_ai_private.cleanup_history_for_student_deletion(uuid,uuid,integer)'), true);
  const receipt = await assertLegacyAiProtectedHistoryReadiness({
    identityPool: pool,
    expectedDatabase: DATABASE,
  });
  assert.deepEqual(receipt, {
    ready: true,
    database: DATABASE,
    runtimeRole: EXPECTED_RUNTIME_ROLE,
    sessionRole: EXPECTED_RUNTIME_ROLE,
  });
  assert.equal(Object.isFrozen(receipt), true);
  assert.deepEqual(calls[2].values, [REQUIRED_RELATIONS]);
  assert.deepEqual(calls[3].values, [[...RUNTIME_FUNCTIONS, ...DENIED_FUNCTIONS]]);
  assert.match(calls[2].sql, /has_any_column_privilege/);
  assert.match(calls[3].sql, /acl\.grantee=0/);
});

test('readiness fails closed for wrong identity, direct grants, PUBLIC execute, and internal execute', async t => {
  const cases = [
    ['database', { database: 'wrong_identity' }],
    ['role', { role: 'dvaia_identity_migration' }],
    ['session role', { sessionRole: 'dvaia_identity_migration' }],
    ['superuser', { superuser: true }],
    ['create role', { createRole: true }],
    ['create database', { createDb: true }],
    ['replication', { replication: true }],
    ['bypass RLS', { bypassRls: true }],
    ['migration membership even without inherited grants', { migrationMember: true }],
    ['schema', { schemaUsage: false }],
    ['schema owner', { schemaOwner: EXPECTED_RUNTIME_ROLE }],
    ['runtime schema CREATE', { schemaCreate: true }],
    ['PUBLIC schema', { schemaPublicUsage: true }],
    ['PUBLIC schema CREATE', { schemaPublicCreate: true }],
    ['table', { relation: { [REQUIRED_RELATIONS[1]]: { table_select: true } } }],
    ['column', { relation: { [REQUIRED_RELATIONS[1]]: { column_update: true } } }],
    ['archive table', { relation: {
      ['legacy_ai_private.import_archive']: { table_select: true },
    } }],
    ['PUBLIC function', { function: { [RUNTIME_FUNCTIONS[0]]: { public_execute: true } } }],
    ['missing API', { function: { [RUNTIME_FUNCTIONS[0]]: { present: false } } }],
    ['function owner', { function: { [RUNTIME_FUNCTIONS[0]]: { owner: EXPECTED_RUNTIME_ROLE } } }],
    ['function invoker', { function: { [RUNTIME_FUNCTIONS[0]]: { security_definer: false } } }],
    ['function search path', { function: { [RUNTIME_FUNCTIONS[0]]: { safe_search_path: false } } }],
    ['internal function', { function: { [DENIED_FUNCTIONS[0]]: { runtime_execute: true } } }],
    ['missing cleanup API', { function: {
      ['legacy_ai_private.cleanup_history_for_student_deletion(uuid,uuid,integer)']:
        { runtime_execute: false },
    } }],
  ];
  for (const [name, overrides] of cases) {
    await t.test(name, async () => {
      const { pool } = readinessPool(overrides);
      await assert.rejects(
        assertLegacyAiProtectedHistoryReadiness({ identityPool: pool, expectedDatabase: DATABASE }),
        error => error?.code === 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE',
      );
    });
  }
});

test('malformed or duplicate catalog readback cannot satisfy readiness', async () => {
  const missing = readinessPool({ relationNames: REQUIRED_RELATIONS.slice(1) }).pool;
  await assert.rejects(
    assertLegacyAiProtectedHistoryReadiness({ identityPool: missing, expectedDatabase: DATABASE }),
    error => error?.code === 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE',
  );
  const duplicate = readinessPool({
    functionNames: [...RUNTIME_FUNCTIONS, ...DENIED_FUNCTIONS.slice(0, -1), RUNTIME_FUNCTIONS[0]],
  }).pool;
  await assert.rejects(
    assertLegacyAiProtectedHistoryReadiness({ identityPool: duplicate, expectedDatabase: DATABASE }),
    error => error?.code === 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE',
  );
});

test('composition constructs an unmounted router only after readiness on the canonical pool', async () => {
  const { pool, calls } = readinessPool();
  const identityAdapter = { pool, async validateSession() { return null; } };
  const composition = await createLegacyAiProtectedHistoryComposition({
    experimentAccess: (req, res, next) => next(), // Controlled enabled exercise fixture.
    identityPool: pool,
    identityAdapter,
    expectedDatabase: DATABASE,
    async infer() { return { response: 'controlled', modelUsed: 'controlled' }; },
  });
  assert.equal(calls.length, 4);
  assert.equal(composition.readiness.ready, true);
  assert.equal(typeof composition.router, 'function');
  assert.deepEqual(Object.keys(composition).sort(), ['readiness', 'router']);
  assert.equal(Object.isFrozen(composition), true);

  const other = readinessPool().pool;
  await assert.rejects(createLegacyAiProtectedHistoryComposition({
    experimentAccess: (req, res, next) => next(), // Controlled enabled exercise fixture.
    identityPool: pool,
    identityAdapter: { pool: other, validateSession() {} },
    expectedDatabase: DATABASE,
    infer() {},
  }), /Canonical protected history dependencies/);
  assert.equal(calls.length, 4, 'pool mismatch must reject before readiness queries');
});

test('readiness query failures are normalized and no router is returned', async () => {
  const failure = new Error('private database detail');
  const pool = { connect() {}, async query() { throw failure; } };
  await assert.rejects(
    createLegacyAiProtectedHistoryComposition({
    experimentAccess: (req, res, next) => next(), // Controlled enabled exercise fixture.
      identityPool: pool,
      identityAdapter: { pool, validateSession() {} },
      expectedDatabase: DATABASE,
      infer() {},
    }),
    error => error?.code === 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE'
      && !error.message.includes('private database detail'),
  );
});
