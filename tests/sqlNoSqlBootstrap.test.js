'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { validateBootstrapEnvironment, bootstrap, safeBootstrapFailure } = require('./postgres/bootstrap-sql-nosql-route');

test('bootstrap diagnostics expose only allowlisted stage and categorical code', () => {
  const error = Object.assign(new Error('postgresql://private@host/db'), { code: '23505', bootstrapStage: 'platform_seed' });
  assert.deepEqual(safeBootstrapFailure(error), { stage: 'platform_seed', errorCode: '23505' });
  assert.deepEqual(safeBootstrapFailure(Object.assign(new Error('private'), { code: 'unsafe-code!', bootstrapStage: 'private' })),
    { stage: 'unknown', errorCode: 'EXECUTION_FAILED' });
  assert.deepEqual(safeBootstrapFailure(Object.assign(new Error('private'), { code: 'PRIVATE_CODE', bootstrapStage: 'platform_seed' })),
    { stage: 'platform_seed', errorCode: 'EXECUTION_FAILED' });
  assert.equal(JSON.stringify(safeBootstrapFailure(error)).includes('private'), false);
});

function environment() {
  const env = { PG_TEST_DISPOSABLE: 'yes', SQL_NOSQL_ROUTE_ISOLATED: '1',
    PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
    DVAIA_ISOLATED_TEST_WORKSPACE: process.cwd() };
  for (const [family, prefix] of [['identity', 'IDENTITY'], ['aria', 'SQL_WORKSHOP'], ['nova', 'NOSQL_WORKSHOP']]) {
    for (const role of ['runtime', 'migration']) env[`${prefix}${role === 'migration' ? '_MIGRATION' : ''}_DATABASE_URL`]
      = `postgresql://dvaia_${family}_${role}@127.0.0.1:15432/dvaia_test_sql_nosql_route_${family}`;
  }
  return env;
}

test('bootstrap admission requires the exact six role/store pairs without opening connections', () => {
  assert.doesNotThrow(() => validateBootstrapEnvironment(environment()));
  for (const key of Object.keys(environment())) {
    const env = environment(); delete env[key];
    assert.throws(() => validateBootstrapEnvironment(env), key);
  }
  for (const replacement of [
    'postgresql://dvaia_nova_runtime@localhost:15432/dvaia_test_sql_nosql_route_nova',
    'postgresql://dvaia_nova_migration@127.0.0.1:15432/dvaia_test_sql_nosql_route_nova',
    'postgresql://dvaia_nova_runtime@127.0.0.1:15433/dvaia_test_sql_nosql_route_nova',
    'postgresql://dvaia_nova_runtime@127.0.0.1:15432/learner',
    'postgresql://dvaia_nova_runtime@127.0.0.1:15432/dvaia_test_sql_nosql_route_nova?options=anything',
  ]) assert.throws(() => validateBootstrapEnvironment({ ...environment(), NOSQL_WORKSHOP_DATABASE_URL: replacement }));
});

test('invalid bootstrap fails before changing fetch or loading database modules', async () => {
  const fetchBefore = global.fetch;
  const databasePath = require.resolve('../server/database/postgres');
  assert.equal(require.cache[databasePath], undefined);
  await assert.rejects(bootstrap({ env: {} }), /isolated PostgreSQL/);
  assert.equal(global.fetch, fetchBefore);
  assert.equal(require.cache[databasePath], undefined);
});

test('invalid bootstrap is categorized at environment stage without exposing its message', async () => {
  let caught;
  try { await bootstrap({ env: {} }); } catch (error) { caught = error; }
  assert.deepEqual(safeBootstrapFailure(caught), { stage: 'environment', errorCode: 'EXECUTION_FAILED' });
});

test('fixed-session catalog fixtures require migration roles before any writes', async () => {
  const { seedFixedSessionFixtures, fixedSessionFixtures } = require('./postgres/bootstrap-sql-nosql-route');
  const nonce = 'a'.repeat(32); const FIXED_SESSION_FIXTURES = fixedSessionFixtures(nonce);
  const writes = [];
  const connection = role => ({ async query(sql, params) {
    if (sql === 'SELECT current_user AS role') return { rows: [{ role }] };
    writes.push({ role, sql, params }); return { rows: [] };
  } });
  await assert.rejects(seedFixedSessionFixtures({ nonce, ariaMigration: connection('dvaia_aria_migration'), novaMigration: connection('dvaia_nova_runtime') }));
  assert.deepEqual(writes, []);
  await seedFixedSessionFixtures({ nonce, ariaMigration: connection('dvaia_aria_migration'), novaMigration: connection('dvaia_nova_migration') });
  assert.equal(writes.length, 3);
  assert.deepEqual(writes.map(row => row.role), ['dvaia_aria_migration', 'dvaia_nova_migration', 'dvaia_nova_migration']);
  assert.deepEqual(writes[0].params, [FIXED_SESSION_FIXTURES.ARIA.publicId, FIXED_SESSION_FIXTURES.ARIA.term]);
  assert.deepEqual(writes.slice(1).map(row => row.params), [
    [FIXED_SESSION_FIXTURES.NOVA.publicId, FIXED_SESSION_FIXTURES.NOVA.term, 'public'],
    [FIXED_SESSION_FIXTURES.NOVA.restrictedId, FIXED_SESSION_FIXTURES.NOVA.term, 'restricted'],
  ]);
  assert.ok(writes.every(row => !/GRANT|ALTER ROLE/.test(row.sql)));
});
