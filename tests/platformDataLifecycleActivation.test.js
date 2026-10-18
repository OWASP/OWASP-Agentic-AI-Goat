'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  EXPECTED_INITIALIZER_NAMES,
  activationPolicy,
  isPlatformDataLifecycleRequested,
  assertPlatformDataLifecycleConfiguration,
  createPlatformDataLifecycleActivation,
} = require('../server/services/platformDataLifecycleActivation');
const { requiredStoreManifest } = require('../db/postgres/initialize-application');

function configuredEnv(flag) {
  const env = { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' };
  if (flag !== undefined) env.LEGACY_PLATFORM_LIFECYCLE_ENABLED = flag;
  for (const row of requiredStoreManifest) {
    env[row.runtimeVariable] = `postgresql://runtime.invalid/${row.schema}`;
    env[row.migrationVariable] = `postgresql://migration.invalid/${row.schema}`;
  }
  return env;
}
const fulfilled = EXPECTED_INITIALIZER_NAMES.map(name => ({ name, status: 'fulfilled', value: true }));

test('PostgreSQL requests lifecycle by default and accepts only an explicit false opt-out', () => {
  assert.equal(isPlatformDataLifecycleRequested({ PLATFORM_DATABASE_ENGINE: 'postgres' }), true);
  assert.equal(isPlatformDataLifecycleRequested({
    PLATFORM_DATABASE_ENGINE: 'postgres', LEGACY_PLATFORM_LIFECYCLE_ENABLED: 'true',
  }), true);
  assert.equal(isPlatformDataLifecycleRequested({
    PLATFORM_DATABASE_ENGINE: 'postgres', LEGACY_PLATFORM_LIFECYCLE_ENABLED: 'false',
  }), false);
  assert.deepEqual(activationPolicy({ PLATFORM_DATABASE_ENGINE: 'sqlite' }), {
    requested: false, postgres: false, explicitlyDisabled: false,
  });
  assert.throws(() => activationPolicy({
    PLATFORM_DATABASE_ENGINE: 'postgres', LEGACY_PLATFORM_LIFECYCLE_ENABLED: 'TRUE',
  }), { code: 'INVALID_CONFIGURATION' });
});

test('required-store manifest is immutable, complete, and required before initialization', () => {
  assert.equal(requiredStoreManifest.length, 16);
  assert.equal(Object.isFrozen(requiredStoreManifest), true);
  assert.ok(requiredStoreManifest.every(Object.isFrozen));
  assert.equal(EXPECTED_INITIALIZER_NAMES.length, 14);
  assert.doesNotThrow(() => assertPlatformDataLifecycleConfiguration(configuredEnv()));
  const missing = configuredEnv(); delete missing.MCP_WORKSHOP_DATABASE_URL;
  assert.throws(() => assertPlatformDataLifecycleConfiguration(missing), error =>
    error.code === 'INVALID_CONFIGURATION' && error.missingStores.includes('mcp'));
  assert.throws(() => assertPlatformDataLifecycleConfiguration({
    ...configuredEnv(), WORKSHOP_DATABASE_ENGINE: 'sqlite',
  }), { code: 'INVALID_CONFIGURATION' });
  assert.doesNotThrow(() => assertPlatformDataLifecycleConfiguration({
    PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
    LEGACY_PLATFORM_LIFECYCLE_ENABLED: 'false',
  }));
});

test('required lifecycle waits for settled initialization and retained composition readiness', async () => {
  const composition = { application: { async deleteStudent() {} } };
  let calls = 0;
  const activation = createPlatformDataLifecycleActivation({
    env: configuredEnv(),
    getComposition: async () => { calls += 1; return composition; },
  });
  assert.throws(() => activation.requireReady(), { code: 'DELETION_UNAVAILABLE', statusCode: 503 });
  assert.deepEqual(await Promise.all([
    activation.initialize({ initializationResults: fulfilled }),
    activation.initialize({ initializationResults: fulfilled }),
  ]), [{ requested: true, ready: true }, { requested: true, ready: true }]);
  assert.equal(calls, 1);
  assert.equal(activation.requireReady(), composition);
});

test('failed, incomplete, duplicate, or unnamed initialization never probes deletion readiness', async () => {
  let calls = 0;
  for (const initializationResults of [undefined, [], fulfilled.slice(1),
    fulfilled.map((row, index) => index ? row : { ...row, status: 'rejected', reason: Error('owned') }),
    fulfilled.map((row, index) => index ? row : { ...row, status: 'pending' }),
    fulfilled.map((row, index) => index ? row : { ...row, name: fulfilled[1].name }),
    fulfilled.map((row, index) => index ? row : { status: row.status })]) {
    const activation = createPlatformDataLifecycleActivation({
      env: configuredEnv('true'),
      getComposition: async () => { calls += 1; return { application: { deleteStudent() {} } }; },
    });
    await assert.rejects(activation.initialize({ initializationResults }), {
      code: 'DELETION_UNAVAILABLE', statusCode: 503,
    });
    assert.throws(() => activation.requireReady(), { code: 'DELETION_UNAVAILABLE' });
  }
  assert.equal(calls, 0);
});

test('explicit opt-out neither constructs nor reports a ready deletion composition', async () => {
  let calls = 0;
  const activation = createPlatformDataLifecycleActivation({
    env: configuredEnv('false'),
    getComposition: async () => { calls += 1; },
  });
  assert.deepEqual(await activation.initialize(), { requested: false, ready: false });
  assert.equal(calls, 0);
  assert.throws(() => activation.requireReady(), { code: 'DELETION_UNAVAILABLE', statusCode: 503 });
});

test('composition capability failure leaves lifecycle unavailable', async () => {
  const activation = createPlatformDataLifecycleActivation({
    env: configuredEnv(),
    getComposition: async () => { throw Object.assign(new Error('ledger mismatch'), { code: 'DELETION_UNAVAILABLE' }); },
  });
  await assert.rejects(activation.initialize({ initializationResults: fulfilled }), /ledger mismatch/);
  assert.throws(() => activation.requireReady(), { code: 'DELETION_UNAVAILABLE' });
});
