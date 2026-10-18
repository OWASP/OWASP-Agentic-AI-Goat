'use strict';

const { configurationPlan, requiredStoreManifest } = require('../../db/postgres/initialize-application');

// SecureShop commerce contains shared read-only templates. Its identity,
// agents and review cleanup state receives deeper ledger/relation probes from
// secureshopCleanupComposition, so only commerce and agents are absent from
// the main startup initializer outcome set.
const EXPECTED_INITIALIZER_NAMES = Object.freeze(requiredStoreManifest
  .map(row => row.schema).filter(name => !['secureshop', 'secureshop_agents'].includes(name)));

function configurationError(message) {
  return Object.assign(new Error(message), { code: 'INVALID_CONFIGURATION' });
}

function unavailable(message = 'Platform data lifecycle is unavailable') {
  return Object.assign(new Error(message), { code: 'DELETION_UNAVAILABLE', statusCode: 503 });
}

function activationPolicy(env = process.env) {
  const value = env.LEGACY_PLATFORM_LIFECYCLE_ENABLED;
  if (value !== undefined && value !== 'true' && value !== 'false') {
    throw configurationError('LEGACY_PLATFORM_LIFECYCLE_ENABLED must be true or false');
  }
  const postgres = env.PLATFORM_DATABASE_ENGINE === 'postgres';
  return Object.freeze({
    requested: postgres && value !== 'false',
    postgres,
    explicitlyDisabled: value === 'false',
  });
}

function isPlatformDataLifecycleRequested(env = process.env) {
  return activationPolicy(env).requested;
}

function assertPlatformDataLifecycleConfiguration(env = process.env) {
  const policy = activationPolicy(env);
  if (!policy.requested) return policy;
  if (env.PLATFORM_DATABASE_ENGINE !== 'postgres' || env.WORKSHOP_DATABASE_ENGINE !== 'postgres') {
    throw configurationError('Platform data lifecycle requires PostgreSQL platform and workshop stores');
  }
  const missing = configurationPlan(env).filter(row => !row.configured).map(row => row.schema);
  if (missing.length) {
    const error = configurationError(`Platform data lifecycle store configuration is incomplete: ${missing.join(', ')}`);
    error.missingStores = Object.freeze(missing);
    throw error;
  }
  return policy;
}

function createPlatformDataLifecycleActivation({ env = process.env, getComposition } = {}) {
  const snapshot = {
    PLATFORM_DATABASE_ENGINE: env.PLATFORM_DATABASE_ENGINE,
    WORKSHOP_DATABASE_ENGINE: env.WORKSHOP_DATABASE_ENGINE,
    ...(env.LEGACY_PLATFORM_LIFECYCLE_ENABLED === undefined ? {} : {
      LEGACY_PLATFORM_LIFECYCLE_ENABLED: env.LEGACY_PLATFORM_LIFECYCLE_ENABLED,
    }),
  };
  for (const row of requiredStoreManifest) {
    snapshot[row.runtimeVariable] = env[row.runtimeVariable];
    snapshot[row.migrationVariable] = env[row.migrationVariable];
  }
  const policy = assertPlatformDataLifecycleConfiguration(snapshot);
  if (policy.requested && typeof getComposition !== 'function') {
    throw configurationError('Platform data lifecycle composition getter required');
  }

  let state = policy.requested ? 'idle' : 'disabled';
  let composition;
  let pending;

  async function initialize({ initializationResults } = {}) {
    if (!policy.requested) return Object.freeze({ requested: false, ready: false });
    if (state === 'ready') return Object.freeze({ requested: true, ready: true });
    if (pending) return pending;
    const names = Array.isArray(initializationResults)
      ? initializationResults.map(result => result?.name) : [];
    const expected = new Set(EXPECTED_INITIALIZER_NAMES);
    if (!Array.isArray(initializationResults) || initializationResults.length !== expected.size
        || new Set(names).size !== expected.size || names.some(name => !expected.has(name))
        || initializationResults.some(result => result?.status !== 'fulfilled')) {
      state = 'failed';
      throw unavailable('Required PostgreSQL initialization did not complete');
    }
    state = 'initializing';
    pending = Promise.resolve().then(getComposition).then(value => {
      if (typeof value?.application?.deleteStudent !== 'function') throw unavailable();
      composition = value;
      state = 'ready';
      return Object.freeze({ requested: true, ready: true });
    }, error => {
      state = 'failed';
      throw error;
    }).finally(() => { pending = undefined; });
    return pending;
  }

  function requireReady() {
    if (!policy.requested) throw unavailable('Platform data lifecycle is explicitly disabled');
    if (state !== 'ready' || !composition) throw unavailable();
    return composition;
  }

  return Object.freeze({ policy, initialize, requireReady });
}

module.exports = {
  EXPECTED_INITIALIZER_NAMES,
  activationPolicy,
  isPlatformDataLifecycleRequested,
  assertPlatformDataLifecycleConfiguration,
  createPlatformDataLifecycleActivation,
};
