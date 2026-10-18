'use strict';

const path = require('node:path');
const { readMigrations } = require('../../db/postgres/migrate');
const { createPool } = require('../database/postgres');
const { createSensitiveInfoAggregateReset } = require('./sensitiveInfoAggregateReset');
const { createSensitiveInfoResetRepository } = require('../database/postgres/sensitiveInfoResetRepository');
const { createSensitiveInfoCleanupRepository } = require('../database/postgres/sensitiveInfoCleanupRepository');
const { legacySensitiveRuns } = require('./legacySensitiveRunCoordinator');
const { FLAG, activationPolicy } = require('./sensitiveInfoResetActivationPolicy');
const STORES = Object.freeze({
  identity: Object.freeze({ runtimeRole: 'dvaia_identity_runtime', migrationRole: 'dvaia_identity_migration',
    migrationEnv: 'IDENTITY_MIGRATION_DATABASE_URL',
    directory: path.join(__dirname, '../../db/postgres/identity-migrations') }),
  finflow: Object.freeze({ runtimeRole: 'dvaia_finflow_runtime', migrationRole: 'dvaia_finflow_migration',
    runtimeEnv: 'FINFLOW_WORKSHOP_DATABASE_URL', migrationEnv: 'FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL',
    directory: path.join(__dirname, '../../db/postgres/workshop-migrations/finflow') }),
});

function unavailable(message = 'Sensitive Information aggregate reset is unavailable') {
  return Object.assign(new Error(message), { code: 'RESET_STORAGE_NOT_READY', statusCode: 503 });
}
function enabled(env = process.env) {
  return activationPolicy(env).requested;
}
async function assertLedger(pool, directory) {
  const expected = await readMigrations(directory);
  const actual = (await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  if (actual.length !== expected.length || actual.some((row, index) => row.name !== expected[index].name
      || row.checksum !== expected[index].checksum)) throw unavailable('Sensitive Information migration history is not ready');
}
async function assertSensitiveInfoResetReadiness({ identityPool, finflowPool, migrationPools } = {}) {
  const runtime = { identity: identityPool, finflow: finflowPool };
  if (!migrationPools || Object.values(runtime).some(pool => typeof pool?.query !== 'function')
      || Object.values(migrationPools).some(pool => typeof pool?.query !== 'function')) throw unavailable();
  const checks = await Promise.allSettled(Object.entries(runtime).map(async ([name, pool]) => {
    const config = STORES[name];
    const runtimeIdentity = (await pool.query('SELECT current_user AS role,current_database() AS database')).rows[0];
    const migrationIdentity = (await migrationPools[name].query(
      'SELECT current_user AS role,current_database() AS database')).rows[0];
    if (runtimeIdentity?.role !== config.runtimeRole || migrationIdentity?.role !== config.migrationRole
        || !runtimeIdentity.database || runtimeIdentity.database !== migrationIdentity.database) {
      throw unavailable('Sensitive Information store identity is not ready');
    }
    await assertLedger(migrationPools[name], config.directory);
    return runtimeIdentity.database;
  }));
  const failed = checks.find(result => result.status === 'rejected');
  if (failed) throw failed.reason;
  if (new Set(checks.map(result => result.value)).size !== checks.length) {
    throw unavailable('Sensitive Information reset stores are not isolated');
  }
  const journal = createSensitiveInfoResetRepository(identityPool);
  const cleanup = createSensitiveInfoCleanupRepository(finflowPool);
  await Promise.all([journal.assertReady(), cleanup.assertReady()]);
  return Object.freeze({ journal, cleanup });
}

let retained;
let pending;
let closing;
async function createSensitiveInfoResetComposition({ env = process.env, identityPool, finflowPool,
  migrationPools, runs = legacySensitiveRuns, finflowReset, journal, cleanup } = {}) {
  if (!enabled(env)) return null;
  if (env.PLATFORM_DATABASE_ENGINE !== 'postgres' || env.WORKSHOP_DATABASE_ENGINE !== 'postgres') {
    throw unavailable('Sensitive Information aggregate reset requires PostgreSQL');
  }
  const authority = journal && cleanup ? { journal, cleanup }
    : await assertSensitiveInfoResetReadiness({ identityPool, finflowPool, migrationPools });
  const resetOwner = finflowReset || require('../routes/sensitiveInfoWorkshop').resetOwner;
  return Object.freeze({ reset: createSensitiveInfoAggregateReset({ legacyRuns: runs,
    finflowReset: resetOwner, journal: authority.journal, cleanup: authority.cleanup }) });
}

async function getSensitiveInfoResetComposition(options = {}) {
  const env = options.env || process.env;
  if (!enabled(env)) return null;
  if (closing) throw unavailable('Sensitive Information aggregate reset is closing');
  if (retained) return retained.value;
  if (pending) return pending;
  pending = (async () => {
    const identityPool = require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool;
    const owned = {};
    const migrationPools = {};
    try {
      owned.finflow = createPool(env, STORES.finflow.runtimeEnv);
      migrationPools.identity = createPool(env, STORES.identity.migrationEnv);
      migrationPools.finflow = createPool(env, STORES.finflow.migrationEnv);
      const value = await createSensitiveInfoResetComposition({ env, identityPool,
        finflowPool: owned.finflow, migrationPools });
      if (closing) throw unavailable('Sensitive Information aggregate reset is closing');
      retained = { value, ownedPools: [owned.finflow] };
      return value;
    } catch (error) {
      await Promise.allSettled(Object.values(owned).map(pool => pool.end()));
      throw error;
    } finally {
      await Promise.allSettled(Object.values(migrationPools).map(pool => pool.end()));
    }
  })();
  try { return await pending; } finally { pending = undefined; }
}

async function closeSensitiveInfoResetComposition() {
  if (closing) return closing;
  closing = (async () => {
    if (pending) { try { await pending; } catch {} }
    const owned = retained;
    retained = undefined;
    const results = await Promise.allSettled((owned?.ownedPools || []).map(pool => pool.end()));
    const errors = results.filter(result => result.status === 'rejected').map(result => result.reason);
    if (errors.length) throw new AggregateError(errors, 'Sensitive Information aggregate reset shutdown failed');
  })();
  try { await closing; } finally { closing = undefined; }
}

module.exports = { FLAG, STORES, enabled, assertSensitiveInfoResetReadiness,
  createSensitiveInfoResetComposition, getSensitiveInfoResetComposition,
  closeSensitiveInfoResetComposition };
