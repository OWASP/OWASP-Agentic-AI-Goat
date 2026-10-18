'use strict';

const path = require('node:path');
const { readMigrations } = require('../../db/postgres/migrate');
const { createPool } = require('../database/postgres');
const { createSensitiveInfoAggregateReset } = require('./sensitiveInfoAggregateReset');
const { createSensitiveInfoResetRepository } = require('../database/postgres/sensitiveInfoResetRepository');
const { createSensitiveInfoCleanupRepository } = require('../database/postgres/sensitiveInfoCleanupRepository');
const { legacySensitiveRuns } = require('./legacySensitiveRunCoordinator');
const { FLAG, activationPolicy } = require('./sensitiveInfoResetActivationPolicy');
const { createFinflowTraversalManager } = require('./finflowTraversalArtifacts');
const { createFinflowTraversalTargetRepository } = require('../database/postgres/finflowTraversalTargetRepository');
const { createFinflowDurableResourceRepository } = require('../database/postgres/finflowDurableResourceRepository');
const { createFinflowDurableResourceLifecycle } = require('./finflowDurableResourceComposition');
const TRAVERSAL_AGENT_METHODS = Object.freeze([
  'read', 'readAdminConfig', 'listAdminDirectory',
]);
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
function traversalUnavailable() {
  return Object.assign(new Error('Controlled traversal storage is not ready'),
    { code: 'TRAVERSAL_TARGET_STORAGE_NOT_READY', statusCode: 503 });
}
function createConfiguredFinflowTraversalManager({ getComposition = getSensitiveInfoResetComposition } = {}) {
  if (typeof getComposition !== 'function') {
    throw new TypeError('Sensitive Information reset composition provider required');
  }
  const resolve = async () => {
    const manager = (await getComposition())?.traversalManager;
    if (!manager || TRAVERSAL_AGENT_METHODS.some(name => typeof manager[name] !== 'function')) {
      throw traversalUnavailable();
    }
    return manager;
  };
  return Object.freeze(Object.fromEntries(TRAVERSAL_AGENT_METHODS.map(method => [method,
    async input => (await resolve())[method](input)])));
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
  const traversalRepository = createFinflowTraversalTargetRepository({ pool: finflowPool });
  const resourceRepository = createFinflowDurableResourceRepository(finflowPool);
  await Promise.all([journal.assertReady(), cleanup.assertReady(), traversalRepository.assertReady(),
    resourceRepository.assertReady()]);
  return Object.freeze({ journal, cleanup, traversalRepository, resourceRepository });
}

function withResourceRetirement(cleanup, resources) {
  if (!resources || typeof resources.retireGeneration !== 'function'
      || typeof resources.readRetirement !== 'function') {
    throw unavailable('FinFlow durable reset retirement is not ready');
  }
  const retirementScope=value=>({operationId:value.operationId,ownerId:value.ownerId,
    fromGeneration:value.fromGeneration,toGeneration:value.toGeneration});
  return Object.freeze({
    async apply(value) {
      if(value.stepKey==='finflow_store')await resources.retireGeneration(retirementScope(value));
      return cleanup.apply(value);
    },
    async readReceipt(value) {
      const receipt=await cleanup.readReceipt(value);
      if(value.stepKey==='finflow_store'){
        const expected=retirementScope(value);const retired=await resources.readRetirement(expected);
        if(!retired||retired.status!=='completed'||Object.keys(expected).some(key=>retired[key]!==expected[key])){
          throw Object.assign(new Error('FinFlow resource retirement receipt mismatch'),
            {code:'RESET_RECEIPT_MISMATCH'});
        }
      }
      return receipt;
    },
  });
}

let retained;
let pending;
let closing;
async function createSensitiveInfoResetComposition({ env = process.env, identityPool, finflowPool,
  migrationPools, runs = legacySensitiveRuns, finflowReset, journal, cleanup, traversalRepository,
  traversalManager, traversalReset, traversalRoot, traversalFs, resourceLifecycle,
  appDataRoot, resourceFileSystem } = {}) {
  if (!enabled(env)) return null;
  if (env.PLATFORM_DATABASE_ENGINE !== 'postgres' || env.WORKSHOP_DATABASE_ENGINE !== 'postgres') {
    throw unavailable('Sensitive Information aggregate reset requires PostgreSQL');
  }
  const authority = journal && cleanup ? { journal, cleanup, traversalRepository }
    : await assertSensitiveInfoResetReadiness({ identityPool, finflowPool, migrationPools });
  const lifecycle=resourceLifecycle || (finflowPool && await createFinflowDurableResourceLifecycle({
    pool:finflowPool,appDataRoot,env,fileSystem:resourceFileSystem}));
  if(!lifecycle?.resources)throw unavailable('FinFlow durable resource lifecycle is not ready');
  const manager = traversalManager || (authority.traversalRepository
    ? createFinflowTraversalManager({ repository: authority.traversalRepository,
      root: traversalRoot || lifecycle.roots?.traversalRoot, fsImpl: traversalFs }) : null);
  const retireTraversal = traversalReset || (manager && (owner => manager.retireOwner(owner)));
  if (typeof retireTraversal !== 'function') {
    throw unavailable('Sensitive Information traversal reset is not ready');
  }
  const resetOwner = finflowReset || require('../routes/sensitiveInfoWorkshop').resetOwner;
  // The target adapter is deliberately inside the same durable owner reset fence.
  // It retires only owner-bound traversal targets and leaves immutable retired rows.
  const fencedReset = async (owner, work) => resetOwner(owner, async () => {
    await retireTraversal(String(owner));
    await work();
  });
  return Object.freeze({ reset: createSensitiveInfoAggregateReset({ legacyRuns: runs,
    finflowReset: fencedReset, journal: authority.journal,
    cleanup:withResourceRetirement(authority.cleanup,lifecycle.resources) }),
  traversalManager: manager, resourceLifecycle:lifecycle });
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
  withResourceRetirement, createSensitiveInfoResetComposition, getSensitiveInfoResetComposition,
  closeSensitiveInfoResetComposition, TRAVERSAL_AGENT_METHODS,
  createConfiguredFinflowTraversalManager };
