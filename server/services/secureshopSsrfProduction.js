'use strict';
const path = require('node:path');
const { createSecureShopBoundSsrfRepository } = require('../database/postgres/secureshopBoundSsrfRepository');
const { createSecureShopSsrfTargetPool } = require('./secureshopSsrfTargetPool');
const { createSecureShopSsrfAvailability } = require('./secureshopSsrfAvailability');
const { createSecureShopSsrfResetAdapter } = require('./secureshopSsrfResetAdapter');
const FLAG = 'SS_CONTROLLED_SSRF_READY';
function unavailable() { return Object.assign(new Error('Controlled SSRF runtime unavailable'), { code: 'BOUND_SSRF_UNAVAILABLE' }); }
function activationPolicy(env = process.env) {
  const value = env[FLAG];
  if (value !== undefined && !['true', 'false'].includes(value)) {
    throw Object.assign(new Error(`${FLAG} must be true or false`), { code: 'INVALID_CONFIGURATION' });
  }
  const postgres = env.PLATFORM_DATABASE_ENGINE === 'postgres';
  if (postgres && value === 'true' && env.WORKSHOP_DATABASE_ENGINE !== 'postgres') throw unavailable();
  return Object.freeze({ requested: postgres && value === 'true', postgres });
}
function createSecureShopSsrfRepositoryBundle({ identityPool, agentsPool, launches, cleanupAuthority, fixtureRoot, auditStore } = {}) {
  if (typeof fixtureRoot !== 'string' || !path.isAbsolute(fixtureRoot)
      || typeof launches?.assertCurrent !== 'function' || typeof cleanupAuthority?.checkTarget !== 'function') throw unavailable();
  const availability = createSecureShopSsrfAvailability(identityPool);
  const repository = createSecureShopBoundSsrfRepository(agentsPool, {
    auditStore,
    checkCurrent: value => launches.assertCurrent(value),
    checkCleanup: value => cleanupAuthority.checkTarget({ ...value, targetKind: 'controlled_ssrf', fromGeneration: value.generation }),
  });
  const targetPool = createSecureShopSsrfTargetPool({ root: fixtureRoot });
  const reset = createSecureShopSsrfResetAdapter({ repository, targetPool, cleanupAuthority });
  return Object.freeze({ repository, targetPool, availability, cleanup: reset.cleanup,
    readCleanupReceipt: reset.readCleanupReceipt, close: () => targetPool.close() });
}
async function assertSecureShopSsrfReadiness({ identityPool, agentsPool } = {}) {
  if (typeof identityPool?.query !== 'function' || typeof agentsPool?.query !== 'function') throw unavailable();
  const names = ['bound_ssrf_targets', 'bound_ssrf_requests', 'bound_ssrf_invocations', 'bound_ssrf_cleanup_receipts']
    .map(name => `secureshop_agents.${name}`);
  const probes = await Promise.allSettled([
    agentsPool.query('SELECT value,to_regclass(value) IS NOT NULL AS ready FROM unnest($1::text[]) value', [names]),
    identityPool.query(`SELECT conname, position(quote_literal('controlled_ssrf') in pg_get_constraintdef(oid))>0 AS ready
      FROM pg_constraint WHERE conname=ANY($1::text[])`, [[
      'secureshop_target_reservations_target_kind_check', 'secureshop_target_cleanup_history_target_kind_check']]),
    createSecureShopSsrfAvailability(identityPool).read(),
  ]);
  const failure = probes.find(result => result.status === 'rejected');
  if (failure) throw failure.reason;
  const [relations, constraints, availability] = probes.map(result => result.value);
  if (relations.rows.length !== names.length || relations.rows.some(row => row.ready !== true)
      || constraints.rows.length !== 2 || constraints.rows.some(row => row.ready !== true)
      || !availability.registered) throw unavailable();
  return true;
}
module.exports = { activationPolicy, createSecureShopSsrfRepositoryBundle, assertSecureShopSsrfReadiness };
