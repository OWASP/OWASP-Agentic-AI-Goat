'use strict';
const { createStudentDeletionRepository } = require('../database/postgres/studentDeletionRepository');
const { createStudentDeletionStoreCleanup } = require('./studentDeletionStoreCleanup');
const { createStudentDeletionAdapters } = require('./studentDeletionAdapters');
const { createStudentDeletionWorker } = require('./studentDeletionWorker');
const { createStudentDeletionApplication } = require('./studentDeletionApplication');

// This order is durable protocol: changing it quarantines already-admitted
// jobs rather than silently acknowledging a different cleanup plan.
const STUDENT_DELETION_STEPS = Object.freeze([
  'revoke_runs',
  'secureshop',
  'excessive_agency',
  'session_disclosure',
  'sql_injection_workshop',
  'nosql_injection_workshop',
  'mcp_workshop',
  'csrf_workshop',
  'direct_prompt_injection',
  'indirect_prompt_injection',
  'supply_chain_rce',
  'ctf',
  'legacy_challenge',
  'sensitive_lookup',
  'xss',
  'finflow',
  'identity',
]);

function createStudentDeletionComposition(options = {}) {
  const { identityPool, xssPool, finflowPool,
    createSecureShopCleanup, retireFinflowTraversalOwner, cleanupFinflowBackups,
    sceneResetPreflight, load = require } = options;
  const authoritySelected = Object.hasOwn(options, 'ctfRuntime');
  if (authoritySelected && typeof options.ctfRuntime?.deleteStudent !== 'function') {
    throw new TypeError('CTF authority deletion runtime required');
  }
  if (typeof createSecureShopCleanup !== 'function') throw new TypeError('SecureShop deletion cleanup factory required');
  const repository = createStudentDeletionRepository(identityPool,
    { steps: STUDENT_DELETION_STEPS, sceneResetPreflight });
  const storeCleanup = createStudentDeletionStoreCleanup({ identityPool, xssPool, finflowPool });
  const secureShopCleanup = createSecureShopCleanup(repository);
  if (typeof secureShopCleanup !== 'function') throw new TypeError('SecureShop deletion cleanup required');
  if (typeof retireFinflowTraversalOwner !== 'function') throw new TypeError('FinFlow traversal deletion cleanup required');
  if (typeof cleanupFinflowBackups !== 'function') throw new TypeError('FinFlow backup deletion cleanup required');
  const adapters = createStudentDeletionAdapters(load, { secureShopCleanup, storeCleanup,
    retireFinflowTraversalOwner, cleanupFinflowBackups,
    ...(authoritySelected ? { ctfRuntime: options.ctfRuntime } : {}) });
  for (const step of STUDENT_DELETION_STEPS) {
    if (typeof adapters[step] !== 'function') throw new TypeError(`Deletion adapter unavailable: ${step}`);
  }
  const worker = createStudentDeletionWorker({ repository, adapters });
  const application = createStudentDeletionApplication({ repository, worker });
  return Object.freeze({ application, repository, worker, adapters,
    steps: STUDENT_DELETION_STEPS });
}

module.exports = { STUDENT_DELETION_STEPS, createStudentDeletionComposition };
