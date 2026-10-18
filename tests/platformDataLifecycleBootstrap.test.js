'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { setImmediate: tick } = require('node:timers/promises');
const activation = require('../server/services/platformDataLifecycleActivation');
const resetActivation = require('../server/services/sensitiveInfoResetActivationPolicy');
const currentReset = require('../server/services/sensitiveInfoResetComposition');
const { requiredStoreManifest } = require('../db/postgres/initialize-application');

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

// Execute the production publish boundary with owned services. No database,
// listener or model is created by these controlled startup-order tests.
function boot({ flag, results = activation.EXPECTED_INITIALIZER_NAMES.map(name => ({ name, status: 'fulfilled' })), composition,
  omitStore, gradingCoreError, teachingSession, sensitiveResetFlag, sensitiveReset, candidateResetPolicy = false, codeBot, protectedHistory, ragProduction } = {}) {
  const source = fs.readFileSync(path.join(__dirname, '../server/applicationServer.js'), 'utf8');
  const start = source.indexOf('const platformDataLifecycle =');
  const end = source.indexOf('// Load RAG embedding model', start);
  assert.ok(start > 0 && end > start);
  // Startup now shares a memoized RAG initializer with route readiness.
  // Evaluate that actual helper too, rather than silently failing the VM on
  // an undefined function before any of the lifecycle gates under test.
  const ragStart = source.indexOf('let workshopRagInitialization;');
  const ragEnd = source.indexOf('// Import routes', ragStart);
  assert.ok(ragStart > 0 && ragEnd > ragStart && ragEnd < start);
  const state = { listens: 0, shutdowns: [], probes: 0, maintenance: 0, ctfProbes: 0 };
  const env = { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' };
  if (flag !== undefined) env.LEGACY_PLATFORM_LIFECYCLE_ENABLED = flag;
  if (sensitiveResetFlag !== undefined) env.SENSITIVE_INFO_AGGREGATE_RESET_ENABLED = sensitiveResetFlag;
  for (const row of requiredStoreManifest) {
    env[row.runtimeVariable] = `postgresql://runtime.invalid/${row.schema}`;
    env[row.migrationVariable] = `postgresql://migration.invalid/${row.schema}`;
  }
  if (omitStore) delete env[requiredStoreManifest.find(row => row.schema === omitStore).runtimeVariable];
  const services = {
    './routes/csrfWorkshop': { configureTeachingSessions: runtime => { state.teachingConfigured = runtime; return {}; } },
    './services/workshopRagProduction': { getWorkshopRagProduction: () => ({ async initialize() {
      state.ragProbes = (state.ragProbes || 0) + 1;
      return ragProduction || { ready: true };
    } }) },
    './services/studentDeletionProduction': { getProductionStudentDeletionComposition() {
      state.probes += 1;
      return composition || { application: { deleteStudent() {} } };
    } },
    './services/postgresIdentityAdapter': { getPostgresIdentityAdapter: () => ({ pool: {}, validateSession() {} }) },
    './database/postgres/ctfDb': { getCtfPool: () => ({ controlled: true }) },
    './agent-runtime/runCoordinator': { createRunCoordinator: options => ({ options }) },
    './services/ctfAuthorityProduction': { async initializeProductionCtfAuthority(options) {
      state.ctfProbes += 1;
      assert.equal(options.env, env);
      assert.equal(options.coordinator.options.family, 'CTF');
      return { router() {} };
    } },
    './database/postgres/objectiveEvidenceRepository': { createObjectiveEvidenceRepository: () => ({}) },
    './services/objectiveEvidenceMaintenance': { startObjectiveEvidenceMaintenance() { state.maintenance += 1; } },
    './services/sensitiveInfoResetComposition': {
      enabled: candidate => candidateResetPolicy
        ? resetActivation.activationPolicy(candidate).requested : currentReset.enabled(candidate),
      async getSensitiveInfoResetComposition() {
      state.sensitiveResetProbes=(state.sensitiveResetProbes||0)+1;
      return sensitiveReset || {reset:{reset(){}}};
    } },
    './services/mcp/ownedResourceProduction': { async installMcpOwnedResourceProduction() {} },
    './services/supplyChain/codeBotProduction': { getCodeBotProductionActivation: () => ({
      async initialize() {
        state.codeBotProbes = (state.codeBotProbes || 0) + 1;
        return codeBot || { enabled: false, ready: false };
      },
    }) },
  };
  vm.runInNewContext(source.slice(ragStart, ragEnd) + source.slice(start, end) + '\ncaptureStartup(startup);', {
    require(name) { assert.ok(Object.hasOwn(services, name), `Unexpected startup service ${name}`); return services[name]; },
    captureStartup(promise) { state.ready = promise.catch(() => state.shutdowns.push(1)); },
    assertActive() {}, checked: async promise => await promise, track: promise => promise, console: {log() {}},
    process: { env }, workshopInitialization: Promise.resolve(results),
    platformDataLifecyclePolicy: {
      createPlatformDataLifecycleActivation: options => activation.createPlatformDataLifecycleActivation({ ...options, env }),
    },
    getStartupObjectiveGradingCore() { state.gradingCoreProbes = (state.gradingCoreProbes || 0) + 1; if (gradingCoreError) throw gradingCoreError; return {}; },
    teachingSessionProduction: { async initialize() { state.teachingProbes = (state.teachingProbes || 0) + 1; return teachingSession || { ready: true }; } },
    secureShopReady: Promise.resolve({ status: 'fulfilled' }),
    legacyAiProtectedHistory: { async initialize() {
      state.protectedHistoryProbes = (state.protectedHistoryProbes || 0) + 1;
      return protectedHistory || { ready: true };
    } },
    app: { locals: {} }, mcpWorkshopRoutes: {}, ctfAuthorityRouter: null, signal: new AbortController().signal,
    lifecycle: { stopping: false, async shutdown(code) { state.shutdowns.push(code); } },
    logger: { error() {}, warn() {}, info() {} }, server: { once() {}, removeListener() {}, listen(port,done) { state.listens += 1; done(); } },
    PORT: 0, evidenceMaintenance: undefined,
  });
  return state;
}

test('production startup waits for retained cleanup readiness with unset and true configuration', async () => {
  for (const flag of [undefined, 'true']) {
    const pending = deferred();
    const state = boot({ flag, composition: pending.promise });
    await tick();
    assert.equal(state.probes, 1); assert.equal(state.listens, 0); assert.equal(state.maintenance, 0);
    assert.equal(state.protectedHistoryProbes || 0, 0);
    pending.resolve({ application: { deleteStudent() {} } });
    await tick();
    assert.equal(state.listens, 1); assert.deepEqual(state.shutdowns, []);
  }
});

test('startup awaits protected history readiness after cleanup and before downstream services', async () => {
  const pending = deferred();
  const state = boot({ protectedHistory: pending.promise });
  await tick();
  assert.equal(state.probes, 1);
  assert.equal(state.protectedHistoryProbes, 1);
  assert.equal(state.codeBotProbes || 0, 0);
  assert.equal(state.maintenance, 0);
  assert.equal(state.listens, 0);
  pending.resolve({ ready: true });
  await tick();
  assert.equal(state.codeBotProbes, 1);
  assert.equal(state.maintenance, 1);
  assert.equal(state.listens, 1);
  assert.deepEqual(state.shutdowns, []);

  const failed = deferred();
  const rejected = boot({ protectedHistory: failed.promise });
  await tick();
  failed.reject(new Error('Protected history readiness failed'));
  await tick();
  assert.equal(rejected.protectedHistoryProbes, 1);
  assert.equal(rejected.codeBotProbes || 0, 0);
  assert.equal(rejected.maintenance, 0);
  assert.equal(rejected.listens, 0);
  assert.deepEqual(rejected.shutdowns, [1]);
});

test('production startup never listens after a migration or cleanup capability failure', async () => {
  const failedMigration = boot({ results: activation.EXPECTED_INITIALIZER_NAMES.map((name, index) => ({
    name, status: index ? 'fulfilled' : 'rejected', ...(index ? {} : { reason: Error('owned migration failure') }),
  })) });
  await tick();
  assert.equal(failedMigration.probes, 0); assert.equal(failedMigration.listens, 0);
  assert.deepEqual(failedMigration.shutdowns, [1]);
  const pending = deferred();
  const failedCapability = boot({ composition: pending.promise });
  await tick(); pending.reject(Error('owned capability failure')); await tick();
  assert.equal(failedCapability.listens, 0); assert.equal(failedCapability.maintenance, 0);
  assert.deepEqual(failedCapability.shutdowns, [1]);
});

test('explicit Sensitive Information reset readiness completes before HTTP listen before promotion', async () => {
 for(const sensitiveResetFlag of ['true']){
  const pending=deferred();
  const state=boot({sensitiveResetFlag,sensitiveReset:pending.promise});
  await tick();
  assert.equal(state.sensitiveResetProbes,1);assert.equal(state.listens,0);
  pending.resolve({reset:{reset(){}}});await tick();
  assert.equal(state.listens,1);assert.deepEqual(state.shutdowns,[]);
 }
  const failed=boot({sensitiveResetFlag:'true',sensitiveReset:Promise.reject(Error('reset not ready'))});
  await tick();
  assert.equal(failed.listens,0);assert.deepEqual(failed.shutdowns,[1]);
  const invalid=boot({sensitiveResetFlag:'TRUE'});await tick();
  assert.equal(invalid.listens,0);assert.deepEqual(invalid.shutdowns,[1]);
});

test('release-candidate default-on policy gates HTTP listen on reset readiness',async()=>{
 const pending=deferred();const state=boot({candidateResetPolicy:true,sensitiveReset:pending.promise});
 await tick();assert.equal(state.sensitiveResetProbes,1);assert.equal(state.listens,0);
 pending.resolve({reset:{reset(){}}});await tick();
 assert.equal(state.listens,1);assert.deepEqual(state.shutdowns,[]);
 const failed=boot({candidateResetPolicy:true,sensitiveReset:Promise.reject(Error('candidate reset not ready'))});
 await tick();assert.equal(failed.listens,0);assert.deepEqual(failed.shutdowns,[1]);
});

test('Sensitive Information reset maintenance opt-out skips reset readiness but permits startup',async()=>{
 const state=boot({sensitiveResetFlag:'false'});await tick();
 assert.equal(state.sensitiveResetProbes||0,0);assert.equal(state.listens,1);assert.deepEqual(state.shutdowns,[]);
});

test('production explicit opt-out skips cleanup activation; invalid configuration fails', async () => {
  const state = boot({ flag: 'false' }); await tick();
  assert.equal(state.probes, 0); assert.equal(state.listens, 1);
  assert.throws(() => boot({ flag: 'TRUE' }), { code: 'INVALID_CONFIGURATION' });
});

test('production startup rejects missing stores and incomplete named initializer outcomes', async () => {
  assert.throws(() => boot({ omitStore: 'session_disclosure' }), { code: 'INVALID_CONFIGURATION' });
  const incomplete = boot({ results: activation.EXPECTED_INITIALIZER_NAMES.slice(1)
    .map(name => ({ name, status: 'fulfilled' })) });
  await tick();
  assert.equal(incomplete.probes, 0); assert.equal(incomplete.listens, 0);
  assert.deepEqual(incomplete.shutdowns, [1]);
});

test('production checks the lifecycle store manifest before framework and database initialization', () => {
  const source = fs.readFileSync(path.join(__dirname, '../server/applicationServer.js'), 'utf8');
  const guard = source.indexOf('platformDataLifecyclePolicy.assertPlatformDataLifecycleConfiguration(process.env)');
  assert.ok(guard > source.indexOf('assertApplicationDatabaseEngine()'));
  assert.ok(guard < source.indexOf("const express = require('express')"));
  assert.ok(guard < source.indexOf('const workshopInitializers ='));
});

test('startup awaits CodeBot activation and rejects initialization failure before listening', async () => {
  const pending = deferred();
  const state = boot({ codeBot: pending.promise });
  await tick();
  assert.equal(state.codeBotProbes, 1);
  assert.equal(state.listens, 0);
  pending.resolve({ enabled: true, ready: true });
  await tick();
  assert.equal(state.listens, 1);
  assert.deepEqual(state.shutdowns, []);

  const failed = deferred();
  const rejected = boot({ codeBot: failed.promise });
  await tick();
  failed.reject(new Error('CodeBot initialization failed'));
  await tick();
  assert.equal(rejected.listens, 0);
  assert.deepEqual(rejected.shutdowns, [1]);
});

 test('startup waits for durable RAG readiness before lifecycle, protected history and listen', async () => {
  const pending=deferred(),state=boot({ragProduction:pending.promise});
  await tick();assert.equal(state.ragProbes,1);assert.equal(state.probes,0);assert.equal(state.protectedHistoryProbes||0,0);assert.equal(state.listens,0);
  pending.resolve({ready:true});await tick();assert.equal(state.probes,1);assert.equal(state.protectedHistoryProbes,1);assert.equal(state.listens,1);assert.deepEqual(state.shutdowns,[]);
  const failed=deferred(),rejected=boot({ragProduction:failed.promise});await tick();failed.reject(new Error('Durable RAG readiness failure'));await tick();
  assert.equal(rejected.ragProbes,1);assert.equal(rejected.probes,0);assert.equal(rejected.protectedHistoryProbes||0,0);assert.equal(rejected.listens,0);assert.deepEqual(rejected.shutdowns,[1]);
 });

test('grading core and teaching session readiness fail closed before downstream startup', async () => {
  const coreFailure = boot({ gradingCoreError: new Error('owned grading core unavailable') });
  await tick();
  assert.equal(coreFailure.gradingCoreProbes, 1); assert.equal(coreFailure.teachingProbes || 0, 0);
  assert.equal(coreFailure.probes, 0); assert.equal(coreFailure.listens, 0); assert.deepEqual(coreFailure.shutdowns, [1]);
  const pending = deferred(), state = boot({ teachingSession: pending.promise });
  await tick(); assert.equal(state.gradingCoreProbes, 1); assert.equal(state.teachingProbes, 1);
  assert.equal(state.ragProbes || 0, 0); assert.equal(state.listens, 0);
  pending.reject(new Error('owned teaching runtime unavailable'));
  await tick(); assert.equal(state.listens, 0); assert.deepEqual(state.shutdowns, [1]);
});
