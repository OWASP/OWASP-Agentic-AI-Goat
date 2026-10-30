'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { fork } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { createFinflowTraversalTargetRepository } = require('../../server/database/postgres/finflowTraversalTargetRepository');
const { createSensitiveInfoResetComposition } = require('../../server/services/sensitiveInfoResetComposition');
const { finflowOwnerKey } = require('../../server/services/finflowTraversalArtifacts');
const { bounded, stopOwnedWorkers, superviseOwnedWorker } = require('../helpers/ownedWorkerLifecycle');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.FINFLOW_TRAVERSAL_ISOLATED === '1';
const TRAVERSAL_MIGRATION = '0010_traversal_targets.sql';

function ownedUrl(name, database) {
  const value = new URL(process.env[name]);
  assert.equal(value.hostname, '127.0.0.1');
  assert.equal(value.pathname, `/${database}`);
  return value.href;
}
function pool(url, max = 4) {
  return new Pool({ connectionString: url, max, connectionTimeoutMillis: 5000,
    statement_timeout: 30000, lock_timeout: 5000,
    application_name: 'owasp-ai-goat-finflow-traversal-durability' });
}
async function rejectedCode(work, code) {
  await assert.rejects(work, error => error?.code === code);
}
function execution(ownerId, generation) {
  return Object.freeze({ ownerId: String(ownerId), ownerKey: finflowOwnerKey(ownerId),
    durableGeneration: String(generation), runId: randomUUID(), check: async () => {} });
}
function resetJournal() {
  let state;
  let next = 0;
  return {
    begin: async ({ ownerId }) => (state ||= { operationId: randomUUID(), ownerId,
      fromGeneration: 0, toGeneration: 1, status: 'pending' }),
    read: async () => state,
    claim: async () => ({ ...state, leaseToken: randomUUID() }),
    nextStep: async () => ['legacy_store', 'finflow_store'][next++] || null,
    acknowledge: async () => {}, fail: async () => {},
    complete: async value => ({ ...value, status: 'completed' }),
  };
}
function resetCleanup() {
  const receipts = new Map();
  return {
    apply: async value => { receipts.set(value.stepKey, { ...value }); },
    readReceipt: async value => receipts.get(value.stepKey),
  };
}
function runWorker(env) {
  const child = fork(path.join(__dirname, 'finflowTraversalProvisionWorker.js'), [], {
    cwd: path.resolve(__dirname, '../..'), env: { ...process.env, ...env },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  child.stderr.resume();
  return superviseOwnedWorker(child);
}

test('owned PostgreSQL proves readiness negatives, immutable lifecycle, process concurrency, and factory retirement adapter',
  { skip: !enabled, timeout: 120000 }, async t => {
    const identityRuntimeUrl = ownedUrl('IDENTITY_DATABASE_URL',
      'owasp_ai_goat_test_finflow_traversal_identity');
    const identityMigrationUrl = ownedUrl('IDENTITY_MIGRATION_DATABASE_URL',
      'owasp_ai_goat_test_finflow_traversal_identity');
    const finflowRuntimeUrl = ownedUrl('FINFLOW_WORKSHOP_DATABASE_URL',
      'owasp_ai_goat_test_finflow_traversal_store');
    const finflowMigrationUrl = ownedUrl('FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL',
      'owasp_ai_goat_test_finflow_traversal_store');
    const probeRuntimeUrl = ownedUrl('FINFLOW_TRAVERSAL_PROBE_DATABASE_URL',
      'owasp_ai_goat_test_finflow_traversal_probe');
    const probeMigrationUrl = ownedUrl('FINFLOW_TRAVERSAL_PROBE_MIGRATION_DATABASE_URL',
      'owasp_ai_goat_test_finflow_traversal_probe');
    const pools = [pool(identityRuntimeUrl), pool(identityMigrationUrl), pool(finflowRuntimeUrl, 1),
      pool(finflowMigrationUrl), pool(probeRuntimeUrl, 1), pool(probeMigrationUrl)];
    const [identityRuntime, identityMigration, finflowRuntime, finflowMigration,
      probeRuntime, probeMigration] = pools;
    t.after(async () => Promise.allSettled(pools.map(value => value.end())));

    const probeRepository = createFinflowTraversalTargetRepository({ pool: probeRuntime });
    await probeMigration.query('DROP SCHEMA IF EXISTS finflow CASCADE');
    await probeMigration.query('DROP SCHEMA IF EXISTS legacy_sensitive CASCADE');
    await probeMigration.query('DROP SCHEMA IF EXISTS dvaia_migrations CASCADE');
    await rejectedCode(probeRepository.assertReady(), 'TRAVERSAL_TARGET_STORAGE_NOT_READY');
    await probeMigration.query(`CREATE SCHEMA finflow AUTHORIZATION dvaia_finflow_migration;
      REVOKE ALL ON SCHEMA finflow FROM PUBLIC; GRANT USAGE ON SCHEMA finflow TO dvaia_finflow_runtime`);
    await rejectedCode(probeRepository.assertReady(), 'TRAVERSAL_TARGET_STORAGE_NOT_READY');
    await probeMigration.query(`CREATE TABLE finflow.traversal_targets(owner_key text);
      CREATE TABLE finflow.trigger_spoof(id integer);
      CREATE FUNCTION finflow.trigger_spoof_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RETURN NEW; END $$;
      CREATE TRIGGER finflow_traversal_target_immutability BEFORE UPDATE
        ON finflow.trigger_spoof FOR EACH ROW EXECUTE FUNCTION finflow.trigger_spoof_guard();
      GRANT SELECT,INSERT,UPDATE ON finflow.traversal_targets TO dvaia_finflow_runtime`);
    await rejectedCode(probeRepository.assertReady(), 'TRAVERSAL_TARGET_STORAGE_NOT_READY');
    await probeMigration.query('DROP SCHEMA finflow CASCADE');
    await probeMigration.query('DROP SCHEMA IF EXISTS legacy_sensitive CASCADE');
    await probeMigration.query('DROP SCHEMA IF EXISTS dvaia_migrations CASCADE');
    const probeDb = require('../../server/database/postgres/sensitiveInfoWorkshopDb')
      .createFinflowWorkshopDb(probeRuntime);
    await probeDb.initialize(probeMigration);
    assert.equal(await probeRepository.assertReady(), true);
    assert.equal((await probeMigration.query(`SELECT count(*)::integer AS count
      FROM dvaia_migrations.ledger WHERE name=$1`, [TRAVERSAL_MIGRATION])).rows[0].count, 1);
    const probeLedger = await probeMigration.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name');
    await probeDb.initialize(probeMigration);
    assert.deepEqual((await probeMigration.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, probeLedger.rows);

    await require('../../server/database/postgres/identityRepository')
      .initializeIdentityRepository(identityRuntime, identityMigration);
    await require('../../server/database/postgres/workshopPlatformSeed')
      .seedWorkshopPlatform(identityMigration);
    await require('../../server/database/postgres/sensitiveInfoWorkshopDb')
      .createFinflowWorkshopDb(finflowRuntime).initialize(finflowMigration);
    assert.equal((await finflowMigration.query(`SELECT count(*)::integer AS count
      FROM dvaia_migrations.ledger WHERE name=$1`, [TRAVERSAL_MIGRATION])).rows[0].count, 1);
    const repository = createFinflowTraversalTargetRepository({ pool: finflowRuntime });
    assert.equal(await repository.assertReady(), true);
    const privilege = (await finflowRuntime.query(`SELECT
      has_table_privilege(current_user,'finflow.traversal_targets','SELECT,INSERT,UPDATE') AS allowed,
      has_table_privilege(current_user,'finflow.traversal_targets','DELETE') AS can_delete`)).rows[0];
    assert.deepEqual(privilege, { allowed: true, can_delete: false });

    const targetRoot = path.resolve(process.env.FINFLOW_TRAVERSAL_TARGET_ROOT);
    fs.mkdirSync(targetRoot, { recursive: true, mode: 0o700 });
    fs.chmodSync(targetRoot, 0o700);
    const workers = [randomUUID(), randomUUID()].map(runId => runWorker({
      FINFLOW_TRAVERSAL_OWNER: '41000', FINFLOW_TRAVERSAL_GENERATION: '3',
      FINFLOW_TRAVERSAL_RUN_ID: runId, FINFLOW_TRAVERSAL_TARGET_ROOT: targetRoot,
    }));
    t.after(() => stopOwnedWorkers(workers));
    let outcomes;
    try {
      await bounded(Promise.all(workers.map(value => value.ready)), 15000,
        'OWNED_WORKER_READY_TIMEOUT');
      workers.forEach(value => value.send('go'));
      outcomes = await bounded(Promise.all(workers.map(value => value.result)), 15000,
        'OWNED_WORKER_RESULT_TIMEOUT');
      assert.equal(outcomes.every(value => value.ok), true, JSON.stringify(outcomes));
      assert.equal(new Set(outcomes.map(value => value.sha256)).size, 1);
      await bounded(Promise.all(workers.map(value => value.exit)), 15000,
        'OWNED_WORKER_EXIT_TIMEOUT');
    } finally {
      await stopOwnedWorkers(workers);
    }
    const concurrentRows = (await finflowRuntime.query(`SELECT target_token::text,state FROM finflow.traversal_targets
      WHERE owner_key=$1 AND generation=3`, [finflowOwnerKey('41000')])).rows;
    assert.equal(concurrentRows.length, 1);
    assert.equal(concurrentRows[0].state, 'active');

    const current = execution('41001', 7);
    const composition = await createSensitiveInfoResetComposition({
      env: { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' },
      journal: resetJournal(), cleanup: resetCleanup(), traversalRepository: repository,
      finflowPool:finflowRuntime,appDataRoot:path.dirname(targetRoot),traversalRoot: targetRoot,
      runs: { reset: async (_owner, work) => work() },
      finflowReset: async (_owner, work) => work(),
    });
    const artifact = await composition.traversalManager.read({ execution: current,
      toolName: 'get_transaction_history',
      params: { account_id: '../../sensitive_files/config/secrets.env' }, resultPrefix: 'native' });
    assert.match(artifact.content, /JWT_SECRET/);
    const active = await repository.get(current);
    assert.equal(active.state, 'active');
    const activeDirectory = path.join(targetRoot, active.targetToken);
    assert.equal(fs.existsSync(activeDirectory), true);
    await rejectedCode(finflowMigration.query(`UPDATE finflow.traversal_targets SET state='retired'
      WHERE owner_key=$1 AND generation=$2`, [current.ownerKey, current.durableGeneration]), '23514');
    await rejectedCode(finflowRuntime.query(`UPDATE finflow.traversal_targets SET target_token=$1
      WHERE owner_key=$2 AND generation=$3`, [randomUUID(), current.ownerKey, current.durableGeneration]), '23514');
    const reset = await composition.reset.reset(41001);
    assert.equal(reset.status, 'completed');
    assert.equal((await repository.get(current)).state, 'retired');
    assert.equal(fs.existsSync(activeDirectory), false);
    await rejectedCode(finflowMigration.query(`UPDATE finflow.traversal_targets SET cleanup_error_code='REWRITE'
      WHERE owner_key=$1 AND generation=$2`, [current.ownerKey, current.durableGeneration]), '23514');
    await rejectedCode(finflowMigration.query(`DELETE FROM finflow.traversal_targets
      WHERE owner_key=$1 AND generation=$2`, [current.ownerKey, current.durableGeneration]), '23514');
    await composition.traversalManager.retireOwner('41000');
    assert.equal((await repository.get(execution('41000', 3))).state, 'retired');

    let failPath = null;
    const targetFs = new Proxy(fs, { get(target, property, receiver) {
      if (property !== 'rmSync') return Reflect.get(target, property, receiver);
      return (filename, options) => {
        if (failPath && path.resolve(filename) === failPath) {
          failPath = null;
          throw Object.assign(new Error('owned cleanup fixture failure'), { code: 'EIO' });
        }
        return target.rmSync(filename, options);
      };
    } });
    const deletionTraversal = await require('../../server/services/studentDeletionProduction')
      .createFinflowDeletionTraversal({ pool: finflowRuntime, root: targetRoot, fsImpl: targetFs });
    const deletionResources = await require('../../server/services/finflowDurableResourceComposition')
      .createFinflowDurableResourceLifecycle({pool:finflowRuntime,appDataRoot:path.dirname(targetRoot)});
    const deletionOwner = execution('41002', 9);
    const siblingOwner = execution('41003', 9);
    await deletionTraversal.manager.read({ execution: deletionOwner,
      toolName: 'get_transaction_history',
      params: { account_id: '../../sensitive_files/config/secrets.env' } });
    await deletionTraversal.manager.read({ execution: siblingOwner,
      toolName: 'get_transaction_history',
      params: { account_id: '../../sensitive_files/config/secrets.env' } });
    const deletionTarget = await repository.get(deletionOwner);
    const siblingTarget = await repository.get(siblingOwner);
    const deletionDirectory = path.join(targetRoot, deletionTarget.targetToken);
    const siblingDirectory = path.join(targetRoot, siblingTarget.targetToken);
    await finflowRuntime.query(`INSERT INTO finflow.progress(user_id,objective_id,completed)
      VALUES($1,'traversal_secrets',true) ON CONFLICT DO NOTHING`, ['41002']);
    let destroyCalls = 0;
    const adapters = require('../../server/services/studentDeletionAdapters')
      .createStudentDeletionAdapters(request => {
        assert.equal(request, '../routes/sensitiveInfoWorkshop');
        return { resetOwner: async (_owner, work) => work() };
      }, {
        secureShopCleanup: async () => ({ completed: true }),
        cleanupFinflowBackups: deletionResources.cleanupOwner,
        retireFinflowTraversalOwner: deletionTraversal.retireOwner,
        storeCleanup: { finflow: async scope => {
          destroyCalls++;
          const removed = Number((await finflowRuntime.query(
            'SELECT finflow.destroy_student_owner($1::bigint,$2::uuid) AS removed',
            [scope.subjectId,scope.jobId])).rows[0].removed);
          return { completed: true, removed };
        } },
      });
    const deletionJob=randomUUID();
    const deletionScope = { subjectId: 41002,jobId:deletionJob,leaseToken:randomUUID(),
      idempotencyKey:`${deletionJob}:finflow`,check: async () => {},
      signal: new AbortController().signal };
    failPath = deletionDirectory;
    await rejectedCode(adapters.finflow(deletionScope),
      'CONTROLLED_TRAVERSAL_CLEANUP_FAILED');
    assert.equal(destroyCalls, 0, 'store destruction must not succeed before target retirement');
    assert.equal((await repository.get(deletionOwner)).state, 'cleanup_debt');
    assert.equal(fs.existsSync(deletionDirectory), true);
    const deletionReceipt = await adapters.finflow(deletionScope);
    assert.equal(deletionReceipt.completed, true);
    assert.equal(destroyCalls, 1);
    assert.equal((await repository.get(deletionOwner)).state, 'retired');
    assert.equal(fs.existsSync(deletionDirectory), false);
    assert.equal((await finflowRuntime.query(
      'SELECT count(*)::integer AS count FROM finflow.progress WHERE user_id=$1',
    ['41002'])).rows[0].count, 0);
    assert.equal((await repository.get(siblingOwner)).state, 'active');
    assert.equal(fs.existsSync(siblingDirectory), true);
    await deletionTraversal.retireOwner('41003');
  });
