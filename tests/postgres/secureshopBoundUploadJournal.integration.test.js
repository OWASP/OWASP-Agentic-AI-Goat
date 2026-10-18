'use strict';

// Database/repository qualification only. This fixture does not perform a physical
// upload, invoke a graph/model/Judge, render a browser, or award objective credit.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { Pool } = require('pg');
const { migrate, readMigrations, executionSql } = require('../../db/postgres/migrate');
const { withTransaction, verifyServer } = require('../../server/database/postgres');
const { createSecureShopBoundUploadRepository } = require('../../server/database/postgres/secureshopBoundUploadRepository');

const PREFIX = 'PG_SECURESHOP_BOUND_UPLOAD_';
const DIRECTORY = path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_review');
const TABLES = ['bound_upload_admissions', 'bound_upload_effects', 'bound_upload_serves',
  'bound_upload_reconciliations', 'bound_upload_cleanup_receipts'];
const FUNCTIONS = ['claim_bound_upload_admission', 'append_bound_upload_effect',
  'append_bound_upload_serve', 'reconcile_bound_upload', 'append_bound_upload_cleanup'];
const enabled = process.env.SECURESHOP_BOUND_UPLOAD_NATIVE === '1';

function urls(store) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes', 'Explicit disposable launcher required');
  const result = {};
  for (const role of ['MIGRATION', 'RUNTIME']) {
    const key = `${PREFIX}${store}_${role}_URL`;
    assert.ok(process.env[key], `Missing ${key}`);
    const parsed = new URL(process.env[key]);
    assert.equal(parsed.protocol, 'postgresql:');
    assert.equal(parsed.hostname, '127.0.0.1');
    assert.equal(parsed.username, `dvaia_secureshop_review_${role.toLowerCase()}`);
    assert.match(parsed.pathname, new RegExp(`^/dvaia_test_bound_upload_[a-f0-9]{12}_${store.toLowerCase()}$`));
    result[role.toLowerCase()] = process.env[key];
  }
  return result;
}

function pools(store) {
  const value = urls(store);
  return { migration: new Pool({ connectionString: value.migration, max: 4 }),
    runtime: new Pool({ connectionString: value.runtime, max: 8 }) };
}

function id(value) {
  const n = String(value);
  return `${n.padStart(8, '0')}-0000-4000-8000-${n.padStart(12, '0')}`;
}

function scope(seed, owner = seed + 100, session = seed + 200) {
  return Object.freeze({ targetId: id(seed), launchId: id(seed + 1000), scenarioId: id(seed + 2000),
    generation: 1, platformOwnerId: owner, platformSessionId: session, sceneId: id(seed + 3000),
    sceneGeneration: 1, grantId: id(seed + 4000), shopUserId: seed + 300,
    personaSessionId: id(seed + 5000), personaAuthorityVersion: '1', mode: 'vuln',
    modeGeneration: 1, modeStamp: 'a'.repeat(64) });
}

function rawAdmission(authority, seed, overrides = {}) {
  const bodySha256 = (seed % 2 ? 'b' : 'c').repeat(64);
  return { operationId: id(seed + 6000), uploadRequestId: id(seed + 7000), storageKey: id(seed + 8000),
    scope: { ...authority }, request: { kind: 'avatar', scopeId: authority.shopUserId,
      originalFilename: `lesson-${seed}.php`, declaredMime: 'application/x-httpd-php', public: true,
      byteCount: 5, bodySha256 }, ...overrides };
}

function fileReceipt(admission) {
  return { storageKey: admission.storageKey, originalFilename: admission.request.originalFilename,
    cleanedFilename: admission.request.originalFilename, declaredMime: admission.request.declaredMime,
    byteCount: admission.request.byteCount, bodySha256: admission.request.bodySha256,
    baseVirtualPath: `/uploads/avatars/${admission.scope.shopUserId}`,
    resolvedVirtualPath: `/uploads/avatars/${admission.scope.shopUserId}/${admission.request.originalFilename}`,
    storedVirtualPath: `/uploads/avatars/${admission.scope.shopUserId}/${admission.storageKey}`,
    isTraversal: false };
}

async function insertTarget(pool, authority, label) {
  await pool.query(`INSERT INTO secureshop_review.product_targets
    (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,own_merchant_id,source_count,source_sha256)
    VALUES($1,$2,$3,$4,$5,$6,$7,1,decode($8,'hex'))`,
  [authority.targetId, authority.launchId, authority.scenarioId, authority.generation,
    authority.platformOwnerId, authority.platformSessionId, authority.shopUserId, '1'.repeat(64)]);
  await pool.query(`INSERT INTO secureshop_review.product_target_products
    (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,description,
     price,stock_quantity,status) VALUES($1,$2,$3,$3,decode($4,'hex'),$5,$6,9.99,1,'active')`,
  [authority.targetId, authority.shopUserId, authority.shopUserId, '2'.repeat(64), label, `${label} preserved`]);
  await pool.query(`INSERT INTO secureshop_review.scene_execution_grants
    (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
     original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
  [authority.grantId, authority.sceneId, authority.sceneGeneration, authority.targetId,
    authority.launchId, authority.scenarioId, authority.generation,
    authority.platformOwnerId, authority.platformSessionId]);
}

async function requireActive(pool, authority) {
  const row = (await pool.query(`SELECT lifecycle,launch_id,scenario_id,generation,
    original_platform_owner_id,original_platform_session_id FROM secureshop_review.product_targets
    WHERE target_id=$1`, [authority.targetId])).rows[0];
  if (!row || row.lifecycle !== 'active' || row.launch_id !== authority.launchId ||
      row.scenario_id !== authority.scenarioId || Number(row.generation) !== authority.generation ||
      row.original_platform_owner_id !== authority.platformOwnerId ||
      row.original_platform_session_id !== authority.platformSessionId) {
    throw Object.assign(new Error('Upload target authority unavailable'), { code: 'BOUND_UPLOAD_AUTHORITY_LOST' });
  }
}

async function requireGrant(pool, authority) {
  const row = (await pool.query(`SELECT secureshop_review.assert_scene_execution_grant
    ($1,$2,$3,$4,$5,$6,$7,$8,$9) AS valid`, [authority.grantId, authority.sceneId,
    authority.sceneGeneration, authority.targetId, authority.launchId, authority.scenarioId,
    authority.generation, authority.platformOwnerId, authority.platformSessionId])).rows[0];
  if (row?.valid !== true) throw Object.assign(new Error('Upload scene authority unavailable'),
    { code: 'BOUND_UPLOAD_AUTHORITY_LOST' });
}

async function requireCleanup(pool, authority) {
  const row = (await pool.query(`SELECT lifecycle,launch_id,scenario_id,generation,
    original_platform_owner_id,original_platform_session_id FROM secureshop_review.product_targets
    WHERE target_id=$1`, [authority.targetId])).rows[0];
  if (!row || row.lifecycle !== 'retired' || row.launch_id !== authority.launchId ||
      row.scenario_id !== authority.scenarioId || Number(row.generation) !== authority.generation ||
      row.original_platform_owner_id !== authority.platformOwnerId ||
      row.original_platform_session_id !== authority.platformSessionId) {
    throw Object.assign(new Error('Upload cleanup authority unavailable'), { code: 'BOUND_UPLOAD_CLEANUP_UNAVAILABLE' });
  }
}

function repository(pool, overrides = {}) {
  return createSecureShopBoundUploadRepository(pool, {
    checkCurrent: overrides.checkCurrent || (value => requireActive(pool, value)),
    assertSceneGrant: overrides.assertSceneGrant || (value => requireGrant(pool, value)),
    checkCleanupAuthority: overrides.checkCleanupAuthority || (value => requireCleanup(pool, value)),
  });
}

async function retire(pool, authority) {
  const result = await pool.query("UPDATE secureshop_review.product_targets SET lifecycle='retired' WHERE target_id=$1 AND lifecycle='active'", [authority.targetId]);
  assert.equal(result.rowCount, 1);
}

async function preparePopulatedPrefix(pool) {
  const migrations = await readMigrations(DIRECTORY);
  const prefix = migrations.filter(value => value.name < '0053_');
  assert.equal(prefix.at(-1)?.name, '0052_bound_upload_journal.sql');
  return withTransaction(pool, async client => {
    await verifyServer(client);
    await client.query('SELECT pg_advisory_xact_lock(1886610804, 1)');
    await client.query('CREATE SCHEMA IF NOT EXISTS dvaia_migrations');
    await client.query(`CREATE TABLE IF NOT EXISTS dvaia_migrations.ledger (
      name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
    const existing = await client.query('SELECT name FROM dvaia_migrations.ledger');
    assert.equal(existing.rowCount, 0);
    for (const migration of prefix) {
      await client.query(executionSql(migration));
      await client.query('INSERT INTO dvaia_migrations.ledger(name,checksum) VALUES($1,$2)',
        [migration.name, migration.checksum]);
    }
    return prefix.map(value => value.name);
  });
}

async function privilegeProof(migration) {
  const roles = await migration.query(`SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls
    FROM pg_roles WHERE rolname=ANY($1::text[]) ORDER BY rolname`,
  [['dvaia_secureshop_review_migration', 'dvaia_secureshop_review_runtime']]);
  assert.deepEqual(roles.rows.map(row => row.rolname),
    ['dvaia_secureshop_review_migration', 'dvaia_secureshop_review_runtime']);
  assert.ok(roles.rows.every(row => ['rolsuper', 'rolcreatedb', 'rolcreaterole', 'rolreplication', 'rolbypassrls']
    .every(field => row[field] === false)));
  const tables = await migration.query(`SELECT c.relname,
    has_table_privilege('dvaia_secureshop_review_runtime',c.oid,'SELECT') AS can_select,
    has_table_privilege('dvaia_secureshop_review_runtime',c.oid,'INSERT') AS can_insert,
    has_table_privilege('dvaia_secureshop_review_runtime',c.oid,'UPDATE') AS can_update,
    has_table_privilege('dvaia_secureshop_review_runtime',c.oid,'DELETE') AS can_delete,
    EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
      WHERE a.grantee=0 AND a.privilege_type IN('SELECT','INSERT','UPDATE','DELETE','TRUNCATE')) AS public_access
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='secureshop_review' AND c.relname=ANY($1::text[]) ORDER BY c.relname`, [TABLES]);
  assert.deepEqual(tables.rows.map(row => row.relname), [...TABLES].sort());
  assert.ok(tables.rows.every(row => row.can_select === true && row.can_insert === false &&
    row.can_update === false && row.can_delete === false && row.public_access === false));
  const functions = await migration.query(`SELECT p.proname,
    has_function_privilege('dvaia_secureshop_review_runtime',p.oid,'EXECUTE') AS runtime_execute,
    EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
      WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='secureshop_review' AND p.proname=ANY($1::text[]) ORDER BY p.proname`, [FUNCTIONS]);
  assert.deepEqual(functions.rows.map(row => row.proname), [...FUNCTIONS].sort());
  assert.ok(functions.rows.every(row => row.runtime_execute === true && row.public_execute === false));
}

test('fresh native journal uses exact repository receipts, least privilege, retirement and lock fences',
  { skip: !enabled, timeout: 120000 }, async () => {
    const store = pools('FRESH');
    let claimPool;
    try {
      const applied = await migrate(store.migration, DIRECTORY);
      assert.equal(applied.at(-1), '0053_bound_upload_reconciliation_aliases.sql');
      assert.deepEqual(await migrate(store.migration, DIRECTORY), []);
      await privilegeProof(store.migration);
      await assert.rejects(store.runtime.query('CREATE TABLE secureshop_review.bound_upload_forbidden(value integer)'),
        error => error.code === '42501');

      const owner = scope(101), sibling = scope(102), raceScope = scope(103);
      await insertTarget(store.runtime, owner, 'owner row');
      await insertTarget(store.runtime, sibling, 'sibling row');
      await insertTarget(store.runtime, raceScope, 'race sibling row');
      const repo = repository(store.runtime);

      const completedRaw = rawAdmission(owner, 201);
      const completed = await repo.claim(completedRaw);
      assert.equal(completed.replayed, false);
      assert.equal((await repo.claim(completedRaw)).replayed, true);
      const claimConflict = rawAdmission(owner, 202, { uploadRequestId: completedRaw.uploadRequestId });
      await assert.rejects(repo.claim(claimConflict), error => error.code === '55000');

      const completedEffectRaw = { effectId: id(9201), outcome: 'completed', file: fileReceipt(completed),
        denialCode: null, quarantineRequired: false };
      const completedEffect = await repo.recordEffect(completedRaw, completedEffectRaw);
      assert.equal(completedEffect.replayed, false);
      assert.equal((await repo.recordEffect(completedRaw, completedEffectRaw)).replayed, true);
      await assert.rejects(repo.recordEffect(completedRaw, { ...completedEffectRaw, effectId: id(9202) }),
        error => error.code === '55000');
      const serveRaw = { serveId: id(9301), receiptPath: '/asset/owned-capability', status: 200,
        contentType: completed.request.declaredMime, contentDisposition: 'inline; filename="lesson.php"',
        nosniffPresent: false, responseByteCount: completed.request.byteCount,
        responseSha256: completed.request.bodySha256 };
      assert.equal((await repo.recordServe(completedRaw, serveRaw, completedEffect)).replayed, false);
      assert.equal((await repo.recordServe(completedRaw, serveRaw, completedEffect)).replayed, true);

      const unresolvedRaw = rawAdmission(owner, 203);
      const unresolved = await repo.claim(unresolvedRaw);
      const unresolvedEffectRaw = { effectId: id(9203), outcome: 'unresolved', file: fileReceipt(unresolved),
        denialCode: null, quarantineRequired: true };
      const unresolvedEffect = await repo.recordEffect(unresolvedRaw, unresolvedEffectRaw);
      const orphanRaw = rawAdmission(owner, 204);
      await repo.claim(orphanRaw);

      const siblingSubstitution = rawAdmission(sibling, 205, { operationId: completedRaw.operationId,
        uploadRequestId: completedRaw.uploadRequestId, storageKey: completedRaw.storageKey });
      await assert.rejects(repo.recordEffect(siblingSubstitution,
        { effectId: id(9205), outcome: 'denied', file: null, denialCode: 'SIBLING', quarantineRequired: false }),
      error => error.code === '22023');
      const requestSubstitution = { ...completedRaw, request: { ...completedRaw.request,
        originalFilename: 'substituted.php', bodySha256: 'd'.repeat(64) } };
      await assert.rejects(repo.recordEffect(requestSubstitution,
        { effectId: id(9206), outcome: 'denied', file: null, denialCode: 'SUBSTITUTED', quarantineRequired: false }),
      error => error.code === '22023');

      await retire(store.runtime, owner);
      const unresolvedReceipt = { action: 'quarantined', receiptSha256: 'e'.repeat(64) };
      assert.equal((await repo.reconcile(unresolvedRaw, unresolvedEffect, unresolvedReceipt)).replayed, false);
      assert.equal((await repo.reconcile(unresolvedRaw, unresolvedEffect, unresolvedReceipt)).replayed, true);
      const orphanReceipt = { action: 'deleted', receiptSha256: 'f'.repeat(64) };
      assert.equal((await repo.reconcileOrphan(orphanRaw, orphanReceipt)).replayed, false);
      assert.equal((await repo.reconcileOrphan(orphanRaw, orphanReceipt)).replayed, true);
      const cleanup = { cleanupOperationId: id(9401), scope: { ...owner }, deletedCount: 2,
        quarantinedCount: 1, receiptSha256: '9'.repeat(64) };
      assert.equal((await repo.recordCleanup(cleanup)).replayed, false);
      assert.equal((await repo.recordCleanup(cleanup)).replayed, true);
      await assert.rejects(repo.recordCleanup({ ...cleanup, cleanupOperationId: id(9402) }),
        error => error.code === '55000');
      assert.equal((await store.runtime.query(`SELECT description FROM secureshop_review.product_target_products
        WHERE target_id=$1`, [sibling.targetId])).rows[0].description, 'sibling row preserved');

      const stale = repository(store.runtime, { checkCurrent: async () => {}, assertSceneGrant: async () => {} });
      await assert.rejects(stale.recordEffect(orphanRaw,
        { effectId: id(9207), outcome: 'denied', file: null, denialCode: 'LATE', quarantineRequired: false }),
      error => error.code === '55000');
      await assert.rejects(store.runtime.query('UPDATE secureshop_review.bound_upload_admissions SET original_filename=$1 WHERE operation_id=$2',
        ['changed.php', completed.operationId]), error => error.code === '42501');

      const raceAdmission = rawAdmission(raceScope, 206);
      await repo.claim(raceAdmission);
      await retire(store.runtime, raceScope);
      await repo.reconcileOrphan(raceAdmission, { action: 'deleted', receiptSha256: '8'.repeat(64) });
      let releaseCleanup = () => {}, cleanupAtCommit, cleanupPending, latePending;
      const held = new Promise(resolve => { releaseCleanup = resolve; });
      const atCommit = new Promise(resolve => { cleanupAtCommit = resolve; });
      try {
        let cleanupChecks = 0;
        const cleanupRepo = repository(store.runtime, { checkCleanupAuthority: async value => {
          await requireCleanup(store.runtime, value);
          if (++cleanupChecks === 3) { cleanupAtCommit(); await held; }
        } });
        cleanupPending = cleanupRepo.recordCleanup({ cleanupOperationId: id(9403), scope: { ...raceScope },
          deletedCount: 1, quarantinedCount: 0, receiptSha256: '7'.repeat(64) });
        await Promise.race([atCommit, cleanupPending.then(() => { throw new Error('cleanup skipped commit fence'); })]);

        const runtimeUrl = urls('FRESH').runtime;
        claimPool = new Pool({ connectionString: runtimeUrl, max: 1 });
        const claimPid = (await claimPool.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
        const lateRepo = repository(claimPool, { checkCurrent: async () => {}, assertSceneGrant: async () => {} });
        const lateClaimRaw = rawAdmission(raceScope, 207);
        latePending = lateRepo.claim(lateClaimRaw).then(value => ({ value }), error => ({ error }));
        let observedLock = false;
        for (let attempt = 0; attempt < 100; attempt += 1) {
          const state = (await store.runtime.query(`SELECT state,wait_event_type FROM pg_stat_activity
            WHERE pid=$1`, [claimPid])).rows[0];
          if (state?.state === 'active' && state.wait_event_type === 'Lock') { observedLock = true; break; }
          await new Promise(resolve => setTimeout(resolve, 10));
        }
        assert.equal(observedLock, true, 'same-target claim must visibly wait on the cleanup transaction lock');
        releaseCleanup();
        const [cleaned, late] = await Promise.all([cleanupPending, latePending]);
        assert.equal(cleaned.deletedCount, 1);
        assert.equal(late.error?.code, '55000');
        assert.equal((await store.runtime.query('SELECT count(*)::integer AS count FROM secureshop_review.bound_upload_admissions WHERE target_id=$1',
          [raceScope.targetId])).rows[0].count, 1);
      } finally {
        releaseCleanup();
        await Promise.allSettled([cleanupPending, latePending]);
      }
    } finally {
      await Promise.allSettled([claimPool?.end(), store.runtime.end(), store.migration.end()]);
    }
  });

test('populated through-0052 store applies only 0053 and preserves sibling rows on no-op replay',
  { skip: !enabled, timeout: 120000 }, async () => {
    const store = pools('POPULATED');
    try {
      const prefix = await preparePopulatedPrefix(store.migration);
      assert.equal(prefix.at(-1), '0052_bound_upload_journal.sql');
      const existing = scope(301);
      await insertTarget(store.runtime, existing, 'pre-0053 populated row');
      const before = (await store.runtime.query(`SELECT p.name,p.description,encode(p.source_product_sha256,'hex') AS digest,
        g.grant_id FROM secureshop_review.product_target_products p
        JOIN secureshop_review.scene_execution_grants g USING(target_id) WHERE p.target_id=$1`, [existing.targetId])).rows;
      assert.equal(before.length, 1);
      assert.deepEqual(await migrate(store.migration, DIRECTORY), ['0053_bound_upload_reconciliation_aliases.sql']);
      assert.deepEqual((await store.runtime.query(`SELECT p.name,p.description,encode(p.source_product_sha256,'hex') AS digest,
        g.grant_id FROM secureshop_review.product_target_products p
        JOIN secureshop_review.scene_execution_grants g USING(target_id) WHERE p.target_id=$1`, [existing.targetId])).rows, before);
      for (const table of TABLES) {
        assert.equal((await store.runtime.query(`SELECT count(*)::integer AS count FROM secureshop_review.${table}`)).rows[0].count, 0);
      }
      assert.deepEqual(await migrate(store.migration, DIRECTORY), []);
      assert.deepEqual((await store.runtime.query(`SELECT p.name,p.description,encode(p.source_product_sha256,'hex') AS digest,
        g.grant_id FROM secureshop_review.product_target_products p
        JOIN secureshop_review.scene_execution_grants g USING(target_id) WHERE p.target_id=$1`, [existing.targetId])).rows, before);
    } finally {
      await Promise.allSettled([store.runtime.end(), store.migration.end()]);
    }
  });
