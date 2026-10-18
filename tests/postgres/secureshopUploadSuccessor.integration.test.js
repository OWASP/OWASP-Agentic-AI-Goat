'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { Pool } = require('pg');
const { readMigrations, migrate, executionSql } = require('../../db/postgres/migrate');
const { withTransaction, verifyServer } = require('../../server/database/postgres');
const { assertBoundToolPolicyReadiness } = require('../../server/database/postgres/secureshopBoundToolPolicyReadiness');
const { createSecureShopBoundUploadRepository } = require('../../server/database/postgres/secureshopBoundUploadRepository');
const { createSecureShopBoundUploadResetAdapter } = require('../../server/services/secureshopBoundUploadResetAdapter');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' &&
  process.env.SECURESHOP_UPLOAD_SUCCESSOR_NATIVE === '1';
const PREFIX = 'PG_SECURESHOP_UPLOAD_SUCCESSOR_';
const AGENTS_DIRECTORY = path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_agents');
const REVIEW_DIRECTORY = path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_review');
const V29 = 'bc8edf04a8a13b42871d01699c19c0782d6093fc190df49c999a8d877228fd71';
const V30 = 'e747a55517a50d484901bcc78a98747c98773042cb2bff6396a7654722a470ef';
const V31 = '0a9e93f87983045aa3194f2794f63118a3d62979d3dada88eb91e2e22ff4c15c';
const V31_GUARD = '29c18a399a6273f8fde1c1c6c23355369a410f4beab42a8a52c2a2aa2115c2cf';

function id(value) {
  const text = String(value);
  return `${text.padStart(8, '0')}-0000-4000-8000-${text.padStart(12, '0')}`;
}

function urls(store, roleBase) {
  const result = {};
  for (const role of ['MIGRATION', 'RUNTIME']) {
    const key = `${PREFIX}${store}_${role}_URL`;
    assert.ok(process.env[key], `${key} required`);
    const parsed = new URL(process.env[key]);
    assert.equal(parsed.protocol, 'postgresql:');
    assert.equal(parsed.hostname, '127.0.0.1');
    assert.equal(parsed.username, `dvaia_secureshop_${roleBase}_${role.toLowerCase()}`);
    assert.match(parsed.pathname, /^\/dvaia_test_upload_successor_[a-f0-9]{12}_[a-z_]+$/);
    result[role.toLowerCase()] = process.env[key];
  }
  return result;
}

function pools(store, roleBase) {
  const value = urls(store, roleBase);
  return {
    migration: new Pool({ connectionString: value.migration, max: 4 }),
    runtime: new Pool({ connectionString: value.runtime, max: 8 }),
  };
}

async function preparePrefix(pool, directory, successor) {
  const migrations = await readMigrations(directory);
  const prefix = migrations.filter(migration => migration.name < successor);
  assert.ok(prefix.length > 0);
  return withTransaction(pool, async client => {
    await verifyServer(client);
    await client.query('SELECT pg_advisory_xact_lock(1886610804, 1)');
    await client.query('CREATE SCHEMA IF NOT EXISTS dvaia_migrations');
    await client.query(`CREATE TABLE IF NOT EXISTS dvaia_migrations.ledger (
      name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
    assert.equal((await client.query('SELECT name FROM dvaia_migrations.ledger')).rowCount, 0);
    for (const migration of prefix) {
      await client.query(executionSql(migration));
      await client.query('INSERT INTO dvaia_migrations.ledger(name,checksum) VALUES($1,$2)',
        [migration.name, migration.checksum]);
    }
    return prefix.map(migration => migration.name);
  });
}

function coordinates(seed = 1) {
  return {
    launchId: id(1000 + seed), scenarioId: id(2000 + seed), generation: 3,
    ownerId: 100 + seed, sessionId: 200 + seed,
  };
}

async function insertPurpose(pool, purpose, seed = 1) {
  const c = coordinates(seed);
  return pool.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
     platform_launch_generation,original_platform_owner_id,original_platform_session_id,conversation_purpose)
    VALUES($1,$2,'customer','launch_bound','pending',$3,$4,$5,$6,$7,$8)
    RETURNING id,conversation_purpose`,
  [id(3000 + seed), 400 + seed, c.launchId, c.scenarioId, c.generation,
    c.ownerId, c.sessionId, purpose]);
}

async function runtimeRoleProof(pool) {
  await assert.rejects(pool.query('CREATE TABLE secureshop_agents.upload_successor_forbidden(value integer)'),
    error => error.code === '42501');
  assert.deepEqual(await assertBoundToolPolicyReadiness(pool), { ready: true });
  const row = (await pool.query(`SELECT
    encode(sha256(convert_to(prosrc,'UTF8')),'hex') AS guard_sha,
    EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='secureshop_agents.bound_tool_registry_upgrades'::regclass
      AND conname='bound_tool_registry_successor_v31' AND contype='c' AND convalidated) AS v31
    FROM pg_proc WHERE oid='secureshop_agents.guard_bound_tool_registry_upgrade()'::regprocedure`)).rows[0];
  assert.deepEqual(row, { guard_sha: V31_GUARD, v31: true });
}

test('0102-0104 use production migration history for fresh, populated and no-op stores',
  { skip: !enabled, timeout: 120000 }, async () => {
    const fresh = pools('AGENTS_FRESH', 'agents');
    const populated = pools('AGENTS_POPULATED', 'agents');
    try {
      const freshApplied = await migrate(fresh.migration, AGENTS_DIRECTORY);
      assert.deepEqual(freshApplied.slice(-3), [
        '0102_avatar_upload_conversation_purpose.sql',
        '0103_avatar_upload_registry_successor.sql',
        '0104_avatar_upload_registry_guard_repair.sql',
      ]);
      assert.deepEqual(await migrate(fresh.migration, AGENTS_DIRECTORY), []);
      assert.equal((await insertPurpose(fresh.runtime, 'secureshop_avatar_upload', 1)).rows[0].conversation_purpose,
        'secureshop_avatar_upload');
      await assert.rejects(insertPurpose(fresh.runtime, 'secureshop_avatar_upload_unknown', 2),
        error => error.code === '23514');
      await assert.rejects(fresh.runtime.query(`INSERT INTO secureshop_agents.agent_sessions
        (id,user_id,role,conversation_purpose) VALUES($1,403,'customer','secureshop_avatar_upload')`, [id(3003)]),
      error => error.code === '23514');
      await runtimeRoleProof(fresh.runtime);

      const prefix = await preparePrefix(populated.migration, AGENTS_DIRECTORY,
        '0104_avatar_upload_registry_guard_repair.sql');
      assert.equal(prefix.at(-1), '0103_avatar_upload_registry_successor.sql');
      const retainedSession = (await insertPurpose(populated.runtime, 'secureshop_checkout_audit_jwt', 10)).rows[0];
      const c = coordinates(20);
      const values = [c.launchId, c.scenarioId, c.generation, c.ownerId, c.sessionId];
      await populated.runtime.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads
        (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
         original_platform_session_id,policy_version,enforcement_enabled,registry_sha256)
        VALUES($1,$2,$3,$4,$5,30,true,decode($6,'hex'))`, [...values, V30]);
      await populated.runtime.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides
        (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
         original_platform_session_id,tool_key,role,allowed)
        VALUES($1,$2,$3,$4,$5,'audit.search_by_user','admin',true)`, values);
      const before = {
        session: (await populated.runtime.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',
          [retainedSession.id])).rows,
        head: (await populated.runtime.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',
          [c.launchId])).rows,
        overrides: (await populated.runtime.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1',
          [c.launchId])).rows,
      };
      assert.deepEqual(await migrate(populated.migration, AGENTS_DIRECTORY), [
        '0104_avatar_upload_registry_guard_repair.sql',
      ]);
      assert.deepEqual((await populated.runtime.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',
        [retainedSession.id])).rows, before.session);
      assert.deepEqual((await populated.runtime.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',
        [c.launchId])).rows, before.head);
      assert.deepEqual((await populated.runtime.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1',
        [c.launchId])).rows, before.overrides);
      assert.equal((await insertPurpose(populated.runtime, 'secureshop_avatar_upload', 11)).rows[0].conversation_purpose,
        'secureshop_avatar_upload');

      const overrides = JSON.stringify([{ toolKey: 'audit.search_by_user', role: 'admin', allowed: true }]);
      const receiptSql = `INSERT INTO secureshop_agents.bound_tool_registry_upgrades
        (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
         original_platform_session_id,predecessor_version,successor_version,predecessor_sha256,
         successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
        VALUES($1,$2,$3,$4,$5,30,31,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
          sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`;
      await assert.rejects(populated.runtime.query(receiptSql,
        [...values, V30, V31, overrides,
          JSON.stringify([{ toolKey: 'uploads.upload_avatar', role: 'merchant' }])]),
      error => error.code === '55000');
      assert.equal((await populated.runtime.query(`SELECT count(*)::integer AS count
        FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1`, [c.launchId])).rows[0].count, 0);

      const tx = await populated.runtime.connect();
      try {
        await tx.query('BEGIN');
        await tx.query(receiptSql, [...values, V30, V31, overrides,
          JSON.stringify([{ toolKey: 'uploads.upload_avatar', role: 'customer' }])]);
        await tx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides
          (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
           original_platform_session_id,tool_key,role,allowed)
          VALUES($1,$2,$3,$4,$5,'uploads.upload_avatar','customer',false)`, values);
        await tx.query(`UPDATE secureshop_agents.bound_tool_policy_heads
          SET policy_version=31,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`, [c.launchId, V31]);
        await tx.query('COMMIT');
      } finally {
        await tx.query('ROLLBACK');
        tx.release();
      }
      const receipt = (await populated.runtime.query(`SELECT predecessor_version,successor_version,
        encode(predecessor_sha256,'hex') AS predecessor,encode(successor_sha256,'hex') AS successor,
        overrides_before,added_denials FROM secureshop_agents.bound_tool_registry_upgrades
        WHERE platform_launch_id=$1`, [c.launchId])).rows[0];
      assert.deepEqual(receipt, {
        predecessor_version: '30', successor_version: '31', predecessor: V30, successor: V31,
        overrides_before: JSON.parse(overrides),
        added_denials: [{ toolKey: 'uploads.upload_avatar', role: 'customer' }],
      });

      const historical = coordinates(21);
      const historicalValues = [historical.launchId, historical.scenarioId, historical.generation,
        historical.ownerId, historical.sessionId];
      const historicalDenials = JSON.stringify([
        { toolKey: 'arithmetic.sum', role: 'customer' },
        { toolKey: 'uploads.upload_avatar', role: 'customer' },
      ]);
      await populated.runtime.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads
        (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
         original_platform_session_id,policy_version,enforcement_enabled,registry_sha256)
        VALUES($1,$2,$3,$4,$5,29,true,decode($6,'hex'))`, [...historicalValues, V29]);
      const historicalTx = await populated.runtime.connect();
      try {
        await historicalTx.query('BEGIN');
        await historicalTx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades
          (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
           original_platform_session_id,predecessor_version,successor_version,predecessor_sha256,
           successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
          VALUES($1,$2,$3,$4,$5,29,30,decode($6,'hex'),decode($7,'hex'),true,'[]'::jsonb,
           sha256(convert_to('[]'::jsonb::text,'UTF8')),$8::jsonb)`,
        [...historicalValues, V29, V31, historicalDenials]);
        await historicalTx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides
          (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
           original_platform_session_id,tool_key,role,allowed)
          SELECT $1,$2,$3,$4,$5,x."toolKey",x.role,false
          FROM jsonb_to_recordset($6::jsonb) AS x("toolKey" text,role text)`,
        [...historicalValues, historicalDenials]);
        await historicalTx.query(`UPDATE secureshop_agents.bound_tool_policy_heads
          SET policy_version=30,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,
        [historical.launchId, V31]);
        await historicalTx.query('COMMIT');
      } finally {
        await historicalTx.query('ROLLBACK');
        historicalTx.release();
      }
      assert.deepEqual((await populated.runtime.query(`SELECT predecessor_version,successor_version,
        encode(predecessor_sha256,'hex') AS predecessor,encode(successor_sha256,'hex') AS successor,
        overrides_before,added_denials FROM secureshop_agents.bound_tool_registry_upgrades
        WHERE platform_launch_id=$1`, [historical.launchId])).rows, [{
        predecessor_version: '29', successor_version: '30', predecessor: V29, successor: V31,
        overrides_before: [], added_denials: JSON.parse(historicalDenials),
      }]);
      assert.deepEqual(await migrate(populated.migration, AGENTS_DIRECTORY), []);
      assert.deepEqual((await populated.runtime.query(`SELECT tool_key,role,allowed
        FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role`,
      [c.launchId])).rows, [
        { tool_key: 'audit.search_by_user', role: 'admin', allowed: true },
        { tool_key: 'uploads.upload_avatar', role: 'customer', allowed: false },
      ]);
      await runtimeRoleProof(populated.runtime);
    } finally {
      await Promise.allSettled([
        fresh.runtime.end(), fresh.migration.end(), populated.runtime.end(), populated.migration.end(),
      ]);
    }
  });

function uploadScope() {
  return Object.freeze({
    targetId: id(5001), launchId: id(5002), scenarioId: id(5003), generation: 8,
    platformOwnerId: 501, platformSessionId: 508, sceneId: id(5004), sceneGeneration: 4,
    grantId: id(5005), shopUserId: 601, personaSessionId: id(5006), personaAuthorityVersion: '3',
    mode: 'vuln', modeGeneration: 9, modeStamp: 'a'.repeat(64),
  });
}

function rawAdmission(scope, seed) {
  return {
    operationId: id(6000 + seed), uploadRequestId: id(6100 + seed), storageKey: id(6200 + seed),
    scope: { ...scope }, request: { kind: 'avatar', scopeId: scope.shopUserId,
      originalFilename: `native-${seed}.html`, declaredMime: 'text/html', public: true,
      byteCount: 7, bodySha256: (seed % 2 ? 'b' : 'c').repeat(64) },
  };
}

function fileReceipt(admission) {
  return {
    storageKey: admission.storageKey, originalFilename: admission.request.originalFilename,
    cleanedFilename: admission.request.originalFilename, declaredMime: admission.request.declaredMime,
    byteCount: admission.request.byteCount, bodySha256: admission.request.bodySha256,
    baseVirtualPath: `/operations/${admission.operationId}/avatars/${admission.scope.shopUserId}`,
    resolvedVirtualPath: `/operations/${admission.operationId}/avatars/${admission.scope.shopUserId}/${admission.request.originalFilename}`,
    storedVirtualPath: `/operations/${admission.operationId}/avatars/${admission.scope.shopUserId}/${admission.storageKey}`,
    isTraversal: false,
  };
}

async function insertReviewTarget(pool, target, label) {
  await pool.query(`INSERT INTO secureshop_review.product_targets
    (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,own_merchant_id,source_count,source_sha256)
    VALUES($1,$2,$3,$4,$5,$6,$7,1,decode($8,'hex'))`,
  [target.targetId, target.launchId, target.scenarioId, target.generation,
    target.platformOwnerId, target.platformSessionId, target.shopUserId, '1'.repeat(64)]);
  await pool.query(`INSERT INTO secureshop_review.product_target_products
    (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,description,
     price,stock_quantity,status) VALUES($1,$2,$3,$3,decode($4,'hex'),$5,$6,9.99,1,'active')`,
  [target.targetId, target.shopUserId, target.shopUserId, '2'.repeat(64), label, `${label} preserved`]);
}

test('real repository and reset adapter join current upload admission to immutable target birth',
  { skip: !enabled, timeout: 120000 }, async () => {
    const store = pools('REVIEW', 'review');
    try {
      await migrate(store.migration, REVIEW_DIRECTORY);
      const current = uploadScope();
      const birth = Object.freeze({
        targetId: current.targetId, launchId: id(5101), scenarioId: id(5102), fromGeneration: 2,
        platformOwnerId: current.platformOwnerId, platformSessionId: 502, targetKind: 'files',
      });
      const sibling = Object.freeze({
        targetId: id(5201), launchId: id(5202), scenarioId: id(5203), generation: 2,
        platformOwnerId: 502, platformSessionId: 503, shopUserId: 602,
      });
      const siblingCurrent = Object.freeze({
        ...current, targetId: sibling.targetId, launchId: sibling.launchId,
        scenarioId: sibling.scenarioId, generation: sibling.generation,
        platformOwnerId: sibling.platformOwnerId, platformSessionId: sibling.platformSessionId,
        sceneId: id(5204), grantId: id(5205), shopUserId: sibling.shopUserId,
        personaSessionId: id(5206),
      });
      await insertReviewTarget(store.runtime, { ...birth, generation: birth.fromGeneration,
        shopUserId: current.shopUserId }, 'birth target');
      await insertReviewTarget(store.runtime, sibling, 'sibling target');
      await store.runtime.query(`INSERT INTO secureshop_review.scene_execution_grants
        (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
         original_platform_owner_id,original_platform_session_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [current.grantId, current.sceneId, current.sceneGeneration, current.targetId, current.launchId,
        current.scenarioId, current.generation, current.platformOwnerId, current.platformSessionId]);
      await store.runtime.query(`INSERT INTO secureshop_review.scene_execution_grants
        (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
         original_platform_owner_id,original_platform_session_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [siblingCurrent.grantId, siblingCurrent.sceneId, siblingCurrent.sceneGeneration,
        siblingCurrent.targetId, siblingCurrent.launchId, siblingCurrent.scenarioId,
        siblingCurrent.generation, siblingCurrent.platformOwnerId, siblingCurrent.platformSessionId]);

      const checkCurrent = async scope => {
        assert.deepEqual(scope, current);
        const row = (await store.runtime.query(`SELECT lifecycle,original_platform_owner_id
          FROM secureshop_review.product_targets WHERE target_id=$1`, [scope.targetId])).rows[0];
        if (!row || row.lifecycle !== 'active' || row.original_platform_owner_id !== scope.platformOwnerId) {
          throw Object.assign(new Error('current upload target unavailable'), { code: 'BOUND_UPLOAD_AUTHORITY_LOST' });
        }
      };
      const assertSceneGrant = async scope => {
        const valid = (await store.runtime.query(`SELECT secureshop_review.assert_scene_execution_grant
          ($1,$2,$3,$4,$5,$6,$7,$8,$9) AS valid`, [scope.grantId, scope.sceneId,
          scope.sceneGeneration, scope.targetId, scope.launchId, scope.scenarioId, scope.generation,
          scope.platformOwnerId, scope.platformSessionId])).rows[0]?.valid;
        if (valid !== true) throw Object.assign(new Error('scene grant unavailable'), { code: 'BOUND_UPLOAD_AUTHORITY_LOST' });
      };
      const cleanupChecks = [];
      const checkTarget = async item => {
        cleanupChecks.push({ ...item });
        const row = (await store.runtime.query(`SELECT lifecycle,launch_id,scenario_id,generation,
          original_platform_owner_id,original_platform_session_id FROM secureshop_review.product_targets
          WHERE target_id=$1`, [item.targetId])).rows[0];
        if (!row || row.lifecycle !== 'retired' || row.launch_id !== item.launchId ||
            row.scenario_id !== item.scenarioId || Number(row.generation) !== item.fromGeneration ||
            row.original_platform_owner_id !== item.platformOwnerId ||
            row.original_platform_session_id !== item.platformSessionId || item.operationId !== id(7001)) {
          throw Object.assign(new Error('cleanup birth authority unavailable'),
            { code: 'BOUND_UPLOAD_CLEANUP_UNAVAILABLE' });
        }
        return { status: 'fenced' };
      };
      const journal = createSecureShopBoundUploadRepository(store.runtime, {
        checkCurrent,
        assertSceneGrant,
        checkCleanupAuthority: (scope, operationId) => checkTarget({
          targetId: scope.targetId, launchId: scope.launchId, scenarioId: scope.scenarioId,
          fromGeneration: scope.generation, platformOwnerId: scope.platformOwnerId,
          platformSessionId: scope.platformSessionId, targetKind: 'files', operationId,
        }),
      });

      const completedRaw = rawAdmission(current, 1);
      const unresolvedRaw = rawAdmission(current, 2);
      const orphanRaw = rawAdmission(current, 3);
      const completed = await journal.claim(completedRaw);
      const unresolved = await journal.claim(unresolvedRaw);
      const orphan = await journal.claim(orphanRaw);
      const completedEffect = await journal.recordEffect(completed, {
        effectId: id(6301), outcome: 'completed', file: fileReceipt(completed),
        denialCode: null, quarantineRequired: false,
      });
      const unresolvedEffect = await journal.recordEffect(unresolved, {
        effectId: id(6302), outcome: 'unresolved', file: fileReceipt(unresolved),
        denialCode: null, quarantineRequired: true,
      });
      assert.deepEqual(await journal.find(completed), { ...completedEffect, replayed: true });

      const siblingJournal = createSecureShopBoundUploadRepository(store.runtime, {
        checkCurrent: async scope => {
          assert.deepEqual(scope, siblingCurrent);
          const row = (await store.runtime.query(`SELECT lifecycle,original_platform_owner_id
            FROM secureshop_review.product_targets WHERE target_id=$1`, [scope.targetId])).rows[0];
          if (!row || row.lifecycle !== 'active' || row.original_platform_owner_id !== scope.platformOwnerId) {
            throw Object.assign(new Error('sibling upload target unavailable'), { code: 'BOUND_UPLOAD_AUTHORITY_LOST' });
          }
        },
        assertSceneGrant,
        checkCleanupAuthority: async () => { throw new Error('sibling cleanup not expected'); },
      });
      const siblingAdmission = await siblingJournal.claim(rawAdmission(siblingCurrent, 4));
      const siblingEffect = await siblingJournal.recordEffect(siblingAdmission, {
        effectId: id(6304), outcome: 'completed', file: fileReceipt(siblingAdmission),
        denialCode: null, quarantineRequired: false,
      });
      const siblingBefore = {
        admission: (await store.runtime.query(`SELECT * FROM secureshop_review.bound_upload_admissions
          WHERE operation_id=$1`, [siblingAdmission.operationId])).rows,
        effect: (await store.runtime.query(`SELECT * FROM secureshop_review.bound_upload_effects
          WHERE operation_id=$1`, [siblingAdmission.operationId])).rows,
      };

      await store.runtime.query("UPDATE secureshop_review.product_targets SET lifecycle='retired' WHERE target_id=$1",
        [birth.targetId]);
      const calls = { reconcile: [], verify: [], remove: [], file: [] };
      const storage = {
        async reconcile(admission) {
          calls.reconcile.push(admission.operationId);
          return admission.operationId === orphan.operationId
            ? { action: 'deleted', receiptSha256: 'd'.repeat(64) }
            : { action: 'quarantined', receiptSha256: 'e'.repeat(64) };
        },
        async verifyReconciliation(admission, receipt) { calls.verify.push([admission.operationId, receipt]); },
        async removeCompleted(admission, effect, operationId) {
          assert.equal(admission.operationId, completed.operationId);
          assert.equal(effect.effectId, completedEffect.effectId);
          assert.equal(operationId, id(7001));
          calls.remove.push(admission.operationId);
        },
      };
      const fileCleanup = { async cleanup(item, options) {
        assert.deepEqual(item, birth);
        assert.deepEqual(options, { operationId: id(7001) });
        calls.file.push(item.targetId);
        return { receiptSha256: 'f'.repeat(64) };
      } };
      const adapter = createSecureShopBoundUploadResetAdapter({
        pool: store.runtime, fileCleanup, journal, cleanupAuthority: { checkTarget }, storage,
      });

      const beforeWrong = JSON.parse(JSON.stringify(calls));
      for (const rejected of [
        { ...birth, fromGeneration: 3 },
        { ...birth, platformOwnerId: birth.platformOwnerId + 1 },
        { ...birth, platformSessionId: birth.platformSessionId + 1 },
        { ...birth, targetId: sibling.targetId },
      ]) {
        await assert.rejects(adapter.cleanup(rejected, { operationId: id(7001) }),
          error => error.code === 'BOUND_UPLOAD_CLEANUP_UNAVAILABLE');
        assert.deepEqual(calls, beforeWrong);
      }
      cleanupChecks.length = 0;
      await adapter.cleanup(birth, { operationId: id(7001) });

      const admissions = (await store.runtime.query(`SELECT operation_id,launch_id,scenario_id,generation,
        platform_owner_id,platform_session_id,encode(binding_sha256,'hex') AS binding,
        encode(request_sha256,'hex') AS request FROM secureshop_review.bound_upload_admissions
        WHERE target_id=$1 ORDER BY operation_id`, [birth.targetId])).rows;
      assert.equal(admissions.length, 3);
      for (const [index, admission] of [completed, unresolved, orphan].entries()) {
        const row = admissions.find(value => value.operation_id === admission.operationId);
        assert.equal(row.launch_id, current.launchId);
        assert.equal(row.scenario_id, current.scenarioId);
        assert.equal(Number(row.generation), current.generation);
        assert.equal(row.platform_owner_id, current.platformOwnerId);
        assert.equal(row.platform_session_id, current.platformSessionId);
        assert.equal(row.binding, admission.bindingSha256, String(index));
        assert.equal(row.request, admission.requestSha256, String(index));
      }
      const reconciliations = (await store.runtime.query(`SELECT operation_id,effect_id,action,
        encode(receipt_sha256,'hex') AS receipt FROM secureshop_review.bound_upload_reconciliations
        WHERE operation_id=ANY($1::uuid[]) ORDER BY operation_id`, [[unresolved.operationId, orphan.operationId]])).rows;
      assert.deepEqual(reconciliations, [
        { operation_id: unresolved.operationId, effect_id: unresolvedEffect.effectId,
          action: 'quarantined', receipt: 'e'.repeat(64) },
        { operation_id: orphan.operationId, effect_id: null, action: 'deleted', receipt: 'd'.repeat(64) },
      ].sort((a, b) => a.operation_id.localeCompare(b.operation_id)));
      assert.deepEqual((await store.runtime.query(`SELECT operation_id,launch_id,scenario_id,generation,
        platform_owner_id,platform_session_id,deleted_count,quarantined_count
        FROM secureshop_review.bound_upload_cleanup_receipts WHERE target_id=$1`, [birth.targetId])).rows, [{
        operation_id: id(7001), launch_id: birth.launchId, scenario_id: birth.scenarioId,
        generation: String(birth.fromGeneration), platform_owner_id: birth.platformOwnerId,
        platform_session_id: birth.platformSessionId, deleted_count: 2, quarantined_count: 1,
      }]);
      assert.deepEqual(calls.reconcile.sort(), [unresolved.operationId, orphan.operationId].sort());
      assert.equal(calls.remove.length, 1);
      assert.equal(calls.file.length, 1);
      assert.ok(cleanupChecks.length > 3);
      assert.ok(cleanupChecks.every(value => value.launchId === birth.launchId &&
        value.fromGeneration === birth.fromGeneration && value.platformSessionId === birth.platformSessionId &&
        value.operationId === id(7001)));
      assert.equal((await store.runtime.query(`SELECT description FROM secureshop_review.product_target_products
        WHERE target_id=$1`, [sibling.targetId])).rows[0].description, 'sibling target preserved');
      assert.deepEqual((await store.runtime.query(`SELECT * FROM secureshop_review.bound_upload_admissions
        WHERE operation_id=$1`, [siblingAdmission.operationId])).rows, siblingBefore.admission);
      assert.deepEqual((await store.runtime.query(`SELECT * FROM secureshop_review.bound_upload_effects
        WHERE operation_id=$1`, [siblingAdmission.operationId])).rows, siblingBefore.effect);
      assert.equal((await store.runtime.query(`SELECT count(*)::integer AS count
        FROM secureshop_review.bound_upload_reconciliations WHERE operation_id=$1`,
      [siblingAdmission.operationId])).rows[0].count, 0);
      assert.equal(siblingEffect.operationId, siblingAdmission.operationId);

      await adapter.cleanup(birth, { operationId: id(7001) });
      assert.equal(calls.reconcile.length, 2);
      assert.equal(calls.verify.length, 2);
      assert.equal(calls.remove.length, 2);
      assert.equal(calls.file.length, 2);
      assert.equal((await store.runtime.query(`SELECT count(*)::integer AS count
        FROM secureshop_review.bound_upload_cleanup_receipts WHERE target_id=$1`, [birth.targetId])).rows[0].count, 1);
    } finally {
      await Promise.allSettled([store.runtime.end(), store.migration.end()]);
    }
  });
