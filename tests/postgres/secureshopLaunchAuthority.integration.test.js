'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && Boolean(process.env.PG_SECURESHOP_LAUNCH_TEST_MIGRATION_URL);

test('native launch authority: durable owner, generation, rotation and revocation boundaries', { skip: !enabled }, async t => {
  for (const suffix of ['MIGRATION', 'RUNTIME']) {
    const url = new URL(process.env[`PG_SECURESHOP_LAUNCH_TEST_${suffix}_URL`]);
    assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
  }
  const migration = new Pool({ connectionString: process.env.PG_SECURESHOP_LAUNCH_TEST_MIGRATION_URL });
  const applicationName = `launch-proof-${randomUUID()}`;
  const pool = new Pool({ connectionString: process.env.PG_SECURESHOP_LAUNCH_TEST_RUNTIME_URL, max: 8, application_name: applicationName });
  const agents=new Pool({connectionString:process.env.PG_SECURESHOP_LAUNCH_AGENTS_TEST_RUNTIME_URL}),agentsMigration=new Pool({connectionString:process.env.PG_SECURESHOP_LAUNCH_AGENTS_TEST_MIGRATION_URL});
  for(const key of ['PG_SECURESHOP_LAUNCH_AGENTS_TEST_RUNTIME_URL','PG_SECURESHOP_LAUNCH_AGENTS_TEST_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
  t.after(async () => { await Promise.all([migration.end(), pool.end(),agents.end(),agentsMigration.end()]); });
  assert.equal((await migration.query("SELECT to_regnamespace('identity') AS present")).rows[0].present, null);
  await initializeIdentityRepository(pool, migration);
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
  const repository = createSecureShopLaunchRepository(pool);
  await require('../../server/database/postgres/secureshopAgentsDb').initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:agentsMigration});
  const cleanupAuthority=require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository').createSecureShopResetCleanupAuthorityRepository(pool);
  const conversationLifecycle=require('../../server/services/secureshopConversationLifecycle').createSecureShopConversationLifecycle({repository:require('../../server/database/postgres/secureshopConversationLifecycleRepository').createSecureShopConversationLifecycleRepository({pool:agents}),cleanupAuthority,turns:{retire(){throw new Error('Authority-only fixture must have no conversations');}}});
  const checkpoint=require('../../server/database/postgres/secureshopConversationCleanupCheckpointRepository').createSecureShopConversationCleanupCheckpointRepository(pool,{getOperation:id=>cleanupAuthority.getOperation(id),readRetirementReceipt:id=>conversationLifecycle.readReceipt(id)});
  const progressCheckpoint=require('../../server/database/postgres/secureshopProgressCleanupCheckpointRepository').createSecureShopProgressCleanupCheckpointRepository(pool);
  async function reconcileEmptyConversationAndProgress(resetId){await conversationLifecycle.retireGeneration(resetId);await checkpoint.finalize(resetId);await progressCheckpoint.finalize(resetId);}
  const identity = createIdentityRepository(pool);
  const passwordHash = await bcrypt.hash('owned-synthetic-fixture', 4);
  const expiry = new Date(Date.now() + 3600000).toISOString();
  const alice = await identity.createUser({ username: 'launch-alice', email: 'alice@launch.invalid', passwordHash });
  const bob = await identity.createUser({ username: 'launch-bob', email: 'bob@launch.invalid', passwordHash });
  const session = await identity.createSession({ userId: alice.id, token: randomUUID(), expiresAt: expiry, expectedPasswordHash: passwordHash });
  const bobSession = await identity.createSession({ userId: bob.id, token: randomUUID(), expiresAt: expiry, expectedPasswordHash: passwordHash });
  const scope = { platformSessionId: session.id, platformOwnerId: alice.id };
  const bobScope = { platformSessionId: bobSession.id, platformOwnerId: bob.id };
  let active;
  let bobLaunch;
  let reservedTarget;
  await t.test('issuance stores only a digest, bounds expiry, rejects wrong owner', async () => {
    await assert.rejects(repository.issueOrRenew({ ...scope, platformOwnerId: bob.id, expiresAt: expiry }));
    active = await repository.issueOrRenew({ ...scope, expiresAt: new Date(Date.now() + 7200000).toISOString() });
    assert.ok(typeof active.bearer === 'string' && active.bearer.length >= 43);
    assert.equal(active.binding.platformOwnerId, alice.id);
    assert.equal(active.binding.platformSessionId, session.id);
    assert.equal(active.binding.generation, 1);
    assert.ok(new Date(active.binding.expiresAt).getTime() <= new Date(expiry).getTime());
    const rows = (await migration.query('SELECT row_to_json(l) AS row FROM identity.secureshop_launches l')).rows;
    assert.ok(!JSON.stringify(rows).includes(active.bearer));
    assert.ok(!JSON.stringify(active.binding).includes(active.bearer));
    assert.equal((await repository.resolve({ ...scope, bearer: active.bearer })).scenarioId, active.binding.scenarioId);
    assert.deepEqual(await repository.resolveCapability(active.bearer), active.binding);
    for (const invalid of [undefined, null, {}, '', 'invalid', 'x'.repeat(1000), 'A'.repeat(43)]) {
      assert.equal(await repository.resolveCapability(invalid), null);
    }
    assert.equal(await repository.resolve({ ...bobScope, bearer: active.bearer }), null);
    assert.equal((await repository.resolveCapability(active.bearer)).platformOwnerId, alice.id);
    assert.equal(await repository.resolve({ ...scope, platformOwnerId: bob.id, bearer: active.bearer }), null);
    bobLaunch = await repository.issueOrRenew({ ...bobScope, expiresAt: expiry });
    assert.notEqual(bobLaunch.binding.scenarioId, active.binding.scenarioId);
  });
  await t.test('concurrent renewal keeps one scenario and exactly one valid bearer', async () => {
    const first = active;
    await assert.rejects(repository.issueOrRenew({ ...scope, expiresAt: expiry }));
    const results = await Promise.allSettled(Array.from({ length: 4 }, () => repository.issueOrRenew({ ...scope, expiresAt: expiry, expectedBearer: first.bearer })));
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    const rotations = results.filter(result => result.status === 'fulfilled').map(result => result.value);
    for (const rotation of rotations) {
      assert.equal(rotation.binding.launchId, first.binding.launchId);
      assert.equal(rotation.binding.scenarioId, first.binding.scenarioId);
      assert.equal(rotation.binding.generation, 1);
    }
    assert.equal(await repository.resolve({ ...scope, bearer: first.bearer }), null);
    assert.equal(await repository.resolveCapability(first.bearer), null);
    const resolutions = await Promise.all(rotations.map(rotation => repository.resolve({ ...scope, bearer: rotation.bearer })));
    assert.equal(resolutions.filter(Boolean).length, 1);
    active = rotations[resolutions.findIndex(Boolean)];
    assert.equal((await migration.query('SELECT count(*)::int AS n FROM identity.secureshop_launches WHERE platform_session_id=$1', [session.id])).rows[0].n, 1);
    const restarted = createSecureShopLaunchRepository(pool);
    assert.equal((await restarted.resolve({ ...scope, bearer: active.bearer })).launchId, active.binding.launchId);
  });
  await t.test('explicit lost-response recovery is owner-bound and compare-and-swap without extending authority', async () => {
    const before = active;
    const metadata = await repository.readActiveMetadata(scope);
    assert.deepEqual(metadata, before.binding);
    assert.equal(await repository.readActiveMetadata({ ...scope, platformOwnerId: bob.id }), null);
    const args = { ...scope, launchId: metadata.launchId, expectedCredentialVersion: metadata.credentialVersion };
    await assert.rejects(repository.recoverCredential({ ...args, ...bobScope }));
    await assert.rejects(repository.recoverCredential({ ...args, platformOwnerId: bob.id }));
    await assert.rejects(repository.recoverCredential({ ...args, expectedCredentialVersion: 0 }));
    const results = await Promise.allSettled(Array.from({ length: 4 }, () => repository.recoverCredential(args)));
    const winners = results.filter(result => result.status === 'fulfilled');
    assert.equal(winners.length, 1);
    active = winners[0].value;
    assert.equal(active.binding.credentialVersion, metadata.credentialVersion + 1);
    for (const key of ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']) {
      assert.equal(active.binding[key], metadata[key]);
    }
    assert.equal(new Date(active.binding.expiresAt).getTime(), new Date(metadata.expiresAt).getTime());
    assert.equal(await repository.resolve({ ...scope, bearer: before.bearer }), null);
    assert.equal(await repository.resolveCapability(before.bearer), null);
    assert.equal((await repository.resolve({ ...scope, bearer: active.bearer })).launchId, metadata.launchId);
    await assert.rejects(repository.recoverCredential(args));
    await assert.rejects(repository.issueOrRenew({ ...scope, expiresAt: expiry }));
    const stored = (await migration.query('SELECT row_to_json(l) AS row FROM identity.secureshop_launches l WHERE launch_id=$1', [metadata.launchId])).rows[0].row;
    assert.ok(!JSON.stringify(stored).includes(active.bearer));
    assert.ok(!JSON.stringify(await repository.readActiveMetadata(scope)).includes(active.bearer));
    const restarted = createSecureShopLaunchRepository(pool);
    assert.deepEqual(await restarted.readActiveMetadata(scope), active.binding);
    // A second lost response is recovered from fresh metadata, not a replay of
    // the old request. Ordinary renewal competes under the same lock/version.
    const second = await restarted.readActiveMetadata(scope);
    const competing = await Promise.allSettled([
      restarted.recoverCredential({ ...scope, launchId: second.launchId, expectedCredentialVersion: second.credentialVersion }),
      restarted.issueOrRenew({ ...scope, expiresAt: second.expiresAt, expectedBearer: active.bearer }),
    ]);
    assert.equal(competing.filter(result => result.status === 'fulfilled').length, 1);
    active = competing.find(result => result.status === 'fulfilled').value;
  });
  await t.test('reset fences before effects, retries once and cannot cross owners or generations', async () => {
    const args = { ...scope, launchId: active.binding.launchId, expectedGeneration: 1, idempotencyKey: 'reset-owned-1' };
    const attempts = await Promise.all([repository.beginReset(args), repository.beginReset(args)]);
    assert.equal(attempts[0].resetId, attempts[1].resetId);
    assert.equal(attempts[0].toGeneration, 2);
    assert.equal(await repository.resolve({ ...scope, bearer: active.bearer }), null);
    assert.equal(await repository.resolveCapability(active.bearer), null);
    assert.equal(await repository.readActiveMetadata(scope), null);
    await assert.rejects(repository.reserveFilesTarget({ ...scope, launchId: active.binding.launchId, expectedGeneration: 1 }));
    await assert.rejects(repository.recoverCredential({ ...scope, launchId: active.binding.launchId,
      expectedCredentialVersion: active.binding.credentialVersion }));
    await assert.rejects(repository.assertCurrent({ ...scope, ...active.binding }));
    await assert.rejects(repository.issueOrRenew({ ...scope, expiresAt: expiry }));
    await assert.rejects(repository.beginReset({ ...args, idempotencyKey: 'different-reset' }));
    const commit = { ...scope, launchId: active.binding.launchId, resetId: attempts[0].resetId, expectedGeneration: 2 };
    await assert.rejects(repository.commitReset({ ...commit, ...bobScope }));
    await assert.rejects(repository.commitReset({ ...commit, expectedGeneration: 1 }));
    await assert.rejects(repository.commitReset(commit),{code:'CLEANUP_REQUIRED'});
    await reconcileEmptyConversationAndProgress(commit.resetId);
    const done = await repository.commitReset(commit);
    assert.equal(done.generation, 2);
    assert.deepEqual(await repository.commitReset(commit), done);
    active = { ...active, binding: done };
    assert.equal((await repository.resolve({ ...scope, bearer: active.bearer })).generation, 2);
    assert.equal((await repository.resolve({ ...bobScope, bearer: bobLaunch.bearer })).generation, 1);
  });
  await t.test('a later reset generation rejects old idempotency keys and commits', async () => {
    const launchId = active.binding.launchId;
    const prior = await repository.beginReset({ ...scope, launchId, expectedGeneration: 1, idempotencyKey: 'reset-owned-1' });
    const next = await repository.beginReset({ ...scope, launchId, expectedGeneration: 2, idempotencyKey: 'reset-owned-2' });
    await reconcileEmptyConversationAndProgress(next.resetId);
    active = { ...active, binding: await repository.commitReset({ ...scope, launchId, resetId: next.resetId, expectedGeneration: 3 }) };
    await assert.rejects(repository.beginReset({ ...scope, launchId, expectedGeneration: 1, idempotencyKey: 'reset-owned-1' }));
    await assert.rejects(repository.commitReset({ ...scope, launchId, resetId: prior.resetId, expectedGeneration: 2 }));
    assert.equal((await repository.resolve({ ...scope, bearer: active.bearer })).generation, 3);
  });
  await t.test('reserved filesystem reads connect native authority to real isolated bytes and survive adapter recreation', async () => {
    const fs = require('node:fs/promises');
    const os = require('node:os');
    const path = require('node:path');
    const { createSecureShopFiles } = require('../../sidecars/sandbox-runner/secureshopFiles');
    const { createSecureShopReservedFileReader } = require('../../server/services/secureshopReservedFiles');
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-native-reserved-files-'));
    t.after(() => fs.rm(root, { recursive: true, force: true }));
    const reader = createSecureShopReservedFileReader({ launches: repository, files: createSecureShopFiles({ root }) });
    const aliceBinding = { ...scope, launchId: active.binding.launchId, generation: active.binding.generation };
    const bobBinding = { ...bobScope, launchId: bobLaunch.binding.launchId, generation: bobLaunch.binding.generation };
    const a = await reader.readFile(aliceBinding, '../server/config/.env', { base: '/uploads' });
    const b = await reader.readFile(bobBinding, '/server/config/.env');
    assert.match(a.data.toString(), /SECURESHOP_LAB_MARKER=[a-f0-9]{48}/);
    assert.notEqual(a.targetId, b.targetId);
    assert.notDeepEqual(a.data, b.data);
    assert.equal((await pool.query('SELECT launch_id FROM identity.secureshop_target_reservations WHERE target_id=$1', [a.targetId])).rows[0].launch_id, aliceBinding.launchId);
    const recreated = createSecureShopReservedFileReader({ launches: createSecureShopLaunchRepository(pool), files: createSecureShopFiles({ root }) });
    const again = await recreated.readFile(aliceBinding, '/server/config/.env');
    assert.equal(again.targetId, a.targetId);
    assert.deepEqual(again.data, a.data);
    assert.ok(!Object.hasOwn(again, 'capability'));
    await assert.rejects(recreated.readFile({ ...aliceBinding, ...bobScope }, '/server/config/.env'));
  });
  await t.test('target admission is durable, owner-bound, idempotent and cannot bypass cleanup with another login', async () => {
    const args = { ...scope, launchId: active.binding.launchId, expectedGeneration: active.binding.generation };
    await assert.rejects(repository.reserveFilesTarget({ ...args, ...bobScope }));
    await assert.rejects(repository.reserveFilesTarget({ ...args, expectedGeneration: 999 }));
    const reservations = await Promise.all(Array.from({ length: 4 }, () => repository.reserveFilesTarget(args)));
    reservedTarget = reservations[0];
    assert.ok(reservations.every(row => row.targetId === reservedTarget.targetId));
    assert.equal(reservedTarget.scenarioId, active.binding.scenarioId);
    assert.equal(reservedTarget.kind, 'files');
    const restarted = createSecureShopLaunchRepository(pool);
    assert.deepEqual(await restarted.reserveFilesTarget(args), reservedTarget);
    const otherSession = await identity.createSession({ userId: alice.id, token: randomUUID(), expiresAt: expiry, expectedPasswordHash: passwordHash });
    const otherScope = { platformOwnerId: alice.id, platformSessionId: otherSession.id };
    const otherLaunch = await repository.issueOrRenew({ ...otherScope, expiresAt: expiry });
    await assert.rejects(repository.reserveFilesTarget({ ...otherScope, launchId: otherLaunch.binding.launchId, expectedGeneration: 1 }), { code: 'CLEANUP_REQUIRED' });
    const bobTarget = await repository.reserveFilesTarget({ ...bobScope, launchId: bobLaunch.binding.launchId, expectedGeneration: 1 });
    assert.notEqual(bobTarget.targetId, reservedTarget.targetId);
    await assert.rejects(pool.query('UPDATE identity.secureshop_target_reservations SET generation=2 WHERE target_id=$1', [reservedTarget.targetId]), /permission denied/);
    await assert.rejects(pool.query('DELETE FROM identity.secureshop_target_reservations WHERE target_id=$1', [reservedTarget.targetId]), /permission denied/);
    await assert.rejects(pool.query("INSERT INTO identity.secureshop_target_reservations(target_id,launch_id,generation,target_kind,original_platform_owner_id) VALUES($1,$2,1,'files',$3)", [randomUUID(), bobLaunch.binding.launchId, alice.id]), /binding is invalid/);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM identity.secureshop_target_reservations')).rows[0].n, 2);
  });
  await t.test('reset commit racing revocation cannot reactivate the launch; deleting owner retains journal', async () => {
    const user = await identity.createUser({ username: 'launch-race', email: 'race@launch.invalid', passwordHash });
    const login = await identity.createSession({ userId: user.id, token: randomUUID(), expiresAt: expiry, expectedPasswordHash: passwordHash });
    const trusted = { platformSessionId: login.id, platformOwnerId: user.id };
    const issued = await repository.issueOrRenew({ ...trusted, expiresAt: expiry });
    const launchId = issued.binding.launchId;
    const reset = await repository.beginReset({ ...trusted, launchId, expectedGeneration: 1, idempotencyKey: 'racing-reset' });
    const results = await Promise.allSettled([
      repository.commitReset({ ...trusted, launchId, resetId: reset.resetId, expectedGeneration: 2 }),
      repository.revoke({ ...trusted, launchId, reason: 'concurrent_logout' })
    ]);
    assert.equal(results[1].status, 'fulfilled');
    assert.equal(await repository.resolve({ ...trusted, bearer: issued.bearer }), null);
    assert.equal(await repository.resolveCapability(issued.bearer), null);
    await assert.rejects(repository.commitReset({ ...trusted, launchId, resetId: reset.resetId, expectedGeneration: 2 }));
    await migration.query('DELETE FROM identity.users WHERE id=$1', [user.id]);
    const retained = (await migration.query('SELECT l.status,l.platform_session_id,r.reset_id FROM identity.secureshop_launches l JOIN identity.secureshop_launch_resets r USING(launch_id) WHERE l.launch_id=$1', [launchId])).rows[0];
    assert.equal(retained.status, 'revoked');
    assert.equal(retained.platform_session_id, null);
    assert.equal(retained.reset_id, reset.resetId);
  });
  await t.test('account disable and session revocation share a lock order', async () => {
    const user = await identity.createUser({ username: 'launch-lock-order', email: 'lock-order@launch.invalid', passwordHash });
    const login = await identity.createSession({ userId: user.id, token: randomUUID(), expiresAt: expiry, expectedPasswordHash: passwordHash });
    const trusted = { platformSessionId: login.id, platformOwnerId: user.id };
    const issued = await repository.issueOrRenew({ ...trusted, expiresAt: expiry });
    await repository.beginReset({ ...trusted, launchId: issued.binding.launchId, expectedGeneration: 1, idempotencyKey: 'lock-order-reset' });
    const gate = await migration.connect();
    let disable;
    try {
      await gate.query('BEGIN');
      await gate.query("SET LOCAL statement_timeout='5s'");
      await gate.query('SELECT id FROM identity.user_sessions WHERE id=$1 FOR UPDATE', [login.id]);
      await gate.query('SELECT launch_id FROM identity.secureshop_launches WHERE launch_id=$1 FOR UPDATE', [issued.binding.launchId]);
      disable = pool.query('UPDATE identity.users SET is_active=0 WHERE id=$1', [user.id]).then(value => ({ value }), error => ({ error }));
      let waiting = false;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const observed = await pool.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'", [applicationName]);
        if (observed.rows[0].n) { waiting = true; break; }
        await new Promise(resolve => setTimeout(resolve, 20));
      }
      assert.ok(waiting, 'Account disable must be observed waiting on the held lifecycle locks');
      await gate.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1', [login.id]);
      await gate.query('COMMIT');
      const result = await disable;
      assert.equal(result.error, undefined, 'Neither lifecycle update may deadlock');
      assert.equal(await repository.resolve({ ...trusted, bearer: issued.bearer }), null);
    assert.equal(await repository.resolveCapability(issued.bearer), null);
    } finally {
      await gate.query('ROLLBACK'); gate.release();
      if (disable) await disable;
    }
  });
  for (const operationName of ['issuance', 'recovery']) await t.test(`${operationName} rechecks session expiry after waiting for a user lock`, async () => {
    const pendingSession = await identity.createSession({ userId: alice.id, token: randomUUID(), expiresAt: expiry, expectedPasswordHash: passwordHash });
    const pendingScope = { platformSessionId: pendingSession.id, platformOwnerId: alice.id };
    const issued = operationName === 'recovery' ? await repository.issueOrRenew({ ...pendingScope, expiresAt: expiry }) : null;
    const gate = await migration.connect();
    let pending;
    try {
      await gate.query('BEGIN');
      await gate.query('SELECT id FROM identity.users WHERE id=$1 FOR UPDATE', [alice.id]);
      const request = issued
        ? repository.recoverCredential({ ...pendingScope, launchId: issued.binding.launchId, expectedCredentialVersion: issued.binding.credentialVersion })
        : repository.issueOrRenew({ ...pendingScope, expiresAt: expiry });
      pending = request.then(value => ({ value }), error => ({ error }));
      let waiting = false;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const observed = await pool.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'", [applicationName]);
        if (observed.rows[0].n > 0) { waiting = true; break; }
        await new Promise(resolve => setTimeout(resolve, 20));
      }
      assert.ok(waiting, 'Native lock wait must be observed before changing session validity');
      await gate.query("UPDATE identity.user_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", [pendingSession.id]);
      await gate.query('COMMIT');
      assert.ok((await pending).error, 'An expiry checked before the blocking lock is not authoritative');
      assert.equal((await migration.query('SELECT count(*)::int AS n FROM identity.secureshop_launches WHERE platform_session_id=$1', [pendingSession.id])).rows[0].n, issued ? 1 : 0);
      if (issued) {
        assert.equal((await migration.query('SELECT credential_version FROM identity.secureshop_launches WHERE launch_id=$1', [issued.binding.launchId])).rows[0].credential_version, String(issued.binding.credentialVersion));
        assert.equal(await repository.readActiveMetadata(pendingScope), null);
      }
    } finally {
      await gate.query('ROLLBACK');
      gate.release();
      if (pending) await pending;
    }
  });
  await t.test('account and session revocation remain authoritative after issuance', async () => {
    await migration.query('UPDATE identity.users SET is_active=0 WHERE id=$1', [alice.id]);
    assert.equal(await repository.resolve({ ...scope, bearer: active.bearer }), null);
    assert.equal(await repository.resolveCapability(active.bearer), null);
    await assert.rejects(repository.assertCurrent({ ...scope, ...active.binding }));
    await migration.query("UPDATE identity.users SET is_active=1,account_locked_until=clock_timestamp()+interval '1 hour' WHERE id=$1", [alice.id]);
    assert.equal(await repository.resolve({ ...scope, bearer: active.bearer }), null);
    assert.equal(await repository.resolveCapability(active.bearer), null);
    await assert.rejects(repository.issueOrRenew({ ...scope, expiresAt: expiry }));
    await migration.query('UPDATE identity.users SET account_locked_until=NULL WHERE id=$1', [alice.id]);
    await identity.revokeAllUserSessions(alice.id);
    assert.equal(await repository.resolve({ ...scope, bearer: active.bearer }), null);
    assert.equal(await repository.resolveCapability(active.bearer), null);
    await assert.rejects(repository.issueOrRenew({ ...scope, expiresAt: expiry }));
    assert.ok(await repository.resolve({ ...bobScope, bearer: bobLaunch.bearer }));
  });
  await t.test('expired launch cannot be revived with its previously valid handle', async () => {
    const user = await identity.createUser({ username: 'launch-expiry', email: 'expiry@launch.invalid', passwordHash });
    const login = await identity.createSession({ userId: user.id, token: randomUUID(), expiresAt: expiry, expectedPasswordHash: passwordHash });
    const trusted = { platformSessionId: login.id, platformOwnerId: user.id };
    const issued = await repository.issueOrRenew({ ...trusted, expiresAt: expiry });
    await migration.query("UPDATE identity.secureshop_launches SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE launch_id=$1", [issued.binding.launchId]);
    assert.equal(await repository.resolve({ ...trusted, bearer: issued.bearer }), null);
    assert.equal(await repository.resolveCapability(issued.bearer), null);
    await assert.rejects(repository.issueOrRenew({ ...trusted, expiresAt: expiry, expectedBearer: issued.bearer }),
      { code: 'LAUNCH_SESSION_TERMINAL' });
    assert.equal(await repository.readActiveMetadata(trusted), null);
    await assert.rejects(repository.recoverCredential({ ...trusted, launchId: issued.binding.launchId,
      expectedCredentialVersion: issued.binding.credentialVersion }));
  });
  await t.test('cleanup references are immutable and reset authority status never proves target cleanup', async () => {
    await assert.rejects(pool.query('UPDATE identity.secureshop_launches SET original_platform_owner_id=$2 WHERE launch_id=$1', [active.binding.launchId, bob.id]), /immutable/);
    await assert.rejects(pool.query('UPDATE identity.secureshop_launches SET scenario_id=$2 WHERE launch_id=$1', [active.binding.launchId, randomUUID()]), /immutable/);
    await assert.rejects(pool.query('UPDATE identity.secureshop_launches SET platform_session_id=$2 WHERE launch_id=$1', [active.binding.launchId, bobSession.id]), /immutable/);
    await assert.rejects(pool.query('UPDATE identity.secureshop_launches SET launch_id=$2 WHERE launch_id=$1', [active.binding.launchId, randomUUID()]), /immutable/);
    const rows = (await migration.query('SELECT status,reconciliation_required FROM identity.secureshop_launch_resets')).rows;
    assert.ok(rows.some(row => row.status === 'committed'));
    assert.ok(rows.some(row => row.status === 'aborted'));
    assert.ok(rows.every(row => row.reconciliation_required === true));
  });
  await t.test('explicit launch revocation is terminal and repeatable', async () => {
    const args = { ...bobScope, launchId: bobLaunch.binding.launchId, reason: 'test_logout' };
    await repository.revoke(args);
    assert.equal(await repository.resolve({ ...bobScope, bearer: bobLaunch.bearer }), null);
    assert.equal(await repository.resolveCapability(bobLaunch.bearer), null);
    await repository.revoke(args);
    await assert.rejects(repository.issueOrRenew({ ...bobScope, expiresAt: expiry }),
      { code: 'LAUNCH_SESSION_TERMINAL' });
    assert.equal(await repository.readActiveMetadata(bobScope), null);
    await assert.rejects(repository.recoverCredential({ ...bobScope, launchId: bobLaunch.binding.launchId,
      expectedCredentialVersion: bobLaunch.binding.credentialVersion }));
  });
  await t.test('platform session deletion retains scenario cleanup identity while invalidating authority', async () => {
    await migration.query('DELETE FROM identity.user_sessions WHERE id=$1', [session.id]);
    assert.equal(await repository.resolve({ ...scope, bearer: active.bearer }), null);
    assert.equal(await repository.resolveCapability(active.bearer), null);
    const row = (await migration.query('SELECT scenario_id,platform_session_id,original_platform_session_id,original_platform_owner_id FROM identity.secureshop_launches WHERE launch_id=$1', [active.binding.launchId])).rows[0];
    assert.ok(row, 'Deleting a login must not erase the only durable scenario cleanup identity');
    assert.equal(row.scenario_id, active.binding.scenarioId);
    const target = (await pool.query('SELECT * FROM identity.secureshop_target_reservations WHERE target_id=$1', [reservedTarget.targetId])).rows[0];
    assert.equal(target.launch_id, active.binding.launchId);
    assert.equal(target.original_platform_owner_id, alice.id);
    assert.equal(row.platform_session_id, null);
    assert.equal(row.original_platform_session_id, session.id);
    assert.equal(row.original_platform_owner_id, alice.id);
  });
});
