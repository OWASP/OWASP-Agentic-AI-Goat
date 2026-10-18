'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const path = require('node:path');
const { createXssBoundedMigrationView } = require('../helpers/xssBoundedMigrationView');
const { createPool } = require('../../server/database/postgres');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { createXssProfileResetJournalRepository } = require(
  '../../server/database/postgres/xssProfileResetJournalRepository');

const RUNTIME = 'PG_XSS_PROFILE_JOURNAL_RUNTIME_URL';
const MIGRATION = 'PG_XSS_PROFILE_JOURNAL_MIGRATION_URL';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env[RUNTIME]) && Boolean(process.env[MIGRATION]);
const password = '$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA';

function assertOwnedUrl(value, role) {
  const url = new URL(value);
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, '/dvaia_test_xss_profile_reset_journal');
  assert.equal(decodeURIComponent(url.username), role);
}
async function user(pool, suffix) {
  return (await pool.query(`INSERT INTO identity.users(username,email,password)
    VALUES($1,$2,$3) RETURNING id`,
  [`xss-profile-reset-${suffix}`, `xss-profile-reset-${suffix}@fixture.invalid`, password])).rows[0];
}
async function authority(pool, ownerId, graphGeneration = 4, workshopGeneration = 2,
  storedUser = 6, storedLlm = 8) {
  const ownerKey = JSON.stringify(['XSS', String(ownerId)]);
  await pool.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,$2)',
    [ownerKey, graphGeneration]);
  await pool.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation)
    VALUES($1,'xss_workshop',$2)`, [ownerId, workshopGeneration]);
  await pool.query(`INSERT INTO identity.xss_scope_state(owner_id,owner_key,scope_key,child_generation)
    VALUES($1,$2,'stored_user',0),($1,$2,'stored_llm',0)`, [ownerId, ownerKey]);
  await pool.query(`UPDATE identity.xss_scope_state SET child_generation=CASE scope_key
    WHEN 'stored_user' THEN $3::bigint WHEN 'stored_llm' THEN $4::bigint END,
    updated_at=clock_timestamp() WHERE owner_id=$1 AND owner_key=$2
      AND scope_key IN ('stored_user','stored_llm')`, [ownerId, ownerKey, storedUser, storedLlm]);
  return ownerKey;
}
function receipt(operation, replayed = false) {
  return { operationId:operation.operationId, ownerId:operation.ownerId,
    graphParentGeneration:operation.graphParentGeneration,
    workshopGeneration:operation.workshopGeneration, children:operation.children,
    profileRevisions:{ name:'11', bio:'12', website:'13' }, originsRemoved:2,
    appliedAt:'2026-09-19T12:00:00.000Z', replayed };
}

test('native 0072 journals one recoverable profile reset without deleting achievements or time',
  { skip:!enabled }, async () => {
    assertOwnedUrl(process.env[RUNTIME], 'dvaia_identity_runtime');
    assertOwnedUrl(process.env[MIGRATION], 'dvaia_identity_migration');
    const runtime = createPool(process.env, RUNTIME);
    const migration = createPool(process.env, MIGRATION);
    // Historical 0071→0076 qualification, not current full-tail readiness.
    const view = createXssBoundedMigrationView({ identity:71 });
    const { migrate, initializeIdentityRepository } = view;
    try {
      assert.equal((await migrate(migration, view.directories.identity)).at(-1), '0071_xss_scope_bind_conflict_fix.sql');
      await seedWorkshopPlatform(migration);
      const [owner, deletionOwner, parentOwner, sibling] = await Promise.all([
        user(migration, 'owner'), user(migration, 'deletion'),
        user(migration, 'parent'), user(migration, 'sibling'),
      ]);
      const ownerKey = await authority(migration, owner.id);
      await authority(migration, deletionOwner.id);
      await authority(migration, parentOwner.id);
      await authority(migration, sibling.id, 3, 1, 2, 4);
      const beforeTail = (await migration.query(`SELECT owner_id,owner_key,scope_key,
        child_generation::text child_generation,state FROM identity.xss_scope_state ORDER BY owner_id,scope_key`)).rows;
      view.setCeiling('identity', 76);
      assert.deepEqual(await initializeIdentityRepository(runtime, migration), [
        '0072_xss_profile_reset_journal.sql',
        '0073_xss_judgment_child_binding.sql',
        '0074_xss_profile_reset_parent_supersession.sql',
        '0075_xss_profile_reset_constraint_repair.sql',
        '0076_xss_profile_reset_owner_lookup.sql',
      ]);
      assert.deepEqual((await migration.query(`SELECT owner_id,owner_key,scope_key,
        child_generation::text child_generation,state FROM identity.xss_scope_state ORDER BY owner_id,scope_key`)).rows,
      beforeTail, '0072 preserves populated scope authority');
      assert.deepEqual(await initializeIdentityRepository(runtime, migration), [], 'bounded tail replays as a no-op');
      // Preserve the historical transition above before qualifying today's
      // repository, whose deletion-redaction readiness requires 0079.
      const ledger0076 = (await migration.query(
        'SELECT name,checksum,applied_at FROM dvaia_migrations.ledger ORDER BY name')).rows;
      view.setCeiling('identity', 79);
      const repositoryTail = [
        '0077_xss_parent_reset_journal.sql',
        '0078_xss_parent_reset_admission_fence.sql',
        '0079_xss_deletion_redaction_recovery_filter.sql',
      ];
      assert.deepEqual(await initializeIdentityRepository(runtime, migration), repositoryTail);
      const ledger0079 = (await migration.query(
        'SELECT name,checksum,applied_at FROM dvaia_migrations.ledger ORDER BY name')).rows;
      assert.deepEqual(ledger0079.slice(0, ledger0076.length), ledger0076);
      assert.deepEqual(ledger0079.slice(ledger0076.length).map(row => row.name), repositoryTail);
      assert.deepEqual((await migration.query(`SELECT owner_id,owner_key,scope_key,
        child_generation::text child_generation,state FROM identity.xss_scope_state ORDER BY owner_id,scope_key`)).rows,
      beforeTail, 'repository prerequisite tail preserves populated child authority');
      assert.deepEqual(await initializeIdentityRepository(runtime, migration), []);
      assert.deepEqual((await migration.query(
        'SELECT name,checksum,applied_at FROM dvaia_migrations.ledger ORDER BY name')).rows, ledger0079);

      await migration.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
        VALUES($1,'xss_workshop','xss_s1'),($1,'xss_workshop','xss_g1')`, [owner.id]);
      await migration.query(`INSERT INTO workshop_platform.activity_counters
        (user_id,workshop_key,activity_key,activity_count)
        VALUES($1,'xss_workshop','xss_s1',3)`, [owner.id]);
      await migration.query(`INSERT INTO workshop_platform.time_tracking
        (user_id,workshop_key,session_start,last_heartbeat,duration_seconds)
        VALUES($1,'xss_workshop',clock_timestamp(),clock_timestamp(),90)`, [owner.id]);
      const preserved = (await migration.query(`SELECT
        (SELECT count(*)::int FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='xss_workshop') completions,
        (SELECT count(*)::int FROM workshop_platform.activity_counters WHERE user_id=$1 AND workshop_key='xss_workshop') activity,
        (SELECT sum(duration_seconds)::int FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key='xss_workshop') seconds`,
      [owner.id])).rows[0];

      const journal = createXssProfileResetJournalRepository(runtime);
      assert.equal(await journal.assertReady(), true);
      // Real session locks serialize independent ledger instances without a
      // parent bump. Observe a native unsuccessful try-lock before releasing.
      const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
      let unlockHolder, enteredHolder, sawContention;
      const held = new Promise(resolve => { enteredHolder = resolve; });
      const releaseGate = new Promise(resolve => { unlockHolder = resolve; });
      const contended = new Promise(resolve => { sawContention = resolve; });
      const firstLedger = createPostgresRunLedger(runtime);
      const secondLedger = createPostgresRunLedger(runtime, {leasePool:{connect:async () => {
        const client = await runtime.connect();
        const query = client.query.bind(client);
        client.query = async (sql, values) => {
          const result = await query(sql, values);
          if (sql.includes('pg_try_advisory_lock') && result.rows[0]?.acquired === false) sawContention();
          return result;
        };
        const release = client.release.bind(client);
        client.release = (...args) => {client.query = query; return release(...args);};
        return client;
      }}});
      let secondEntered = false;
      const first = firstLedger.withOwnerLease({ownerKey}, async lease => {
        assert.equal(lease.durableGeneration, '4'); enteredHolder(); await releaseGate;
      });
      await held;
      const second = secondLedger.withOwnerLease({ownerKey, signal:AbortSignal.timeout(5000)}, async lease => {
        secondEntered = true; await lease.check();
      });
      try {
        await contended;
        assert.equal(secondEntered, false);
      } finally { unlockHolder(); }
      await Promise.all([first, second]);
      assert.equal(secondEntered, true);
      assert.equal(String((await migration.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',
        [ownerKey])).rows[0].generation), '4');

      // Terminate only this fixture's checked-out runtime-role connection.
      let leasePid;
      const lostLedger = createPostgresRunLedger(runtime, {leasePool:{connect:async () => {
        const client = await runtime.connect(); leasePid = client.processID; return client;
      }}});
      let afterLoss = false;
      await assert.rejects(lostLedger.withOwnerLease({ownerKey}, async lease => {
        assert.equal((await runtime.query('SELECT pg_terminate_backend($1) AS terminated',
          [leasePid])).rows[0].terminated, true);
        await lease.check();
        afterLoss = true;
      }));
      assert.equal(afterLoss, false);
      await firstLedger.withOwnerLease({ownerKey}, async lease => { await lease.check(); });

      const operationId = randomUUID();
      const begun = await journal.begin({ operationId, ownerId:owner.id,
        graphParentGeneration:'4', workshopGeneration:'2' });
      assert.deepEqual(begun.children, {
        stored_user:{ from:'6', to:'7' }, stored_llm:{ from:'8', to:'9' },
      });
      assert.equal(begun.status, 'pending');
      assert.equal((await journal.readNonterminalForOwner(owner.id)).operationId, operationId,
        'owner lookup returns the unique pending operation');
      assert.equal(await journal.readNonterminalForOwner(sibling.id), null,
        'owner lookup never crosses to a sibling');
      assert.deepEqual((await journal.begin({ operationId, ownerId:owner.id,
        graphParentGeneration:'4', workshopGeneration:'2' })).children, begun.children,
      'same-operation replay never advances a child twice');
      await assert.rejects(journal.begin({ operationId:randomUUID(), ownerId:owner.id,
        graphParentGeneration:'4', workshopGeneration:'2' }), { code:'XSS_PROFILE_RESET_UNAVAILABLE' });
      assert.deepEqual((await migration.query(`SELECT scope_key,child_generation::text generation,state
        FROM identity.xss_scope_state WHERE owner_id=$1 ORDER BY scope_key`, [owner.id])).rows, [
        { scope_key:'stored_llm', generation:'9', state:'resetting' },
        { scope_key:'stored_user', generation:'7', state:'resetting' },
      ]);
      const claim = await journal.claim(operationId, { leaseMs:60000 });
      assert.equal(claim.status, 'running');
      assert.ok(claim.leaseToken);
      assert.equal((await journal.assertCurrent({ operationId, leaseToken:claim.leaseToken })).operationId,
        operationId);
      const ack = await journal.acknowledgeStore({ operationId, leaseToken:claim.leaseToken,
        receipt:receipt(claim) });
      assert.match(ack.receiptSha256, /^[0-9a-f]{64}$/);
      assert.equal(ack.replayed, false);
      const replay = await journal.acknowledgeStore({ operationId, leaseToken:claim.leaseToken,
        receipt:receipt(claim, true) });
      assert.deepEqual(replay, { receiptSha256:ack.receiptSha256, replayed:true },
        'store replay metadata is excluded from the immutable receipt digest');
      await assert.rejects(journal.acknowledgeStore({ operationId, leaseToken:claim.leaseToken,
        receipt:{ ...receipt(claim), ownerId:sibling.id } }), { code:'XSS_PROFILE_RESET_CONFLICT' });
      const completed = await journal.complete({ operationId, leaseToken:claim.leaseToken });
      assert.equal(completed.status, 'completed');
      assert.equal(await journal.readNonterminalForOwner(owner.id), null,
        'terminal operations are excluded from parent-reset lookup');
      assert.deepEqual((await migration.query(`SELECT scope_key,child_generation::text generation,state
        FROM identity.xss_scope_state WHERE owner_id=$1 ORDER BY scope_key`, [owner.id])).rows, [
        { scope_key:'stored_llm', generation:'9', state:'active' },
        { scope_key:'stored_user', generation:'7', state:'active' },
      ]);
      assert.deepEqual((await migration.query(`SELECT
        (SELECT count(*)::int FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='xss_workshop') completions,
        (SELECT count(*)::int FROM workshop_platform.activity_counters WHERE user_id=$1 AND workshop_key='xss_workshop') activity,
        (SELECT sum(duration_seconds)::int FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key='xss_workshop') seconds`,
      [owner.id])).rows[0], preserved, 'profile reset journal never removes achievements, activity or time');
      assert.equal((await migration.query(`SELECT owner_key FROM graph_runtime.owners WHERE owner_key=$1`,
        [ownerKey])).rows[0].owner_key, ownerKey);

      const recoveryId = randomUUID();
      const recovery = await journal.begin({ operationId:recoveryId, ownerId:sibling.id,
        graphParentGeneration:'3', workshopGeneration:'1' });
      const firstLease = await journal.claim(recoveryId, { leaseMs:60000 });
      await migration.query(`UPDATE identity.xss_profile_reset_operations
        SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE operation_id=$1`, [recoveryId]);
      assert.ok((await journal.listRecoverable()).includes(recoveryId));
      const secondLease = await journal.claim(recoveryId, { leaseMs:60000 });
      assert.notEqual(firstLease.leaseToken, secondLease.leaseToken);
      await assert.rejects(journal.assertCurrent({ operationId:recoveryId,
        leaseToken:firstLease.leaseToken }), { code:'XSS_PROFILE_RESET_STALE' });
      assert.deepEqual((await journal.fail({ operationId:recoveryId,
        leaseToken:secondLease.leaseToken, code:'FIXTURE_FAILURE' })), { status:'failed' });
      const resumed = await journal.claim(recoveryId, { leaseMs:60000 });
      assert.deepEqual(resumed.children, recovery.children);

      const deletionJob = randomUUID();
      await migration.query(`INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by)
        VALUES($1,$2,$3)`, [deletionJob, deletionOwner.id, sibling.id]);
      await assert.rejects(journal.begin({ operationId:randomUUID(), ownerId:deletionOwner.id,
        graphParentGeneration:'4', workshopGeneration:'2' }), { code:'XSS_PROFILE_RESET_UNAVAILABLE' });
      await assert.rejects(journal.readNonterminalForOwner(deletionOwner.id),
        { code:'XSS_PROFILE_RESET_UNAVAILABLE' }, 'admitted deletion denies owner lookup');

      const parentId = randomUUID();
      const parent = await journal.begin({ operationId:parentId, ownerId:parentOwner.id,
        graphParentGeneration:'4', workshopGeneration:'2' });
      const parentLease = await journal.claim(parentId, { leaseMs:60000 });
      await journal.acknowledgeStore({ operationId:parentId, leaseToken:parentLease.leaseToken,
        receipt:receipt(parentLease) });
      await migration.query('UPDATE graph_runtime.owners SET generation=generation+1 WHERE owner_key=$1',
        [parent.ownerKey]);
      await assert.rejects(journal.assertCurrent({ operationId:parentId,
        leaseToken:parentLease.leaseToken }), { code:'XSS_PROFILE_RESET_STALE' });
      await assert.rejects(journal.complete({ operationId:parentId,
        leaseToken:parentLease.leaseToken }), { code:'XSS_PROFILE_RESET_STALE' });
      assert.equal((await journal.readNonterminalForOwner(parentOwner.id)).operationId, parentId,
        'stale parent operations remain discoverable for bounded reconciliation');

      for (const sql of [
        'SELECT * FROM identity.xss_profile_reset_operations',
        'SELECT * FROM identity.xss_profile_reset_steps',
        `UPDATE identity.xss_profile_reset_operations SET status='completed' WHERE operation_id='${recoveryId}'`,
      ]) await assert.rejects(runtime.query(sql), { code:'42501' });
      await assert.rejects(migration.query(`UPDATE identity.xss_profile_reset_operations
        SET owner_id=$2 WHERE operation_id=$1`, [operationId, sibling.id]), { code:'55000' });
    } finally {
      const closed = await Promise.allSettled([runtime.end(), migration.end()]);
      const failures = closed.filter(result => result.status === 'rejected').map(result => result.reason);
      if (failures.length) throw new AggregateError(failures, 'XSS profile reset journal cleanup failed');
    }
  });
