'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopResetCleanupAuthorityRepository } = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const { createStudentDeletionRepository } = require('../../server/database/postgres/studentDeletionRepository');
const { createSecureShopStudentDeletionCleanup } = require('../../server/services/secureshopStudentDeletionCleanup');

const PREFIX = 'PG_STUDENT_DELETION_SECURESHOP_TEST';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env[`${PREFIX}_MIGRATION_URL`] && process.env[`${PREFIX}_RUNTIME_URL`];

test('native account deletion fences every owned SecureShop launch and recovers its immutable reset set', {
  skip: !enabled, timeout: 30000,
}, async () => {
  const migrationUrl = new URL(process.env[`${PREFIX}_MIGRATION_URL`]);
  const runtimeUrl = new URL(process.env[`${PREFIX}_RUNTIME_URL`]);
  for (const url of [migrationUrl, runtimeUrl]) {
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
    assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  }
  assert.equal(migrationUrl.pathname, runtimeUrl.pathname);
  assert.notEqual(migrationUrl.username, runtimeUrl.username);
  const migration = new Pool({ connectionString: migrationUrl.href, max: 2 });
  const runtime = new Pool({ connectionString: runtimeUrl.href, max: 6 });
  try {
    await initializeIdentityRepository(runtime, migration);
    await migration.query(await fs.readFile(path.resolve(__dirname,
      '../../docs/modernization/drafts/student-deletion-journal.sql'), 'utf8'));
    const identities = createIdentityRepository(runtime);
    const launches = createSecureShopLaunchRepository(runtime);
    const passwordHash = await bcrypt.hash('owned deletion fixture', 4);
    async function owner(label, role = 'student') {
      const user = await identities.createUser({ username: `${label}-${randomUUID().slice(0, 8)}`,
        email: `${randomUUID()}@deletion.invalid`, passwordHash });
      if (role === 'admin') await migration.query(
        "UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1", [user.id]);
      const session = await identities.createSession({ userId: user.id, token: randomUUID(),
        expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
      const launch = await launches.issueOrRenew({ platformOwnerId: user.id,
        platformSessionId: session.id, expiresAt: new Date(Date.now() + 3600000) });
      return { user, session, launch };
    }
    const admin = await owner('admin', 'admin');
    const subject = await owner('subject');
    const sibling = await owner('sibling');
    const secondSession = await identities.createSession({ userId: subject.user.id, token: randomUUID(),
      expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
    const secondLaunch = await launches.issueOrRenew({ platformOwnerId: subject.user.id,
      platformSessionId: secondSession.id, expiresAt: new Date(Date.now() + 3600000) });
    const racingSession = await identities.createSession({ userId: subject.user.id, token: randomUUID(),
      expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
    const revokedSession = await identities.createSession({ userId: subject.user.id, token: randomUUID(),
      expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
    const revokedLaunch = await launches.issueOrRenew({ platformOwnerId: subject.user.id,
      platformSessionId: revokedSession.id, expiresAt: new Date(Date.now() + 3600000) });
    await migration.query(`UPDATE identity.user_sessions SET is_active=0,
      revoked_at=clock_timestamp(),revoke_reason='ordinary_logout' WHERE id=$1`, [revokedSession.id]);
    assert.equal((await runtime.query(`SELECT status FROM identity.secureshop_launches
      WHERE launch_id=$1`, [revokedLaunch.binding.launchId])).rows[0].status, 'revoked');
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.secureshop_launch_resets
      WHERE launch_id=$1`, [revokedLaunch.binding.launchId])).rows[0].n, 0);
    const existing = await launches.beginReset({ launchId: secondLaunch.binding.launchId,
      platformSessionId: secondSession.id, platformOwnerId: subject.user.id,
      expectedGeneration: 1, idempotencyKey: 'preexisting-reset' });

    const repository = createStudentDeletionRepository(runtime,
      { steps: ['revoke_runs', 'secureshop', 'identity'] });
    // Hold admission after it has locked both identity rows but before it can
    // fence launches. A concurrent issue then queues on the owner row and must
    // fail after admission revokes the session; it cannot escape the reset set.
    const blocker = await migration.connect();
    const gate = 771923;
    await blocker.query('SELECT pg_advisory_lock($1)', [gate]);
    await migration.query(`CREATE FUNCTION identity.hold_deletion_admission() RETURNS trigger
      LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(${gate}); RETURN NEW; END $$;
      CREATE TRIGGER hold_deletion_admission BEFORE INSERT ON identity.student_deletion_steps
      FOR EACH ROW EXECUTE FUNCTION identity.hold_deletion_admission()`);
    let admitted;
    try {
      const admissionPromise = repository.admit({ requesterId: admin.user.id, subjectId: subject.user.id });
      let admissionWaiting = false;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        admissionWaiting = (await migration.query(`SELECT EXISTS(SELECT 1 FROM pg_locks
          WHERE locktype='advisory' AND granted=false) AS waiting`)).rows[0].waiting;
        if (admissionWaiting) break;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      assert.equal(admissionWaiting, true, 'deletion admission reached the controlled lock boundary');
      const lateIssue = launches.issueOrRenew({ platformOwnerId: subject.user.id,
        platformSessionId: racingSession.id, expiresAt: new Date(Date.now() + 3600000) })
        .then(value => ({ value }), error => ({ error }));
      await new Promise(resolve => setTimeout(resolve, 30));
      await blocker.query('SELECT pg_advisory_unlock($1)', [gate]);
      admitted = await admissionPromise;
      assert.equal((await lateIssue).error?.code, 'SESSION_UNAVAILABLE');
    } finally {
      await blocker.query('SELECT pg_advisory_unlock($1)', [gate]).catch(() => {});
      blocker.release();
    }
    await migration.query(`DROP TRIGGER hold_deletion_admission ON identity.student_deletion_steps;
      DROP FUNCTION identity.hold_deletion_admission()`);
    const rows = (await runtime.query(`SELECT m.reset_id,m.launch_id,r.status,r.from_generation,
        r.to_generation,l.status AS launch_status,l.original_platform_owner_id
      FROM identity.student_deletion_secureshop_resets m
      JOIN identity.secureshop_launch_resets r USING(reset_id)
      JOIN identity.secureshop_launches l ON l.launch_id=m.launch_id
      WHERE m.job_id=$1 ORDER BY m.launch_id`, [admitted.jobId])).rows;
    assert.equal(rows.length, 3);
    assert.ok(rows.some(row => row.reset_id === existing.resetId),
      'admission associates the compatible reset instead of competing for a generation');
    assert.ok(rows.every(row => row.status === 'aborted' && row.launch_status === 'revoked'
      && Number(row.original_platform_owner_id) === subject.user.id));
    assert.deepEqual(rows.find(row => row.launch_id === revokedLaunch.binding.launchId),
      { reset_id: rows.find(row => row.launch_id === revokedLaunch.binding.launchId).reset_id,
        launch_id: revokedLaunch.binding.launchId, status: 'aborted', from_generation: '1',
        to_generation: '2', launch_status: 'revoked', original_platform_owner_id: subject.user.id });
    assert.deepEqual((await runtime.query(`SELECT status,generation FROM identity.secureshop_launches
      WHERE launch_id=$1`, [sibling.launch.binding.launchId])).rows[0],
    { status: 'active', generation: '1' });
    await assert.rejects(launches.issueOrRenew({ platformOwnerId: subject.user.id,
      platformSessionId: subject.session.id, expiresAt: new Date(Date.now() + 3600000),
      expectedBearer: subject.launch.bearer }), { code: 'SESSION_UNAVAILABLE' });

    const lease = await repository.claim(admitted.jobId);
    assert.ok(lease);
    await assert.rejects(repository.listSecureShopResetIds({ jobId: admitted.jobId,
      subjectId: subject.user.id, leaseToken: randomUUID() }), { code: 'DELETION_JOB_UNAVAILABLE' });
    const authority = createSecureShopResetCleanupAuthorityRepository(runtime);
    const recoveries = [];
    let failOnce = true;
    const coordinator = { async recover(resetId) {
      const operation = await authority.getOperation(resetId);
      recoveries.push(resetId);
      if (failOnce && recoveries.length === 2) { failOnce = false; throw new Error('fixture interruption'); }
      return { resetId, status: operation.status, resolved: true, activated: false };
    } };
    const cleanup = createSecureShopStudentDeletionCleanup({ repository,
      launchResetCoordinator: coordinator });
    const scope = { subjectId: subject.user.id, jobId: admitted.jobId,
      leaseToken: lease.leaseToken, check: async () => repository.renew({ jobId: admitted.jobId,
        leaseToken: lease.leaseToken }), signal: new AbortController().signal };
    await assert.rejects(cleanup(scope), /fixture interruption/);
    assert.equal((await runtime.query(`SELECT state FROM identity.student_deletion_steps
      WHERE job_id=$1 AND step_key='secureshop'`, [admitted.jobId])).rows[0].state, 'pending');
    const completed = await cleanup(scope);
    assert.deepEqual(completed, { completed: true, resetCount: 3 });
    assert.equal(recoveries.length, 5, 'retry revalidates and idempotently recovers the exact reset set');
    assert.ok(rows.every(row => row.launch_status === 'revoked'));
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n
      FROM identity.student_deletion_secureshop_resets WHERE job_id=$1`, [admitted.jobId])).rows[0].n, 3);
  } finally {
    await Promise.allSettled([runtime.end(), migration.end()]);
  }
});
