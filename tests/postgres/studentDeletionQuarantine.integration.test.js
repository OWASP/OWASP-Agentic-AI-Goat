'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');

test('native deletion quarantine preserves progress and requires an exact privileged resume', {
  skip: process.env.PG_TEST_DISPOSABLE !== 'yes' || !process.env.PG_DELETION_RUNTIME_URL,
}, async () => {
  for (const key of ['PG_DELETION_RUNTIME_URL', 'PG_DELETION_MIGRATION_URL']) {
    assert.match(new URL(process.env[key]).pathname, /^\/dvaia_test_/);
  }

  const { createPool } = require('../../server/database/postgres');
  const runtime = createPool(process.env, 'PG_DELETION_RUNTIME_URL');
  const migration = createPool(process.env, 'PG_DELETION_MIGRATION_URL');
  try {
    const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
    await initializeIdentityRepository(runtime, migration);
    await migration.query(await fs.readFile(path.resolve(__dirname, '../../docs/modernization/drafts/student-deletion-journal.sql'), 'utf8'));

    const users = createIdentityRepository(runtime);
    const passwordHash = await require('bcryptjs').hash('owned quarantine fixture', 4);
    let sequence = 0;
    const create = async prefix => {
      sequence += 1;
      const name = `${prefix}_${sequence}`;
      return users.createUser({ username: name, email: `${name}@fixture.test`, passwordHash });
    };
    const promote = async (user, { level = 2, active = 1 } = {}) => {
      await migration.query("UPDATE identity.users SET role='admin',admin_level=$2,is_active=$3 WHERE id=$1", [user.id, level, active]);
    };

    const admin = await create('quarantine_admin');
    const levelOne = await create('quarantine_level_one');
    const inactiveAdmin = await create('quarantine_inactive');
    const ordinaryStudent = await create('quarantine_student_requester');
    await promote(admin);
    await promote(levelOne, { level: 1 });
    await promote(inactiveAdmin, { active: 0 });

    const { createStudentDeletionRepository } = require('../../server/database/postgres/studentDeletionRepository');
    const { createStudentDeletionWorker } = require('../../server/services/studentDeletionWorker');
    const restoredManifest = ['revoke_runs', 'excessive_agency', 'identity'];
    const changedManifest = ['revoke_runs', 'mcp', 'identity'];
    const restored = createStudentDeletionRepository(runtime, { steps: restoredManifest });
    const changed = createStudentDeletionRepository(runtime, { steps: changedManifest });

    const subject = await create('quarantine_subject');
    const admitted = await restored.admit({ requesterId: admin.id, subjectId: subject.id });
    const originalLease = await restored.claim(admitted.jobId);
    await restored.acknowledge({ jobId: admitted.jobId, leaseToken: originalLease.leaseToken, stepKey: 'revoke_runs' });
    await migration.query("UPDATE identity.student_deletion_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE job_id=$1", [admitted.jobId]);

    let adapterCalls = 0;
    const mismatchWorker = createStudentDeletionWorker({
      repository: changed,
      adapters: {
        revoke_runs: async () => { adapterCalls += 1; return { completed: true }; },
        mcp: async () => { adapterCalls += 1; return { completed: true }; },
        identity: async () => { adapterCalls += 1; return { completed: true }; },
      },
    });
    assert.deepEqual(await mismatchWorker.run(admitted.jobId), {
      state: 'quarantined',
      code: 'DELETION_MANIFEST_MISMATCH',
    });
    assert.equal(adapterCalls, 0, 'A changed manifest is quarantined before adapter dispatch');

    const quarantined = (await runtime.query(
      'SELECT state,failure_code,lease_token,lease_expires_at FROM identity.student_deletion_jobs WHERE job_id=$1',
      [admitted.jobId],
    )).rows[0];
    assert.deepEqual(quarantined, {
      state: 'quarantined',
      failure_code: 'DELETION_MANIFEST_MISMATCH',
      lease_token: null,
      lease_expires_at: null,
    });
    assert.deepEqual(await restored.listRecoverable({ retryAfterMs: 1000 }), []);
    await migration.query("UPDATE identity.student_deletion_jobs SET updated_at=clock_timestamp()-interval '1 year' WHERE job_id=$1", [admitted.jobId]);
    assert.deepEqual(await restored.listRecoverable({ retryAfterMs: 1000 }), [], 'Quarantine never ages into automatic recovery');
    assert.equal(await restored.claim(admitted.jobId), null, 'A quarantined job cannot be claimed automatically');

    assert.deepEqual((await runtime.query(
      'SELECT step_key,state,attempts FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal',
      [admitted.jobId],
    )).rows, [
      { step_key: 'revoke_runs', state: 'completed', attempts: 1 },
      { step_key: 'excessive_agency', state: 'pending', attempts: 0 },
      { step_key: 'identity', state: 'pending', attempts: 0 },
    ]);
    const retainedBlocks = (await runtime.query(
      'SELECT count(*)::int AS n FROM identity.student_deletion_run_blocks WHERE job_id=$1',
      [admitted.jobId],
    )).rows[0].n;
    assert.equal(retainedBlocks, require('../../server/database/postgres/agentRunReadRepository').RUN_FAMILIES.length);
    assert.equal((await runtime.query('SELECT is_active FROM identity.users WHERE id=$1', [subject.id])).rows[0].is_active, 0);

    await assert.rejects(changed.resumeQuarantined({ requesterId: admin.id, jobId: admitted.jobId }), { code: 'DELETION_MANIFEST_MISMATCH' });
    await assert.rejects(restored.resumeQuarantined({ requesterId: ordinaryStudent.id, jobId: admitted.jobId }), { code: 'ADMIN_REQUIRED' });
    await assert.rejects(restored.resumeQuarantined({ requesterId: levelOne.id, jobId: admitted.jobId }), { code: 'ADMIN_REQUIRED' });
    await assert.rejects(restored.resumeQuarantined({ requesterId: inactiveAdmin.id, jobId: admitted.jobId }), { code: 'ADMIN_REQUIRED' });

    const resumes = await Promise.allSettled([
      restored.resumeQuarantined({ requesterId: admin.id, jobId: admitted.jobId }),
      restored.resumeQuarantined({ requesterId: admin.id, jobId: admitted.jobId }),
    ]);
    assert.equal(resumes.filter(result => result.status === 'fulfilled').length, 1);
    assert.equal(resumes.filter(result => result.status === 'rejected' && result.reason?.code === 'DELETION_NOT_QUARANTINED').length, 1);
    const resumed = (await runtime.query(
      'SELECT state,failure_code,lease_token,lease_expires_at FROM identity.student_deletion_jobs WHERE job_id=$1',
      [admitted.jobId],
    )).rows[0];
    assert.deepEqual(resumed, { state: 'pending', failure_code: null, lease_token: null, lease_expires_at: null });
    assert.equal((await runtime.query(
      'SELECT count(*)::int AS n FROM identity.student_deletion_run_blocks WHERE job_id=$1',
      [admitted.jobId],
    )).rows[0].n, retainedBlocks);
    const resumedLease = await restored.claim(admitted.jobId);
    assert.deepEqual(await restored.nextStep({ jobId: admitted.jobId, leaseToken: resumedLease.leaseToken }), {
      subjectId: subject.id,
      stepKey: 'excessive_agency',
    });

    const matchingSubject = await create('matching_subject');
    const matchingJob = await restored.admit({ requesterId: admin.id, subjectId: matchingSubject.id });
    const matchingLease = await restored.claim(matchingJob.jobId);
    await assert.rejects(restored.quarantine({ jobId: matchingJob.jobId, leaseToken: matchingLease.leaseToken }), { code: 'DELETION_MANIFEST_MATCHES' });
    assert.equal((await runtime.query('SELECT state FROM identity.student_deletion_jobs WHERE job_id=$1', [matchingJob.jobId])).rows[0].state, 'running');

    const staleSubject = await create('stale_subject');
    const staleJob = await restored.admit({ requesterId: admin.id, subjectId: staleSubject.id });
    const staleLease = await restored.claim(staleJob.jobId, 1000);
    await migration.query("UPDATE identity.student_deletion_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE job_id=$1", [staleJob.jobId]);
    await assert.rejects(changed.quarantine({ jobId: staleJob.jobId, leaseToken: staleLease.leaseToken }), { code: 'STALE_DELETION_LEASE' });
    assert.equal((await runtime.query('SELECT state FROM identity.student_deletion_jobs WHERE job_id=$1', [staleJob.jobId])).rows[0].state, 'running');
  } finally {
    await Promise.all([runtime.end(), migration.end()]);
  }
});
