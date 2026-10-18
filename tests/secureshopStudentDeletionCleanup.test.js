'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopStudentDeletionCleanup } = require('../server/services/secureshopStudentDeletionCleanup');

const JOB = '11111111-1111-4111-8111-111111111111';
const LEASE = '22222222-2222-4222-8222-222222222222';
const RESET_A = '33333333-3333-4333-8333-333333333333';
const RESET_B = '44444444-4444-4444-8444-444444444444';

test('SecureShop deletion recovers the immutable reset set without activating launches', async () => {
  const calls = [];
  const mapped = [RESET_A, RESET_B];
  const cleanup = createSecureShopStudentDeletionCleanup({
    repository: { async listSecureShopResetIds(scope) {
      calls.push(['list', scope]);
      return [...mapped];
    } },
    launchResetCoordinator: { async recover(resetId, { signal }) {
      assert.equal(signal.aborted, false);
      calls.push(['recover', resetId]);
      return { resetId, status: 'aborted', resolved: true, activated: false };
    } },
  });
  let checks = 0;
  const result = await cleanup({ subjectId: 17, jobId: JOB, leaseToken: LEASE,
    signal: new AbortController().signal, check: async () => { checks += 1; } });
  assert.deepEqual(result, { completed: true, resetCount: 2 });
  assert.equal(checks, 6);
  assert.deepEqual(calls.filter(([kind]) => kind === 'list'), [
    ['list', { jobId: JOB, subjectId: 17, leaseToken: LEASE }],
    ['list', { jobId: JOB, subjectId: 17, leaseToken: LEASE }],
  ]);
  assert.deepEqual(calls.filter(([kind]) => kind === 'recover'), [
    ['recover', RESET_A], ['recover', RESET_B],
  ]);
});

test('SecureShop deletion preserves cleanup debt for incomplete, activated, or changed recovery', async () => {
  for (const recovered of [null,
    { resetId: RESET_A, status: 'aborted', resolved: false, activated: false },
    { resetId: RESET_A, status: 'committed', resolved: true, activated: true },
    { resetId: RESET_A, status: 'fenced', resolved: true, activated: false }]) {
    const cleanup = createSecureShopStudentDeletionCleanup({
      repository: { async listSecureShopResetIds() { return [RESET_A]; } },
      launchResetCoordinator: { async recover() { return recovered; } },
    });
    await assert.rejects(cleanup({ subjectId: 17, jobId: JOB, leaseToken: LEASE,
      check: async () => {} }), /incomplete/);
  }
  let reads = 0;
  const cleanup = createSecureShopStudentDeletionCleanup({
    repository: { async listSecureShopResetIds() { return ++reads === 1 ? [RESET_A] : [RESET_B]; } },
    launchResetCoordinator: { async recover(resetId) {
      return { resetId, status: 'aborted', resolved: true, activated: false };
    } },
  });
  await assert.rejects(cleanup({ subjectId: 17, jobId: JOB, leaseToken: LEASE,
    check: async () => {} }), /mapping changed/);
});

test('SecureShop deletion cannot acknowledge an active launch persona', async () => {
  let reads = 0;
  const cleanup = createSecureShopStudentDeletionCleanup({
    repository: { async listSecureShopResetIds() { reads += 1; return [RESET_A]; } },
    launchResetCoordinator: { async recover() {
      throw Object.assign(new Error('Active persona remains'), { code: 'RETIREMENT_INCOMPLETE' });
    } },
  });
  await assert.rejects(cleanup({ subjectId: 17, jobId: JOB, leaseToken: LEASE,
    check: async () => {} }), { code: 'RETIREMENT_INCOMPLETE' });
  assert.equal(reads, 1, 'failed persona retirement cannot reach immutable mapping acknowledgement');
});

test('SecureShop deletion rejects invalid scope and cancellation before recovery', async () => {
  const cleanup = createSecureShopStudentDeletionCleanup({
    repository: { async listSecureShopResetIds() { throw new Error('must not read'); } },
    launchResetCoordinator: { async recover() { throw new Error('must not recover'); } },
  });
  await assert.rejects(cleanup({ subjectId: 17, jobId: JOB, check: async () => {} }), TypeError);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(cleanup({ subjectId: 17, jobId: JOB, leaseToken: LEASE,
    signal: controller.signal, check: async () => {} }), { name: 'AbortError' });
});

test('SecureShop deletion runs optional bound audit cleanup only after immutable reset replay', async () => {
  const calls = [];
  const cleanup = createSecureShopStudentDeletionCleanup({
    repository: { async listSecureShopResetIds() { calls.push('list'); return [RESET_A]; } },
    launchResetCoordinator: { async recover(resetId) {
      calls.push('recover');
      return { resetId, status: 'committed', resolved: true, activated: false };
    } },
    auditCleanup: async scope => {
      calls.push('audit');
      assert.equal(scope.subjectId, 17);
      assert.equal(scope.jobId, JOB);
      assert.equal(scope.leaseToken, LEASE);
      assert.equal(typeof scope.check, 'function');
      assert.equal(scope.signal.aborted, false);
      return { completed: true };
    },
  });
  let checks = 0;
  const signal = new AbortController().signal;
  assert.deepEqual(await cleanup({ subjectId: 17, jobId: JOB, leaseToken: LEASE, signal,
    check: async () => { checks += 1; } }), { completed: true, resetCount: 1 });
  assert.deepEqual(calls, ['list', 'recover', 'list', 'audit']);
  assert.equal(checks, 5);

  const failed = createSecureShopStudentDeletionCleanup({
    repository: { async listSecureShopResetIds() { return []; } },
    launchResetCoordinator: { async recover() { throw new Error('unused'); } },
    auditCleanup: async () => { throw new Error('audit cleanup debt'); },
  });
  await assert.rejects(failed({ subjectId: 17, jobId: JOB, leaseToken: LEASE,
    check: async () => {} }), /audit cleanup debt/);
});

test('SecureShop deletion does not run optional audit cleanup when reset mapping changes', async () => {
  let reads = 0; let auditCalls = 0;
  const cleanup = createSecureShopStudentDeletionCleanup({
    repository: { async listSecureShopResetIds() { return ++reads === 1 ? [RESET_A] : []; } },
    launchResetCoordinator: { async recover(resetId) {
      return { resetId, status: 'aborted', resolved: true, activated: false };
    } },
    auditCleanup: async () => { auditCalls += 1; return { completed: true }; },
  });
  await assert.rejects(cleanup({ subjectId: 17, jobId: JOB, leaseToken: LEASE,
    check: async () => {} }), /mapping changed/);
  assert.equal(auditCalls, 0);
});
