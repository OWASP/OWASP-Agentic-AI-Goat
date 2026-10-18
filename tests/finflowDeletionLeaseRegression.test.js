'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createFinflowOwnerResourceDeletion } = require('../server/services/finflowOwnerResourceDeletion');
const { createStudentDeletionAdapters } = require('../server/services/studentDeletionAdapters');
const { issueFinflowOwnerDeletionReceipt } = require('../server/services/finflowOwnerDeletionReceipt');
const jobId = '11111111-1111-4111-8111-111111111111';
const leaseToken = '22222222-2222-4222-8222-222222222222';

test('lease loss after owner reservation prevents physical removal and database completion', async () => {
  const events = [], lost = Object.assign(new Error('lease lost'), { name: 'AbortError' });
  let reserved = false;
  const cleanup = createFinflowOwnerResourceDeletion({
    repository: {
      async beginOwnerDeletion(scope) { events.push('reserve'); reserved = true;
        return { ownerId: scope.ownerId, jobId: scope.jobId, status: 'pending', fileTokens: [], artifactCount: 0, datasetCount: 0 }; },
      async completeOwnerDeletion() { events.push('complete'); throw Error('Must not complete'); }
    },
    files: { async remove() { events.push('remove'); }, async absent() { events.push('absent'); return true; } }
  });
  await assert.rejects(cleanup({ subjectId: 44, jobId, leaseToken,
    async check() { if (reserved) throw lost; } }), error => error === lost);
  assert.deepEqual(events, ['reserve']);
});

function adapter(retire, events) {
  return createStudentDeletionAdapters(name => {
    assert.equal(name, '../routes/sensitiveInfoWorkshop');
    return { async resetOwner(owner, work) { assert.equal(owner, '44'); return work(); } };
  }, {
    cleanupFinflowBackups: async scope => {
      events.push('backups');
      return issueFinflowOwnerDeletionReceipt({ completed: true, ownerId: scope.subjectId, jobId: scope.jobId, artifactCount: 0 });
    },
    retireFinflowTraversalOwner: async owner => { assert.equal(owner, '44'); events.push('retire'); return retire(); },
    storeCleanup: { finflow: async () => { events.push('store'); return { completed: true }; } }
  }).finflow;
}

test('lease loss after successful traversal retirement prevents store destruction', async () => {
  const events = [], lost = Object.assign(new Error('lease lost'), { name: 'AbortError' });
  let retired = false;
  const run = adapter(() => { retired = true; return true; }, events);
  await assert.rejects(run({ subjectId: 44, jobId, leaseToken,
    async check() { if (retired) throw lost; } }), error => error === lost);
  assert.deepEqual(events, ['backups', 'retire']);
});

test('undefined and object retirement acknowledgements cannot authorize store destruction', async () => {
  // The existing adapter suite already covers false; retain these distinct historical cases.
  for (const acknowledgement of [undefined, { completed: true }]) {
    const events = [];
    await assert.rejects(adapter(() => acknowledgement, events)({ subjectId: 44, jobId, leaseToken, check: async () => {} }),
      /Invalid FinFlow traversal deletion receipt/);
    assert.deepEqual(events, ['backups', 'retire']);
  }
});
