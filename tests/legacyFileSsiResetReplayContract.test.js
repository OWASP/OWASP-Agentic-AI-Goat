'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createLegacyFileSsiReset } = require('../server/services/legacyFileSsiReset');

function fixture({ loseFirstReceipt = false } = {}) {
  const operations = new Map();
  let applyCount = 0;
  let receiptReads = 0;
  let completionCount = 0;
  const scopes = [];
  const journal = {
    async begin({ ownerId, operationId }) {
      let op = operations.get(operationId);
      if (!op) {
        op = { operationId, ownerId, fromGeneration: 0, toGeneration: 1, status: 'pending', ownerActive: true, step: 'pending' };
        operations.set(operationId, op);
      }
      return { ...op };
    },
    async read(operationId) {
      const op = operations.get(operationId);
      if (!op) throw Object.assign(new Error('missing'), { code: 'LEGACY_FILE_SSI_RESET_UNAVAILABLE' });
      return { ...op };
    },
    async claim(operationId) {
      const op = operations.get(operationId);
      if (!op || op.status === 'completed' || op.status === 'leased') return null;
      op.status = 'leased';
      return { ...op };
    },
    async nextStep(lease) {
      const op = operations.get(lease.operationId);
      return op?.step === 'pending' || op?.step === 'failed' ? 'legacy_cleanup' : null;
    },
    async acknowledge({ operationId }) {
      const op = operations.get(operationId);
      op.step = 'done';
      op.status = 'leased';
    },
    async fail({ operationId }) {
      const op = operations.get(operationId);
      op.step = 'failed';
      op.status = 'failed';
    },
    async complete({ operationId }) {
      const op = operations.get(operationId);
      op.step = 'done';
      op.status = 'completed';
      return { ...op };
    },
    async listRecoverable() { return []; },
  };
  const cleanup = {
    async apply(scope) { applyCount += 1; completionCount = 0; scopes.push({ ...scope }); return scope; },
    async readReceipt(scope) {
      receiptReads += 1;
      if (loseFirstReceipt && receiptReads === 1) throw new Error('lost cleanup response');
      return { ...scope };
    },
  };
  const reset = createLegacyFileSsiReset({
    legacyRuns: { reset: async (_ownerId, work) => work() },
    cleanup,
    journal,
  });
  return { reset, journal, operations, scopes, counts: () => ({ applyCount, receiptReads, completionCount }), markNewerCompletion: () => { completionCount = 1; } };
}

test('reset replay preserves newer completion without a second cleanup', async () => {
  const f = fixture();
  const operationId = randomUUID();
  await f.reset.reset(7, { operationId });
  // A newer completion may be written after the reset operation has completed.
  f.markNewerCompletion();
  const replay = await f.reset.reset(7, { operationId });
  assert.equal(replay.status, 'completed');
  assert.equal(f.counts().completionCount, 1, 'completed-operation replay must preserve newer completion');
  assert.equal(f.counts().applyCount, 1);
});

test('lost-response retry reuses the exact operation scope', async () => {
  const f = fixture({ loseFirstReceipt: true });
  const operationId = randomUUID();
  await assert.rejects(f.reset.reset(7, { operationId }), /lost cleanup response/);
  await f.reset.reset(7, { operationId });
  assert.equal(f.counts().applyCount, 2);
  assert.equal(f.scopes.length, 2);
  assert.deepEqual(f.scopes[0], f.scopes[1]);
  assert.deepEqual(f.scopes[0], { operationId, stepKey: 'legacy_cleanup', ownerId: 7, fromGeneration: 0, toGeneration: 1 });
});

test('reset recovery rejects a reset whose owner was deleted', async () => {
  const f = fixture();
  const operationId = randomUUID();
  await f.journal.begin({ ownerId: 7, operationId });
  f.operations.get(operationId).ownerActive = false;
  await assert.rejects(f.reset.recover(operationId), { code: 'LEGACY_FILE_SSI_OWNER_UNAVAILABLE' });
  assert.equal(f.counts().applyCount, 0);
});
