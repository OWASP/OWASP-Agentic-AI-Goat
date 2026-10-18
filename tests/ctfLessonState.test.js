'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { LESSON_STATE_KEYS, createCtfLessonReceipt } = require('../server/agent-runtime/ctfLessonState');

const binding = { ownerId: 71, participantId: 17, stageId: 8, stageNumber: 8 };
const expected = { ownerId: 71, participantId: 17, stageId: 8, attemptNumber: 3 };

test('lesson receipt projects only the exact five booleans after exact owner/stage/attempt binding', () => {
  const receipt = createCtfLessonReceipt(binding);
  receipt.bindAttempt(3);
  receipt.observeReviewer();
  receipt.observeCategoryConsumed();
  const value = receipt.project(expected);
  assert.deepEqual(Object.keys(value), LESSON_STATE_KEYS);
  assert.deepEqual(value, {
    input_guard_observed: false,
    reviewer_observed: true,
    category_consumed: true,
    category_reuse_blocked: false,
    shared_similarity_blocked: false,
  });
  assert.equal(Object.isFrozen(value), true);
});

test('lesson receipt rejects owner, participant, stage and attempt substitution', () => {
  for (const changed of [
    { ownerId: 72 }, { participantId: 18 }, { stageId: 9 }, { attemptNumber: 4 },
  ]) {
    const receipt = createCtfLessonReceipt(binding); receipt.bindAttempt(3);
    assert.throws(() => receipt.project({ ...expected, ...changed }), /binding mismatch/);
  }
  const receipt = createCtfLessonReceipt(binding); receipt.bindAttempt(3);
  assert.throws(() => receipt.bindAttempt(4), /attempt binding mismatch/);
});

test('fresh participant/reset receipts cannot inherit another owner lesson state', () => {
  const prior = createCtfLessonReceipt(binding); prior.bindAttempt(3); prior.observeCategoryConsumed();
  assert.equal(prior.project(expected).category_consumed, true);
  const reset = createCtfLessonReceipt(binding); reset.bindAttempt(1);
  assert.deepEqual(reset.project({ ...expected, attemptNumber: 1 }),
    Object.fromEntries(LESSON_STATE_KEYS.map(key => [key, false])));
  const sibling = createCtfLessonReceipt({ ...binding, ownerId: 72, participantId: 18 }); sibling.bindAttempt(1);
  assert.deepEqual(sibling.project({ ownerId: 72, participantId: 18, stageId: 8, attemptNumber: 1 }),
    Object.fromEntries(LESSON_STATE_KEYS.map(key => [key, false])));
});

test('stages outside 6 through 10 do not project lesson state', () => {
  const receipt = createCtfLessonReceipt({ ...binding, stageNumber: 5 }); receipt.bindAttempt(1);
  receipt.observeInputGuard();
  assert.equal(receipt.project({ ...expected, attemptNumber: 1 }), undefined);
});
