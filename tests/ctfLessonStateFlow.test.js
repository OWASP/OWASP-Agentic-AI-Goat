'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCtfLessonReceipt } = require('../server/agent-runtime/ctfLessonState');
const { runCtfAdmissionGraph } = require('../server/agent-runtime/ctfAdmissionGraph');
const { runCtfResultGraph } = require('../server/agent-runtime/ctfResultGraph');

const participant = Object.freeze({ id: 17, user_id: 71 });
const exactFalse = Object.freeze({
  input_guard_observed: false,
  reviewer_observed: false,
  category_consumed: false,
  category_reuse_blocked: false,
  shared_similarity_blocked: false,
});

async function admission({ stageNumber, adaptiveMode = 'none', techniqueBlocked = false,
  similarityBlocked = false, inputBlocked = false, ownerId = 71, participantId = 17 }) {
  const stageId = stageNumber;
  const currentParticipant = { id: participantId, user_id: ownerId };
  const receipt = createCtfLessonReceipt({ ownerId, participantId, stageId, stageNumber });
  let attempts = 0;
  const result = await runCtfAdmissionGraph({ payload: 'PRIVATE_LEARNER_PAYLOAD', stage: {
    stage_number: stageNumber, adaptive_mode: adaptiveMode, feedback_mode: 'reason',
  }, participant: currentParticipant, stageId, sessionToken: 'PRIVATE_SESSION', ownerId, lessonReceipt: receipt }, {
    classifyTechnique: () => ({ tag: 'role_play', confidence: 0.9 }),
    hashPayload: () => ({ hash: 'f'.repeat(64), normalized: 'PRIVATE_NORMALIZED_PAYLOAD' }),
    isNearDuplicate: () => ({ blocked: similarityBlocked, matchedHash: 'e'.repeat(64) }),
    TECHNIQUE_TAGS: { OTHER: 'other' },
    CTFHelpers: {
      getConfig: async () => 'true',
      istechniqueBlocked: async (owner, stage, tag) => {
        assert.deepEqual([owner, stage, tag], [participantId, stageId, 'role_play']); return techniqueBlocked;
      },
      getPayloadBlocklist: async stage => { assert.equal(stage, stageId); return [{ payload_hash: 'PRIVATE_HASH' }]; },
      incrementPayloadHitCount: async () => {}, logAttempt: async () => {},
    },
    atomicIncrementAttempts: async () => ++attempts,
    runDefenseLayers: async () => inputBlocked ? { blocked: true, reason: 'categorical block' } : { blocked: false },
  });
  return { result, receipt };
}

test('stage 6 and 7 input defenses project only input guard evidence before any reviewer', async () => {
  for (const stageNumber of [6, 7]) {
    const { result } = await admission({ stageNumber, inputBlocked: true });
    assert.deepEqual(result.blockedResponse.lessonState, {
      ...exactFalse, input_guard_observed: true,
    });
    assert.equal(result.blockedResponse.lessonState.reviewer_observed, false);
  }
});

test('stage 8 category reuse and stage 9 shared similarity blocks remain distinct', async () => {
  const reused = await admission({ stageNumber: 8, adaptiveMode: 'technique', techniqueBlocked: true });
  assert.deepEqual(reused.result.blockedResponse.lessonState, {
    ...exactFalse, category_reuse_blocked: true,
  });
  const shared = await admission({ stageNumber: 9, adaptiveMode: 'payload', similarityBlocked: true,
    ownerId: 72, participantId: 18 });
  assert.deepEqual(shared.result.blockedResponse.lessonState, {
    ...exactFalse, shared_similarity_blocked: true,
  });
});

test('stage 10 reports the exact fence that stopped each attempt and never claims a downstream reviewer', async () => {
  const category = await admission({ stageNumber: 10, adaptiveMode: 'hybrid', techniqueBlocked: true,
    similarityBlocked: true });
  assert.equal(category.result.blockedResponse.lessonState.category_reuse_blocked, true);
  assert.equal(category.result.blockedResponse.lessonState.shared_similarity_blocked, false);
  assert.equal(category.result.blockedResponse.lessonState.reviewer_observed, false);

  const similarity = await admission({ stageNumber: 10, adaptiveMode: 'hybrid', similarityBlocked: true });
  assert.equal(similarity.result.blockedResponse.lessonState.category_reuse_blocked, false);
  assert.equal(similarity.result.blockedResponse.lessonState.shared_similarity_blocked, true);
  assert.equal(similarity.result.blockedResponse.lessonState.reviewer_observed, false);
});

test('post-commit recognized category and validated reviewer are projected from the current participant/stage receipt', async () => {
  const receipt = createCtfLessonReceipt({ ownerId: 71, participantId: 17, stageId: 8, stageNumber: 8 });
  receipt.bindAttempt(2); receipt.observeReviewer();
  const output = await runCtfResultGraph({ wasSuccessful: false, progress: {}, participant, stageId: 8,
    payload: 'PRIVATE_PAYLOAD', techniqueTag: 'role_play', adaptiveMode: 'technique',
    payloadHash: 'PRIVATE_HASH', normalizedSnippet: 'PRIVATE_SNIPPET', stage: { stage_name: 'Stage 8', level_score: 800 },
    attemptNumber: 2, studentResponse: 'PRIVATE_MODEL_RESPONSE', responseTime: 4,
    sessionToken: 'PRIVATE_SESSION', techniqueConfidence: 0.9, showFeedback: false,
    ownerId: 71, lessonReceipt: receipt }, {
    CTFHelpers: {
      getConfig: async () => '3', getProgress: async () => ({ hint_penalty_total: 0, hints_used: 0 }),
      getUserTechniques: async () => { throw new Error('hidden technique list should not be projected'); },
    },
    TECHNIQUE_TAGS: { OTHER: 'other' }, commit: async () => ({ accepted: false, stale: false,
      categoryConsumed: true }),
    judgment: { verdict: 'fail' },
  });
  assert.deepEqual(output.lessonState, {
    ...exactFalse, reviewer_observed: true, category_consumed: true,
  });
  assert.doesNotMatch(JSON.stringify(output.lessonState), /PRIVATE|payload|response|session|hash|provider|model/i);
});
