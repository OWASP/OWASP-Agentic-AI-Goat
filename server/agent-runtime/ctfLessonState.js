'use strict';

const LESSON_STATE_KEYS = Object.freeze([
  'input_guard_observed',
  'reviewer_observed',
  'category_consumed',
  'category_reuse_blocked',
  'shared_similarity_blocked',
]);

function positiveInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new TypeError(`${label} must be a positive integer`);
  return number;
}

function createCtfLessonReceipt({ ownerId, participantId, stageId, stageNumber, stageDigest = null, reviewerProfile = null }) {
  const binding = Object.freeze({
    ownerId: positiveInteger(ownerId, 'CTF lesson owner'),
    participantId: positiveInteger(participantId, 'CTF lesson participant'),
    stageId: positiveInteger(stageId, 'CTF lesson stage'),
    stageNumber: positiveInteger(stageNumber, 'CTF lesson stage number'),
  });
  if (reviewerProfile !== null && (binding.stageNumber !== 6
      || typeof stageDigest !== 'string' || !/^[a-f0-9]{64}$/.test(stageDigest)
      || !reviewerProfile || typeof reviewerProfile !== 'object' || Array.isArray(reviewerProfile)
      || Object.keys(reviewerProfile).sort().join(',') !== 'id,policyDigest,version'
      || typeof reviewerProfile.id !== 'string' || !reviewerProfile.id
      || typeof reviewerProfile.version !== 'string' || !reviewerProfile.version
      || typeof reviewerProfile.policyDigest !== 'string' || !/^[a-f0-9]{64}$/.test(reviewerProfile.policyDigest))) {
    throw new TypeError('Invalid CTF reviewer profile receipt');
  }
  const profileEvidence = reviewerProfile === null ? null : Object.freeze({
    stageDigest,
    reviewerProfile: Object.freeze({...reviewerProfile}),
  });
  let attemptNumber = null;
  const state = Object.fromEntries(LESSON_STATE_KEYS.map(key => [key, false]));

  function bindAttempt(value) {
    const number = positiveInteger(value, 'CTF lesson attempt');
    if (attemptNumber !== null && attemptNumber !== number) throw new Error('CTF lesson attempt binding mismatch');
    attemptNumber = number;
  }
  function observe(key) {
    if (!LESSON_STATE_KEYS.includes(key)) throw new TypeError('Unknown CTF lesson observation');
    state[key] = true;
  }
  function project(expected) {
    if (binding.stageNumber < 6 || binding.stageNumber > 10) return undefined;
    if (!expected || positiveInteger(expected.ownerId, 'CTF lesson owner') !== binding.ownerId
        || positiveInteger(expected.participantId, 'CTF lesson participant') !== binding.participantId
        || positiveInteger(expected.stageId, 'CTF lesson stage') !== binding.stageId
        || positiveInteger(expected.attemptNumber, 'CTF lesson attempt') !== attemptNumber) {
      throw new Error('CTF lesson receipt binding mismatch');
    }
    return Object.freeze(Object.fromEntries(LESSON_STATE_KEYS.map(key => [key, state[key] === true])));
  }

  return Object.freeze({
    bindAttempt,
    observeInputGuard: () => observe('input_guard_observed'),
    observeReviewer: () => observe('reviewer_observed'),
    observeCategoryConsumed: () => observe('category_consumed'),
    observeCategoryReuseBlock: () => observe('category_reuse_blocked'),
    observeSharedSimilarityBlock: () => observe('shared_similarity_blocked'),
    profileEvidence: () => profileEvidence,
    project,
  });
}

module.exports = { LESSON_STATE_KEYS, createCtfLessonReceipt };
