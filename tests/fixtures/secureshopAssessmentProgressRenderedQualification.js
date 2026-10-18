'use strict';

const assert = require('node:assert/strict');

const PROGRESS_RENDERED_SCOPE = 'secureshop-assessment-progress-rendered-controlled-v1';
const PROGRESS_RENDERED_FLAGS = Object.freeze([
  'isolatedStores', 'controlledContributionLabeled', 'physicalLearnerSelf',
  'physicalAdminList', 'physicalAdminDetail', 'resetRetiresOwnerOnly',
  'siblingPreserved', 'foreignDenied', 'staleSessionDenied', 'noModelOrJudge',
  'browserClosed', 'profileRemoved', 'cleanupComplete',
]);

function assertProgressRenderedReceipt(value) {
  assert.ok(value && Object.getPrototypeOf(value) === Object.prototype);
  assert.deepEqual(Object.keys(value).sort(),
    ['scope', 'actorCalls', 'judgeCalls', 'errors', ...PROGRESS_RENDERED_FLAGS].sort());
  assert.equal(value.scope, PROGRESS_RENDERED_SCOPE);
  for (const key of PROGRESS_RENDERED_FLAGS) assert.equal(value[key], true, key);
  assert.equal(value.actorCalls, 0, 'controlled progress rows are not a model run');
  assert.equal(value.judgeCalls, 0, 'controlled progress rows are not a Judge run');
  assert.deepEqual(value.errors, []);
  return value;
}

function assertProgressProjection(value, { principalId, objectiveId, completed }) {
  assert.deepEqual(Object.keys(value).sort(), [
    'principalId', 'shopUserId', 'username', 'role', 'generation', 'objectives',
    'totalObjectives', 'completedObjectives',
  ].sort());
  assert.equal(value.principalId, principalId);
  assert.ok(Number.isSafeInteger(value.generation) && value.generation >= 0);
  assert.equal(value.totalObjectives, value.objectives.length);
  assert.equal(value.completedObjectives, value.objectives.filter(row => row.completed).length);
  const row = value.objectives.find(item => item.objectiveId === objectiveId);
  assert.ok(row, 'current enabled objective must be projected');
  assert.deepEqual(Object.keys(row).sort(), ['completed', 'label', 'objectiveId']);
  assert.equal(row.completed, completed);
  assert.ok(!JSON.stringify(value).includes('evidence_digest'));
  assert.ok(!JSON.stringify(value).includes('packet'));
  assert.ok(!JSON.stringify(value).includes('canRetry'));
  return value;
}

module.exports = { PROGRESS_RENDERED_SCOPE, PROGRESS_RENDERED_FLAGS,
  assertProgressRenderedReceipt, assertProgressProjection };
