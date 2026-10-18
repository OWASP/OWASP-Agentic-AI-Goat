'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { PROGRESS_RENDERED_SCOPE, PROGRESS_RENDERED_FLAGS,
  assertProgressRenderedReceipt, assertProgressProjection } =
  require('./fixtures/secureshopAssessmentProgressRenderedQualification');

const receipt = () => ({ ...Object.fromEntries(PROGRESS_RENDERED_FLAGS.map(key => [key, true])),
  scope: PROGRESS_RENDERED_SCOPE, actorCalls: 0, judgeCalls: 0, errors: [] });
const projection = () => ({ principalId: '11111111-1111-4111-8111-111111111111',
  shopUserId: 7, username: 'progress_learner', role: 'customer', generation: 3,
  objectives: [{ objectiveId: 'ss_loop_observation', label: 'Observe a model tool loop', completed: true }],
  totalObjectives: 1, completedObjectives: 1 });

test('controlled rendered receipt cannot be mistaken for an actual model or Judge run', () => {
  assert.deepEqual(assertProgressRenderedReceipt(receipt()), receipt());
  for (const change of [{ physicalLearnerSelf: false }, { physicalAdminDetail: false },
    { staleSessionDenied: false }, { cleanupComplete: false }, { actorCalls: 1 },
    { judgeCalls: 1 }, { errors: ['incomplete'] }, { extra: true }]) {
    assert.throws(() => assertProgressRenderedReceipt({ ...receipt(), ...change }));
  }
});

test('closed projection asserts the exact current objective and rejects evidence fields', () => {
  assert.deepEqual(assertProgressProjection(projection(), {
    principalId: projection().principalId, objectiveId: 'ss_loop_observation', completed: true }),
  projection());
  for (const change of [{ completedObjectives: 0 }, { objectives: [] },
    { objectives: [{ ...projection().objectives[0], completed: false }] },
    { packet: 'leaked' }, { canRetry: true }]) {
    assert.throws(() => assertProgressProjection({ ...projection(), ...change }, {
      principalId: projection().principalId, objectiveId: 'ss_loop_observation', completed: true }));
  }
});

test('native rendered caller uses four owned stores and physical standalone progress controls', () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopAssessmentProgressRendered.integration.test.js'), 'utf8');
  assert.ok(source.includes("const PREFIX = 'PG_SECURESHOP_ASSESSMENT_PROGRESS_RENDERED_';"));
  assert.ok(source.includes('SECURESHOP_ASSESSMENT_PROGRESS_RENDERED_NATIVE'));
  assert.ok(source.includes('dvaia_test_agent_host_'));
  assert.ok(source.includes("physicalButton(customerPage, 'Shop settings')"));
  assert.ok(source.includes("physicalButton(adminPage, 'Shop settings')"));
  assert.ok(source.includes("'/api/secureshop/auth/progress'"));
  assert.ok(source.includes("'/api/secureshop/auth/admin/progress/learners'"));
  assert.ok(source.includes("physicalButton(customerPage, 'Refresh progress')"));
  assert.ok(source.includes('controlled-rendered-progress-fixture'));
  assert.ok(!source.includes('LIVE_OLLAMA_TEST'));
});
