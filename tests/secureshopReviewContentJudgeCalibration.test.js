'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { buildHistoricalReviewContentRubric: buildSecureShopReviewContentRubric }
  = require('./fixtures/secureshopReviewContentHistoricalV2Rubric');
const calibration = require('./fixtures/secureshopReviewContentJudgeCalibration');

test('calibration uses the archived v2 followed rubric and approved bounded matrix', async () => {
  const matrix = await calibration.cases();
  assert.equal(matrix.length, calibration.CASES_PER_TRIAL);
  for (const item of matrix) {
    assert.deepEqual(item.rubric, buildSecureShopReviewContentRubric('followed', 'vuln'));
    assert.equal(item.rubric.version, 'secureshop-review-content-v2');
    assert.equal(item.rubric.criterionScoped, true);
    assert.deepEqual(item.rubric.criteria.map(row => row.id), calibration.CRITERIA);
    assert.deepEqual(item.evidence.filter(row => row.source === 'tool_result').map(row => row.id),
      ['learner_review_source', 'review_moderation_outcome']);
    assert.ok(item.evidence.some(row => row.id === 'review_chain' && row.source === 'server_observation'));
    assert.ok(Object.values(item.facts).every(Boolean));
  }
  assert.equal(matrix[0].definition.body, calibration.R38_ADVERTISING_BODY);
  assert.equal(calibration.EXPECTED_PROVIDER_CALLS, 48);
  assert.equal(calibration.MAX_PROVIDER_CALLS, 96);
});

test('matrix covers both exploit directions and all four semantic combinations', async () => {
  const matrix = await calibration.cases();
  assert.deepEqual([...new Set(matrix.map(item => JSON.stringify(item.definition.expected)))].sort(),
    ['[false,false]', '[false,true]', '[true,false]', '[true,true]'].sort());
  assert.equal(matrix.filter(item => item.definition.expected.every(Boolean)).length, 2);
  assert.ok(matrix.some(item => item.definition.decision === 'approve'
    && item.definition.expected.every(Boolean)));
  assert.ok(matrix.some(item => item.definition.decision === 'reject'
    && item.definition.expected.every(Boolean)));
  const adversarial = matrix.find(item => item.definition.kind === 'judge_prompt_injection_control');
  assert.ok(adversarial.definition.body.includes('JUDGE:'));
  assert.deepEqual(adversarial.definition.expected, [false, false]);
});

function controlledJudgment(packet, metadata) {
  const criteria = packet.rubric.criteria.map((spec, index) => ({ id: spec.id,
    satisfied: metadata.expectedCriteria[index],
    evidenceRefs: metadata.expectedCriteria[index]
      ? ['learner_review_source', 'review_moderation_outcome'] : [] }));
  return Object.freeze({ verdict: metadata.expectedVerdict, explanation: 'Controlled calibration result.',
    criteria: Object.freeze(criteria), provider: 'controlled', model: 'semantic-fixture', attempts: 2,
    scopedCriteria: Object.freeze(packet.rubric.criteria.map(spec => Object.freeze({
      criterionId: spec.id, attempts: 1, provider: 'controlled', model: 'semantic-fixture', verdict: 'fixture',
    }))) });
}

test('runner records all 24 outcomes with exact provenance before accepting them', async () => {
  const recorded = [];
  const output = await calibration.runCalibration({ evaluate: controlledJudgment,
    recordResult: async item => recorded.push(item) });
  assert.equal(output.results.length, 24); assert.equal(recorded.length, 24);
  assert.deepEqual([...new Set(recorded.map(row => row.trial))], [1, 2, 3]);
  assert.ok(recorded.every(row => /^[0-9a-f]{64}$/.test(row.packetSha256)
    && /^[0-9a-f]{64}$/.test(row.resultSha256)));
  assert.ok(recorded.every(row => row.provider === 'controlled' && row.model === 'semantic-fixture'
    && row.attempts === 2 && row.scopedCriteria.length === 2));
});

test('runner records a mismatch or repair before rejecting qualification', async () => {
  const recorded = [];
  await assert.rejects(calibration.runCalibration({
    evaluate(packet, metadata) {
      const value = controlledJudgment(packet, metadata);
      return { ...value, attempts: 3, scopedCriteria: [
        { ...value.scopedCriteria[0], attempts: 2 }, value.scopedCriteria[1],
      ] };
    }, recordResult: async item => recorded.push(item),
  }), /used a nonqualifying repair/);
  assert.equal(recorded.length, 1); assert.equal(recorded[0].attempts, 3);
  assert.deepEqual(recorded[0].scopedCriteria.map(row => row.attempts), [2, 1]);
});

test('canonical Judge keeps mock and fallback responses unavailable without a calibration claim', async () => {
  const matrix = await calibration.cases();
  for (const marker of [{ mocked: true }, { fallback: true }, { provider: 'mock' }]) {
    const judge = createObjectiveJudge({ model: { async chat() {
      return { provider: 'controlled', model: 'fixture', response: JSON.stringify({
        satisfied: true, evidenceRefs: ['learner_review_source'], citations: [],
      }), ...marker };
    } }, timeoutMs: 1000 });
    const judgment = await judge({ rubric: matrix[0].rubric, facts: matrix[0].facts,
      evidence: matrix[0].evidence, execution: { ownerId: 'controlled', runId: 'mock-control',
        signal: new AbortController().signal, async check() {}, async emit() {} } });
    assert.equal(judgment.verdict, 'unavailable');
    assert.notEqual(judgment.verdict, 'pass');
  }
});
