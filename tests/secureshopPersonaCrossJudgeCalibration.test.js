'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createObjectiveJudge, JUDGE_VERSION }
  = require('../server/agent-runtime/objectiveJudge');
const { createSecureShopPersonaInboxRubric }
  = require('../server/services/secureshopPersonaInboxAssessment');
const calibration = require('./fixtures/secureshopPersonaCrossJudgeCalibration');

function responseFor(value, overrides = {}) {
  return { response: JSON.stringify(value), provider: 'controlled', model: 'controlled',
    mocked: false, fallback: false, metadata: { eval_count: 20 }, ...overrides };
}

function expectedResponse(calibrationCase) {
  const satisfied = calibrationCase.definition.expectedSatisfied;
  return responseFor({ verdict: satisfied ? 'pass' : 'fail',
    explanation: satisfied ? 'The completed effect returned a resource owned by another persona.'
      : 'The observed result does not show a completed cross-persona disclosure.',
    criteria: [{ id: calibration.CRITERION_ID, satisfied,
      evidenceRefs: ['persona_inbox_chain'] }] });
}

test('matrix preserves the exact historical cross v1 rubric and packet shape', () => {
  const production = createSecureShopPersonaInboxRubric('cross', 'vuln');
  const matrix = calibration.cases();
  assert.equal(matrix.length, calibration.SEMANTIC_CASES);
  assert.equal(production.version, 'secureshop-persona-inbox-v2');
  assert.equal(production.criterionScoped, undefined);
  assert.ok(matrix.every(item => item.rubric.version === 'secureshop-persona-inbox-v1'));
  assert.ok(matrix.every(item => JSON.stringify(item.rubric) !== JSON.stringify(production)));
  assert.equal(matrix.filter(item => item.definition.kind === 'authentic_positive').length, 3);
  assert.equal(matrix.filter(item => item.definition.kind === 'all_true_semantic_stress').length, 3);
  for (const item of matrix) {
    assert.deepEqual(Object.keys(item.facts), item.rubric.requiredFacts);
    assert.ok(item.rubric.requiredFacts.every(id => item.facts[id] === true));
    assert.deepEqual(item.evidence.map(row => [row.id, row.source]),
      item.definition.id === 'enforced_no_body_all_true_stress'
        ? [['persona_inbox_chain', 'server_observation']]
        : [['disclosed_private_message', 'tool_result'], ['persona_inbox_chain', 'server_observation']]);
    assert.equal(item.evidence.some(row => row.id === 'advisory_acl_outcome'), false);
  }
  assert.deepEqual(matrix.slice(0, 3).map(item =>
    item.evidence.find(row => row.id === 'disclosed_private_message').content),
  [calibration.BODIES.customer, calibration.BODIES.merchant, calibration.BODIES.admin]);
});

test('required-fact enforcement controls are separate from all-true semantic stress packets', () => {
  const controls = calibration.requiredFactCases();
  assert.equal(controls.length, calibration.REQUIRED_FACT_CONTROLS);
  for (const control of controls) {
    assert.equal(control.kind, 'required_fact_enforcement');
    assert.deepEqual(control.rubric.requiredFacts.filter(id => control.facts[id] !== true),
      [control.falseFact]);
  }
  assert.ok(calibration.cases().filter(item => item.definition.kind === 'all_true_semantic_stress')
    .every(item => item.rubric.requiredFacts.every(id => item.facts[id] === true)));
});

test('canonical Judge records bounded attempts before validation and normalizes terminal results', async () => {
  const seenAttempts = [];
  const seenResults = [];
  const byId = new Map(calibration.cases().map(item => [item.definition.id, item]));
  const output = await calibration.runCalibration({
    classify: async ({ caseId }) => expectedResponse(byId.get(caseId)),
    recordAttempt: async item => seenAttempts.push(item),
    recordResult: async item => seenResults.push(item),
  });
  assert.equal(output.providerAttempts, calibration.EXPECTED_PROVIDER_CALLS);
  assert.equal(seenAttempts.length, calibration.EXPECTED_PROVIDER_CALLS);
  assert.equal(seenResults.length, calibration.EXPECTED_RESULTS);
  for (const attempt of seenAttempts) {
    for (const field of ['promptSha256','systemPromptSha256','evidencePromptSha256',
      'outputPolicySha256','responseSha256']) assert.match(attempt[field], /^[0-9a-f]{64}$/);
    assert.equal(attempt.responseRetained, true);
    assert.ok(attempt.rawResponseBytes > 0 && attempt.rawResponseBytes <= calibration.MAX_RAW_RESPONSE_BYTES);
  }
  for (const result of seenResults) {
    assert.match(result.packetSha256, /^[0-9a-f]{64}$/);
    assert.match(result.policySha256, /^[0-9a-f]{64}$/);
    assert.match(result.resultSha256, /^[0-9a-f]{64}$/);
    assert.equal(result.persistedResult.judgeVersion, JUDGE_VERSION);
    assert.deepEqual(JSON.parse(JSON.stringify(result.persistedResult.criteria)),
      JSON.parse(JSON.stringify(result.judgment.criteria)));
  }
});

test('false required facts cannot earn pass even when the model repeats pass through repair', async () => {
  for (const control of calibration.requiredFactCases()) {
    let calls = 0;
    const model = { async chat() { calls += 1; return responseFor({ verdict: 'pass',
      explanation: 'Attempted positive despite a false authoritative fact.',
      criteria: [{ id: calibration.CRITERION_ID, satisfied: true,
        evidenceRefs: ['persona_inbox_chain'] }] }); } };
    const judge = createObjectiveJudge({ model, timeoutMs: 1000 });
    const judgment = await judge({ rubric: control.rubric, facts: control.facts,
      evidence: control.evidence, execution: { ownerId: 'controlled',
        runId: `77000000-0000-4000-8000-${String(calls + control.falseFact.length).padStart(12, '0')}`,
        async check() {}, async emit() {} } });
    assert.equal(calls, 2);
    assert.notEqual(judgment.verdict, 'pass');
    assert.equal(judgment.verdict, 'inconclusive');
    assert.doesNotThrow(() => calibration.persistedResult(judgment));
  }
});

test('malformed terminal responses remain captured before the canonical Judge reports unavailable', async () => {
  const attempts = [];
  const results = [];
  const output = await calibration.runCalibration({
    classify: async () => ({ response: '{', provider: 'controlled', model: 'controlled',
      mocked: false, fallback: false }),
    recordAttempt: async item => attempts.push(item),
    recordResult: async item => results.push(item),
    assertExpected: false,
  });
  assert.equal(output.providerAttempts, calibration.MAX_PROVIDER_CALLS);
  assert.equal(attempts.length, calibration.MAX_PROVIDER_CALLS);
  assert.equal(results.length, calibration.EXPECTED_RESULTS);
  assert.ok(results.every(item => item.judgment.verdict === 'unavailable'
    && item.judgment.errorCode === 'INVALID_JUDGE_OUTPUT'
    && item.attempts.length === 2 && item.invalidAttempts.length === 2
    && item.persistedResult.verdict === 'unavailable'));
  assert.ok(attempts.every(item => item.rawResponse === '{' && item.responseRetained));
});

test('semantic mismatches fail only after all trials and matched controls are retained', async () => {
  const results = [];
  await assert.rejects(calibration.runCalibration({
    classify: async () => responseFor({ verdict: 'fail', explanation: 'Controlled false result.',
      criteria: [{ id: calibration.CRITERION_ID, satisfied: false,
        evidenceRefs: ['persona_inbox_chain'] }] }),
    recordResult: async item => results.push(item),
  }), /Cross-persona semantic calibration mismatches/);
  assert.equal(results.length, calibration.EXPECTED_RESULTS);
  assert.deepEqual([...new Set(results.map(item => item.trial))], [1, 2, 3]);
  assert.equal(results.filter(item => item.kind === 'authentic_positive').length, 9);
  assert.equal(results.filter(item => item.kind === 'all_true_semantic_stress').length, 9);
});

test('oversized responses are bounded and retained categorically without raw bytes', async () => {
  const attempts = [];
  await assert.rejects(calibration.runCalibration({
    classify: async () => ({ response: 'x'.repeat(calibration.MAX_RAW_RESPONSE_BYTES + 1),
      provider: 'controlled', model: 'controlled', mocked: false, fallback: false }),
    recordAttempt: async item => attempts.push(item),
    assertExpected: false,
  }), { code: 'CALIBRATION_RESPONSE_TOO_LARGE' });
  assert.equal(attempts.length, 1);
  assert.ok(attempts.every(item => item.rawResponse === null && item.responseRetained === false
    && item.rawResponseBytes === calibration.MAX_RAW_RESPONSE_BYTES + 1
    && /^[0-9a-f]{64}$/.test(item.responseSha256)));
});

test('transport and provenance failures abort the batch after retaining the failed attempt', async () => {
  for (const [classify, code] of [
    [async () => { throw Object.assign(new Error('offline'), { code: 'CONTROLLED_TRANSPORT' }); },
      'CONTROLLED_TRANSPORT'],
    [async () => ({ response: '{}', provider: '', model: null, mocked: false, fallback: false }),
      'CALIBRATION_PROVENANCE_MISSING'],
  ]) {
    const attempts = [];
    await assert.rejects(calibration.runCalibration({ classify,
      recordAttempt: async item => attempts.push(item), assertExpected: false }), { code });
    assert.equal(attempts.length, 1);
  }
});

test('attempt-retention failure aborts after the first transport call', async () => {
  let transportCalls = 0;
  let retentionCalls = 0;
  const failure = Object.assign(new Error('attempt audit unavailable'),
    { code: 'CONTROLLED_RETENTION_FAILURE' });
  await assert.rejects(calibration.runCalibration({
    classify: async () => {
      transportCalls += 1;
      return responseFor({ verdict: 'pass', explanation: 'Controlled positive.',
        criteria: [{ id: calibration.CRITERION_ID, satisfied: true,
          evidenceRefs: ['persona_inbox_chain'] }] });
    },
    recordAttempt: async () => { retentionCalls += 1; throw failure; },
    assertExpected: false,
  }), { code: 'CONTROLLED_RETENTION_FAILURE' });
  assert.equal(transportCalls, 1);
  assert.equal(retentionCalls, 1);
});

test('qualification rejects unknown mocked provenance and accepts explicit false', async () => {
  const byId = new Map(calibration.cases().map(item => [item.definition.id, item]));
  const unknown = [];
  await assert.rejects(calibration.runCalibration({
    classify: async ({ caseId }) => {
      const response = expectedResponse(byId.get(caseId));
      delete response.mocked;
      response.provider = 'ollama'; response.model = calibration.MODEL;
      return response;
    },
    recordAttempt: async item => unknown.push(item),
    qualification: true,
  }), /requires actual-model provenance/);
  assert.equal(unknown.length, 1);
  assert.equal(unknown[0].mocked, null);
  assert.equal(unknown[0].fallback, false);

  const explicit = [];
  const output = await calibration.runCalibration({
    classify: async ({ caseId }) => ({ ...expectedResponse(byId.get(caseId)),
      provider: 'ollama', model: calibration.MODEL, mocked: false }),
    recordAttempt: async item => explicit.push(item),
    qualification: true,
  });
  assert.equal(output.providerAttempts, calibration.EXPECTED_PROVIDER_CALLS);
  assert.ok(explicit.every(item => item.mocked === false && item.fallback === false));
});
