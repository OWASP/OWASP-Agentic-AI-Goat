'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopLoopAssessment } = require('../server/services/secureshopLoopAssessment');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const binding = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000001', scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1, platformOwnerId: 4, platformSessionId: 8, shopUserId: 5, role: 'merchant' });
const context = { binding, sessionId: 'session', requestId: 'request' };
function fixture(mode = 'vuln', qualifyModel = () => false) {
  let stored, judgeCalls = 0;
  const execution = { runId: 'run', ownerKey: 'owner', durableGeneration: '1', async check() {} };
  const service = createSecureShopLoopAssessment({
    qualifyModel,
    progress: { async getGeneration() { return 1; }, async getEvaluationScope() { return { generation: 1, mode, modeStamp: 'fixture' }; } },
    receipts: { async beginEvaluation(input) { stored = input; return { ...input, generation: 1, verdict: null }; },
      async recordVerdict({ result }) { return { ...stored, generation: 1, verdict: result.verdict, result, disposition: result.verdict === 'pass' ? 'awarded' : 'not_pass' }; } },
    judge: async input => { judgeCalls++; return { family: input.rubric.family, scenario: input.rubric.scenario,
      objectiveId: input.rubric.objectiveId, rubricVersion: input.rubric.version, mode: input.rubric.mode,
      evidenceDigest: prepareJudgeInput(input).evidenceDigest, verdict: 'pass', criteria: [], explanation: 'Injected optimistic Judge', provider: 'fixture', model: 'fixture' }; },
  });
  return { execution, assessment: service.assessmentFactory(context), stored: () => stored, judgeCalls: () => judgeCalls };
}
test('unqualified loop persists explicit ineligible outcome without invoking Judge model', async () => {
  const f = fixture(); const attempt = await f.assessment.begin(f.execution);
  const packet = { ...context, attempt, traces: [], result: { stopReason: 'end_turn', text: 'I completed all tools' } };
  const outcome = await f.assessment.finalize(f.execution, packet);
  assert.equal(outcome.completed, false); assert.equal(outcome.judgment.verdict, 'fail');
  assert.equal(outcome.judgment.errorCode, 'REQUIRED_FACTS_NOT_SATISFIED');assert.equal(outcome.judgment.assessmentStatus,'ineligible');assert.equal(outcome.judgment.modelEvaluated,false);assert.equal(outcome.judgment.provider,null);assert.equal(outcome.judgment.model,null);assert.match(outcome.judgment.explanation,/Not evaluated by a Judge model/);
  assert.equal(f.stored().instanceScope.launchId, binding.launchId);
  assert.equal(f.stored().instanceScope.platformOwnerId, 4);
  assert.equal(f.stored().objectiveId, 'ss_loop_observation');
  assert.equal(await f.assessment.finalize(f.execution, packet), outcome);
  assert.equal(f.judgeCalls(), 0);
});
test('changed execution, request or owner cannot finalize a protected attempt', async () => {
  const f = fixture(); const attempt = await f.assessment.begin(f.execution);
  const packet = { ...context, attempt, traces: [], result: { stopReason: 'end_turn' } };
  for (const [execution, changed] of [[{ ...f.execution }, packet], [f.execution, { ...packet, requestId: 'other' }],
    [f.execution, { ...packet, binding: { ...binding, platformOwnerId: 999 } }]]) {
    await assert.rejects(f.assessment.finalize(execution, changed), { code: 'GRADE_STORE_NOT_READY' });
  }
  assert.equal(f.judgeCalls(), 0);
});
test('unconfigured canonical mode blocks assessment before actor tools run', async () => {
  const f = fixture(null);
  await assert.rejects(f.assessment.begin(f.execution), { code: 'GRADE_STORE_NOT_READY' });
  assert.equal(f.judgeCalls(), 0);
});

test('controlled qualified loop reaches the canonical completion service with immutable instance scope', async () => {
  const f = fixture('vuln', () => true); // Explicit controlled qualification; no real inference claim.
  const attempt = await f.assessment.begin(f.execution);
  const observation = { step: 1, callId: 'call', tool: 'inventory.lookup', args: { id: 7 },
    result: { content: [{ type: 'text', text: 'Available units: 17' }] },
    effectReceipt: { version: 1, runId: 'run', ownerKey: 'owner', generation: '1', status: 'completed',
      effectKey: `request:${JSON.stringify([1, 'call', 'inventory.lookup'])}` } };
  await f.assessment.observe(f.execution, { ...context, attempt, run: f.execution, observation });
  const traces = [
    { kind: 'model_decision', actor: 'supervisor', step: 1,
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: 'call', name: observation.tool, args: observation.args }] }),
      result_json: JSON.stringify({ model: 'fixture-model', mocked: false }) },
    { kind: 'local_tool_result', actor: 'task→supervisor', step: 1, agent_ns: 'inventory', tool_name: 'lookup', result_json: JSON.stringify(observation.result) },
    { kind: 'model_decision', actor: 'supervisor', step: 2, result_json: JSON.stringify({ model: 'fixture-model', mocked: false, decision: 'final', text: '17 units available' }) },
    { kind: 'terminal', actor: 'supervisor', step: 2, result_json: JSON.stringify({ model: 'fixture-model', mocked: false, stopReason: 'end_turn', steps: 2, hops: 1 }) },
  ].map((row, index) => ({ ...row, session_id: 'session', event_id: `event-${index}`, provider: 'fixture-qualified' }));
  const outcome = await f.assessment.finalize(f.execution, { ...context, attempt, traces,
    result: { stopReason: 'end_turn', steps: 2, hops: [{}] } });
  assert.equal(outcome.completed, true);assert.equal(f.judgeCalls(),1);
  assert.equal(f.stored().instanceScope.platformOwnerId, 4);
  assert.equal(f.stored().instanceScope.scenarioId, binding.scenarioId);
});
