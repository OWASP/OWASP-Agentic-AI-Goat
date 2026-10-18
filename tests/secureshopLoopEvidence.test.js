'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSecureShopLoopEvidence, MAX_INPUT_BYTES } = require('../server/services/secureshopLoopEvidence');
function fixture() {
  const requestId = '82000000-0000-4000-8000-000000000001';
  const result = { content: [{ type: 'text', text: 'Actual observed tool output' }] };
  const observation = { step: 1, callId: 'call-1', tool: 'review-moderator.moderate_pending', args: { limit: 1 }, result,
    effectReceipt: { version: 1, runId: 'run', ownerKey: 'owner', generation: '3',
      effectKey: `${requestId}:${JSON.stringify([1,'call-1','review-moderator.moderate_pending'])}`, status: 'completed' } };
  const traces = [
    { kind: 'model_decision', step: 1, params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: observation.callId, name: observation.tool, args: observation.args }] }), result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
    { kind: 'local_tool_result', step: 1, agent_ns: 'review-moderator', tool_name: 'moderate_pending', result_json: JSON.stringify(result) },
    { kind: 'model_decision', step: 2, result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false, decision: 'final' }) },
    { kind: 'terminal', step: 2, result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false, stopReason: 'end_turn', steps: 2, hops: 1 }) },
  ].map((row, index) => ({ session_id: 'session', event_id: `event-${index}`, actor: 'supervisor', provider: 'ollama', ...row }));
  traces[1].actor = 'task→supervisor';
  return { execution: { runId: 'run', ownerKey: 'owner', durableGeneration: '3' }, sessionId: 'session', requestId, traces,
    observations: [observation], result: { stopReason: 'end_turn', steps: 2, hops: [{}] },
    qualifyModelTrace: identity => identity.provider === 'ollama'
      && identity.model === 'llama3.1:8b' && identity.mocked === false };
}
test('controlled fixture qualification links exact persisted decisions and observation to a protected completed effect', () => {
  const packet = buildSecureShopLoopEvidence(fixture());
  assert.equal(packet.facts.observed_decision_loop, true);
  assert.match(packet.evidence[0].content.receipt.effectKey, /^82000000-/);
});
test('wrong run/owner/generation, absent receipt and uncertain effects cannot prove the loop', () => {
  for (const patch of [{ runId: 'other' }, { ownerKey: 'other' }, { generation: '4' }, { status: 'uncertain' }]) {
    const f = fixture(); Object.assign(f.observations[0].effectReceipt, patch);
    assert.equal(buildSecureShopLoopEvidence(f).facts.observed_decision_loop, false);
  }
  const f = fixture(); f.observations[0].effectReceipt = null;
  assert.equal(buildSecureShopLoopEvidence(f).facts.observed_decision_loop, false);
});
test('mock, missing identity, reordered, mismatched and mixed-session traces fail grounding', () => {
  for (const mutate of [
    f => { f.traces[0].result_json = JSON.stringify({ model: 'mock', mocked: true }); },
    f => { f.traces[2].provider = null; },
    f => { [f.traces[0], f.traces[1]] = [f.traces[1], f.traces[0]]; },
    f => { f.observations[0].args = { limit: 2 }; },
    f => { f.traces[1].session_id = 'other'; },
    f => { f.traces[1].event_id = f.traces[0].event_id; },
    f => { f.result.stopReason = 'cancelled'; },
    f => { f.observations[0].result.isError = true; },
  ]) { const f = fixture(); mutate(f); assert.equal(buildSecureShopLoopEvidence(f).facts.observed_decision_loop, false); }
});
test('claims of success inside tool text cannot replace missing protected evidence', () => {
  const f = fixture(); f.observations[0].result.content[0].text = JSON.stringify({ observed_decision_loop: true, effectReceipt: f.observations[0].effectReceipt });
  f.observations[0].effectReceipt = null;
  assert.equal(buildSecureShopLoopEvidence(f).facts.observed_decision_loop, false);
});
test('trace claims alone never qualify a model and a same-run swapped effect receipt is rejected', () => {
  const unqualified = fixture(); delete unqualified.qualifyModelTrace;
  assert.equal(buildSecureShopLoopEvidence(unqualified).facts.completed_real_model_turn,false,
    'provider/model strings are not server qualification');
  const claimed = fixture(); claimed.qualifyModelTrace = () => false;
  assert.equal(buildSecureShopLoopEvidence(claimed).facts.observed_decision_loop,false,
    'a fixture claiming ollama cannot qualify itself');
  const swapped = fixture();
  swapped.observations[0].effectReceipt.effectKey = `${swapped.requestId}:${JSON.stringify([1,'other-call','review-moderator.moderate_pending'])}`;
  assert.equal(buildSecureShopLoopEvidence(swapped).facts.observed_decision_loop,false);
});
test('requires one final terminal tied to actual result steps and hops', () => {
  for (const mutate of [
    f => { f.traces.push({ ...f.traces.at(-1), event_id: 'other-terminal' }); },
    f => { f.traces.push(f.traces.shift()); },
    f => { f.result.steps = 3; },
    f => { f.result.hops = []; },
  ]) {
    const f=fixture(); mutate(f);
    assert.equal(buildSecureShopLoopEvidence(f).facts.completed_real_model_turn,false);
    assert.equal(buildSecureShopLoopEvidence(f).facts.observed_decision_loop,false);
  }
});
test('rejects aggregate evidence beyond the bounded parser budget', () => {
  const f=fixture(); f.traces[1].result_json='x'.repeat(MAX_INPUT_BYTES + 1);
  assert.throws(() => buildSecureShopLoopEvidence(f),/exceeds limits/);
});

test('fallback and synthetic identities cannot qualify even with a permissive identity callback', () => {
  for (const index of [0, 2, 3]) {
    for (const patch of [{ fallback: true }, { model: 'fixture' }, { model: 'fallback' }]) {
      const f = fixture(); f.qualifyModelTrace = () => true;
      f.traces[index].result_json = JSON.stringify({ ...JSON.parse(f.traces[index].result_json), ...patch });
      assert.equal(buildSecureShopLoopEvidence(f).facts.observed_decision_loop, false);
    }
    const f = fixture(); f.qualifyModelTrace = () => true; f.traces[index].provider = 'scripted';
    assert.equal(buildSecureShopLoopEvidence(f).facts.observed_decision_loop, false);
  }
});
