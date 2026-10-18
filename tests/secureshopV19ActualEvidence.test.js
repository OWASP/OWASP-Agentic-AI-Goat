'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { assertOriginalActorJoin, COUNTERS, assertGetOnlyRecovery } = require('./fixtures/secureshopV19ActualEvidence');
function fixture() {
  const model = { provider: 'ollama', model: 'configured-model', mocked: false };
  const source = 'Read this synthetic source.', answer = 'A summary of this source.';
  const row = { result_json: { text: answer, steps: 2, stopReason: 'end_turn', hops: [{ tool: 'summarizer.summarize_file', params: {}, error: null, policyViolation: null, result: { content: [{ type: 'text', text: source }] } }],
    taskMetadata: { boundFileSummary: { originalEnvelope: '{"message":"Summarize"}', graphEffect: { callId: 'read' } } } } };
  const tool = { id: 'read', name: 'summarizer.summarize_file', args: {} };
  const actorSpans = [
    { method: 'chat', request: { messages: [{ role: 'user', content: '{"message":"Summarize"}' }] },
      response: { ...model, tool_uses: [tool], stop_reason: 'tool_use' } },
    { method: 'chat', request: { messages: [{ role: 'tool', tool_call_id: 'read', content: source }] },
      response: { ...model, text: answer, stop_reason: 'end_turn' } }
  ];
  const traces = [
    { kind: 'model_decision', provider: model.provider, step: 1,
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [tool] }), result_json: JSON.stringify(model) },
    { kind: 'model_decision', provider: model.provider, step: 2,
      result_json: JSON.stringify({ ...model, decision: 'final', text: answer }) },
    { kind: 'local_tool_call' }, { kind: 'local_tool_result' }, { kind: 'final' },
    { kind: 'terminal', provider: model.provider, step: 2, result_json: JSON.stringify(model) }
  ];
  return { row, actorSpans, traces, qualifyModel: identity => identity.provider === 'ollama'
    && identity.model === 'configured-model' && identity.mocked === false };
}
test('original observer joins both recorded chat responses without invoking a provider', () => {
  assert.equal(assertOriginalActorJoin(fixture()).callId, 'read');
});
for (const [name, mutate] of [
  ['mock', f => { f.actorSpans[0].response.mocked = true; }],
  ['wrong final API', f => { f.actorSpans[1].method = 'finalResponse'; }],
  ['supplied path', f => { f.actorSpans[0].response.tool_uses[0].args.path = '/host'; }],
  ['changed observed source', f => { f.actorSpans[1].request.messages[0].content += 'modified'; }],
  ['changed original answer', f => { f.actorSpans[1].response.text = 'substitute'; }],
  ['foreign model', f => { f.actorSpans[1].response.model = 'other'; }],
  ['extra selected effect', f => { f.traces.push({ kind: 'local_tool_call' }); }],
  ['blocked tool trace', f => { f.traces.push({ kind: 'tool_blocked' }); }],
  ['prior tool context', f => { f.actorSpans[0].request.messages.push({ role: 'tool', content: 'prior' }); }]
]) test(`original observer rejects ${name}`, () => {
  const f = fixture(); mutate(f); assert.throws(() => assertOriginalActorJoin(f));
});
test('saved read counter snapshots are copied and forbid every new execution or publication', () => {
  const before = Object.fromEntries(COUNTERS.map(key => [key, 1]));
  assertGetOnlyRecovery(before, { ...before });
  for (const key of COUNTERS) assert.throws(() => assertGetOnlyRecovery(before, { ...before, [key]: 2 }));
});
