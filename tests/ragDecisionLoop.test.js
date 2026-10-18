'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { runRagDecisionLoop } = require('../server/agent-runtime/ragDecisionLoop');
const search = (query = 'policy') => ({ action: 'search_document', query, topK: 2 });
const answer = { action: 'answer', answer: 'Two days.' };
function fixture(decisions, searchDocument) {
  const calls = [], effects = [], traces = [];
  return { calls, effects, traces, options: {
    policy: 'Use observed policy.', question: 'How many days?',
    model: { chatWithMessages: async messages => { calls.push(messages);
      const next = decisions.shift(); return { provider: 'controlled', model: 'fixture',
        response: typeof next === 'string' ? next : JSON.stringify(next) }; } },
    execution: { check: async () => {}, effect: async (key, callback) => { effects.push(key); return callback(); },
      trace: async event => traces.push(event), signal: new AbortController().signal },
    searchDocument: searchDocument || (async () => ({ chunks: [{ text: 'Two days.', score: 1, chunkIndex: 0 }], receipt: { source: 'controlled' } })),
  } };
}
test('real graph executes exact selected search and exposes observations to the next model decision', async () => {
  let args;
  const f = fixture([search('remote days'), answer], async selected => { args = selected;
    return { chunks: [{ text: 'Two days.', score: 1, chunkIndex: 3 }], receipt: { source: 'controlled' } }; });
  const output = await runRagDecisionLoop(f.options);
  assert.deepEqual(args, { query: 'remote days', topK: 2 });
  assert.equal(f.effects.length, 1); assert.equal(f.calls.length, 2);
  assert.ok(f.calls[1][1].content.includes('Two days.'));
  assert.equal(output.answer, 'Two days.'); assert.equal(output.observations[0].chunks[0].chunkIndex, 3);
});
test('model may answer without a fabricated retrieval', async () => {
  const f = fixture([answer]); const output = await runRagDecisionLoop(f.options);
  assert.equal(f.effects.length, 0); assert.deepEqual(output.observations, []);
});
test('one invalid schema is repaired but repeated invalid schema fails before any effect', async () => {
  const repaired = fixture(['invalid', search(), answer]);
  await runRagDecisionLoop(repaired.options); assert.equal(repaired.effects.length, 1);
  const failed = fixture(['invalid', 'invalid']);
  await assert.rejects(runRagDecisionLoop(failed.options), { code: 'RAG_DECISION_INVALID' });
  assert.equal(failed.effects.length, 0); assert.equal(failed.calls.length, 2);
});
test('duplicate search terminates without replaying the effect', async () => {
  const f = fixture([search(), search()]);
  await assert.rejects(runRagDecisionLoop(f.options), { code: 'RAG_DUPLICATE_SEARCH' });
  assert.equal(f.effects.length, 1);
});
test('three-search budget prevents a fourth search', async () => {
  const f = fixture(['one','two','three','four'].map(search));
  await assert.rejects(runRagDecisionLoop(f.options), { code: 'RAG_SEARCH_BUDGET_EXHAUSTED' });
  assert.equal(f.effects.length, 3);
});
test('tool failure never becomes an empty successful observation', async () => {
  const f = fixture([search(), answer], async () => { throw Object.assign(Error('offline'), { code: 'DB_UNAVAILABLE' }); });
  await assert.rejects(runRagDecisionLoop(f.options), { code: 'DB_UNAVAILABLE' });
  assert.equal(f.calls.length, 1);
});
test('missing retrieval receipt rejects claimed chunks before answer generation', async () => {
  const f = fixture([search(), answer], async () => ({ chunks: [] }));
  await assert.rejects(runRagDecisionLoop(f.options), { code: 'RAG_SEARCH_EVIDENCE_INVALID' });
  assert.equal(f.calls.length, 1);
});

test('reset while a retrieval is pending prevents the next model call and answer', async () => {
  let reset = false, release, entered;
  const started = new Promise(resolve => { entered = resolve; });
  const held = new Promise(resolve => { release = resolve; });
  const f = fixture([search(), answer], async () => { entered(); await held;
    return { chunks: [{ text: 'old policy', score: 1, chunkIndex: 0 }], receipt: { source: 'old' } }; });
  f.options.execution.check = async () => { if (reset) throw Object.assign(Error('reset'), { code: 'GENERATION_STALE' }); };
  const running = runRagDecisionLoop(f.options);
  const rejected = assert.rejects(running, { code: 'GENERATION_STALE' });
  await started; reset = true; release(); await rejected;
  assert.equal(f.calls.length, 1);
});

test('ledger replay cannot bypass retrieval shape and score validation', async () => {
  for (const chunks of [
    [{ text: 'bad', score: 1, chunkIndex: -1 }],
    [{ text: 'bad', score: Infinity, chunkIndex: 0 }],
    [{ text: 'a', score: 1, chunkIndex: 0 }, { text: 'b', score: 1, chunkIndex: 0 }],
  ]) {
    const f = fixture([search(), answer]);
    f.options.execution.effect = async () => ({ chunks, receipt: { source: 'controlled replay' } });
    await assert.rejects(runRagDecisionLoop(f.options), { code: 'RAG_SEARCH_EVIDENCE_INVALID' });
    assert.equal(f.calls.length, 1);
  }
});

test('decision, tool and termination metadata survive the production trace allowlist', async () => {
  const { traceData } = require('../server/agent-runtime/runTraceStore');
  const f = fixture([search(), answer]);
  await runRagDecisionLoop(f.options);
  const events = f.traces.map(event => ({ ...event, data: traceData(event.data) }));
  assert.deepEqual(events.filter(event => event.node === 'rag_decide').map(event => event.data.tool), ['search_document', 'answer']);
  assert.ok(events.every(event => event.data.decisionSource === 'model'));
  assert.equal(events.find(event => event.node === 'rag_search').type, 'tool');
  assert.equal(events.at(-1).data.toolSteps, 1);
  assert.equal(events.at(-1).data.terminationReason, 'model_finished');
});
