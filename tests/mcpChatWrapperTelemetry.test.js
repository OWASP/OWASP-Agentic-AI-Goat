'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createMultiProviderAIService } = require('../server/services/multiProviderAIService');
function service(result) {
  const ai = createMultiProviderAIService({ env: { AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'configured-only' }, logger: { log() {} } });
  ai._chatModel = async () => { if (result instanceof Error) throw result;return result; };
  return ai;
}
test('chat wrapper forwards exact adapter response identity and simulation flags', async () => {
  const tools = [{ id: 'controlled' }];
  const result = await service({ response: 'answer', tool_calls: tools, provider: 'reported-provider', model: 'reported-model',
    mocked: true, fallback: false }).chatWithTools([]);
  assert.deepEqual(result, { role: 'assistant', content: 'answer', tool_calls: tools,
    provider: 'reported-provider', model: 'reported-model', mocked: true, fallback: false });
});
test('chat wrapper never substitutes configured identity for missing fields or errors', async () => {
  for (const input of [{ response: 'answer' }, { response: 'answer', provider: '', model: null }, new Error('controlled failure')]) {
    const result = await service(input).chatWithTools([]);
    assert.equal(result.provider, undefined);assert.equal(result.model, undefined);
    assert.equal(result.mocked, undefined);assert.equal(result.fallback, undefined);
  }
});
test('chat wrapper preserves fallback denial marker independently of identity', async () => {
  const result = await service({ response: 'fallback text', fallback: true }).chatWithTools([]);
  assert.equal(result.fallback, true);assert.equal(result.provider, undefined);assert.equal(result.model, undefined);
});

test('shared chat wrapper identity reaches the MCP run trace without configured substitution', async () => {
  const { decideMcp } = require('../server/agent-runtime/mcpDecision');
  const traces = require('../server/agent-runtime/runTraceStore');
  const context = { runId: '66666666-6666-4666-8666-666666666666', ownerKey: '["MCP","telemetry-test"]', generation: 0 };
  traces.begin(context);
  try {
    const result = await decideMcp({
      model: service({ response: JSON.stringify({ tool: 'read_ticket', params: { id: '4290' } }),
        provider: 'reported-provider', model: 'reported-model' }),
      message: 'Read ticket 4290.', catalog: [{ name: 'read_ticket' }],
      execution: { ...context, check: async () => {}, trace: async event => traces.append(context, event) },
    });
    assert.equal(result.decisionSource, 'model');
    const run = traces.getRun(context.runId, context.ownerKey);
    assert.equal(run.provider, 'reported-provider');assert.equal(run.model, 'reported-model');
    assert.ok(run.events.some(event => event.data.provider === run.provider && event.data.model === run.model));
  } finally { traces.finish(context, 'completed'); }
});
