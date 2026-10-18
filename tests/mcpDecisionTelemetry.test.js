'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { decideMcp, decideObservedAction } = require('../server/agent-runtime/mcpDecision');

async function capture(observed, response, provider = 'configured-provider') {
  const events = [];
  const execution = { ownerKey: JSON.stringify(['MCP', '7']),
    runId: '123e4567-e89b-42d3-a456-426614174000', durableGeneration: 0,
    async check() {}, async trace(event) { events.push(event); } };
  const model = { provider, model: 'configured-model', async chatWithTools() { return response; } };
  const result = observed
    ? await decideObservedAction({ model, execution, scenario: 'indirect_injection', observationSource: 'support_ticket',
      untrustedText: 'A controlled ticket.', userRequest: 'Summarize the ticket.' })
    : await decideMcp({ model, execution, message: 'Read ticket 4290.', catalog: [{ name: 'read_ticket' }] });
  return { result, events };
}
for (const observed of [false, true]) {
  const name = observed ? 'observed action' : 'main decision';
  const content = none => JSON.stringify(observed
    ? { action: none ? 'none' : 'send_report', params: none ? {} : { to: 'owned@example.invalid', body: 'Exact text.' } }
    : { tool: none ? 'none' : 'read_ticket', params: none ? {} : { id: '4290' } });
  test(`${name} records actual response identity for action and none`, async () => {
    for (const none of [false, true]) {
      const { events } = await capture(observed, { content: content(none), provider: 'ollama', model: 'llama3.1:8b' });
      const decision = events.find(event => event.type === 'decision' && event.data.tool);
      assert.equal(decision.data.provider, 'ollama');assert.equal(decision.data.model, 'llama3.1:8b');
      assert.equal(decision.data.decisionSource, 'model');
      if (none) assert.equal(decision.data.tool, 'none');
    }
  });
  test(`${name} never fabricates configured or missing identity`, async () => {
    for (const metadata of [{}, { provider: 'ollama' }, { model: 'reported-model' }, { provider: '', model: null }]) {
      const { events } = await capture(observed, { content: content(false), ...metadata });
      const decision = events.find(event => event.type === 'decision' && event.data.tool);
      assert.equal(decision.data.provider, metadata.provider || undefined);
      assert.equal(decision.data.model, metadata.model || undefined);
    }
  });
  test(`${name} rejected responses cannot supply identity`, async () => {
    for (const response of [
      { content: content(false), mocked: true }, { content: content(false), fallback: true }, { content: 'invalid JSON' },
    ]) {
      const { events } = await capture(observed, { ...response, provider: 'ollama', model: 'llama3.1:8b' });
      assert.ok(events.every(event => !('provider' in event.data) && !('model' in event.data)));
    }
  });
}
test('scripted observed mock path never reports actual identity', async () => {
  const { result, events } = await capture(true, {}, 'mock');
  assert.equal(result.decisionSource, 'scripted');
  assert.ok(events.every(event => !('provider' in event.data) && !('model' in event.data)));
});
