'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { BedrockProvider } = require('../../../../server/services/secureshop/providers/bedrockProvider');

test('Bedrock uses LangChain Converse, pairs tool history, and preserves unsafe tool output', async () => {
  const requests = [];
  const client = { send: async command => {
    requests.push(command.input);
    return { output: { message: { role: 'assistant', content: [{ text: 'done' }] } },
      stopReason: 'end_turn', usage: { inputTokens: 3, outputTokens: 1, totalTokens: 4 } };
  } };
  const provider = new BedrockProvider({ modelId: 'fixture.model', region: 'us-west-2', client });
  assert.equal(await provider.isReachable(), true);
  const result = await provider.chat({ system: 'teaching system', messages: [
    { role: 'user', content: 'read' },
    { role: 'assistant', content: '', tool_calls: [{ id: 'one', function: { name: 'system.read', arguments: '{}' } }] },
    { role: 'tool', tool_call_id: 'one', content: '<script>INJECTION</script>' },
  ], tools: [{ agent: 'system', tool: 'read', inputSchema: { type: 'object', properties: {} } }] });
  assert.deepEqual(result, { stop_reason: 'end_turn', text: 'done' });
  assert.equal(requests[0].messages[1].content[0].toolUse.toolUseId, 'one');
  assert.equal(requests[0].messages[1].content[0].toolUse.name, 'system__read');
  assert.equal(requests[0].messages[2].content[0].toolResult.toolUseId, 'one');
  assert.equal(requests[0].messages[2].content[0].toolResult.content[0].text, '<script>INJECTION</script>');
});

test('Bedrock service errors expose status without provider diagnostics', async () => {
  const provider = new BedrockProvider({ modelId: 'fixture.model', client: { send: async () => {
    throw Object.assign(new Error('private provider diagnostic'), { $metadata: { httpStatusCode: 503 } });
  } } });
  await assert.rejects(provider.chat({ messages: [{ role: 'user', content: 'hi' }] }), error => {
    assert.equal(error.status, 503); assert.equal(error.retryable, true);
    assert.equal(error.message, 'bedrock HTTP 503'); return true;
  });
});
