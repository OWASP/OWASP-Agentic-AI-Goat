'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { OpenAIProvider } = require('../../../../server/services/secureshop/providers/openaiProvider');
const { ProviderRouter } = require('../../../../server/services/secureshop/providerRouter');

test('HTTP 429 triggers provider fallback without leaking response bodies', async t => {
  const server = http.createServer((_req, res) => {
    res.writeHead(429, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: { message: 'private upstream diagnostic' } }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const openai = new OpenAIProvider({ apiKey: 'fixture', baseUrl: `http://127.0.0.1:${server.address().port}` });
  await assert.rejects(openai.chat({ messages: [] }), error => {
    assert.equal(error.status, 429);
    assert.equal(error.retryable, true);
    assert.equal(error.message.includes('private'), false);
    return true;
  });
  let fallback = 0;
  const router = new ProviderRouter({ openai, mock: {
    isReachable: async () => true,
    chat: async () => { fallback++; return { stop_reason: 'end_turn', text: 'fallback' }; },
  } });
  assert.equal((await router.chat({ messages: [] })).text, 'fallback');
  assert.equal(fallback, 1);
});

test('paired assistant tool-call history survives LangChain conversion and empty success rejects', async () => {
  const tool_calls = [{ id: 'call_1', type: 'function', function: { name: 'cart__read', arguments: '{}' } }];
  const provider = new OpenAIProvider({ apiKey: 'fixture' }, { modelFactory: () => ({ invoke: async messages => {
    assert.equal(messages[0].tool_calls[0].name, 'cart__read');
    assert.equal(messages[0].tool_calls[0].id, 'call_1');
    assert.equal(messages[1].tool_call_id, 'call_1');
    return { content: '' };
  } }) });
  await assert.rejects(provider.chat({ messages: [
    { role: 'assistant', content: null, tool_calls },
    { role: 'tool', tool_call_id: 'call_1', content: '{}' },
  ] }), /request failed/);
});
