'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { assertLiveRefundEnvironment, createLiveRefundProvider } = require('./postgres/secureshopRefundActual8bGate');

test('actual refund gate rejects fallback, non-loopback, and wrong-model configurations', () => {
  for (const env of [
    { SS_REFUND_LIVE_MODEL: '1', OLLAMA_MODEL: 'llama3.1:8b', OLLAMA_BASE_URL: 'https://remote.invalid' },
    { SS_REFUND_LIVE_MODEL: '1', OLLAMA_MODEL: 'other-model', OLLAMA_BASE_URL: 'http://127.0.0.1:11434' },
    { SS_REFUND_LIVE_MODEL: '0', OLLAMA_MODEL: 'llama3.1:8b', OLLAMA_BASE_URL: 'http://127.0.0.1:11434' },
  ]) assert.throws(() => assertLiveRefundEnvironment(env));
});

test('actual refund provider has no mock fallback and enforces a bounded physical call budget', async () => {
  const env = { SS_REFUND_LIVE_MODEL: '1', OLLAMA_MODEL: 'llama3.1:8b', OLLAMA_BASE_URL: 'http://127.0.0.1:11434' };
  for (const maxCalls of [0, -1, 7, NaN, Infinity, 1.5]) {
    assert.throws(() => createLiveRefundProvider({ env, maxCalls }), /budget/);
  }
  const { provider, getCalls } = createLiveRefundProvider({
    env,
    maxCalls: 6,
    transportChat: async () => ({ response: getCalls() === 5
      ? '{"bad":true}' : getCalls() === 6 ? '{"answer":"done"}' : '{"tool_calls":[{"agent":"support","tool":"order_status","args":{"order_id":1}}]}',
      usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } }),
  });
  assert.deepEqual(provider._order(), ['ollama']);
  const ollama = provider.providers.ollama;
  for (let index = 0; index < 4; index += 1) await ollama.chat({ system: '', messages: [], tools: [] });
  const final = await ollama.finalResponse({ system: '', messages: [] });
  assert.equal(final.text, 'done');
  assert.equal(getCalls(), 6);
  await assert.rejects(() => ollama.chat({ system: '', messages: [], tools: [] }), /budget exceeded/);
  assert.equal(getCalls(), 7);
});
