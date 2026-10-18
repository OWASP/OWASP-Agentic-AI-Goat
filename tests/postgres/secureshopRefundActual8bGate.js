'use strict';

const assert = require('node:assert/strict');
const { ProviderRouter } = require('../../server/services/secureshop/providerRouter');
const { OllamaProvider } = require('../../server/services/secureshop/providers/ollamaProvider');

const MODEL = 'llama3.1:8b';
function assertLiveRefundEnvironment(env = process.env) {
  assert.equal(env.SS_REFUND_LIVE_MODEL, '1');
  assert.equal(env.OLLAMA_MODEL, MODEL, 'live refund gate requires the pinned model');
  assert.match(env.OLLAMA_BASE_URL || '', /^http:\/\/(127\.0\.0\.1|localhost):11434\/?$/,
    'live refund gate requires loopback Ollama');
}

function createLiveRefundProvider({ env = process.env, maxCalls = 6, transportChat } = {}) {
  assertLiveRefundEnvironment(env);
  if (!Number.isSafeInteger(maxCalls) || maxCalls < 1 || maxCalls > 6) {
    throw new RangeError('refund model call budget must be an integer between 1 and 6');
  }
  let calls = 0;
  const ollama = new OllamaProvider({ baseUrl: env.OLLAMA_BASE_URL, model: MODEL });
  if (transportChat) ollama.transport.chat = transportChat;
  const dispatch = ollama.transport.chat.bind(ollama.transport);
  ollama.transport.chat = async (...args) => {
    calls += 1;
    if (calls > maxCalls) throw Object.assign(new Error('refund model call budget exceeded'), {
      code: 'REFUND_MODEL_CALL_BUDGET',
    });
    return dispatch(...args);
  };
  const provider = new ProviderRouter({ ollama });
  return Object.freeze({ provider, getCalls: () => calls });
}

module.exports = { MODEL, assertLiveRefundEnvironment, createLiveRefundProvider };
