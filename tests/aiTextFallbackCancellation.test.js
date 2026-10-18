'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createMultiProviderAIService } = require('../server/services/multiProviderAIService');
const { withOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');
function service() {
  return createMultiProviderAIService({ env: { AI_PROVIDER: 'ollama' }, logger: { log() {} }, providerFactory() { throw new Error('Unexpected real adapter'); } });
}
test('text fallback forwards request options to the selected provider', async () => {
  const ai = service(); const signal = new AbortController().signal;
  const options = { signal, ownerId: 'isolated-learner', customOption: 'preserve' };
  ai.generateWithLMStudio = async (prompt, temperature, tokens, timeout, forwarded) => {
    assert.equal(prompt, 'test'); assert.equal(timeout, 1234);
    assert.equal(forwarded.signal, signal); assert.equal(forwarded.ownerId, options.ownerId);
    assert.equal(forwarded.customOption, 'preserve'); return { response: 'ok' };
  };
  assert.deepEqual(await ai.fallbackGenerate('test', 0, 12, 1234, options), { response: 'ok' });
});
test('already cancelled owner never invokes a fallback provider', async () => {
  const ai = service(); const controller = new AbortController();
  const reason = new DOMException('Reset', 'AbortError'); controller.abort(reason);
  let calls = 0; ai.generateWithLMStudio = async () => { calls++; return { response: 'late' }; };
  await withOwnerExecution({ signal: controller.signal }, async () => {
    await assert.rejects(ai.fallbackGenerate('test', 0, 12), error => error === reason);
    await assert.rejects(ai.generateResponse('test'), error => error === reason);
  });
  assert.equal(calls, 0);
});
test('cancellation during fallback propagates without trying another provider', async () => {
  const ai = service(); const controller = new AbortController();
  const reason = new DOMException('Reset', 'AbortError'); let lateCalls = 0;
  ai.claudeApiKey = 'test-only';
  ai.generateWithLMStudio = async () => { controller.abort(reason); throw reason; };
  ai.generateWithClaude = async () => { lateCalls++; return { response: 'late' }; };
  await assert.rejects(ai.fallbackGenerate('test', 0, 12, 1234, { signal: controller.signal }), error => error === reason);
  assert.equal(lateCalls, 0);
});
test('primary provider AbortError is not converted into a fallback response', async () => {
  const ai = service(); const reason = new DOMException('Provider cancelled', 'AbortError');
  let fallbackCalls = 0;
  ai.generateWithOllama = async () => { throw reason; };
  ai.fallbackGenerate = async () => { fallbackCalls++; return { response: 'late' }; };
  await assert.rejects(ai.generateResponse('test'), error => error === reason);
  assert.equal(fallbackCalls, 0);
  assert.equal(ai.inFlightRequests.size, 0);
});
test('explicit fallback opt-out rethrows a provider failure', async () => {
  const ai = service(); const failure = new Error('formatter timed out');
  let fallbackCalls = 0;
  ai.generateWithOllama = async () => { throw failure; };
  ai.fallbackGenerate = async () => { fallbackCalls++; return { response: 'late' }; };
  await assert.rejects(ai.generateResponse('test', { allowFallback: false }), error => error === failure);
  assert.equal(fallbackCalls, 0);
  assert.equal(ai.inFlightRequests.size, 0);
});
test('ordinary fallback failure still reaches the next configured provider with intact options', async () => {
  const ai = service(); const options = { ownerId: 'learner', signal: new AbortController().signal };
  const calls = []; ai.claudeApiKey = 'test-only';
  ai.generateWithLMStudio = async () => { calls.push('lmstudio'); throw new Error('Connection unavailable'); };
  ai.generateWithClaude = async (_prompt, _temperature, _tokens, _timeout, forwarded) => {
    calls.push('claude'); assert.equal(forwarded.ownerId, options.ownerId);
    assert.equal(forwarded.signal, options.signal); return { response: 'recovered', provider: 'claude' };
  };
  assert.deepEqual(await ai.fallbackGenerate('test', 0, 12, 1234, options), { response: 'recovered', provider: 'claude' });
  assert.deepEqual(calls, ['lmstudio', 'claude']);
});
