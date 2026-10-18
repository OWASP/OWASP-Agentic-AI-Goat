'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createMultiProviderAIService } = require('../server/services/multiProviderAIService');
const { createLegacySensitivePayloadSuggestion } = require('../server/services/legacySensitivePayloadSuggestion');

test('text-only suggestion uses the real MultiProvider service over its injected lower adapter', async () => {
  const invocations = [];
  const service = createMultiProviderAIService({
    env: { AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'fixture-model', OLLAMA_BASE_URL: 'http://fixture.invalid' },
    logger: { log() {} },
    providerFactory(config) {
      assert.deepEqual(config, { provider: 'ollama', model: 'fixture-model', baseURL: 'http://fixture.invalid' });
      return { generate: async (prompt, options) => {
        invocations.push({ prompt, options });
        return { response: JSON.stringify({ payload: '../secret/fixture.txt', explanation: 'Text only',
          example: 'Ask the lab to read it', vulnerability: 'path_traversal' }),
          provider: 'ollama', model: 'fixture-model', mocked: false, fallback: false };
      } };
    },
  });
  const result = await createLegacySensitivePayloadSuggestion(service)('suggest a path example', 'path_traversal');
  assert.equal(result.payload, '../secret/fixture.txt');
  assert.equal(result.textOnly, true);
  assert.equal(invocations.length, 1);
  assert.match(invocations[0].prompt, /cannot execute tools/);
  assert.equal(invocations[0].options.format, 'json');
});

test('fallback, mock, malformed and invented extra fields fail without a suggested payload', async t => {
  for (const result of [
    { response: '{}', provider: 'fallback', fallback: true },
    { response: '{}', provider: 'mock', mocked: true },
    { response: 'not json', provider: 'ollama' },
    { response: JSON.stringify({ payload: 'x', explanation: 'x', example: 'x', vulnerability: 'path_traversal', executed: true }), provider: 'ollama' },
  ]) await t.test(result.provider || result.response, async () => {
    const suggest = createLegacySensitivePayloadSuggestion({ generateResponse: async () => result });
    await assert.rejects(suggest('fixture', 'auto'), { code: result.fallback || result.mocked
      ? 'PAYLOAD_SUGGESTION_UNAVAILABLE' : 'PAYLOAD_SUGGESTION_INVALID' });
  });
});

test('an explicit requested category cannot be silently changed by the model', async () => {
  const suggest = createLegacySensitivePayloadSuggestion({ generateResponse: async () => ({
    response: JSON.stringify({ payload: '../secret/x', explanation: 'x', example: 'x', vulnerability: 'path_traversal' }),
    provider: 'ollama', model: 'fixture',
  }) });
  await assert.rejects(suggest('SSI example', 'ssi_injection'), { code: 'PAYLOAD_SUGGESTION_INVALID' });
});
