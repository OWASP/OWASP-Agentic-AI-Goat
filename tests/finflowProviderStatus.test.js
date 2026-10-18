'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { getFinflowProviderStatus } = require('../server/services/finflowProviderStatus');
function service(provider, overrides = {}) {
  return { getActiveProviderInfo: () => ({ provider, providerName: provider, model: 'llama3.1:8b', region: 'us-west-2' }),
    verifyProviderConnectionLite: async selected => {
      assert.equal(selected, provider);
      return { configured: true, available: true, healthy: true, message: 'SECRET', error: 'SECRET' };
    },
    verifyProviderConnection: () => assert.fail('No generation probe'),
    checkOllamaAvailable: () => assert.fail('No model switching'),
    generateResponse: () => assert.fail('No inference'),
    getOllamaAvailableModels: async () => ['llama3.1:8b'],
    getOllamaVersion: async () => '0.12.0', ...overrides };
}
for (const provider of ['openai', 'chatgpt', 'anthropic', 'claude', 'bedrock']) {
  test(`${provider} configuration is not evidence of availability`, async () => {
    const status = await getFinflowProviderStatus(service(provider));
    assert.equal(status.available, null); assert.equal(status.configured, true);
    assert.equal(status.checkKind, 'configuration_only');
    assert.doesNotMatch(JSON.stringify(status), /SECRET/);
    const missing = await getFinflowProviderStatus(service(provider, {
      verifyProviderConnectionLite: async () => ({ configured: false }) }));
    assert.equal(missing.available, false); assert.equal(missing.configured, false);
  });
}
test('Ollama status verifies exact model listing without switching or generation', async () => {
  const status = await getFinflowProviderStatus(service('ollama'));
  assert.equal(status.available, true); assert.equal(status.ollamaVersion, '0.12.0');
  assert.equal(status.checkKind, 'model_listing');
  assert.match(status.message, /generation has not been tested/);
  for (const names of [['llama3.1:8b-instruct'], ['llama3.1:8b:other'], [], null]) {
    const missing = await getFinflowProviderStatus(service('ollama', { getOllamaAvailableModels: async () => names }));
    assert.equal(missing.available, false);
  }
});
test('only implicit latest normalization is permitted', async () => {
  for (const [model, name, expected] of [['llama3.1','llama3.1:latest',true],
    ['llama3.1:latest','llama3.1',true],['llama3.1','llama3.1:8b',false]]) {
    const status = await getFinflowProviderStatus(service('ollama', {
      getActiveProviderInfo: () => ({ provider: 'ollama', model }), getOllamaAvailableModels: async () => [name] }));
    assert.equal(status.available, expected);
  }
});
test('LM Studio reachability does not prove configured model readiness', async () => {
  const status = await getFinflowProviderStatus(service('lmstudio'));
  assert.equal(status.available, null); assert.equal(status.checkKind, 'reachability');
});
test('Bedrock missing credential hints remains unavailable despite configured model and region', async () => {
  const status = await getFinflowProviderStatus(service('bedrock', {
    getActiveProviderInfo: () => ({ provider: 'bedrock', model: 'configured-model' }),
    bedrockRegion: 'us-west-2',
    verifyProviderConnectionLite: async () => ({ configured: true, available: false,
      message: 'SECRET credential details', error: 'SECRET' }),
  }));
  assert.equal(status.configured, true);
  assert.equal(status.available, false);
  assert.equal(status.region, 'us-west-2');
  assert.equal(status.checkKind, 'configuration_only');
  assert.match(status.message, /credentials are incomplete/);
  assert.doesNotMatch(JSON.stringify(status), /SECRET/);
});
test('unknown and mock providers never look like a genuine available model', async () => {
  for (const provider of ['mock', 'unsupported-secret']) {
    const status = await getFinflowProviderStatus(service(provider, {
      verifyProviderConnectionLite: () => assert.fail('No probe needed') }));
    assert.equal(status.available, false);
    assert.doesNotMatch(JSON.stringify(status), /unsupported-secret/);
  }
});
test('unreachable local services and thrown transport failures expose no private details', async () => {
  for (const provider of ['ollama','lmstudio','openai']) {
    const status = await getFinflowProviderStatus(service(provider, {
      verifyProviderConnectionLite: async () => { throw new Error('https://user:SECRET@private.invalid'); } }));
    assert.equal(status.available, false); assert.doesNotMatch(JSON.stringify(status), /SECRET|private.invalid/);
  }
  const status = await getFinflowProviderStatus(service('ollama', {
    verifyProviderConnectionLite: async () => ({ configured: true, available: false }),
    getOllamaAvailableModels: () => assert.fail('No further probe when unreachable') }));
  assert.equal(status.available, false);
});

test('display limit does not hide the configured model from readiness inspection', async () => {
  const names = [...Array.from({ length: 256 }, (_, index) => `other-${index}:latest`), 'llama3.1:8b'];
  const status = await getFinflowProviderStatus(service('ollama', { getOllamaAvailableModels: async () => names }));
  assert.equal(status.available, true);
  assert.equal(status.availableModels.length, 256);
  assert.equal(status.model, 'llama3.1:8b');
});
