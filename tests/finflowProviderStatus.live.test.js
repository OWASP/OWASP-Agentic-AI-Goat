'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { getFinflowProviderStatus } = require('../server/services/finflowProviderStatus');
const { createMultiProviderAIService } = require('../server/services/multiProviderAIService');

test('local status observes exact installed model without generation or model switching', {
  skip: process.env.RUN_LIVE_FINFLOW_STATUS !== '1', timeout: 30000,
}, async t => {
  for (const installed of [true, false]) {
    const model = installed ? 'llama3.1:8b' : `owasp-ai-goat-absent-${randomUUID()}:latest`;
    const service = createMultiProviderAIService({
      env: { AI_PROVIDER: 'ollama', OLLAMA_MODEL: model, OLLAMA_BASE_URL: 'http://127.0.0.1:11434' },
      logger: { log() {} },
      providerFactory: () => assert.fail('Status must not instantiate a generation provider'),
    });
    service.checkOllamaAvailable = () => assert.fail('Model-switching availability probe forbidden');
    service.ensureOllamaModel = () => assert.fail('Model switching forbidden');
    service.verifyProviderConnection = () => assert.fail('Deep generation probe forbidden');
    const status = await getFinflowProviderStatus(service);
    assert.equal(status.available, installed);
    assert.equal(status.checkKind, 'model_listing');
    assert.equal(service.ollamaModel, model);
    assert.equal(status.model, model);
    assert.equal(Object.hasOwn(status, 'error'), false);
    t.diagnostic(JSON.stringify({ installed, available: status.available, checkKind: status.checkKind,
      modelUnchanged: true, scope: 'read-only local metadata; no generation or database access' }));
  }
});
