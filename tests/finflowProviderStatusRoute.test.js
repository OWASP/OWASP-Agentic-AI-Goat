'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
function loadControlledRouter() {
  const load = Module._load;
  const stubs = {
    '../database/sensitiveInfoWorkshopDb': { engine: 'postgres' },
    '../services/sensitiveInfoWorkshopAgent': { SensitiveInfoWorkshopAgent: class {}, OBJECTIVES: [],
      createSensitiveInfoWorkshopStateStore: () => ({}), getConfiguredSsrfExamples: () => ({}) },
    '../middleware/adminAuth': { authenticateToken: (_req, _res, next) => next() },
    '../services/workshopModeService': {},
    '../services/workshopModeHandlers': { createWorkshopModeHandlers: () => ({ get() {}, set() {} }) },
    '../services/sensitiveInfoResetComposition': { createConfiguredFinflowTraversalManager: () => ({}) },
    '../services/finflowAgentResourceComposition': { configuredFinflowAgentResources: () => ({}) },
    '../utils/contextLogger': {},
    '../utils/progressSync': {},
  };
  Module._load = function(request, parent, main) {
    return Object.hasOwn(stubs, request) ? stubs[request] : load.call(this, request, parent, main);
  };
  try {
    const routePath = require.resolve('../server/routes/sensitiveInfoWorkshop');
    delete require.cache[routePath];
    return require(routePath);
  } finally { Module._load = load; }
}
const router = loadControlledRouter();
const handler = router.stack.find(layer => layer.route?.path === '/llm-status').route.stack[0].handle;

async function readStatus(service) {
  const load = Module._load;
  let result;
  Module._load = function(name, parent, main) {
    return name === '../services/multiProviderAIService' ? service : load.call(this, name, parent, main);
  };
  try { await handler({}, { json(value) { result = value; } }); }
  finally { Module._load = load; }
  return result;
}

test('registered public cloud status handler never generates or claims verified readiness', async () => {
  for (const provider of ['bedrock', 'openai', 'anthropic']) {
    let checks = 0;
    const result = await readStatus({
      getActiveProviderInfo: () => ({ provider, model: 'configured-model' }),
      verifyProviderConnection: () => assert.fail('Public status must not generate'),
      verifyProviderConnectionLite: async selected => {
        checks++; assert.equal(selected, provider);
        return { available: true, configured: true, message: 'SECRET raw provider detail' };
      },
    });
    assert.equal(checks, 1);
    assert.equal(result.available, null);
    assert.equal(result.checkKind, 'configuration_only');
    assert.doesNotMatch(JSON.stringify(result), /SECRET/);
  }
});

test('registered local status handler preserves selected model and rejects another installed variant', async () => {
  const service = {
    model: 'llama3.1:8b',
    getActiveProviderInfo() { return { provider: 'ollama', model: this.model }; },
    verifyProviderConnectionLite: async () => ({ configured: true, available: true }),
    getOllamaAvailableModels: async () => ['llama3.1:8b-instruct'],
    checkOllamaAvailable: () => assert.fail('Model-switching probe must not run'),
    verifyProviderConnection: () => assert.fail('Public status must not generate'),
  };
  const result = await readStatus(service);
  assert.equal(result.available, false);
  assert.equal(result.model, 'llama3.1:8b');
  assert.equal(service.model, 'llama3.1:8b');
});
