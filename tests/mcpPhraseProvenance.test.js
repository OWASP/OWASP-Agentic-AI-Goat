'use strict';

process.env.EXPORT_INTERNALS = '1';
const test = require('node:test');
const assert = require('node:assert/strict');
const aiService = require('../server/services/multiProviderAIService');
const { _internals: { phraseRecon, phraseReply } } = require('../server/services/mcp/workshopAgent');
const { withOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');
const { runMcpWorkshopGraph } = require('../server/agent-runtime/mcpWorkshopGraph');

const catalog = [{ name: 'run_command', description: 'Run an allowed command' },
  { name: 'fetch_url', description: 'Fetch a URL' }];

async function withModel(provider, generate, fn) {
  const originalProvider = aiService.provider;
  const originalGenerate = aiService.generateResponse;
  aiService.provider = provider;
  aiService.generateResponse = generate;
  try { return await fn(); }
  finally { aiService.provider = originalProvider; aiService.generateResponse = originalGenerate; }
}

test('recon phrasing passes owner cancellation and forbids provider fallback', async () => {
  const controller = new AbortController();
  await withModel('ollama', async (_prompt, options) => {
    assert.equal(options.signal, controller.signal);
    assert.equal(options.allowFallback, false);
    assert.equal(options.max_tokens, 500);
    return { response: 'run_command runs commands; fetch_url fetches URLs.', provider: 'ollama',
      model: 'controlled', mocked: false, fallback: false };
  }, async () => {
    const reply = await withOwnerExecution({ signal: controller.signal },
      () => phraseRecon(catalog, { requireRealModel: true }));
    assert.match(reply, /run_command/);
  });
  await withModel('ollama', async () => ({ response: 'run_command runs commands; fetch_url fetches URLs.',
    fallback: true }), () => assert.rejects(phraseRecon(catalog, { requireRealModel: true }),
    { code: 'MCP_RESPONSE_UNAVAILABLE' }));
  await withModel('ollama', async () => { throw Error('provider unavailable'); },
    () => assert.rejects(phraseRecon(catalog, { requireRealModel: true }), /provider unavailable/));
  await withModel('ollama', async () => {
    controller.abort(new Error('owner reset'));
    throw Error('transport closed');
  }, () => assert.rejects(withOwnerExecution({ signal: controller.signal },
    () => phraseRecon(catalog, { requireRealModel: true })), /owner reset/));
  await withModel('ollama', async () => ({ fallback: true }),
    async () => assert.match(await phraseRecon(catalog), /fetch_url/));
});

test('recon follow-up requires model while ordinary and explicit mock turns retain deterministic text', async () => {
  const toolResult = { tool: 'list_tools', output: 'run_command: Run command' };
  await withModel('ollama', async (_prompt, options) => {
    assert.equal(options.allowFallback, false);
    assert.equal(options.max_tokens, 260);
    return { response: 'offline', fallback: true };
  }, () => assert.rejects(phraseReply('What tools?', toolResult, [], { requireRealModel: true }),
    { code: 'MCP_RESPONSE_UNAVAILABLE' }));
  await withModel('ollama', async (_prompt, options) => {
    assert.equal(options.allowFallback, true);
    return { fallback: true };
  }, async () => assert.match(await phraseReply('ordinary', toolResult), /run_command/));
  await withModel('mock', async () => ({ fallback: true, mocked: true }),
    async () => assert.match(await phraseRecon(catalog), /fetch_url/));
});

test('graph marks model-selected recon phrasing as credit-bearing', async () => {
  let required = false;
  const result = await runMcpWorkshopGraph({ message: 'What can you do?',
    sandbox: { toolListTools: () => catalog } }, {
    model: { provider: 'ollama', chatWithTools: async () => ({
      content: '{"tool":"list_tools","params":{}}', provider: 'ollama', model: 'controlled' }) },
    execution: { check: async () => {}, trace: async () => {} },
    listTools: () => catalog,
    formatCatalog: () => 'catalog',
    phraseRecon: async (_catalog, options) => {
      required = options.requireRealModel;
      return 'run_command runs commands; fetch_url fetches URLs.';
    },
    detectObjectives: () => [],
  });
  assert.equal(required, true);
  assert.deepEqual(result.objectivesHit, ['mcp_recon']);
});
