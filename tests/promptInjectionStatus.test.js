const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const Module = require('node:module');
const path = require('node:path');
const { getPromptInjectionProviderStatus } = require('../server/services/promptInjectionStatusService');
const { createMultiProviderAIService } = require('../server/services/multiProviderAIService');

const silentLogger = { log() {}, warn() {}, error() {} };

async function captureLlmTelemetry(run) {
  const records = [];
  const servicePath = path.resolve(__dirname, '../server/services/multiProviderAIService.js');
  const originalLoad = Module._load;
  Module._load = function captureLogger(request, parent, isMain) {
    if (parent?.filename === servicePath && request === '../middleware/llmLogger') {
      return { logLLMCall: (record) => records.push(record) };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    await run();
    return { records, error: null };
  } catch (error) {
    return { records, error };
  } finally {
    Module._load = originalLoad;
  }
}

test('generation failure telemetry uses the active Anthropic model', async () => {
  const ai = createMultiProviderAIService({
    env: { AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'test', ANTHROPIC_MODEL: 'claude-sonnet-4' },
    logger: silentLogger,
  });
  ai.generateWithClaude = async () => { throw new Error('anthropic failed'); };
  ai.fallbackGenerate = async () => ({ response: 'fallback' });

  const { records } = await captureLlmTelemetry(() => ai.generateResponse('test prompt'));
  const failure = records.find((record) => record.success === false);
  assert.equal(failure.provider, 'anthropic');
  assert.equal(failure.model, 'claude-sonnet-4');
});

test('chat failure telemetry uses the active OpenAI model', async () => {
  const ai = createMultiProviderAIService({
    env: { AI_PROVIDER: 'openai', OPENAI_API_KEY: 'test', OPENAI_MODEL: 'gpt-4.1' },
    providerFactory: () => ({capabilities:{tools:false},chat:async()=>{throw new Error('openai failed');}}),
    logger: silentLogger,
  });

  const { records, error } = await captureLlmTelemetry(
    () => ai.chatWithMessages([{ role: 'user', content: 'hello' }]),
  );
  assert.match(error?.message || '', /openai failed/);
  const failure = records.find((record) => record.success === false);
  assert.equal(failure.provider, 'openai');
  assert.equal(failure.model, 'gpt-4.1');
});

test('Ollama failure telemetry keeps the configured Ollama model', async () => {
  const ai = createMultiProviderAIService({
    env: { AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'llama3.1:8b' },
    logger: silentLogger,
  });
  ai.generateWithOllama = async () => { throw new Error('ollama failed'); };
  ai.fallbackGenerate = async () => ({ response: 'fallback' });

  const { records } = await captureLlmTelemetry(() => ai.generateResponse('test prompt'));
  const failure = records.find((record) => record.success === false);
  assert.equal(failure.provider, 'ollama');
  assert.equal(failure.model, 'llama3.1:8b');
});

test('production provider configuration reports Ollama, OpenAI, Anthropic, and Bedrock identities', async () => {
  const httpClient = {
    get: async (url) => url.endsWith('/api/tags')
      ? { data: { models: [{ name: 'llama3.1:8b' }] } }
      : { data: { version: 'test' } },
  };
  const scenarios = [
    {
      env: { AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'llama3.1:8b' },
      expected: { provider: 'ollama', providerName: 'Ollama', model: 'llama3.1:8b', available: true },
    },
    {
      env: { AI_PROVIDER: 'openai', OPENAI_API_KEY: 'test-key', OPENAI_MODEL: 'gpt-4.1' },
      expected: { provider: 'openai', providerName: 'ChatGPT', model: 'gpt-4.1', available: true },
    },
    {
      env: { AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'test-key', ANTHROPIC_MODEL: 'claude-sonnet-4' },
      expected: { provider: 'anthropic', providerName: 'Anthropic', model: 'claude-sonnet-4', available: true },
    },
    {
      env: {
        AI_PROVIDER: 'bedrock', BEDROCK_MODEL_ID: 'anthropic.claude-sonnet', AWS_REGION: 'us-west-2',
        AWS_ACCESS_KEY_ID: 'test', AWS_SECRET_ACCESS_KEY: 'test',
      },
      expected: {
        provider: 'bedrock', providerName: 'Amazon Bedrock', model: 'anthropic.claude-sonnet', available: true,
      },
    },
  ];

  for (const { env, expected } of scenarios) {
    const ai = createMultiProviderAIService({ env, httpClient, logger: silentLogger });
    const status = await getPromptInjectionProviderStatus(ai);
    assert.equal(status.provider, expected.provider);
    assert.equal(status.providerName, expected.providerName);
    assert.equal(status.model, expected.model);
    assert.equal(status.available, expected.available);
  }
});

test('unknown production provider identity fails closed without Ollama defaults', async () => {
  const ai = createMultiProviderAIService({
    env: { AI_PROVIDER: 'future-provider', OLLAMA_MODEL: 'must-not-leak' },
    httpClient: { get: async () => { throw new Error('network must not run'); } },
    logger: silentLogger,
  });
  const status = await getPromptInjectionProviderStatus(ai);
  assert.equal(status.provider, 'future-provider');
  assert.equal(status.providerName, 'Configured AI provider');
  assert.equal(status.model, null);
  assert.equal(status.available, false);
  assert.equal(status.healthy, false);
  assert.doesNotMatch(JSON.stringify(status), /ollama|must-not-leak/i);
});

test('OpenAI status checks the configured provider and never probes Ollama', async () => {
  let checked;
  const ai = {
    getActiveProviderInfo: () => ({ provider: 'openai', providerName: 'ChatGPT', model: 'gpt-4' }),
    verifyProviderConnectionLite: async (provider) => {
      checked = provider;
      return { available: true, healthy: true, configured: true, message: 'ready', error: null };
    },
  };
  const status = await getPromptInjectionProviderStatus(ai);
  assert.equal(checked, 'openai');
  assert.equal(status.providerName, 'ChatGPT');
  assert.equal(status.available, true);
});

test('injected Anthropic and Bedrock status preserve their configured provider identity', async () => {
  for (const expected of [
    { provider: 'anthropic', providerName: 'Anthropic', model: 'claude-sonnet' },
    { provider: 'bedrock', providerName: 'Amazon Bedrock', model: 'anthropic.claude-sonnet' },
  ]) {
    let checked;
    const status = await getPromptInjectionProviderStatus({
      getActiveProviderInfo: () => expected,
      verifyProviderConnectionLite: async (provider) => {
        checked = provider;
        return { available: true, healthy: true, configured: true, message: 'ready' };
      },
    });
    assert.equal(checked, expected.provider);
    assert.equal(status.provider, expected.provider);
    assert.equal(status.providerName, expected.providerName);
    assert.equal(status.model, expected.model);
  }
});

function loadPromptInjectionRoute() {
  const routePath = path.resolve(__dirname, '../server/routes/promptInjectionWorkshop.js');
  const originalLoad = Module._load;
  Module._load = function load(request, parent, isMain) {
    if (parent?.filename === routePath) {
      if (request === '../services/promptInjectionProgressService') {
        return {
          createPromptInjectionProgressService: () => ({}),
          createDefaultPromptInjectionProgressService: () => ({}),
        };
      }
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    delete require.cache[routePath];
    return require(routePath);
  } finally {
    Module._load = originalLoad;
    delete require.cache[routePath];
  }
}

async function withServer(router, run) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    if (req.headers['x-verified-user']) { req.user = { id: Number(req.headers['x-verified-user']) }; req.identitySession = { id: 700 }; }
    if (req.headers['x-session-user']) req.session = { userId: Number(req.headers['x-session-user']) };
    next();
  });
  app.use(router);
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await run(base);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('public health and status routes expose configured provider identity without Ollama fields', async () => {
  const loaded = loadPromptInjectionRoute();
  const checked = [];
  const aiService = {
    getActiveProviderInfo: () => ({ provider: 'openai', providerName: 'ChatGPT', model: 'gpt-4.1' }),
    verifyProviderConnectionLite: async (provider) => {
      checked.push(provider);
      return { available: true, healthy: true, configured: true, message: 'OpenAI configured', error: null };
    },
    checkOllamaAvailable: () => { throw new Error('Ollama must not be probed'); },
  };
  const router = loaded.createPromptInjectionWorkshopRouter({
    aiService,
    workshopService: {},
    progressService: {},
    logger: { error() {} },
  });

  await withServer(router, async (base) => {
    for (const route of ['/health', '/llm-status']) {
      const response = await fetch(`${base}${route}`);
      assert.equal(response.status, 200);
      const body = await response.json();
      const status = route === '/health' ? body.providerStatus : body;
      assert.equal(status.provider, 'openai');
      assert.equal(status.providerName, 'ChatGPT');
      assert.equal(Object.hasOwn(status, 'ollamaBaseURL'), false);
    }
  });
  assert.deepEqual(checked, ['openai', 'openai']);
});

test('chat requires verified identity and emits provider-specific neutral errors', async () => {
  const loaded = loadPromptInjectionRoute();
  let modelCalls = 0;
  const router = loaded.createPromptInjectionWorkshopRouter({
    validateSession: async token => token === 'controlled-session' ? {user:{id:4},session:{id:700,user_id:4}} : null,
    runCoordinator: require('../server/agent-runtime/runCoordinator').createRunCoordinator({ family: 'DPI-status-fixture', ledger: null }),
    completionService: {
      async beginAttempt({ userId, workshopKey, objectiveId, execution }) {
        assert.equal(userId, 4);
        assert.equal(workshopKey, 'direct_prompt_injection');
        assert.equal(objectiveId, 'interact');
        await execution.check();
        return { runId: execution.runId };
      },
    },
    aiService: {
      getActiveProviderInfo: () => ({ provider: 'openai', providerName: 'ChatGPT', model: 'gpt-4.1' }),
      verifyProviderConnectionLite: async () => ({ available: true, healthy: true, message: 'ready' }),
    },
    workshopService: {
      chat: async () => { modelCalls += 1; throw new Error('upstream request failed'); },
    },
    progressService: { assertObjectiveEnabled: async () => true },
    logger: { error() {} },
  });

  await withServer(router, async (base) => {
    const sessionOnly = await fetch(`${base}/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-session-user': '4' },
      body: JSON.stringify({ userMessage: 'What is S3?', activeObjectiveId: 'interact' }),
    });
    assert.equal(sessionOnly.status, 401);

    const missingBearer = await fetch(`${base}/chat`, {
      method: 'POST', headers: {'content-type':'application/json','x-verified-user':'4'},
      body: JSON.stringify({userMessage:'What is S3?',activeObjectiveId:'interact'}),
    });
    assert.equal(missingBearer.status,401);
    assert.equal(modelCalls,0);

    const verified = await fetch(`${base}/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-verified-user': '4', authorization: 'Bearer controlled-session' },
      body: JSON.stringify({ userMessage: 'What is S3?', activeObjectiveId: 'interact' }),
    });
    assert.equal(verified.status, 500);
    const body = await verified.json();
    assert.equal(body.provider, 'openai');
    assert.equal(body.providerName, 'ChatGPT');
    assert.doesNotMatch(body.error, /ollama/i);
  });
  assert.equal(modelCalls, 1);
});


test('failed adapter telemetry binds attempted provider config rather than current provider', async () => {
  let selected;
  const failure = new Error('controlled failure');
  const ai = createMultiProviderAIService({
    env: {AI_PROVIDER:'ollama', OLLAMA_MODEL:'other-model', OPENAI_MODEL:'attempted-model', OPENAI_API_KEY:'private-test-key'},
    logger:silentLogger,
    providerFactory: config => { selected=config; return {capabilities:{tools:false},chat:async()=>{ai.openaiModel='changed-after-admission';throw failure;}}; },
  });
  const {records,error}=await captureLlmTelemetry(()=>ai._chatModel('openai',[{role:'user',content:'private-prompt-marker'}],[],{}));
  assert.equal(error,failure);
  assert.equal(selected.model,'attempted-model');
  assert.equal(records.length,1);
  assert.equal(records[0].provider,'openai');
  assert.equal(records[0].model,'attempted-model');
  assert.equal(JSON.stringify(records).includes('private-test-key'),false);
  assert.equal(JSON.stringify(records).includes('private-prompt-marker'),false);
});
