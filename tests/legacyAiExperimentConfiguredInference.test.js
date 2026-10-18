'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createLegacyAiExperimentConfiguredInference } = require('../server/services/legacyAiExperimentConfiguredInference');
function fixture(initial = {}) {
  let env = initial; const created = []; const calls = []; const clients = [];
  const infer = createLegacyAiExperimentConfiguredInference({ getEnvironment: () => env,
    createProduction: config => { created.push(config); return { run: async (input, execution) => {
      calls.push({ input, execution, config }); return { response: 'actual adapter result' };
    } }; }, createBedrockClient: options => { clients.push(options); return { send() {} }; } });
  return { infer, created, calls, clients, reload: value => { env = value; } };
}

test('defaults bind real Ollama actor and Judge and forward execution unchanged', async () => {
  const f = fixture(); const input = { sourceRoute: 'prompt_injection', prompt: 'test' };
  const execution = Object.freeze({ ownerId: 7, signal: new AbortController().signal, check: async () => {} });
  assert.deepEqual(await f.infer(input, execution), { response: 'actual adapter result' });
  assert.deepEqual(f.created[0], { inferenceConfig: { provider: 'ollama', model: 'llama3.1:8b', baseURL: 'http://localhost:11434' },
    judgeConfig: { provider: 'ollama', model: 'llama3.1:8b', baseURL: 'http://localhost:11434' },
    inferenceTimeoutMs: 90000, judgeTimeoutMs: 60000, totalTimeoutMs: 150000,
    inferenceContextTokens: 32768, judgeContextTokens: 32768 });
  assert.equal(f.calls[0].input, input); assert.equal(f.calls[0].execution, execution);
});

test('actor and Judge configure independently with aliases and vendor defaults', async () => {
  const f = fixture({ AI_PROVIDER: 'chatgpt', OPENAI_MODEL: 'actor', OPENAI_API_KEY: 'private-a',
    JUDGE_PROVIDER: 'claude', JUDGE_MODEL: 'judge', ANTHROPIC_API_KEY: 'private-b' });
  await f.infer({}, {});
  assert.deepEqual(f.created[0].inferenceConfig, { provider: 'openai', model: 'actor', apiKey: 'private-a', baseURL: 'https://api.openai.com/v1' });
  assert.deepEqual(f.created[0].judgeConfig, { provider: 'anthropic', model: 'judge', apiKey: 'private-b', baseURL: 'https://api.anthropic.com' });
});

test('operator reload replaces current instance and caller overrides never select configuration', async () => {
  const f = fixture({ OLLAMA_MODEL: 'first' });
  const input = { model: 'caller', apiKey: 'caller', options: { model: 'caller', provider: 'mock' } };
  await f.infer(input, {}); await f.infer(input, {});
  assert.equal(f.created.length, 1);
  f.reload({ OLLAMA_MODEL: 'second', JUDGE_MODEL: 'judge-2', OLLAMA_BASE_URL: 'http://localhost:11435' });
  await f.infer(input, {});
  assert.equal(f.created.length, 2);
  assert.equal(f.created[1].inferenceConfig.model, 'second');
  assert.equal(f.created[1].judgeConfig.model, 'judge-2');
  f.reload({ OLLAMA_MODEL: 'first' }); await f.infer(input, {});
  assert.equal(f.created.length, 3, 'cache retains only the current configuration');
});

test('missing/unsupported configuration rejects without fallback or credential disclosure', async () => {
  for (const env of [{ AI_PROVIDER: 'mock' }, { JUDGE_PROVIDER: 'mock' },
    { AI_PROVIDER: 'openai', OPENAI_API_KEY: 'private-secret' },
    { JUDGE_PROVIDER: 'anthropic', JUDGE_MODEL: 'judge' },
    { AI_PROVIDER: 'bedrock', BEDROCK_MODEL_ID: 'model' },
    { OLLAMA_BASE_URL: 'http://secret:private-secret@localhost:11434' }]) {
    const f = fixture(env);
    await assert.rejects(f.infer({}, {}), error => error.code === 'LEGACY_AI_EXPERIMENT_CONFIGURATION_UNAVAILABLE'
      && !error.message.includes('private-secret'));
    assert.equal(f.created.length, 0);
  }
});

test('Bedrock client is lazy and LMStudio supports operator endpoint selection', async () => {
  const f = fixture({ AI_PROVIDER: 'lmstudio', LMSTUDIO_MODEL: 'local', LMSTUDIO_BASE_URL: 'http://localhost:1235/v1' });
  await f.infer({}, {}); assert.equal(f.clients.length, 0);
  assert.equal(f.created[0].inferenceConfig.baseURL, 'http://localhost:1235/v1');
  f.reload({ AI_PROVIDER: 'bedrock', BEDROCK_MODEL_ID: 'bedrock-model', AWS_REGION: 'us-west-2' });
  await f.infer({}, {}); await f.infer({}, {});
  assert.deepEqual(f.clients, [{ region: 'us-west-2' }]);
  assert.equal(typeof f.created[1].inferenceConfig.client.send, 'function');
  assert.equal(f.created[1].judgeConfig.provider, 'ollama');
});

test('factory errors are sanitized while model execution failures propagate without fallback', async () => {
  const infer = createLegacyAiExperimentConfiguredInference({ getEnvironment: () => ({}), createProduction() { throw Error('private credential'); } });
  await assert.rejects(infer({}, {}), error => !error.message.includes('private credential'));
  let calls = 0;
  const run = createLegacyAiExperimentConfiguredInference({ getEnvironment: () => ({}), createProduction: () => ({ run: async () => {
    calls++; throw Object.assign(new Error('model unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
  } }) });
  await assert.rejects(run({}, {}), error => error.code === 'PROVIDER_UNAVAILABLE');
  assert.equal(calls, 1);
});
