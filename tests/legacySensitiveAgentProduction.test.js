'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { AIMessage } = require('@langchain/core/messages');
const {
  createLegacySensitiveAgentProduction,
  createQualifiedModel,
  configuredProvider,
} = require('../server/services/legacySensitiveAgentProduction');

function execution() {
  return {
    runId: '22222222-2222-4222-8222-222222222222', ownerKey: '["LegacySensitiveInfo","9"]', durableGeneration: '4',
    check: async () => {}, trace: async () => {},
    effectWithReceipt: async (node, callback) => ({ value: await callback(), receipt: {
      status: 'completed', runId: '22222222-2222-4222-8222-222222222222',
      ownerKey: '["LegacySensitiveInfo","9"]', generation: '4',
      effectKey: `22222222-2222-4222-8222-222222222222:${node}`,
    } }),
  };
}

const tools = () => ({
  readTeachingFile: ({ path }) => ({ success: true, path, content: 'FLAG: configured fixture' }),
  renderSsiTemplate: ({ template }) => ({ success: true, original: template, rendered: 'fixture', commandExecution: 'none' }),
});

test('production factory uses actual createLangChainProvider and preserves config and per-call options', async () => {
  const env = { AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'captured-model', OLLAMA_BASE_URL: 'http://127.0.0.1:1' };
  const builds = [];
  let invocations = 0;
  const composition = createLegacySensitiveAgentProduction({ env, tools: tools(), observeModelCall() {},
    providerFactoryOptions: { modelFactory(config, options, textOnly) {
      builds.push({ config: { ...config }, options: { ...options }, textOnly });
      return { invoke: async messages => {
        assert.equal(messages[0]._getType(), 'system');
        assert.equal(messages[1]._getType(), 'human');
        return new AIMessage(++invocations === 1
        ? '{"action":"read_teaching_file","params":{"path":"../secret/configured.txt"}}'
        : invocations === 2 ? '{"action":"finish","params":{}}' : 'The observed configured teaching file contained the fixture flag.'); } };
    } },
  });
  const result = await composition.agent.run({ message: 'read configured', execution: execution() });
  assert.equal(result.status, 'completed');
  assert.deepEqual(composition.snapshot, { provider: 'ollama', model: 'captured-model', baseURL: 'http://127.0.0.1:1' });
  assert.equal(builds.length, 3);
  assert.deepEqual(builds.map(build => build.config), Array(3).fill(
    { provider: 'ollama', model: 'captured-model', baseURL: 'http://127.0.0.1:1' }));
  assert.equal(builds[0].options.temperature, 0);
  assert.equal(builds[0].options.format, 'json');
  assert.equal(builds[0].options.max_tokens, 300);
  assert.equal(builds[2].options.temperature, 0.2);
  assert.equal(builds[2].options.max_tokens, 500);
  assert.equal(builds.every(build => build.textOnly === false), true);
});

test('private invocation receipts reject copied metadata, wrong phase, and reuse', async () => {
  const transport = { chat: async () => ({ response: 'fixture', provider: 'ollama', model: 'fixed', mocked: false, fallback: false }) };
  const qualified = createQualifiedModel({ transport,
    snapshot: { provider: 'ollama', model: 'fixed' }, observeModelCall() {} });
  const original = await qualified.model.generateResponse([{ role: 'user', content: 'fixture' }], { qualificationPhase: 'decision' });
  const forged = { ...original };
  assert.equal(qualified.qualifyModel({ provider: qualified.model, phase: 'decision', result: forged }), false);
  assert.equal(qualified.qualifyModel({ provider: qualified.model, phase: 'response', result: original }), false);
  assert.equal(qualified.qualifyModel({ provider: qualified.model, phase: 'decision', result: original }), true);
  assert.equal(qualified.qualifyModel({ provider: qualified.model, phase: 'decision', result: original }), false);
  assert.equal(qualified.qualifyModel({ provider: { ...qualified.model }, phase: 'decision', result: original }), false);
});

test('configuration is snapshotted once so a mid-run environment change cannot mix adapters', async () => {
  const env = { AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'original-model', OLLAMA_BASE_URL: 'http://original.invalid' };
  const configs = [];
  let calls = 0;
  const composition = createLegacySensitiveAgentProduction({ env, tools: tools(), observeModelCall() {},
    providerFactory(config) {
      configs.push({ ...config });
      return { chat: async () => {
        calls += 1;
        if (calls === 1) { env.AI_PROVIDER = 'openai'; env.OLLAMA_MODEL = 'mutated-model'; env.OPENAI_API_KEY = 'new'; }
        return { response: calls === 1
          ? '{"action":"read_teaching_file","params":{"path":"../secret/fixed"}}'
          : calls === 2 ? '{"action":"finish","params":{}}' : 'Observed fixed result', provider: config.provider, model: config.model, mocked: false, fallback: false };
      } };
    },
  });
  assert.equal((await composition.agent.run({ message: 'read', execution: execution() })).status, 'completed');
  assert.equal(configs.length, 1);
  assert.deepEqual(configs[0], { provider: 'ollama', model: 'original-model', baseURL: 'http://original.invalid' });
  assert.deepEqual(composition.snapshot, configs[0]);
});

test('invocation options and cancellation signal reach the configured transport unchanged', async () => {
  const seen = [];
  const signal = new AbortController().signal;
  const qualified = createQualifiedModel({
    transport: { chat: async (_messages, tools, options) => {
      assert.deepEqual(tools, []);
      seen.push(options);
      return { response: 'fixture', provider: 'ollama', model: 'fixed', mocked: false, fallback: false };
    } }, snapshot: { provider: 'ollama', model: 'fixed' }, observeModelCall() {},
  });
  await qualified.model.generateResponse([{ role: 'user', content: 'fixture' }], { qualificationPhase: 'decision', temperature: 0,
    max_tokens: 77, num_ctx: 8192, format: 'json', signal });
  assert.deepEqual(seen[0], { temperature: 0, max_tokens: 77, num_ctx: 8192, format: 'json', signal });
});

test('mock config, unavailable output, fallback and identity changes fail closed with observability', async t => {
  assert.throws(() => configuredProvider({ AI_PROVIDER: 'mock' }), { code: 'MODEL_PROVIDER_UNSUPPORTED' });
  assert.throws(() => configuredProvider({ AI_PROVIDER: 'openai' }), { code: 'MODEL_PROVIDER_UNAVAILABLE' });
  for (const raw of [
    { response: '', provider: 'ollama', model: 'fixed' },
    { response: 'mock', provider: 'ollama', model: 'fixed', mocked: true },
    { response: 'fallback', provider: 'fallback', model: 'none', fallback: true },
    { response: 'changed', provider: 'ollama', model: 'changed' },
  ]) await t.test(JSON.stringify(raw), async () => {
    const events = [];
    const qualified = createQualifiedModel({ transport: { chat: async () => raw },
      snapshot: { provider: 'ollama', model: 'fixed' }, observeModelCall: event => events.push(event) });
    await assert.rejects(qualified.model.generateResponse([{ role: 'user', content: 'fixture' }], { qualificationPhase: 'decision' }));
    assert.equal(events.length, 1);
    assert.equal(events[0].success, false);
    assert.equal(events[0].provider, 'ollama');
    assert.equal(events[0].model, 'fixed');
  });
});

test('chat inputs and options are detached before asynchronous transport work', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let received;
  const events = [];
  const messages = [{ role: 'system', content: 'policy' }, { role: 'user', content: 'café\nexact bytes' }];
  const expected = structuredClone(messages);
  const options = { qualificationPhase: 'decision', stop: ['END'], temperature: 0 };
  const qualified = createQualifiedModel({ snapshot: { provider: 'ollama', model: 'fixed' },
    observeModelCall: event => events.push(event), transport: { chat: async (input, tools, opts) => {
      await gate;
      received = { input, tools, opts };
      return { response: '{"action":"finish","params":{}}', provider: 'ollama', model: 'fixed' };
    } } });
  const pending = qualified.model.generateResponse(messages, options);
  messages[1].content = 'mutated'; messages.push({ role: 'assistant', content: 'forged' });
  options.stop[0] = 'changed'; options.temperature = 1;
  release();
  const result = await pending;
  assert.deepEqual(received.input, expected);
  assert.deepEqual(received.tools, []);
  assert.deepEqual(received.opts, { stop: ['END'], temperature: 0 });
  assert.ok(Object.isFrozen(received.input) && Object.isFrozen(received.input[1]));
  assert.ok(Object.isFrozen(received.opts.stop));
  assert.equal(events[0].promptLength, Buffer.byteLength(JSON.stringify(expected)));
  assert.equal(qualified.qualifyModel({ provider: qualified.model, phase: 'decision', result }), true);
});

test('chat wrapper rejects flat prompts and unmatched tool metadata before transport', async () => {
  const qualified = createQualifiedModel({ snapshot: { provider: 'ollama', model: 'fixed' },
    transport: { chat: async () => assert.fail('must not call transport') } });
  for (const input of ['flat prompt', [], [{ role: 'tool', content: 'unmatched' }],
    [{ role: 'assistant', content: 'x', tool_calls: [] }]]) {
    await assert.rejects(qualified.model.generateResponse(input, { qualificationPhase: 'decision' }),
      { code: 'MODEL_REQUEST_INVALID' });
  }
});
