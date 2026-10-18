'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { AIMessage } = require('@langchain/core/messages');
const { WORKFLOW_ROUTE_SCHEMA, parseWorkflowRoute } = require('../server/agent-runtime/providers/workflowRouteContract');
const { OllamaProvider } = require('../server/services/secureshop/providers/ollamaProvider');
const { LangChainAdapter } = require('../server/services/secureshop/providers/langchainAdapter');
const { ProviderRouter } = require('../server/services/secureshop/providerRouter');
const { MockProvider } = require('../server/services/secureshop/providers/mockProvider');
const input = { system: 'Choose management or registered_tools; clarify ambiguity.',
  messages: [{ role: 'user', content: '{"message":"Use the registered catalog"}' }],
  role: 'admin', max_tokens: 256, ownerId: 17 };

test('Ollama routing uses the real adapter HTTP path with the exact schema and no tool catalog', async t => {
  const requests = [];
  const server = require('node:http').createServer((req, res) => {
    let body = ''; req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      requests.push({ path: req.url, body: JSON.parse(body) });
      res.writeHead(200, { 'content-type': 'application/x-ndjson' });
      res.end(JSON.stringify({ model: 'controlled-model', message: { role: 'assistant',
        content: '{"route":"registered_tools"}' }, done: true, prompt_eval_count: 7, eval_count: 3 }) + '\n');
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const provider = new OllamaProvider({ model: 'controlled-model',
    baseUrl: `http://127.0.0.1:${server.address().port}` });
  const result = await provider.routeWorkflow(input);
  assert.equal(requests.length, 1); assert.equal(requests[0].path, '/api/chat');
  assert.deepEqual(requests[0].body.format, WORKFLOW_ROUTE_SCHEMA);
  assert.equal(requests[0].body.tools?.length || 0, 0);
  assert.equal(requests[0].body.options.num_predict, 256);
  assert.equal(requests[0].body.messages[1].content, input.messages[0].content);
  assert.deepEqual(result.decision, { route: 'registered_tools' });
  assert.deepEqual(result.usage, { inputTokens: 7, outputTokens: 3, totalTokens: 10, attempts: 1 });
});

test('route parser accepts only closed routes or bounded clarification; no aliases or tool output', () => {
  for (const route of ['management', 'registered_tools']) assert.deepEqual(parseWorkflowRoute({ route }), { route });
  assert.deepEqual(parseWorkflowRoute({ route: 'clarification', message: 'Which workflow?' }),
    { route: 'clarification', message: 'Which workflow?' });
  for (const bad of [null, [], { route: 'admin_management' }, { route: 'management', message: 'extra' },
    { route: 'clarification' }, { route: 'clarification', message: ' ' },
    { route: 'clarification', message: '\u0000' }, { route: 'clarification', message: '😀'.repeat(513) },
    { route: 'registered_tools', tool_calls: [] }, { reply: 'registered_tools' }]) {
    assert.equal(parseWorkflowRoute(bad), null);
  }
});

for (const decision of [{ route: 'management' }, { route: 'registered_tools' },
  { route: 'clarification', message: 'Do you mean accounts or registered tools?' }]) {
  test(`Ollama route ${decision.route} makes one explicit schema call with usage`, async () => {
    const provider = new OllamaProvider({ model: 'controlled-model' }); let calls = 0;
    provider.transport = { async chat(messages, tools, options) {
      calls++; assert.equal(messages[1].content, input.messages[0].content);
      assert.deepEqual(tools, []); assert.deepEqual(options.format, WORKFLOW_ROUTE_SCHEMA);
      assert.equal(options.num_predict, 256); assert.equal(options.temperature, 0);
      return { response: JSON.stringify(decision), metadata: { prompt_eval_count: 9, eval_count: 4 } };
    } };
    const result = await provider.routeWorkflow(input);
    assert.equal(calls, 1); assert.deepEqual(result.decision, decision);
    assert.equal(result.responseMode, 'decision_routing_v1');
    assert.equal(result.provider, 'ollama'); assert.equal(result.model, 'controlled-model');
    assert.deepEqual(result.usage, { inputTokens: 9, outputTokens: 4, totalTokens: 13, attempts: 1 });
  });
}

test('invalid Ollama route is not repaired or converted, and retains consumed usage', async () => {
  const provider = new OllamaProvider(); let calls = 0;
  provider.transport = { async chat() { calls++; return { response: '{"tool_calls":[]}',
    metadata: { prompt_eval_count: 8, eval_count: 3 } }; } };
  await assert.rejects(provider.routeWorkflow(input), error => error.code === 'SECURESHOP_INVALID_DECISION'
    && error.usage.outputTokens === 3 && error.usage.attempts === 1);
  assert.equal(calls, 1);
});

test('late Ollama route cancellation never publishes a decision and retains usage', async () => {
  const provider = new OllamaProvider(), controller = new AbortController();
  provider.transport = { async chat() { controller.abort(new Error('authority ended'));
    return { response: '{"route":"registered_tools"}', metadata: { eval_count: 3 } }; } };
  await assert.rejects(provider.routeWorkflow({ ...input, signal: controller.signal }),
    error => error.message === 'authority ended' && error.usage.outputTokens === 3);
});

for (const providerName of ['openai', 'anthropic', 'bedrock']) {
  test(`${providerName} uses one native structured routing invocation, with original message and usage`, async () => {
    let count = 0;
    const adapter = new LangChainAdapter({ provider: providerName, model: 'controlled-model' }, {
      modelFactory(config, options) {
        assert.equal(options.max_tokens, 256); assert.equal(options.temperature, 0);
        return { withStructuredOutput(schema, settings) {
          assert.equal(schema.type, 'object'); assert.deepEqual(schema.required, ['decision']);
          assert.deepEqual(schema.properties.decision.anyOf, WORKFLOW_ROUTE_SCHEMA.oneOf);
          assert.equal(settings.method, providerName === 'bedrock' ? 'functionCalling' : 'jsonSchema');
          return { async invoke(messages) { count++;
            assert.equal(messages[1].content, input.messages[0].content);
            return { parsed: { decision: { route: 'registered_tools' } },
              raw: new AIMessage({ content: '', usage_metadata: { input_tokens: 5, output_tokens: 2, total_tokens: 7 } }) };
          } };
        } };
      },
    });
    const result = await adapter.routeWorkflow(input);
    assert.equal(count, 1); assert.deepEqual(result.decision, { route: 'registered_tools' });
    assert.equal(result.provider, providerName); assert.equal(result.mocked, false);
    assert.deepEqual(result.usage, { inputTokens: 5, outputTokens: 2, totalTokens: 7, attempts: 1 });
  });
}

test('hosted unsupported SDK and malformed typed output fail without ordinary chat', async () => {
  let calls = 0;
  const unsupported = new LangChainAdapter({ provider: 'openai', model: 'test' }, {
    modelFactory: () => ({ invoke() { throw Error('ordinary chat forbidden'); } }),
  });
  await assert.rejects(unsupported.routeWorkflow(input), { code: 'SECURESHOP_ROUTE_UNSUPPORTED' });
  const malformed = new LangChainAdapter({ provider: 'anthropic', model: 'test' }, {
    modelFactory: () => ({ withStructuredOutput() { return { async invoke() { calls++;
      return { parsed: { decision: { route: 'management' }, extra: true }, raw: {} }; } }; } }),
  });
  await assert.rejects(malformed.routeWorkflow(input), { code: 'SECURESHOP_INVALID_DECISION' });
  assert.equal(calls, 1);
});

test('hosted routing cancellation rejects a late SDK response without a route', async () => {
  const controller = new AbortController(); let release, entered;
  const started = new Promise(resolve => { entered = resolve; });
  const adapter = new LangChainAdapter({ provider: 'openai', model: 'test' }, {
    modelFactory: () => ({ withStructuredOutput() { return { invoke() {
      entered(); return new Promise(resolve => { release = resolve; });
    } }; } }),
  });
  const pending = adapter.routeWorkflow({ ...input, signal: controller.signal });
  await started; controller.abort(new Error('session revoked'));
  release({ parsed: { decision: { route: 'registered_tools' } }, raw: {} });
  await assert.rejects(pending, /session revoked/);
});

test('routing never treats missing provider counters as zero or performs an extra call', async () => {
  const provider = new OllamaProvider(); let calls = 0;
  provider.transport = { async chat() { calls++; return { response: '{"route":"management"}' }; } };
  const result = await provider.routeWorkflow(input);
  assert.deepEqual(result.usage, { inputTokens: null, outputTokens: null, totalTokens: null, attempts: 1 });
  const controller = new AbortController(); controller.abort();
  await assert.rejects(provider.routeWorkflow({ ...input, signal: controller.signal }));
  assert.equal(calls, 1);
});

test('router rejects a tool-bearing route response instead of dispatching it', async () => {
  const router = new ProviderRouter({ mock: { capabilities: { decisionRoutingV1: true },
    async isReachable() { return true; }, async routeWorkflow() { return {
      responseMode: 'decision_routing_v1', decision: { route: 'management' },
      tool_uses: [{ name: 'admin.users_search', args: {} }],
    }; },
  } });
  await assert.rejects(router.routeWorkflow(input), { code: 'SECURESHOP_INVALID_DECISION' });
});

test('router attributes selected routing provider and never falls through after failure', async () => {
  const previous = process.env.AI_PROVIDER; delete process.env.AI_PROVIDER;
  try {
    let fallback = 0;
    const primary = { model: 'actual', capabilities: { decisionRoutingV1: true },
      async isReachable() { return true; }, async routeWorkflow() { return {
        responseMode: 'decision_routing_v1', decision: { route: 'management' },
        provider: 'forged', model: 'forged', usage: { outputTokens: 2, attempts: 1 },
      }; } };
    const router = new ProviderRouter({ ollama: primary, mock: {
      async isReachable() { fallback++; return true; },
    } });
    const result = await router.routeWorkflow(input);
    assert.equal(result.provider, 'ollama'); assert.equal(result.model, 'actual'); assert.equal(result.mocked, false);
    primary.routeWorkflow = async () => { throw Object.assign(Error('invalid'), { code: 'SECURESHOP_INVALID_DECISION' }); };
    await assert.rejects(router.routeWorkflow(input), error => error.code === 'SECURESHOP_INVALID_DECISION'
      && error.provider === 'ollama' && error.model === 'actual' && error.mocked === false);
    primary.capabilities = {};
    await assert.rejects(router.routeWorkflow(input), { code: 'SECURESHOP_ROUTE_UNSUPPORTED',
      provider: 'ollama', model: 'actual', mocked: false });
    primary.capabilities = { decisionRoutingV1: true };
    const usage = { inputTokens: 7, outputTokens: 3, totalTokens: 10, attempts: 1 };
    primary.routeWorkflow = async () => ({ responseMode: 'decision_routing_v1',
      decision: { route: 'invalid' }, provider: 'forged', model: 'forged', usage });
    await assert.rejects(router.routeWorkflow(input), { code: 'SECURESHOP_INVALID_DECISION',
      provider: 'ollama', model: 'actual', mocked: false, usage });
    const controller = new AbortController();
    const reason = new Error('Authority ended');
    primary.routeWorkflow = async () => { controller.abort(reason); return { usage }; };
    await assert.rejects(router.routeWorkflow({ ...input, signal: controller.signal }), error => {
      assert.equal(error, reason);
      assert.equal(error.provider, 'ollama'); assert.equal(error.model, 'actual');
      assert.equal(error.mocked, false); assert.deepEqual(error.usage, usage);
      return true;
    });
    assert.equal(fallback, 0);
  } finally { if (previous === undefined) delete process.env.AI_PROVIDER; else process.env.AI_PROVIDER = previous; }
});

test('mock routing requires an explicit scripted route and remains labelled mocked', async () => {
  const provider = new MockProvider(); provider.script([{ stop: 'route', decision: { route: 'registered_tools' } }]);
  const result = await provider.routeWorkflow(input);
  assert.equal(result.mocked, true); assert.deepEqual(result.decision, { route: 'registered_tools' });
  await assert.rejects(provider.routeWorkflow(input), { code: 'SECURESHOP_INVALID_DECISION' });
  provider.script([{ stop: 'route', decision: { route: 'management' } }]);
  const routed = await new ProviderRouter({ mock: provider }).routeWorkflow(input);
  assert.equal(routed.provider, 'mock'); assert.equal(routed.model, 'mock'); assert.equal(routed.mocked, true);
});
