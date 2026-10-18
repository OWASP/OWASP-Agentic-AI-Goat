'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { AIMessage } = require('@langchain/core/messages');
const { createLangChainProvider, messagesForLangChain } = require('../server/agent-runtime/providers/langchainProvider');
test('provider inherits the protected owner cancellation signal when a caller omits it', async () => {
  const { withOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');
  const controller = new AbortController(); let entered;
  const started = new Promise(resolve => { entered = resolve; });
  const provider = createLangChainProvider({ provider: 'ollama', model: 'fixture' }, { modelFactory: () => ({
    invoke: (_input, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason), { once: true }); entered();
    }),
  }) });
  const pending = withOwnerExecution({ signal: controller.signal }, () => provider.generate('fixture'));
  await started; controller.abort(new Error('OWNER_RESET'));
  await assert.rejects(pending, /OWNER_RESET/);
});
for (const provider of ['ollama', 'openai', 'anthropic', 'bedrock']) {
  test(`${provider} adapter preserves native tools, payload bytes, usage and zero temperature`, async () => {
    let captured;
    const adapter = createLangChainProvider({ provider, model: 'test' }, { modelFactory(config, options) {
      assert.equal(options.temperature, 0);
      return { bindTools(tools) { assert.equal(tools[0].function.name, 'read'); return this; }, async invoke(messages) {
        captured = messages;
        return new AIMessage({ content: '', tool_calls: [{ id: 'call1', name: 'read', args: { path: '../../secret' } }],
          usage_metadata: { output_tokens: 3, input_tokens: 1, total_tokens: 4 } });
      } };
    } });
    const result = await adapter.chat([{ role: 'user', content: "' OR 1=1 --" }],
      [{ type: 'function', function: { name: 'read', parameters: { type: 'object' } } }], { temperature: 0 });
    assert.equal(captured[0].content, "' OR 1=1 --");
    assert.equal(result.tokens, 3); assert.deepEqual(result.tool_calls[0].function.arguments, { path: '../../secret' });
  });
}
for (const provider of ['ollama', 'openai', 'anthropic', 'bedrock']) {
  test(`${provider} structured final response uses its verified SDK method and retains usage`, async () => {
    let captured;
    const adapter = createLangChainProvider({ provider, model: 'test' }, { modelFactory(config, options) {
      assert.equal(config.provider, provider);
      return { withStructuredOutput(schema, structuredOptions) {
        captured = { schema, structuredOptions, signal: options.signal };
        return { async invoke(messages, invocation) {
          captured.messages = messages; captured.invocation = invocation;
          return { parsed: { answer: `answer from ${provider}` }, raw: new AIMessage({ content: '',
            usage_metadata: { input_tokens: 5, output_tokens: 7, total_tokens: 12 } }) };
        } };
      } };
    } });
    const result = await adapter.finalResponse([{ role: 'user', content: 'answer now' }], {
      max_tokens: 33, ownerId: 'owner-final', temperature: 0,
    });
    assert.equal(result.response, `answer from ${provider}`);
    assert.deepEqual(result.usage, { inputTokens: 5, outputTokens: 7, totalTokens: 12, attempts: 1 });
    assert.equal(captured.schema.additionalProperties, false);
    assert.deepEqual(captured.schema.required, ['answer']);
    assert.equal(captured.structuredOptions.method, provider === 'bedrock' ? 'functionCalling' : 'jsonSchema');
    assert.equal(captured.structuredOptions.strict, provider === 'openai' ? true : undefined);
    assert.equal(captured.structuredOptions.includeRaw, true);
    assert.equal(captured.messages[0].content, 'answer now');
    assert.equal(captured.invocation.signal, captured.signal);
  });
}
test('structured final response rejects unsupported SDKs and malformed parsed output', async () => {
  const unsupported = createLangChainProvider({ provider: 'openai', model: 'test' }, {
    modelFactory: () => ({ invoke: async () => new AIMessage('ordinary text') }),
  });
  await assert.rejects(unsupported.finalResponse([{ role: 'user', content: 'answer' }]),
    { code: 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED' });
  const malformed = createLangChainProvider({ provider: 'anthropic', model: 'test' }, {
    modelFactory: () => ({ withStructuredOutput() { return { async invoke() {
      return { parsed: { tool_calls: [{ name: 'read' }] }, raw: new AIMessage('') };
    } }; } }),
  });
  await assert.rejects(malformed.finalResponse([{ role: 'user', content: 'answer' }]),
    { code: 'SECURESHOP_INVALID_DECISION' });
});
test('structured final response honors protected cancellation without falling back', async () => {
  const controller = new AbortController();
  let entered;
  const started = new Promise(resolve => { entered = resolve; });
  const provider = createLangChainProvider({ provider: 'openai', model: 'test' }, {
    modelFactory: () => ({ withStructuredOutput() { return {
      invoke: (_messages, { signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        entered();
      }),
    }; } }),
  });
  const pending = provider.finalResponse([{ role: 'user', content: 'answer' }], {
    signal: controller.signal,
  });
  await started;
  controller.abort(new Error('OWNER_RESET'));
  await assert.rejects(pending, /OWNER_RESET/);
});
test('legacy tool result messages acquire the matching ordered call IDs', () => {
  const messages = messagesForLangChain([
    { role: 'assistant', content: '', tool_calls: [{ function: { name: 'one', arguments: '{}' } }, { function: { name: 'two', arguments: {} } }] },
    { role: 'tool', content: 'raw <script>one</script>' }, { role: 'tool', content: 'second' },
  ]);
  assert.equal(messages[1].tool_call_id, messages[0].tool_calls[0].id);
  assert.equal(messages[2].tool_call_id, messages[0].tool_calls[1].id);
  assert.equal(messages[1].content, 'raw <script>one</script>');
  assert.throws(() => messagesForLangChain([{ role: 'tool', content: 'orphan' }]), /matching/);
});
test('empty/error results reject instead of blank success; deadline bounds waiting', async () => {
  const empty = createLangChainProvider({ provider: 'openai' }, { modelFactory: () => ({ invoke: async () => new AIMessage('') }) });
  await assert.rejects(empty.generate('hi'), /empty response/);
  const hung = createLangChainProvider({ provider: 'openai' }, { modelFactory: () => ({ invoke: () => new Promise(() => {}) }) });
  const keepAlive = setTimeout(() => {}, 100);
  try { await assert.rejects(hung.generate('hi', { timeout: 10 }), { name: 'TimeoutError' }); }
  finally { clearTimeout(keepAlive); }
});
test('public provider services use injected LangChain facade and preserve DTO/fallback', async () => {
  const calls = [];
  const providerFactory = config => ({ capabilities: { tools: true },
    async generate(prompt, options) { calls.push([config.provider, options.temperature]); return { response: 'ok', model: config.model, provider: config.provider, tokens: 4, metadata: { response: undefined } }; },
    async chat() { return { response: '', tool_calls: [{ function: { name: 'read', arguments: {} } }] }; },
  });
  const { createMultiProviderAIService } = require('../server/services/multiProviderAIService');
  const service = createMultiProviderAIService({ env: { AI_PROVIDER: 'openai', OPENAI_API_KEY: 'test' }, providerFactory });
  assert.equal((await service.generateWithChatGPT('hi', 0, 10)).response, 'ok');
  assert.equal((await service.chatWithTools([{ role: 'user', content: 'hi' }], [])).tool_calls[0].function.name, 'read');
  const { OllamaService } = require('../server/services/ollamaService');
  const ollama = new OllamaService('http://unused', { providerFactory });
  assert.equal((await ollama.generateResponse('hi', { temperature: 0 })).success, true);
  assert.equal((await ollama.chatWithTools([], [])).tool_calls[0].function.name, 'read');
  assert.deepEqual(calls.map(call => call[1]), [0, 0]);
  const format={type:'object',properties:{action:{type:'string'}},required:['action'],additionalProperties:false};let forwarded;
  ollama.providerFactory=()=>({chat:async(messages,tools,options)=>{forwarded=options;return{response:'{}'};}});
  await ollama.chatWithTools([],[],{format,temperature:0});assert.deepEqual(forwarded.format,format);assert.equal(forwarded.temperature,0);
  await ollama.chatWithTools([],[],{format:[]});assert.equal(forwarded.format,undefined);
  ollama.providerFactory = () => ({ generate: async () => { throw new Error('offline'); } });
  assert.equal((await ollama.generateResponse('hi')).fallback, true);
});

test('multi-provider text generation forwards a closed output schema to the actual adapter', async () => {
  const format = { type: 'object', properties: { verdict: { type: 'string', enum: ['SAFE', 'LEAKED'] } },
    required: ['verdict'], additionalProperties: false };
  let captured;
  const { createMultiProviderAIService } = require('../server/services/multiProviderAIService');
  const service = createMultiProviderAIService({ env: { AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'fixture' },
    logger: { log() {} }, providerFactory: () => ({
      async generate(_prompt, options) {
        captured = options;
        return { response: '{"verdict":"SAFE"}', provider: 'ollama', model: 'fixture', mocked: false, fallback: false };
      },
    }) });
  await service.generateResponse('review', { temperature: 0, max_tokens: 64, num_predict: 64, format, timeout: 15000 });
  assert.deepEqual(captured.format, format);
  assert.equal(captured.temperature, 0);
  assert.equal(captured.max_tokens, 64);
  assert.equal(captured.num_predict, 64);
  assert.equal(captured.timeout, 15000);
});

test('real OpenAI/Anthropic/Bedrock LangChain classes consume injected local transports', async () => {
  const http = require('node:http');
  const requests = [];
  const server = http.createServer(async (req, res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    requests.push(JSON.parse(body)); res.setHeader('Content-Type', 'application/json');
    if (req.url.includes('messages')) res.end(JSON.stringify({ id: 'msg_1', type: 'message', role: 'assistant', model: 'test',
      content: [{ type: 'text', text: 'anthropic local' }], stop_reason: 'end_turn', usage: { input_tokens: 1, output_tokens: 2 } }));
    else res.end(JSON.stringify({ id: 'chat1', object: 'chat.completion', created: 1, model: 'test',
      choices: [{ index: 0, message: { role: 'assistant', content: 'openai local' }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 } }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const baseURL = `http://127.0.0.1:${server.address().port}/v1`;
  try {
    for (const provider of ['openai', 'anthropic']) {
      const result = await createLangChainProvider({ provider, model: 'test', baseURL, apiKey: 'local-test' }).generate('hi', { temperature: 0 });
      assert.equal(result.response, `${provider} local`); assert.equal(result.tokens, 2);
      assert.equal(result.mocked,false);assert.equal(result.fallback,false);
      assert.equal(require('../server/agent-runtime/ctfGuardianResult').requireCtfGuardianResult(result).provider,provider);
    }
    assert.equal(requests.every(request => request.temperature === 0), true);
  } finally { await new Promise(resolve => server.close(resolve)); }
  const bedrock = createLangChainProvider({ provider: 'bedrock', model: 'test', region: 'us-west-2', client: {
    async send(command) {
      assert.equal(command.input.inferenceConfig.temperature, 0);
      return { output: { message: { role: 'assistant', content: [{ text: 'bedrock injected' }] } },
        stopReason: 'end_turn', usage: { inputTokens: 1, outputTokens: 2, totalTokens: 3 } };
    },
  } });
  assert.equal((await bedrock.generate('hi', { temperature: 0 })).response, 'bedrock injected');
});

test('ollama provider retains scheduler slots until delayed NDJSON transports settle', async () => {
  const http = require('node:http');
  const pendingResponses = new Set();
  let requests = 0;
  const server = http.createServer((req, res) => {
    requests += 1;
    pendingResponses.add(res);
    res.setHeader('content-type', 'application/x-ndjson');
    res.write(JSON.stringify({ model: 'fixture', response: 'OK', done: false }) + '\n');
    res.write(JSON.stringify({ model: 'fixture', done: true }) + '\n');
    res.once('close', () => pendingResponses.delete(res));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const baseURL = `http://127.0.0.1:${server.address().port}`;
    const provider = createLangChainProvider({ provider: 'ollama', model: 'fixture', baseURL });
    const first = provider.generate('one', { timeout: 2000, ownerId: 'transport-a' });
    const second = provider.generate('two', { timeout: 2000, ownerId: 'transport-b' });
    const deadline = Date.now() + 1000;
    while (requests < 2 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(requests, 2);
    const third = provider.generate('three', { timeout: 2000, ownerId: 'transport-c' });
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(requests, 2, 'third request remains queued while terminal frames have open transports');
    for (const response of [...pendingResponses]) response.end();
    assert.equal((await first).response, 'OK');
    assert.equal((await second).response, 'OK');
    const thirdDeadline = Date.now() + 1000;
    while (requests < 3 && Date.now() < thirdDeadline) await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(requests, 3);
    for (const response of [...pendingResponses]) response.end();
    const thirdResult = await third;
    assert.equal(thirdResult.response, 'OK');
    assert.equal(requests, 3);
  } finally {
    for (const response of [...pendingResponses]) response.end();
    await new Promise(resolve => server.close(resolve));
  }
});
