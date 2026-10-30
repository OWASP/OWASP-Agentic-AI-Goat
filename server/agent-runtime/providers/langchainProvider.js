'use strict';
const { HumanMessage, AIMessage, SystemMessage, ToolMessage } = require('@langchain/core/messages');

const CAPABILITIES = Object.freeze({
  ollama: { text: true, tools: true, reliableTools: false },
  openai: { text: true, tools: true }, anthropic: { text: true, tools: true },
  bedrock: { text: true, tools: true }, lmstudio: { text: true, tools: false },
});
function canonical(provider) {
  return ({ chatgpt: 'openai', claude: 'anthropic' })[provider] || provider;
}
function messagesForLangChain(messages) {
  const pending = [];
  return messages.map((message, index) => {
    if (!message || !['system', 'user', 'assistant', 'tool'].includes(message.role)) throw new Error('Unsupported chat message role');
    const content = message.content ?? '';
    if (message.role === 'system') return new SystemMessage(content);
    if (message.role === 'tool') {
      const call = message.tool_call_id ? pending.find(item => item.id === message.tool_call_id) : pending[0];
      if (!call) throw new Error('Tool result has no matching tool call');
      pending.splice(pending.indexOf(call), 1);
      return new ToolMessage({ content, tool_call_id: call.id, name: call.name });
    }
    if (message.role === 'assistant') {
      const tool_calls = (message.tool_calls || []).map((call, offset) => ({
        id: call.id || `call_${index}_${offset}`, name: call.function?.name || call.name,
        args: typeof call.function?.arguments === 'string' ? JSON.parse(call.function.arguments)
          : call.function?.arguments || call.args || {}, type: 'tool_call',
      }));
      pending.push(...tool_calls);
      return new AIMessage({ content, tool_calls });
    }
    return new HumanMessage(content);
  });
}
async function drainResponseBody(response, maxBytes = 16 * 1024 * 1024, abortController) {
  if (!response?.body || typeof response.clone !== 'function') return;
  const clone = response.clone();
  const reader = clone.body?.getReader?.();
  if (!reader) return;
  let total = 0;
  // Observe only bounded NDJSON frames during the existing physical drain.
  // The SDK remains responsible for response text and protocol validation.
  const decoder = new TextDecoder();
  let line = '', oversizedLine = false, terminal = null;
  const observe = text => {
    for (const part of text.split(/(?<=\n)/)) {
      if (!oversizedLine) {
        if (line.length + part.length > 65536) { line = ''; oversizedLine = true; }
        else line += part;
      }
      if (part.endsWith('\n')) {
        if (!oversizedLine) {
          try {
            const frame = JSON.parse(line);
            if (frame.done === true) terminal = {
              done: true,
              ...(typeof frame.done_reason === 'string' && /^[a-z_]{1,32}$/.test(frame.done_reason)
                ? { done_reason: frame.done_reason } : {}),
            };
          } catch { /* SDK owns malformed-response handling. */ }
        }
        line = ''; oversizedLine = false;
      }
    }
  };
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) { observe(decoder.decode() + "\n"); return terminal; }
      total += value?.byteLength || 0;
      if (total > maxBytes) {
        const error = Object.assign(new Error('Provider response exceeded bounded transport drain'), { code: 'PROVIDER_RESPONSE_TOO_LARGE' });
        abortController?.abort(error);
        throw error;
      }
      observe(decoder.decode(value, { stream: true }));
    }
  } catch (error) {
    try { await reader.cancel(error); } catch {}
    throw error;
  } finally {
    reader.releaseLock();
  }
}

function ollamaContextWindow(options, env = process.env) {
  const explicit = Object.hasOwn(options, 'num_ctx');
  const configured = env.OLLAMA_CONTEXT_WINDOW;
  const value = explicit ? options.num_ctx : configured === undefined || configured === '' ? 8192 : configured;
  const valid = typeof value === 'number' ? Number.isSafeInteger(value) && value > 0
    : typeof value === 'string' && /^[1-9]\d*$/.test(value) && Number.isSafeInteger(Number(value));
  if (!valid) throw new RangeError('Ollama context window must be a positive integer');
  return Number(value);
}

function buildModel(config, options, textOnly) {
  const provider = canonical(config.provider);
  const common = { model: config.model, temperature: options.temperature ?? 0.7,
    maxRetries: 0, maxTokens: options.max_tokens ?? options.num_predict ?? 1024 };
  if (provider === 'ollama') {
    const numCtx = ollamaContextWindow(options);
    const { Ollama, ChatOllama } = require('@langchain/ollama');
    class MetadataOllama extends Ollama {
      invocationParams(callOptions) {
        const params = super.invocationParams(callOptions);
        const excluded = new Set(['signal', 'timeout', 'ownerId', 'max_tokens', 'format', 'keep_alive', 'transportState', 'allowFallback']);
        const raw = Object.fromEntries(Object.entries(options).filter(([key]) => !excluded.has(key)));
        params.options = { ...params.options, ...raw };
        params.options.num_ctx = numCtx;
        if (raw.num_predict === null) delete params.options.num_predict;
        return params;
      }
      async *_streamResponseChunks(...args) {
        for await (const chunk of super._streamResponseChunks(...args)) {
          this.lastResponseMetadata = { ...this.lastResponseMetadata, ...chunk.generationInfo };
          yield chunk;
        }
      }
    }
    return new (textOnly ? MetadataOllama : ChatOllama)({ ...common, baseUrl: config.baseURL,
      // The SDK checks cancellation between chunks; bind it to the HTTP request
      // as well so a server which sends no chunks cannot hold a slot forever.
      fetch: async (url, init = {}) => {
        const transportAbort = new AbortController();
        const signals = [transportAbort.signal, options.signal, init.signal].filter(Boolean);
        const signal = signals.length === 1 ? signals[0] : AbortSignal.any(signals);
        const response = await fetch(url, { ...init, signal });
        // ChatOllama can return after the terminal `done` frame while the
        // underlying NDJSON response remains open. Drain a clone so the
        // scheduler's job does not release its slot before the transport has
        // actually settled; the model still consumes the original response.
        if (options.transportState) {
          options.transportState.settled = drainResponseBody(response, 16 * 1024 * 1024, transportAbort)
            .then(metadata => { options.transportState.terminalMetadata = metadata; return null; }, error => { options.transportState.error = error; return error; });
        }
        return response;
      },
      numPredict: options.num_predict === null ? undefined : options.num_predict ?? options.max_tokens ?? 1024,
      numCtx, topP: options.top_p, topK: options.top_k,
      repeatPenalty: options.repeat_penalty, seed: options.seed, stop: options.stop,
      format: options.format, keepAlive: options.keep_alive });
  }
  if (provider === 'openai' || provider === 'lmstudio') {
    const { ChatOpenAI } = require('@langchain/openai');
    return new ChatOpenAI({ ...common, apiKey: config.apiKey || 'local',
      configuration: { baseURL: config.baseURL }, timeout: options.timeout });
  }
  if (provider === 'anthropic') {
    const { ChatAnthropic } = require('@langchain/anthropic');
    return new ChatAnthropic({ ...common, apiKey: config.apiKey, anthropicApiUrl: config.baseURL });
  }
  if (provider === 'bedrock') {
    const { ChatBedrockConverse } = require('@langchain/aws');
    return new ChatBedrockConverse({ ...common, region: config.region, client: config.client });
  }
  throw new Error(`Unsupported LangChain provider: ${provider}`);
}
function contentText(content) {
  if (typeof content === 'string') return content;
  return Array.isArray(content) ? content.filter(item => item.type === 'text').map(item => item.text).join('') : '';
}
function createLangChainProvider(config, { modelFactory = buildModel } = {}) {
  const provider = canonical(config.provider);
  const capabilities = CAPABILITIES[provider];
  const scheduler = require('./modelScheduler').sharedModelScheduler(provider, config.baseURL || config.region);
  if (!capabilities) throw new Error(`Unsupported LangChain provider: ${provider}`);
  async function invoke(input, tools, options, textOnly) {
    const timeout = options.timeout ?? 120000;
    const ownerExecution = require('../ownerWorkflowRoutes').getOwnerExecution();
    const parentSignal = options.signal || ownerExecution?.signal;
    const signal = parentSignal ? AbortSignal.any([parentSignal, AbortSignal.timeout(timeout)]) : AbortSignal.timeout(timeout);
    const transportState = { settled: Promise.resolve(), error: null };
    const runWithTransport = async (runnable, value) => {
      let result;
      let invocationError;
      try { result = await runnable.invoke(value, { signal }); }
      catch (error) { invocationError = error; }
      const transportError = await transportState.settled;
      if (invocationError) throw invocationError;
      if (transportError) throw transportError;
      return result;
    };
    const model = modelFactory(config, { ...options, signal, transportState }, textOnly);
    if (tools.length && (!capabilities.tools || typeof model.bindTools !== 'function')) {
      throw new Error(`${provider} does not support native tools for this configuration`);
    }
    const runnable = tools.length ? model.bindTools(tools) : model;
    const result = await new Promise((resolve, reject) => {
      const abort = () => reject(signal.reason);
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) return abort();
      const owner = options.ownerId ?? require('../../utils/requestContext').getRequestContext().userId;
      scheduler.run(owner, signal, () => runWithTransport(runnable, input)).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
    });
    const response = typeof result === 'string' ? result : contentText(result.content);
    const toolCalls = typeof result === 'object' ? (result.tool_calls || []) : [];
    if (!response.trim() && !toolCalls.length) throw new Error(`${provider} returned an empty response`);
    return { response, model: config.model, provider: config.provider,
      // Only reached after the configured LangChain runnable completed. Mock
      // and offline fallbacks live outside this adapter and must stay explicit.
      mocked: false, fallback: false,
      tokens: result.usage_metadata?.output_tokens || result.response_metadata?.eval_count || model.lastResponseMetadata?.eval_count || 0,
      metadata: { ...(result.response_metadata || model.lastResponseMetadata || {}), ...transportState.terminalMetadata },
      tool_calls: toolCalls.map((call, i) => ({ id: call.id || `call_${i}`, type: 'function',
        function: { name: call.name, arguments: call.args } })),
    };
  }
  async function finalResponse(input, options = {}) {
    const { FINAL_RESPONSE_SCHEMA, parseFinalResponse, usageTelemetry } = require('./finalResponseContract');
    const timeout = options.timeout ?? 120000;
    const ownerExecution = require('../ownerWorkflowRoutes').getOwnerExecution();
    const parentSignal = options.signal || ownerExecution?.signal;
    const signal = parentSignal ? AbortSignal.any([parentSignal, AbortSignal.timeout(timeout)]) : AbortSignal.timeout(timeout);
    const transportState = { settled: Promise.resolve(), error: null };
    const runWithTransport = async runnable => {
      let result;
      let invocationError;
      try { result = await runnable.invoke(input, { signal }); }
      catch (error) { invocationError = error; }
      const transportError = await transportState.settled;
      if (invocationError) throw invocationError;
      if (transportError) throw transportError;
      return result;
    };
    const model = modelFactory(config, { ...options, signal, transportState }, false);
    if (typeof model?.withStructuredOutput !== 'function') {
      const error = new Error(`${provider} does not support structured final responses for this configuration`);
      error.code = 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED';
      throw error;
    }
    const method = provider === 'bedrock' ? 'functionCalling' : 'jsonSchema';
    let runnable;
    try {
      runnable = model.withStructuredOutput(FINAL_RESPONSE_SCHEMA, {
        name: 'owasp_ai_goat_final_response', method, includeRaw: true,
        ...(provider === 'openai' ? { strict: true } : {}),
      });
    } catch (cause) {
      const error = new Error(`${provider} does not support structured final responses for this configuration`, { cause });
      error.code = 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED';
      throw error;
    }
    let result;
    try {
      result = await new Promise((resolve, reject) => {
        const abort = () => reject(signal.reason);
        signal.addEventListener('abort', abort, { once: true });
        if (signal.aborted) return abort();
        const owner = options.ownerId ?? require('../../utils/requestContext').getRequestContext().userId;
        scheduler.run(owner, signal, () => runWithTransport(runnable)).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
      });
    } catch (cause) {
      signal.throwIfAborted();
      const error = new Error(`${provider} structured final response failed`, { cause });
      const invalidDecision = cause?.name === 'OutputParserException'
        || cause?.lc_error_code === 'OUTPUT_PARSING_FAILURE';
      error.code = cause?.code === 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED'
        ? cause.code : invalidDecision ? 'SECURESHOP_INVALID_DECISION' : undefined;
      throw error;
    }
    const parsed = parseFinalResponse(result?.parsed);
    if (!parsed) {
      const error = new Error(`${provider} returned an invalid structured final response`);
      error.code = 'SECURESHOP_INVALID_DECISION';
      throw error;
    }
    const raw = result.raw || {};
    const usage = Object.freeze({ ...usageTelemetry(raw), attempts: 1 });
    return { response: parsed.answer, model: config.model, provider: config.provider,
      mocked: false, fallback: false, tokens: usage.outputTokens || 0,
      usage, metadata: raw.response_metadata || {} };
  }
  async function routeWorkflow(input, options = {}) {
    const { WORKFLOW_ROUTE_SCHEMA, parseWorkflowRoute } = require('./workflowRouteContract');
    const { usageTelemetry } = require('./finalResponseContract');
    if (!Number.isSafeInteger(options.max_tokens) || options.max_tokens < 1) throw new TypeError('Routing token budget required');
    const parentSignal = options.signal || require('../ownerWorkflowRoutes').getOwnerExecution()?.signal;
    const timeoutSignal = AbortSignal.timeout(options.timeout ?? 120000);
    const signal = parentSignal ? AbortSignal.any([parentSignal, timeoutSignal]) : timeoutSignal;
    signal.throwIfAborted();
    const transportState = { settled: Promise.resolve(), error: null };
    const model = modelFactory(config, { ...options, temperature: 0, signal, transportState }, false);
    const unsupported = cause => Object.assign(new Error('Workflow routing capability unavailable', { cause }),
      { code: 'SECURESHOP_ROUTE_UNSUPPORTED' });
    if (typeof model?.withStructuredOutput !== 'function') throw unsupported();
    let runnable;
    try {
      // Hosted strict-output APIs require an object at the schema root. The
      // wrapper is transport-only; the graph still receives the closed route.
      const schema = { type: 'object', properties: { decision: {
        anyOf: structuredClone(WORKFLOW_ROUTE_SCHEMA.oneOf),
      } }, required: ['decision'], additionalProperties: false };
      runnable = model.withStructuredOutput(schema, {
        name: 'owasp_ai_goat_workflow_route', method: provider === 'bedrock' ? 'functionCalling' : 'jsonSchema',
        includeRaw: true, ...(provider === 'openai' ? { strict: true } : {}),
      });
    } catch (cause) { throw unsupported(cause); }
    let result;
    try {
      const owner = options.ownerId ?? require('../../utils/requestContext').getRequestContext().userId;
      result = await new Promise((resolve, reject) => {
        const abort = () => reject(signal.reason);
        signal.addEventListener('abort', abort, { once: true });
        if (signal.aborted) { signal.removeEventListener('abort', abort); return abort(); }
        scheduler.run(owner, signal, async () => {
          let value, error;
          try { value = await runnable.invoke(input, { signal }); } catch (cause) { error = cause; }
          const transportError = await transportState.settled;
          if (error) throw error;
          if (transportError) throw transportError;
          return value;
        }).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
      });
    } catch (cause) {
      const error = signal.aborted ? (signal.reason instanceof Error ? signal.reason : new DOMException('Aborted', 'AbortError'))
        : Object.assign(new Error('Workflow routing request failed', { cause }), {
          code: cause?.name === 'OutputParserException' || cause?.lc_error_code === 'OUTPUT_PARSING_FAILURE'
            ? 'SECURESHOP_INVALID_DECISION' : undefined,
        });
      try { error.usage = { ...usageTelemetry(cause), attempts: 1 }; } catch { /* Preserve failure. */ }
      throw error;
    }
    const usage = Object.freeze({ ...usageTelemetry(result?.raw), attempts: 1 });
    if (signal.aborted) {
      const error = signal.reason instanceof Error ? signal.reason : new DOMException('Aborted', 'AbortError');
      try { error.usage = usage; } catch { /* Preserve cancellation. */ }
      throw error;
    }
    const rawDecision = result?.parsed;
    const decision = rawDecision && Object.getPrototypeOf(rawDecision) === Object.prototype
      && Object.keys(rawDecision).join(',') === 'decision' ? parseWorkflowRoute(rawDecision.decision) : null;
    if (!decision) throw Object.assign(new Error('Invalid workflow routing decision'),
      { code: 'SECURESHOP_INVALID_DECISION', usage });
    return { decision, provider, model: config.model, mocked: false, fallback: false, usage };
  }
  return { capabilities,
    generate: (prompt, options = {}) => invoke(provider === 'ollama' ? prompt : [new HumanMessage(prompt)], [], options, provider === 'ollama'),
    chat: (messages, tools = [], options = {}) => invoke(messagesForLangChain(messages), tools, options, false),
    finalResponse: (messages, options = {}) => finalResponse(messagesForLangChain(messages), options),
    routeWorkflow: (messages, options = {}) => routeWorkflow(messagesForLangChain(messages), options),
  };
}
module.exports = { createLangChainProvider, messagesForLangChain, CAPABILITIES, ollamaContextWindow };
