'use strict';

const { createLangChainProvider } = require('../agent-runtime/providers/langchainProvider');
const { createLegacySensitiveAgent } = require('./legacySensitiveAgent');

const PROVIDER_ALIASES = Object.freeze({ chatgpt: 'openai', claude: 'anthropic' });
const SUPPORTED = new Set(['ollama', 'openai', 'anthropic', 'bedrock', 'lmstudio']);

function nonempty(value, fallback) {
  const selected = value == null || value === '' ? fallback : value;
  if (typeof selected !== 'string' || !selected.trim()) throw new TypeError('Configured model identity is required');
  return selected.trim();
}

function configuredProvider(env) {
  const requested = nonempty(env.AI_PROVIDER, 'ollama').toLowerCase();
  const provider = PROVIDER_ALIASES[requested] || requested;
  if (!SUPPORTED.has(provider)) throw Object.assign(new Error('Legacy Sensitive model provider is unsupported'), { code: 'MODEL_PROVIDER_UNSUPPORTED' });
  if (provider === 'ollama') return Object.freeze({ provider, model: nonempty(env.OLLAMA_MODEL, 'llama3.1:8b'),
    baseURL: nonempty(env.OLLAMA_BASE_URL, 'http://localhost:11434') });
  if (provider === 'lmstudio') return Object.freeze({ provider, model: nonempty(env.LMSTUDIO_MODEL, 'local-model'),
    baseURL: nonempty(env.LMSTUDIO_BASE_URL, 'http://localhost:1234/v1') });
  if (provider === 'openai') {
    if (!env.OPENAI_API_KEY) throw Object.assign(new Error('OpenAI is not configured'), { code: 'MODEL_PROVIDER_UNAVAILABLE' });
    return Object.freeze({ provider, model: nonempty(env.OPENAI_MODEL, 'gpt-4'),
      baseURL: 'https://api.openai.com/v1', apiKey: env.OPENAI_API_KEY });
  }
  if (provider === 'anthropic') {
    const apiKey = env.ANTHROPIC_API_KEY || env.CLAUDE_API_KEY;
    if (!apiKey) throw Object.assign(new Error('Anthropic is not configured'), { code: 'MODEL_PROVIDER_UNAVAILABLE' });
    return Object.freeze({ provider, model: nonempty(env.ANTHROPIC_MODEL || env.CLAUDE_MODEL, 'claude-3-5-sonnet-20241022'),
      baseURL: 'https://api.anthropic.com/v1', apiKey });
  }
  return Object.freeze({ provider, model: nonempty(env.BEDROCK_MODEL_ID, 'us.meta.llama3-1-8b-instruct-v1:0'),
    region: nonempty(env.AWS_REGION || env.BEDROCK_REGION, 'us-east-1') });
}

function publicSnapshot(config) {
  return Object.freeze({ provider: config.provider, model: config.model,
    ...(config.baseURL ? { baseURL: config.baseURL } : {}),
    ...(config.region ? { region: config.region } : {}) });
}

function defaultObserver(event) {
  try { require('../middleware/llmLogger').logLLMCall(event); } catch {}
}

function createQualifiedModel({ transport, snapshot, observeModelCall = defaultObserver } = {}) {
  if (typeof transport?.chat !== 'function') throw new TypeError('A LangChain chat transport is required');
  const issued = new WeakMap();
  const observe = event => { try { observeModelCall(event); } catch {} };
  const model = Object.freeze({
    async generateResponse(input, options = {}) {
      const phase = options.qualificationPhase;
      if (!['decision', 'response'].includes(phase)) throw Object.assign(new Error('Model invocation phase is required'), { code: 'MODEL_PHASE_INVALID' });
      if (!Array.isArray(input) || input.length === 0 || input.some(message =>
        !message || Object.getPrototypeOf(message) !== Object.prototype
        || Object.keys(message).some(key => !['role', 'content'].includes(key))
        || !['system', 'user', 'assistant'].includes(message.role) || typeof message.content !== 'string')) {
        throw Object.assign(new Error('A server-owned chat message sequence is required'), { code: 'MODEL_REQUEST_INVALID' });
      }
      const messages = Object.freeze(input.map(({ role, content }) => Object.freeze({ role, content })));
      const promptLength = Buffer.byteLength(JSON.stringify(messages));
      const freeze = value => {
        if (value && typeof value === 'object') {
          for (const item of Object.values(value)) freeze(item);
          Object.freeze(value);
        }
        return value;
      };
      const forwarded = Object.freeze(Object.fromEntries(Object.entries(options)
        .filter(([key]) => key !== 'qualificationPhase')
        .map(([key, value]) => [key, key === 'signal' ? value : freeze(structuredClone(value))])));
      const started = Date.now();
      try {
        const raw = await transport.chat(messages, [], forwarded);
        if (!raw || typeof raw !== 'object' || typeof raw.response !== 'string' || !raw.response.trim()
            || raw.mocked === true || raw.fallback === true || raw._error) {
          throw Object.assign(new Error('Configured model returned an unavailable response'), { code: 'MODEL_PROVIDER_UNAVAILABLE' });
        }
        if (raw.provider !== snapshot.provider || raw.model !== snapshot.model) {
          throw Object.assign(new Error('Configured model identity changed during invocation'), { code: 'MODEL_IDENTITY_MISMATCH' });
        }
        const result = Object.freeze({ ...raw });
        issued.set(result, { phase, used: false });
        observe({ provider: snapshot.provider, model: snapshot.model, phase,
          promptLength, responseLength: Buffer.byteLength(result.response),
          latencyMs: Date.now() - started, success: true });
        return result;
      } catch (error) {
        observe({ provider: snapshot.provider, model: snapshot.model, phase,
          promptLength, latencyMs: Date.now() - started,
          success: false, error: error.code || error.name || 'MODEL_PROVIDER_UNAVAILABLE' });
        throw error;
      }
    },
  });
  const qualifyModel = ({ provider, phase, result }) => {
    if (provider !== model || !result || typeof result !== 'object') return false;
    const receipt = issued.get(result);
    if (!receipt || receipt.used || receipt.phase !== phase) return false;
    receipt.used = true;
    return true;
  };
  return Object.freeze({ model, qualifyModel });
}

function createLegacySensitiveAgentProduction({
  env = process.env,
  tools,
  providerFactory = createLangChainProvider,
  providerFactoryOptions = {},
  observeModelCall = defaultObserver,
} = {}) {
  const config = configuredProvider({ ...env });
  const snapshot = publicSnapshot(config);
  const factoryOptions = Object.freeze({ ...providerFactoryOptions });
  const transport = providerFactory(config, factoryOptions);
  const qualified = createQualifiedModel({ transport, snapshot, observeModelCall });
  return Object.freeze({
    snapshot,
    agent: createLegacySensitiveAgent({ model: qualified.model, tools,
      qualifyModel: qualified.qualifyModel, modelIdentity: snapshot }),
  });
}

module.exports = { createLegacySensitiveAgentProduction, createQualifiedModel, configuredProvider };
