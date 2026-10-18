'use strict';

const { createLangChainProvider } = require('../agent-runtime/providers/langchainProvider');
const { createObjectiveJudge } = require('../agent-runtime/objectiveJudge');
const { createLegacyAiExperimentRunner } = require('./legacyAiExperimentRunner');

const SUPPORTED_PROVIDERS = new Set(['ollama', 'openai', 'anthropic', 'bedrock', 'lmstudio']);
const MAX_CONFIG_TEXT_BYTES = 2048;
const MAX_RESPONSE_BYTES = 256 * 1024;
const ANONYMOUS_OWNER_LANE = 'legacy-ai-experiment-anonymous';

function invalid(message) {
  return Object.assign(new TypeError(message), { code: 'INVALID_EXPERIMENT_PRODUCTION_CONFIG' });
}

function plain(value, label) {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    throw invalid('Valid ' + label + ' required');
  }
  return value;
}

function member(value, key, label) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw invalid('Valid ' + label + ' required');
  return descriptor.value;
}

function boundedText(value, label, maximum = MAX_CONFIG_TEXT_BYTES) {
  if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value) > maximum) {
    throw invalid('Valid ' + label + ' required');
  }
  return value.trim();
}

function boundedResponse(value, label) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > MAX_RESPONSE_BYTES) {
    throw invalid('Valid ' + label + ' required');
  }
  return value;
}

function url(value, label) {
  const text = boundedText(value, label);
  let parsed;
  try { parsed = new URL(text); } catch { throw invalid('Valid ' + label + ' required'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw invalid('Valid ' + label + ' required');
  }
  return text;
}

function onlyKeys(value, keys, label) {
  if (Reflect.ownKeys(value).some(key => typeof key !== 'string' || !keys.has(key))) {
    throw invalid('Valid ' + label + ' required');
  }
}

function copyConfig(value, label) {
  const source = plain(value, label);
  const provider = boundedText(member(source, 'provider', label + ' provider'), label + ' provider').toLowerCase();
  if (!SUPPORTED_PROVIDERS.has(provider)) throw invalid('Supported ' + label + ' provider required');
  const model = boundedText(member(source, 'model', label + ' model'), label + ' model');
  if (provider === 'ollama' || provider === 'lmstudio') {
    onlyKeys(source, new Set(['provider', 'model', 'baseURL']), label);
    return Object.freeze({ provider, model, baseURL: url(member(source, 'baseURL', label + ' base URL'), label + ' base URL') });
  }
  if (provider === 'openai' || provider === 'anthropic') {
    onlyKeys(source, new Set(['provider', 'model', 'baseURL', 'apiKey']), label);
    return Object.freeze({
      provider,
      model,
      baseURL: url(member(source, 'baseURL', label + ' base URL'), label + ' base URL'),
      apiKey: boundedText(member(source, 'apiKey', label + ' API key'), label + ' API key'),
    });
  }
  onlyKeys(source, new Set(['provider', 'model', 'region', 'client']), label);
  const client = member(source, 'client', label + ' Bedrock client');
  if (!client || typeof client.send !== 'function') throw invalid('Valid ' + label + ' Bedrock client required');
  const send = client.send.bind(client);
  return Object.freeze({
    provider,
    model,
    region: boundedText(member(source, 'region', label + ' region'), label + ' region'),
    client: Object.freeze({ send }),
  });
}

function publicConfig(config) {
  return Object.freeze({
    provider: config.provider,
    model: config.model,
  });
}

function timeout(value, label, maximum) {
  if (!Number.isSafeInteger(value) || value < 100 || value > maximum) {
    throw invalid('Valid ' + label + ' required');
  }
  return value;
}

function executionScope(value) {
  const source = plain(value, 'server execution');
  const signal = member(source, 'signal', 'server execution signal');
  if (!signal || typeof signal.throwIfAborted !== 'function' || typeof signal.addEventListener !== 'function') {
    throw invalid('Valid server execution signal required');
  }
  const check = member(source, 'check', 'server execution check');
  if (typeof check !== 'function') throw invalid('Valid server execution check required');
  const suppliedOwnerId = member(source, 'ownerId', 'server execution owner');
  const ownerId = suppliedOwnerId === null ? ANONYMOUS_OWNER_LANE : suppliedOwnerId;
  if (ownerId !== ANONYMOUS_OWNER_LANE && (!Number.isSafeInteger(ownerId) || ownerId < 1)) {
    throw invalid('Valid server execution owner required');
  }
  return Object.freeze({
    signal,
    check,
    ownerId,
  });
}

function copyJson(value, depth, ancestors) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw invalid('Valid bounded experiment options required');
    return value;
  }
  if (!value || typeof value !== 'object' || depth > 6 || ancestors.has(value)) {
    throw invalid('Valid bounded experiment options required');
  }
  ancestors.add(value);
  let copy;
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || Reflect.ownKeys(value).length !== value.length + 1) {
      throw invalid('Valid bounded experiment options required');
    }
    copy = new Array(value.length);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw invalid('Valid bounded experiment options required');
      }
      copy[index] = copyJson(descriptor.value, depth + 1, ancestors);
    }
  } else {
    if (Object.getPrototypeOf(value) !== Object.prototype) throw invalid('Valid bounded experiment options required');
    copy = {};
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') throw invalid('Valid bounded experiment options required');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw invalid('Valid bounded experiment options required');
      }
      Object.defineProperty(copy, key, {
        configurable: true,
        enumerable: true,
        value: copyJson(descriptor.value, depth + 1, ancestors),
        writable: true,
      });
    }
  }
  ancestors.delete(value);
  return copy;
}

function freezeDeep(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function optionalMember(value, key, label) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor) return undefined;
  if (!Object.hasOwn(descriptor, 'value')) throw invalid('Valid ' + label + ' required');
  return descriptor.value;
}

function snapshotInput(value) {
  const input = plain(value, 'legacy AI experiment input');
  const sourceRoute = member(input, 'sourceRoute', 'legacy AI experiment route');
  const prompt = member(input, 'prompt', 'legacy AI experiment prompt');
  if (typeof sourceRoute !== 'string' || typeof prompt !== 'string') {
    throw invalid('Valid legacy AI experiment input required');
  }
  const rawOptions = optionalMember(input, 'options', 'legacy AI experiment options');
  const options = rawOptions === undefined ? undefined : copyJson(rawOptions, 0, new WeakSet());
  if (options !== undefined && Buffer.byteLength(JSON.stringify(options)) > 256 * 1024) {
    throw invalid('Valid bounded experiment options required');
  }
  return Object.freeze({ sourceRoute, prompt, ...(options === undefined ? {} : { options: freezeDeep(options) }) });
}

function resultFromTransport(raw, config, label) {
  const value = plain(raw, label + ' transport result');
  const response = boundedResponse(member(value, 'response', label + ' response'), label + ' response');
  if (member(value, 'provider', label + ' provider') !== config.provider
      || member(value, 'model', label + ' model') !== config.model
      || member(value, 'mocked', label + ' mock state') !== false
      || member(value, 'fallback', label + ' fallback state') !== false) {
    throw Object.assign(new Error('Configured ' + label + ' transport identity changed during invocation'), {
      code: 'MODEL_IDENTITY_MISMATCH',
    });
  }
  const tokens = Number.isSafeInteger(value.tokens) && value.tokens > 0 ? value.tokens : null;
  const metadataValue = value.metadata;
  const evalCount = metadataValue && typeof metadataValue === 'object'
    && Number.isSafeInteger(metadataValue.eval_count) && metadataValue.eval_count >= 0
    ? metadataValue.eval_count : null;
  return Object.freeze({
    response,
    provider: config.provider,
    model: config.model,
    mocked: false,
    fallback: false,
    tokens,
    metadata: Object.freeze(evalCount === null ? {} : { eval_count: evalCount }),
  });
}

function optionsFor(value, scope, signal, timeoutMs, contextTokens) {
  const forwarded = Object.assign(Object.create(null), value || {});
  const internalSignal = forwarded.signal;
  const callSignal = internalSignal && typeof internalSignal.throwIfAborted === 'function'
    ? AbortSignal.any([signal, internalSignal]) : signal;
  forwarded.ownerId = scope.ownerId;
  forwarded.signal = callSignal;
  forwarded.timeout = timeoutMs;
  forwarded.num_ctx = contextTokens;
  return Object.freeze({ options: Object.freeze(forwarded), signal: callSignal });
}

function boundTransport(transport, config, scope, signal, timeoutMs, contextTokens, label) {
  if (typeof transport?.generate !== 'function' || typeof transport?.chat !== 'function') {
    throw new TypeError('Configured ' + label + ' LangChain transport is required');
  }
  const current = async callSignal => {
    callSignal.throwIfAborted();
    await scope.check();
    callSignal.throwIfAborted();
  };
  return Object.freeze({
    async generate(prompt, options) {
      const call = optionsFor(options, scope, signal, timeoutMs, contextTokens);
      await current(call.signal);
      const raw = await transport.generate(prompt, call.options);
      await current(call.signal);
      return resultFromTransport(raw, config, label);
    },
    async chat(messages, tools, options) {
      const call = optionsFor(options, scope, signal, timeoutMs, contextTokens);
      await current(call.signal);
      const raw = await transport.chat(messages, tools, call.options);
      await current(call.signal);
      return resultFromTransport(raw, config, label);
    },
  });
}

function createLegacyAiExperimentProduction({
  inferenceConfig,
  judgeConfig,
  inferenceTimeoutMs,
  judgeTimeoutMs,
  inferenceContextTokens,
  judgeContextTokens,
  totalTimeoutMs,
} = {}) {
  const inference = copyConfig(inferenceConfig, 'inference configuration');
  const judgeConfigCopy = copyConfig(judgeConfig, 'Judge configuration');
  const inferenceTimeout = timeout(inferenceTimeoutMs, 'inference timeout', 120000);
  const judgeTimeout = timeout(judgeTimeoutMs, 'Judge timeout', 120000);
  if (!Number.isSafeInteger(inferenceContextTokens) || inferenceContextTokens < 4096 || inferenceContextTokens > 131072) {
    throw invalid('Valid inference context token limit required');
  }
  if (!Number.isSafeInteger(judgeContextTokens) || judgeContextTokens < 4096 || judgeContextTokens > 131072) {
    throw invalid('Valid Judge context token limit required');
  }
  const totalTimeout = timeout(totalTimeoutMs, 'total timeout', 240000);
  if (inferenceTimeout > totalTimeout || judgeTimeout > totalTimeout) {
    throw invalid('Component timeouts must fit within total timeout');
  }
  const inferenceTransport = createLangChainProvider(inference);
  const judgeTransport = createLangChainProvider(judgeConfigCopy);
  if (typeof inferenceTransport?.generate !== 'function' || typeof judgeTransport?.chat !== 'function') {
    throw new TypeError('Configured LangChain transports are required');
  }
  const snapshot = Object.freeze({
    inference: publicConfig(inference),
    judge: publicConfig(judgeConfigCopy),
    inferenceTimeoutMs: inferenceTimeout,
    judgeTimeoutMs: judgeTimeout,
    inferenceContextTokens,
    judgeContextTokens,
    totalTimeoutMs: totalTimeout,
  });

  return Object.freeze({
    snapshot,
    async run(input, execution) {
      const request = snapshotInput(input);
      const scope = executionScope(execution);
      const totalSignal = AbortSignal.any([scope.signal, AbortSignal.timeout(totalTimeout)]);
      const current = async () => {
        totalSignal.throwIfAborted();
        await scope.check();
        totalSignal.throwIfAborted();
      };
      await current();
      const actor = boundTransport(
        inferenceTransport,
        inference,
        scope,
        totalSignal,
        inferenceTimeout,
        inferenceContextTokens,
        'inference',
      );
      const judgeModel = boundTransport(
        judgeTransport,
        judgeConfigCopy,
        scope,
        totalSignal,
        judgeTimeout,
        judgeContextTokens,
        'Judge',
      );
      const objectiveJudge = createObjectiveJudge({
        model: judgeModel,
        timeoutMs: judgeTimeout,
        contextTokens: judgeContextTokens,
      });
      const runner = createLegacyAiExperimentRunner({
        provider: actor,
        judge: packet => objectiveJudge({
          rubric: packet.rubric,
          evidence: packet.evidence,
          facts: packet.facts,
          execution: { signal: totalSignal, check: current, ownerId: scope.ownerId },
        }),
      });
      const result = await runner.run(request);
      // The runner treats Judge errors as unavailable. Recheck the authoritative
      // execution fence so cancellation cannot become a publishable response.
      await current();
      return result;
    },
  });
}

module.exports = {
  createLegacyAiExperimentProduction,
};
