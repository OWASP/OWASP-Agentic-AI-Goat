'use strict';

const { createLegacyAiExperimentProduction } = require('./legacyAiExperimentProduction');

function unavailable() {
  return Object.assign(new Error('Legacy AI actor or Judge configuration is unavailable'), {
    code: 'LEGACY_AI_EXPERIMENT_CONFIGURATION_UNAVAILABLE', statusCode: 503,
  });
}
function text(value, fallback) {
  const chosen = value === undefined || value === '' ? fallback : value;
  if (typeof chosen !== 'string' || !chosen.trim() || Buffer.byteLength(chosen) > 2048) throw unavailable();
  return chosen.trim();
}
function endpoint(value, fallback) {
  const result = text(value, fallback);
  let parsed;
  try { parsed = new URL(result); } catch { throw unavailable(); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw unavailable();
  return result;
}
function configFor(env, judge) {
  const selected = text(judge ? env.JUDGE_PROVIDER : env.AI_PROVIDER, 'ollama').toLowerCase();
  const provider = ({ claude: 'anthropic', chatgpt: 'openai' })[selected] || selected;
  const modelOverride = judge ? env.JUDGE_MODEL : undefined;
  switch (provider) {
    case 'ollama': return { provider, model: text(modelOverride || env.OLLAMA_MODEL, 'llama3.1:8b'),
      baseURL: endpoint(env.OLLAMA_BASE_URL, 'http://localhost:11434') };
    case 'lmstudio': return { provider, model: text(modelOverride || env.LMSTUDIO_MODEL, 'local-model'),
      baseURL: endpoint(env.LMSTUDIO_BASE_URL, 'http://localhost:1234/v1') };
    case 'openai': return { provider, model: text(modelOverride || env.OPENAI_MODEL),
      apiKey: text(env.OPENAI_API_KEY), baseURL: endpoint(env.OPENAI_BASE_URL, 'https://api.openai.com/v1') };
    case 'anthropic': return { provider, model: text(modelOverride || env.ANTHROPIC_MODEL || env.CLAUDE_MODEL),
      apiKey: text(env.ANTHROPIC_API_KEY || env.CLAUDE_API_KEY), baseURL: endpoint(env.ANTHROPIC_BASE_URL, 'https://api.anthropic.com') };
    case 'bedrock': return { provider, model: text(modelOverride || env.BEDROCK_MODEL_ID),
      region: text(env.AWS_REGION || env.BEDROCK_REGION) };
    default: throw unavailable();
  }
}
function defaultBedrockClient(options) {
  const { BedrockRuntimeClient } = require('@aws-sdk/client-bedrock-runtime');
  return new BedrockRuntimeClient(options);
}

// A single current configuration is retained. In-flight requests keep their
// already selected instance; the next request observes operator env changes.
// Configuration/credentials are never included in returned results or errors.
function createLegacyAiExperimentConfiguredInference({ getEnvironment = () => process.env,
  createProduction = createLegacyAiExperimentProduction, createBedrockClient = defaultBedrockClient } = {}) {
  if ([getEnvironment, createProduction, createBedrockClient].some(value => typeof value !== 'function')) {
    throw new TypeError('Configured inference factories required');
  }
  let current;
  return async function infer(input, execution) {
    const env = getEnvironment();
    if (!env || typeof env !== 'object') throw unavailable();
    let specification;
    try {
      specification = { inferenceConfig: configFor(env, false), judgeConfig: configFor(env, true),
        inferenceTimeoutMs: 90000, judgeTimeoutMs: 60000, totalTimeoutMs: 150000,
        inferenceContextTokens: 32768, judgeContextTokens: 32768 };
    } catch { throw unavailable(); }
    const key = JSON.stringify(specification);
    if (!current || current.key !== key) {
      try {
        for (const field of ['inferenceConfig', 'judgeConfig']) {
          const config = specification[field];
          if (config.provider === 'bedrock') config.client = createBedrockClient({ region: config.region });
        }
        const production = createProduction(specification);
        if (typeof production?.run !== 'function') throw unavailable();
        current = { key, production };
      } catch { throw unavailable(); }
    }
    // No input field participates in selecting provider, model or credentials.
    const production = current.production;
    return production.run(input, execution);
  };
}

module.exports = { createLegacyAiExperimentConfiguredInference };
