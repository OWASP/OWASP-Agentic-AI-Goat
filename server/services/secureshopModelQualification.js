'use strict';

const { ProviderRouter } = require('./secureshop/providerRouter');
const { OllamaProvider } = require('./secureshop/providers/ollamaProvider');
const { AnthropicProvider } = require('./secureshop/providers/anthropicProvider');
const { OpenAIProvider } = require('./secureshop/providers/openaiProvider');
const { BedrockProvider } = require('./secureshop/providers/bedrockProvider');

const SUPPORTED = Object.freeze({
  ollama: OllamaProvider,
  anthropic: AnthropicProvider,
  openai: OpenAIProvider,
  bedrock: BedrockProvider,
});
function exactInstance(value, Constructor) {
  try { return value instanceof Constructor && Object.getPrototypeOf(value) === Constructor.prototype; }
  catch { return false; }
}

function configuredIdentity(instance, expectedName) {
  const Provider = SUPPORTED[expectedName];
  if (!Provider || !exactInstance(instance,Provider)) return null;
  const provider = instance.config?.provider || (expectedName === 'ollama' ? 'ollama' : null);
  const model = instance.config?.model || instance.model || instance.modelId || null;
  if (provider !== expectedName || typeof model !== 'string' || !model.trim()) return null;
  return Object.freeze({ provider: expectedName, model: model.trim() });
}

// This proves only that trace identity matches a supported adapter instance
// captured by trusted server composition. It does not attest replacement of
// server code or transport internals and never changes provider execution.
function createSecureShopModelQualifier(provider) {
  const accepted = new Map();
  if (exactInstance(provider,ProviderRouter)) {
    for (const name of Object.keys(SUPPORTED)) {
      const identity = configuredIdentity(provider.providers?.[name],name);
      if (identity) accepted.set(identity.provider,identity.model);
    }
  } else {
    for (const name of Object.keys(SUPPORTED)) {
      const identity = configuredIdentity(provider,name);
      if (identity) accepted.set(identity.provider,identity.model);
    }
  }
  return Object.freeze(function qualifiesModelTrace(identity) {
    if (!identity || identity.mocked !== false || identity.fallback === true
        || typeof identity.provider !== 'string'
        || typeof identity.model !== 'string') return false;
    return accepted.get(identity.provider) === identity.model;
  });
}

module.exports = { createSecureShopModelQualifier };
