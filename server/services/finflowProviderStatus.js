'use strict';

const CLOUD = new Set(['openai', 'chatgpt', 'anthropic', 'claude', 'bedrock']);
const KNOWN = new Set([...CLOUD, 'ollama', 'lmstudio', 'mock']);
function text(value, maximum = 256) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/u.test(value) ? value : null;
}
function modelTag(value) {
  // A missing Ollama tag means :latest, never an arbitrary model variant.
  if (!value) return null;
  const last = value.slice(value.lastIndexOf('/') + 1);
  return last.includes(':') ? value : `${value}:latest`;
}

async function getFinflowProviderStatus(aiService) {
  let result = { available: false, configured: false, healthy: false,
    provider: 'unknown', providerName: 'Configured AI provider', model: null,
    checkKind: 'unavailable', message: 'AI provider status could not be checked.' };
  try {
    const info = aiService.getActiveProviderInfo();
    const provider = typeof info?.provider === 'string' ? info.provider.toLowerCase() : '';
    if (!KNOWN.has(provider)) return { ...result, checkKind: 'unsupported',
      message: 'The configured AI provider is not supported.' };
    result = { ...result, provider, providerName: text(info.providerName) || provider,
      model: text(info.model) };
    if (provider === 'mock') return { ...result, mocked: true, checkKind: 'mock',
      message: 'Deterministic simulation is configured; no real model is available.' };
    const health = await aiService.verifyProviderConnectionLite(provider);
    const configured = health?.configured === true;
    result = { ...result, configured };
    if (CLOUD.has(provider)) {
      const incomplete = !configured || health?.available === false;
      const region = provider === 'bedrock' ? text(info.region) || text(aiService.bedrockRegion) : null;
      return { ...result, available: incomplete ? false : null,
      healthy: null, checkKind: 'configuration_only',
      ...(region ? { region } : {}),
      message: incomplete ? 'AI provider configuration or credentials are incomplete.'
        : 'AI provider configured; connection and generation have not been tested.' };
    }
    if (!configured || health?.available !== true) return { ...result,
      checkKind: 'reachability', message: 'The local AI service could not be reached.' };
    if (provider === 'lmstudio') return { ...result, available: null, healthy: null,
      checkKind: 'reachability',
      message: 'LM Studio is reachable; selected model availability and generation have not been verified.' };
    // Lite health alone uses permissive prefix matching. Read the advertised
    // names without checkOllamaAvailable/ensureOllamaModel, which can switch models.
    const names = await aiService.getOllamaAvailableModels();
    const availableModels = Array.isArray(names)
      ? names.filter(name => text(name)).slice(0, 256) : [];
    const matched = result.model !== null
      && Array.isArray(names)
      && names.some(name => text(name) && modelTag(name) === modelTag(result.model));
    let version = null;
    if (typeof aiService.getOllamaVersion === 'function') {
      try { version = text(await aiService.getOllamaVersion(), 64); } catch { /* optional metadata */ }
    }
    return { ...result, available: matched, healthy: matched, checkKind: 'model_listing',
      availableModels, ...(version ? { ollamaVersion: version } : {}),
      message: matched ? 'Ollama is reachable and the selected model is installed; generation has not been tested.'
        : 'Ollama is reachable, but the selected model was not found in its model listing.' };
  } catch {
    // Transport errors may contain private URLs, credentials or response bodies.
    return { ...result, available: false, healthy: false, checkKind: 'unavailable',
      message: 'AI provider status could not be checked.' };
  }
}

module.exports = { getFinflowProviderStatus };
