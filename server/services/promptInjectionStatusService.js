async function getPromptInjectionProviderStatus(aiService) {
  const info = aiService.getActiveProviderInfo();
  const health = await aiService.verifyProviderConnectionLite(info.provider);
  return {
    available: Boolean(health.available && health.healthy),
    healthy: Boolean(health.healthy),
    configured: Boolean(health.configured),
    provider: info.provider,
    providerName: info.providerName,
    model: info.model,
    message: health.message || '',
    error: health.error || null,
  };
}

module.exports = { getPromptInjectionProviderStatus };
