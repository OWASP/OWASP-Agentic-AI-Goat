'use strict';
const { createHash } = require('node:crypto');

const PROVIDERS = new Set(['ollama', 'anthropic', 'claude', 'openai', 'chatgpt',
  'bedrock', 'lmstudio']);

// This projection consumes only the server-owned multi-provider result. A
// learner-visible string is kept separate from the provenance decision so a
// malformed or fallback adapter result can still produce honest retry copy
// without becoming completion evidence.
function projectCtfGuardianResult(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    return Object.freeze({ text: '', realModel: false });
  }
  const response = typeof result.response === 'string' ? result.response
    : typeof result.text === 'string' ? result.text : '';
  const text = response.trim() ? response : '';
  const provider = typeof result.provider === 'string' ? result.provider.trim().toLowerCase() : '';
  const model = typeof result.model === 'string' ? result.model.trim() : '';
  const realModel = Boolean(text && PROVIDERS.has(provider) && model
    && result.mocked === false && result.fallback !== true);
  return Object.freeze({ text, realModel,
    ...(realModel ? { provider, model } : {}) });
}

function requireCtfGuardianResult(result) {
  const guardian = projectCtfGuardianResult(result);
  if (!guardian.realModel) {
    throw Object.assign(new Error('CTF guardian unavailable'), { code: 'CTF_GUARDIAN_UNAVAILABLE' });
  }
  return guardian;
}

// Persist identity and byte provenance separately from the Objective Judge's
// identity. Hash raw guardian output without exposing pre-defense secrets in
// learner/admin attempt projections.
function captureCtfGuardianEvidence(result, visibleResponse) {
  const guardian = projectCtfGuardianResult(result);
  if (!guardian.realModel || typeof visibleResponse !== 'string') return null;
  const digest = value => createHash('sha256').update(value, 'utf8').digest('hex');
  return Object.freeze({ version: 'ctf-guardian-provenance-v1',
    provider: guardian.provider, model: guardian.model,
    rawResponseSha256: digest(guardian.text),
    visibleResponseSha256: digest(visibleResponse),
    rawResponseBytes: Buffer.byteLength(guardian.text, 'utf8'),
    visibleResponseBytes: Buffer.byteLength(visibleResponse, 'utf8') });
}

module.exports = { projectCtfGuardianResult, requireCtfGuardianResult, captureCtfGuardianEvidence };
