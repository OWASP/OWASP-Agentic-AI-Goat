'use strict';
// Metadata completeness is necessary, not a cryptographic proof of a provider call.
// Callers must obtain this object from their server-owned provider adapter.
function hasModelResponseProvenance(result) {
  return Boolean(result && !result.mocked && !result.fallback &&
    typeof result.provider === 'string' && result.provider.trim() &&
    !['mock', 'fallback', 'unavailable'].includes(result.provider.trim().toLowerCase()) &&
    typeof result.model === 'string' && result.model.trim() &&
    typeof result.response === 'string' && result.response.trim());
}
module.exports = { hasModelResponseProvenance };
