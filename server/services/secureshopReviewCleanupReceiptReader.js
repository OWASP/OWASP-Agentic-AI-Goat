'use strict';

function invalid(message) {
  return Object.assign(new TypeError(message), { code: 'INVALID_CONFIGURATION' });
}

/**
 * Private fixed-target adapter. It invokes the repository's read-only receipt
 * verifier, which requires an existing receipt and a retired, empty target.
 * No caller-provided receipt or target kind is trusted.
 */
function createSecureShopReviewCleanupReceiptReader({ repository }) {
  if (!repository || typeof repository.readCleanupReceipt !== 'function') {
    throw invalid('review cleanup repository is required');
  }
  return async function readReviewCleanupReceipt(input) {
    if (!input || typeof input !== 'object' || input.targetKind !== 'reviews') {
      throw invalid('review cleanup target is invalid');
    }
    const scope = Object.freeze({
      targetId: input.targetId, launchId: input.launchId, scenarioId: input.scenarioId,
      generation: input.fromGeneration, platformOwnerId: input.platformOwnerId,
      platformSessionId: input.platformSessionId,
    });
    const stored = await repository.readCleanupReceipt(scope, { operationId: input.operationId });
    return Object.freeze({ ...stored, kind: 'reviews' });
  };
}

module.exports = { createSecureShopReviewCleanupReceiptReader };
