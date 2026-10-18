'use strict';

const { digestMcpValue } = require('./secureshopMcpTrustTools');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function unavailable(message = 'Bound SSRF cleanup unavailable') {
  return Object.assign(new Error(message), { code: 'BOUND_SSRF_UNAVAILABLE' });
}
function positive(value) { if (!Number.isSafeInteger(value) || value < 1) throw unavailable(); return value; }
function uuid(value) { if (!UUID.test(value || '')) throw unavailable(); return value.toLowerCase(); }
function scope(input, operationId) {
  return Object.freeze({ targetId: uuid(input?.targetId), launchId: uuid(input?.launchId), scenarioId: uuid(input?.scenarioId),
    generation: positive(input?.fromGeneration), platformOwnerId: positive(input?.platformOwnerId),
    platformSessionId: positive(input?.platformSessionId), operationId: uuid(operationId) });
}

function createSecureShopSsrfResetAdapter({ repository, targetPool, cleanupAuthority } = {}) {
  if (typeof repository?.retire !== 'function' || typeof repository?.readCleanupReceipt !== 'function'
    || typeof targetPool?.retireRecovered !== 'function' || typeof cleanupAuthority?.checkTarget !== 'function') throw unavailable();
  async function authorize(value) {
    const outcome = await cleanupAuthority.checkTarget(Object.freeze({ ...value, targetKind:'controlled_ssrf',
      fromGeneration: value.generation }));
    if (!['fenced', 'committed', 'aborted'].includes(outcome?.status)) throw unavailable();
  }
  async function readCleanupReceipt(input, { operationId } = {}) {
    const value = scope(input, operationId || input?.operationId); await authorize(value);
    const stored = await repository.readCleanupReceipt(value, { operationId: value.operationId,
      fromGeneration: value.generation });
    return Object.freeze({ targetId: stored.targetId, kind:'controlled_ssrf', launchId: stored.launchId, scenarioId: stored.scenarioId,
      generation: stored.fromGeneration, platformOwnerId: stored.platformOwnerId,
      platformSessionId: stored.platformSessionId, operationId: stored.operationId,
      version: stored.targetReceiptVersion, receiptSha256: stored.targetReceiptSha256,
      completedAt: stored.targetCompletedAt });
  }
  return Object.freeze({
    async cleanup(input, { operationId } = {}) {
      const value = scope(input, operationId); await authorize(value);
      await targetPool.retireRecovered(value); await authorize(value);
      const receiptSha256 = digestMcpValue({ version: 1, operationId: value.operationId,
        targetId: value.targetId, launchId: value.launchId, scenarioId: value.scenarioId,
        generation: value.generation, platformOwnerId: value.platformOwnerId,
        platformSessionId: value.platformSessionId, ownedFixtureAbsent: true });
      await repository.retire(value, { operationId: value.operationId, fromGeneration: value.generation, receiptSha256 });
      return readCleanupReceipt(input, { operationId: value.operationId });
    },
    readCleanupReceipt,
  });
}

module.exports = { createSecureShopSsrfResetAdapter };
