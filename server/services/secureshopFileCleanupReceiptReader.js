'use strict';

const { createHash } = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function failure(code, message) { return Object.assign(new Error(message), { code }); }
function uuid(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', 'file cleanup coordinate is invalid');
  return value.toLowerCase();
}
function positive(value, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw failure('INVALID_ARGUMENT', 'file cleanup coordinate is invalid');
  return value;
}
function snapshot(input) {
  if (!input || Object.getPrototypeOf(input) !== Object.prototype || input.targetKind !== 'files') {
    throw failure('INVALID_ARGUMENT', 'file cleanup scope is invalid');
  }
  return Object.freeze({ targetKind: 'files', targetId: uuid(input.targetId),
    launchId: uuid(input.launchId), scenarioId: uuid(input.scenarioId),
    fromGeneration: positive(input.fromGeneration),
    platformOwnerId: positive(input.platformOwnerId, 2147483647),
    platformSessionId: positive(input.platformSessionId, 2147483647),
    operationId: uuid(input.operationId) });
}

/**
 * Internal read-only bridge. The file receipt binds a launch and owner, while
 * durable identity authority binds that launch to the original platform
 * session. Neither model arguments nor a caller-provided receipt supply proof.
 * This adapter does not retire a target or enable a route.
 */
function createSecureShopFileCleanupReceiptReader({ files, cleanupAuthority } = {}) {
  if (typeof files?.readReservedCleanupReceipt !== 'function'
      || typeof cleanupAuthority?.checkTarget !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'file cleanup reader dependencies are required');
  }
  return async function readFileCleanupReceipt(input) {
    const scope = snapshot(input);
    const binding = Object.freeze({ targetId: scope.targetId, launchId: scope.launchId,
      scenarioId: scope.scenarioId, generation: scope.fromGeneration,
      ownerId: String(scope.platformOwnerId) });
    const coordinates = Object.freeze({ version: 1, ...binding, operationId: scope.operationId });
    const matches = value => value && Object.keys(coordinates).every(key => value[key] === coordinates[key]);
    const checkAuthority = async () => {
      const authority = await cleanupAuthority.checkTarget(scope);
      if (!['fenced', 'committed', 'aborted'].includes(authority?.status)) {
        throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED', 'durable file cleanup authority is unavailable');
      }
    };
    const authorize = async requested => {
      if (!matches(requested)) throw failure('TARGET_RECEIPT_MISMATCH', 'file cleanup request does not match authority');
      await checkAuthority();
      return true;
    };
    await checkAuthority();
    const receipt = await files.readReservedCleanupReceipt(binding,
      { operationId: scope.operationId, authorize });
    const receiptCoordinates = receipt?.version === 2 && receipt.durabilityMode === 'file_synced_rename_verified'
      ? { ...coordinates, version: 2, durabilityMode: 'file_synced_rename_verified' } : coordinates;
    const expectedKeys = [...Object.keys(receiptCoordinates), 'status', 'completedAt', 'cleanupPending', 'receiptSha256'].sort();
    if (!receipt || !Object.keys(receiptCoordinates).every(key => receipt[key] === receiptCoordinates[key])
        || Object.keys(receipt).sort().join(',') !== expectedKeys.join(',') || receipt.status !== 'completed' || receipt.cleanupPending !== false
        || typeof receipt.completedAt !== 'string' || !Number.isFinite(Date.parse(receipt.completedAt))
        || new Date(receipt.completedAt).toISOString() !== receipt.completedAt) {
      throw failure('TARGET_RECEIPT_MISMATCH', 'file cleanup receipt does not match authority');
    }
    const canonical = { ...receiptCoordinates, status: 'completed', completedAt: receipt.completedAt, cleanupPending: false };
    const digest = createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
    if (receipt.receiptSha256 !== digest) throw failure('TARGET_RECEIPT_MISMATCH', 'file cleanup receipt digest is invalid');
    await checkAuthority();
    return Object.freeze({ version: 1, kind: 'files', targetId: scope.targetId,
      launchId: scope.launchId, scenarioId: scope.scenarioId, generation: scope.fromGeneration,
      platformOwnerId: scope.platformOwnerId, platformSessionId: scope.platformSessionId,
      operationId: scope.operationId, receiptSha256: digest, completedAt: receipt.completedAt });
  };
}

module.exports = { createSecureShopFileCleanupReceiptReader };
