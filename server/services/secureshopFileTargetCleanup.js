'use strict';

const { createSecureShopFileCleanupReceiptReader } = require('./secureshopFileCleanupReceiptReader');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ALLOWED_STATUSES = new Set(['fenced', 'committed', 'aborted']);

function failure(code, message) { return Object.assign(new Error(message), { code }); }
function uuid(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', 'file cleanup coordinate is invalid');
  return value.toLowerCase();
}
function positive(value, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw failure('INVALID_ARGUMENT', 'file cleanup coordinate is invalid');
  return value;
}
function snapshot(input, operationId) {
  if (!input || Object.getPrototypeOf(input) !== Object.prototype || input.targetKind !== 'files') {
    throw failure('INVALID_ARGUMENT', 'file cleanup target is invalid');
  }
  return Object.freeze({ targetId: uuid(input.targetId), targetKind: 'files',
    launchId: uuid(input.launchId), scenarioId: uuid(input.scenarioId),
    fromGeneration: positive(input.fromGeneration),
    platformOwnerId: positive(input.platformOwnerId, 2147483647),
    platformSessionId: positive(input.platformSessionId, 2147483647),
    operationId: uuid(operationId) });
}
/**
 * Private fixed-kind effect adapter. Durable reset authority, never learner or
 * model input, authorizes every runner lifecycle checkpoint.
 */
function createSecureShopFileTargetCleanup({ files, cleanupAuthority } = {}) {
  if (typeof files?.retireReservedTarget !== 'function'
      || typeof cleanupAuthority?.checkTarget !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'file cleanup dependencies are required');
  }
  const readCleanupReceipt = createSecureShopFileCleanupReceiptReader({ files, cleanupAuthority });
  return Object.freeze({
    async cleanup(input, { operationId } = {}) {
      const scope = snapshot(input, operationId);
      const binding = Object.freeze({ targetId: scope.targetId, launchId: scope.launchId,
        scenarioId: scope.scenarioId, generation: scope.fromGeneration,
        ownerId: String(scope.platformOwnerId) });
      const coordinates = Object.freeze({ version: 1, ...binding, operationId: scope.operationId });
      const expectedKeys = Object.keys(coordinates).sort();
      const matches = value => value && Object.getPrototypeOf(value) === Object.prototype
        && Object.keys(value).sort().length === expectedKeys.length
        && Object.keys(value).sort().every((key, index) => key === expectedKeys[index])
        && expectedKeys.every(key => value[key] === coordinates[key]);
      const checkAuthority = async () => {
        const authority = await cleanupAuthority.checkTarget(scope);
        if (!ALLOWED_STATUSES.has(authority?.status)) {
          throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED', 'durable file cleanup authority is unavailable');
        }
      };
      const authorize = async requested => {
        if (!matches(requested)) throw failure('TARGET_BINDING_MISMATCH', 'file cleanup request does not match authority');
        await checkAuthority();
        return true;
      };
      await checkAuthority();
      await files.retireReservedTarget(binding, { operationId: scope.operationId, authorize });
      // Reuse the same private read-only projection consumed by identity
      // reconciliation so cleanup success and durable evidence cannot drift.
      return readCleanupReceipt(scope);
    },
  });
}

module.exports = { createSecureShopFileTargetCleanup };
