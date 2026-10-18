'use strict';
const { createHash } = require('node:crypto');
const { posix } = require('node:path');

// Backend-owned facade. trustedScope must come from platform launch resolution,
// never from a model/tool argument. The filesystem primitive is local/injected;
// this is not an authenticated cross-process runner protocol.
function createSecureShopReservedFileReader({ launches, files }) {
  if (!launches || typeof launches.reserveFilesTarget !== 'function' || typeof launches.assertCurrent !== 'function'
    || !files || typeof files.provisionReservedTarget !== 'function' || typeof files.readFile !== 'function') {
    throw new TypeError('Reserved file reader dependencies required');
  }
  return Object.freeze({
    async readFile(trustedScope, requestedPath, { base = '/' } = {}) {
      // Snapshot authority and learner arguments before the first await.
      const scope = Object.freeze({ platformSessionId: trustedScope.platformSessionId,
        platformOwnerId: trustedScope.platformOwnerId, launchId: trustedScope.launchId,
        generation: trustedScope.generation });
      if (typeof requestedPath !== 'string' || typeof base !== 'string') throw new TypeError('Virtual file path required');
      const expectedPath = posix.resolve('/', base, requestedPath);
      const target = Object.freeze({ ...await launches.reserveFilesTarget({ ...scope, expectedGeneration: scope.generation }) });
      if (target.launchId !== scope.launchId || target.generation !== scope.generation || target.kind !== 'files'
        || typeof target.targetId !== 'string' || !target.targetId
        || typeof target.scenarioId !== 'string' || !target.scenarioId) {
        throw Object.assign(new Error('File reservation does not match the authorized launch'), { code: 'RESERVATION_BINDING_MISMATCH' });
      }
      const current = () => launches.assertCurrent({ ...scope, scenarioId: target.scenarioId });
      await current();
      const provisioned = await files.provisionReservedTarget({ targetId: target.targetId,
        launchId: target.launchId, scenarioId: target.scenarioId,
        generation: target.generation, ownerId: String(scope.platformOwnerId) });
      if (provisioned.targetId !== target.targetId || provisioned.launchId !== target.launchId
        || provisioned.scenarioId !== target.scenarioId || provisioned.generation !== target.generation
        || provisioned.ownerId !== String(scope.platformOwnerId)) {
        throw Object.assign(new Error('Isolated file target does not match its reservation'), { code: 'TARGET_BINDING_MISMATCH' });
      }
      // Provisioning may have completed after a reset/revocation. Keep its
      // durable cleanup obligation. These checks detect observed revocation;
      // they are not an atomic publication fence or graded effect receipt.
      await current();
      const result = await files.readFile(provisioned.capability, requestedPath,
        { base, expectedGeneration: target.generation, maxBytes: 256 * 1024 });
      await current();
      if (!Buffer.isBuffer(result.data) || result.generation !== target.generation
        || result.bytes !== result.data.length || result.virtualPath !== expectedPath
        || result.sha256 !== createHash('sha256').update(result.data).digest('hex')) {
        throw Object.assign(new Error('Isolated file result is invalid'), { code: 'INVALID_FILE_RESULT' });
      }
      return Object.freeze({ targetId: target.targetId, launchId: target.launchId,
        scenarioId: target.scenarioId, generation: target.generation,
        virtualPath: result.virtualPath, bytes: result.bytes, sha256: result.sha256,
        data: Buffer.from(result.data) });
    },
  });
}

module.exports = { createSecureShopReservedFileReader };
