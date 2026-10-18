'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope, withSceneLease } = require('./secureshopSceneBinding');
const { canonicalDigest } = require('./mcp/protocolContext');
const { validPath } = require('./secureshopV44FilePathSummaryExecutionConfig');

const fail = () => Object.assign(Error('File path summary source unavailable'), {
  code: 'FILE_PATH_SUMMARY_SOURCE_UNAVAILABLE',
});
const sha = value => createHash('sha256').update(value).digest('hex');

// Recovery opens the exact retained target. It must never reserve or provision a
// replacement target: a missing historical target makes the source unavailable.
function createV44FilePathSummarySourceReader({ launches, files } = {}) {
  for (const [object, method] of [[launches, 'readExistingFilesTarget'],
    [files, 'openExistingReservedTarget'], [files, 'readFile']]) {
    if (typeof object?.[method] !== 'function') throw TypeError('Retained owned-file reader required');
  }
  return Object.freeze({
    async read({ scope, receipt, target, mode, signal, check, checkAtEffect } = {}) {
      const trusted = createLaunchScope(scope);
      if (typeof check !== 'function' || typeof checkAtEffect !== 'function' || !target?.scene
          || !equal(createLaunchScope(executionScope(target)), trusted)
          || !receipt || receipt.version !== 1 || !validPath(receipt.requestedPath)
          || receipt.authority?.sceneTargetId !== target.targetId
          || !equal(receipt.authority?.scene, target.scene) || !equal(receipt.authority?.mode, mode)) throw fail();
      const { receiptSha256, ...body } = receipt;
      if (canonicalDigest(body) !== receiptSha256) throw fail();
      signal?.throwIfAborted();
      await check();
      const retained = await launches.readExistingFilesTarget(trusted);
      await check();
      const binding = Object.freeze({ targetId: receipt.targetId, launchId: receipt.launchId,
        scenarioId: receipt.scenarioId, generation: receipt.generation,
        ownerId: String(trusted.platformOwnerId) });
      if (retained?.kind !== 'files' || retained.targetId !== binding.targetId
          || retained.launchId !== binding.launchId || retained.scenarioId !== binding.scenarioId
          || retained.generation !== binding.generation) throw fail();
      await checkAtEffect();
      const result = await withSceneLease(target, async () => {
        const opened = await files.openExistingReservedTarget(binding);
        await checkAtEffect();
        if (!Object.keys(binding).every(key => opened?.[key] === binding[key])
            || typeof opened.capability !== 'string' || !opened.capability) throw fail();
        return files.readFile(opened.capability, receipt.requestedPath,
          { base: '/uploads', expectedGeneration: binding.generation, maxBytes: 256 * 1024 });
      });
      await checkAtEffect();
      await check();
      signal?.throwIfAborted();
      if (!Buffer.isBuffer(result?.data) || result.generation !== receipt.generation
          || result.virtualPath !== receipt.resolvedPath
          || result.bytes !== receipt.byteCount || result.sha256 !== receipt.bodySha256
          || result.bytes !== result.data.length || sha(result.data) !== result.sha256) throw fail();
      return Object.freeze({ receipt: Object.freeze(structuredClone(receipt)), data: Buffer.from(result.data) });
    },
  });
}

module.exports = { createV44FilePathSummarySourceReader };
