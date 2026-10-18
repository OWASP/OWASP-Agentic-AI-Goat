'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope } = require('./secureshopConversationBinding');

const fail = () => Object.assign(new Error('Original traversal upload evidence unavailable'), {
  code: 'UPLOAD_SOURCE_UNAVAILABLE',
  executionBoundary: true
});

function createV46TraversalSourceReader({ assets, assertCurrent, read } = {}) {
  if (typeof assets?.lookup !== 'function' || typeof assertCurrent !== 'function' || typeof read !== 'function') {
    throw new TypeError('Traversal upload evidence reader dependencies required');
  }
  return Object.freeze({
    async read(input) {
      input.signal?.throwIfAborted();
      const { scope, persona, personaSession, target, mode } = input;
      if (!target?.scene || mode?.featureId !== 'uploads' || mode.mode !== 'vuln') return null;
      const found = await assets.lookup({
        effectId: input.effectId,
        operationId: input.operationId,
        targetId: target.targetId,
        generation: scope.generation,
        sceneId: target.scene.sceneId,
        sceneGeneration: target.scene.sceneGeneration,
        mode: mode.mode,
        modeGeneration: mode.generation,
        modeStamp: mode.modeStamp
      });
      if (!found) return null;
      const { admission, effect } = found, bound = admission.scope;
      if (!equal(createLaunchScope(bound), createLaunchScope(scope))
          || bound.shopUserId !== persona.id || persona.role !== 'customer'
          || bound.personaSessionId !== personaSession.sessionId
          || bound.personaAuthorityVersion !== personaSession.authorityVersion
          || bound.targetId !== target.targetId || bound.sceneId !== target.scene.sceneId
          || bound.sceneGeneration !== target.scene.sceneGeneration || bound.grantId !== target.scene.grantId
          || bound.mode !== mode.mode || bound.modeGeneration !== mode.generation || bound.modeStamp !== mode.modeStamp
          || effect.outcome !== 'completed' || effect.file.isTraversal !== true
          || admission.operationId !== input.operationId || effect.effectId !== input.effectId) throw fail();
      await assertCurrent(admission);
      input.signal?.throwIfAborted();
      const bytes = await read({
        storedVirtualPath: effect.file.storedVirtualPath,
        responseByteCount: effect.file.byteCount,
        responseSha256: effect.file.bodySha256
      });
      if (!Buffer.isBuffer(bytes) || bytes.length !== effect.file.byteCount
          || createHash('sha256').update(bytes).digest('hex') !== effect.file.bodySha256) throw fail();
      await assertCurrent(admission);
      input.signal?.throwIfAborted();
      return Object.freeze({
        admission,
        effect,
        readback: Object.freeze({
          byteCount: bytes.length,
          bodySha256: effect.file.bodySha256
        })
      });
    }
  });
}

module.exports = { createV46TraversalSourceReader };
