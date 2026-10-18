'use strict';

const {
  isDeepStrictEqual: equal
} = require('node:util');
const {
  createLaunchScope
} = require('./secureshopConversationBinding');
const fail = () => Object.assign(new Error('Original upload evidence unavailable'), {
  code: 'UPLOAD_SOURCE_UNAVAILABLE',
  executionBoundary: true
});

// Read the original immutable first serve, never mint or perform an HTTP request.
function createV06UploadSourceReader({
  assets,
  assertCurrent,
  read
} = {}) {
  if (typeof assets?.lookup !== 'function' || typeof assertCurrent !== 'function' || typeof read !== 'function') throw new TypeError('Upload evidence reader dependencies required');
  return Object.freeze({
    async read(input) {
      input.signal?.throwIfAborted();
      const {
        scope,
        persona,
        personaSession,
        target,
        mode
      } = input;
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
      if (!found?.canonicalServe) return null;
      const {
          admission,
          effect,
          canonicalServe: serve
        } = found,
        bound = admission.scope;
      if (!equal(createLaunchScope(bound), createLaunchScope(scope)) || bound.shopUserId !== persona.id || persona.role !== 'customer' || bound.personaSessionId !== personaSession.sessionId || bound.personaAuthorityVersion !== personaSession.authorityVersion || bound.targetId !== target.targetId || bound.sceneId !== target.scene.sceneId || bound.sceneGeneration !== target.scene.sceneGeneration || bound.grantId !== target.scene.grantId || bound.mode !== mode.mode || bound.modeGeneration !== mode.generation || bound.modeStamp !== mode.modeStamp || effect.outcome !== 'completed' || effect.file.isTraversal || admission.operationId !== input.operationId || effect.effectId !== input.effectId) throw fail();
      await assertCurrent(admission);
      input.signal?.throwIfAborted();
      await read({
        storedVirtualPath: effect.file.storedVirtualPath,
        responseByteCount: effect.file.byteCount,
        responseSha256: effect.file.bodySha256
      });
      await assertCurrent(admission);
      input.signal?.throwIfAborted();
      return Object.freeze({
        admission,
        effect,
        serve
      });
    }
  });
}
module.exports = {
  createV06UploadSourceReader
};
