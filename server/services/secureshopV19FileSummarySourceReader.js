'use strict';
const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const fail = () => Object.assign(Error('File summary source unavailable'), { code: 'FILE_SUMMARY_SOURCE_UNAVAILABLE' });
function createV19FileSummarySourceReader({ attachment } = {}) {
  if (typeof attachment?.readRetained !== 'function') throw TypeError('Owned attachment reader required');
  return Object.freeze({ async read({ scope, persona, personaSession, sessionId, requestId,
    receipt, target, mode, signal, check, checkAtEffect } = {}) {
    if (typeof check !== 'function' || typeof checkAtEffect !== 'function' || !target?.scene
      || !equal(createLaunchScope(executionScope(target)), createLaunchScope(scope))) throw fail();
    signal?.throwIfAborted(); await check();
    const saved = await attachment.readRetained({ scope: createLaunchScope(scope), persona,
      personaSession, sessionId, requestId }, receipt, { signal, check, checkAtEffect });
    await check(); signal?.throwIfAborted();
    if (!equal(saved.receipt, receipt) || !Buffer.isBuffer(saved.data)
      || !equal(receipt.authority?.scene, target.scene) || receipt.authority.sceneTargetId !== target.targetId
      || !equal(receipt.authority.mode, mode)) throw fail();
    return Object.freeze({ receipt: saved.receipt, data: Buffer.from(saved.data) });
  } });
}
module.exports = { createV19FileSummarySourceReader };
