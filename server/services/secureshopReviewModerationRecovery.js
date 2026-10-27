'use strict';
const {createHash} = require('node:crypto');
const {createConversationBinding} = require('./secureshopConversationBinding');
const reviewScene = require('./secureshopReviewSceneBinding');
const {checkedMode} = require('./secureshopAnalyticsModeAuthority');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{64}$/;
const fail = code => Object.assign(new Error('Review moderation recovery unavailable'), {code,
  ...(['SHOP_AUTH_INVALID','OWNER_MISMATCH','SHOP_SCENE_STALE','REVIEW_RECOVERY_SCOPE_CHANGED'].includes(code)
    ? {executionBoundary:true} : {})});
function request(requestId, limit, recoveryScopeKey) {
  if (typeof requestId !== 'string' || !UUID.test(requestId)
      || !Number.isInteger(limit) || limit < 1 || limit > 100
      || (recoveryScopeKey !== undefined && (typeof recoveryScopeKey !== 'string' || !SHA.test(recoveryScopeKey)))) throw fail('INVALID_ARGUMENT');
  return Object.freeze({requestId:requestId.toLowerCase(),requestedLimit:limit,
    ...(recoveryScopeKey === undefined ? {} : {recoveryScopeKey})});
}
function metadata(value) {
  const r = request(value.requestId,value.requestedLimit,value.recoveryScopeKey);
  if (!r.recoveryScopeKey) throw fail('REVIEW_RECOVERY_UNAVAILABLE');
  return Object.freeze({version:1,kind:'review_moderation',...r});
}
function assertResult(result, expected) {
  const saved = result?.taskMetadata?.reviewRecovery;
  const wanted = metadata(expected);
  if (!saved || Object.keys(saved).length !== Object.keys(wanted).length
      || Object.keys(wanted).some(key => saved[key] !== wanted[key])
      || result?.taskMetadata?.reviewBatch?.requested !== wanted.requestedLimit) throw fail('REVIEW_RECOVERY_UNAVAILABLE');
  return result;
}
// All readers are production-injected. Neither the opaque digest nor client
// state is authority; each operation rechecks the original retained identities.
function createReviewModerationRecovery({checkCurrent,personaAuthority,readTarget,readMode}) {
  if ([checkCurrent,personaAuthority?.capture,readTarget,readMode].some(fn => typeof fn !== 'function'))
    throw TypeError('Read-only moderation recovery dependencies required');
  async function capture({scope,persona,personaSession,recoveryScopeKey}) {
    const binding = createConversationBinding(scope,persona);
    if (binding.role !== 'merchant') throw fail('OWNER_MISMATCH');
    const {shopUserId:_user,role:_role,...coordinates} = binding;
    scope = Object.freeze(coordinates);
    if (typeof personaSession?.sessionId !== 'string' || !UUID.test(personaSession.sessionId)
        || typeof personaSession.authorityVersion !== 'string' || !/^[1-9][0-9]*$/.test(personaSession.authorityVersion)) throw fail('SHOP_AUTH_INVALID');
    const credential = Object.freeze({sessionId:personaSession.sessionId.toLowerCase(),authorityVersion:personaSession.authorityVersion});
    const fence = await personaAuthority.capture({scope,personaId:binding.shopUserId,role:binding.role,
      sessionId:credential.sessionId,authorityVersion:credential.authorityVersion});
    if (typeof fence?.assertRemoteAdmission !== 'function' || !fence.binding
        || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(key => fence.binding[key] !== binding[key])
        || fence.binding.personaId !== binding.shopUserId || fence.binding.role !== binding.role
        || fence.binding.sessionId !== credential.sessionId.toLowerCase()
        || fence.binding.authorityVersion !== credential.authorityVersion) throw fail('SHOP_AUTH_INVALID');
    const snapshot = async () => {
      await checkCurrent(scope); await fence.assertRemoteAdmission();
      const target = await readTarget(scope);
      const scene = reviewScene.productScene(target);
      if (!target || !scene?.scene) throw fail('SHOP_SCENE_STALE');
      const execution = reviewScene.current(target);
      if (['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(key => execution[key] !== binding[key])) throw fail('SHOP_SCENE_STALE');
      const mode = checkedMode(await readMode(scope));
      const key = createHash('sha256').update(JSON.stringify(['review-moderation-recovery-v1',binding,
        target.targetId,scene.targetId,scene.scene.sceneId,scene.scene.sceneGeneration,scene.scene.grantId,
        credential.sessionId,credential.authorityVersion,mode])).digest('hex');
      await fence.assertRemoteAdmission(); await checkCurrent(scope);
      return {target,key};
    };
    const original = await snapshot();
    if (recoveryScopeKey !== undefined && recoveryScopeKey !== original.key) throw fail('REVIEW_RECOVERY_SCOPE_CHANGED');
    const check = async () => {
      if ((await snapshot()).key !== original.key) throw fail('REVIEW_RECOVERY_SCOPE_CHANGED');
    };
    return Object.freeze({key:original.key,target:original.target,check});
  }
  return Object.freeze({capture});
}
module.exports = {normalizeReviewRecoveryRequest:request,reviewRecoveryMetadata:metadata,
  assertReviewRecoveryResult:assertResult,createReviewModerationRecovery};
