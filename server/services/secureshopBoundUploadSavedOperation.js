'use strict';

const {
  normalizeAdmission
} = require('./secureshopBoundUploadReceipt');
const {
  projectSecureShopV46TraversalDestination
} = require('./secureshopV46TraversalDestination');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function unavailable() {
  return Object.assign(Error('Upload operation unavailable'), {
    code: 'BOUND_UPLOAD_UNAVAILABLE'
  });
}
function createSecureShopBoundUploadSavedOperation({
  pool,
  assertCurrent,
  effects,
  capability,
  assetOrigin,
  read = require('./secureshopUploadAssetReader').createSecureShopUploadAssetReader(),
  readTraversal = require('./secureshopV46TraversalAssetReader').createSecureShopV46TraversalAssetReader()
} = {}) {
  if (typeof pool?.query !== 'function' || typeof assertCurrent !== 'function' || typeof effects?.find !== 'function'
      || typeof capability?.mint !== 'function' || typeof read !== 'function' || typeof readTraversal !== 'function') throw unavailable();
  async function load(input) {
    input.signal?.throwIfAborted();
    const s = input.scope,
      p = input.persona,
      session = input.personaSession;
    const byRequest = input.operationId === undefined && UUID.test(input.uploadRequestId || '');
    if (!byRequest && !UUID.test(input.operationId || '') || input.operationId !== undefined && input.uploadRequestId !== undefined || p?.role !== 'customer' || !session) throw unavailable();
    const rows = (await pool.query(`SELECT a.* FROM secureshop_review.bound_upload_admissions a
     WHERE ${byRequest ? 'a.upload_request_id' : 'a.operation_id'}=$1 AND a.launch_id=$2 AND a.scenario_id=$3 AND a.generation=$4
       AND a.platform_owner_id=$5 AND a.platform_session_id=$6 AND a.shop_user_id=$7
       AND a.persona_session_id=$8 AND a.persona_authority_version=$9`, [byRequest ? input.uploadRequestId : input.operationId, s.launchId, s.scenarioId, s.generation, s.platformOwnerId, s.platformSessionId, p.id, session.sessionId, String(session.authorityVersion)])).rows;
    if (rows.length !== 1) throw unavailable();
    const row = rows[0];
    const admission = normalizeAdmission({
      operationId: row.operation_id,
      uploadRequestId: row.upload_request_id,
      storageKey: row.storage_key,
      scope: {
        targetId: row.target_id,
        launchId: row.launch_id,
        scenarioId: row.scenario_id,
        generation: Number(row.generation),
        platformOwnerId: row.platform_owner_id,
        platformSessionId: row.platform_session_id,
        sceneId: row.scene_id,
        sceneGeneration: Number(row.scene_generation),
        grantId: row.grant_id,
        shopUserId: row.shop_user_id,
        personaSessionId: row.persona_session_id,
        personaAuthorityVersion: row.persona_authority_version,
        mode: row.mode,
        modeGeneration: Number(row.mode_generation),
        modeStamp: row.mode_stamp.toString('hex')
      },
      request: {
        kind: row.kind,
        scopeId: row.scope_id,
        originalFilename: row.original_filename,
        declaredMime: row.declared_mime,
        public: row.is_public,
        byteCount: row.byte_count,
        bodySha256: row.body_sha256.toString('hex')
      }
    });
    if (admission.bindingSha256 !== row.binding_sha256.toString('hex') || admission.requestSha256 !== row.request_sha256.toString('hex')) throw unavailable();
    await assertCurrent(admission);
    const effect = await effects.find(admission);
    if (effect?.outcome === 'completed') await (effect.file.isTraversal ? readTraversal : read)({
      storedVirtualPath: effect.file.storedVirtualPath,
      responseByteCount: effect.file.byteCount,
      responseSha256: effect.file.bodySha256
    });
    await assertCurrent(admission);
    input.signal?.throwIfAborted();
    return {
      admission,
      effect
    };
  }
  return Object.freeze({
    async read(input) {
      const {
        admission,
        effect
      } = await load(input);
      return Object.freeze({
        operationId: admission.operationId,
        uploadRequestId: admission.uploadRequestId,
        status: effect?.outcome || 'uncertain',
        filename: admission.request.originalFilename,
        byteCount: admission.request.byteCount,
        ...(effect?.outcome === 'denied' ? {
          denialCode: effect.denialCode
        } : {}),
        ...(effect?.outcome === 'completed' ? {
          bodySha256: effect.file.bodySha256,
          ...(effect.file.isTraversal ? {
            traversal: true,
            ...projectSecureShopV46TraversalDestination(effect.file, {
              storageKey: admission.storageKey,
              shopUserId: admission.scope.shopUserId
            })
          } : {})
        } : {})
      });
    },
    async asset(input) {
      const {
        admission,
        effect
      } = await load(input);
      if (effect?.outcome !== 'completed' || effect.file.isTraversal) throw unavailable();
      const s = admission.scope;
      const token = capability.mint({
        effectId: effect.effectId,
        operationId: admission.operationId,
        targetId: s.targetId,
        generation: s.generation,
        sceneId: s.sceneId,
        sceneGeneration: s.sceneGeneration,
        mode: s.mode,
        modeGeneration: s.modeGeneration,
        modeStamp: s.modeStamp
      });
      return Object.freeze({
        operationId: admission.operationId,
        assetUrl: `${assetOrigin}${token.path}`,
        expiresAt: token.expiresAt
      });
    }
  });
}
module.exports = {
  createSecureShopBoundUploadSavedOperation
};
