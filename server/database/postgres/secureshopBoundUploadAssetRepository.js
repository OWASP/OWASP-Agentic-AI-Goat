'use strict';

const {
  normalizeAdmission,
  normalizeEffect,
  normalizeServe
} = require('../../services/secureshopBoundUploadReceipt');
function createSecureShopBoundUploadAssetRepository(pool) {
  if (typeof pool?.query !== 'function') throw new TypeError('SecureShop review pool required');
  return Object.freeze({
    async lookup(claim = {}) {
      const row = (await pool.query(`SELECT
   s.serve_id AS prior_serve_id,s.receipt_path AS prior_receipt_path,s.status AS prior_status,
   s.content_type AS prior_content_type,s.content_disposition AS prior_content_disposition,
   s.nosniff_present AS prior_nosniff,s.response_byte_count AS prior_byte_count,
   s.response_sha256 AS prior_response_sha256,s.serve_sha256 AS prior_serve_sha256,
   a.binding_sha256,a.request_sha256,e.effect_sha256,a.operation_id,a.upload_request_id,a.storage_key AS admission_storage_key,a.target_id,a.launch_id,a.scenario_id,a.generation,
   a.platform_owner_id,a.platform_session_id,a.scene_id,a.scene_generation,a.grant_id,a.shop_user_id,
   a.persona_session_id,a.persona_authority_version,a.mode,a.mode_generation,a.mode_stamp,a.kind,a.scope_id,
   a.original_filename AS admission_original_filename,a.declared_mime AS admission_declared_mime,a.is_public,
   a.byte_count AS admission_byte_count,a.body_sha256 AS admission_body_sha256,
   e.effect_id,e.outcome,e.storage_key AS effect_storage_key,e.original_filename AS effect_original_filename,
   e.cleaned_filename,e.declared_mime AS effect_declared_mime,e.byte_count AS effect_byte_count,
   e.body_sha256 AS effect_body_sha256,e.base_virtual_path,e.resolved_virtual_path,e.stored_virtual_path,e.is_traversal
   FROM secureshop_review.bound_upload_effects e
   JOIN secureshop_review.bound_upload_admissions a ON a.operation_id=e.operation_id
   JOIN secureshop_review.product_targets t ON t.target_id=a.target_id AND t.lifecycle='active'
   LEFT JOIN secureshop_review.bound_upload_serves s ON s.operation_id=e.operation_id AND s.effect_id=e.effect_id
   LEFT JOIN secureshop_review.bound_upload_reconciliations r ON r.operation_id=a.operation_id
   LEFT JOIN secureshop_review.bound_upload_cleanup_receipts c ON c.target_id=a.target_id
   WHERE e.effect_id=$1 AND a.operation_id=$2 AND a.target_id=$3 AND a.generation=$4
    AND a.scene_id=$5 AND a.scene_generation=$6 AND a.mode=$7 AND a.mode_generation=$8 AND a.mode_stamp=decode($9,'hex')
    AND e.outcome='completed'
    AND secureshop_review.assert_scene_execution_grant(a.grant_id,a.scene_id,a.scene_generation,a.target_id,a.launch_id,a.scenario_id,a.generation,a.platform_owner_id,a.platform_session_id)
    AND r.operation_id IS NULL AND c.target_id IS NULL`, [claim.effectId, claim.operationId, claim.targetId, claim.generation, claim.sceneId, claim.sceneGeneration, claim.mode, claim.modeGeneration, claim.modeStamp])).rows[0];
      if (!row) return null;
      const admission = normalizeAdmission({
        operationId: row.operation_id,
        uploadRequestId: row.upload_request_id,
        storageKey: row.admission_storage_key,
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
          personaAuthorityVersion: String(row.persona_authority_version),
          mode: row.mode,
          modeGeneration: Number(row.mode_generation),
          modeStamp: row.mode_stamp.toString('hex')
        },
        request: {
          kind: row.kind,
          scopeId: row.scope_id,
          originalFilename: row.admission_original_filename,
          declaredMime: row.admission_declared_mime,
          public: row.is_public,
          byteCount: row.admission_byte_count,
          bodySha256: row.admission_body_sha256.toString('hex')
        }
      });
      if (row.admission_storage_key !== row.effect_storage_key || !row.stored_virtual_path.startsWith(`operations/${row.admission_storage_key}/avatars/${row.shop_user_id}/`) || row.is_traversal) throw Error('BOUND_UPLOAD_PATH_CHANGED');
      const effect = normalizeEffect({
        effectId: row.effect_id,
        outcome: row.outcome,
        file: {
          storageKey: row.effect_storage_key,
          originalFilename: row.effect_original_filename,
          cleanedFilename: row.cleaned_filename,
          declaredMime: row.effect_declared_mime,
          byteCount: row.effect_byte_count,
          bodySha256: row.effect_body_sha256.toString('hex'),
          baseVirtualPath: row.base_virtual_path,
          resolvedVirtualPath: row.resolved_virtual_path,
          storedVirtualPath: row.stored_virtual_path,
          isTraversal: row.is_traversal
        },
        denialCode: null,
        quarantineRequired: false
      }, admission);
      if (admission.bindingSha256 !== row.binding_sha256.toString('hex') || admission.requestSha256 !== row.request_sha256.toString('hex') || effect.effectSha256 !== row.effect_sha256.toString('hex')) throw Error('BOUND_UPLOAD_RECEIPT_CHANGED');
      let canonicalServe = null;
      if (row.prior_serve_id) {
        canonicalServe = normalizeServe({
          serveId: row.prior_serve_id,
          receiptPath: row.prior_receipt_path,
          status: row.prior_status,
          contentType: row.prior_content_type,
          contentDisposition: row.prior_content_disposition,
          nosniffPresent: row.prior_nosniff,
          responseByteCount: row.prior_byte_count,
          responseSha256: row.prior_response_sha256.toString('hex')
        }, admission, effect);
        if (canonicalServe.serveSha256 !== row.prior_serve_sha256.toString('hex') || canonicalServe.contentType !== effect.file.declaredMime || canonicalServe.nosniffPresent !== false) throw Error('BOUND_UPLOAD_SERVE_CHANGED');
      }
      return Object.freeze({
        admission,
        effect,
        canonicalServe,
        storedVirtualPath: effect.file.storedVirtualPath,
        responseByteCount: effect.file.byteCount,
        responseSha256: effect.file.bodySha256,
        contentType: effect.file.declaredMime,
        contentDisposition: `inline; filename="${effect.file.cleanedFilename.replace(/[\\"]+/g, '_')}"`
      });
    }
  });
}
module.exports = {
  createSecureShopBoundUploadAssetRepository
};
