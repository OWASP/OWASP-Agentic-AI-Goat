'use strict';

const {
  createHash
} = require('node:crypto');
const {
  normalizeAdmission,
  normalizeEffect
} = require('./secureshopBoundUploadReceipt');
function fail(code, message) {
  return Object.assign(new Error(message), {
    code
  });
}
function decode(row) {
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
  let effect = null;
  if (row.effect_id) effect = normalizeEffect({
    effectId: row.effect_id,
    outcome: row.outcome,
    file: row.effect_storage_key ? {
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
    } : null,
    denialCode: row.denial_code,
    quarantineRequired: row.quarantine_required
  }, admission);
  if (admission.bindingSha256 !== row.binding_sha256.toString('hex') || admission.requestSha256 !== row.request_sha256.toString('hex') || effect && effect.effectSha256 !== row.effect_sha256.toString('hex')) throw fail('BOUND_UPLOAD_MISMATCH', 'Upload immutable preimage changed');
  return {
    admission,
    effect,
    reconciled: row.reconciliation_action,
    reconciliationSha256: row.reconciliation_receipt_sha256?.toString('hex')
  };
}
function createSecureShopBoundUploadResetAdapter({
  pool,
  fileCleanup,
  targetKind = 'files',
  journal,
  cleanupAuthority,
  storage
} = {}) {
  if (!['files', 'products'].includes(targetKind)) throw fail('INVALID_CONFIGURATION', 'Bound upload cleanup target kind invalid');
  if (typeof pool?.query !== 'function' || typeof fileCleanup?.cleanup !== 'function' || typeof journal?.recordCleanup !== 'function' || typeof journal?.reconcile !== 'function' || typeof journal?.reconcileOrphan !== 'function' || typeof cleanupAuthority?.checkTarget !== 'function' || typeof storage?.verifyReconciliation !== 'function' || typeof storage?.reconcile !== 'function' || typeof storage?.removeCompleted !== 'function') throw fail('INVALID_CONFIGURATION', 'Bound upload reset dependencies required');
  return Object.freeze({
    async cleanup(item, {
      operationId
    } = {}) {
      if (item.targetKind !== undefined && item.targetKind !== targetKind) throw fail('BOUND_UPLOAD_MISMATCH', 'Upload cleanup target kind changed');
      const fromGeneration = targetKind === 'products' ? item.generation : item.fromGeneration;
      if (!Number.isSafeInteger(fromGeneration) || fromGeneration < 1
          || (item.fromGeneration !== undefined && item.fromGeneration !== fromGeneration)) throw fail('BOUND_UPLOAD_MISMATCH', 'Upload cleanup generation changed');
      const authority = Object.freeze({
        ...item,
        fromGeneration,
        targetKind,
        operationId
      });
      const check = async () => {
        const result = await cleanupAuthority.checkTarget(authority);
        if (!['fenced', 'committed', 'aborted'].includes(result?.status)) throw fail('RESET_CLEANUP_AUTHORITY_REQUIRED', 'Durable upload cleanup authority unavailable');
      };
      await check();
      const rows = (await pool.query(`SELECT a.binding_sha256,a.request_sha256,a.operation_id,a.upload_request_id,a.storage_key AS admission_storage_key,a.target_id,a.launch_id,a.scenario_id,a.generation,a.platform_owner_id,a.platform_session_id,a.scene_id,a.scene_generation,a.grant_id,a.shop_user_id,a.persona_session_id,a.persona_authority_version,a.mode,a.mode_generation,a.mode_stamp,a.kind,a.scope_id,a.original_filename AS admission_original_filename,a.declared_mime AS admission_declared_mime,a.is_public,a.byte_count AS admission_byte_count,a.body_sha256 AS admission_body_sha256,e.effect_id,e.outcome,e.storage_key AS effect_storage_key,e.original_filename AS effect_original_filename,e.cleaned_filename,e.declared_mime AS effect_declared_mime,e.byte_count AS effect_byte_count,e.body_sha256 AS effect_body_sha256,e.base_virtual_path,e.resolved_virtual_path,e.stored_virtual_path,e.is_traversal,e.denial_code,e.quarantine_required,e.effect_sha256,r.action AS reconciliation_action,r.receipt_sha256 AS reconciliation_receipt_sha256 FROM secureshop_review.bound_upload_admissions a LEFT JOIN secureshop_review.bound_upload_effects e USING(operation_id) LEFT JOIN secureshop_review.bound_upload_reconciliations r USING(operation_id) WHERE a.target_id=$1 ORDER BY a.operation_id`, [item.targetId])).rows;
      let deletedCount = 0,
        quarantinedCount = 0;
      const decoded = rows.map(decode);
      for (const value of decoded) {
        const s = value.admission.scope;
        if (s.targetId !== item.targetId || s.platformOwnerId !== item.platformOwnerId) throw fail('BOUND_UPLOAD_MISMATCH', 'Upload reset scope changed');
      }
      const birthScope = scope => Object.freeze({
        ...scope,
        targetId: item.targetId,
        launchId: item.launchId,
        scenarioId: item.scenarioId,
        generation: fromGeneration,
        platformOwnerId: item.platformOwnerId,
        platformSessionId: item.platformSessionId
      });
      for (const value of decoded) {
        await check();
        if (value.reconciled) {
          await storage.verifyReconciliation(value.admission, {
            action: value.reconciled,
            receiptSha256: value.reconciliationSha256
          });
          if (value.reconciled === 'deleted') deletedCount++;else quarantinedCount++;
          continue;
        }
        if (!value.effect) {
          const receipt = await storage.reconcile(value.admission);
          await journal.reconcileOrphan(value.admission, receipt, {
            cleanupOperationId: operationId,
            cleanupScope: birthScope(value.admission.scope)
          });
          if (receipt.action === 'deleted') deletedCount++;else quarantinedCount++;
        } else if (value.effect.outcome === 'unresolved') {
          const receipt = await storage.reconcile(value.admission);
          await journal.reconcile(value.admission, value.effect, receipt, {
            cleanupOperationId: operationId,
            cleanupScope: birthScope(value.admission.scope)
          });
          if (receipt.action === 'deleted') deletedCount++;else quarantinedCount++;
        } else if (value.effect.outcome === 'completed') {
          await storage.removeCompleted(value.admission, value.effect, operationId);
          deletedCount++;
        } else if (value.effect.outcome === 'denied') {
          const absent = await storage.reconcile(value.admission);
          if (absent.action !== 'deleted') throw fail('BOUND_UPLOAD_MISMATCH', 'Denied upload unexpectedly owns bytes');
        }
      }
      await check();
      const fileReceipt = await fileCleanup.cleanup(item, {
        operationId
      });
      if (!rows.length) return fileReceipt;
      const scope = birthScope(decoded[0].admission.scope),
        receiptSha256 = createHash('sha256').update(JSON.stringify(['bound-upload-target-cleanup-v2', operationId, item.targetId, fileReceipt.receiptSha256, deletedCount, quarantinedCount])).digest('hex');
      await journal.recordCleanup({
        cleanupOperationId: operationId,
        scope,
        deletedCount,
        quarantinedCount,
        receiptSha256
      });
      await check();
      return fileReceipt;
    }
  });
}
module.exports = {
  createSecureShopBoundUploadResetAdapter
};
