'use strict';

const {
  normalizeEffect
} = require('../../services/secureshopBoundUploadReceipt');
const {
  uploadAdmission
} = require('../../services/secureshopBoundUploadAdmission');
function createSecureShopBoundUploadEffectReader(pool, {
  checkCurrent,
  assertSceneGrant
} = {}) {
  if (typeof pool?.query !== 'function' || typeof checkCurrent !== 'function' || typeof assertSceneGrant !== 'function') throw new TypeError('Bound upload effect reader unavailable');
  return Object.freeze({
    async find(value) {
      const input = uploadAdmission(value),
        check = async () => {
          await checkCurrent(input.scope);
          await assertSceneGrant(input.scope);
        };
      await check();
      const row = (await pool.query(`SELECT e.* FROM secureshop_review.bound_upload_effects e JOIN secureshop_review.bound_upload_admissions a ON a.operation_id=e.operation_id LEFT JOIN secureshop_review.bound_upload_reconciliations r ON r.operation_id=e.operation_id LEFT JOIN secureshop_review.bound_upload_cleanup_receipts c ON c.target_id=a.target_id WHERE e.operation_id=$1 AND a.binding_sha256=decode($2,'hex') AND a.request_sha256=decode($3,'hex') AND r.operation_id IS NULL AND c.target_id IS NULL`, [input.operationId, input.bindingSha256, input.requestSha256])).rows[0];
      await check();
      if (!row) return null;
      const file = row.storage_key ? {
        storageKey: row.storage_key,
        originalFilename: row.original_filename,
        cleanedFilename: row.cleaned_filename,
        declaredMime: row.declared_mime,
        byteCount: row.byte_count,
        bodySha256: row.body_sha256.toString('hex'),
        baseVirtualPath: row.base_virtual_path,
        resolvedVirtualPath: row.resolved_virtual_path,
        storedVirtualPath: row.stored_virtual_path,
        isTraversal: row.is_traversal
      } : null;
      const effect = normalizeEffect({
        effectId: row.effect_id,
        outcome: row.outcome,
        file,
        denialCode: row.denial_code,
        quarantineRequired: row.quarantine_required
      }, input);
      if (row.effect_sha256.toString('hex') !== effect.effectSha256) throw Error('BOUND_UPLOAD_EFFECT_CHANGED');
      return Object.freeze({
        ...effect,
        replayed: true
      });
    }
  });
}
module.exports = {
  createSecureShopBoundUploadEffectReader
};
