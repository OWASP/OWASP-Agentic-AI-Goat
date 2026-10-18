'use strict';

const STEPS = new Set(['legacy_store','finflow_store']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function scope(value) {
  if (!value || typeof value !== 'object' || !UUID.test(value.operationId || '')
      || !STEPS.has(value.stepKey) || !Number.isSafeInteger(value.ownerId) || value.ownerId < 1
      || !Number.isSafeInteger(value.fromGeneration) || value.fromGeneration < 0
      || value.toGeneration !== value.fromGeneration + 1) throw new TypeError('Valid Sensitive Information cleanup scope required');
  return { operationId:value.operationId.toLowerCase(),stepKey:value.stepKey,ownerId:value.ownerId,
    fromGeneration:value.fromGeneration,toGeneration:value.toGeneration };
}
function receipt(row) {
  if (!row) return null;
  return Object.freeze({operationId:row.operation_id,stepKey:row.step_key,ownerId:Number(row.owner_id),
    fromGeneration:Number(row.from_generation),toGeneration:Number(row.to_generation)});
}
function createSensitiveInfoCleanupRepository(pool) {
  if (typeof pool?.query !== 'function') throw new TypeError('FinFlow PostgreSQL pool required');
  return Object.freeze({
    async assertReady() {
      const row=(await pool.query(`SELECT
        to_regclass('finflow.sensitive_info_cleanup_operations') IS NOT NULL AS operations,
        to_regclass('finflow.sensitive_info_cleanup_receipts') IS NOT NULL AS receipts,
        to_regprocedure('finflow.apply_sensitive_info_cleanup(uuid,bigint,integer,integer,text)') IS NOT NULL AS apply,
        to_regprocedure('finflow.read_sensitive_info_cleanup_receipt(uuid,text)') IS NOT NULL AS read,
        EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='sensitive_info_cleanup_operation_binding_guard' AND NOT tgisinternal) AS operation_guard,
        EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='sensitive_info_cleanup_receipt_binding_guard' AND NOT tgisinternal) AS receipt_guard,
        has_function_privilege(current_user,'finflow.apply_sensitive_info_cleanup(uuid,bigint,integer,integer,text)','EXECUTE') AS runtime_apply,
        has_function_privilege(current_user,'finflow.read_sensitive_info_cleanup_receipt(uuid,text)','EXECUTE') AS runtime_read,
        NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
          WHERE p.oid IN ('finflow.apply_sensitive_info_cleanup(uuid,bigint,integer,integer,text)'::regprocedure,
            'finflow.read_sensitive_info_cleanup_receipt(uuid,text)'::regprocedure)
            AND a.grantee=0 AND a.privilege_type='EXECUTE') AS no_public_execute`)).rows[0];
      if(!row||Object.values(row).some(value=>value!==true))throw Object.assign(new Error('RESET_STORAGE_NOT_READY'),{code:'RESET_STORAGE_NOT_READY'});
      return true;
    },
    async apply(value) {
      const input=scope(value);return receipt((await pool.query(
        'SELECT * FROM finflow.apply_sensitive_info_cleanup($1,$2,$3,$4,$5)',
        [input.operationId,input.ownerId,input.fromGeneration,input.toGeneration,input.stepKey])).rows[0]);
    },
    async readReceipt(value) {
      const input=scope(value);return receipt((await pool.query(
        'SELECT * FROM finflow.read_sensitive_info_cleanup_receipt($1,$2)',
        [input.operationId,input.stepKey])).rows[0]);
    },
  });
}
module.exports={createSensitiveInfoCleanupRepository};
