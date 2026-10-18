'use strict';

const crypto = require('node:crypto');

const RECEIPT_VERSION = 'secureshop-bound-audit-owner-deletion-v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function normalizeScope(scope) {
  if (!Number.isSafeInteger(scope?.subjectId) || scope.subjectId < 1
      || scope.subjectId > 2147483647 || typeof scope.jobId !== 'string'
      || !UUID.test(scope.jobId.toLowerCase()) || typeof scope.check !== 'function') {
    throw new TypeError('Bound audit deletion owner, job, and lease check required');
  }
  return Object.freeze({ subjectId: scope.subjectId, jobId: scope.jobId.toLowerCase() });
}

function normalizeCount(value) {
  if (!((typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value))
      || (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
      || (typeof value === 'bigint' && value >= 0n))) {
    throw new Error('Bound audit deletion receipt count is invalid');
  }
  return BigInt(value).toString();
}

function receiptDigest(jobId, subjectId, deletedEventCount) {
  return crypto.createHash('sha256').update([
    RECEIPT_VERSION, jobId, String(subjectId), deletedEventCount,
  ].join('\x1f'), 'utf8').digest();
}

function verifyReceipt(row, expected, store) {
  if (!row || String(row.deletion_job_id).toLowerCase() !== expected.jobId
      || Number(row.original_platform_owner_id) !== expected.subjectId) {
    throw new Error(`Bound audit ${store} deletion receipt scope mismatch`);
  }
  const deletedEventCount = normalizeCount(row.deleted_event_count);
  const digest = row.receipt_sha256;
  const wanted = receiptDigest(expected.jobId, expected.subjectId, deletedEventCount);
  if (!Buffer.isBuffer(digest) || digest.length !== 32
      || !crypto.timingSafeEqual(digest, wanted)) {
    throw new Error(`Bound audit ${store} deletion receipt digest mismatch`);
  }
  return Object.freeze({ deletionJobId: expected.jobId,
    originalPlatformOwnerId: expected.subjectId, deletedEventCount,
    receiptSha256: digest.toString('hex') });
}

async function current(scope) {
  scope.signal?.throwIfAborted();
  await scope.check();
  scope.signal?.throwIfAborted();
}

function createSecureShopBoundAuditCleanup({ agentsPool, reviewPool } = {}) {
  if (typeof agentsPool?.query !== 'function' || typeof reviewPool?.query !== 'function') {
    throw new TypeError('Bound audit cleanup pools required');
  }
  const stores = Object.freeze([
    Object.freeze({ name: 'agents', schema: 'secureshop_agents', pool: agentsPool }),
    Object.freeze({ name: 'review', schema: 'secureshop_review', pool: reviewPool }),
  ]);

  return async function cleanSecureShopBoundAudit(scope = {}) {
    const expected = normalizeScope(scope);
    const destroyed = [];
    await current(scope);
    for (const store of stores) {
      const result = await store.pool.query(
        `SELECT deletion_job_id::text, original_platform_owner_id,
                deleted_event_count, receipt_sha256
           FROM ${store.schema}.destroy_bound_audit_owner($1,$2::uuid)`,
        [expected.subjectId, expected.jobId]);
      if (!Array.isArray(result?.rows) || result.rows.length !== 1) {
        throw new Error(`Bound audit ${store.name} deletion receipt missing`);
      }
      destroyed.push(verifyReceipt(result.rows[0], expected, store.name));
      await current(scope);
    }

    const confirmed = [];
    for (let index = 0; index < stores.length; index += 1) {
      const store = stores[index];
      const result = await store.pool.query(
        `SELECT deletion_job_id::text, original_platform_owner_id,
                deleted_event_count, receipt_sha256
           FROM ${store.schema}.bound_audit_owner_deletion_receipts
          WHERE deletion_job_id=$1::uuid AND original_platform_owner_id=$2`,
        [expected.jobId, expected.subjectId]);
      if (!Array.isArray(result?.rows) || result.rows.length !== 1) {
        throw new Error(`Bound audit ${store.name} deletion receipt re-read missing`);
      }
      const receipt = verifyReceipt(result.rows[0], expected, store.name);
      if (JSON.stringify(receipt) !== JSON.stringify(destroyed[index])) {
        throw new Error(`Bound audit ${store.name} deletion receipt changed`);
      }
      confirmed.push(receipt);
      await current(scope);
    }
    return Object.freeze({ completed: true, agents: confirmed[0], review: confirmed[1] });
  };
}

module.exports = { createSecureShopBoundAuditCleanup };
