'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createSecureShopAuditRunCleanup } = require('../server/services/secureshopAuditRunCleanup');

const owner = 17;
const jobId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

function receipt(overrides = {}) {
  const counts = { deleted_run_count: '2', deleted_artifact_count: '10', deleted_chunk_count: '20', deleted_bytes: '1234', ...overrides };
  const digest = createHash('sha256').update(['secureshop-audit-run-deletion-v1', jobId, String(owner),
    counts.deleted_run_count, counts.deleted_artifact_count, counts.deleted_chunk_count, counts.deleted_bytes].join('\x1f')).digest();
  return { deletion_job_id: jobId, original_platform_owner_id: owner, ...counts, receipt_sha256: digest };
}

function fixture({ returned = receipt(), reread = returned, check, journal } = {}) {
  const events = []; let poolCalls = 0; let cleanCalls = 0;
  const pool = { async query(sql, params) {
    poolCalls++; events.push(sql.includes('destroy_bound_audit_runs') ? 'destroy' : 'reread');
    assert.deepEqual(params, sql.includes('destroy_bound_audit_runs') ? [owner, jobId] : [jobId, owner]);
    return { rows: sql.includes('destroy_bound_audit_runs') ? (returned === null ? [] : [returned]) : (reread === null ? [] : [reread]) };
  } };
  const cleanJournals = async value => {
    cleanCalls++; events.push('journals');
    assert.equal(value.jobId, jobId); assert.equal(value.subjectId, owner);
    return journal || { completed: true, agents: { deletionJobId: jobId, originalPlatformOwnerId: owner },
      review: { deletionJobId: jobId, originalPlatformOwnerId: owner } };
  };
  const service = createSecureShopAuditRunCleanup({ pool, cleanJournals });
  return { service, events, get poolCalls() { return poolCalls; }, get cleanCalls() { return cleanCalls; },
    scope: { subjectId: owner, jobId, check: check || (async () => {}) } };
}

test('journal deletion precedes artifact cleanup and rereads the exact receipt', async () => {
  const f = fixture();
  const result = await f.service(f.scope);
  assert.deepEqual(f.events, ['journals', 'destroy', 'reread']);
  assert.equal(f.cleanCalls, 1); assert.equal(f.poolCalls, 2);
  assert.deepEqual(result.artifacts, { deletionJobId: jobId, originalPlatformOwnerId: owner,
    deletedRunCount: '2', deletedArtifactCount: '10', deletedChunkCount: '20', deletedBytes: '1234',
    receiptSha256: receipt().receipt_sha256.toString('hex') });
});

test('corrupt or missing receipts fail closed after deletion and before reread', async () => {
  const corrupted = receipt(); corrupted.receipt_sha256 = Buffer.alloc(32);
  const corrupt = fixture({ returned: corrupted });
  await assert.rejects(corrupt.service(corrupt.scope), /receipt digest mismatch/);
  assert.deepEqual(corrupt.events, ['journals', 'destroy']);
  const missing = fixture({ returned: null });
  await assert.rejects(missing.service(missing.scope), /receipt missing/);
  assert.deepEqual(missing.events, ['journals', 'destroy']);
});

test('reread mismatch and fence loss reject publication', async () => {
  const mismatch = fixture({ reread: receipt({ deleted_run_count: '3' }) });
  await assert.rejects(mismatch.service(mismatch.scope), /receipt changed/);
  assert.deepEqual(mismatch.events, ['journals', 'destroy', 'reread']);
  let checks = 0;
  const fenced = fixture({ check: async () => { if (++checks === 3) throw new Error('owner fence lost'); } });
  await assert.rejects(fenced.service(fenced.scope), /owner fence lost/);
  assert.deepEqual(fenced.events, ['journals', 'destroy']);
});

test('replaying a partial cleanup with the same job is idempotent', async () => {
  const f = fixture();
  const first = await f.service(f.scope);
  const second = await f.service(f.scope);
  assert.deepEqual(second, first);
  assert.deepEqual(f.events, ['journals', 'destroy', 'reread', 'journals', 'destroy', 'reread']);
});

test('invalid scope is rejected without journal or database queries', async () => {
  for (const bad of [{ subjectId: 0 }, { subjectId: owner, jobId: 'not-a-uuid' }, { subjectId: owner, jobId, check: null }]) {
    const f = fixture();
    await assert.rejects(f.service({ ...f.scope, ...bad }), TypeError);
    assert.equal(f.cleanCalls, 0); assert.equal(f.poolCalls, 0);
  }
});
