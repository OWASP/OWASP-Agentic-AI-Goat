'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createSecureShopBoundAuditCleanup } = require(
  '../server/services/secureshopBoundAuditCleanup');

const JOB = '11111111-1111-4111-8111-111111111111';
const LEASE = '22222222-2222-4222-8222-222222222222';
const OWNER = 17;

function row(count = '2') {
  const receipt = ['secureshop-bound-audit-owner-deletion-v1', JOB, String(OWNER), String(count)]
    .join('\x1f');
  return { deletion_job_id: JOB, original_platform_owner_id: OWNER,
    deleted_event_count: String(count), receipt_sha256: crypto.createHash('sha256').update(receipt).digest() };
}

function pool(name, calls, receipt = row()) {
  return { async query(sql, values) {
    calls.push([name, sql.includes('destroy_bound_audit_owner') ? 'destroy' : 'read', values]);
    return { rows: [{ ...receipt }] };
  } };
}

test('bound audit cleanup destroys both owner journals and confirms immutable receipts', async () => {
  const calls = []; let checks = 0;
  const cleanup = createSecureShopBoundAuditCleanup({
    agentsPool: pool('agents', calls), reviewPool: pool('review', calls),
  });
  const scope = { subjectId: OWNER, jobId: JOB, leaseToken: LEASE,
    signal: new AbortController().signal, check: async () => { checks += 1; } };
  const expected = { deletionJobId: JOB, originalPlatformOwnerId: OWNER,
    deletedEventCount: '2', receiptSha256: row().receipt_sha256.toString('hex') };
  assert.deepEqual(await cleanup(scope), { completed: true, agents: expected, review: expected });
  assert.equal(checks, 5);
  assert.deepEqual(calls.map(([name, operation]) => [name, operation]), [
    ['agents', 'destroy'], ['review', 'destroy'], ['agents', 'read'], ['review', 'read'],
  ]);
  assert.deepEqual(calls.map(call => call[2]), [
    [OWNER, JOB], [OWNER, JOB], [JOB, OWNER], [JOB, OWNER],
  ]);

  assert.deepEqual(await cleanup(scope), { completed: true, agents: expected, review: expected },
    'the durable deletion job is safe to replay');
});

test('bound audit cleanup rejects malformed or changed receipts', async () => {
  for (const mutate of [
    value => { value.deletion_job_id = '33333333-3333-4333-8333-333333333333'; },
    value => { value.original_platform_owner_id = OWNER + 1; },
    value => { value.deleted_event_count = '-1'; },
    value => { value.receipt_sha256 = Buffer.alloc(32); },
  ]) {
    const bad = row(); mutate(bad);
    const cleanup = createSecureShopBoundAuditCleanup({
      agentsPool: pool('agents', [], bad), reviewPool: pool('review', []),
    });
    await assert.rejects(cleanup({ subjectId: OWNER, jobId: JOB, leaseToken: LEASE,
      check: async () => {} }), /receipt/);
  }

  let reads = 0;
  const changed = { async query(sql) {
    reads += 1;
    return { rows: [sql.includes('destroy_bound_audit_owner') ? row('2') : row('3')] };
  } };
  const cleanup = createSecureShopBoundAuditCleanup({
    agentsPool: changed, reviewPool: pool('review', []),
  });
  await assert.rejects(cleanup({ subjectId: OWNER, jobId: JOB, leaseToken: LEASE,
    check: async () => {} }), /changed/);
  assert.equal(reads, 2);
});

test('bound audit cleanup observes cancellation and lease loss between stores', async () => {
  const calls = []; let checks = 0;
  const cleanup = createSecureShopBoundAuditCleanup({
    agentsPool: pool('agents', calls), reviewPool: pool('review', calls),
  });
  await assert.rejects(cleanup({ subjectId: OWNER, jobId: JOB, leaseToken: LEASE,
    check: async () => { checks += 1; if (checks === 2) throw new Error('lease lost'); } }), /lease lost/);
  assert.deepEqual(calls.map(([name, operation]) => [name, operation]), [['agents', 'destroy']]);

  const controller = new AbortController(); controller.abort();
  await assert.rejects(cleanup({ subjectId: OWNER, jobId: JOB, leaseToken: LEASE,
    signal: controller.signal, check: async () => {} }), { name: 'AbortError' });
});

test('bound audit cleanup requires exact bounded dependencies and scope', async () => {
  assert.throws(() => createSecureShopBoundAuditCleanup({}), TypeError);
  const cleanup = createSecureShopBoundAuditCleanup({
    agentsPool: pool('agents', []), reviewPool: pool('review', []),
  });
  await assert.rejects(cleanup({ subjectId: 0, jobId: JOB, check: async () => {} }), TypeError);
  await assert.rejects(cleanup({ subjectId: OWNER, jobId: 'not-a-uuid', check: async () => {} }), TypeError);
});
