'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { createSecureShopFiles } = require('../sidecars/sandbox-runner/secureshopFiles');
const { createSecureShopFileCleanupReceiptReader } = require('../server/services/secureshopFileCleanupReceiptReader');

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-file-receipt-adapter-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const scope = Object.freeze({ targetKind: 'files', targetId: randomUUID(), launchId: randomUUID(),
    scenarioId: randomUUID(), fromGeneration: 4, platformOwnerId: 17, platformSessionId: 29,
    operationId: randomUUID() });
  const binding = { targetId: scope.targetId, launchId: scope.launchId, scenarioId: scope.scenarioId,
    generation: scope.fromGeneration, ownerId: String(scope.platformOwnerId) };
  const files = createSecureShopFiles({ root });
  const target = await files.provisionReservedTarget(binding);
  const cleanupAuthority = { async checkTarget(actual) {
    assert.deepEqual(actual, scope, 'only the durable original identity scope is authorized');
    return { status: 'fenced' };
  } };
  return { root, scope, binding, files, target, cleanupAuthority };
}

test('private file receipt adapter reads existing proof and cannot perform first cleanup', async t => {
  const f = await fixture(t);
  const read = createSecureShopFileCleanupReceiptReader(f);
  await assert.rejects(read(f.scope), { code: 'CLEANUP_RECEIPT_UNAVAILABLE' });
  assert.ok((await f.files.readFile(f.target.capability, '/etc/passwd')).bytes > 0);
  const raw = await f.files.retireReservedTarget(f.binding,
    { operationId: f.scope.operationId, authorize: async () => true });
  const receipt = await read(f.scope);
  assert.equal(receipt.kind, 'files');
  assert.equal(receipt.platformOwnerId, f.scope.platformOwnerId);
  assert.equal(receipt.platformSessionId, f.scope.platformSessionId);
  assert.equal(receipt.receiptSha256, raw.receiptSha256);
  assert.equal(receipt.completedAt, raw.completedAt);
  assert.equal(receipt.generation, f.scope.fromGeneration);
  assert.equal(JSON.stringify(receipt).includes(f.root), false);
  assert.equal(JSON.stringify(receipt).includes(f.target.capability), false);
  assert.deepEqual(await createSecureShopFileCleanupReceiptReader({
    files: createSecureShopFiles({ root: f.root }), cleanupAuthority: f.cleanupAuthority,
  })(f.scope), receipt);
});

test('wrong owner/session and kind cannot reach private target storage', async t => {
  const f = await fixture(t);
  let reads = 0;
  const read = createSecureShopFileCleanupReceiptReader({
    files: { async readReservedCleanupReceipt() { reads++; throw Error('unexpected read'); } },
    cleanupAuthority: f.cleanupAuthority,
  });
  for (const changed of [{ platformOwnerId: 18 }, { platformSessionId: 30 }, { targetKind: 'reviews' }]) {
    await assert.rejects(read({ ...f.scope, ...changed }));
  }
  assert.equal(reads, 0);
  for (const result of [undefined, false, {}, { status: 'active' }]) {
    const unavailable = createSecureShopFileCleanupReceiptReader({
      files: { async readReservedCleanupReceipt() { reads++; } },
      cleanupAuthority: { async checkTarget() { return result; } },
    });
    await assert.rejects(unavailable(f.scope), { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' });
  }
  assert.equal(reads, 0);
});

test('receipt projection rejects misrouting, digest corruption and authority loss after read', async t => {
  const f = await fixture(t);
  const raw = await f.files.retireReservedTarget(f.binding,
    { operationId: f.scope.operationId, authorize: async () => true });
  for (const corruption of [{ ownerId: '18' }, { receiptSha256: 'f'.repeat(64) }, { completedAt: '2026-09-13T00:00:00Z' }]) {
    const read = createSecureShopFileCleanupReceiptReader({ cleanupAuthority: f.cleanupAuthority,
      files: { async readReservedCleanupReceipt() { return { ...raw, ...corruption }; } } });
    await assert.rejects(read(f.scope), { code: 'TARGET_RECEIPT_MISMATCH' });
  }
  let checks = 0;
  const mutable = { ...f.scope };
  const read = createSecureShopFileCleanupReceiptReader({
    cleanupAuthority: { async checkTarget(actual) {
      assert.deepEqual(actual, f.scope);
      if (++checks === 2) throw Object.assign(new Error('authority ended'), { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' });
      return { status: 'fenced' };
    } },
    files: { async readReservedCleanupReceipt() { mutable.platformSessionId = 999; return raw; } },
  });
  await assert.rejects(read(mutable), { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' });
});
