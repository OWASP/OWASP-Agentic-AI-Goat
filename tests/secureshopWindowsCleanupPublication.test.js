'use strict';
// Controlled platform-branch and real local filesystem tests; not a Windows run.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { createSecureShopFiles } = require('../sidecars/sandbox-runner/secureshopFiles');
const { createSecureShopFileCleanupReceiptReader } = require('../server/services/secureshopFileCleanupReceiptReader');
function platformFiles(root, platform, options = {}) {
  const original = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { ...original, value: platform });
  try { return createSecureShopFiles({ root, ...options }); }
  finally { Object.defineProperty(process, 'platform', original); }
}
async function fixture(t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-windows-cleanup-control-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const binding = { targetId: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(), generation: 4, ownerId: '17' };
  const operationId = randomUUID(), coordinates = { version: 1, ...binding, operationId };
  const scope = { targetKind: 'files', targetId: binding.targetId, launchId: binding.launchId,
    scenarioId: binding.scenarioId, fromGeneration: 4, platformOwnerId: 17, platformSessionId: 29, operationId };
  const files = platformFiles(root, 'win32'); await files.provisionReservedTarget(binding);
  const authorize = async requested => { assert.deepEqual(requested, coordinates); return true; };
  return { root, binding, operationId, coordinates, scope, files, authorize,
    journal: path.join(root, '.cleanup-' + binding.targetId + '.json'),
    container: path.join(root, 'target-' + binding.targetId),
    cleanupAuthority: { async checkTarget(actual) { assert.deepEqual(actual, scope); return { status: 'fenced' }; } } };
}
test('Windows v2 cleanup records file-synced rename/readback without directory flush and projects exact proof', async t => {
  const f = await fixture(t), originalOpen = fs.open, directoryFlag = require('node:fs').constants.O_DIRECTORY;
  let directoryOpens = 0;
  fs.open = async (filename, flags, ...args) => {
    if (directoryFlag && typeof flags === 'number' && (flags & directoryFlag)) { directoryOpens++; throw Error('Windows directory flush unavailable'); }
    return originalOpen(filename, flags, ...args);
  };
  let receipt;
  try { receipt = await f.files.retireReservedTarget(f.binding, { operationId: f.operationId, authorize: f.authorize }); }
  finally { fs.open = originalOpen; }
  assert.equal(directoryOpens, 0); assert.equal(receipt.version, 2);
  assert.equal(receipt.durabilityMode, 'file_synced_rename_verified');
  await assert.rejects(fs.stat(f.container), { code: 'ENOENT' });
  assert.deepEqual(JSON.parse(await fs.readFile(f.journal, 'utf8')), receipt);
  const cold = platformFiles(f.root, 'win32');
  assert.deepEqual(await cold.readReservedCleanupReceipt(f.binding,
    { operationId: f.operationId, authorize: f.authorize }), receipt);
  const projected = await createSecureShopFileCleanupReceiptReader({ files: cold, cleanupAuthority: f.cleanupAuthority })(f.scope);
  assert.equal(projected.receiptSha256, receipt.receiptSha256); assert.equal(projected.version, 1);
});
test('authorized pending v1 advances to v2 while denial preserves its exact bytes and target', async t => {
  const f = await fixture(t), pending = JSON.stringify({ ...f.coordinates, status: 'pending' }) + '\n';
  await fs.writeFile(f.journal, pending);
  await assert.rejects(f.files.retireReservedTarget(f.binding,
    { operationId: f.operationId, authorize: async () => false }), { code: 'CLEANUP_NOT_AUTHORIZED' });
  assert.equal(await fs.readFile(f.journal, 'utf8'), pending); assert.ok((await fs.stat(f.container)).isDirectory());
  const receipt = await f.files.retireReservedTarget(f.binding, { operationId: f.operationId, authorize: f.authorize });
  assert.equal(receipt.version, 2); assert.equal(receipt.durabilityMode, 'file_synced_rename_verified');
});
test('completed historical POSIX v1 remains byte-identical when read or retired from Windows', async t => {
  const f = await fixture(t), posix = platformFiles(f.root, 'linux');
  const receipt = await posix.retireReservedTarget(f.binding, { operationId: f.operationId, authorize: f.authorize });
  assert.equal(receipt.version, 1); assert.equal(Object.hasOwn(receipt, 'durabilityMode'), false);
  const bytes = await fs.readFile(f.journal), windows = platformFiles(f.root, 'win32');
  assert.deepEqual(await windows.readReservedCleanupReceipt(f.binding,
    { operationId: f.operationId, authorize: f.authorize }), receipt);
  assert.deepEqual(await windows.retireReservedTarget(f.binding,
    { operationId: f.operationId, authorize: f.authorize }), receipt);
  assert.deepEqual(await fs.readFile(f.journal), bytes);
});
test('no-op removal cannot publish completion; pending v2 resumes after exact target absence', async t => {
  const f = await fixture(t), failed = platformFiles(f.root, 'win32', { removeTree: async () => {} });
  await assert.rejects(failed.retireReservedTarget(f.binding,
    { operationId: f.operationId, authorize: f.authorize }), { code: 'RESERVED_CLEANUP_FAILED' });
  const pending = JSON.parse(await fs.readFile(f.journal, 'utf8'));
  assert.equal(pending.status, 'pending'); assert.equal(pending.version, 2);
  await assert.rejects(failed.readReservedCleanupReceipt(f.binding,
    { operationId: f.operationId, authorize: f.authorize }), { code: 'CLEANUP_RECEIPT_UNAVAILABLE' });
  assert.ok((await fs.stat(f.container)).isDirectory());
  const resumed = platformFiles(f.root, 'win32');
  const receipt = await resumed.retireReservedTarget(f.binding,
    { operationId: f.operationId, authorize: f.authorize });
  assert.equal(receipt.status, 'completed'); await assert.rejects(fs.stat(f.container), { code: 'ENOENT' });
});
test('cleanup mode, version, digest and exact target absence are independently checked', async t => {
  const f = await fixture(t), receipt = await f.files.retireReservedTarget(f.binding,
    { operationId: f.operationId, authorize: f.authorize });
  for (const delta of [{ durabilityMode: 'directory_synced' }, { version: 3 }, { receiptSha256: 'a'.repeat(64) }]) {
    await fs.writeFile(f.journal, JSON.stringify({ ...receipt, ...delta }));
    await assert.rejects(f.files.readReservedCleanupReceipt(f.binding,
      { operationId: f.operationId, authorize: f.authorize }), { code: 'TARGET_RECONCILIATION_REQUIRED' });
    const reader = createSecureShopFileCleanupReceiptReader({ cleanupAuthority: f.cleanupAuthority,
      files: { async readReservedCleanupReceipt() { return { ...receipt, ...delta }; } } });
    await assert.rejects(reader(f.scope), { code: 'TARGET_RECEIPT_MISMATCH' });
  }
  await fs.writeFile(f.journal, JSON.stringify(receipt)); await fs.mkdir(f.container);
  await assert.rejects(f.files.readReservedCleanupReceipt(f.binding,
    { operationId: f.operationId, authorize: f.authorize }), { code: 'TARGET_RECONCILIATION_REQUIRED' });
});
test('pending journal survives a removal error with no completed receipt and sibling unchanged', async t => {
  const f = await fixture(t), sibling = { ...f.binding, targetId: randomUUID(), ownerId: '18' };
  const siblingTarget = await f.files.provisionReservedTarget(sibling);
  await f.files.writeFile(siblingTarget.capability, '/uploads/keep.txt', 'unchanged', { expectedGeneration: 4 });
  const failed = platformFiles(f.root, 'win32', { removeTree: async () => { throw Error('controlled removal failure'); } });
  await assert.rejects(failed.retireReservedTarget(f.binding,
    { operationId: f.operationId, authorize: f.authorize }), { code: 'RESERVED_CLEANUP_FAILED' });
  const pending = JSON.parse(await fs.readFile(f.journal, 'utf8'));
  assert.equal(pending.status, 'pending'); assert.equal(pending.version, 2);
  assert.equal((await f.files.readFile(siblingTarget.capability, '/uploads/keep.txt', { expectedGeneration: 4 })).data.toString(), 'unchanged');
});
