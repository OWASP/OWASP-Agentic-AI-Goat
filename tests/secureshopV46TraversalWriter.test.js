'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { createSecureShopV46TraversalWriter } = require('../server/services/secureshopV46TraversalWriter');
const { createUploadTools } = require('../agent-host/agents/uploads/tools');

async function fixture(t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'ss-v46-writer-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const environment = { SECURESHOP_UPLOAD_ROOT: root };
  return { root, environment, writer: createSecureShopV46TraversalWriter({ environment, createTools: createUploadTools }) };
}

const input = overrides => ({
  operationId: randomUUID(),
  storageKey: randomUUID(),
  shopUserId: 41,
  bytes: Buffer.from('owned-v46-synthetic'),
  filename: '....//escaped-v46.txt',
  mime: 'text/plain',
  signal: new AbortController().signal,
  ...overrides
});

test('V46 writer proves the unchanged single-pass sink escaped only the owned avatar subdirectory', async t => {
  const f = await fixture(t), raw = input();
  const result = await f.writer.writeAndReadBack(raw);
  assert.equal(result.isTraversal, true);
  assert.equal(result.cleanedFilename, '../escaped-v46.txt');
  assert.equal(result.baseVirtualPath, `operations/${raw.storageKey}/avatars/${raw.shopUserId}`);
  assert.equal(result.resolvedVirtualPath, `operations/${raw.storageKey}/avatars/${raw.shopUserId}/../escaped-v46.txt`);
  assert.equal(result.storedVirtualPath, `operations/${raw.storageKey}/avatars/escaped-v46.txt`);
  assert.deepEqual(await fs.readFile(path.join(f.root, result.storedVirtualPath)), raw.bytes);
  assert.deepEqual(await fs.readdir(path.join(f.root, 'operations')), [raw.storageKey]);
});

test('V46 writer rejects non-traversal, host escape, sibling-operation and replay inputs', async t => {
  const f = await fixture(t);
  await assert.rejects(f.writer.writeAndReadBack(input({ filename: 'ordinary.txt' })), { code: 'INVALID_ARGUMENT' });
  await assert.rejects(f.writer.writeAndReadBack(input({ filename: '/tmp/escape.txt' })), { code: 'INVALID_ARGUMENT' });
  await assert.rejects(f.writer.writeAndReadBack(input({ filename: '....//....//....//escape.txt' })), { code: 'INVALID_ARGUMENT' });
  const unsupported = input({ filename: '....//....//owned-but-unsupported.txt' });
  await assert.rejects(f.writer.writeAndReadBack(unsupported), { code: 'INVALID_ARGUMENT' });
  await assert.rejects(fs.access(path.join(f.root, 'operations', unsupported.storageKey)), { code: 'ENOENT' });
  const raw = input();
  await f.writer.writeAndReadBack(raw);
  await assert.rejects(f.writer.writeAndReadBack(raw), { code: 'BOUND_UPLOAD_OUTCOME_UNCERTAIN' });
});

test('V46 reader rejects symlinked traversal destinations and changed bytes', async t => {
  const f = await fixture(t), raw = input();
  const result = await f.writer.writeAndReadBack(raw);
  const file = path.join(f.root, result.storedVirtualPath);
  await fs.writeFile(file, Buffer.from('changed-v46-synthetic'));
  const reader = require('../server/services/secureshopV46TraversalAssetReader')
    .createSecureShopV46TraversalAssetReader({ environment: f.environment });
  await assert.rejects(reader({ storedVirtualPath: result.storedVirtualPath,
    responseByteCount: result.byteCount, responseSha256: result.bodySha256 }), /UPLOAD_ASSET_BYTES_CHANGED/);
  await fs.rm(file);
  await fs.symlink(path.join(f.root, 'outside'), file);
  await assert.rejects(reader({ storedVirtualPath: result.storedVirtualPath,
    responseByteCount: result.byteCount, responseSha256: result.bodySha256 }), /UPLOAD_ASSET_PATH_UNAVAILABLE/);
});
