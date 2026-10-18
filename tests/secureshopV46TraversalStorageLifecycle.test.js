'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { createSecureShopUploadStorageLifecycle } = require('../server/services/secureshopUploadStorageLifecycle');
const { createSecureShopV46TraversalWriter } = require('../server/services/secureshopV46TraversalWriter');

const sha = value => createHash('sha256').update(value).digest('hex');
async function fixture(t, filename = '....//!escaped-v46.txt') {
  const root = await fs.realpath(await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'ss-v46-cleanup-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const bytes = Buffer.from('owned-v46-cleanup');
  const admission = {
    operationId: randomUUID(), storageKey: randomUUID(),
    bindingSha256: 'a'.repeat(64), requestSha256: 'b'.repeat(64),
    scope: { shopUserId: 41 }, request: { byteCount: bytes.length, bodySha256: sha(bytes) }
  };
  const written = await createSecureShopV46TraversalWriter({
    environment: { SECURESHOP_UPLOAD_ROOT: root }
  }).writeAndReadBack({
    operationId: admission.operationId, storageKey: admission.storageKey, shopUserId: 41,
    bytes, filename, mime: 'text/plain', signal: new AbortController().signal
  });
  const effect = {
    outcome: 'completed', effectSha256: 'c'.repeat(64),
    file: { storageKey: admission.storageKey, originalFilename: filename,
      declaredMime: 'text/plain', ...written }
  };
  return { root, bytes, admission, effect, storage: createSecureShopUploadStorageLifecycle({ root }) };
}

test('V46 completed cleanup removes only the escaped file operation tree and is idempotent', async t => {
  const x = await fixture(t);
  const sibling = path.join(x.root, 'operations', randomUUID());
  await fs.mkdir(sibling);
  await fs.writeFile(path.join(sibling, 'sentinel'), x.bytes, { mode: 0o600 });
  const cleanupId = randomUUID();
  await x.storage.removeCompleted(x.admission, x.effect, cleanupId);
  await x.storage.removeCompleted(x.admission, x.effect, cleanupId);
  assert.deepEqual(await fs.readFile(path.join(sibling, 'sentinel')), x.bytes);
  await assert.rejects(fs.lstat(path.join(x.root, 'operations', x.admission.storageKey)));
});

test('V46 cleanup rejects path substitution, changed bytes and extra files before deleting', async t => {
  const x = await fixture(t);
  await assert.rejects(x.storage.removeCompleted(x.admission, {
    ...x.effect,
    file: { ...x.effect.file, storedVirtualPath: `operations/${randomUUID()}/avatars/!escaped-v46.txt` }
  }, randomUUID()));
  const file = path.join(x.root, x.effect.file.storedVirtualPath);
  await fs.writeFile(file, 'changed');
  await assert.rejects(x.storage.removeCompleted(x.admission, x.effect, randomUUID()));
  await fs.writeFile(file, x.bytes);
  await fs.writeFile(path.join(x.root, 'operations', x.admission.storageKey, 'avatars', 'foreign'), 'preserve');
  await assert.rejects(x.storage.removeCompleted(x.admission, x.effect, randomUUID()));
  assert.equal(await fs.readFile(path.join(x.root, 'operations', x.admission.storageKey, 'avatars', 'foreign'), 'utf8'), 'preserve');
});

test('V46 cleanup rejects symlink and hardlink escape without mutating foreign bytes', async t => {
  const x = await fixture(t, '....//escaped-v46.txt');
  const file = path.join(x.root, x.effect.file.storedVirtualPath);
  const foreign = path.join(x.root, 'foreign');
  await fs.mkdir(foreign);
  await fs.writeFile(path.join(foreign, 'sentinel'), 'preserve');
  await fs.link(file, path.join(foreign, 'linked'));
  await assert.rejects(x.storage.removeCompleted(x.admission, x.effect, randomUUID()));
  assert.equal(await fs.readFile(path.join(foreign, 'sentinel'), 'utf8'), 'preserve');
});
