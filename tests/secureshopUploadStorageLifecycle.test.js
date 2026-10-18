"use strict";

const test = require('node:test'),
  assert = require('node:assert/strict'),
  fs = require('node:fs/promises'),
  os = require('node:os'),
  path = require('node:path'),
  crypto = require('node:crypto');
const {
  createSecureShopUploadStorageLifecycle
} = require('../server/services/secureshopUploadStorageLifecycle');
const id = n => `0000000${n}-0000-4000-8000-00000000000${n}`,
  bytes = Buffer.from('owned'),
  sha = crypto.createHash('sha256').update(bytes).digest('hex');
function admitted(n = 1) {
  return {
    operationId: id(n),
    storageKey: id(n + 1),
    bindingSha256: 'a'.repeat(64),
    requestSha256: 'b'.repeat(64),
    scope: {
      shopUserId: 9
    },
    request: {
      byteCount: bytes.length,
      bodySha256: sha
    }
  };
}
async function fixture(t) {
  const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'v06-storage-'));
  t.after(() => fs.rm(root, {
    recursive: true,
    force: true
  }));
  const a = admitted(),
    dir = path.join(root, 'operations', a.storageKey),
    file = path.join(dir, 'avatars', '9', 'x.html');
  await fs.mkdir(path.dirname(file), {
    recursive: true,
    mode: 0o700
  });
  await fs.writeFile(file, bytes, {
    mode: 0o600
  });
  const effect = {
    outcome: 'completed',
    effectSha256: 'c'.repeat(64),
    file: {
      storageKey: a.storageKey,
      storedVirtualPath: `operations/${a.storageKey}/avatars/9/x.html`,
      bodySha256: sha,
      byteCount: bytes.length
    }
  };
  return {
    root,
    a,
    dir,
    file,
    effect,
    storage: createSecureShopUploadStorageLifecycle({
      root
    })
  };
}
test('uncertain rename before journal acknowledgement is repeatable without a completed file effect', async t => {
  const x = await fixture(t),
    first = await x.storage.reconcile(x.a);
  assert.equal(first.action, 'quarantined');
  assert.deepEqual(await x.storage.reconcile(x.a), first);
  assert.deepEqual(await x.storage.verifyReconciliation(x.a, first), first);
  assert.equal((await fs.readFile(path.join(x.root, '.quarantine', x.a.storageKey, 'avatars/9/x.html'))).toString(), 'owned');
  await assert.rejects(fs.lstat(x.dir));
  assert.equal(first.effectId, undefined);
});
test('partial bytes and empty operation directories quarantine as uncertain without claiming exact upload bytes', async t => {
  const x = await fixture(t);
  await fs.writeFile(x.file, 'partial');
  assert.equal((await x.storage.reconcile(x.a)).action, 'quarantined');
  const other = admitted(3);
  await fs.mkdir(path.join(x.root, 'operations', other.storageKey));
  assert.equal((await x.storage.reconcile(other)).action, 'quarantined');
});
test('absent orphan is deleted; changed immutable quarantine receipt rejects', async t => {
  const x = await fixture(t);
  assert.equal((await x.storage.reconcile(admitted(3))).action, 'deleted');
  const prior = await x.storage.reconcile(x.a);
  await assert.rejects(x.storage.verifyReconciliation(x.a, {
    ...prior,
    receiptSha256: 'd'.repeat(64)
  }));
});
test('completed cleanup is idempotent and preserves an identical sibling', async t => {
  const x = await fixture(t),
    sibling = path.join(x.root, 'operations', id(4));
  await fs.mkdir(sibling);
  await fs.writeFile(path.join(sibling, 'sentinel'), bytes);
  await x.storage.removeCompleted(x.a, x.effect, id(8));
  await x.storage.removeCompleted(x.a, x.effect, id(8));
  assert.deepEqual(await fs.readFile(path.join(sibling, 'sentinel')), bytes);
  await assert.rejects(x.storage.removeCompleted(x.a, x.effect, id(7)));
});
for (const point of ['rename', 'marker', 'unlink', 'rmdir']) test(`completed cleanup resumes after crash following ${point}`, async t => {
  const x = await fixture(t);
  let hit = false;
  const fsApi = {
    ...fs,
    async [point === 'marker' ? 'rename' : point](...args) {
      const result = await fs[point === 'marker' ? 'rename' : point](...args);
      const selected = point === 'marker' ? args[1].endsWith('.json') : point !== 'rename' || args[1].endsWith('.data');
      if (selected && !hit) {
        hit = true;
        throw Error('injected crash');
      }
      return result;
    }
  };
  await assert.rejects(createSecureShopUploadStorageLifecycle({
    root: x.root,
    fsApi
  }).removeCompleted(x.a, x.effect, id(8)), /injected crash/);
  assert.equal(hit, true);
  await x.storage.removeCompleted(x.a, x.effect, id(8));
  await assert.rejects(fs.lstat(path.join(x.root, '.cleanup', `${x.a.storageKey}.data`)));
});
test('unknown file in interrupted cleanup blocks all further deletion', async t => {
  const x = await fixture(t),
    fsApi = {
      ...fs,
      async rename(a, b) {
        await fs.rename(a, b);
        if (b.endsWith('.data')) throw Error('crash');
      }
    };
  await assert.rejects(createSecureShopUploadStorageLifecycle({
    root: x.root,
    fsApi
  }).removeCompleted(x.a, x.effect, id(8)));
  const unknown = path.join(x.root, '.cleanup', `${x.a.storageKey}.data`, 'foreign');
  await fs.writeFile(unknown, 'preserve');
  await assert.rejects(x.storage.removeCompleted(x.a, x.effect, id(8)));
  assert.equal(await fs.readFile(unknown, 'utf8'), 'preserve');
});
test('symlinked operation ancestor, symlinked root and hardlink fail without foreign mutation', async t => {
  const x = await fixture(t),
    foreign = path.join(x.root, 'foreign');
  await fs.mkdir(foreign);
  await fs.writeFile(path.join(foreign, 'sentinel'), 'preserve');
  await fs.rename(path.join(x.dir, 'avatars'), path.join(x.root, 'saved'));
  await fs.symlink(foreign, path.join(x.dir, 'avatars'));
  await assert.rejects(x.storage.reconcile(x.a));
  assert.equal(await fs.readFile(path.join(foreign, 'sentinel'), 'utf8'), 'preserve');
  const alias = path.join(x.root, 'alias');
  await fs.symlink(foreign, alias);
  await assert.rejects(createSecureShopUploadStorageLifecycle({
    root: alias
  }).reconcile(x.a));
  await fs.unlink(path.join(x.dir, 'avatars'));
  await fs.rename(path.join(x.root, 'saved'), path.join(x.dir, 'avatars'));
  await fs.link(x.file, path.join(foreign, 'linked'));
  await assert.rejects(x.storage.removeCompleted(x.a, x.effect, id(8)));
  assert.deepEqual(await fs.readFile(x.file), bytes);
});
test('changed completed bytes, sibling path substitution and missing files fail before cleanup intent', async t => {
  const x = await fixture(t);
  await assert.rejects(x.storage.removeCompleted(x.a, {
    ...x.effect,
    file: {
      ...x.effect.file,
      storedVirtualPath: `operations/${id(4)}/avatars/9/x.html`
    }
  }, id(8)));
  await fs.writeFile(x.file, 'changed');
  await assert.rejects(x.storage.removeCompleted(x.a, x.effect, id(8)));
  await fs.unlink(x.file);
  await assert.rejects(x.storage.removeCompleted(x.a, x.effect, id(8)));
  await assert.rejects(fs.lstat(path.join(x.root, '.cleanup', `${x.a.storageKey}.json`)));
});
