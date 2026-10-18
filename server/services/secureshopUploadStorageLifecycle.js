"use strict";

const fs = require('node:fs/promises');
const {
  constants
} = require('node:fs');
const path = require('node:path');
const {
  createHash
} = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest = value => createHash('sha256').update(value).digest('hex');
function fail() {
  throw Object.assign(new Error('Owned upload storage cannot be reconciled'), {
    code: 'UPLOAD_STORAGE_UNSAFE'
  });
}
function createSecureShopUploadStorageLifecycle({
  root,
  fsApi = fs
} = {}) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || root.includes('\0')) fail();
  const base = path.resolve(root),
    operations = path.join(base, 'operations'),
    quarantine = path.join(base, '.quarantine'),
    cleanup = path.join(base, '.cleanup');
  const key = value => {
    if (typeof value !== 'string' || value.length !== 36 || !UUID.test(value)) fail();
    return value;
  };
  async function stat(p) {
    try {
      return await fsApi.lstat(p);
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      throw e;
    }
  }
  async function directory(p) {
    const s = await stat(p);
    if (!s || !s.isDirectory() || s.isSymbolicLink()) fail();
    if ((p === base || p.startsWith(base + path.sep)) && ((s.mode & 0o022) !== 0 || s.uid !== process.getuid())) fail();
    return s;
  }
  async function chain(p, create = false) {
    const parsed = path.parse(p);
    let current = parsed.root;
    for (const part of p.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, part);
      if (create && !(await stat(current))) {
        await fsApi.mkdir(current, {
          mode: 0o700
        });
      }
      await directory(current);
    }
  }
  async function roots() {
    await chain(base, true);
    for (const p of [operations, quarantine, cleanup]) await chain(p, true);
  }
  async function syncDir(p) {
    const h = await fsApi.open(p, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      await h.sync();
    } finally {
      await h.close();
    }
  }
  async function read(p, max = 20 * 1024 * 1024) {
    await chain(path.dirname(p));
    const before = await stat(p);
    if (!before || !before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.uid !== process.getuid() || before.mode & 0o022 || before.size > max) fail();
    const h = await fsApi.open(p, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const s = await h.stat();
      if (s.dev !== before.dev || s.ino !== before.ino || s.nlink !== 1 || s.size !== before.size) fail();
      const bytes = await h.readFile();
      if (bytes.length !== s.size) fail();
      return bytes;
    } finally {
      await h.close();
    }
  }
  async function scan(container) {
    await chain(container);
    const entries = [];
    let size = 0;
    async function walk(p, relative, depth) {
      if (depth > 5 || entries.length > 16) fail();
      for (const name of (await fsApi.readdir(p)).sort()) {
        if (entries.length >= 16) fail();
        const next = path.join(p, name),
          rel = relative ? `${relative}/${name}` : name,
          s = await stat(next);
        if (!s || s.isSymbolicLink()) fail();
        if (s.isDirectory()) {
          await directory(next);
          entries.push({
            path: rel,
            type: 'directory'
          });
          await walk(next, rel, depth + 1);
        } else {
          const bytes = await read(next);
          size += bytes.length;
          if (size > 20 * 1024 * 1024) fail();
          entries.push({
            path: rel,
            type: 'file',
            size: bytes.length,
            sha256: digest(bytes)
          });
        }
      }
    }
    await walk(container, '', 0);
    return entries;
  }
  function receipt(admission, action, entries = []) {
    return Object.freeze({
      action,
      receiptSha256: digest(JSON.stringify(['bound-upload-storage-reconciliation-v2', admission.operationId, admission.storageKey, admission.bindingSha256, admission.requestSha256, action, entries]))
    });
  }
  async function reconcile(admission) {
    await roots();
    const storageKey = key(admission.storageKey),
      active = path.join(operations, storageKey),
      held = path.join(quarantine, storageKey);
    const a = await stat(active),
      q = await stat(held);
    if (a && q) fail();
    if (a) {
      const entries = await scan(active);
      await fsApi.rename(active, held);
      await syncDir(operations);
      await syncDir(quarantine);
      if (JSON.stringify(await scan(held)) !== JSON.stringify(entries)) fail();
      return receipt(admission, 'quarantined', entries);
    }
    if (q) return receipt(admission, 'quarantined', await scan(held));
    return receipt(admission, 'deleted');
  }
  async function marker(p, expected) {
    const prior = await stat(p);
    if (prior) {
      if ((await read(p, 32768)).toString() !== expected) fail();
      return;
    }
    const pending = `${p}.pending`,
      existing = await stat(pending);
    if (existing) {
      const bytes = await read(pending, 32768);
      if (!expected.startsWith(bytes.toString())) fail();
    }
    const h = await fsApi.open(pending, constants.O_WRONLY | constants.O_NOFOLLOW | (existing ? 0 : constants.O_CREAT | constants.O_EXCL), 0o600);
    try {
      const s = await h.stat();
      if (!s.isFile() || s.nlink !== 1 || s.uid !== process.getuid() || s.mode & 0o077) fail();
      await h.truncate(0);
      await h.writeFile(expected);
      await h.sync();
    } finally {
      await h.close();
    }
    await fsApi.rename(pending, p);
    await syncDir(cleanup);
  }
  async function removeCompleted(admission, effect, cleanupOperationId) {
    await roots();
    key(cleanupOperationId);
    const storageKey = key(admission.storageKey),
      active = path.join(operations, storageKey),
      held = path.join(cleanup, `${storageKey}.data`),
      record = path.join(cleanup, `${storageKey}.json`);
    if (effect.outcome !== 'completed' || effect.file?.storageKey !== storageKey) fail();
    const traversal = effect.file.isTraversal === true,
      prefix = traversal ? `operations/${storageKey}/avatars/` : `operations/${storageKey}/avatars/${admission.scope.shopUserId}/`,
      stored = effect.file.storedVirtualPath;
    if (typeof stored !== 'string' || !stored.startsWith(prefix)) fail();
    const name = stored.slice(prefix.length);
    if (!name || ['.', '..'].includes(name) || /[\\/\0]/.test(name)) fail();
    if (traversal) {
      const base = `operations/${storageKey}/avatars/${admission.scope.shopUserId}`;
      if (effect.file.baseVirtualPath !== base || !effect.file.resolvedVirtualPath.startsWith(`${base}/../`)
          || path.posix.normalize(effect.file.resolvedVirtualPath) !== stored) fail();
    }
    const expectedEntries = [{
      path: 'avatars',
      type: 'directory'
    }, ...(traversal ? [{
      path: `avatars/${admission.scope.shopUserId}`,
      type: 'directory'
    }, {
      path: `avatars/${name}`,
      type: 'file',
      size: effect.file.byteCount,
      sha256: effect.file.bodySha256
    }].sort((left, right) => {
      const a = left.path.split('/').at(-1), b = right.path.split('/').at(-1);
      return a < b ? -1 : a > b ? 1 : 0;
    }) : [{
      path: `avatars/${admission.scope.shopUserId}`,
      type: 'directory'
    }, {
      path: `avatars/${admission.scope.shopUserId}/${name}`,
      type: 'file',
      size: effect.file.byteCount,
      sha256: effect.file.bodySha256
    }])];
    const expected = JSON.stringify({
      version: 1,
      cleanupOperationId,
      operationId: admission.operationId,
      storageKey,
      bindingSha256: admission.bindingSha256,
      requestSha256: admission.requestSha256,
      effectSha256: effect.effectSha256,
      entries: expectedEntries
    });
    if (await stat(path.join(quarantine, storageKey))) fail();
    let a = await stat(active),
      h = await stat(held);
    if (a && h) fail();
    const prior = await stat(record),
      pending = await stat(`${record}.pending`);
    if (!prior && !pending) {
      if (!a || h || JSON.stringify(await scan(active)) !== JSON.stringify(expectedEntries)) fail();
    }
    await marker(record, expected);
    // An intent permits only this exact operation's original file and ancestor directories.
    // Empty/subset trees are valid after a process stopped between individual removals.
    if (a) {
      if (JSON.stringify(await scan(active)) !== JSON.stringify(expectedEntries)) fail();
      await fsApi.rename(active, held);
      await syncDir(operations);
      await syncDir(cleanup);
      h = await stat(held);
    }
    if (h) {
      const entries = await scan(held);
      for (const entry of entries) {
        if (!expectedEntries.some(e => JSON.stringify(e) === JSON.stringify(entry))) fail();
      }
      for (const entry of [...entries].reverse()) {
        const p = path.join(held, entry.path);
        if (entry.type === 'file') {
          await fsApi.unlink(p);
          await syncDir(path.dirname(p));
        } else {
          await fsApi.rmdir(p);
          await syncDir(path.dirname(p));
        }
      }
      await fsApi.rmdir(held);
      await syncDir(cleanup);
    }
  }
  return Object.freeze({
    reconcile,
    removeCompleted,
    async verifyReconciliation(admission, expected) {
      const actual = await reconcile(admission);
      if (actual.action !== expected.action || actual.receiptSha256 !== expected.receiptSha256) fail();
      return actual;
    }
  });
}
module.exports = {
  createSecureShopUploadStorageLifecycle
};
