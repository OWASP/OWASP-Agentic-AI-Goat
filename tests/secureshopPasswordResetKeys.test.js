'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { ensurePasswordResetKey } = require('../scripts/lib/setup-password-reset-key');
const { loadPasswordResetKeys } = require('../server/services/secureshopPasswordResetKeys');
function directory(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-reset-key-test-'));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
test('explicit setup provisions a private key once and preserves its bytes on rerun', t => {
  const root = directory(t), first = ensurePasswordResetKey({ directory: root });
  assert.equal(first.created, true);
  const bytes = fs.readFileSync(first.filePath);
  assert.equal(fs.statSync(first.filePath).mode & 0o777, 0o600);
  const loaded = loadPasswordResetKeys(first);
  assert.equal(loaded.keys.get(loaded.activeKeyId).length, 32);
  loaded.keys.get(loaded.activeKeyId).fill(0);
  assert.deepEqual(ensurePasswordResetKey({ directory: root }), { filePath: first.filePath, created: false });
  assert.deepEqual(fs.readFileSync(first.filePath), bytes);
  assert.notDeepEqual(loadPasswordResetKeys(first).keys.get(loaded.activeKeyId), Buffer.alloc(32));
});
test('runtime missing or malformed keys fail without creating or replacing files', t => {
  const root = directory(t), filePath = path.join(root, 'secureshop-reset-key.json');
  assert.throws(() => loadPasswordResetKeys({ filePath }), { code: 'PASSWORD_RESET_KEY_UNAVAILABLE' });
  assert.equal(fs.existsSync(filePath), false);
  fs.writeFileSync(filePath, 'invalid existing private key', { mode: 0o600 });
  assert.throws(() => ensurePasswordResetKey({ directory: root }), { code: 'PASSWORD_RESET_KEY_UNAVAILABLE' });
  assert.equal(fs.readFileSync(filePath, 'utf8'), 'invalid existing private key');
});
test('rejects public keys, symlinks, hardlinks and non-private directory without following links', t => {
  const root = directory(t), key = ensurePasswordResetKey({ directory: root });
  fs.chmodSync(key.filePath, 0o644);
  assert.throws(() => loadPasswordResetKeys(key), { code: 'PASSWORD_RESET_KEY_UNAVAILABLE' });
  fs.chmodSync(key.filePath, 0o600);
  const link = path.join(root, 'link'); fs.symlinkSync(key.filePath, link);
  assert.throws(() => loadPasswordResetKeys({ filePath: link }), { code: 'PASSWORD_RESET_KEY_UNAVAILABLE' });
  fs.unlinkSync(link); fs.linkSync(key.filePath, link);
  assert.throws(() => loadPasswordResetKeys(key), { code: 'PASSWORD_RESET_KEY_UNAVAILABLE' });
  fs.unlinkSync(link); fs.chmodSync(root, 0o755);
  assert.throws(() => loadPasswordResetKeys(key), { code: 'PASSWORD_RESET_KEY_UNAVAILABLE' });
  fs.chmodSync(root, 0o700);
});
test('strict key schema rejects unknown fields, noncanonical material and unavailable active key', t => {
  const root = directory(t), key = ensurePasswordResetKey({ directory: root });
  const original = JSON.parse(fs.readFileSync(key.filePath));
  for (const value of [{ ...original, secret: 'extra' }, { ...original, activeKeyId: 'missing' },
    { ...original, keys: { [original.activeKeyId]: 'bad' } }, { ...original, version: 2 }]) {
    fs.writeFileSync(key.filePath, JSON.stringify(value));
    assert.throws(() => loadPasswordResetKeys(key), { code: 'PASSWORD_RESET_KEY_UNAVAILABLE' });
  }
});
test('concurrent explicit setup atomically publishes one complete key without staging debris', async t => {
  const root = directory(t);
  const execFile = require('node:util').promisify(require('node:child_process').execFile);
  const modulePath = require.resolve('../scripts/lib/setup-password-reset-key');
  const script = 'const r=require(process.argv[1]).ensurePasswordResetKey({directory:process.argv[2]});process.stdout.write(JSON.stringify({created:r.created}));';
  const results = await Promise.all(Array.from({ length: 6 }, () => execFile(process.execPath,
    ['-e', script, modulePath, root], { timeout: 10000, maxBuffer: 1024 })));
  assert.equal(results.filter(r => JSON.parse(r.stdout).created).length, 1);
  assert.deepEqual(fs.readdirSync(root), ['secureshop-reset-key.json']);
  const loaded = loadPasswordResetKeys({ filePath: path.join(root, 'secureshop-reset-key.json') });
  assert.equal(loaded.keys.size, 1);
});
test('runtime rejects a pathname replaced while its original descriptor is being read', t => {
  const root = directory(t), key = ensurePasswordResetKey({ directory: root });
  const original = fs.readFileSync(key.filePath), read = fs.readSync;
  t.mock.method(fs, 'readSync', (...args) => {
    const count = read(...args);
    fs.renameSync(key.filePath, path.join(root, 'previous-key.json'));
    fs.writeFileSync(key.filePath, original, { mode: 0o600 });
    return count;
  });
  assert.throws(() => loadPasswordResetKeys(key), { code: 'PASSWORD_RESET_KEY_UNAVAILABLE' });
});
test('setup revalidates publication when the staging link disappears after its first read', t => {
  const root = directory(t), key = ensurePasswordResetKey({ directory: root });
  const original = fs.readFileSync(key.filePath), stat = fs.fstatSync;
  let first = true;
  t.mock.method(fs, 'fstatSync', (...args) => {
    const result = stat(...args);
    if (first) { first = false; result.nlink = 2; }
    return result;
  });
  assert.equal(ensurePasswordResetKey({ directory: root }).created, false);
  assert.deepEqual(fs.readFileSync(key.filePath), original);
  assert.deepEqual(fs.readdirSync(root), ['secureshop-reset-key.json']);
});
