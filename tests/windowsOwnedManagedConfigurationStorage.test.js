'use strict';
// Memory-backed native/SQL/service boundaries. These controls do not execute
// PowerShell, PostgreSQL, Docker, or claim Windows namespace durability.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const core = require('../server/services/mcp/ownedManagedConfiguration');
const { createWindowsProvisioningJournal } = require('../scripts/lib/windows-provisioning-journal');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const missing = () => Object.assign(Error('absent'), { code: 'ENOENT' });

function configuration(kind, enabled = false) {
  const profile = `dvaia-owned-${kind}-${'a'.repeat(12)}`;
  return { version: 1, enabled, url: 'http://127.0.0.1:8094', token: 'x'.repeat(64), profile,
    container: profile, image: `sha256:${'b'.repeat(64)}`, ...(kind === 'shadow' ? { runtimeDigest: enabled ? 'c'.repeat(64) : null } : {}) };
}
function fixture(kind = 'http') {
  const file = String.raw`C:\Users\Alice\.dvaia\aaaaaaaaaaaa\mcp-owned-${kind}.json`, parent = path.win32.dirname(file);
  const files = new Map(), intents = new Map(), calls = [], flags = {};
  let sequence = 1, directoryId = '1111111111111111';
  const identity = () => ({ volumeSerial: 1, fileId: (++sequence).toString(16).padStart(16, '0') });
  const put = (name, bytes) => { files.set(name, { bytes: Buffer.from(bytes), identity: identity() }); };
  put(file, JSON.stringify(configuration(kind)) + '\n');
  const snapshot = name => {
    calls.push(['read', name]); if (flags.denyRead || flags.denyTarget && name === file) throw Error('PRIVATE_TOKEN_DIAGNOSTIC');
    const value = files.get(name); if (!value) throw missing();
    return { path: name, size: value.bytes.length, identity: { ...value.identity }, bytes: Buffer.from(value.bytes) };
  };
  const privateState = {
    inspectPrivateDirectory(name) {
      calls.push(['directory', name]); assert.equal(name, parent);
      if (flags.denyDirectory) throw Error('PRIVATE_TOKEN_DIAGNOSTIC');
      return { path: parent, size: null, identity: { volumeSerial: 1, fileId: directoryId } };
    },
    readPrivateFileSnapshot: snapshot, readAndFlushPrivateFileSnapshot: snapshot,
    readPrivateFile: name => snapshot(name).bytes,
    createPrivateFile(name, bytes) {
      calls.push(['create', name]); if (files.has(name)) throw Object.assign(Error('PRIVATE_TOKEN_DIAGNOSTIC'), { code: 'EEXIST' });
      put(name, bytes); if (flags.ambiguousCreate) throw Error('PRIVATE_TOKEN_DIAGNOSTIC');
      const value = files.get(name); return { path: name, size: value.bytes.length, identity: { ...value.identity } };
    },
    deleteMatchingPrivateFile(name, bytes, expected) {
      calls.push(['delete', name]); const value = files.get(name);
      assert(value && value.bytes.equals(bytes)); assert.deepEqual(value.identity, expected);
      if (flags.denyDelete) throw Error('PRIVATE_TOKEN_DIAGNOSTIC');
      if (!flags.retainedName) files.delete(name);
      return { path: name, size: bytes.length, identity: expected, deleted: true };
    },
  };
  const fileSystem = {
    lstatSync(name) { if (flags.denyObservation) throw Object.assign(Error('PRIVATE_TOKEN_DIAGNOSTIC'), { code: 'EACCES' }); if (!files.has(name)) throw missing(); return { isFile: () => true }; },
    openSync() { throw Error('POSIX open must not run'); }, readFileSync() { throw Error('raw private read must not run'); },
  };
  const publication = {
    preparePrivatePublication(value) {
      calls.push(['prepare', value]); const current = files.get(value.targetPath);
      assert(value.originalBytes === null ? !current : current && current.bytes.equals(value.originalBytes), 'exact old bytes required');
      const retained = intents.get(value.intentPath);
      if (retained) { assert(retained.resultBytes.equals(value.resultBytes)); assert(retained.originalBytes.equals(value.originalBytes)); return retained.receipt; }
      const receipt = { state: 'prepared', identity: identity(), size: value.resultBytes.length, intentSha256: hash(value.resultBytes) };
      intents.set(value.intentPath, { ...value, resultBytes: Buffer.from(value.resultBytes), originalBytes: Buffer.from(value.originalBytes), receipt });
      return receipt;
    },
    publishPrivatePublication(binding) {
      calls.push(['publish', binding]); const retained = intents.get(binding.intentPath); assert(retained);
      if (flags.interrupt === 'before') throw Error('PRIVATE_TOKEN_DIAGNOSTIC');
      assert(files.get(binding.targetPath).bytes.equals(retained.originalBytes));
      files.set(binding.targetPath, { bytes: Buffer.from(retained.resultBytes), identity: retained.receipt.identity });
      if (flags.interrupt === 'after') throw Error('PRIVATE_TOKEN_DIAGNOSTIC');
      return { ...retained.receipt, state: 'committed' };
    },
  };
  const privateJournal = createWindowsProvisioningJournal({ platform: 'win32', privateState, publication });
  const module = require(`../server/services/mcp/owned${kind === 'http' ? 'Http' : 'Shadow'}ManagedConfiguration`);
  const loader = module.createManagedConfiguration({ filesystemPlatform: 'win32', privateState, fileSystem });
  const pool = { async query(sql, args) {
    calls.push(['sql', sql]);
    if (sql.includes('ledger')) {
      const folder = args[0].startsWith('008') ? 'identity-migrations' : 'workshop-migrations/mcp';
      return { rows: [{ checksum: flags.migrationMismatch ? 'bad' : hash(fs.readFileSync(path.resolve('db/postgres', folder, args[0]))) }] };
    }
    return { rows: [sql.includes('to_regclass') ? { name: 'controlled relation' } : { read: true, insert: true, publish: true, delete: false }] };
  } };
  const status = { ready: true, runtimeDigest: 'c'.repeat(64), manifestSha256: hash(fs.readFileSync('sidecars/sandbox-runner/owned-http/network-manifest.json')) };
  const service = { async readiness() {
    if (flags.replaceTarget) put(file, files.get(file).bytes);
    if (flags.replaceDirectory) directoryId = '2222222222222222';
    if (flags.replaceLock) put(file + '.activation-lock', Buffer.from('foreign'));
    return { ...status, ...(flags.serviceUnavailable ? { ready: false } : {}) };
  } };
  const proper = kind === 'http' ? 'Http' : 'Shadow';
  const activate = require(`../scripts/install/mcp-owned-${kind}-activate`)[`createOwned${proper}Activator`]({ filesystemPlatform: 'win32', privateState, privateJournal, fileSystem })[`activateOwned${proper}Candidate`];
  const args = { file, identityPool: pool, resourcePool: pool, identityMigrationPool: pool, resourceMigrationPool: pool,
    cli: { readiness: async () => ({ ready: !flags.cliUnavailable, runnerReady: true, isolation: 'bwrap-seccomp-v1' }) }, [kind === 'http' ? 'http' : 'shadow']: service };
  return { file, parent, loader, privateState, fileSystem, privateJournal, files, intents, calls, flags, put, status, activate: () => activate(args) };
}

for (const kind of ['http', 'shadow']) {
  test(`${kind} Windows loader admits bounded private snapshot and clones retained bytes`, () => {
    const f = fixture(kind), observed = f.loader.loadSnapshot({ file: f.file });
    assert.equal(observed.value.enabled, false); assert.equal(f.loader.load({ file: f.file }).token, 'x'.repeat(64));
    observed.bytes.fill(0); assert.equal(observed.bytes[0], '{'.charCodeAt(0));
    assert(f.calls.some(([name]) => name === 'directory'));
  });
  test(`${kind} Windows optional configuration requires admitted parent and fresh exact absence`, () => {
    const f = fixture(kind); f.files.delete(f.file); assert.equal(f.loader.load({ file: f.file }), null);
    for (const flag of ['denyDirectory', 'denyObservation']) {
      f.flags[flag] = true; assert.throws(() => f.loader.load({ file: f.file }), { code: `MCP_${kind.toUpperCase()}_CONFIGURATION_UNTRUSTED` }); delete f.flags[flag];
    }
    f.put(f.file, JSON.stringify(configuration(kind))); f.flags.denyRead = true;
    assert.throws(() => f.loader.load({ file: f.file }), error => !error.message.includes('PRIVATE_TOKEN_DIAGNOSTIC'));
  });
  test(`${kind} Windows loader denies malformed, oversize and unsafe paths`, () => {
    const f = fixture(kind);
    for (const bytes of ['{"token":"PRIVATE_SECRET"}', 'x'.repeat(16385)]) {
      f.put(f.file, bytes); assert.throws(() => f.loader.load({ file: f.file }), error => !error.message.includes('PRIVATE_SECRET'));
    }
    assert.throws(() => f.loader.load({ file: '\\server\share\private' }));
  });
  test(`${kind} Windows activation uses strict lock and exact retained original/result transition; repeat is read-only`, async () => {
    const f = fixture(kind), original = Buffer.from(f.files.get(f.file).bytes);
    assert.equal((await f.activate()).activationEnabled, true); assert.equal(f.loader.load({ file: f.file }).enabled, true);
    const intent = [...f.intents.values()][0]; assert(intent.originalBytes.equals(original));
    assert.equal(JSON.parse(intent.resultBytes).token, JSON.parse(original).token);
    const committed = Buffer.from(f.files.get(f.file).bytes); await f.activate();
    assert(f.files.get(f.file).bytes.equals(committed)); assert.equal(f.intents.size, 1);
    assert.equal(f.files.has(f.file + '.activation-lock'), false);
    assert.equal(f.calls.filter(([name]) => name === 'create').length, 2);
  });
  test(`${kind} Windows lock collision and ambiguous first acquisition never adopt or delete a retained lock`, async () => {
    for (const existing of [true, false]) {
      const f = fixture(kind); if (existing) f.put(f.file + '.activation-lock', 'foreign'); else f.flags.ambiguousCreate = true;
      await assert.rejects(f.activate(), error => !error.message.includes('PRIVATE_TOKEN_DIAGNOSTIC'));
      assert(f.files.has(f.file + '.activation-lock')); assert(!f.calls.some(([name]) => name === 'delete' || name === 'sql'));
      await assert.rejects(f.activate()); assert(!f.calls.some(([name]) => name === 'delete'));
    }
  });
  test(`${kind} Windows migration, CLI and service fences deny before publication`, async () => {
    for (const flag of ['migrationMismatch', 'cliUnavailable', 'serviceUnavailable']) {
      const f = fixture(kind); f.flags[flag] = true; const original = Buffer.from(f.files.get(f.file).bytes);
      await assert.rejects(f.activate()); assert(f.files.get(f.file).bytes.equals(original));
      assert.equal(f.intents.size, 0); assert.equal(f.files.has(f.file + '.activation-lock'), false);
    }
  });
  test(`${kind} Windows source identity, private parent and lock replacement refuse authority`, async () => {
    for (const flag of ['replaceTarget', 'replaceDirectory', 'replaceLock']) {
      const f = fixture(kind); f.flags[flag] = true; await assert.rejects(f.activate()); assert.equal(f.intents.size, 0);
      if (flag !== 'replaceTarget') { assert(f.files.has(f.file + '.activation-lock')); assert(!f.calls.some(([name]) => name === 'delete')); }
    }
  });
  test(`${kind} Windows interrupted transition retains uncertainty before and after promotion`, async () => {
    for (const phase of ['before', 'after']) {
      const f = fixture(kind); f.flags.interrupt = phase;
      await assert.rejects(f.activate(), { code: `MCP_${kind.toUpperCase()}_CONFIGURATION_PUBLICATION_UNCERTAIN` });
      assert.equal(f.intents.size, 1); assert.equal(JSON.parse(f.files.get(f.file).bytes).enabled, phase === 'after');
      assert.equal(f.files.has(f.file + '.activation-lock'), false);
      delete f.flags.interrupt; await f.activate(); assert.equal(f.intents.size, 1); assert.equal(f.loader.load({ file: f.file }).enabled, true);
    }
  });
  test(`${kind} Windows matching lock deletion requires observable named absence`, async () => {
    for (const flag of ['denyDelete', 'retainedName']) {
      const f = fixture(kind); f.flags[flag] = true; await assert.rejects(f.activate(), { code: `MCP_${kind.toUpperCase()}_CONFIGURATION_UNTRUSTED` });
      assert(f.files.has(f.file + '.activation-lock')); assert.equal(f.intents.size, 1);
    }
  });
}
test('shadow Windows repeat activation keeps immutable runtime pin', async () => {
  const f = fixture('shadow'); await f.activate(); const prior = Buffer.from(f.files.get(f.file).bytes); f.status.runtimeDigest = 'd'.repeat(64);
  await assert.rejects(f.activate(), /MCP_SHADOW_RUNTIME_CHANGED/); assert(f.files.get(f.file).bytes.equals(prior));
});
test('core Windows managed runner reader uses same admitted bounded snapshot and strict parser', () => {
  const f = fixture(), file = f.file.replace('mcp-owned-http.json', 'mcp-owned.env');
  const values = { ...core.EXACT, MCP_OWNED_TARGET_TOKEN: 'x'.repeat(64), MCP_OWNED_RESOURCES_ENABLED: 'false', CODEBOT_OWNED_EXECUTION_ENABLED: 'false' };
  f.put(file, Object.entries(values).map(([key, value]) => `${key}=${value}`).join('\n'));
  const loader = core.createManagedConfiguration({ filesystemPlatform: 'win32', privateState: f.privateState, fileSystem: f.fileSystem });
  assert.equal(loader.loadOwnedManagedConfiguration({ file }).MCP_OWNED_TARGET_TOKEN, 'x'.repeat(64));
  f.flags.denyRead = true; assert.throws(() => loader.loadOwnedManagedConfiguration({ file }), { code: 'MCP_MANAGED_CONFIGURATION_UNTRUSTED' });
  delete f.flags.denyRead; f.files.delete(file); assert.deepEqual(loader.loadOwnedManagedConfiguration({ file }), {});
  f.flags.denyDirectory = true; assert.throws(() => loader.loadOwnedManagedConfiguration({ file }));
});
