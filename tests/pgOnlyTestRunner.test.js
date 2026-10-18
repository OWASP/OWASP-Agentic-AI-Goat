'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { isolatedDatabaseGuard, selectIsolatedTests } = require('../scripts/lib/isolated-test-selection');
const { discoveryReceipt, resultReceipt, writeJsonExclusive } = require('../scripts/lib/isolated-test-receipt');

const ROOT = path.resolve(__dirname, '..');
const GUARD = isolatedDatabaseGuard(ROOT);

function controlledEnvironment(extra = {}) {
  return { PATH: path.dirname(process.execPath), NODE_ENV: 'test', ...extra };
}

test('database preload denies real drivers while preserving injected factories and unrelated modules', () => {
  assert.equal(path.isAbsolute(GUARD), true);
  assert.equal(require.resolve(GUARD), GUARD);
  const script = String.raw`
    const assert=require('node:assert/strict');
    const net=require('node:net');
    const pg=require('pg');
    const pool=new pg.Pool();
    assert.throws(()=>pool.query('SELECT 1'),{code:'ISOLATED_DATABASE_ACCESS_DENIED'});
    const client=new pg.Client();
    assert.throws(()=>client.connect(),{code:'ISOLATED_DATABASE_ACCESS_DENIED'});
    const sqlite3=require('sqlite3');
    assert.throws(()=>new sqlite3.Database(':memory:'),{code:'ISOLATED_DATABASE_ACCESS_DENIED'});
    assert.throws(()=>sqlite3.cached.Database(':memory:'),{code:'ISOLATED_DATABASE_ACCESS_DENIED'});
    const Better=require('better-sqlite3');
    assert.throws(()=>new Better(':memory:'),{code:'ISOLATED_DATABASE_ACCESS_DENIED'});
    const {createPostgresSessionManager}=require('./server/middleware/postgresSessionManager');
    const manager=createPostgresSessionManager({repository:{cleanupExpiredSessions:async()=>0},validateSession:async()=>null});
    manager.stopCleanupTask();
    assert.equal(typeof net.connect,'function');
    process.stdout.write('controlled\n');
  `;
  const output = execFileSync(process.execPath, ['--require', GUARD, '-e', script], {
    cwd: ROOT, env: controlledEnvironment(), encoding: 'utf8', timeout: 10000,
  });
  assert.equal(output, 'controlled\n');
});

test('database preload rejects inherited application connection configuration without disclosing it', () => {
  const secret = 'postgresql://private.invalid/never-print-this';
  const result = spawnSync(process.execPath, ['--require', GUARD, '-e', 'process.stdout.write("unexpected")'], {
    cwd: ROOT, env: controlledEnvironment({ IDENTITY_DATABASE_URL: secret }), encoding: 'utf8', timeout: 10000,
  });
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /ISOLATED_DATABASE_ACCESS_DENIED|Controlled aggregate denies database access/);
  assert.doesNotMatch(result.stderr, /never-print-this|private\.invalid/);
});

test('focused selection is explicit and cannot cross unit or SecureShop boundaries', t => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'pg-runner-select-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const relative of ['tests/unit.test.js', 'tests/secureshop/unit/store.test.js']) {
    fs.mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    fs.writeFileSync(path.join(root, relative), `'use strict';\n`);
  }
  assert.deepEqual(selectIsolatedTests(root, 'unit', ['tests/unit.test.js']), ['tests/unit.test.js']);
  assert.deepEqual(selectIsolatedTests(root, 'secureshop', ['tests/secureshop/unit/store.test.js']),
    ['tests/secureshop/unit/store.test.js']);
  assert.throws(() => selectIsolatedTests(root, 'unit', ['tests/secureshop/unit/store.test.js']),
    /top-level/);
  assert.throws(() => selectIsolatedTests(root, 'secureshop', ['tests/unit.test.js']),
    /below tests\/secureshop/);
});

test('private receipts bind exact discovery and preserve focused limitations on failure', t => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'pg-runner-receipt-')));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const discovery = discoveryReceipt({ mode: 'unit', focused: true,
    files: ['tests/platformSessionValidity.test.js', 'tests/sessionManagerReview.test.js'],
    nodeExecutable: '/controlled/node', nodeVersion: 'v1.2.3', boundaryKind: 'controlled' });
  const discoveryFile = writeJsonExclusive(directory, 'discovery.json', discovery);
  const log = path.join(directory, 'tests.log');
  fs.writeFileSync(log, '# tests 2\n# pass 1\n# fail 1\n# skipped 0\n', { mode: 0o600, flag: 'wx' });
  const result = resultReceipt({ discovery, discoverySha256: discoveryFile.sha256,
    argv: ['--test', ...discovery.files], result: { code: 1, signal: null, timedOut: false }, testsLog: log });
  const deceptiveExit = resultReceipt({ discovery, discoverySha256: discoveryFile.sha256,
    argv: ['--test', ...discovery.files], result: { code: 0, signal: null, timedOut: false }, testsLog: log });
  const resultFile = writeJsonExclusive(directory, 'result.json', result);
  assert.equal(result.scope, 'focused');
  assert.equal(result.passed, false);
  assert.equal(deceptiveExit.passed, false);
  assert.match(result.limitation, /not an aggregate pass/);
  assert.equal(result.counts.fail, 1);
  assert.equal(fs.statSync(discoveryFile.path).mode & 0o777, 0o600);
  assert.equal(fs.statSync(resultFile.path).mode & 0o777, 0o600);
  assert.throws(() => writeJsonExclusive(directory, 'result.json', result), /EEXIST/);
});

test('default runner source has no legacy initializer and records guarded aggregate results', () => {
  const source = fs.readFileSync(path.join(ROOT, 'scripts/test-isolated.js'), 'utf8');
  assert.doesNotMatch(source, /db\/initialize-db\/run-all\.js|initialization\.log/);
  assert.match(source, /artifactEnvironment\(destination\)/);
  assert.match(source, /PLATFORM_DATABASE_ENGINE: 'postgres'/);
  assert.match(source, /WORKSHOP_DATABASE_ENGINE: 'postgres'/);
  assert.match(source, /isolatedDatabaseGuard\(source\)/);
  assert.match(source, /discovery\.json/);
  assert.match(source, /result\.json/);
  assert.match(source, /if \(!completed\.passed\) throw new Error/);
});

test('controlled receipts retain native routing and never claim deferred qualification', t => {
  const registry = require('../scripts/lib/native-secureshop-suites');
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'native-routing-receipt-')));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const deferredNative = [registry.schemaFirst[0], registry.nativePg[0], registry.nativeBrowser[0]];
  const discovery = discoveryReceipt({ mode: 'secureshop', focused: false,
    files: registry.fixtureContract.map(row => row.file), deferredNative });
  const saved = writeJsonExclusive(directory, 'discovery.json', discovery);
  const log = path.join(directory, 'tests.log');
  fs.writeFileSync(log, '# tests 1\n# pass 1\n# fail 0\n# skipped 0\n');
  const result = resultReceipt({ discovery, discoverySha256: saved.sha256,
    argv: ['--test', ...discovery.files], result: { code: 0, signal: null, timedOut: false }, testsLog: log });
  assert.equal(result.passed, true);
  assert.deepEqual(result.deferredNative, discovery.deferredNative);
  assert.equal(result.deferredNativeSha256, discovery.deferredNativeSha256);
  assert.equal(result.nativeQualificationAccepted, false);
  assert.match(result.limitation, /native PostgreSQL, browser and actual-model qualifications are separate/);
  const input = { mode: 'secureshop', focused: false, files: discovery.files };
  for (const rows of [[{ ...deferredNative[0], launcher: 'wrong.py' }], [deferredNative[0], deferredNative[0]], [{ file: 'tests/secureshop/unit/unregistered.test.js' }]]) {
    assert.throws(() => discoveryReceipt({ ...input, deferredNative: rows }), /Invalid deferred native/);
  }
  assert.throws(() => discoveryReceipt({ ...input, files: [deferredNative[0].file], deferredNative }), /Invalid deferred native/);
});
