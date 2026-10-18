'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { childEnvironment, assertOwnedPrefix, runVerifier, REQUIRED, sha256,
  processExists, CLI_DISABLED_REASON } = require('../tests/release-inputs/transformers43-qualification-runner.cjs');

const RUNNER = path.resolve(__dirname, '../tests/release-inputs/transformers43-qualification-runner.cjs');
const posix = process.platform !== 'win32';
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

async function waitForFile(file, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { return Number((await fsp.readFile(file, 'utf8')).trim()); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await pause(10);
  }
  throw new Error(`file not observed: ${file}`);
}

async function fixture(t, source, { maxOutputBytes = 1024 * 1024 } = {}) {
  const prefix = await fsp.mkdtemp(path.join(os.tmpdir(), 'dvaia-43-runner-'));
  t.after(async () => { await fsp.rm(prefix, { recursive: true, force: true }); });
  const packages = { lockfileVersion: 3, packages: {} };
  for (const [name, version] of Object.entries(REQUIRED)) {
    const dir = path.join(prefix, 'node_modules', name);
    await fsp.mkdir(dir, { recursive: true });
    await fsp.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name, version }));
    packages.packages[`node_modules/${name}`] = { version, integrity: `sha512-${'A'.repeat(86)}==` };
  }
  await fsp.writeFile(path.join(prefix, 'package-lock.json'), JSON.stringify(packages));
  const verifier = path.join(prefix, 'verifier.cjs');
  await fsp.writeFile(verifier, source);
  const home = path.join(prefix, 'owned-home');
  const npmCache = path.join(prefix, 'owned-npm-cache');
  const cache = path.join(prefix, 'cache');
  await Promise.all([fsp.mkdir(home), fsp.mkdir(npmCache), fsp.mkdir(cache)]);
  const files = { 'package-lock.json': sha256(path.join(prefix, 'package-lock.json')),
    'verifier.cjs': sha256(verifier) };
  for (const name of Object.keys(REQUIRED)) {
    const relative = `node_modules/${name}/package.json`;
    files[relative] = sha256(path.join(prefix, relative));
  }
  return { prefix, verifier, home, npmCache, cache, maxOutputBytes,
    integrity: { version: 1, scope: 'controlled_process_test', files,
      nodeSha256: sha256(process.execPath),
      networkDenySha256: sha256(path.resolve(__dirname, '../tests/release-inputs/transformers43-network-deny.cjs')) } };
}

test('offline environment is minimal and forces both model flags plus network deny preload', () => {
  const env = childEnvironment({ cache: '/owned/cache', mode: 'offline', home: '/owned/home', npmCache: '/owned/npm' });
  assert.deepEqual(Object.keys(env).sort(), ['HF_HUB_OFFLINE', 'HOME', 'LANG', 'NODE_OPTIONS',
    'PATH', 'TRANSFORMERS_OFFLINE', 'XENOVA_CACHE', 'npm_config_cache'].sort());
  assert.equal(env.HF_HUB_OFFLINE, '1');
  assert.equal(env.TRANSFORMERS_OFFLINE, '1');
  assert.match(env.NODE_OPTIONS, /^--require=.*transformers43-network-deny\.cjs$/);
  assert.equal(env.NODE_TLS_REJECT_UNAUTHORIZED, undefined);
});

test('owned prefix and child directories reject workspace, wrong types, and symlink escapes', async t => {
  const outside = await fsp.mkdtemp(path.join(os.tmpdir(), 'dvaia-43-path-'));
  t.after(() => fsp.rm(outside, { recursive: true, force: true }));
  assert.throws(() => assertOwnedPrefix(process.cwd(), process.cwd()), /outside the workspace/);
  assert.equal(assertOwnedPrefix(outside, process.cwd()), fs.realpathSync(outside));
  const regular = path.join(outside, 'not-a-directory');
  await fsp.writeFile(regular, 'x');
  assert.throws(() => assertOwnedPrefix(regular, process.cwd()), /must be a directory/);
  const link = `${outside}-link`;
  await fsp.symlink(outside, link, 'dir');
  t.after(() => fsp.rm(link, { force: true }));
  assert.throws(() => assertOwnedPrefix(link, process.cwd()), /symlink/);
  const setup = await fixture(t, 'process.exit(0);');
  const external = await fsp.mkdtemp(path.join(os.tmpdir(), 'dvaia-43-external-'));
  t.after(() => fsp.rm(external, { recursive: true, force: true }));
  await assert.rejects(runVerifier({ ...setup, cache: external, timeoutMs: 100 }), /cache must be inside prefix/);
  const cacheFile = path.join(setup.prefix, 'cache-file');
  await fsp.writeFile(cacheFile, 'x');
  await assert.rejects(runVerifier({ ...setup, cache: cacheFile, timeoutMs: 100 }), /must be a directory/);
  const cacheLink = path.join(setup.prefix, 'cache-link');
  await fsp.symlink(setup.cache, cacheLink, 'dir');
  await assert.rejects(runVerifier({ ...setup, cache: cacheLink, timeoutMs: 100 }), /symlink/);
  const realParent = path.join(setup.prefix, 'real-parent');
  const nested = path.join(realParent, 'nested');
  await fsp.mkdir(nested, { recursive: true });
  const parentLink = path.join(setup.prefix, 'parent-link');
  await fsp.symlink(realParent, parentLink, 'dir');
  await assert.rejects(runVerifier({ ...setup, home: path.join(parentLink, 'nested'), timeoutMs: 100 }), /symlink/);
});

test('exported runner refuses absent or changed installed-file pins before spawning', async t => {
  const marker = path.join(os.tmpdir(), `dvaia-43-marker-${process.pid}-${Date.now()}`);
  t.after(() => fsp.rm(marker, { force: true }));
  const setup = await fixture(t, `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ran');`);
  await assert.rejects(runVerifier({ ...setup, prefix: process.cwd(), workspace: setup.prefix,
    integrity: undefined, timeoutMs: 100 }), /outside the workspace/);
  await assert.rejects(runVerifier({ ...setup, integrity: undefined, timeoutMs: 100 }),
    new RegExp(CLI_DISABLED_REASON));
  assert.equal(fs.existsSync(marker), false);
  const packageFile = path.join(setup.prefix, 'node_modules', 'sharp', 'package.json');
  await fsp.appendFile(packageFile, ' ');
  await assert.rejects(runVerifier({ ...setup, timeoutMs: 100 }), /installed file digest mismatch/);
  assert.equal(fs.existsSync(marker), false);
});

test('normal exit reaps leader and removes a real lingering grandchild process group', { skip: !posix }, async t => {
  const pidFileName = 'grandchild.pid';
  const source = `
    const fs=require('node:fs'); const {spawn}=require('node:child_process');
    const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});
    fs.writeFileSync(${JSON.stringify(pidFileName)},String(child.pid)); child.unref();
    process.stdout.write('verified\\n');
  `;
  const setup = await fixture(t, source);
  const result = await runVerifier({ ...setup, timeoutMs: 2000 });
  const grandchild = await waitForFile(path.join(setup.prefix, pidFileName));
  assert.equal(result.code, 0);
  assert.equal(result.closeObserved, true);
  assert.equal(result.reaped, true);
  assert.equal(result.pidAbsent, true);
  assert.equal(result.pgidAbsent, true);
  assert.equal(result.cleanup.groupAbsent, true);
  assert.equal(processExists(grandchild), false);
  assert.equal(result.stdout, 'verified\n');
});

test('timeout waits for observed close and proves leader and real grandchild absent', { skip: !posix }, async t => {
  const pidFileName = 'grandchild.pid';
  const source = `
    const fs=require('node:fs'); const {spawn}=require('node:child_process');
    const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});
    fs.writeFileSync(${JSON.stringify(pidFileName)},String(child.pid));
    setInterval(()=>{},1000);
  `;
  const setup = await fixture(t, source);
  await assert.rejects(runVerifier({ ...setup, timeoutMs: 100 }), error => {
    assert.match(error.message, /timeout/);
    assert.equal(error.result.timedOut, true);
    assert.equal(error.result.closeObserved, true);
    assert.equal(error.result.reaped, true);
    assert.equal(error.result.pidAbsent, true);
    assert.equal(error.result.pgidAbsent, true);
    assert.equal(error.result.cleanup.groupAbsent, true);
    assert.ok(error.result.signal, 'actual close signal must be retained');
    return true;
  });
  const grandchild = await waitForFile(path.join(setup.prefix, pidFileName));
  assert.equal(processExists(grandchild), false);
});

test('output limit is enforced by data events and still returns terminal cleanup proof', { skip: !posix }, async t => {
  const setup = await fixture(t, "process.stdout.write('x'.repeat(4096));setInterval(()=>{},1000);",
    { maxOutputBytes: 128 });
  await assert.rejects(runVerifier({ ...setup, timeoutMs: 2000 }), error => {
    assert.match(error.message, /output limit/);
    assert.ok(error.result.outputBytes > 128);
    assert.ok(Buffer.byteLength(error.result.stdout) <= 128);
    assert.equal(error.result.closeObserved, true);
    assert.equal(error.result.pidAbsent, true);
    assert.equal(error.result.pgidAbsent, true);
    return true;
  });
});

test('spawn error reports no fabricated terminal and no owned PID or group', { skip: !posix }, async t => {
  const setup = await fixture(t, 'process.exit(0);');
  const broken = path.join(setup.prefix, 'broken-node');
  await fsp.writeFile(broken, '#!/definitely/missing/interpreter\n');
  await fsp.chmod(broken, 0o700);
  const integrity = { ...setup.integrity, nodeSha256: sha256(broken) };
  await assert.rejects(runVerifier({ ...setup, integrity, node: broken, timeoutMs: 500 }), error => {
    assert.match(error.message, /spawn failed/);
    assert.equal(error.result.spawned, false);
    assert.equal(error.result.closeObserved, true);
    assert.equal(error.result.pidAbsent, true);
    assert.equal(error.result.pgidAbsent, true);
    return true;
  });
});

test('offline preload denies TCP, HTTP, DNS, datagrams and fetch in a child', () => {
  const guard = path.resolve(__dirname, '../tests/release-inputs/transformers43-network-deny.cjs');
  const script = `require(${JSON.stringify(guard)}); const checks=[
    ()=>require('node:net').connect(9), ()=>require('node:http').get('http://127.0.0.1/'),
    ()=>require('node:dns').lookup('localhost',()=>{}), ()=>require('node:dgram').createSocket('udp4'),
    ()=>fetch('http://127.0.0.1/')];
    for(const check of checks){try{check();process.exit(3)}catch(e){if(!/forbids network/.test(e.message))process.exit(4)}}`;
  const child = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);
});

test('CLI remains closed until the reviewed native qualification manifest exists', () => {
  const child = spawnSync(process.execPath, [RUNNER], { encoding: 'utf8' });
  assert.equal(child.status, 2);
  assert.match(child.stderr, new RegExp(CLI_DISABLED_REASON));
  assert.equal(child.stdout, '');
});

for (const phase of ['before-spawn', 'after-spawn']) test(`controlled inventory failure ${phase} settles without unsafe signaling`, { timeout: 5000 }, async t => {
  const { EventEmitter } = require('node:events');
  const { PassThrough } = require('node:stream');
  const Module = require('node:module');
  const vm = require('node:vm');
  let probes = 0, spawned = 0, signals = 0, released = false;
  const child = new EventEmitter();
  Object.assign(child, { pid: 123456, exitCode: null, signalCode: null,
    stdout: new PassThrough(), stderr: new PassThrough(), unref() { released = true; } });
  const localProcess = Object.create(process);
  localProcess.kill = () => { signals++; throw Error('unverified signal'); };
  const nativeRequire = Module.createRequire(RUNNER), module = { exports: {} };
  const childProcess = { ...require('node:child_process'),
    spawn() { spawned++; return child; },
    spawnSync() { probes++; return phase === 'after-spawn' && probes === 1
      ? { status: 0, stdout: `${process.pid} ${process.pid} ${process.getuid()}\n` }
      : { status: null, error: Object.assign(Error('controlled inventory denied'), { code: 'EPERM' }) }; } };
  vm.runInNewContext(fs.readFileSync(RUNNER, 'utf8'), { module, exports: module.exports,
    require: name => name === 'node:child_process' ? childProcess : nativeRequire(name),
    __dirname: path.dirname(RUNNER), process: localProcess, Buffer, console, setTimeout, clearTimeout });
  const setup = await fixture(t, '/* controlled; never executed */');
  await assert.rejects(module.exports.runVerifier({ ...setup, timeoutMs: 10 }), error => {
    if (phase === 'before-spawn') assert.match(error.message, /process inventory failed/);
    else {
      assert.match(error.message, /cleanup was not proven/);
      assert.equal(error.result.cleanupUnproven, true);
      assert.equal(error.result.closeObserved, false);
      assert.equal(error.result.pidAbsent, false);
      assert.equal(error.result.pgidAbsent, false);
      assert.equal(error.result.cleanup.groupAbsent, false);
    }
    return true;
  });
  assert.equal(spawned, phase === 'before-spawn' ? 0 : 1);
  assert.equal(signals, 0);
  assert.equal(released, phase === 'after-spawn');
});
