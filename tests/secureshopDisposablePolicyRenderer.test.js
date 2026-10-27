'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createArgs, assertOwnedResource, transientHealthFailure,
  diagnosticDestination, startupFailureRecord }
  = require('./fixtures/secureshopDisposablePolicyRenderer');
const installer = require('../scripts/install/secureshop-owned-policy-renderer');
const crypto = require('node:crypto');
const managed = require('../server/services/secureshopPolicyRendererManagedConfiguration');
const authority = require('../scripts/local-docker-authority');
const { workspaceId } = require('../scripts/application-data-root');
const { _internals: { privateAdmission, captureDisposableAdmission } }
  = require('./fixtures/secureshopDisposablePolicyRenderer');

test('V24 borrows its paired renderer while the template cohort retains disposable diagnostics and cleanup', async () => {
  const caller = await fs.readFile(path.join(__dirname, 'postgres',
    'secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  const setup = caller.slice(caller.indexOf('externalPolicyRenderer = POLICY_INSTRUCTION_BROWSER'),
    caller.indexOf("if (POLICY_RENDERER_BROWSER) assert.ok(externalPolicyRenderer"));
  assert.match(setup, /externalPolicyRenderer = POLICY_INSTRUCTION_BROWSER\s*\? await capturePolicyInstructionRenderer\(workspace\)\s*: POLICY_TEMPLATE_BROWSER/);
  assert.match(setup, /createDisposablePolicyRenderer\(\{/);
  assert.match(setup, /SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_RENDERER_ADMISSION/);
  assert.match(setup, /path\.join\(path\.dirname\(evidencePath\), 'disposable-policy-renderer-diagnostic\.json'\)/);
  assert.match(setup, /: POLICY_RENDERER_BROWSER\s*\? await capturePolicyRenderer/);
  assert.match(caller, /\(\) => externalPolicyRenderer\?\.check\(\), \(\) => externalPolicyRenderer\?\.close\?\.\(\)/);
});

const digest = 'a'.repeat(64);
const suffix = 'a1b2c3d4e5f6';
const name = `dvaia-v59-policy-${suffix}`;
const labels = { 'dvaia.policy.workspace': suffix, 'dvaia.policy.owner': 'owned-teaching',
  'dvaia.policy.source': digest, 'dvaia.qualification': suffix };

test('dedicated build uses the production closed policy-only source manifest', () => {
  const source = installer.sourceManifest(path.resolve(__dirname, '..'));
  assert.equal(Object.keys(source.files).length, 11);
  for (const entry of ['Dockerfile', 'Dockerfile.dockerignore', 'listener.js', 'executor.js',
    'http-handler.js', 'worker.js', 'secureshopPromptPolicyContract.js']) {
    assert.match(source.files[`sidecars/sandbox-runner/policy-render/${entry}`], /^[a-f0-9]{64}$/);
  }
});

test('disposable container uses exact production isolation and a fixed loopback port', () => {
  const args = createArgs({ name, network: name, profile: `dvaia-owned-policy-renderer-${suffix}`,
    imageId: `sha256:${digest}`, labels, port: 34567 });
  for (const required of ['--read-only', '10001:10001', '--cap-drop', 'ALL',
    'apparmor=dvaia-owned-policy-renderer-a1b2c3d4e5f6', 'seccomp=unconfined',
    '127.0.0.1:34567:8090', 'SECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1']) {
    assert.ok(args.includes(required), required);
  }
  assert.ok(args.includes('dvaia.qualification=a1b2c3d4e5f6'));
  assert.throws(() => createArgs({ name, network: name,
    profile: `dvaia-owned-policy-renderer-${suffix}`, imageId: `sha256:${digest}`,
    labels, port: 0 }));
});

test('cleanup admission rejects replaced IDs, foreign run labels and renamed resources', () => {
  const common = { expectedId: digest, labels, name, network: name };
  assert.equal(assertOwnedResource('container', { Id: digest, Name: `/${name}`,
    Config: { Labels: labels } }, common), digest);
  assert.throws(() => assertOwnedResource('container', { Id: 'b'.repeat(64), Name: `/${name}`,
    Config: { Labels: labels } }, common));
  assert.throws(() => assertOwnedResource('container', { Id: digest, Name: `/${name}`,
    Config: { Labels: { ...labels, 'dvaia.qualification': 'foreign' } } }, common));
  assert.throws(() => assertOwnedResource('container', { Id: digest, Name: '/other',
    Config: { Labels: labels } }, common));
  assert.equal(assertOwnedResource('network', { Id: digest, Name: name, Labels: labels }, common), digest);
  assert.equal(assertOwnedResource('image', { Id: `sha256:${digest}`,
    Config: { Labels: labels } }, { ...common, expectedId: `sha256:${digest}` }), `sha256:${digest}`);
});

test('startup polling retries only connection startup errors', () => {
  assert.equal(transientHealthFailure({ cause: { code: 'ECONNREFUSED' } }), true);
  assert.equal(transientHealthFailure({ cause: { errors: [{ code: 'ECONNRESET' }] } }), true);
  assert.equal(transientHealthFailure({ cause: { code: 'UND_ERR_SOCKET',
    message: 'other side closed' } }), true);
  assert.equal(transientHealthFailure({ cause: { code: 'UND_ERR_SOCKET',
    message: 'socket failed during response' } }), false);
  assert.equal(transientHealthFailure({ cause: { code: 'ETIMEDOUT' } }), false);
  assert.equal(transientHealthFailure(new Error('invalid health response')), false);
});

test('diagnostic destination is a fresh private run file', async () => {
  const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'run-ab'));
  const filename = path.join(root, 'disposable-policy-renderer-diagnostic.json');
  try {
    assert.equal((await diagnosticDestination(filename)).parent, root);
    await fs.writeFile(filename, '{}', { flag: 'wx', mode: 0o600 });
    await assert.rejects(diagnosticDestination(filename));
    await assert.rejects(diagnosticDestination(path.join(root, 'other.json')));
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('startup diagnostic keeps the original fetch cause and bounded owned container state', () => {
  const error = new TypeError('fetch failed', { cause: Object.assign(new Error('connect ECONNREFUSED'),
    { code: 'ECONNREFUSED' }) });
  const record = startupFailureRecord({ stage: 'loopback-health', error, healthAttempts: 20,
    containerId: 'a'.repeat(64), port: 34567,
    state: { Status: 'exited', Running: false, ExitCode: 1, OOMKilled: false,
      Error: 'startup failure' },
    publishedPorts: [{ HostIp: '127.0.0.1', HostPort: '34567' }],
    logs: `startup\n${'x'.repeat(6000)}` });
  assert.equal(record.stage, 'loopback-health');
  assert.equal(record.error.cause.code, 'ECONNREFUSED');
  assert.equal(record.healthAttempts, 20);
  assert.deepEqual(record.containerState, { status: 'exited', running: false,
    exitCode: 1, oomKilled: false, error: 'startup failure' });
  assert.deepEqual(record.publishedPorts, [{ hostIp: '127.0.0.1', hostPort: '34567' }]);
  assert.equal(record.startupLogs.length, 4096);
  assert.equal(JSON.stringify(record).includes('x'.repeat(4097)), false);
});

const hash = value => crypto.createHash('sha256').update(value).digest('hex');
async function admissionFixture(t) {
  const base = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'renderer-admission-'));
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  const workspace = path.join(base, 'workspace'), home = path.join(base, 'managed-home');
  await fs.mkdir(workspace, { mode: 0o700 }); await fs.mkdir(home, { mode: 0o700 });
  const original = path.resolve(__dirname, '..');
  const files = [...Object.keys(installer.sourceManifest(original).files),
    'server/services/secureshopPromptPolicyContract.js',
    'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'];
  for (const name of files) {
    const target = path.join(workspace, name);
    await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await fs.copyFile(path.join(original, name), target);
  }
  const runId = 'a'.repeat(32), owner = path.join(workspace, 'tasks/qualification', `system-original-owner-${runId}`);
  const admissionFilename = path.join(workspace, 'tasks/qualification', `system-renderer-${runId}`, 'admission.json');
  await fs.mkdir(owner, { recursive: true, mode: 0o700 });
  await fs.mkdir(path.dirname(admissionFilename), { recursive: true, mode: 0o700 });
  const id = workspaceId(workspace), location = managed.paths({ root: workspace, home });
  await fs.mkdir(location.directory, { recursive: true, mode: 0o700 });
  const dockerAuthority = { version: 1, workspaceId: id, host: 'unix:///var/run/docker.sock',
    daemonId: 'controlled-renderer-only', source: 'environment-host' };
  await fs.writeFile(path.join(location.directory, 'local-docker.json'), JSON.stringify(dockerAuthority), { mode: 0o600 });
  const value = { version: 1, workspaceId: id, ownerId: '11111111-1111-4111-8111-111111111111',
    architecture: 'arm64', dockerAuthoritySha256: authority.authorityDigest(dockerAuthority),
    sourceSha256: installer.sourceManifest(workspace).sha256, imageId: 'sha256:' + 'b'.repeat(64),
    profile: `dvaia-owned-policy-renderer-${id}`, profileSha256: hash(installer._internals.profileBytes(workspace, id)),
    container: `dvaia-policy-renderer-${id}`, containerId: 'c'.repeat(64), port: 8098, enabled: true };
  const { containerId, enabled, ...stageValue } = value;
  await fs.writeFile(location.filename, JSON.stringify(managed.validate(value, { root: workspace })) + '\n', { mode: 0o600 });
  await fs.writeFile(location.stage, JSON.stringify(managed.validate({ ...stageValue, activateRequested: true }, { root: workspace }, true)) + '\n', { mode: 0o600 });
  // This executable-shaped file is hashed, never executed by these controls.
  const binary = path.join(base, 'controlled-docker');
  await fs.writeFile(binary, 'controlled non-native executable bytes\n', { mode: 0o700 });
  const admission = { version: 1, workspace, home,
    managedSha256: managed.capture({ root: workspace, home }).sha256,
    stageSha256: managed.capture({ root: workspace, home }, true).sha256,
    dockerExecutable: binary, dockerExecutableSha256: hash(await fs.readFile(binary)) };
  await fs.writeFile(admissionFilename, JSON.stringify(admission), { mode: 0o600 });
  const env = { SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE: '1', PG_TEST_DISPOSABLE: 'yes', NODE_ENV: 'test',
    DVAIA_CURRENT_MAIN_WORKSPACE: workspace, SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_RUN_ID: runId,
    SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_DIRECTORY: owner };
  const args = { workspace, admissionFilename, diagnosticPath: path.join(owner, 'disposable-policy-renderer-diagnostic.json') };
  return { base, workspace, owner, env, args, location, admission, binary };
}
async function withOwnerEnvironment(env, work) {
  const saved = Object.fromEntries(Object.keys(env).map(key => [key, process.env[key]]));
  try { Object.assign(process.env, env); return await work(); }
  finally { for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  } }
}

test('actual composed admission accepts exact V24 directories and real captured managed/staged bytes', async t => {
  const f = await admissionFixture(t);
  await withOwnerEnvironment(f.env, async () => {
    const captured = await captureDisposableAdmission(f.args);
    assert.equal(captured.admission.directory.parent, path.dirname(f.args.admissionFilename));
    assert.equal(captured.diagnosticDirectory.parent, f.owner);
    assert.equal(captured.record.sha256, f.admission.managedSha256);
    assert.equal(captured.stage.sha256, f.admission.stageSha256);
    assert.equal(captured.record.value.profileSha256, hash(installer._internals.profileBytes(f.workspace, workspaceId(f.workspace))));
    assert.equal(captured.source.sha256, installer.sourceManifest(f.workspace).sha256);
  });
});

test('V24 admission and diagnostic paths reject every missing/foreign owner environment field', async t => {
  const f = await admissionFixture(t);
  await withOwnerEnvironment(f.env, async () => {
    for (const key of Object.keys(f.env)) {
      for (const value of [undefined, 'wrong']) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
        await assert.rejects(privateAdmission(f.workspace, f.args.admissionFilename));
        await assert.rejects(diagnosticDestination(f.args.diagnosticPath));
        process.env[key] = f.env[key];
      }
    }
    await assert.rejects(captureDisposableAdmission({ ...f.args,
      admissionFilename: f.args.admissionFilename.replace('a'.repeat(32), 'b'.repeat(32)) }));
    const peer = path.join(f.workspace, 'tasks/qualification', 'system-original-owner-' + 'b'.repeat(32));
    await fs.mkdir(peer, { mode: 0o700 });
    await assert.rejects(captureDisposableAdmission({ ...f.args,
      diagnosticPath: path.join(peer, 'disposable-policy-renderer-diagnostic.json') }));
    const legacy = path.join(f.base, 'run-abcdefgh'); await fs.mkdir(legacy, { mode: 0o700 });
    await assert.rejects(captureDisposableAdmission({ ...f.args,
      diagnosticPath: path.join(legacy, 'disposable-policy-renderer-diagnostic.json') }));
    const external = path.join(f.base, 'admission.json'); await fs.copyFile(f.args.admissionFilename, external);
    await assert.rejects(captureDisposableAdmission({ ...f.args, admissionFilename: external }));
  });
});

test('V24 rejects loose directories/files, symlinks, hardlinks and changed renderer identity', async t => {
  const f = await admissionFixture(t);
  await withOwnerEnvironment(f.env, async () => {
    for (const folder of [f.owner, path.dirname(f.args.admissionFilename)]) {
      await fs.chmod(folder, 0o755); await assert.rejects(captureDisposableAdmission(f.args)); await fs.chmod(folder, 0o700);
      const moved = folder + '.original'; await fs.rename(folder, moved); await fs.symlink(moved, folder);
      await assert.rejects(captureDisposableAdmission(f.args)); await fs.unlink(folder); await fs.rename(moved, folder);
    }
    const file = f.args.admissionFilename;
    await fs.chmod(file, 0o644); await assert.rejects(captureDisposableAdmission(f.args)); await fs.chmod(file, 0o600);
    await fs.link(file, file + '.link'); await assert.rejects(captureDisposableAdmission(f.args)); await fs.unlink(file + '.link');
    await fs.rename(file, file + '.original'); await fs.symlink(file + '.original', file);
    await assert.rejects(captureDisposableAdmission(f.args)); await fs.unlink(file); await fs.rename(file + '.original', file);
    for (const target of [f.location.filename, f.location.stage, f.binary]) {
      const bytes = await fs.readFile(target); await fs.appendFile(target, '\n');
      await assert.rejects(captureDisposableAdmission(f.args)); await fs.writeFile(target, bytes);
    }
    const profile = path.join(f.workspace, 'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in');
    await fs.appendFile(profile, '\n'); await assert.rejects(captureDisposableAdmission(f.args));
  });
});

test('external legacy admission and run diagnostic require no V24 environment', async t => {
  const f = await admissionFixture(t), outside = path.join(f.base, 'admission.json');
  await fs.copyFile(f.args.admissionFilename, outside);
  const run = path.join(f.base, 'run-abcdefgh'); await fs.mkdir(run, { mode: 0o700 });
  await withOwnerEnvironment(Object.fromEntries(Object.keys(f.env).map(key => [key, 'disabled'])), async () => {
    const captured = await captureDisposableAdmission({ ...f.args, admissionFilename: outside,
      diagnosticPath: path.join(run, 'disposable-policy-renderer-diagnostic.json') });
    assert.equal(captured.admission.directory, undefined);
    assert.equal(captured.record.sha256, f.admission.managedSha256);
  });
});

test('real disposable entry joins both V24 paths before first controlled Docker inspection; never native', async t => {
  const f = await admissionFixture(t), filename = path.join(__dirname, 'fixtures/secureshopDisposablePolicyRenderer.js');
  const createRequire = require('node:module').createRequire(filename), calls = [];
  const module = { exports: {} }, sandbox = { module, exports: module.exports, process, Buffer, URL, AbortSignal,
    setTimeout, clearTimeout, require(name) {
      if (name === 'node:child_process') return { execFile(file, args, options, done) {
        calls.push({ file, args }); done(Object.assign(new Error('controlled inspection unavailable'), { code: 'CONTROLLED_STOP' }));
      } };
      return createRequire(name);
    } };
  require('node:vm').runInNewContext(await fs.readFile(filename, 'utf8'), sandbox, { filename });
  await withOwnerEnvironment(f.env, async () => {
    await assert.rejects(module.exports.createDisposablePolicyRenderer(f.args));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].file, f.binary);
    assert.deepEqual(Array.from(calls[0].args.slice(0, 3)), ['--host', 'unix:///var/run/docker.sock', 'info']);
    const diagnostic = JSON.parse(await fs.readFile(f.args.diagnosticPath));
    assert.equal(diagnostic.stage, 'docker-authority');
    assert.equal(diagnostic.containerId, null);
    await fs.unlink(f.args.diagnosticPath);
    delete process.env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_RUN_ID;
    await assert.rejects(module.exports.createDisposablePolicyRenderer(f.args));
    assert.equal(calls.length, 1, 'invalid owner cannot reach even controlled inspection');
  });
});
