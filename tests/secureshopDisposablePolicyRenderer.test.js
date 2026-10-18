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

test('V24 uses the disposable renderer and retains run-local diagnostics and cleanup', async () => {
  const caller = await fs.readFile(path.join(__dirname, 'postgres',
    'secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  const setup = caller.slice(caller.indexOf('externalPolicyRenderer = POLICY_TEMPLATE_BROWSER'),
    caller.indexOf("if (POLICY_RENDERER_BROWSER) assert.ok(externalPolicyRenderer"));
  assert.match(setup, /externalPolicyRenderer = POLICY_TEMPLATE_BROWSER \|\| POLICY_INSTRUCTION_BROWSER/);
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
