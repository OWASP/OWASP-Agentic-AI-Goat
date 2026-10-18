'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  MAILPIT_IMAGE, MAILPIT_IMAGE_DIGEST, MAILPIT_IMAGE_VERSION,
  assertOwnedContainer,
} = require('../scripts/local-mailpit');
const { SOURCE_FILES, buildProvisionPlan, cleanupOwnedMailpit, copyFrozenSource, runProvision } = require('../scripts/run-ipi-local-mailpit-provision-isolated');

test('Mailpit native launcher defaults to a non-mutating pinned plan', () => {
  const plan = buildProvisionPlan({ root: process.cwd(), node: '/managed/node' });
  assert.equal(plan.mode, 'plan');
  assert.equal(plan.nodePath, '/managed/node');
  assert.deepEqual(plan.image, { ref: MAILPIT_IMAGE, version: MAILPIT_IMAGE_VERSION, digest: MAILPIT_IMAGE_DIGEST });
  assert.deepEqual(plan.sourceFiles, SOURCE_FILES);
});

test('Mailpit native cleanup refuses a replaced container identity', async () => {
  const state = { version: 1, id: 'fixture', name: 'dvaia-mailpit-fixture', nonce: 'a'.repeat(64),
    image: MAILPIT_IMAGE, imageVersion: MAILPIT_IMAGE_VERSION, imageDigest: MAILPIT_IMAGE_DIGEST,
    containerId: 'b'.repeat(64), dockerAuthorityDigest: 'c'.repeat(64), smtpPort: 41025, apiPort: 48025 };
  const docker = async args => {
    if (args.includes('inspect')) return { stdout: JSON.stringify([{ Id: 'd'.repeat(64), Config: { Labels: {
      'org.dvaia.workspace': 'fixture', 'org.dvaia.mailpit.nonce': state.nonce }, Image: MAILPIT_IMAGE }, Image: MAILPIT_IMAGE_DIGEST,
      HostConfig: { PortBindings: { '1025/tcp': [{ HostIp: '127.0.0.1', HostPort: '41025' }], '8025/tcp': [{ HostIp: '127.0.0.1', HostPort: '48025' }] } } }]) };
    throw new Error('cleanup must not remove a replaced identity');
  };
  await assert.rejects(cleanupOwnedMailpit({ docker, state, ownerId: 'fixture', name: state.name, assertOwned: assertOwnedContainer }), /identity changed/);
});

test('Mailpit native launcher requires explicit isolation before creating evidence', async () => {
  await assert.rejects(runProvision({ environment: {} }), /MAILPIT_PROVISION_ISOLATED=1/);
});

test('Mailpit native launcher source snapshot is bounded and complete', async () => {
  const evidence = await fs.mkdtemp(path.join(os.tmpdir(), 'mailpit-source-snapshot-'));
  try {
    const { snapshot, source } = await copyFrozenSource(process.cwd(), evidence);
    assert.deepEqual(Object.keys(snapshot), SOURCE_FILES);
    for (const relative of SOURCE_FILES) {
      assert.match(snapshot[relative], /^[a-f0-9]{64}$/);
      assert.equal((await fs.stat(path.join(source, relative))).mode & 0o777, 0o500);
    }
  } finally { await fs.rm(evidence, { recursive: true, force: true }); }
});

function fakeProvisionTransport({ healthy }) {
  let container = null;
  const execute = async (_file, args) => {
    if (args.includes('info')) return { stdout: JSON.stringify('fake-daemon') };
    if (args.includes('image') && args.includes('inspect')) return { stdout: JSON.stringify([{ Id: MAILPIT_IMAGE_DIGEST, RepoDigests: [MAILPIT_IMAGE] }]) };
    if (args.includes('inspect')) {
      if (!container) { const error = new Error('missing'); error.code = 1; throw error; }
      return { stdout: JSON.stringify([container]) };
    }
    if (args.includes('run')) {
      const label = key => args[args.indexOf('--label', args.indexOf(`org.dvaia.${key}`)) + 1];
      const name = args[args.indexOf('--name') + 1];
      const workspace = args.find(value => String(value).startsWith('org.dvaia.workspace='))?.split('=')[1];
      const nonce = args.find(value => String(value).startsWith('org.dvaia.mailpit.nonce='))?.split('=')[1];
      const publishes = args.flatMap((value, index) => value === '--publish' ? [args[index + 1]] : []);
      const port = service => publishes.find(value => value.endsWith(`:${service}`)).split(':')[1];
      container = { Id: 'f'.repeat(64), Config: { Labels: { 'org.dvaia.workspace': workspace, 'org.dvaia.mailpit.nonce': nonce }, Image: MAILPIT_IMAGE }, Image: MAILPIT_IMAGE_DIGEST,
        HostConfig: { PortBindings: { '1025/tcp': [{ HostIp: '127.0.0.1', HostPort: port(1025) }], '8025/tcp': [{ HostIp: '127.0.0.1', HostPort: port(8025) }] } }, State: { Running: true }, name };
      return { stdout: '' };
    }
    if (args.includes('rm')) { container = null; return { stdout: '' }; }
    throw new Error(`unexpected fake Docker command: ${args.join(' ')}`);
  };
  const request = (_url, callback) => { const response = new (require('node:events').EventEmitter)(); response.statusCode = healthy ? 200 : 503; process.nextTick(() => { callback(response); response.emit('end'); }); return Object.assign(new (require('node:events').EventEmitter)(), { destroy() {}, setTimeout() {} }); };
  const connect = () => { const socket = new (require('node:events').EventEmitter)(); socket.setTimeout = () => {}; socket.destroy = () => {}; process.nextTick(() => socket.emit('data', Buffer.from('220 fake ESMTP\r\n'))); return socket; };
  return { execute, request, connect };
}

test('runProvision completes and retains an exact cleanup receipt with injected transports', async () => {
  const { runProvision } = require('../scripts/run-ipi-local-mailpit-provision-isolated');
  const node = process.execPath; const digest = crypto.createHash('sha256').update(await fs.readFile(node)).digest('hex');
  const evidence = await fs.mkdtemp(path.join(os.tmpdir(), 'mailpit-run-success-')); const transport = fakeProvisionTransport({ healthy: true });
  const result = await runProvision({ evidenceRoot: evidence, nodePath: node, nodeSha256: digest, dockerCli: node, dockerCliSha256: digest,
    dockerHost: 'unix:///controlled', environment: { MAILPIT_PROVISION_ISOLATED: '1' }, ...transport });
  const receipt = JSON.parse(await fs.readFile(path.join(evidence, 'cleanup.json'), 'utf8'));
  assert.equal(receipt.status.status, 'removed'); assert.equal(result.state.containerId, 'f'.repeat(64));
  await fs.rm(evidence, { recursive: true, force: true });
});

test('runProvision retains evidence after post-create readiness failure', async () => {
  const { runProvision } = require('../scripts/run-ipi-local-mailpit-provision-isolated');
  const node = process.execPath; const digest = crypto.createHash('sha256').update(await fs.readFile(node)).digest('hex');
  const evidence = await fs.mkdtemp(path.join(os.tmpdir(), 'mailpit-run-failure-')); const transport = fakeProvisionTransport({ healthy: false });
  await assert.rejects(runProvision({ evidenceRoot: evidence, nodePath: node, nodeSha256: digest, dockerCli: node, dockerCliSha256: digest,
    dockerHost: 'unix:///controlled', environment: { MAILPIT_PROVISION_ISOLATED: '1' }, readinessAttempts: 1, ...transport }), /did not become ready/);
  const receipt = JSON.parse(await fs.readFile(path.join(evidence, 'cleanup.json'), 'utf8'));
  assert.equal(receipt.version, 2); assert.ok(receipt.primaryError); assert.equal(JSON.parse(await fs.readFile(path.join(evidence, 'mailpit.json'), 'utf8')).containerId, undefined);
  await fs.rm(evidence, { recursive: true, force: true });
});
