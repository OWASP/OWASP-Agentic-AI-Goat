'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const {
  MAILPIT_IMAGE,
  MAILPIT_IMAGE_VERSION,
  MAILPIT_IMAGE_DIGEST,
  validateMailpitState,
  probeApi,
  probeSmtp,
  ensureLocalMailpit,
  assertLocalMailpitReady,
  assertOwnedContainer,
} = require('../scripts/local-mailpit');

function state() {
  return {
    version: 1, id: 'fixture', name: 'dvaia-mailpit-fixture', nonce: 'c'.repeat(64), image: MAILPIT_IMAGE,
    imageVersion: MAILPIT_IMAGE_VERSION, imageDigest: MAILPIT_IMAGE_DIGEST, containerId: 'b'.repeat(64), dockerAuthorityDigest: 'a'.repeat(64), smtpPort: 41025, apiPort: 48025,
  };
}

test('Mailpit state requires the reviewed immutable image and owned ports', () => {
  assert.equal(validateMailpitState(state(), { id: 'fixture', name: 'dvaia-mailpit-fixture' }).image, MAILPIT_IMAGE);
  assert.throws(() => validateMailpitState({ ...state(), image: 'axllent/mailpit:latest' }, { id: 'fixture', name: 'dvaia-mailpit-fixture' }), /state/);
  assert.throws(() => validateMailpitState({ ...state(), apiPort: 41025 }, { id: 'fixture', name: 'dvaia-mailpit-fixture' }), /state/);
});

test('Mailpit API and SMTP readiness probes accept controlled healthy endpoints', async () => {
  const request = (_url, callback) => {
    const response = new EventEmitter(); response.statusCode = 200; response.resume = () => {};
    process.nextTick(() => { callback(response); response.emit('end'); });
    return Object.assign(new EventEmitter(), { setTimeout() {}, destroy() {} });
  };
  const connect = () => {
    const socket = new EventEmitter();
    socket.setTimeout = () => {}; socket.destroy = () => {};
    process.nextTick(() => { socket.emit('connect'); socket.emit('data', Buffer.from('220 mailpit ESMTP\r\n')); });
    return socket;
  };
  await probeApi(48025, request);
  await probeSmtp(41025, connect);
});

test('Mailpit readiness rejects an unhealthy API response', async () => {
  let healthy = false;
  const request = (_url, callback) => {
    const response = new EventEmitter(); response.statusCode = healthy ? 200 : 503; response.resume = () => {};
    process.nextTick(() => { callback(response); response.emit('end'); });
    return Object.assign(new EventEmitter(), { setTimeout() {}, destroy() {} });
  };
  const connect = () => { const socket = new EventEmitter(); socket.setTimeout = () => {}; socket.destroy = () => {}; process.nextTick(() => socket.emit('data', Buffer.from('220 mailpit ESMTP\r\n'))); return socket; };
  await assert.rejects(probeApi(48025, request), /HTTP 503/);
});

test('Mailpit startup rejects missing containers and non-private state files', async () => {
  assert.throws(() => assertOwnedContainer(null, { id: 'fixture', name: 'dvaia-mailpit-fixture', state: state() }), /unavailable/);
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-mailpit-private-'));
  const file = path.join(directory, 'mailpit.json');
  try {
    await fs.writeFile(file, JSON.stringify({ ...state(), containerId: 'b'.repeat(64) }) + '\n', { mode: 0o644 });
    await assert.rejects(assertLocalMailpitReady({ statePath: file, execute: async () => ({ stdout: '[]' }) }), /owner-only/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('Mailpit setup removes an owned container after readiness failure', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-mailpit-test-'));
  const commands = [];
  let removed = false;
  let runStarted = false;
  let healthy = false;
  let runPorts = { smtp: null, api: null };
  const execute = async (_command, args) => {
    commands.push(args);
    if (args.includes('run')) { removed = false; runStarted = true; }
    if (args.includes('inspect')) {
      if (args.includes('image')) return { stdout: JSON.stringify([{ Id: MAILPIT_IMAGE_DIGEST, RepoDigests: [MAILPIT_IMAGE] }]) };
      if (removed) { const error = new Error('gone'); error.code = 1; throw error; }
      if (!runStarted) { const error = new Error('missing'); error.code = 1; throw error; }
        const saved = JSON.parse(await fs.readFile(path.join(directory, 'mailpit.json'), 'utf8'));
        return { stdout: JSON.stringify([{ Id: 'b'.repeat(64), Config: { Labels: { 'org.dvaia.workspace': 'fixture', 'org.dvaia.mailpit.nonce': saved.nonce }, Image: MAILPIT_IMAGE }, Image: MAILPIT_IMAGE_DIGEST,
        HostConfig: { PortBindings: { '1025/tcp': [{ HostIp: '127.0.0.1', HostPort: String(runPorts.smtp) }], '8025/tcp': [{ HostIp: '127.0.0.1', HostPort: String(runPorts.api) }] } }, State: { Running: true } }]) };
    }
    for (let publish = args.indexOf('--publish'); publish >= 0; publish = args.indexOf('--publish', publish + 1)) {
      const mapping = args[publish + 1];
      if (mapping.endsWith(':1025')) runPorts.smtp = mapping.split(':')[1];
      if (mapping.endsWith(':8025')) runPorts.api = mapping.split(':')[1];
    }
    if (args.includes('rm')) removed = true;
    return { stdout: '' };
  };
  const request = (_url, callback) => {
    const response = new EventEmitter(); response.statusCode = healthy ? 200 : 503; response.resume = () => {};
    process.nextTick(() => { callback(response); response.emit('end'); });
    return Object.assign(new EventEmitter(), { setTimeout() {}, destroy() {} });
  };
  const connect = () => { const socket = new EventEmitter(); socket.setTimeout = () => {}; socket.destroy = () => {}; process.nextTick(() => socket.emit('data', Buffer.from('220 mailpit ESMTP\\r\\n'))); return socket; };
  try {
    await assert.rejects(ensureLocalMailpit({ directory, id: 'fixture', execute,
      resolveAuthority: async () => ({ authority: { host: 'unix:///controlled', daemonId: 'daemon' }, persisted: true }),
      request, readinessAttempts: 1, wait: async () => {} }), /did not become ready/);
    assert.ok(commands.some(args => args.includes('rm') && args.includes('--force') && args.includes('b'.repeat(64))));
    const pending = JSON.parse(await fs.readFile(path.join(directory, 'mailpit.json'), 'utf8'));
    assert.equal(pending.containerId, undefined);
    healthy = true;
    const retried = await ensureLocalMailpit({ directory, id: 'fixture', execute,
      resolveAuthority: async () => ({ authority: { host: 'unix:///controlled', daemonId: 'daemon' }, persisted: true }),
      request, connect, readinessAttempts: 1, wait: async () => {} });
    assert.equal(retried.containerId, 'b'.repeat(64));
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('Mailpit setup can retry after a failed create without adopting a replacement container', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-mailpit-retry-'));
  let runCount = 0;
  let container = null;
  const execute = async (_command, args) => {
    if (args.includes('inspect')) {
      if (args.includes('image')) return { stdout: JSON.stringify([{ Id: MAILPIT_IMAGE_DIGEST, RepoDigests: [MAILPIT_IMAGE] }]) };
      if (!container) { const error = new Error('missing'); error.code = 1; throw error; }
      return { stdout: JSON.stringify([container]) };
    }
    if (args.includes('run')) {
      runCount += 1;
      const saved = JSON.parse(await fs.readFile(path.join(directory, 'mailpit.json'), 'utf8'));
      if (runCount === 1) { const error = new Error('simulated daemon failure'); throw error; }
      const smtp = args[args.indexOf('--publish') + 1].split(':')[1];
      const api = args[args.lastIndexOf('--publish') + 1].split(':')[1];
      container = { Id: 'd'.repeat(64), Config: { Labels: { 'org.dvaia.workspace': 'fixture', 'org.dvaia.mailpit.nonce': saved.nonce }, Image: MAILPIT_IMAGE }, Image: MAILPIT_IMAGE_DIGEST,
        HostConfig: { PortBindings: { '1025/tcp': [{ HostIp: '127.0.0.1', HostPort: smtp }], '8025/tcp': [{ HostIp: '127.0.0.1', HostPort: api }] } }, State: { Running: true } };
      return { stdout: '' };
    }
    if (args.includes('rm')) { container = null; return { stdout: '' }; }
    return { stdout: '' };
  };
  const healthyRequest = (_url, callback) => { const response = new EventEmitter(); response.statusCode = 200; response.resume = () => {}; process.nextTick(() => { callback(response); response.emit('end'); }); return Object.assign(new EventEmitter(), { setTimeout() {}, destroy() {} }); };
  const healthyConnect = () => { const socket = new EventEmitter(); socket.setTimeout = () => {}; socket.destroy = () => {}; process.nextTick(() => socket.emit('data', Buffer.from('220 mailpit ESMTP\r\n'))); return socket; };
  try {
    await assert.rejects(ensureLocalMailpit({ directory, id: 'fixture', execute, pullImage: false,
      resolveAuthority: async () => ({ authority: { host: 'unix:///controlled', daemonId: 'daemon' }, persisted: true }), readinessAttempts: 1, request: healthyRequest, connect: healthyConnect }), /daemon failure/);
    const pending = JSON.parse(await fs.readFile(path.join(directory, 'mailpit.json'), 'utf8'));
    assert.equal(pending.containerId, undefined);
    assert.match(pending.nonce, /^[a-f0-9]{64}$/);
    const result = await ensureLocalMailpit({ directory, id: 'fixture', execute, pullImage: false,
      resolveAuthority: async () => ({ authority: { host: 'unix:///controlled', daemonId: 'daemon' }, persisted: true }), readinessAttempts: 1, request: healthyRequest, connect: healthyConnect });
    assert.equal(result.containerId, 'd'.repeat(64));
    assert.equal(runCount, 2);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('Mailpit startup rejects a replacement container with a different identity', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-mailpit-replaced-'));
  const file = path.join(directory, 'mailpit.json');
  const saved = state();
  const authority = { host: 'unix:///controlled' };
  const { authorityDigest } = require('../scripts/local-docker-authority');
  saved.dockerAuthorityDigest = authorityDigest(authority);
  await fs.writeFile(file, JSON.stringify(saved) + '\n', { mode: 0o600 });
  const execute = async (_command, args) => {
    if (args.includes('inspect')) return { stdout: JSON.stringify([{ Id: 'e'.repeat(64), Config: { Labels: { 'org.dvaia.workspace': 'fixture', 'org.dvaia.mailpit.nonce': saved.nonce }, Image: MAILPIT_IMAGE }, Image: MAILPIT_IMAGE_DIGEST, HostConfig: { PortBindings: { '1025/tcp': [{ HostIp: '127.0.0.1', HostPort: String(saved.smtpPort) }], '8025/tcp': [{ HostIp: '127.0.0.1', HostPort: String(saved.apiPort) }] } }, State: { Running: true } }]) };
    return { stdout: '' };
  };
  try { await assert.rejects(assertLocalMailpitReady({ statePath: file, execute, resolveAuthority: async () => ({ authority, persisted: true }) }), /identity changed/); }
  finally { await fs.rm(directory, { recursive: true, force: true }); }
});


test('legacy Mailpit state is rejected before authority calls without changing its bytes', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-mailpit-legacy-'));
  const file = path.join(directory, 'mailpit.json');
  const legacy = state();
  delete legacy.nonce; delete legacy.imageVersion; delete legacy.containerId;
  const original = JSON.stringify(legacy) + '\n';
  let calls = 0;
  const forbidden = async () => { calls++; throw new Error('Unexpected authority operation'); };
  try {
    await fs.writeFile(file, original, { mode: 0o600 });
    await assert.rejects(ensureLocalMailpit({ directory, id: 'fixture', execute: forbidden,
      resolveAuthority: forbidden, writeAuthority: forbidden }), { code: 'MAILPIT_LEGACY_STATE_UNSUPPORTED' });
    await assert.rejects(assertLocalMailpitReady({ statePath: file, execute: forbidden,
      resolveAuthority: forbidden }), { code: 'MAILPIT_LEGACY_STATE_UNSUPPORTED' });
    assert.equal(calls, 0);
    assert.equal(await fs.readFile(file, 'utf8'), original);
    const provisional = state(); delete provisional.containerId;
    assert.equal(validateMailpitState(provisional, { id: 'fixture', name: provisional.name,
      requireContainerId: false }), provisional);
    assert.throws(() => validateMailpitState(provisional, { id: 'fixture', name: provisional.name }), /state/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});
