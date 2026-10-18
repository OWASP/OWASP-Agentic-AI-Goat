'use strict';

// Controlled Docker/session providers prove retained-start decisions only.
// They do not establish native Windows or an actual running guest service.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { KEYS } = require('../server/services/mcp/ownedManagedConfiguration');
const root = path.resolve(__dirname, '..');
const id = require('../scripts/application-data-root').workspaceId(root);
const project = 'dvaia-' + id;
const containerId = 'a'.repeat(64), imageId = 'sha256:' + 'b'.repeat(64);
const imageName = 'mcp-owned-sandbox-runner:dev';
const volumeName = project + '_mcp-owned-targets';
const networkName = project + '_mcplab';
const token = 't'.repeat(64);

function load(relative, overrides = {}) {
  const filename = path.join(root, relative), module = { exports: {} }, original = createRequire(filename);
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), { module, exports: module.exports, __dirname: path.dirname(filename),
    process, Buffer, console, setTimeout, clearTimeout, require: name => overrides[name] || original(name) });
  return module.exports;
}
function fixture({ running = false, protectedRecovery = false } = {}) {
  const calls = [], session = {};
  const binding = { kind: 'owned-windows-lab', workspaceId: id, daemonId: 'owned-daemon', bindingSha256: 'c'.repeat(64) };
  const local = load('scripts/install/mcp-owned-local.js', {
    '../lib/windows-owned-lab': { describeOwnedLab(value) { if (value !== session) throw Error('unadmitted'); return binding; } },
  });
  const api = load('scripts/install/mcp-owned-provision.js', { './mcp-owned-local': local });
  const values = {
    MCP_OWNED_TARGET_APPARMOR_PROFILE: 'dvaia-mcp-sandbox', MCP_OWNED_TARGET_PORT: '8092',
    MCP_OWNED_TARGET_URL: 'http://127.0.0.1:8092', MCP_OWNED_TARGET_TOKEN: token,
    MCP_OWNED_RESOURCES_ENABLED: 'true', MCP_OBSERVED_ACTION_ENABLED: 'false',
    MCP_INDIRECT_INJECTION_ENABLED: 'false', MCP_SUPPLY_CHAIN_ENABLED: 'false',
    MCP_PROTECTED_RECOVERY_ENABLED: protectedRecovery ? 'true' : 'false',
    CODEBOT_SANDBOX_RUNNER_URL: 'http://127.0.0.1:8092', CODEBOT_OWNED_EXECUTION_ENABLED: 'true',
  };
  const privateStorage = { async read(file) { calls.push(['managed-read', file]); return Buffer.from(KEYS.map(key => `${key}=${JSON.stringify(values[key])}`).join('\n') + '\n'); } };
  const container = {
    Id: containerId, Name: '/' + project + '-mcp-owned-sandbox-1', Image: imageId,
    AppArmorProfile: 'dvaia-mcp-sandbox', State: { Running: running },
    Config: { Image: imageName, Labels: { 'com.docker.compose.project': project,
      'com.docker.compose.service': 'mcp-owned-sandbox' }, Env: [
      'MCP_OWNED_TARGETS_ENABLED=true', 'MCP_OWNED_TARGET_TOKEN=' + token,
      'MCP_OWNED_TARGET_APPARMOR_PROFILE=dvaia-mcp-sandbox',
      'MCP_OWNED_TARGET_ROOT=/sandbox/owned-targets',
    ] },
    HostConfig: { Privileged: false, NetworkMode: networkName, PidMode: '', IpcMode: '',
      SecurityOpt: ['apparmor=dvaia-mcp-sandbox', 'seccomp=unconfined'],
      PortBindings: { '8090/tcp': [{ HostIp: '127.0.0.1', HostPort: '8092' }] } },
    Mounts: [{ Type: 'volume', Name: volumeName, Destination: '/sandbox/owned-targets', RW: true }],
    NetworkSettings: { Networks: { [networkName]: {} },
      Ports: { '8090/tcp': [{ HostIp: '127.0.0.1', HostPort: '8092' }] } },
  };
  const image = { Id: imageId, RepoTags: [imageName] };
  const volume = { Name: volumeName, Labels: { 'com.docker.compose.project': project,
    'com.docker.compose.volume': 'mcp-owned-targets' } };
  let profileSha256, failProfile = false, mutateAfterStart;
  session.assertCurrent = async () => { calls.push(['assert-current']); };
  session.installAndVerifyProfile = async request => {
    calls.push(['profile', request]); profileSha256 = request.sha256;
    if (failProfile) throw Error('missing private profile secret');
    return { name: request.name, sha256: request.sha256, destination: '/etc/apparmor.d/' + request.name,
      bindingSha256: binding.bindingSha256 };
  };
  session.executeDocker = async (args, options) => {
    calls.push(['docker', args, options]);
    if (args[0] === 'image') return JSON.stringify([image]);
    if (args[0] === 'volume') return JSON.stringify([volume]);
    if (args[0] === 'ps') return containerId + '\n';
    if (args[0] === 'inspect') return JSON.stringify([container]);
    if (args[0] === 'start') { container.State.Running = true; mutateAfterStart?.(container); return containerId + '\n'; }
    throw Error('unexpected guest mutation');
  };
  const options = { root, home: 'C:\\Users\\Learner', platform: 'win32', ownedLabSession: session,
    commandEnv: {}, privateStorage, managedPath: 'C:\\Users\\Learner\\private\\mcp-owned.env' };
  return { api, options, calls, container, image, volume, values, binding,
    get profileSha256() { return profileSha256; }, denyProfile() { failProfile = true; }, afterStart(fn) { mutateAfterStart = fn; } };
}
const guestCalls = fixture => fixture.calls.filter(call => call[0] === 'docker').map(call => call[1]);

test('retained stopped runner is verified, started by exact ID, then re-inspected without provisioning', async () => {
  const f = fixture(), result = await f.api.startExisting(f.options), calls = guestCalls(f);
  assert.equal(result.url, 'http://127.0.0.1:8092'); assert.equal(result.port, 8092);
  assert.equal(result.activationEnabled, true); assert.equal(result.containerId, containerId);
  assert.equal(result.imageId, imageId); assert.equal(result.bindingSha256, f.binding.bindingSha256);
  assert.equal(f.calls.find(call => call[0] === 'profile')[1].existingOnly, true);
  assert.deepEqual(Array.from(calls.find(call => call[0] === 'start')), ['start', containerId]);
  assert.equal(calls.filter(call => call[0] === 'inspect').length, 2);
  assert(calls.every(call => !['build', 'run', 'compose', 'pull', 'rm'].includes(call[0])));
  assert(!f.calls.some(call => ['write', 'stage', 'bundle'].includes(call[0])));
});

test('already running retained runner is inspected without restart', async () => {
  const f = fixture({ running: true }); await f.api.startExisting(f.options);
  assert(!guestCalls(f).some(call => call[0] === 'start'));
});

test('disabled or mismatched managed configuration and missing profile never reach Docker', async () => {
  for (const mutation of [f => { f.values.MCP_OWNED_RESOURCES_ENABLED = 'false'; f.values.CODEBOT_OWNED_EXECUTION_ENABLED = 'false'; },
    f => { f.options.commandEnv.MCP_OWNED_TARGET_TOKEN = 'u'.repeat(64); }, f => f.denyProfile()]) {
    const f = fixture(); mutation(f);
    await assert.rejects(f.api.startExisting(f.options), { code: 'MCP_INSTALL_EXISTING_UNAVAILABLE' });
    assert.equal(guestCalls(f).length, 0);
  }
});

test('foreign project, image, loopback, profile, volume or token refuse before start', async () => {
  for (const mutation of [f => { f.container.Config.Labels['com.docker.compose.project'] = 'foreign'; },
    f => { f.container.Image = 'sha256:' + 'f'.repeat(64); },
    f => { f.container.HostConfig.PortBindings['8090/tcp'][0].HostIp = '0.0.0.0'; },
    f => { f.container.AppArmorProfile = 'unconfined'; },
    f => { f.volume.Labels['com.docker.compose.project'] = 'foreign'; },
    f => { f.container.Config.Env[1] = 'MCP_OWNED_TARGET_TOKEN=wrong'; }]) {
    const f = fixture(); mutation(f);
    await assert.rejects(f.api.startExisting(f.options), { code: 'MCP_INSTALL_EXISTING_UNAVAILABLE' });
    assert(!guestCalls(f).some(call => call[0] === 'start'));
  }
});

test('post-start identity drift is denied after the exact start', async () => {
  for (const mutation of [container => { container.Image = 'sha256:' + 'f'.repeat(64); },
    container => { container.NetworkSettings.Ports['8090/tcp'][0].HostIp = '0.0.0.0'; }]) {
    const f = fixture(); f.afterStart(mutation);
    await assert.rejects(f.api.startExisting(f.options), { code: 'MCP_INSTALL_EXISTING_UNAVAILABLE' });
    assert.equal(guestCalls(f).filter(call => call[0] === 'start').length, 1);
  }
});

test('protected recovery activation requires a trusted expected release image and profile', async () => {
  const f = fixture({ protectedRecovery: true });
  await assert.rejects(f.api.startExisting(f.options), { code: 'MCP_INSTALL_EXISTING_UNAVAILABLE' });
  assert(!guestCalls(f).some(call => call[0] === 'start'));
  const profile = require('../scripts/render-mcp-sandbox-apparmor').renderMcpSandboxAppArmor(
    fs.readFileSync(path.join(root, 'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'), 'utf8'),
    'dvaia-mcp-sandbox');
  const sha256 = require('node:crypto').createHash('sha256').update(profile).digest('hex');
  const result = await f.api.startExisting({ ...f.options, protectedRecoveryRelease: { image: imageId, profileSha256: sha256 } });
  assert.equal(result.imageId, imageId); assert.equal(f.profileSha256, sha256);
});
