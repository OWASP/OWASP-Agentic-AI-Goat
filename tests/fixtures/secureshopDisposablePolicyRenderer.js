'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const net = require('node:net');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const managed = require('../../server/services/secureshopPolicyRendererManagedConfiguration');
const installer = require('../../scripts/install/secureshop-owned-policy-renderer');
const authority = require('../../scripts/local-docker-authority');
const { createSecureShopPolicySandboxRuntime, readBoundedPolicyRenderJson }
  = require('../../server/services/secureshopPolicySandboxRuntime');
const { ISOLATION } = require('../../server/services/secureshopPromptPolicyContract');

const invoke = promisify(execFile);
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const UUID_HEX = /^[a-f0-9]{12}$/;

function createArgs({ name, network, profile, imageId, labels, port }) {
  assert.match(name, /^dvaia-v59-policy-[a-f0-9]{12}$/);
  assert.match(network, /^dvaia-v59-policy-[a-f0-9]{12}$/);
  assert.match(profile, /^dvaia-owned-policy-renderer-[a-f0-9]{12}$/);
  assert.match(imageId, /^sha256:[a-f0-9]{64}$/);
  assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535);
  return ['create', '--name', name, ...Object.entries(labels).flatMap(([key, value]) => ['--label', `${key}=${value}`]),
    '--network', network, '--read-only', '--user', '10001:10001', '--memory', '512m', '--cpus', '1',
    '--pids-limit', '128', '--cap-drop', 'ALL', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,mode=1777,size=128m',
    '--security-opt', 'seccomp=unconfined', '--security-opt', `apparmor=${profile}`,
    '--publish', `127.0.0.1:${port}:8090`, '--env', 'SECURESHOP_POLICY_RENDER_ENABLED=true',
    '--env', 'SECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1', imageId];
}

function assertOwnedResource(kind, row, { expectedId, labels, name, network }) {
  const id = row?.Id;
  assert.ok(typeof id === 'string' && /^[a-f0-9]{64}$|^sha256:[a-f0-9]{64}$/.test(id));
  if (expectedId) assert.equal(id, expectedId);
  const actual = kind === 'container' ? row.Config?.Labels : row.Labels || row.Config?.Labels;
  for (const [key, value] of Object.entries(labels)) assert.equal(actual?.[key], value);
  if (kind === 'container') assert.equal(row.Name, `/${name}`);
  if (kind === 'network') assert.equal(row.Name, network);
  return id;
}

async function chooseLoopbackPort() {
  const listener = net.createServer();
  await new Promise((resolve, reject) => {
    listener.once('error', reject);
    listener.listen(0, '127.0.0.1', resolve);
  });
  const port = listener.address().port;
  await new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
  return port;
}
function transientHealthFailure(error) {
  const cause = error?.cause;
  const errors = cause?.errors || [cause];
  return errors.length > 0 && errors.every(item => item?.code === 'ECONNREFUSED'
    || item?.code === 'ECONNRESET'
    || (item?.code === 'UND_ERR_SOCKET' && item?.message === 'other side closed'));
}
async function diagnosticDestination(filename) {
  assert.ok(typeof filename === 'string' && path.isAbsolute(filename)
    && path.basename(filename) === 'disposable-policy-renderer-diagnostic.json');
  const parent = path.dirname(filename), stat = await fs.lstat(parent);
  assert.match(path.basename(parent), /^run-[A-Za-z0-9_]{8,32}$/);
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid()
    && (stat.mode & 0o777) === 0o700 && await fs.realpath(parent) === parent);
  await assert.rejects(fs.lstat(filename), error => error?.code === 'ENOENT');
  return { parent, dev: stat.dev, ino: stat.ino };
}
function startupErrorFacts(error, depth = 0) {
  if (!error || depth > 3) return null;
  const fact = { name: String(error.name || 'Error').slice(0, 80),
    code: typeof error.code === 'string' ? error.code.slice(0, 80) : null,
    message: String(error.message || '').slice(0, 512) };
  if (error.cause) fact.cause = startupErrorFacts(error.cause, depth + 1);
  if (Array.isArray(error.errors)) fact.errors = error.errors.slice(0, 4)
    .map(item => startupErrorFacts(item, depth + 1));
  return fact;
}
function startupFailureRecord({ stage, error, healthAttempts, containerId, port,
  state, publishedPorts, logs, observationErrors = [] }) {
  return { version: 1, stage, error: startupErrorFacts(error), healthAttempts,
    containerId: containerId || null, port: port || null,
    containerState: state ? { status: state.Status || null, running: state.Running === true,
      exitCode: Number.isInteger(state.ExitCode) ? state.ExitCode : null,
      oomKilled: state.OOMKilled === true, error: String(state.Error || '').slice(0, 512) } : null,
    publishedPorts: Array.isArray(publishedPorts) ? publishedPorts.slice(0, 2)
      .map(value => ({ hostIp: String(value.HostIp || '').slice(0, 64),
        hostPort: String(value.HostPort || '').slice(0, 16) })) : null,
    startupLogs: typeof logs === 'string' ? logs.slice(-4096) : null,
    observationErrors: observationErrors.slice(0, 3).map(value => String(value).slice(0, 160)) };
}

async function privateAdmission(workspace, filename) {
  assert.ok(path.isAbsolute(filename) && !filename.startsWith(`${workspace}${path.sep}`));
  assert.equal(await fs.realpath(filename), filename);
  const stat = await fs.lstat(filename);
  assert.ok(stat.isFile() && stat.uid === process.getuid() && stat.nlink === 1
    && (stat.mode & 0o777) === 0o600 && stat.size <= 8192);
  const bytes = await fs.readFile(filename);
  const value = JSON.parse(bytes);
  assert.deepEqual(Object.keys(value).sort(), ['version', 'workspace', 'home', 'managedSha256',
    'stageSha256', 'dockerExecutable', 'dockerExecutableSha256'].sort());
  assert.equal(value.version, 1); assert.equal(value.workspace, workspace);
  for (const key of ['managedSha256', 'stageSha256', 'dockerExecutableSha256']) {
    assert.match(value[key], /^[a-f0-9]{64}$/);
  }
  assert.ok(path.isAbsolute(value.home) && path.isAbsolute(value.dockerExecutable));
  assert.equal(await fs.realpath(value.home), value.home);
  assert.equal(await fs.realpath(value.dockerExecutable), value.dockerExecutable);
  const bin = await fs.lstat(value.dockerExecutable);
  assert.ok(bin.isFile() && !bin.isSymbolicLink() && (bin.mode & 0o111) !== 0
    && bin.size <= 128 * 1024 * 1024);
  assert.equal(sha(await fs.readFile(value.dockerExecutable)), value.dockerExecutableSha256);
  return { value, stat, bytes, bin };
}

async function createDisposablePolicyRenderer({ workspace, admissionFilename, diagnosticPath } = {}) {
  assert.ok(path.isAbsolute(workspace) && await fs.realpath(workspace) === workspace);
  const diagnosticDirectory = await diagnosticDestination(diagnosticPath);
  const admission = await privateAdmission(workspace, admissionFilename);
  const options = { root: workspace, home: admission.value.home };
  const record = managed.capture(options), stage = managed.capture(options, true);
  assert.equal(record?.sha256, admission.value.managedSha256);
  assert.equal(stage?.sha256, admission.value.stageSha256);
  assert.equal(record.value.enabled, true);
  assert.equal(record.authority.workspaceId, record.value.workspaceId);
  assert.equal(record.value.profile, `dvaia-owned-policy-renderer-${record.value.workspaceId}`);
  assert.equal(sha(installer._internals.profileBytes(workspace, record.value.workspaceId)), record.value.profileSha256);
  const source = installer.sourceManifest(workspace);
  const suffix = crypto.randomBytes(6).toString('hex');
  assert.match(suffix, UUID_HEX);
  const name = `dvaia-v59-policy-${suffix}`, network = name, image = `${name}:local`;
  const labels = { 'dvaia.policy.workspace': record.value.workspaceId,
    'dvaia.policy.owner': record.value.ownerId, 'dvaia.policy.source': source.sha256,
    'dvaia.qualification': suffix };
  const env = authority.sanitizeDockerEnvironment(process.env);
  const execute = async (file, args, { timeoutMs = 30000, maxBuffer = 1024 * 1024 } = {}) => {
    assert.ok(['docker', 'ssh', 'sudo'].includes(file));
    const command = file === 'docker' ? admission.value.dockerExecutable : file;
    const response = await invoke(command, args, { cwd: workspace, env, encoding: 'utf8',
      timeout: timeoutMs, maxBuffer });
    return { ...response, exitCode: 0 };
  };
  const docker = async (args, timeoutMs = 30000, maxBuffer = 1024 * 1024) => (await execute('docker',
    ['--host', record.authority.host, ...args], { timeoutMs, maxBuffer })).stdout;
  let imageAttempted = false, networkAttempted = false, containerAttempted = false;
  let imageId, networkId, containerId, port, closed = false, closePromise;
  let setupStage = 'preflight', healthAttempts = 0;
  const assertUnchanged = async () => {
    const now = await fs.lstat(admissionFilename);
    assert.equal(now.dev, admission.stat.dev); assert.equal(now.ino, admission.stat.ino);
    assert.ok(now.isFile() && now.uid === admission.stat.uid && now.nlink === 1
      && (now.mode & 0o777) === 0o600);
    assert.deepEqual(await fs.readFile(admissionFilename), admission.bytes);
    const bin = await fs.lstat(admission.value.dockerExecutable);
    assert.equal(bin.dev, admission.bin.dev); assert.equal(bin.ino, admission.bin.ino);
    assert.equal(sha(await fs.readFile(admission.value.dockerExecutable)), admission.value.dockerExecutableSha256);
    managed.assertCaptured(record, options); managed.assertCaptured(stage, options, true);
    assert.equal(installer.sourceManifest(workspace).sha256, source.sha256);
    assert.equal(sha(installer._internals.profileBytes(workspace, record.value.workspaceId)), record.value.profileSha256);
  };
  const inspect = async (kind, id) => {
    const rows = JSON.parse(await docker([kind, 'inspect', id], 10000));
    assert.equal(rows.length, 1); return rows[0];
  };
  const assertOwned = (kind, row, expectedId) => assertOwnedResource(kind, row,
    { expectedId, labels, name, network });
  const absent = async (kind, label) => {
    if (kind === 'container') return !(await docker(['ps', '-aq', '--filter', `name=^/${label}$`, '--format', '{{.Names}}'], 10000)).trim();
    if (kind === 'network') return !(await docker(['network', 'ls', '--filter', `name=^${label}$`, '--format', '{{.Name}}'], 10000)).trim();
    return !(await docker(['images', '--filter', `reference=${label}`, '--format', '{{.Repository}}:{{.Tag}}'], 10000)).trim();
  };
  const labeled = async kind => {
    const args = kind === 'container' ? ['ps', '-aq'] : kind === 'network' ? ['network', 'ls'] : ['images'];
    return (await docker([...args, '--filter', `label=dvaia.qualification=${suffix}`,
      '--format', kind === 'container' ? '{{.ID}}' : kind === 'network' ? '{{.ID}}' : '{{.Repository}}:{{.Tag}}'], 10000)).trim();
  };
  async function check() {
    if (closed) throw new Error('Disposable policy renderer closed');
    await assertUnchanged();
    await authority.verifyDockerAuthority({ authority: record.authority, execute });
    await installer._internals.provisionProfile({ p: { workspaceId: record.value.workspaceId,
      profile: record.value.profile }, authority: record.authority, ...options,
      platform: process.platform, existingOnly: true,
      run: (file, args) => execute(file, args) });
    const p = { workspaceId: record.value.workspaceId, sourceSha256: source.sha256,
      profile: record.value.profile, container: name, network, port };
    const built = await inspect('image', imageId);
    assertOwned('image', built, imageId);
    installer._internals.inspectImage(built, p);
    const net = await inspect('network', network);
    assertOwned('network', net, networkId);
    assert.equal(net.Id, networkId); assert.equal(net.Name, network);
    assert.equal(net.Driver, 'bridge'); assert.equal(net.Internal, false);
    for (const [key, value] of Object.entries(labels)) assert.equal(net.Labels[key], value);
    const container = await inspect('container', name);
    assertOwned('container', container, containerId);
    assert.equal(container.Id, containerId); assert.equal(container.State.Running, true);
    assert.equal(container.RestartCount, 0); assert.equal(container.AppArmorProfile, p.profile);
    installer._internals.inspectContainer(container, { p, value: { imageId }, image: built, labels });
    assert.equal(container.NetworkSettings.Networks[network].NetworkID, networkId);
    assert.equal(container.NetworkSettings.Ports['8090/tcp'][0].HostPort, String(port));
  }
  async function close() {
    if (closePromise) return closePromise;
    closePromise = (async () => {
      closed = true;
      const failures = [];
      if (containerAttempted || networkAttempted || imageAttempted) {
        await authority.verifyDockerAuthority({ authority: record.authority, execute });
      }
      for (const [kind, attempted, label, expectedId] of [
        ['container', containerAttempted, name, containerId],
        ['network', networkAttempted, network, networkId],
        ['image', imageAttempted, image, imageId],
      ]) {
        if (!attempted) continue;
        try {
          if (await absent(kind, label)) {
            if (expectedId && await labeled(kind)) throw new Error('Owned resource lost its expected name');
            continue;
          }
          const row = await inspect(kind, label);
          const id = assertOwned(kind, row, expectedId);
          const remove = kind === 'container' ? ['rm', '-f', id]
            : kind === 'network' ? ['network', 'rm', id] : ['image', 'rm', '-f', id];
          await docker(remove, 60000);
        } catch (error) { failures.push(error); }
      }
      const gone = await Promise.all([
        containerAttempted ? Promise.all([absent('container', name), labeled('container')]).then(([a, b]) => a && !b) : true,
        networkAttempted ? Promise.all([absent('network', network), labeled('network')]).then(([a, b]) => a && !b) : true,
        imageAttempted ? Promise.all([absent('image', image), labeled('image')]).then(([a, b]) => a && !b) : true,
      ]);
      await assertUnchanged();
      if (failures.length || gone.some(value => !value)) throw new Error('Disposable policy renderer cleanup incomplete');
    })();
    return closePromise;
  }
  async function captureStartupFailure(error) {
    const parent = diagnosticDirectory.parent, stat = await fs.lstat(parent);
    assert.ok(stat.isDirectory() && stat.uid === process.getuid()
      && (stat.mode & 0o777) === 0o700 && stat.dev === diagnosticDirectory.dev
      && stat.ino === diagnosticDirectory.ino && await fs.realpath(parent) === parent);
    let state = null, publishedPorts = null, logs = null;
    const observationErrors = [];
    if (containerAttempted) {
      try {
        const row = await inspect('container', name);
        assertOwned('container', row, containerId);
        state = row.State;
        publishedPorts = row.NetworkSettings?.Ports?.['8090/tcp'];
        const output = await execute('docker', ['--host', record.authority.host,
          'logs', '--tail', '60', row.Id], { timeoutMs: 5000, maxBuffer: 64 * 1024 });
        logs = `${output.stdout || ''}\n${output.stderr || ''}`;
      } catch (observationError) {
        observationErrors.push(startupErrorFacts(observationError)?.code ||
          startupErrorFacts(observationError)?.name || 'observation-failed');
      }
    }
    const value = startupFailureRecord({ stage: setupStage, error, healthAttempts,
      containerId, port, state, publishedPorts, logs, observationErrors });
    const handle = await fs.open(diagnosticPath, 'wx', 0o600);
    try { await handle.writeFile(`${JSON.stringify(value)}\n`); await handle.sync(); }
    finally { await handle.close(); }
  }
  try {
    await assertUnchanged();
    setupStage = 'docker-authority';
    await authority.verifyDockerAuthority({ authority: record.authority, execute });
    setupStage = 'enforced-profile';
    await installer._internals.provisionProfile({ p: { workspaceId: record.value.workspaceId,
      profile: record.value.profile }, authority: record.authority, ...options,
      platform: process.platform, existingOnly: true,
      run: (file, args) => execute(file, args) });
    assert.ok(await absent('container', name) && await absent('network', network) && await absent('image', image));
    setupStage = 'dedicated-image-build';
    imageAttempted = true;
    await docker(['build', '--pull=false', '--network=default', '--label', `dvaia.policy.source=${source.sha256}`,
      '--label', `dvaia.qualification=${suffix}`, '--label', `dvaia.policy.workspace=${record.value.workspaceId}`,
      '--label', `dvaia.policy.owner=${record.value.ownerId}`,
      '-f', path.join(workspace, 'sidecars/sandbox-runner/policy-render/Dockerfile'),
      '-t', image, path.join(workspace, 'sidecars/sandbox-runner')], 300000, 16 * 1024 * 1024);
    await assertUnchanged();
    imageId = (await inspect('image', image)).Id;
    installer._internals.inspectImage(await inspect('image', imageId), { sourceSha256: source.sha256 });
    setupStage = 'isolated-network';
    networkAttempted = true;
    networkId = (await docker(['network', 'create', ...Object.entries(labels).flatMap(([key, value]) =>
      ['--label', `${key}=${value}`]), network])).trim();
    port = await chooseLoopbackPort();
    setupStage = 'isolated-container-create';
    containerAttempted = true;
    containerId = (await docker(createArgs({ name, network, profile: record.value.profile,
      imageId, labels, port }))).trim();
    setupStage = 'isolated-container-start';
    await docker(['start', containerId]);
    const runtime = createSecureShopPolicySandboxRuntime({ baseUrl: `http://127.0.0.1:${port}`,
      timeoutMs: 10000, fetchImpl: (url, request) => {
        const parsed = new URL(url);
        assert.equal(parsed.origin, `http://127.0.0.1:${port}`);
        assert.ok((request.method === undefined && parsed.pathname === '/health')
          || (request.method === 'POST' && parsed.pathname === '/secureshop/policy-render'));
        return fetch(url, { ...request, redirect: 'error' });
      } });
    let ready = false, lastError;
    setupStage = 'loopback-health';
    for (let attempt = 0; attempt < 20; attempt += 1) {
      healthAttempts = attempt + 1;
      try {
        const response = await fetch(`http://127.0.0.1:${port}/health`, {
          signal: AbortSignal.timeout(1000), redirect: 'error' });
        if (!response.ok) throw new Error('Disposable policy renderer health rejected');
        const health = await readBoundedPolicyRenderJson(response);
        if (health?.policyRenderer?.enabled !== true || health.policyRenderer.available !== true
            || health.policyRenderer.isolation !== ISOLATION) {
          throw new Error('Disposable policy renderer health identity mismatch');
        }
        await runtime.checkReadiness(); ready = true; break;
      } catch (error) { if (!transientHealthFailure(error)) throw error; lastError = error; }
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    if (!ready) throw lastError || new Error('Disposable policy renderer did not become ready');
    setupStage = 'post-start-identity';
    await check();
    return Object.freeze({ runtime, check, close,
      identity: Object.freeze({ sourceSha256: source.sha256, imageId, containerId,
        networkId, profileSha256: record.value.profileSha256, port }) });
  } catch (error) {
    if (error && typeof error === 'object') {
      error.stage = setupStage;
      if (!error.code && typeof error.cause?.code === 'string') error.code = error.cause.code;
    }
    try { await captureStartupFailure(error); } catch { /* Keep the original setup failure and owned cleanup. */ }
    try { await close(); } catch (cleanup) { throw new AggregateError([error, cleanup], 'Disposable policy renderer setup and cleanup failed'); }
    throw error;
  }
}

module.exports = { createDisposablePolicyRenderer, createArgs, assertOwnedResource,
  transientHealthFailure, diagnosticDestination, startupErrorFacts, startupFailureRecord };
