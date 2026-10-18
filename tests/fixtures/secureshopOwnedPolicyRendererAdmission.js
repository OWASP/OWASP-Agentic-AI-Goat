'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

// Optional borrowed stateless renderer. This never starts, provisions, publishes,
// or removes installed resources; all policy persistence uses disposable pools.
async function capturePolicyRenderer(workspace, filename) {
  if (filename === undefined) return null;
  assert.ok(path.isAbsolute(filename) && !filename.startsWith(`${workspace}${path.sep}`));
  assert.equal(await fs.realpath(filename), filename);
  const stat = await fs.lstat(filename);
  assert.ok(stat.isFile() && stat.uid === process.getuid() && stat.nlink === 1
    && (stat.mode & 0o777) === 0o600 && stat.size <= 8192);
  const bytes = await fs.readFile(filename), admission = JSON.parse(bytes);
  assert.deepEqual(Object.keys(admission).sort(), ['version', 'workspace', 'home',
    'managedSha256', 'stageSha256', 'dockerExecutable', 'dockerExecutableSha256'].sort());
  assert.equal(admission.version, 1); assert.equal(admission.workspace, workspace);
  assert.ok(['managedSha256', 'stageSha256', 'dockerExecutableSha256']
    .every(key => /^[a-f0-9]{64}$/.test(admission[key])));
  assert.ok(path.isAbsolute(admission.home) && path.isAbsolute(admission.dockerExecutable));
  assert.equal(await fs.realpath(admission.home), admission.home);
  assert.equal(await fs.realpath(admission.dockerExecutable), admission.dockerExecutable);
  const digest = value => createHash('sha256').update(value).digest('hex');
  const executableStat = await fs.lstat(admission.dockerExecutable);
  assert.ok(executableStat.isFile() && (executableStat.mode & 0o111) !== 0
    && executableStat.size <= 128 * 1024 * 1024);
  assert.equal(digest(await fs.readFile(admission.dockerExecutable)), admission.dockerExecutableSha256);
  const managed = require('../../server/services/secureshopPolicyRendererManagedConfiguration');
  const installer = require('../../scripts/install/secureshop-owned-policy-renderer');
  const authority = require('../../scripts/local-docker-authority');
  const options = { root: workspace, home: admission.home };
  const record = managed.capture(options), stage = managed.capture(options, true);
  assert.equal(record?.sha256, admission.managedSha256);
  assert.equal(stage?.sha256, admission.stageSha256);
  assert.equal(record.value.enabled, true);
  const invoke = promisify(execFile);
  const execute = async (file, args, callOptions = {}) => {
    assert.ok(['docker', 'ssh', 'sudo'].includes(file));
    try { const result = await invoke(file === 'docker' ? admission.dockerExecutable : file, args, {
      cwd: workspace, env: callOptions.env || process.env, encoding: 'utf8',
      timeout: 25000, maxBuffer: 1024 * 1024 });
      return { ...result, exitCode: 0 }; }
    catch { throw Object.assign(Error('External policy renderer read-only inspection unavailable'),
      { code: 'POLICY_RENDER_INSPECTION_UNAVAILABLE' }); }
  };
  const p = await installer.plan({ ...options, execute });
  const inspect = async (kind, id) => {
    const value = await execute('docker', ['--host', record.authority.host, kind, 'inspect', id],
      { env: authority.sanitizeDockerEnvironment(process.env) });
    const rows = JSON.parse(value.stdout); assert.equal(rows.length, 1); return rows[0];
  };
  let retainedResource;
  const check = async () => {
    const currentStat = await fs.lstat(filename);
    assert.equal(currentStat.dev, stat.dev); assert.equal(currentStat.ino, stat.ino);
    assert.ok(currentStat.isFile() && currentStat.uid === stat.uid && currentStat.nlink === 1
      && (currentStat.mode & 0o777) === 0o600);
    assert.deepEqual(await fs.readFile(filename), bytes);
    const binStat = await fs.lstat(admission.dockerExecutable);
    assert.equal(binStat.dev, executableStat.dev); assert.equal(binStat.ino, executableStat.ino);
    assert.equal(digest(await fs.readFile(admission.dockerExecutable)), admission.dockerExecutableSha256);
    managed.assertCaptured(record, options); managed.assertCaptured(stage, options, true);
    await authority.verifyDockerAuthority({ authority: record.authority, execute });
    assert.equal(installer.sourceManifest(workspace).sha256, record.value.sourceSha256);
    const image = await inspect('image', record.value.imageId);
    installer._internals.inspectImage(image, p);
    const labels = { 'dvaia.policy.workspace': record.value.workspaceId,
      'dvaia.policy.owner': record.value.ownerId, 'dvaia.policy.source': record.value.sourceSha256 };
    const network = await inspect('network', p.network);
    assert.equal(network.Name, p.network); assert.equal(network.Driver, 'bridge');
    assert.equal(network.Internal, false);
    for (const [key, value] of Object.entries(labels)) assert.equal(network.Labels[key], value);
    const container = await inspect('container', record.value.containerId);
    assert.equal(container.Id, record.value.containerId); assert.equal(container.State.Running, true);
    installer._internals.inspectContainer(container, { p, value: record.value, image, labels });
    assert.equal(container.NetworkSettings.Networks[p.network].NetworkID, network.Id);
    assert.equal(container.AppArmorProfile, p.profile);
    const resource = { networkId: network.Id, startedAt: container.State.StartedAt,
      restartCount: container.RestartCount };
    if (retainedResource) assert.deepEqual(resource, retainedResource);
    else retainedResource = resource;
    await installer._internals.provisionProfile({ p, authority: record.authority,
      ...options, platform: process.platform, existingOnly: true,
      run: (file, args) => execute(file, args) }); // existingOnly verifies bytes/enforce; never installs.
  };
  await check();
  const runtime = require('../../server/services/secureshopPolicySandboxRuntime')
    .createSecureShopPolicySandboxRuntime({ baseUrl: `http://127.0.0.1:${record.value.port}`,
      timeoutMs: 10000, fetchImpl: (url, options) => {
        const parsed = new URL(url);
        assert.equal(parsed.origin, `http://127.0.0.1:${record.value.port}`);
        assert.ok((options.method === undefined && parsed.pathname === '/health')
          || (options.method === 'POST' && parsed.pathname === '/secureshop/policy-render'));
        return fetch(url, { ...options, redirect: 'error' });
      } });
  await runtime.checkReadiness();
  return { runtime, check, identity: { managedSha256: record.sha256,
    sourceSha256: record.value.sourceSha256, containerId: record.value.containerId,
    imageId: record.value.imageId } };
}


module.exports = { capturePolicyRenderer };
