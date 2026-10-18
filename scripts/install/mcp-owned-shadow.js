'use strict';
// Separate local service provisioning; no import-time effects, migration or
// objective activation. The CLI sandbox profile and containers are untouched.
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { localProfilePlan, createOwnedPrivateStorage } = require('./mcp-owned-local');
const { createCommandRunner, _internals } = require('./mcp-owned-provision');
const { collectOwnedServiceBuildContext } = require('./mcp-owned-service-build-context');
const config = require('../../server/services/mcp/ownedShadowManagedConfiguration');
const { workspaceId } = require('../../server/services/mcp/ownedManagedConfiguration');
const { renderOwnedShadowProfile } = require('../../sidecars/sandbox-runner/owned-shadow/profile');
const { createOwnedShadowServiceClient } = require('../../server/services/mcp/ownedShadowServiceClient');
function plan({ root = path.resolve(__dirname, '../..'), home = os.homedir(), platform = process.platform, colimaProfile, ownedLabSession, port = 8094 } = {}) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('MCP_SHADOW_PORT_INVALID');
  const profile = `dvaia-owned-shadow-${workspaceId(root)}`;
  return Object.freeze({ ...localProfilePlan({ root, home, platform, colimaProfile, ownedLabSession }), profile,
    destination: `/etc/apparmor.d/${profile}`, container: profile, volume: `${profile}-state`,
    managedPath: config.managedPath({ root, home }), port, root });
}
function assertMatchingContainer(inspected, p, image, token) {
  if (inspected?.Config?.Labels?.['dvaia.shadow.owner'] !== p.profile || inspected.Image !== image
      || !inspected.HostConfig.SecurityOpt.includes(`apparmor=${p.profile}`)
      || !inspected.HostConfig.SecurityOpt.includes('seccomp=unconfined')
      || inspected.Config.User !== '10001:10001'
      || inspected.HostConfig.Privileged === true || inspected.HostConfig.NetworkMode === 'host'
      || inspected.Mounts?.length !== 1 || !inspected.Mounts.every(mount => mount.Type === 'volume' && mount.Name === p.volume && mount.Destination === '/state' && mount.RW === true)
      || inspected.HostConfig.PortBindings?.['8092/tcp']?.length !== 1
      || inspected.HostConfig.PortBindings['8092/tcp'][0].HostIp !== '127.0.0.1'
      || inspected.HostConfig.PortBindings['8092/tcp'][0].HostPort !== String(p.port)
      || !inspected.Config.Env?.includes(`MCP_OWNED_SHADOW_TOKEN=${token}`)
      || !inspected.Config.Env?.includes('MCP_OWNED_SHADOW_ROOT=/state/targets')
      || !inspected.Config.Env?.includes(`MCP_OWNED_TARGET_APPARMOR_PROFILE=${p.profile}`)) throw new Error('MCP_SHADOW_CONTAINER_CONFLICT');
}
async function provision({ root, home, platform, colimaProfile, ownedLabSession, port, commandEnv = process.env,
  run, privateStorage, serviceFactory = createOwnedShadowServiceClient } = {}) {
  const p = plan({ root, home, platform, colimaProfile, ownedLabSession, port });
  _internals.assertDockerAuthority(commandEnv, p);
  if (p.platform !== 'win32') run ||= createCommandRunner({ cwd: p.root, env: commandEnv });
  async function checked(file, args, stage, timeoutMs = 30000) {
    const result = await run(file, args, { stage, timeoutMs, maxOutputBytes: 2 * 1024 * 1024 });
    if (result?.exitCode !== 0) throw new Error(`MCP_SHADOW_INSTALL_FAILED:${stage}`);
    return result.stdout || '';
  }
  const docker = (args, stage, timeout, bundlePath) => p.platform === 'win32'
    ? ownedLabSession.executeDocker(args, { scope: 'provision', ...(bundlePath ? { bundlePath } : {}) })
    : checked('docker', ['--host', p.dockerHost, ...args], stage, timeout);
  const existing = config.load({ file: p.managedPath });
  if (existing && (existing.profile !== p.profile || existing.container !== p.container || existing.url !== `http://127.0.0.1:${p.port}`)) throw new Error('MCP_SHADOW_INSTALL_CONFLICT');
  const rendered = renderOwnedShadowProfile(p.profile);
  const temporary = p.platform === 'win32' ? null : await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-shadow-install-'));
  try {
    const renderedSha256 = crypto.createHash('sha256').update(rendered).digest('hex');
    if (p.platform === 'win32') await ownedLabSession.installAndVerifyProfile({ name: p.profile, bytes: Buffer.from(rendered), sha256: renderedSha256 });
    else {
      const renderedFile = path.join(temporary, 'profile');
      await fs.writeFile(renderedFile, rendered, { flag: 'wx', mode: 0o600 });
      const profileArgs = { plan: p, renderedFile, renderedSha256, run,
        nonce: crypto.randomBytes(6).toString('hex') };
      if (p.platform === 'linux') await _internals.linuxInstall(profileArgs);
      else await _internals.darwinInstall(profileArgs);
    }
    const tag = `${p.container}:local`;
    // Reuse the recorded immutable image on repeat. Rebuilding unchanged Docker
    // input can change image metadata; it must not silently select a new runtime.
    const buildSecrets=[];
    if(commandEnv.NODE_EXTRA_CA_CERTS){
      const ca=await fs.lstat(commandEnv.NODE_EXTRA_CA_CERTS);
      if(!ca.isFile()||ca.isSymbolicLink()||ca.size===0||ca.size>2*1024*1024)throw Error('MCP_SHADOW_BUILD_CA_INVALID');
      if (p.platform === 'win32') {
        const bytes = await fs.readFile(commandEnv.NODE_EXTRA_CA_CERTS);
        if (bytes.length !== ca.size) throw Error('MCP_SHADOW_BUILD_CA_INVALID');
        const source = await ownedLabSession.stagePrivateBuildSecret({ id: 'npm_ca', bytes,
          sha256: crypto.createHash('sha256').update(bytes).digest('hex') });
        buildSecrets.push('--secret', `id=npm_ca,src=${source}`);
      } else buildSecrets.push('--secret',`id=npm_ca,src=${path.resolve(commandEnv.NODE_EXTRA_CA_CERTS)}`);
    }
    if (!existing) {
      const bundlePath = p.platform === 'win32'
        ? await ownedLabSession.stageReviewedBundle(await collectOwnedServiceBuildContext({ root: p.root, service: 'shadow' })) : undefined;
      await docker(['build', ...buildSecrets, '-f', p.platform === 'win32' ? 'sidecars/sandbox-runner/owned-shadow/Dockerfile'
        : path.join(p.root, 'sidecars/sandbox-runner/owned-shadow/Dockerfile'), '-t', tag,
        p.platform === 'win32' ? 'sidecars/sandbox-runner' : path.join(p.root, 'sidecars/sandbox-runner')], 'shadow-build', 300000, bundlePath);
    }
    const image = JSON.parse(await docker(['image', 'inspect', existing?.image || tag], 'shadow-image'))[0]?.Id;
    const values = config.validate({ version: 1, enabled: existing?.enabled || false,
      url: `http://127.0.0.1:${p.port}`, token: existing?.token || crypto.randomBytes(48).toString('base64url'),
      profile: p.profile, container: p.container, image, runtimeDigest: existing?.runtimeDigest || null });
    // Save recovery credentials before any service exists; never overwrite a
    // previous configuration or rotate a token during an ambiguous operation.
    if (!existing) {
      const bytes = Buffer.from(JSON.stringify(values) + '\n');
      if (p.platform === 'win32') await (privateStorage || createOwnedPrivateStorage()).write(p.managedPath, bytes, null);
      else {
        await fs.mkdir(path.dirname(p.managedPath), { recursive: true, mode: 0o700 });
        const fd = await fs.open(p.managedPath, 'wx', 0o600);
        try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
      }
    } else if (existing.image !== image) throw new Error('MCP_SHADOW_IMAGE_UPGRADE_REQUIRES_DRAIN');
    const ids = (await docker(['ps', '-aq', '--filter', `name=^/${p.container}$`], 'shadow-existing')).trim();
    if (ids) {
      const found = JSON.parse(await docker(['inspect', p.container], 'shadow-inspect'))[0];
      assertMatchingContainer(found, p, image, values.token);
      if (found.State?.Running !== true) {
        if (!/^[a-f0-9]{64}$/.test(found.Id || '')) throw new Error('MCP_SHADOW_CONTAINER_CONFLICT');
        await docker(['start', found.Id], 'shadow-restart');
        const resumed = JSON.parse(await docker(['inspect', found.Id], 'shadow-reinspect'))[0];
        if (resumed?.Id !== found.Id || resumed.State?.Running !== true) throw new Error('MCP_SHADOW_CONTAINER_CONFLICT');
        assertMatchingContainer(resumed, p, image, values.token);
      }
    } else {
      await docker(['volume', 'create', '--label', `dvaia.shadow.owner=${p.profile}`, p.volume], 'shadow-volume');
      const volume = JSON.parse(await docker(['volume', 'inspect', p.volume], 'shadow-volume-inspect'))[0];
      if (volume?.Labels?.['dvaia.shadow.owner'] !== p.profile) throw new Error('MCP_SHADOW_VOLUME_CONFLICT');
      await docker(['run', '--rm', '--network', 'none', '--user', '0:0', '--mount', `type=volume,source=${p.volume},target=/state`,
        '--entrypoint', 'sh', image, '-c', 'chown 10001:10001 /state && chmod 0700 /state'], 'shadow-state-owner');
      const envBytes = Buffer.from(`MCP_OWNED_SHADOW_TOKEN=${values.token}\nMCP_OWNED_SHADOW_ROOT=/state/targets\nMCP_OWNED_TARGET_APPARMOR_PROFILE=${p.profile}\n`);
      let envFile;
      if (p.platform === 'win32') envFile = await ownedLabSession.stagePrivateEnvironment({ bytes: envBytes,
        sha256: crypto.createHash('sha256').update(envBytes).digest('hex') });
      else {
        envFile = path.join(temporary, 'service.env');
        await fs.writeFile(envFile, envBytes, { flag: 'wx', mode: 0o600 });
      }
      await docker(['run', '--detach', '--name', p.container, '--label', `dvaia.shadow.owner=${p.profile}`,
        '--user', '10001:10001', '--security-opt', `apparmor=${p.profile}`, '--security-opt', 'seccomp=unconfined',
        '--publish', `127.0.0.1:${p.port}:8092`, '--mount', `type=volume,source=${p.volume},target=/state`,
        '--env-file', envFile, '--entrypoint', 'node', image, '/app/owned-shadow/service.js'], 'shadow-start');
    }
    const service = serviceFactory({ baseUrl: values.url, token: values.token });
    let ready = false;
    for (let attempt = 0; attempt < 10; attempt++) {
      try { ready = (await service.readiness())?.ready === true; } catch { ready = false; }
      if (ready) break;
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    if (!ready) throw new Error('MCP_SHADOW_SERVICE_NOT_READY');
    return Object.freeze({ ok: true, profile: p.profile, image, managedPath: p.managedPath,
      activationEnabled: values.enabled, migrationsApplied: false });
  } finally { if (temporary) await fs.rm(temporary, { recursive: true, force: true }); }
}
async function startExisting({ root = path.resolve(__dirname, '../..'), home = os.homedir(), platform = process.platform,
  ownedLabSession, commandEnv = process.env, loadManaged = config.load, planService = plan } = {}) {
  if (platform !== 'win32') throw new Error('MCP_SHADOW_OWNED_LAB_REQUIRED');
  const managedPath = config.managedPath({ root, home });
  const existing = loadManaged({ file: managedPath });
  if (!existing || config.validate(existing).enabled !== true) throw new Error('MCP_SHADOW_CONFIGURATION_REQUIRED');
  const port = Number(new URL(existing.url).port);
  const p = planService({ root, home, platform, ownedLabSession, port });
  _internals.assertDockerAuthority(commandEnv, p);
  if (existing.profile !== p.profile || existing.container !== p.container || existing.url !== `http://127.0.0.1:${p.port}`)
    throw new Error('MCP_SHADOW_INSTALL_CONFLICT');
  const inspect = args => ownedLabSession.executeDocker(args, { scope: 'inspect' });
  const image = JSON.parse(await inspect(['image', 'inspect', existing.image]))[0]?.Id;
  if (image !== existing.image) throw new Error('MCP_SHADOW_IMAGE_UPGRADE_REQUIRES_DRAIN');
  const ids = (await inspect(['ps', '-aq', '--filter', `name=^/${p.container}$`])).trim();
  if (!ids) throw new Error('MCP_SHADOW_CONTAINER_CONFLICT');
  const found = JSON.parse(await inspect(['inspect', p.container]))[0];
  assertMatchingContainer(found, p, image, existing.token);
  if (!/^[a-f0-9]{64}$/.test(found.Id || '')) throw new Error('MCP_SHADOW_CONTAINER_CONFLICT');
  if (found.State?.Running === true) {
    if (found.AppArmorProfile !== p.profile) throw new Error('MCP_SHADOW_CONTAINER_CONFLICT');
  } else {
    await ownedLabSession.executeDocker(['start', found.Id], { scope: 'provision' });
    const resumed = JSON.parse(await inspect(['inspect', found.Id]))[0];
    if (resumed?.Id !== found.Id || resumed.State?.Running !== true || resumed.AppArmorProfile !== p.profile)
      throw new Error('MCP_SHADOW_CONTAINER_CONFLICT');
    assertMatchingContainer(resumed, p, image, existing.token);
  }
  return Object.freeze({ ok: true, enabled: true, url: existing.url, managedPath, profile: p.profile, container: p.container });
}
module.exports = { plan, provision, startExisting };
if (require.main === module) {
  const args = process.argv.slice(2);
  const profile = args.find(arg => arg.startsWith('--colima-profile='))?.slice('--colima-profile='.length);
  if (args.some(arg => !['--plan', '--provision'].includes(arg) && !arg.startsWith('--colima-profile='))
      || Number(args.includes('--plan')) + Number(args.includes('--provision')) !== 1) {
    process.stderr.write('Use --plan or --provision, with --colima-profile=colima-<name> on macOS.\n');
    process.exitCode = 2;
  } else {
    Promise.resolve().then(() => args.includes('--plan') ? plan({ colimaProfile: profile }) : provision({ colimaProfile: profile }))
      .then(result => process.stdout.write(JSON.stringify(result) + '\n'))
      .catch(error => { process.stderr.write(JSON.stringify({ ok: false, error: error.code || error.message }) + '\n'); process.exitCode = 1; });
  }
}
