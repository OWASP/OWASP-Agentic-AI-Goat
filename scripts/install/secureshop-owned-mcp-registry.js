'use strict';

// Build-free managed lifecycle. Never send the workspace (including private archives)
// as a Docker build context. Production qualification remains a separate gate.
const fs = require('node:fs/promises'),
  path = require('node:path'),
  os = require('node:os'),
  crypto = require('node:crypto');
const {
  localProfilePlan
} = require('./mcp-owned-local');
const {
  createCommandRunner,
  _internals
} = require('./mcp-owned-provision');
const {
  workspaceId
} = require('../../server/services/mcp/ownedManagedConfiguration');
const {
  validateConfiguration
} = require('../../server/services/secureshopOwnedMcpRegistryProduction');
const {
  createOwnedMcpRegistryClient
} = require('../../server/services/secureshopOwnedMcpRegistryClient');
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const fail = code => Object.assign(Error('Registry service requires explicit recovery'), {
  code
});
const ID = /^[a-f0-9]{64}$/,
  IMAGE = /^sha256:[a-f0-9]{64}$/;
function plan({
  root = path.resolve(__dirname, '../..'),
  home = os.homedir(),
  configurationHome = home,
  platform = process.platform,
  colimaProfile,
  port = 8095,
  imageId,
  resourceNamespace,
  mode = 'vuln'
} = {}) {
  if (typeof configurationHome !== 'string' || !path.isAbsolute(configurationHome)) throw fail('REGISTRY_CONFIGURATION_HOME_INVALID');
  if (resourceNamespace !== undefined && (typeof resourceNamespace !== 'string' || !/^[a-f0-9]{12}$/.test(resourceNamespace))) throw fail('REGISTRY_NAMESPACE_INVALID');
  if (!IMAGE.test(imageId || '') || !Number.isInteger(port) || port < 1024 || port > 65535 || !['vuln', 'fixed'].includes(mode)) throw fail('REGISTRY_PLAN_INVALID');
  const workspace = workspaceId(root),
    profile = 'owasp-ai-goat-owned-mcp-registry-' + workspace,
    directory = path.join(configurationHome, '.owasp-ai-goat', workspace);
  return Object.freeze({
    ...localProfilePlan({
      root,
      home,
      platform,
      colimaProfile
    }),
    root,
    workspace,
    profile,
    ...(resourceNamespace === undefined ? {} : { resourceNamespace }),
    container: profile + (resourceNamespace === undefined ? '' : '-qualification-' + resourceNamespace),
    network: profile + (resourceNamespace === undefined ? '' : '-qualification-' + resourceNamespace) + '-internal',
    destination: '/etc/apparmor.d/' + profile,
    port,
    imageId,
    mode,
    directory,
    configFile: path.join(directory, 'secureshop-owned-mcp-registry.json'),
    receiptFile: path.join(directory, 'secureshop-owned-mcp-registry-install.json')
  });
}
async function readPrivate(file) {
  let fd;
  try {
    fd = await fs.open(file, require('node:fs').constants.O_RDONLY | require('node:fs').constants.O_NOFOLLOW);
    const s = await fd.stat();
    if (!s.isFile() || s.uid !== process.getuid() || s.mode & 0o077 || s.nlink !== 1 || s.size > 16384) throw fail('REGISTRY_PRIVATE_STATE_UNTRUSTED');
    return JSON.parse(await fd.readFile('utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  } finally {
    await fd?.close();
  }
}
async function writePrivate(file, value, previous) {
  if (JSON.stringify(await readPrivate(file)) !== JSON.stringify(previous)) throw fail('REGISTRY_PRIVATE_STATE_CHANGED');
  const temp = file + '.pending-' + crypto.randomBytes(8).toString('hex');
  const fd = await fs.open(temp, 'wx', 0o600);
  try {
    await fd.writeFile(JSON.stringify(value) + '\n');
    await fd.sync();
  } finally {
    await fd.close();
  }
  try {
    if (JSON.stringify(await readPrivate(file)) !== JSON.stringify(previous)) throw fail('REGISTRY_PRIVATE_STATE_CHANGED');
    await fs.rename(temp, file);
  } finally {
    await fs.unlink(temp).catch(e => {
      if (e.code !== 'ENOENT') throw e;
    });
  }
}
function labels(p) {
  return {
    'owasp-ai-goat.registry.workspace': p.workspace,
    'owasp-ai-goat.registry.owner': p.profile,
    ...(p.resourceNamespace === undefined ? {} : { 'owasp-ai-goat.registry.namespace': p.resourceNamespace })
  };
}
function validateNetwork(n, p, record) {
  if (!n || !ID.test(n.Id || '') || n.Name !== p.network || n.Driver !== 'bridge' || n.Internal !== false || n.EnableIPv6 !== false || n.Ingress === true || n.Labels?.['owasp-ai-goat.registry.namespace'] !== p.resourceNamespace || Object.entries(labels(p)).some(([k, v]) => n.Labels?.[k] !== v) || record?.networkId && record.networkId !== n.Id) throw fail('REGISTRY_NETWORK_CONFLICT');
  const ids = Object.keys(n.Containers || {});
  if (ids.some(id => id !== record?.containerId)) throw fail('REGISTRY_NETWORK_FOREIGN_ENDPOINT');
  return n;
}
function validateContainer(c, p, record, token) {
  const h = c?.HostConfig,
    e = c?.Config,
    net = c?.NetworkSettings?.Networks;
  const expectedEnv = [`SECURESHOP_MCP_REGISTRY_ENABLED=true`, `SECURESHOP_MCP_REGISTRY_TOKEN=${token}`, `SECURESHOP_MCP_REGISTRY_PROFILE=${p.profile}`, 'SECURESHOP_MCP_REGISTRY_HOST=0.0.0.0', 'SECURESHOP_MCP_REGISTRY_PORT=8094'];
  if (!c || !ID.test(c.Id || '') || record.containerId && c.Id !== record.containerId || c.Name !== '/' + p.container || c.Image !== p.imageId || e?.Labels?.['owasp-ai-goat.registry.namespace'] !== p.resourceNamespace || Object.entries(labels(p)).some(([k, v]) => e?.Labels?.[k] !== v) || e?.User !== '10001:10001' || JSON.stringify(e.Entrypoint) !== JSON.stringify(['node', 'sidecars/sandbox-runner/owned-mcp-registry/http-listener.js']) || e.Cmd?.length || !expectedEnv.every(v => e.Env?.includes(v)) || e.Env.filter(v => v.startsWith('SECURESHOP_MCP_REGISTRY_')).length !== 5 || h?.Privileged || h?.ReadonlyRootfs !== true || h?.NetworkMode !== p.network || h?.PidMode || h?.IpcMode === 'host' || h?.CapAdd?.length || JSON.stringify(h?.CapDrop) !== JSON.stringify(['ALL']) || h?.Memory !== 536870912 || h?.NanoCpus !== 1000000000 || h?.PidsLimit !== 128 || h?.RestartPolicy?.Name !== 'unless-stopped' || h?.SecurityOpt?.length !== 2 || !h.SecurityOpt.includes('apparmor=' + p.profile) || !h.SecurityOpt.includes('seccomp=unconfined') || JSON.stringify(h.PortBindings) !== JSON.stringify({
    '8094/tcp': [{
      HostIp: '127.0.0.1',
      HostPort: String(p.port)
    }]
  }) || Object.keys(h.Tmpfs || {}).join() !== '/tmp' || h.Tmpfs['/tmp'] !== 'rw,nosuid,nodev,noexec,size=16m' || c.Mounts?.some(m => m.Type !== 'tmpfs' || m.Destination !== '/tmp') || Object.keys(net || {}).join() !== p.network || (net[p.network].NetworkID !== record.networkId && !(net[p.network].NetworkID === '' && c.State?.Status === 'created' && c.State?.Running === false))) throw fail('REGISTRY_CONTAINER_CONFLICT');
  return c;
}
// The historical network name ends in -internal. The control-plane bridge is
// deliberately noninternal so Docker publishes its loopback port. Only worker
// operations have network namespace isolation; outer-container egress is possible.
function validateRunningContainer(c, p, record, token) {
  validateContainer(c, p, record, token);
  const ports = c.NetworkSettings?.Ports;
  const published = ports?.['8094/tcp'];
  if (c.State?.Running !== true || c.State?.Status !== 'running' ||
      Object.keys(ports || {}).length !== 1 || !Array.isArray(published) || published.length !== 1 ||
      Object.keys(published[0]).sort().join(',') !== 'HostIp,HostPort' ||
      published[0].HostIp !== '127.0.0.1' || published[0].HostPort !== String(p.port)) {
    throw fail('REGISTRY_RUNTIME_PORT_UNAVAILABLE');
  }
  return c;
}
// Executes only immutable-image packaged assets, never host source. This derives
// the digest independently of the serving health endpoint and verifies each asset.
const IMAGE_PROBE = "const f=require('fs'),c=require('crypto'),e=require('./sidecars/sandbox-runner/owned-mcp-registry/executor');const a=JSON.parse(f.readFileSync('/usr/share/owasp-ai-goat/owned-mcp-registry-assets.json'));if(Object.keys(a).sort().join()!=[...e.ASSETS].sort().join())throw Error('assets');for(const p of e.ASSETS){const s=f.lstatSync(p);if(!s.isFile()||s.isSymbolicLink()||s.uid!==0||(s.mode&18)||(()=>{const h=c.createHash('sha256'),fd=f.openSync(p,'r'),b=Buffer.alloc(65536);try{let n;while((n=f.readSync(fd,b,0,b.length,null))>0)h.update(b.subarray(0,n));return h.digest('hex');}finally{f.closeSync(fd);}})()!==a[p])throw Error('asset');}process.stdout.write(c.createHash('sha256').update(JSON.stringify(a)).digest('hex'));";
async function waitForHealth(client, runtimeDigest, {
  timeoutMs = 10000,
  intervalMs = 200,
  now = Date.now,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
} = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000 || !Number.isInteger(intervalMs) || intervalMs < 1 || intervalMs > 1000) throw fail('REGISTRY_READINESS_BUDGET_INVALID');
  const deadline = now() + timeoutMs;
  let lastFailure;
  while (now() < deadline) {
    const controller = new AbortController();
    let timer;
    try {
      const pending = Promise.resolve().then(() => client.health({
        signal: controller.signal
      }));
      const expired = new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(fail('REGISTRY_READINESS_TIMEOUT'));
        }, Math.max(1, deadline - now()));
      });
      const health = await Promise.race([pending, expired]);
      if (health.ready !== true || health.runtimeDigest !== runtimeDigest) throw fail('REGISTRY_HEALTH_MISMATCH');
      return health;
    } catch (error) {
      lastFailure = error;
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
    const remaining = deadline - now();
    if (remaining > 0) await sleep(Math.min(intervalMs, remaining));
  }
  const error = fail('REGISTRY_READINESS_TIMEOUT');
  error.cause = lastFailure;
  throw error;
}
function isMissingInspect(result, args) {
  if (result.exitCode !== 1 || args.length !== 3 || args[1] !== 'inspect' || !['container', 'network', 'image'].includes(args[0])) return false;
  const [kind, , id] = args;
  if (typeof id !== 'string' || !id || /[\r\n]/.test(id)) return false;
  const message = String(result.stderr || '').trim();
  return [
    `Error: No such ${kind}: ${id}`,
    `Error response from daemon: No such ${kind}: ${id}`,
    `Error: No such object: ${id}`,
    ...(kind === 'network' ? [`Error response from daemon: network ${id} not found`] : []),
  ].includes(message);
}
async function provision(options = {}) {
  const p = plan(options),
    environment = options.environment || process.env;
  _internals.assertDockerAuthority(environment, p);
  const run = options.run || createCommandRunner({
    cwd: p.root,
    env: environment
  });
  const docker = async (args, stage, missing = false) => {
    const r = await run('docker', ['--host', p.dockerHost, ...args], {
      stage,
      allowExitCodes: missing ? [0, 1] : [0],
      timeoutMs: 30000,
      maxOutputBytes: 1048576
    });
    if (r.exitCode !== 0) {
      if (missing && isMissingInspect(r, args)) return null;
      throw fail('REGISTRY_COMMAND_FAILED');
    }
    return r.stdout || '';
  };
  const inspect = async (kind, id) => {
    const raw = await docker([kind, 'inspect', id], 'inspect-' + kind, true);
    if (raw === null) return null;
    const rows = JSON.parse(raw);
    if (!Array.isArray(rows) || rows.length !== 1) throw fail('REGISTRY_INSPECT_INVALID');
    return rows[0];
  };
  const image = await inspect('image', p.imageId);
  if (image?.Id !== p.imageId || image.Architecture !== 'arm64' || image.Os !== 'linux' || image.Config?.User !== '10001:10001' || JSON.stringify(image.Config.Entrypoint) !== JSON.stringify(['node', 'sidecars/sandbox-runner/owned-mcp-registry/http-listener.js']) || image.Config.Volumes && Object.keys(image.Config.Volumes).length) throw fail('REGISTRY_IMAGE_UNQUALIFIED');
  const daemon = JSON.parse(await docker(['info', '--format', '{{json .Architecture}}'], 'architecture'));
  if (!['arm64', 'aarch64'].includes(daemon)) throw fail('REGISTRY_ARCHITECTURE_UNQUALIFIED');
  await fs.mkdir(p.directory, {
    recursive: true,
    mode: 0o700
  });
  const dir = await fs.lstat(p.directory);
  if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== process.getuid() || dir.mode & 0o077) throw fail('REGISTRY_PRIVATE_DIRECTORY_UNTRUSTED');
  const lock = await fs.open(p.receiptFile + '.lock', 'wx', 0o600);
  let record,
    configuration,
    createdContainer = false,
    createdNetwork = false,
    temp;
  try {
    record = await readPrivate(p.receiptFile);
    configuration = await readPrivate(p.configFile);
    const template = await fs.readFile(path.join(p.root, 'sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in'), 'utf8'),
      rendered = template.replaceAll('@@SUPERVISOR_PROFILE@@', p.profile),
      profileSha256 = sha(rendered);
    if (configuration) {
      validateConfiguration(configuration, {
        root: p.root
      });
      if (configuration.baseURL !== `http://127.0.0.1:${p.port}` || configuration.mode !== p.mode) throw fail('REGISTRY_STATE_CONFLICT');
    }
    if (record && (record.version !== 1 || record.resourceNamespace !== p.resourceNamespace || record.workspace !== p.workspace || record.imageId !== p.imageId || record.dockerHost !== p.dockerHost || record.profileSha256 !== profileSha256 || record.port !== p.port || record.mode !== p.mode || record.networkId !== null && !ID.test(record.networkId || '') || record.containerId !== null && !ID.test(record.containerId || '') || !['staged', 'ready', 'recovery'].includes(record.phase) || !configuration || configuration.token !== record.token || configuration.runtimeDigest !== record.runtimeDigest)) throw fail('REGISTRY_STATE_CONFLICT');
    if (configuration && !record) throw fail('REGISTRY_RECOVERY_REQUIRED');
    // Inspect ownership before mutation. A name alone never authorizes adoption.
    let network = await inspect('network', p.network),
      container = await inspect('container', p.container);
    if (!record && (network || container)) throw fail('REGISTRY_UNRECORDED_RESOURCES');
    if (record && network) validateNetwork(network, p, record);
    if (record && container) validateContainer(container, p, record, record.token);
    if (record?.containerId && !container || record?.networkId && !network) throw fail('REGISTRY_RESOURCE_MISSING');
    const probeName = p.container + '-assets-' + crypto.randomBytes(6).toString('hex');
    let probeId, digest;
    try {
      probeId = (await docker(['create', '--name', probeName, '--label', 'owasp-ai-goat.registry.probe=' + p.workspace, '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--memory', '512m', '--pids-limit', '32', '--user', '10001:10001', '--entrypoint', 'node', p.imageId, '-e', IMAGE_PROBE], 'image-assets-create')).trim();
      if (!ID.test(probeId)) throw fail('REGISTRY_PROBE_CREATE_UNCERTAIN');
      const probe = await inspect('container', probeId);
      if (probe?.Id !== probeId || probe.Name !== '/' + probeName || probe.Image !== p.imageId || probe.Config?.Labels?.['owasp-ai-goat.registry.probe'] !== p.workspace || probe.HostConfig?.NetworkMode !== 'none') throw fail('REGISTRY_PROBE_CONFLICT');
      digest = (await docker(['start', '--attach', probeId], 'image-assets')).trim();
      const ended = await inspect('container', probeId);
      if (ended?.State?.Running || ended?.State?.ExitCode !== 0) throw fail('REGISTRY_PROBE_FAILED');
    } finally {
      if (probeId && ID.test(probeId)) {
        const probe = await inspect('container', probeId);
        if (probe?.Id !== probeId || probe.Name !== '/' + probeName || probe.Image !== p.imageId || probe.Config?.Labels?.['owasp-ai-goat.registry.probe'] !== p.workspace) throw fail('REGISTRY_PROBE_CLEANUP_CONFLICT');
        if (probe.State?.Running) await docker(['stop', '--time', '5', probeId], 'image-assets-stop');
        await docker(['rm', probeId], 'image-assets-remove');
        if (await inspect('container', probeId)) throw fail('REGISTRY_PROBE_REMAINS');
      }
    }
    if (!/^[a-f0-9]{64}$/.test(digest) || record && digest !== record.runtimeDigest) throw fail('REGISTRY_IMAGE_ASSETS_CHANGED');
    if (!record) {
      record = {
        version: 1,
        workspace: p.workspace,
        ...(p.resourceNamespace === undefined ? {} : {resourceNamespace:p.resourceNamespace}),
        imageId: p.imageId,
        dockerHost: p.dockerHost,
        profileSha256,
        port: p.port,
        mode: p.mode,
        token: crypto.randomBytes(48).toString('base64url'),
        runtimeDigest: digest,
        networkId: null,
        containerId: null,
        phase: 'staged'
      };
      await writePrivate(p.receiptFile, record, null);
      configuration = validateConfiguration({
        version: 1,
        workspace: p.workspace,
        enabled: false,
        baseURL: `http://127.0.0.1:${p.port}`,
        token: record.token,
        runtimeDigest: digest,
        mode: p.mode
      }, {
        root: p.root
      });
      await writePrivate(p.configFile, configuration, null);
    }
    const update = async fields => {
      const next = {
        ...record,
        ...fields
      };
      await writePrivate(p.receiptFile, next, record);
      record = next;
    };
    temp = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-registry-install-'));
    await fs.chmod(temp, 0o700);
    const renderedFile = path.join(temp, 'profile');
    await fs.writeFile(renderedFile, rendered, {
      flag: 'wx',
      mode: 0o600
    });
    await (options.installProfile || (p.platform === 'linux' ? _internals.linuxInstall : _internals.darwinInstall))({
      plan: p,
      renderedFile,
      renderedSha256: profileSha256,
      run,
      nonce: crypto.randomBytes(6).toString('hex')
    });
    const labelArgs = Object.entries(labels(p)).flatMap(([k, v]) => ['--label', k + '=' + v]);
    if (!network) {
      const id = (await docker(['network', 'create', '--driver', 'bridge', ...labelArgs, p.network], 'network-create')).trim();
      if (!ID.test(id)) throw fail('REGISTRY_NETWORK_CREATE_UNCERTAIN');
      createdNetwork = true;
      await update({
        networkId: id
      });
      network = validateNetwork(await inspect('network', id), p, record);
    }
    if (!container) {
      const envFile = path.join(temp, 'runtime.env');
      await fs.writeFile(envFile, `SECURESHOP_MCP_REGISTRY_ENABLED=true\nSECURESHOP_MCP_REGISTRY_TOKEN=${record.token}\nSECURESHOP_MCP_REGISTRY_PROFILE=${p.profile}\nSECURESHOP_MCP_REGISTRY_HOST=0.0.0.0\nSECURESHOP_MCP_REGISTRY_PORT=8094\n`, {
        flag: 'wx',
        mode: 0o600
      });
      const id = (await docker(['create', '--name', p.container, ...labelArgs, '--network', p.network, '--read-only', '--user', '10001:10001', '--memory', '512m', '--cpus', '1', '--pids-limit', '128', '--cap-drop', 'ALL', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m', '--security-opt', 'apparmor=' + p.profile, '--security-opt', 'seccomp=unconfined', '--restart', 'unless-stopped', '--publish', `127.0.0.1:${p.port}:8094`, '--env-file', envFile, p.imageId], 'container-create')).trim();
      if (!ID.test(id)) throw fail('REGISTRY_CONTAINER_CREATE_UNCERTAIN');
      await update({
        containerId: id
      });
      createdContainer = true;
      container = validateContainer(await inspect('container', id), p, record, record.token);
    }
    if (!container.State?.Running) await docker(['start', record.containerId], 'container-start');
    validateRunningContainer(await inspect('container', record.containerId), p, record, record.token);
    validateNetwork(await inspect('network', record.networkId), p, record);
    const client = (options.createClient || createOwnedMcpRegistryClient)({
      baseURL: configuration.baseURL,
      token: record.token,
      expectedRuntimeDigest: digest
    });
    await waitForHealth(client, digest, options.readinessOptions);
    // Provisioning is not activation: root must qualify lifecycle/UI before opening
    // the production gate. Preserve an existing enabled configuration unchanged.
    await update({
      phase: 'ready'
    });
    return {
      ready: true,
      activationEnabled: configuration.enabled,
      containerId: record.containerId,
      networkId: record.networkId,
      imageId: p.imageId,
      runtimeDigest: digest,
      architecture: 'arm64'
    };
  } catch (error) {
    // Never remove a pre-existing resource. Ambiguous create failures retain receipt
    // for recovery; no guessing by name and no token rotation.
    try {
      if (createdContainer) {
        const c = validateContainer(await inspect('container', record.containerId), p, record, record.token);
        await docker(['stop', '--time', '20', c.Id], 'rollback-stop');
        await docker(['rm', c.Id], 'rollback-remove');
        if (await inspect('container', c.Id)) throw fail('REGISTRY_ROLLBACK_CONTAINER_REMAINS');
        const next = {
          ...record,
          containerId: null,
          phase: 'recovery'
        };
        await writePrivate(p.receiptFile, next, record);
        record = next;
      }
      if (createdNetwork) {
        const n = validateNetwork(await inspect('network', record.networkId), p, {
          ...record,
          containerId: null
        });
        await docker(['network', 'rm', n.Id], 'rollback-network');
        if (await inspect('network', n.Id)) throw fail('REGISTRY_ROLLBACK_NETWORK_REMAINS');
        const next = {
          ...record,
          networkId: null,
          phase: 'recovery'
        };
        await writePrivate(p.receiptFile, next, record);
        record = next;
      }
    } catch {
      error.rollbackIncomplete = true;
    }
    throw error;
  } finally {
    if (temp) await fs.rm(temp, {
      recursive: true,
      force: true
    });
    await lock.close();
    await fs.unlink(p.receiptFile + '.lock');
  }
}
module.exports = {
  plan,
  provision,
  _internals: {
    isMissingInspect,
    waitForHealth,
    validateNetwork,
    validateContainer,
    validateRunningContainer,
    readPrivate,
    writePrivate,
    IMAGE_PROBE
  }
};
if (require.main === module) {
  const args = process.argv.slice(2),
    values = Object.fromEntries(args.filter(x => x.includes('=')).map(x => x.slice(2).split('=')));
  if (args.some(x => !['--plan', '--provision'].includes(x) && !/^--(image|colima-profile|port|mode)=/.test(x)) || Number(args.includes('--plan')) + Number(args.includes('--provision')) !== 1) process.exitCode = 2;else Promise.resolve().then(() => {
    const options = {
      imageId: values.image,
      colimaProfile: values['colima-profile'],
      ...(values.port ? {
        port: Number(values.port)
      } : {}),
      ...(values.mode ? {
        mode: values.mode
      } : {})
    };
    return args.includes('--plan') ? plan(options) : provision(options);
  }).then(x => console.log(JSON.stringify(x))).catch(e => {
    console.error(JSON.stringify({
      ok: false,
      code: e.code || 'REGISTRY_INSTALL_FAILED',
      rollbackIncomplete: e.rollbackIncomplete === true
    }));
    process.exitCode = 1;
  });
}

// Replacement is an in-scope maintenance operation, not dirty-epoch recovery.
// Incomplete transitions are retained for explicit recovery review; never infer
// retirement of old executor obligations from a replacement process's status.
function validateTransitionNetwork(network, p, record, allowedIds) {
  if (Object.keys(network?.Containers || {}).some(id => !allowedIds.includes(id))) throw fail('REGISTRY_NETWORK_FOREIGN_ENDPOINT');
  return validateNetwork({ ...network, Containers: {} }, p, { ...record, containerId: null });
}
function validateDetachedRollback(container, p, record, token) {
  if (!container || container.State?.Running !== false || Object.keys(container.NetworkSettings?.Networks || {}).length !== 0) throw fail('REGISTRY_UPGRADE_ROLLBACK_NETWORK_CONFLICT');
  // Only this exact stopped rollback identity may be detached during transition.
  return validateContainer({ ...container, NetworkSettings: { ...container.NetworkSettings, Networks: { [p.network]: { NetworkID: record.networkId } } } }, p, record, token);
}
async function assertNoUpgradeDebt({ environment, maintenanceScope, createPool = require('../../server/database/postgres').createPool }) {
  const check = () => require('../lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope, environment);
  check();
  const pool = createPool(environment, 'SECURESHOP_AGENTS_DATABASE_URL');
  try {
    check();
    const result = await pool.query(`SELECT
      (SELECT count(*)::int FROM secureshop_agents.owned_mcp_invocation_journal WHERE NOT drained) AS invocations,
      (SELECT count(*)::int FROM secureshop_agents.bound_mcp_registry_operations WHERE state <> 'completed') AS operations`);
    check();
    if (result.rows.length !== 1 || result.rows[0].invocations !== 0 || result.rows[0].operations !== 0) throw fail('REGISTRY_UPGRADE_UNRESOLVED_DEBT');
  } finally { await pool.end(); }
  check();
}
async function replace(options = {}) {
  const { maintenanceScope, applicationEnvironment, previousBuild, nextBuild } = options;
  const check = () => require('../lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope, applicationEnvironment);
  check(); // A boolean/environment flag cannot authorize replacement.
  const p = plan(options), environment = options.environment || process.env;
  _internals.assertDockerAuthority(environment, p);
  const run = options.run || createCommandRunner({ cwd: p.root, env: environment });
  const docker = async (args, stage, missing = false) => {
    check();
    const result = await run('docker', ['--host', p.dockerHost, ...args], {
      stage, timeoutMs: 30000, maxOutputBytes: 1048576, allowExitCodes: missing ? [0, 1] : [0], signal: maintenanceScope.signal
    });
    check();
    if (result.exitCode !== 0) { if (missing && isMissingInspect(result, args)) return null; throw fail('REGISTRY_COMMAND_FAILED'); }
    return result.stdout || '';
  };
  const inspect = async (kind, id) => {
    const raw = await docker([kind, 'inspect', id], 'upgrade-inspect', true);
    if (raw === null) return null;
    const rows = JSON.parse(raw); if (!Array.isArray(rows) || rows.length !== 1) throw fail('REGISTRY_INSPECT_INVALID'); return rows[0];
  };
  const buildFile = path.join(p.directory, 'secureshop-owned-mcp-registry-build.json');
  const transitionFile = path.join(p.directory, 'secureshop-owned-mcp-registry-upgrade.json');
  const directory = await fs.lstat(p.directory);
  if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== process.getuid() || directory.mode & 0o077 || await fs.realpath(p.directory) !== p.directory) throw fail('REGISTRY_PRIVATE_DIRECTORY_UNTRUSTED');
  const lock = await fs.open(p.receiptFile + '.lock', 'wx', 0o600);
  let transition, original, configuration, temp, candidateId, digest, probeId;
  const advance = async fields => { check(); const next = { ...transition, ...fields }; await writePrivate(transitionFile, next, transition); transition = next; check(); };
  const restore = async (file, before, after) => {
    check(); const current = await readPrivate(file);
    if (JSON.stringify(current) === JSON.stringify(before)) return;
    if (JSON.stringify(current) !== JSON.stringify(after)) throw fail('REGISTRY_UPGRADE_PUBLICATION_CONFLICT');
    await writePrivate(file, before, current); check();
  };
  try {
    const retained = await readPrivate(transitionFile);
    if (retained) throw fail(retained.phase === 'committed' ? 'REGISTRY_UPGRADE_RETAINED_ROLLBACK_REQUIRES_REVIEW' : 'REGISTRY_UPGRADE_RECOVERY_REQUIRED');
    original = await readPrivate(p.receiptFile); configuration = await readPrivate(p.configFile);
    if (!original || !configuration || JSON.stringify(await readPrivate(buildFile)) !== JSON.stringify(previousBuild)
        || previousBuild?.imageId !== original.imageId || previousBuild.dockerHost !== p.dockerHost
        || nextBuild?.imageId !== p.imageId || nextBuild.dockerHost !== p.dockerHost || nextBuild.version !== 1
        || !ID.test(nextBuild.packageDigest || '') || original.imageId === p.imageId) throw fail('REGISTRY_UPGRADE_STATE_CONFLICT');
    validateConfiguration(configuration, { root: p.root });
    if (original.version !== 1 || original.resourceNamespace !== p.resourceNamespace || original.workspace !== p.workspace || original.phase !== 'ready'
        || original.token !== configuration.token || original.runtimeDigest !== configuration.runtimeDigest
        || original.port !== p.port || original.mode !== p.mode || original.dockerHost !== p.dockerHost
        || configuration.baseURL !== `http://127.0.0.1:${p.port}` || configuration.mode !== p.mode) throw fail('REGISTRY_UPGRADE_STATE_CONFLICT');
    const profile = (await fs.readFile(path.join(p.root, 'sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in'), 'utf8')).replaceAll('@@SUPERVISOR_PROFILE@@', p.profile);
    if (sha(profile) !== original.profileSha256) throw fail('REGISTRY_UPGRADE_PROFILE_DRIFT');
    const oldPlan = { ...p, imageId: original.imageId };
    validateRunningContainer(await inspect('container', original.containerId), oldPlan, original, original.token);
    validateNetwork(await inspect('network', original.networkId), p, original);
    const image = await inspect('image', p.imageId);
    if (image?.Id !== p.imageId || image.Architecture !== 'arm64' || image.Os !== 'linux' || image.Config?.User !== '10001:10001'
        || image.Config?.Labels?.['owasp-ai-goat.registry.package'] !== nextBuild.packageDigest
        || JSON.stringify(image.Config.Entrypoint) !== JSON.stringify(['node', 'sidecars/sandbox-runner/owned-mcp-registry/http-listener.js'])
        || image.Config.Volumes && Object.keys(image.Config.Volumes).length) throw fail('REGISTRY_IMAGE_UNQUALIFIED');
    await assertNoUpgradeDebt({ environment: applicationEnvironment, maintenanceScope, createPool: options.createPool });
    const id = crypto.randomUUID(), rollbackName = p.container + '-rollback-' + id;
    if (await inspect('container', rollbackName)) throw fail('REGISTRY_UPGRADE_ROLLBACK_CONFLICT');
    const initial = { version: 1, id, phase: 'prepared', workspace: p.workspace, dockerHost: p.dockerHost,
      rollbackName, original: { build: previousBuild, install: original, configuration }, candidate: { build: nextBuild, containerId: null, runtimeDigest: null },
      recovery: 'requires-authentic-maintenance-admission; dirty-epoch recovery is not implemented' };
    check(); await writePrivate(transitionFile, initial, retained); transition = initial; check();
    // Probe before stopping the old service; derive digest from immutable assets.
    const probeName = p.container + '-assets-' + id;
    await advance({ phase: 'probe-intent', probeName });
    probeId = (await docker(['create', '--name', probeName, '--label', 'owasp-ai-goat.registry.probe=' + p.workspace, '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--memory', '512m', '--pids-limit', '32', '--user', '10001:10001', '--entrypoint', 'node', p.imageId, '-e', IMAGE_PROBE], 'upgrade-probe-create')).trim();
    if (!ID.test(probeId)) throw fail('REGISTRY_PROBE_CREATE_UNCERTAIN');
    await advance({ probeId });
    const probe = await inspect('container', probeId);
    if (probe?.Id !== probeId || probe.Name !== '/' + probeName || probe.Image !== p.imageId || probe.Config?.Labels?.['owasp-ai-goat.registry.probe'] !== p.workspace || probe.HostConfig?.NetworkMode !== 'none') throw fail('REGISTRY_PROBE_CONFLICT');
    digest = (await docker(['start', '--attach', probeId], 'upgrade-probe-start')).trim();
    const ended = await inspect('container', probeId);
    if (!ID.test(digest) || ended?.State?.Running || ended?.State?.ExitCode !== 0) throw fail('REGISTRY_PROBE_FAILED');
    await docker(['rm', probeId], 'upgrade-probe-remove');
    if (await inspect('container', probeId)) throw fail('REGISTRY_PROBE_REMAINS');
    probeId = null;
    await advance({ phase: 'stop-intent', probeId: null, candidate: { ...transition.candidate, runtimeDigest: digest } });
    await docker(['stop', '--time', '20', original.containerId], 'upgrade-old-stop');
    const stopped = validateContainer(await inspect('container', original.containerId), oldPlan, original, original.token);
    if (stopped.State?.Running) throw fail('REGISTRY_UPGRADE_OLD_RUNNING');
    await advance({ phase: 'rename-intent' });
    await docker(['rename', original.containerId, rollbackName], 'upgrade-old-rename');
    validateContainer(await inspect('container', original.containerId), { ...oldPlan, container: rollbackName }, original, original.token);
    await advance({ phase: 'candidate-create-intent' });
    temp = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-registry-upgrade-')); await fs.chmod(temp, 0o700);
    const envFile = path.join(temp, 'runtime.env');
    await fs.writeFile(envFile, `SECURESHOP_MCP_REGISTRY_ENABLED=true\nSECURESHOP_MCP_REGISTRY_TOKEN=${original.token}\nSECURESHOP_MCP_REGISTRY_PROFILE=${p.profile}\nSECURESHOP_MCP_REGISTRY_HOST=0.0.0.0\nSECURESHOP_MCP_REGISTRY_PORT=8094\n`, { flag: 'wx', mode: 0o600 });
    const labelArgs = Object.entries({ ...labels(p), 'owasp-ai-goat.registry.upgrade': id }).flatMap(([k, v]) => ['--label', k + '=' + v]);
    candidateId = (await docker(['create', '--name', p.container, ...labelArgs, '--network', p.network, '--read-only', '--user', '10001:10001', '--memory', '512m', '--cpus', '1', '--pids-limit', '128', '--cap-drop', 'ALL', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m', '--security-opt', 'apparmor=' + p.profile, '--security-opt', 'seccomp=unconfined', '--restart', 'unless-stopped', '--publish', `127.0.0.1:${p.port}:8094`, '--env-file', envFile, p.imageId], 'upgrade-create')).trim();
    if (!ID.test(candidateId)) throw fail('REGISTRY_CONTAINER_CREATE_UNCERTAIN');
    await advance({ phase: 'candidate-start-intent', candidate: { ...transition.candidate, containerId: candidateId } });
    const nextRecord = { ...original, imageId: p.imageId, runtimeDigest: digest, containerId: candidateId, phase: 'ready' };
    validateContainer(await inspect('container', candidateId), p, nextRecord, original.token);
    await docker(['start', candidateId], 'upgrade-start');
    validateRunningContainer(await inspect('container', candidateId), p, nextRecord, original.token);
    validateTransitionNetwork(await inspect('network', original.networkId), p, original, [original.containerId, candidateId]);
    const nextConfiguration = { ...configuration, runtimeDigest: digest };
    const client = (options.createClient || createOwnedMcpRegistryClient)({ baseURL: configuration.baseURL, token: original.token, expectedRuntimeDigest: digest });
    await waitForHealth({ health: async ({signal}) => { check(); const value = await client.health({signal:maintenanceScope.signal ? AbortSignal.any([signal,maintenanceScope.signal]) : signal}); check(); return value; } }, digest, options.readinessOptions); check();
    if (typeof options.verifyReadiness !== 'function' || await options.verifyReadiness(nextConfiguration) !== true) throw fail('REGISTRY_UPGRADE_NOT_READY');
    check(); await advance({ phase: 'old-disconnect-intent' });
    const rollbackPlan = { ...p, imageId: original.imageId, container: rollbackName };
    const rollbackContainer = validateContainer(await inspect('container', original.containerId), rollbackPlan, original, original.token);
    if (rollbackContainer.State?.Running) throw fail('REGISTRY_UPGRADE_OLD_RUNNING');
    await docker(['network','disconnect',original.networkId,original.containerId], 'upgrade-old-disconnect');
    validateDetachedRollback(await inspect('container', original.containerId), rollbackPlan, original, original.token);
    validateNetwork(await inspect('network',original.networkId),p,nextRecord);
    check(); await advance({ phase: 'publication-intent', nextInstall: nextRecord, nextConfiguration });
    await writePrivate(p.receiptFile, nextRecord, original); check();
    await writePrivate(p.configFile, nextConfiguration, configuration); check();
    await writePrivate(buildFile, nextBuild, previousBuild); check();
    await advance({ phase: 'committed' });
    return { ready: true, upgraded: true, activationEnabled: configuration.enabled, architecture: 'arm64', imageId: p.imageId,
      runtimeDigest: digest, containerId: candidateId, networkId: original.networkId, rollbackContainerId: original.containerId };
  } catch (error) {
    if (transition && !['committed', 'rolled-back'].includes(transition.phase)) {
      try {
        check();
        if (transition.probeName) {
          const probe = await inspect('container', probeId || transition.probeName);
          if (probe) {
            if (probe.Name !== '/' + transition.probeName || probe.Image !== p.imageId || probe.Config?.Labels?.['owasp-ai-goat.registry.probe'] !== p.workspace || probe.HostConfig?.NetworkMode !== 'none' || probeId && probe.Id !== probeId) throw fail('REGISTRY_UPGRADE_PROBE_RECOVERY_REQUIRED');
            if (probe.State?.Running) await docker(['stop','--time','5',probe.Id], 'upgrade-rollback-probe-stop');
            await docker(['rm',probe.Id], 'upgrade-rollback-probe-remove');
            if (await inspect('container',probe.Id)) throw fail('REGISTRY_PROBE_REMAINS');
          }
        }
        const current = await inspect('container', p.container);
        if (current && current.Id !== original.containerId) {
          const record = { ...original, containerId: candidateId || transition.candidate.containerId };
          if (current.Config?.Labels?.['owasp-ai-goat.registry.upgrade'] !== transition.id || record.containerId && current.Id !== record.containerId) throw fail('REGISTRY_UPGRADE_CANDIDATE_UNCERTAIN');
          record.containerId = current.Id;
          validateContainer(current, p, record, original.token);
          if (current.State?.Running) await docker(['stop', '--time', '20', current.Id], 'upgrade-rollback-stop');
          await docker(['rm', current.Id], 'upgrade-rollback-remove');
          if (await inspect('container', current.Id)) throw fail('REGISTRY_UPGRADE_CANDIDATE_REMAINS');
        }
        let old = await inspect('container', original.containerId);
        const oldPlan = { ...p, imageId: original.imageId, container: old?.Name === '/' + transition.rollbackName ? transition.rollbackName : p.container };
        if (Object.keys(old?.NetworkSettings?.Networks || {}).length === 0) {
          validateDetachedRollback(old, oldPlan, original, original.token);
          await docker(['network','connect',original.networkId,old.Id], 'upgrade-rollback-connect');
          old = await inspect('container',old.Id);
        }
        validateContainer(old, oldPlan, original, original.token);
        if (oldPlan.container !== p.container) await docker(['rename', old.Id, p.container], 'upgrade-rollback-rename');
        if (!old.State?.Running) await docker(['start', old.Id], 'upgrade-rollback-start');
        validateRunningContainer(await inspect('container', old.Id), { ...p, imageId: original.imageId }, original, original.token);
        validateNetwork(await inspect('network', original.networkId), p, original);
        await waitForHealth((options.createClient || createOwnedMcpRegistryClient)({ baseURL: configuration.baseURL, token: original.token, expectedRuntimeDigest: original.runtimeDigest }), original.runtimeDigest, options.readinessOptions);
        check();
        await restore(p.receiptFile, original, transition.nextInstall);
        await restore(p.configFile, configuration, transition.nextConfiguration);
        await restore(buildFile, previousBuild, nextBuild);
        await advance({ phase: 'rolled-back' });
      } catch { error.rollbackIncomplete = true; }
    }
    throw error;
  } finally {
    let held = false; try { check(); held = true; } catch {}
    await lock.close();
    if (held) { if (temp) await fs.rm(temp, { recursive: true, force: true }); await fs.unlink(p.receiptFile + '.lock'); }
  }
}
module.exports.replace = replace;
Object.assign(module.exports._internals, { validateTransitionNetwork, assertNoUpgradeDebt });
