'use strict';

// Owned image preparation and explicitly requested, readiness-gated activation.
const fs = require('node:fs/promises');
const constants = require('node:fs').constants;
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const {
  spawn
} = require('node:child_process');
const tar = require('tar-stream');
const authority = require('./manifests/secureshop-owned-mcp-registry-build.json');
const installer = require('./secureshop-owned-mcp-registry');
const {
  localProfilePlan
} = require('./mcp-owned-local');
const {
  workspaceId
} = require('../../server/services/mcp/ownedManagedConfiguration');
const {
  createCommandRunner,
  _internals
} = require('./mcp-owned-provision');
const {
  configuredBuildCa
} = require('./listings-setup');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const DOCKER_INFO_FORMAT = '{{json .ID}}|{{json .Architecture}}';
const fail = code => Object.assign(Error('Registry automatic image preparation unavailable'), {
  code
});
// Exact private build receipt: {version:1,packageDigest,dockerHost,imageId}.
// A pre-existing unlabeled root-reviewed image requires a separately reviewed
// one-time receipt; never infer adoption from an image tag or imported report.
const packageDigest = () => sha(JSON.stringify(authority));
async function readBuildSource(file, digest, io = fs) {
  if ((await io.realpath(file)) !== file) throw fail('REGISTRY_BUILD_SYMLINK');
  const fd = await io.open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await fd.stat();
    if (!before.isFile() || before.size <= 0 || before.size > 2 * 1024 * 1024 || before.nlink !== 1)
      throw fail('REGISTRY_BUILD_SOURCE_INVALID');
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await fd.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead <= 0) throw fail('REGISTRY_BUILD_SOURCE_CHANGED');
      offset += bytesRead;
    }
    const after = await fd.stat(), named = await io.lstat(file);
    for (const key of ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs', 'nlink']) {
      if (before[key] !== after[key] || after[key] !== named[key]) throw fail('REGISTRY_BUILD_SOURCE_CHANGED');
    }
    if (!named.isFile() || named.isSymbolicLink() || sha(bytes) !== digest)
      throw fail('REGISTRY_BUILD_SOURCE_CHANGED');
    return bytes;
  } finally {
    await fd.close();
  }
}
async function capture(root) {
  if (authority.version !== 1 || authority.platform !== 'linux/arm64' || Object.keys(authority.files).length !== 20) throw fail('REGISTRY_BUILD_AUTHORITY_INVALID');
  const result = [];
  let total = 0;
  for (const [name, digest] of Object.entries(authority.files)) {
    if (path.isAbsolute(name) || name.split('/').some(x => !x || x === '..' || x === '.') || !/^[a-f0-9]{64}$/.test(digest)) throw fail('REGISTRY_BUILD_AUTHORITY_INVALID');
    const file = path.join(root, name);
    const bytes = await readBuildSource(file, digest);
    total += bytes.length;
    if (total > 8 * 1024 * 1024) throw fail('REGISTRY_BUILD_CONTEXT_LIMIT');
    result.push({
      name,
      bytes
    });
  }
  return result;
}
function contextStream(files) {
  const pack = tar.pack();
  // All entries derive from verified in-memory bytes; no directory traversal,
  // filesystem walk, symlink or private working-tree file reaches Docker.
  process.nextTick(() => {
    for (const {
      name,
      bytes
    } of files) pack.entry({
      name,
      size: bytes.length,
      mode: 0o444,
      uid: 0,
      gid: 0,
      mtime: new Date(0),
      type: 'file'
    }, bytes);
    pack.finalize();
  });
  return pack;
}
function buildImage({
  root,
  environment,
  args,
  files,
  timeoutMs = 300000
}) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, {
      cwd: root,
      env: environment,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    let failure,
      output = 0;
    const stop = code => {
      failure ||= fail(code);
      child.kill('SIGKILL');
    };
    const timer = setTimeout(() => stop('REGISTRY_BUILD_TIMEOUT'), timeoutMs);
    const input = contextStream(files);
    input.on('error', () => stop('REGISTRY_BUILD_STREAM_FAILED'));
    child.stdin.on('error', () => stop('REGISTRY_BUILD_INPUT_FAILED'));
    for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => {
      output += bytes.length;
      if (output > 2 * 1024 * 1024) stop('REGISTRY_BUILD_OUTPUT_LIMIT');
    });
    child.on('error', () => {
      failure ||= fail('REGISTRY_BUILD_SPAWN_FAILED');
    });
    child.on('close', code => {
      clearTimeout(timer);
      input.destroy();
      if (failure || code !== 0) reject(failure || fail('REGISTRY_BUILD_FAILED'));else resolve();
    });
    input.pipe(child.stdin);
  });
}
async function assertActivationReadiness({applicationEnvironment,configuration,createPool,assertBound,assertPersona,assertRegistry,createClient}={}) {
  const env=applicationEnvironment;
  if(!env || env.SS_ENABLE!=='true'||env.SS_BOUND_REVIEWS_ENABLED!=='true'||env.PLATFORM_DATABASE_ENGINE!=='postgres'||env.WORKSHOP_DATABASE_ENGINE!=='postgres')throw fail('REGISTRY_ACTIVATION_PREREQUISITES');
  createPool ||= require('../../server/database/postgres').createPool;
  // Supported setup has already selected PostgreSQL before importing composition.
  if(!assertBound&&process.env.PLATFORM_DATABASE_ENGINE!=='postgres')throw fail('REGISTRY_ACTIVATION_PHASE_REQUIRED');
  assertBound ||= require('../../server/services/secureshopBoundReviewComposition').assertSecureShopBoundReviewReadiness;
  assertPersona ||= require('../../server/database/postgres/secureshopBoundPersonaAuthority').assertAuthorityReady;
  assertRegistry ||= require('../../server/database/postgres/secureshopOwnedMcpRegistryRepository').assertOwnedMcpRegistryReady;
  createClient ||= require('../../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient;
  const runtime={},migration={},owned=[];
  try {
    for(const [store,prefix] of Object.entries({identity:'IDENTITY',agents:'SECURESHOP_AGENTS',review:'SECURESHOP_REVIEW',commerce:'SECURESHOP'})) {
      for(const [target,suffix] of [[runtime,'DATABASE_URL'],[migration,'MIGRATION_DATABASE_URL']]) {
        const key=prefix+'_'+suffix;if(typeof env[key]!=='string'||!env[key])throw fail('REGISTRY_ACTIVATION_DATABASE_MISSING');
        target[store]=createPool(env,key);owned.push(target[store]);
      }
    }
    const pools={identityPool:runtime.identity,agentsPool:runtime.agents,reviewPool:runtime.review,commercePool:runtime.commerce,migrationPools:migration};
    await assertBound(pools);
    const identity=(await runtime.identity.query('SELECT current_database() AS database')).rows[0];
    if(identity?.database!==new URL(env.IDENTITY_DATABASE_URL).pathname.slice(1))throw fail('REGISTRY_ACTIVATION_IDENTITY_MISMATCH');
    await assertPersona({pool:runtime.agents,expectedDatabase:new URL(env.SECURESHOP_AGENTS_DATABASE_URL).pathname.slice(1)});
    await assertRegistry({pool:runtime.agents,expectedDatabase:new URL(env.SECURESHOP_AGENTS_DATABASE_URL).pathname.slice(1)});
    const client=createClient({baseURL:configuration.baseURL,token:configuration.token,expectedRuntimeDigest:configuration.runtimeDigest});
    await client.health();
    await client.registrationHealth();
  } finally {
    const closed=await Promise.allSettled(owned.map(pool=>Promise.resolve().then(()=>pool.end())));
    if(closed.some(row=>row.status!=='fulfilled'))throw fail('REGISTRY_ACTIVATION_POOL_CLEANUP');
  }
  return true;
}
async function publishActivation({root,configFile,previous,applicationEnvironment,readiness=assertActivationReadiness}) {
  const configuration=require('../../server/services/secureshopOwnedMcpRegistryProduction').validateConfiguration(previous,{root});
  if(await readiness({applicationEnvironment,configuration})!==true)throw fail('REGISTRY_ACTIVATION_NOT_READY');
  await installer._internals.writePrivate(configFile,{...configuration,enabled:true},previous);
  return true;
}
// Inspect the daemon selected for this owned registry, not the host CPU or an
// ambient Docker context. Setup calls this before provisioning application
// databases; image preparation repeats it so a changed daemon fails closed.
async function preflightOwnedMcpRegistryArchitecture({
  root = path.resolve(__dirname, '../..'),
  homeDirectory = os.homedir(),
  platform = process.platform,
  environment = process.env,
  colimaProfile,
  dockerAuthority,
  run
} = {}) {
  root = path.resolve(root);
  const location = localProfilePlan({root, home:homeDirectory, platform,
    colimaProfile:colimaProfile || environment.OWASP_AI_GOAT_MCP_OWNED_COLIMA_PROFILE});
  _internals.assertDockerAuthority(environment, location);
  if (dockerAuthority?.host && dockerAuthority.host !== location.dockerHost) {
    throw fail('REGISTRY_BUILD_DOCKER_AUTHORITY_MISMATCH');
  }
  run ||= createCommandRunner({cwd:root, env:environment});
  const result = await run('docker', ['--host', location.dockerHost, 'info', '--format', DOCKER_INFO_FORMAT], {
    timeoutMs:30000, maxOutputBytes:1048576, allowExitCodes:[0]
  });
  if (result.exitCode !== 0) throw fail('REGISTRY_BUILD_COMMAND_FAILED');
  let daemonId, architecture;
  try {
    const fields = result.stdout.trim().split('|');
    if (fields.length !== 2) throw Error();
    [daemonId, architecture] = fields.map(value => JSON.parse(value));
  }
  catch { throw fail('REGISTRY_BUILD_ARCHITECTURE_INVALID'); }
  if (typeof daemonId !== 'string' || !daemonId || daemonId.length > 256 || /[\x00-\x1f\x7f]/.test(daemonId)
    || typeof architecture !== 'string') throw fail('REGISTRY_BUILD_ARCHITECTURE_INVALID');
  if (dockerAuthority?.daemonId && daemonId !== dockerAuthority.daemonId)
    throw fail('REGISTRY_BUILD_DOCKER_AUTHORITY_MISMATCH');
  if (!['arm64','aarch64'].includes(architecture)) throw fail('REGISTRY_BUILD_AMD64_UNQUALIFIED');
  return Object.freeze({architecture, dockerHost:location.dockerHost, daemonId});
}
async function setupOwnedMcpRegistry({
  root = path.resolve(__dirname, '../..'),
  homeDirectory = os.homedir(),
  platform = process.platform,
  environment = process.env,
  colimaProfile,
  requested,
  explicitActivation=false,
  upgrade=false,
  maintenanceScope,
  applicationEnvironment=environment,
  readiness=assertActivationReadiness,
  productionQualified=require('../../server/services/secureshopOwnedMcpRegistryProduction').PRODUCTION_QUALIFIED,
  run,
  build = buildImage,
  provision = installer.provision
} = {}) {
  if(typeof upgrade!=='boolean'||requested!==undefined&&typeof requested!=='boolean'||typeof explicitActivation!=='boolean')throw fail('REGISTRY_ACTIVATION_REQUEST_INVALID');
  if(requested===false){if(explicitActivation)throw fail('REGISTRY_ACTIVATION_REQUEST_INVALID');return Object.freeze({requested:false,activationEnabled:false});}
  root = path.resolve(root);
  const location = localProfilePlan({
    root,
    home: homeDirectory,
    platform,
    colimaProfile: colimaProfile || environment.OWASP_AI_GOAT_MCP_OWNED_COLIMA_PROFILE
  });
  _internals.assertDockerAuthority(environment, location);
  run ||= createCommandRunner({
    cwd: root,
    env: environment
  });
  const command = async args => {
    const result = await run('docker', ['--host', location.dockerHost, ...args], {
      timeoutMs: 30000,
      maxOutputBytes: 1048576,
      allowExitCodes: [0]
    });
    if (result.exitCode !== 0) throw fail('REGISTRY_BUILD_COMMAND_FAILED');
    return result.stdout;
  };
  const selectedDaemon = await preflightOwnedMcpRegistryArchitecture({root,homeDirectory,platform,environment,colimaProfile,run});
  const files = await capture(root),
    digest = packageDigest();
  const directory = path.join(homeDirectory, '.owasp-ai-goat', workspaceId(root));
  await fs.mkdir(directory, {
    recursive: true,
    mode: 0o700
  });
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || stat.mode & 0o077) throw fail('REGISTRY_BUILD_PRIVATE_DIRECTORY');
  const buildFile = path.join(directory, 'secureshop-owned-mcp-registry-build.json');
  const receiptFile = path.join(directory, 'secureshop-owned-mcp-registry-install.json');
  const lock = await fs.open(buildFile + '.lock', 'wx', 0o600);
  let temporary, replacing = false, maintenanceAdmitted = false;
  try {
    const configFile=path.join(directory,'secureshop-owned-mcp-registry.json');
    const priorConfiguration=await installer._internals.readPrivate(configFile);
    const saved = await installer._internals.readPrivate(buildFile);
    const receipt = await installer._internals.readPrivate(receiptFile);
    if (saved && (Object.keys(saved).sort().join(',') !== 'dockerHost,imageId,packageDigest,version' || saved.version !== 1 || !/^[a-f0-9]{64}$/.test(saved.packageDigest) || saved.dockerHost !== location.dockerHost || !/^sha256:[a-f0-9]{64}$/.test(saved.imageId))) throw fail('REGISTRY_BUILD_UPGRADE_REQUIRES_REVIEW');
    replacing = Boolean(saved && saved.packageDigest !== digest);
    if (replacing) {
      if (!upgrade || !receipt || !priorConfiguration) throw fail('REGISTRY_BUILD_UPGRADE_REQUIRES_REVIEW');
      require('../lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope, applicationEnvironment);
      maintenanceAdmitted = true;
    }
    const transition = await installer._internals.readPrivate(path.join(directory, 'secureshop-owned-mcp-registry-upgrade.json'));
    if (transition && !['committed','rolled-back'].includes(transition.phase)) throw fail('REGISTRY_UPGRADE_RECOVERY_REQUIRED');
    if (receipt && !saved) throw fail('REGISTRY_BUILD_EXISTING_IMAGE_REQUIRES_ADOPTION');
    if (receipt && receipt.imageId !== saved.imageId) throw fail('REGISTRY_BUILD_IMAGE_CONFLICT');
    let imageId = replacing ? null : saved?.imageId;
    if (!imageId) {
      const ca = configuredBuildCa(environment),
        secrets = [];
      if (ca.buildCaFile) {
        const bytes = await fs.readFile(ca.buildCaFile);
        if (sha(bytes) !== ca.buildCaSha256) throw fail('REGISTRY_BUILD_CA_CHANGED');
        temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-registry-ca-'));
        await fs.chmod(temporary, 0o700);
        const file = path.join(temporary, 'npm-ca.pem');
        await fs.writeFile(file, bytes, {
          flag: 'wx',
          mode: 0o600
        });
        secrets.push('--secret', 'id=npm_ca,src=' + file);
      }
      const tag = 'owasp-ai-goat-owned-mcp-registry-' + workspaceId(root) + ':build-' + crypto.randomBytes(6).toString('hex');
      await preflightOwnedMcpRegistryArchitecture({root,homeDirectory,platform,environment,colimaProfile,run,
        dockerAuthority:{host:selectedDaemon.dockerHost,daemonId:selectedDaemon.daemonId}});
      await build({
        root,
        environment,
        files,
        args: ['--host', location.dockerHost, 'build', '--pull=false', '--platform', 'linux/arm64', '--label', 'owasp-ai-goat.registry.package=' + digest, ...secrets, '-f', authority.dockerfile, '-t', tag, '-']
      });
      if (replacing) require('../lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope, applicationEnvironment);
      await capture(root);
      const images = JSON.parse(await command(['image', 'inspect', tag]));
      if (images.length !== 1 || !/^sha256:[a-f0-9]{64}$/.test(images[0].Id) || images[0].Architecture !== 'arm64' || images[0].Os !== 'linux' || images[0].Config?.Labels?.['owasp-ai-goat.registry.package'] !== digest) throw fail('REGISTRY_BUILD_IMAGE_INVALID');
      imageId = images[0].Id;
      if (!replacing) await installer._internals.writePrivate(buildFile, {
        version: 1,
        packageDigest: digest,
        dockerHost: location.dockerHost,
        imageId
      }, null);
    } else {
      const images = JSON.parse(await command(['image', 'inspect', imageId]));
      if (images.length !== 1 || images[0].Id !== imageId || images[0].Architecture !== 'arm64' || images[0].Os !== 'linux' || images[0].Config?.Labels?.['owasp-ai-goat.registry.package'] !== undefined && images[0].Config.Labels['owasp-ai-goat.registry.package'] !== digest) throw fail('REGISTRY_BUILD_IMAGE_CONFLICT');
    }
    const result = replacing ? await installer.replace({
      root, home:homeDirectory, platform, colimaProfile:location.colimaProfile, environment, imageId, run,
      mode:receipt.mode, port:receipt.port, maintenanceScope, applicationEnvironment, previousBuild:saved,
      nextBuild:{version:1,packageDigest:digest,dockerHost:location.dockerHost,imageId},
      verifyReadiness:configuration=>readiness({applicationEnvironment,configuration})
    }) : await provision({
      root,
      home: homeDirectory,
      platform,
      colimaProfile: location.colimaProfile,
      environment,
      imageId
    });
    let activationEnabled=result.activationEnabled;
    if(requested===true&&(!replacing||explicitActivation&&!priorConfiguration.enabled)&&(!priorConfiguration||priorConfiguration.enabled===true||explicitActivation)) {
      if(productionQualified!==true)throw fail('REGISTRY_ACTIVATION_UNQUALIFIED');
      const configuration=await installer._internals.readPrivate(configFile);
      if(priorConfiguration&&!replacing&&JSON.stringify(configuration)!==JSON.stringify(priorConfiguration))throw fail('REGISTRY_ACTIVATION_CONFIGURATION_CHANGED');
      if(result.ready!==true||result.architecture!=='arm64'||result.imageId!==imageId||configuration?.runtimeDigest!==result.runtimeDigest)throw fail('REGISTRY_ACTIVATION_RUNTIME_MISMATCH');
      activationEnabled=await publishActivation({root,configFile,previous:configuration,applicationEnvironment,readiness});
    }
    return Object.freeze({
      ...result,
      activationEnabled,
      restartRequired:activationEnabled===true,
      packageDigest: digest,
      automaticImagePreparation: true
    });
  } finally {
    let held = true;
    if (maintenanceAdmitted) { try { require('../lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope, applicationEnvironment); } catch { held = false; } }
    await lock.close();
    if (held) {
      if (temporary) await fs.rm(temporary, {recursive:true,force:true});
      await fs.unlink(buildFile + '.lock');
    }
  }
}
module.exports = {
  setupOwnedMcpRegistry,
  preflightOwnedMcpRegistryArchitecture,
  _internals: {
    capture,
    readBuildSource,
    contextStream,
    packageDigest,
    buildImage,
    assertActivationReadiness,
    publishActivation
  }
};
