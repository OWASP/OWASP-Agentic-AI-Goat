'use strict';

// Application-owned local provisioning. This module has no import-time side
// effects: an installer must call provisionOwnedLocal explicitly after the
// owned database migrations have passed their preservation gate.
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { renderMcpSandboxAppArmor } = require('../render-mcp-sandbox-apparmor');
const dotenv = require('dotenv');
const { PROFILE, localProfilePlan, prepareOwnedManagedConfiguration, managedConfigurationPath, createOwnedPrivateStorage } = require('./mcp-owned-local');

const SHA256 = /^[a-f0-9]{64}$/;
const ENFORCED = `${PROFILE} (enforce)`;
function failure(code, stage) {
  const error = new Error(code); error.code = code; error.stage = stage; return error;
}
function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function boundedText(value) {
  const text = typeof value === 'string' ? value : Buffer.isBuffer(value) ? value.toString('utf8') : '';
  if (Buffer.byteLength(text) > 1024 * 1024) throw failure('MCP_INSTALL_COMMAND_OUTPUT_INVALID', 'command');
  return text;
}
async function readTemplate(file) {
  const stat = await fs.lstat(file).catch(() => null);
  if (!stat?.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 128 * 1024) {
    throw failure('MCP_INSTALL_PROFILE_SOURCE_INVALID', 'source');
  }
  return fs.readFile(file, 'utf8');
}
function exactProfileList(stdout) {
  return boundedText(stdout).split(/\r?\n/).filter(Boolean);
}
function outputOf(result) { return boundedText(result?.stdout); }
async function checked(run, file, args, stage, options = {}) {
  try {
    const result = await run(file, args, { stage, timeoutMs: options.timeoutMs || 30_000,
      maxOutputBytes: options.maxOutputBytes || 1024 * 1024 });
    if (result?.exitCode !== 0) throw failure('MCP_INSTALL_COMMAND_FAILED', stage);
    return result;
  }
  catch (cause) {
    const error = failure('MCP_INSTALL_PROFILE_RECOVERY_REQUIRED', stage);
    error.cause = cause; throw error;
  }
}
function assertDockerAuthority(env, plan) {
  if(plan.platform==='win32') {
    if(env?.DOCKER_HOST||env?.DOCKER_CONTEXT||env?.DOCKER_TLS_VERIFY||env?.DOCKER_CERT_PATH)
      throw failure('MCP_INSTALL_DOCKER_AUTHORITY_CONFLICT','docker-authority');
    return null;
  }
  const host = env?.DOCKER_HOST;
  const context = env?.DOCKER_CONTEXT;
  if ((host && host !== plan.dockerHost) || (context && context !== 'default')) {
    throw failure('MCP_INSTALL_DOCKER_AUTHORITY_CONFLICT', 'docker-authority');
  }
  return plan.dockerHost;
}
// The exact checked-in Dockerfile COPY inputs, excluding tests and unrelated
// sidecars. The admitted session transfers these bounded bytes into its own
// guest directory; no Windows paths or ambient Compose .env cross the boundary.
async function reviewedRunnerBundle(root) {
  const files=[],base='sidecars/sandbox-runner/';
  const names=['docker-compose.yml',...['Dockerfile','package.json','index.js','mcpTargets.js','mcpProtectedState.js','mcpPackageCatalog.js','ownedTargetApi.js','entrypoint.sh','mcpSeccompFilter.c','mcpSeccompProbe.c','policy-render/process-supervisor.c','policy-render/policy-init.c','policy-render/executor.js','policy-render/http-handler.js','policy-render/worker.js','policy-render/secureshopPromptPolicyContract.js'].map(name=>base+name)];
  async function collect(relative) {
    const filename=path.join(root,...relative.split('/')),stat=await fs.lstat(filename);
    if(stat.isSymbolicLink())throw failure('MCP_INSTALL_BUILD_SOURCE_INVALID','build-source');
    if(stat.isDirectory()){
      const entries=(await fs.readdir(filename)).sort();
      for(const name of entries){if(!/^[A-Za-z0-9_.-]+$/.test(name))throw failure('MCP_INSTALL_BUILD_SOURCE_INVALID','build-source');await collect(relative+'/'+name);}
    }else if(stat.isFile()&&stat.size<=1024*1024){
      const bytes=await fs.readFile(filename);if(bytes.length!==stat.size)throw failure('MCP_INSTALL_BUILD_SOURCE_INVALID','build-source');
      files.push({path:relative,bytes,sha256:digest(bytes)});
      if(files.length>128||files.reduce((total,file)=>total+file.bytes.length,0)>16*1024*1024)throw failure('MCP_INSTALL_BUILD_SOURCE_INVALID','build-source');
    }else throw failure('MCP_INSTALL_BUILD_SOURCE_INVALID','build-source');
  }
  for(const name of [...names,...['protected-operations','owned-http','policy-render/assets','labfs'].map(name=>base+name)])await collect(name);
  return files;
}
async function windowsInstall({plan,rendered,renderedSha256,session,root,commandEnv,bundleCollector=reviewedRunnerBundle}) {
  if(commandEnv.MCP_OWNED_TARGET_APPARMOR_PROFILE!==undefined&&commandEnv.MCP_OWNED_TARGET_APPARMOR_PROFILE!==PROFILE
    ||commandEnv.MCP_OWNED_TARGET_PORT!==undefined&&commandEnv.MCP_OWNED_TARGET_PORT!=='8092'
    ||commandEnv.MCP_OWNED_TARGET_TOKEN!==undefined&&(typeof commandEnv.MCP_OWNED_TARGET_TOKEN!=='string'||!/^[A-Za-z0-9_-]{43,128}$/.test(commandEnv.MCP_OWNED_TARGET_TOKEN)))
    throw failure('MCP_INSTALL_ENV_CONFLICT','docker-authority');
  const installed=await session.installAndVerifyProfile({name:PROFILE,bytes:Buffer.from(rendered),sha256:renderedSha256});
  if(installed?.name!==PROFILE||installed.sha256!==renderedSha256||installed.destination!==plan.destination||installed.bindingSha256!==plan.sessionBinding.bindingSha256)
    throw failure('MCP_INSTALL_PROFILE_RECOVERY_REQUIRED','profile-verify');
  const bundlePath=await session.stageReviewedBundle(await bundleCollector(root));
  const values=['MCP_OWNED_TARGET_TOKEN','MCP_OWNED_TARGET_APPARMOR_PROFILE','MCP_OWNED_TARGET_PORT'];
  const bytes=Buffer.from(values.filter(key=>commandEnv[key]!==undefined).map(key=>`${key}=${JSON.stringify(commandEnv[key])}`).join('\n')+'\n');
  const envPath=await session.stagePrivateEnvironment({bytes,sha256:digest(bytes)});
  return async(file,args,{timeoutMs=30000}={})=>{
    if(file!=='docker'||args[0]!=='--host'||args[1]!==null)throw failure('MCP_INSTALL_COMMAND_INVALID','command');
    let guestArgs=args.slice(2);
    // Bundle paths change with reviewed source bytes. Compose resources belong
    // to the admitted workspace, so never derive their project from that path.
    if(guestArgs[0]==='compose')guestArgs=['compose','--project-name','dvaia-'+plan.sessionBinding.workspaceId,'--env-file',envPath,...guestArgs.slice(1)];
    const stdout=await session.executeDocker(guestArgs,{scope:'provision',bundlePath,timeoutMs});
    return{exitCode:0,stdout:boundedText(stdout)};
  };
}
function createCommandRunner({ cwd = process.cwd(), env = process.env } = {}) {
  return (file, args, { timeoutMs = 30_000, maxOutputBytes = 1024 * 1024,
    allowExitCodes = [0] } = {}) => new Promise((resolve, reject) => {
    if (typeof file !== 'string' || !Array.isArray(args) || args.some(arg => typeof arg !== 'string')) {
      reject(failure('MCP_INSTALL_COMMAND_INVALID', 'command')); return;
    }
    const child = spawn(file, args, { cwd, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = []; const stderr = []; let bytes = 0; let settled = false;
    const finish = (error, value) => {
      if (settled) return; settled = true; clearTimeout(timer);
      if (error) reject(error); else resolve(value);
    };
    const collect = target => chunk => {
      bytes += chunk.length;
      if (bytes > maxOutputBytes) {
        child.kill('SIGKILL'); finish(failure('MCP_INSTALL_COMMAND_OUTPUT_INVALID', 'command')); return;
      }
      target.push(chunk);
    };
    child.stdout.on('data', collect(stdout)); child.stderr.on('data', collect(stderr));
    child.on('error', error => finish(error));
    child.on('close', (exitCode, signal) => {
      const result = { exitCode, signal, stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8') };
      if (!Number.isInteger(exitCode) || !allowExitCodes.includes(exitCode)) {
        const error = failure('MCP_INSTALL_COMMAND_FAILED', 'command'); error.result = result; finish(error); return;
      }
      finish(null, result);
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL'); const error = failure('MCP_INSTALL_COMMAND_TIMEOUT', 'command');
      error.partial = { stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
      finish(error);
    }, timeoutMs);
  });
}
async function linuxInstall({ plan, renderedFile, renderedSha256, run }) {
  const admin = (file, args, stage) => checked(run, 'sudo', ['--non-interactive', file, ...args], stage);
  await admin('true', [], 'privilege-preflight');
  await admin('apparmor_parser', ['--skip-kernel-load', renderedFile], 'profile-parse');
  const exists = await run('sudo', ['--non-interactive', 'test', '-e', plan.destination], {
    stage: 'profile-existing-state', timeoutMs: 10_000, maxOutputBytes: 4096, allowExitCodes: [0, 1],
  });
  if (exists?.exitCode === 0) {
    const existing = await admin('sha256sum', [plan.destination], 'profile-existing-digest');
    const found = outputOf(existing).trim().split(/\s+/)[0];
    if (!SHA256.test(found) || found !== renderedSha256) {
      throw failure('MCP_INSTALL_PROFILE_CONFLICT', 'profile-existing-digest');
    }
  } else if (exists?.exitCode === 1) {
    await admin('install', ['-o', 'root', '-g', 'root', '-m', '0600', renderedFile, plan.destination], 'profile-install');
  } else {
    throw failure('MCP_INSTALL_PROFILE_RECOVERY_REQUIRED', 'profile-existing-digest');
  }
  const trust = await admin('stat', ['-c', '%u:%g:%a:%F', plan.destination], 'profile-trust');
  if (outputOf(trust).trim() !== '0:0:600:regular file') {
    throw failure('MCP_INSTALL_PROFILE_TRUST_INVALID', 'profile-trust');
  }
  await admin('apparmor_parser', ['-r', plan.destination], 'profile-load');
  const profiles = await admin('cat', ['/sys/kernel/security/apparmor/profiles'], 'profile-verify');
  if (!exactProfileList(outputOf(profiles)).includes(`${plan.profile || PROFILE} (enforce)`)) {
    throw failure('MCP_INSTALL_PROFILE_RECOVERY_REQUIRED', 'profile-verify');
  }
}
function remoteCommand(...parts) {
  if (parts.some(part => typeof part !== 'string' || !/^[A-Za-z0-9_./:@=%-]+$/.test(part))) {
    throw failure('MCP_INSTALL_REMOTE_COMMAND_INVALID', 'profile-plan');
  }
  return parts.join(' ');
}
async function darwinInstall({ plan, renderedFile, renderedSha256, run, nonce }) {
  const suffix = `${renderedSha256.slice(0, 12)}-${nonce}`;
  if (!/^[a-f0-9]{12}-[a-f0-9]{12}$/.test(suffix)) throw failure('MCP_INSTALL_REMOTE_COMMAND_INVALID', 'profile-plan');
  const remoteDir = `/tmp/dvaia-mcp-owned-${suffix}`;
  const remoteProfile = `${remoteDir}/profile`;
  const ssh = ['-F', plan.sshConfig, plan.sshHost];
  let remoteCreated = false; let creationAttempted = false; let primaryError = null;
  try {
    const absent = await run('ssh', [...ssh, remoteCommand('test', '-e', remoteDir)], {
      stage: 'remote-preflight', timeoutMs: 10_000, maxOutputBytes: 4096, allowExitCodes: [0, 1],
    });
    if (absent?.exitCode !== 1) throw failure('MCP_INSTALL_REMOTE_CONFLICT', 'remote-preflight');
    creationAttempted = true;
    await checked(run, 'ssh', [...ssh, remoteCommand('mkdir', '-m', '0700', remoteDir)], 'remote-create');
    remoteCreated = true;
    await checked(run, 'scp', ['-F', plan.sshConfig, renderedFile, `${plan.sshHost}:${remoteProfile}`], 'remote-copy');
    await checked(run, 'ssh', [...ssh, remoteCommand('chmod', '0600', remoteProfile)], 'remote-mode');
    await checked(run, 'ssh', [...ssh, remoteCommand('sudo', 'apparmor_parser', '--skip-kernel-load', remoteProfile)], 'profile-parse');
    const exists = await run('ssh', [...ssh, remoteCommand('sudo', 'test', '-e', plan.destination)], {
      stage: 'profile-existing-state', timeoutMs: 10_000, maxOutputBytes: 4096, allowExitCodes: [0, 1],
    });
    if (exists?.exitCode === 0) {
      const existing = await checked(run, 'ssh', [...ssh,
        remoteCommand('sudo', 'sha256sum', plan.destination)], 'profile-existing-digest');
      const found = outputOf(existing).trim().split(/\s+/)[0];
      if (!SHA256.test(found) || found !== renderedSha256) {
        throw failure('MCP_INSTALL_PROFILE_CONFLICT', 'profile-existing-digest');
      }
    } else if (exists?.exitCode === 1) {
      await checked(run, 'ssh', [...ssh, remoteCommand('sudo', 'install', '-o', 'root', '-g', 'root', '-m', '0600', remoteProfile, plan.destination)], 'profile-install');
    } else throw failure('MCP_INSTALL_PROFILE_RECOVERY_REQUIRED', 'profile-existing-digest');
    const trust = await checked(run, 'ssh', [...ssh,
      remoteCommand('sudo', 'stat', '-c', '%u:%g:%a:%F', plan.destination)], 'profile-trust');
    if (outputOf(trust).trim() !== '0:0:600:regular file') {
      throw failure('MCP_INSTALL_PROFILE_TRUST_INVALID', 'profile-trust');
    }
    await checked(run, 'ssh', [...ssh, remoteCommand('sudo', 'apparmor_parser', '-r', plan.destination)], 'profile-load');
    const profiles = await checked(run, 'ssh', [...ssh,
      remoteCommand('sudo', 'cat', '/sys/kernel/security/apparmor/profiles')], 'profile-verify');
    if (!exactProfileList(outputOf(profiles)).includes(`${plan.profile || PROFILE} (enforce)`)) {
      throw failure('MCP_INSTALL_PROFILE_RECOVERY_REQUIRED', 'profile-verify');
    }
  } catch (error) {
    primaryError = error;
    if (creationAttempted && !remoteCreated) {
      error.cleanupDebt = Object.freeze({ remoteDir, ownership: 'creation_unconfirmed' });
    }
    throw error;
  } finally {
    if (remoteCreated) {
      try {
        await checked(run, 'ssh', [...ssh, remoteCommand('rm', '-rf', remoteDir)], 'remote-cleanup');
      } catch (cleanupError) {
        if (primaryError) primaryError.cleanupDebt = Object.freeze({ remoteDir, ownership: 'confirmed' });
        else throw cleanupError;
      }
    }
  }
}

async function provisionOwnedLocal({ platform = process.platform, root = path.resolve(__dirname, '../..'),
  home = os.homedir(), colimaProfile, run, readiness, codeBotReadiness, protectedRecoveryRelease = null, commandEnv = process.env,
  nonce = crypto.randomBytes(6).toString('hex'), ownedLabSession } = {}) {
  if (run === undefined) run = createCommandRunner({ cwd: root, env: commandEnv });
  if (typeof run !== 'function' || typeof readiness !== 'function') throw new TypeError('Controlled command and readiness adapters are required');
  const plan = localProfilePlan({ platform, root, home, colimaProfile,ownedLabSession });
  const dockerHost = assertDockerAuthority(commandEnv, plan);
  const template = await readTemplate(plan.template);
  const rendered = renderMcpSandboxAppArmor(template, PROFILE);
  const directory = platform==='win32'?null:await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-mcp-owned-profile-'));
  const renderedFile = directory?path.join(directory, 'profile'):null;
  try {
    const renderedSha256 = digest(rendered);
    if(platform==='win32')run=await windowsInstall({plan,rendered,renderedSha256,session:ownedLabSession,root,commandEnv});
    else {
    const handle = await fs.open(renderedFile, 'wx', 0o600);
    try { await handle.writeFile(rendered); await handle.sync(); } finally { await handle.close(); }
    if (platform === 'linux') await linuxInstall({ plan, renderedFile, renderedSha256, run });
    else await darwinInstall({ plan, renderedFile, renderedSha256, run, nonce });
    }

    // Mailpit holds learner-observed messages and has no persistent volume.
    // Reuse it exactly; only the owned runner is rebuilt.
    await checked(run, 'docker', ['--host', dockerHost, 'compose', '--profile', 'mcp-owned', 'up', '--no-recreate',
      '--wait', 'mailpit'], 'mailpit-preserve', { timeoutMs: 2 * 60_000, maxOutputBytes: 1024 * 1024 });
    await checked(run, 'docker', ['--host', dockerHost, 'compose', '--profile', 'mcp-owned', 'up', '--build', '--wait',
      'mcp-owned-sandbox'], 'runner-start', { timeoutMs: 10 * 60_000, maxOutputBytes: 2 * 1024 * 1024 });
    const receipt = await readiness();
    const codeBot = codeBotReadiness ? await codeBotReadiness() : null;
    const isolation = receipt?.runnerIsolation || receipt?.isolation;
    if (receipt?.ready !== true || receipt.runnerReady !== true
        || isolation !== 'bwrap-seccomp-v1'
        || receipt.supervisorProfile !== ENFORCED
        || (codeBotReadiness && (codeBot?.ready !== true || codeBot.isolation !== 'bwrap-codebot-v1'))) {
      throw failure('MCP_INSTALL_READINESS_FAILED', 'owned-readiness');
    }
    let protectedRecoveryQualified=false;
    if(protectedRecoveryRelease){
      if(!/^sha256:[a-f0-9]{64}$/.test(protectedRecoveryRelease.image||'')||protectedRecoveryRelease.profileSha256!==renderedSha256||receipt.protectedJournalCapability!=='mcp-owned-protected-operation-journal.v1'||receipt.protectedReadbackCapability!=='mcp-owned-protected-readback.v1')throw failure('MCP_INSTALL_PROTECTED_RECOVERY_UNQUALIFIED','protected-recovery');
      const selected=outputOf(await checked(run,'docker',['--host',dockerHost,'compose','--profile','mcp-owned','ps','-q','mcp-owned-sandbox'],'protected-container')).trim();
      if(!/^[a-f0-9]{64}$/.test(selected))throw failure('MCP_INSTALL_PROTECTED_RECOVERY_UNQUALIFIED','protected-container');
      const actual=JSON.parse(outputOf(await checked(run,'docker',['--host',dockerHost,'inspect','--format','{{json .}}',selected],'protected-image')));
      if(actual.Image!==protectedRecoveryRelease.image||actual.AppArmorProfile!==PROFILE)throw failure('MCP_INSTALL_PROTECTED_RECOVERY_UNQUALIFIED','protected-image');
      protectedRecoveryQualified=true;
    }
    return Object.freeze({ ok: true, profile: PROFILE, profileSha256: renderedSha256, protectedRecoveryQualified,
      runnerIsolation: isolation, codeBotIsolation: codeBot?.isolation || null, activationEnabled: false });
  } finally {
    if(directory)await fs.rm(directory, { recursive: true, force: true });
  }
}

function assertRequestedCapabilities(receipt, { activateObservedAction = false, activateIndirectInjection = false, activateSupplyChain = false } = {}) {
  const { PROTECTED_STATE_CAPABILITY, OBSERVED_ACTION_CAPABILITY,
    TICKET_READ_CAPABILITY, PACKAGE_INSTALL_CAPABILITY } = require('../../server/services/mcp/ownedQualification');
  if ((activateObservedAction || activateIndirectInjection || activateSupplyChain)
      && (receipt?.protectedStateCapability !== PROTECTED_STATE_CAPABILITY
        || receipt.observedActionCapability !== OBSERVED_ACTION_CAPABILITY)
      || activateIndirectInjection && receipt?.ticketReadCapability !== TICKET_READ_CAPABILITY
      || activateSupplyChain && receipt?.packageInstallCapability !== PACKAGE_INSTALL_CAPABILITY) {
    throw failure('MCP_INSTALL_CAPABILITY_UNAVAILABLE', 'owned-readiness');
  }
  return true;
}

async function provisionFromEnvironment({ envPath, platform = process.platform, root = path.resolve(__dirname, '../..'),
  home = os.homedir(), managedPath = managedConfigurationPath({ root, home }), activateQualified = false,
  activateObservedAction = false, activateSupplyChain = false, activateIndirectInjection = false,
  activateProtectedRecovery = false, protectedRecoveryRelease = null,
  colimaProfile, run, ownedLabSession, storage=createOwnedPrivateStorage(),
  codeBotReadiness,
  provision = provisionOwnedLocal,
  targetClientFactory = require('../../server/services/mcp/ownedTargetClient').createMcpOwnedTargetClient } = {}) {
  if(platform==='win32')localProfilePlan({platform,root,home,ownedLabSession});
  const prepared = await prepareOwnedManagedConfiguration({ envPath, managedPath, forceDisabled: true,storage });
  const privateValues = dotenv.parse(await storage.read(envPath,{workspace:true}));
  const parsed = { ...privateValues, ...prepared.values };
  const targets = targetClientFactory({
    baseURL: parsed.MCP_OWNED_TARGET_URL, token: parsed.MCP_OWNED_TARGET_TOKEN,
  });
  let capabilityReadinessVerified = false;
  const requestedReadiness = async () => {
    const receipt = await targets.readiness();
    assertRequestedCapabilities(receipt, { activateObservedAction, activateIndirectInjection, activateSupplyChain });
    capabilityReadinessVerified = true;
    return receipt;
  };
  const provisioned = await provision({ platform, root, home, colimaProfile, run,ownedLabSession,
    protectedRecoveryRelease: activateProtectedRecovery?protectedRecoveryRelease:null,
    commandEnv: { ...process.env, ...parsed }, readiness: requestedReadiness,
    codeBotReadiness: codeBotReadiness || (() => require('../../server/services/supplyChain/codeBotProduction')
      .readRunnerReadiness({ env: parsed })) });
  if (!activateQualified) return Object.freeze({ ...provisioned, managedPath });
  if ((activateObservedAction || activateIndirectInjection || activateSupplyChain) && !capabilityReadinessVerified) {
    throw failure('MCP_INSTALL_CAPABILITY_UNAVAILABLE', 'owned-readiness');
  }
  const activated = await prepareOwnedManagedConfiguration({ envPath, managedPath, activateQualified: true,
    activateObservedAction, activateSupplyChain, activateIndirectInjection,activateProtectedRecovery,protectedRecoveryQualified:provisioned.protectedRecoveryQualified===true,storage });
  return Object.freeze({ ...provisioned, managedPath, activationEnabled: activated.activationEnabled });
}

// Startup of a previously activated Windows runner. This path has no source
// staging, Compose up, image build, volume creation, or configuration write.
async function startExisting({ root = path.resolve(__dirname, '../..'), home = os.homedir(),
  platform = process.platform, ownedLabSession, commandEnv = process.env, privateStorage,
  managedPath = managedConfigurationPath({ root, home }), protectedRecoveryRelease = null } = {}) {
  const stage = 'existing-start';
  try {
    if (platform !== 'win32' || !ownedLabSession || !commandEnv || typeof commandEnv !== 'object') throw Error();
    const plan = localProfilePlan({ platform, root, home, ownedLabSession });
    assertDockerAuthority(commandEnv, plan);
    const storage = privateStorage || createOwnedPrivateStorage({ filesystemPlatform: 'win32' });
    const { parseManagedConfiguration } = require('../../server/services/mcp/ownedManagedConfiguration');
    const managed = parseManagedConfiguration(await storage.read(managedPath));
    if (managed.MCP_OWNED_RESOURCES_ENABLED !== 'true' || managed.CODEBOT_OWNED_EXECUTION_ENABLED !== 'true'
      || ['MCP_OWNED_TARGET_TOKEN', 'MCP_OWNED_TARGET_APPARMOR_PROFILE', 'MCP_OWNED_TARGET_PORT', 'MCP_OWNED_TARGET_URL']
        .some(key => commandEnv[key] !== undefined && commandEnv[key] !== managed[key])) throw Error();
    await ownedLabSession.assertCurrent();
    const template = await readTemplate(plan.template);
    const rendered = Buffer.from(renderMcpSandboxAppArmor(template, PROFILE));
    const profileSha256 = digest(rendered);
    const profile = await ownedLabSession.installAndVerifyProfile({ name: PROFILE, bytes: rendered,
      sha256: profileSha256, existingOnly: true });
    if (profile?.name !== PROFILE || profile.sha256 !== profileSha256 || profile.destination !== plan.destination
      || profile.bindingSha256 !== plan.sessionBinding.bindingSha256) throw Error();

    const project = 'dvaia-' + plan.sessionBinding.workspaceId;
    const service = 'mcp-owned-sandbox';
    const containerName = project + '-' + service + '-1';
    const imageName = 'mcp-owned-sandbox-runner:dev';
    const volumeName = project + '_mcp-owned-targets';
    const networkName = project + '_mcplab';
    const docker = args => ownedLabSession.executeDocker(args, { scope: 'provision' });
    const parseOne = text => {
      if (typeof text !== 'string' || Buffer.byteLength(text) > 1024 * 1024) throw Error();
      const value = JSON.parse(text);
      return Array.isArray(value) && value.length === 1 ? value[0] : value;
    };
    const image = parseOne(await docker(['image', 'inspect', imageName]));
    if (!/^sha256:[a-f0-9]{64}$/.test(image?.Id || '') || !image.RepoTags?.includes(imageName)) throw Error();
    if (managed.MCP_PROTECTED_RECOVERY_ENABLED === 'true'
      && (protectedRecoveryRelease?.image !== image.Id || protectedRecoveryRelease.profileSha256 !== profileSha256)) throw Error();
    const volume = parseOne(await docker(['volume', 'inspect', volumeName]));
    if (volume?.Name !== volumeName || volume.Labels?.['com.docker.compose.project'] !== project
      || volume.Labels?.['com.docker.compose.volume'] !== 'mcp-owned-targets') throw Error();
    const listed = (await docker(['ps', '--all', '--no-trunc', '--filter', `label=com.docker.compose.project=${project}`,
      '--filter', `label=com.docker.compose.service=${service}`, '--format', '{{.ID}}'])).trim();
    if (!/^[a-f0-9]{64}$/.test(listed)) throw Error();
    const inspect = async () => parseOne(await docker(['inspect', listed]));
    const matches = container => {
      const labels = container?.Config?.Labels, host = container?.HostConfig;
      const ports = host?.PortBindings?.['8090/tcp'], mount = container?.Mounts?.[0];
      const networks = container?.NetworkSettings?.Networks;
      const livePorts = container?.NetworkSettings?.Ports?.['8090/tcp'];
      return container?.Id === listed && container.Name === '/' + containerName && container.Image === image.Id
        && container.Config.Image === imageName && container.AppArmorProfile === PROFILE
        && labels?.['com.docker.compose.project'] === project && labels?.['com.docker.compose.service'] === service
        && container.Config.Env?.includes('MCP_OWNED_TARGETS_ENABLED=true')
        && container.Config.Env?.includes('MCP_OWNED_TARGET_TOKEN=' + managed.MCP_OWNED_TARGET_TOKEN)
        && container.Config.Env?.includes('MCP_OWNED_TARGET_APPARMOR_PROFILE=' + PROFILE)
        && container.Config.Env?.includes('MCP_OWNED_TARGET_ROOT=/sandbox/owned-targets')
        && host.Privileged === false && host.NetworkMode === networkName
        && !['host'].includes(host.PidMode) && !['host'].includes(host.IpcMode)
        && host.SecurityOpt?.includes('apparmor=' + PROFILE) && host.SecurityOpt?.includes('seccomp=unconfined')
        && Array.isArray(ports) && ports.length === 1 && ports[0].HostIp === '127.0.0.1' && ports[0].HostPort === '8092'
        && Object.keys(host.PortBindings).length === 1
        && container.Mounts?.length === 1 && mount.Type === 'volume' && mount.Name === volumeName
        && mount.Destination === '/sandbox/owned-targets' && mount.RW === true
        && networks && Object.keys(networks).length === 1 && Object.hasOwn(networks, networkName)
        && (container.State?.Running !== true || Array.isArray(livePorts) && livePorts.length === 1
          && livePorts[0].HostIp === '127.0.0.1' && livePorts[0].HostPort === '8092')
        && (container.State?.Running === true || container.State?.Running === false);
    };
    const before = await inspect();
    if (!matches(before)) throw Error();
    if (before.State.Running === false) await docker(['start', listed]);
    const after = await inspect();
    if (!matches(after) || after.State.Running !== true) throw Error();
    await ownedLabSession.assertCurrent();
    return Object.freeze({ url: managed.MCP_OWNED_TARGET_URL, port: 8092, activationEnabled: true,
      containerId: listed, imageId: image.Id, profileSha256, bindingSha256: plan.sessionBinding.bindingSha256 });
  } catch { throw failure('MCP_INSTALL_EXISTING_UNAVAILABLE', stage); }
}

if (require.main === module) {
  const root = path.resolve(__dirname, '../..'); const args = process.argv.slice(2);
  const value = name => { const index = args.indexOf(name); return index < 0 ? null : args[index + 1]; };
  const envPath = path.resolve(value('--env') || path.join(root, '.env'));
  const managedPath = path.resolve(value('--managed-config') || managedConfigurationPath({ root }));
  const colimaProfile = value('--colima-profile') || undefined;
  const activateQualified = args.includes('--activate-qualified');
  const activateObservedAction = args.includes('--activate-observed-action');
  const activateSupplyChain = args.includes('--activate-supply-chain');
  const activateIndirectInjection = args.includes('--activate-indirect-injection');
  provisionFromEnvironment({ envPath, managedPath, activateQualified, activateObservedAction, activateSupplyChain,
    activateIndirectInjection,
    root, colimaProfile }).then(result => {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }).catch(error => {
    process.stderr.write(`${JSON.stringify({ ok: false, code: error?.code || 'MCP_INSTALL_FAILED',
      stage: error?.stage || null, cleanupDebt: error?.cleanupDebt || null })}\n`);
    process.exitCode = 1;
  });
}

module.exports = { assertRequestedCapabilities, provisionOwnedLocal, provisionFromEnvironment, startExisting, createCommandRunner,
  _internals: { exactProfileList, linuxInstall, darwinInstall, remoteCommand, readTemplate,
    assertDockerAuthority, reviewedRunnerBundle,windowsInstall, ENFORCED } };
