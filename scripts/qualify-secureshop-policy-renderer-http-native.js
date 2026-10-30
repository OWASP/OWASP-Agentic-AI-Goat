#!/usr/bin/env node
'use strict';

// Disposable native HTTP composition qualification for the launch-owned policy renderer. It
// never starts or modifies the installed sidecar.

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const exec = promisify(execFile);
const ROOT = path.resolve(__dirname, '..');
const DOCKER = '/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker';
const DOCKER_HOST = 'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock';
const BUILDER_ID = 'sha256:b02aa7a4e02c967c34e0441b516dca784e40dc0ca1094aebfd705c56623d52bb';
const RUNTIME_ID = 'sha256:3232d0a6b7e424680b31c4bb9cc4bccdd82087d50c5fabae7f9758eba3ff1b1b';
const EXPECTED_OUTER_BOUNDING = '00000000a80425fb';
const TRACKED = Object.freeze([
  'scripts/qualify-secureshop-policy-renderer-http-native.js',
  'server/services/secureshopPolicySandboxRuntime.js',
  'server/services/secureshopPromptPolicyContract.js',
  'sidecars/sandbox-runner/policy-render/executor.js',
  'sidecars/sandbox-runner/policy-render/worker.js',
  'sidecars/sandbox-runner/policy-render/process-supervisor.c',
  'sidecars/sandbox-runner/policy-render/policy-init.c',
  'sidecars/sandbox-runner/policy-render/http-handler.js',
  'sidecars/sandbox-runner/policy-render/http-native-qualification.js',
  'sidecars/sandbox-runner/policy-render/assets/nunjucks-3.2.4.js',
  'sidecars/sandbox-runner/policy-render/assets/NUNJUCKS-LICENSE.txt',
]);

const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function sourceHashes() {
  return Object.fromEntries(TRACKED.map(name => {
    const filename = path.join(ROOT, name);
    const stat = fs.lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Tracked source is not a regular file: ${name}`);
    return [name, digest(fs.readFileSync(filename))];
  }));
}
const suffix = crypto.randomBytes(6).toString('hex');
const container = `owasp-ai-goat-policy-render-http-${suffix}`;
const image = `owasp-ai-goat-policy-render-http-qual:${suffix}`;
const builderAlias = `owasp-ai-goat-policy-render-http-builder:${suffix}`;
const runtimeAlias = `owasp-ai-goat-policy-render-http-runtime:${suffix}`;
const evidenceParent = path.join(os.homedir(), '.owasp-ai-goat', 'native-verification');
const evidence = path.join(evidenceParent, `owasp-ai-goat-policy-render-http-${suffix}`);
const buildContext = path.join(evidence, 'build');
const resultFile = path.join(ROOT, 'tasks', `secureshop-policy-renderer-http-native-${suffix}.json`);
const before = sourceHashes();
const result = { version: 1, candidateOnly: true, installedActivation: false,
  actualModel: false, dockerHost: DOCKER_HOST, container, image,
  sourceHashes: before, evidence, startedAt: new Date().toISOString() };

async function docker(args, options = {}) {
  return exec(DOCKER, ['--host', DOCKER_HOST, ...args], {
    cwd: ROOT, timeout: options.timeout || 120000, maxBuffer: options.maxBuffer || 2 * 1024 * 1024,
    encoding: 'utf8', ...options,
  });
}
async function absentContainer() {
  return !(await docker(['ps','-aq','--filter',`name=^/${container}$`,'--format','{{.Names}}'])).stdout.trim();
}
async function absentImage(reference = image) {
  return !(await docker(['images','--filter',`reference=${reference}`,'--format','{{.Repository}}:{{.Tag}}'])).stdout.trim();
}
async function atomicJson(filename, value) {
  const pending = `${filename}.${process.pid}.pending`;
  await fsp.writeFile(pending, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await fsp.rename(pending, filename);
}
async function prepareContext() {
  await fsp.mkdir(buildContext, { recursive: true, mode: 0o700 });
  for (const name of TRACKED.filter(name => name !== 'scripts/qualify-secureshop-policy-renderer-http-native.js')) {
    const target = path.join(buildContext, name);
    await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await fsp.copyFile(path.join(ROOT, name), target);
    const copiedSha256 = digest(await fsp.readFile(target));
    if (copiedSha256 !== before[name]) throw new Error(`Frozen source changed before copy: ${name}`);
  }
  const dockerfile = [
    `FROM ${builderAlias} AS builder`,
    'COPY sidecars/sandbox-runner/policy-render/process-supervisor.c /build/process-supervisor.c',
    'COPY sidecars/sandbox-runner/policy-render/policy-init.c /build/policy-init.c',
    'RUN gcc -static -O2 -Wall -Wextra -Werror /build/process-supervisor.c -o /out-policy-render-supervisor && gcc -static -O2 -Wall -Wextra -Werror /build/policy-init.c -o /out-policy-render-init && chmod 0555 /out-policy-render-supervisor /out-policy-render-init',
    `FROM ${runtimeAlias}`,
    `LABEL owasp-ai-goat.qualification.policy-render-http=${suffix}`,
    'COPY --from=builder /out-policy-render-supervisor /usr/local/libexec/owasp-ai-goat-policy-render-supervisor',
    'COPY --from=builder /out-policy-render-init /usr/local/libexec/owasp-ai-goat-policy-render-init',
    'COPY sidecars/sandbox-runner/policy-render /app/sidecars/sandbox-runner/policy-render',
    'COPY server/services/secureshopPromptPolicyContract.js /app/server/services/secureshopPromptPolicyContract.js',
    'COPY server/services/secureshopPolicySandboxRuntime.js /app/server/services/secureshopPolicySandboxRuntime.js',
    'RUN chown 0:0 /usr/bin/bwrap /usr/local/libexec/owasp-ai-goat-policy-render-supervisor /usr/local/libexec/owasp-ai-goat-policy-render-init && chmod 0755 /usr/bin/bwrap && chmod 0555 /usr/local/libexec/owasp-ai-goat-policy-render-supervisor /usr/local/libexec/owasp-ai-goat-policy-render-init && chmod -R a+rX /app/sidecars/sandbox-runner/policy-render /app/server/services/secureshopPromptPolicyContract.js /app/server/services/secureshopPolicySandboxRuntime.js',
  ].join('\n') + '\n';
  await fsp.writeFile(path.join(buildContext, 'Dockerfile'), dockerfile, { mode: 0o600 });
  result.dockerfileSha256 = digest(Buffer.from(dockerfile));
  result.buildContextHashes = Object.fromEntries(
    TRACKED.filter(name => name !== 'scripts/qualify-secureshop-policy-renderer-http-native.js')
      .map(name => [name, digest(fs.readFileSync(path.join(buildContext, name)))]),
  );
}
async function inspectBase(reference, expected) {
  const parsed = JSON.parse((await docker(['inspect', reference])).stdout)[0];
  if (parsed.Id !== expected) throw new Error(`Frozen base image changed: ${reference}`);
  return { reference, id: parsed.Id, architecture: parsed.Architecture, os: parsed.Os };
}
async function diagnostics() {
  const value = {};
  try {
    const inspected = JSON.parse((await docker(['inspect', container], { timeout: 20000 })).stdout)[0];
    value.inspect = { id: inspected.Id, image: inspected.Image,
      state: inspected.State, hostConfig: { readonlyRootfs: inspected.HostConfig.ReadonlyRootfs,
        securityOpt: inspected.HostConfig.SecurityOpt, capDrop: inspected.HostConfig.CapDrop,
        capAdd: inspected.HostConfig.CapAdd,
        networkMode: inspected.HostConfig.NetworkMode,
        tmpfs: inspected.HostConfig.Tmpfs }, mounts: inspected.Mounts };
  } catch (error) { value.inspectError = error.code || error.name; }
  try {
    const logs = await docker(['logs','--tail','200',container], { timeout: 20000 });
    const bytes = Buffer.from(`${logs.stdout}${logs.stderr}`);
    await fsp.writeFile(path.join(evidence, 'container.log'), bytes, { mode: 0o600 });
    value.logSha256 = digest(bytes);
  } catch (error) { value.logError = error.code || error.name; }
  return value;
}

async function main() {
  if (process.argv.length !== 3 || !['--plan','--run'].includes(process.argv[2])) {
    throw new Error('Usage: node scripts/qualify-secureshop-policy-renderer-http-native.js --plan|--run');
  }
  await fsp.mkdir(evidenceParent, { recursive: true, mode: 0o700 });
  if (process.argv[2] === '--plan') {
    process.stdout.write(`${JSON.stringify({ docker: DOCKER, dockerHost: DOCKER_HOST,
      baseImages: { builder: BUILDER_ID, runtime: RUNTIME_ID }, container, image,
      temporaryAliases: [builderAlias, runtimeAlias],
      tracked: before, mutations: ['unique disposable image','unique disposable container','private evidence directory'] }, null, 2)}\n`);
    return;
  }
  await fsp.mkdir(evidence, { mode: 0o700 });
  let buildAttempted = false, containerAttempted = false, aliasesAttempted = false;
  try {
    const daemon = JSON.parse((await docker(['info','--format','{{json .}}'], { timeout: 30000 })).stdout);
    if (daemon.Name !== 'colima-owasp-ai-goat-pg-verify' || daemon.Architecture !== 'aarch64') throw new Error('Reviewed Docker daemon identity mismatch');
    result.daemon = { name: daemon.Name, architecture: daemon.Architecture, serverVersion: daemon.ServerVersion };
    result.baseImages = {
      builder: await inspectBase(BUILDER_ID, BUILDER_ID), runtime: await inspectBase(RUNTIME_ID, RUNTIME_ID),
    };
    if (!await absentContainer() || !await absentImage()
        || !await absentImage(builderAlias) || !await absentImage(runtimeAlias)) {
      throw new Error('Unique native resources already exist');
    }
    aliasesAttempted = true;
    await docker(['tag',BUILDER_ID,builderAlias]);
    await docker(['tag',RUNTIME_ID,runtimeAlias]);
    const aliasedBuilder = await inspectBase(builderAlias, BUILDER_ID);
    const aliasedRuntime = await inspectBase(runtimeAlias, RUNTIME_ID);
    result.temporaryAliases = { builder: aliasedBuilder, runtime: aliasedRuntime };
    await prepareContext();
    buildAttempted = true;
    const buildLog = path.join(evidence, 'build.log');
    try {
      const build = await docker(['build','--pull=false','--network=none','--tag',image,buildContext], { timeout: 300000, maxBuffer: 8 * 1024 * 1024 });
      await fsp.writeFile(buildLog, `${build.stdout}${build.stderr}`, { mode: 0o600 });
    } catch (error) {
      await fsp.writeFile(buildLog, `${error.stdout || ''}${error.stderr || ''}`, { mode: 0o600 });
      throw error;
    }
    result.buildLogSha256 = digest(fs.readFileSync(buildLog));
    const builtImage = JSON.parse((await docker(['inspect',image])).stdout)[0];
    if (builtImage.Config?.Labels?.['owasp-ai-goat.qualification.policy-render-http'] !== suffix) {
      throw new Error('Disposable renderer image ownership label mismatch');
    }
    result.builtImage = { id: builtImage.Id,
      ownershipLabel: builtImage.Config.Labels['owasp-ai-goat.qualification.policy-render-http'] };
    containerAttempted = true;
    await docker(['run','--detach','--name',container,'--label',`owasp-ai-goat.qualification=${suffix}`,
      '--user','10001:10001','--network','none','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=16777216',
      '--security-opt','seccomp=unconfined','--security-opt','apparmor=owasp-ai-goat-mcp-sandbox',
      '--entrypoint','/bin/sh',image,'-c','while :; do sleep 3600; done']);
    const inspected = JSON.parse((await docker(['inspect',container])).stdout)[0];
    const tmpfs = inspected.HostConfig.Tmpfs || {};
    if ((inspected.Mounts || []).some(mount => mount.Type !== 'tmpfs')
        || JSON.stringify(Object.keys(tmpfs)) !== JSON.stringify(['/tmp'])
        || tmpfs['/tmp'] !== 'rw,nosuid,nodev,size=16777216'
        || inspected.Config?.Labels?.['owasp-ai-goat.qualification'] !== suffix
        || inspected.Image !== result.builtImage.id
        || inspected.HostConfig.NetworkMode !== 'none'
        || inspected.HostConfig.ReadonlyRootfs !== true
        || (inspected.HostConfig.CapDrop || []).length !== 0
        || (inspected.HostConfig.CapAdd || []).length !== 0
        || !new Set(inspected.HostConfig.SecurityOpt || []).has('seccomp=unconfined')
        || !new Set(inspected.HostConfig.SecurityOpt || []).has('apparmor=owasp-ai-goat-mcp-sandbox')) {
      throw new Error('Disposable renderer container boundary mismatch');
    }
    const outerStatus = (await docker(['exec','--user','10001:10001',container,'/bin/cat','/proc/1/status'], { timeout: 20000 })).stdout;
    const outerCaps = Object.fromEntries(['CapEff','CapPrm','CapInh','CapAmb','CapBnd'].map(name => {
      const match = outerStatus.match(new RegExp(`^${name}:\\s+([0-9a-f]+)$`, 'mi'));
      return [name, match?.[1] || null];
    }));
    const outerUid = outerStatus.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mi)?.slice(1).map(Number);
    const outerGid = outerStatus.match(/^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mi)?.slice(1).map(Number);
    if (['CapEff','CapPrm','CapInh','CapAmb'].some(name => !outerCaps[name] || !/^0+$/.test(outerCaps[name]))
        || outerCaps.CapBnd !== EXPECTED_OUTER_BOUNDING
        || outerUid?.some(value => value !== 10001) || outerUid?.length !== 4
        || outerGid?.some(value => value !== 10001) || outerGid?.length !== 4) {
      throw new Error('Outer renderer supervisor unexpectedly has active capabilities');
    }
    result.runtime = {
      bwrap: (await docker(['exec','--user','10001:10001',container,'/usr/bin/bwrap','--version'], { timeout: 20000 })).stdout.trim(),
      bwrapIdentity: (await docker(['exec','--user','10001:10001',container,'/usr/bin/stat','-c','%a:%u:%g',
        '/usr/bin/bwrap'], { timeout: 20000 })).stdout.trim(),
      supervisorIdentity: (await docker(['exec','--user','10001:10001',container,'/usr/bin/stat','-c','%a:%u:%g',
        '/usr/local/libexec/owasp-ai-goat-policy-render-supervisor'], { timeout: 20000 })).stdout.trim(),
      supervisorSha256: (await docker(['exec','--user','10001:10001',container,'/usr/bin/sha256sum',
        '/usr/local/libexec/owasp-ai-goat-policy-render-supervisor'], { timeout: 20000 })).stdout.trim().split(/\s+/)[0],
      initSha256: (await docker(['exec','--user','10001:10001',container,'/usr/bin/sha256sum',
        '/usr/local/libexec/owasp-ai-goat-policy-render-init'], { timeout: 20000 })).stdout.trim().split(/\s+/)[0],
      outerIdentity: { uid: outerUid, gid: outerGid, capabilities: outerCaps },
    };
    if (result.runtime.bwrapIdentity !== '755:0:0' || result.runtime.supervisorIdentity !== '555:0:0') {
      throw new Error('Dedicated policy supervisor bootstrap identity mismatch');
    }
    const qualified = await docker(['exec','--user','10001:10001',container,
      '/usr/local/bin/node','/app/sidecars/sandbox-runner/policy-render/http-native-qualification.js'],
    { timeout: 30000, maxBuffer: 1024 * 1024 });
    result.qualification = JSON.parse(qualified.stdout);
    if (result.qualification.node !== 'v26.9.0') throw new Error('Frozen Node 26.9 qualification runtime mismatch');
    result.runtimeScope = { node: 'v26.9.0', architecture: 'arm64', amd64Qualified: false };
    const residual = (await docker(['exec','--user','10001:10001',container,'/bin/sh','-c',
      "find /tmp -mindepth 1 -maxdepth 2 -print; ps -eo args | grep -E '[d]vaia-policy-render-supervisor|[s]leep 30|[b]wrap' || true"], { timeout: 20000 })).stdout.trim();
    if (residual) throw new Error(`Renderer left residual owned state or descendants: ${residual.slice(0, 512)}`);
    result.residualStateAbsent = true;
    result.passed = true;
  } catch (error) {
    result.passed = false; result.error = { name: error.name, code: error.code || null, message: String(error.message).slice(0, 2048) };
    throw error;
  } finally {
    if (containerAttempted) result.failureDiagnostics = await diagnostics();
    if (containerAttempted) await docker(['rm','-f',container], { timeout: 30000 }).catch(() => {});
    if (buildAttempted) await docker(['image','rm','-f',image], { timeout: 60000 }).catch(() => {});
    if (aliasesAttempted) {
      await docker(['image','rm','-f',builderAlias], { timeout: 60000 }).catch(() => {});
      await docker(['image','rm','-f',runtimeAlias], { timeout: 60000 }).catch(() => {});
    }
    result.cleanup = { containerAbsent: await absentContainer().catch(() => false),
      imageAbsent: await absentImage().catch(() => false),
      builderAliasAbsent: await absentImage(builderAlias).catch(() => false),
      runtimeAliasAbsent: await absentImage(runtimeAlias).catch(() => false) };
    try {
      result.sourceUnchanged = JSON.stringify(sourceHashes()) === JSON.stringify(before);
    } catch (error) {
      result.sourceUnchanged = false;
      result.sourceVerificationError = String(error.message).slice(0, 1024);
    }
    if (!Object.values(result.cleanup).every(Boolean) || !result.sourceUnchanged) {
      result.passed = false;
      result.terminalError = 'Owned cleanup or frozen source verification failed';
      process.exitCode = 1;
    }
    result.completedAt = new Date().toISOString();
    await atomicJson(path.join(evidence, 'result.json'), result);
    await atomicJson(resultFile, result);
    process.stdout.write(`${JSON.stringify({ passed: result.passed, evidence, resultFile,
      cleanup: result.cleanup, sourceUnchanged: result.sourceUnchanged })}\n`);
  }
}

main().catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });
