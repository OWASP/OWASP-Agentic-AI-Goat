#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { normalizeRenderExecution, validateRenderExecutionResult }
  = require('../server/services/secureshopPromptPolicyContract');
const exec = promisify(execFile);

const ROOT = path.resolve(__dirname, '..');
const DOCKER = '/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker';
const DOCKER_HOST = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock';
const NODE_DIGEST = 'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1';
const NODE_IMAGE = `docker.io/library/node:26.10.0-slim@${NODE_DIGEST}`;
const suffix = crypto.randomBytes(6).toString('hex');
const image = `dvaia-policy-render-package:${suffix}`;
const enabled = `dvaia-policy-render-package-enabled-${suffix}`;
const unavailable = `dvaia-policy-render-package-unavailable-${suffix}`;
const evidence = path.join(os.homedir(), '.dvaia', 'native-verification', `dvaia-policy-render-package-${suffix}`);
const resultFile = path.join(ROOT, 'tasks', `secureshop-policy-renderer-package-native-${suffix}.json`);
const COPIED_TREES = Object.freeze(['sidecars/sandbox-runner/owned-http',
  'sidecars/sandbox-runner/protected-operations', 'sidecars/sandbox-runner/labfs',
  'sidecars/sandbox-runner/policy-render/assets']);
function treeFiles(directory) {
  return fs.readdirSync(path.join(ROOT, directory), { withFileTypes: true }).flatMap(entry => {
    const name = `${directory}/${entry.name}`;
    if (entry.isDirectory()) return treeFiles(name);
    if (!entry.isFile() || fs.realpathSync(path.join(ROOT, name)) !== path.join(ROOT, name)) {
      throw new Error(`Invalid Docker build input: ${name}`);
    }
    return [name];
  });
}
const DIRECT_INPUTS = Object.freeze([
  'scripts/qualify-secureshop-policy-renderer-package-native.js',
  'sidecars/sandbox-runner/Dockerfile', 'sidecars/sandbox-runner/index.js',
  'sidecars/sandbox-runner/entrypoint.sh', 'sidecars/sandbox-runner/package.json',
  'sidecars/sandbox-runner/mcpSeccompFilter.c', 'sidecars/sandbox-runner/mcpSeccompProbe.c',
  'sidecars/sandbox-runner/mcpTargets.js', 'sidecars/sandbox-runner/mcpProtectedState.js',
  'sidecars/sandbox-runner/mcpPackageCatalog.js', 'sidecars/sandbox-runner/ownedTargetApi.js',
  'sidecars/sandbox-runner/policy-render/executor.js',
  'sidecars/sandbox-runner/policy-render/http-handler.js',
  'sidecars/sandbox-runner/policy-render/worker.js',
  'sidecars/sandbox-runner/policy-render/process-supervisor.c',
  'sidecars/sandbox-runner/policy-render/policy-init.c',
  'sidecars/sandbox-runner/policy-render/secureshopPromptPolicyContract.js',
  'server/services/secureshopPromptPolicyContract.js',
]);
const trackedFiles = () => [...new Set([...DIRECT_INPUTS, ...COPIED_TREES.flatMap(treeFiles)])].sort();
const TRACKED = Object.freeze(trackedFiles());
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
const hashes = () => Object.fromEntries(trackedFiles().map(name => [name, digest(fs.readFileSync(path.join(ROOT, name)))]));
const before = hashes();
const result = { version: 1, candidateOnly: true, installedActivation: false, actualModel: false,
  dockerHost: DOCKER_HOST, image, containers: { enabled, unavailable }, sourceHashes: before,
  evidence, startedAt: new Date().toISOString(), runtimeScope: { node: 'v26.10.0', architecture: 'arm64', amd64Qualified: false } };

const effectMarkdown = `{{ process.mainModule.require('node:child_process').execFileSync('/bin/sh',['-c',"umask 077 && cp /owned-source/effect-canary /owned-effect/command-effect && printf packaged-v2-canary"]).toString() }}`;
function validateV2Pair({ request, vulnerable, fixed }) {
  if (request?.markdown !== effectMarkdown) throw new Error('Packaged v2 canary source mismatch');
  const vulnEnvelope = normalizeRenderExecution({ version: 2, mode: 'vuln', request });
  const fixedEnvelope = normalizeRenderExecution({ version: 2, mode: 'fixed', request });
  if (vulnerable?.status !== 200 || fixed?.status !== 200) throw new Error('Packaged v2 endpoint status mismatch');
  const isolated = validateRenderExecutionResult(vulnEnvelope, vulnerable.body);
  const literal = validateRenderExecutionResult(fixedEnvelope, fixed.body);
  if (isolated.rendered !== 'packaged-v2-canary' || isolated.effectWitness.commandEffectObserved !== true
      || isolated.effectWitness.effectSha256 === null || literal.rendered !== request.markdown
      || isolated.requestSha256 !== literal.requestSha256 || isolated.executionSha256 === literal.executionSha256) {
    throw new Error('Packaged v2 effect or fixed literal proof failed');
  }
  return { isolated, literal };
}
function verifyPackageSource() {
  const dockerfile = fs.readFileSync(path.join(ROOT, 'sidecars/sandbox-runner/Dockerfile'), 'utf8');
  const bases = dockerfile.split('\n').filter(line => line.startsWith('FROM '));
  if (bases.length !== 2 || bases.some(line => !line.startsWith(`FROM ${NODE_IMAGE}`))) {
    throw new Error('Packaged Dockerfile base digest mismatch');
  }
  const canonical = fs.readFileSync(path.join(ROOT, 'server/services/secureshopPromptPolicyContract.js'));
  const packaged = fs.readFileSync(path.join(ROOT, 'sidecars/sandbox-runner/policy-render/secureshopPromptPolicyContract.js'));
  if (!canonical.equals(packaged)) throw new Error('Packaged policy contract differs from server contract');
}

async function docker(args, options = {}) {
  return exec(DOCKER, ['--host', DOCKER_HOST, ...args], { cwd: ROOT, encoding: 'utf8', timeout: options.timeout || 120000,
    maxBuffer: options.maxBuffer || 4 * 1024 * 1024, ...options });
}
async function atomic(filename, value) {
  const pending = `${filename}.${process.pid}.pending`;
  await fsp.writeFile(pending, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await fsp.rename(pending, filename);
}
async function waitHealth(container, expectedAvailable) {
  const program = `const end=Date.now()+15000;(async()=>{for(;;){try{const r=await fetch('http://127.0.0.1:8090/health');const j=await r.json();if(j.policyRenderer?.enabled===true&&j.policyRenderer?.available===${expectedAvailable}&&j.policyRenderer?.isolation==='${expectedAvailable ? 'bwrap-policy-template-v1' : 'unavailable'}'){process.stdout.write(JSON.stringify(j));return;}}catch{}if(Date.now()>end)throw Error('health timeout');await new Promise(r=>setTimeout(r,100));}})().catch(e=>{console.error(e);process.exit(1)});`;
  return JSON.parse((await docker(['exec',container,'/usr/local/bin/node','-e',program], { timeout: 20000 })).stdout);
}
async function absentContainer(name) {
  return !(await docker(['ps','-aq','--filter',`name=^/${name}$`,'--format','{{.Names}}'])).stdout.trim();
}
async function absentImage() {
  return !(await docker(['images','--filter',`reference=${image}`,'--format','{{.Repository}}:{{.Tag}}'])).stdout.trim();
}

async function main() {
  if (process.argv.length !== 3 || !['--plan','--run'].includes(process.argv[2])) throw new Error('Usage: qualify-secureshop-policy-renderer-package-native.js --plan|--run');
  verifyPackageSource();
  if (process.argv[2] === '--plan') { process.stdout.write(`${JSON.stringify({ image, containers: result.containers, nodeImage: NODE_IMAGE, tracked: before }, null, 2)}\n`); return; }
  await fsp.mkdir(evidence, { recursive: true, mode: 0o700 });
  let imageAttempted = false, enabledAttempted = false, unavailableAttempted = false;
  try {
    const daemon = JSON.parse((await docker(['info','--format','{{json .}}'], { timeout: 30000 })).stdout);
    if (daemon.Name !== 'colima-dvaia-pg-verify' || daemon.Architecture !== 'aarch64') throw new Error('Docker daemon mismatch');
    result.daemon = { name: daemon.Name, architecture: daemon.Architecture, serverVersion: daemon.ServerVersion };
    const nodeImage = JSON.parse((await docker(['inspect',NODE_IMAGE])).stdout)[0];
    if (nodeImage.Id !== NODE_DIGEST || nodeImage.Architecture !== 'arm64' || nodeImage.Os !== 'linux'
        || !nodeImage.RepoDigests?.some(value => value === `node@${NODE_DIGEST}` || value === `docker.io/library/node@${NODE_DIGEST}`)) {
      throw new Error('Pinned Node 26.10 base image drift');
    }
    result.nodeImage = { reference: NODE_IMAGE, id: nodeImage.Id, architecture: nodeImage.Architecture, os: nodeImage.Os };
    if (!await absentImage() || !await absentContainer(enabled) || !await absentContainer(unavailable)) throw new Error('Unique resource collision');
    imageAttempted = true;
    const build = await docker(['build','--pull=false','--network=default','-f','sidecars/sandbox-runner/Dockerfile','-t',image,'sidecars/sandbox-runner'], { timeout: 300000, maxBuffer: 16 * 1024 * 1024 });
    const buildBytes = Buffer.from(`${build.stdout}${build.stderr}`); await fsp.writeFile(path.join(evidence, 'build.log'), buildBytes, { mode: 0o600 });
    result.buildLogSha256 = digest(buildBytes);
    const built = JSON.parse((await docker(['inspect',image])).stdout)[0]; result.builtImage = { id: built.Id, architecture: built.Architecture, os: built.Os };

    enabledAttempted = true;
    await docker(['run','--detach','--name',enabled,'--label',`dvaia.qualification=${suffix}`,'--network','none',
      '--security-opt','seccomp=unconfined','--security-opt','apparmor=dvaia-mcp-sandbox',
      '--env','SECURESHOP_POLICY_RENDER_ENABLED=true','--env','SECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1',image]);
    const health = await waitHealth(enabled, true);
    const endpointProgram = `const c=require('node:crypto');const post=async(path,body)=>{const r=await fetch('http://127.0.0.1:8090'+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});return{status:r.status,body:await r.json()}};(async()=>{const req=m=>({operationId:c.randomUUID(),name:'packaged',markdown:m,targets:['admin']});const inert=await post('/secureshop/policy-render',req('Returns for {{ store_name }}.'));const exploit=await post('/secureshop/policy-render',req(\"{{ process.mainModule.require('node:child_process').execFileSync('/bin/sh',['-c','printf packaged-real-nunjucks']).toString() }}\"));const v2req=req(${JSON.stringify(effectMarkdown)});const vulnerable=await post('/secureshop/policy-render',{version:2,mode:'vuln',request:v2req});const fixed=await post('/secureshop/policy-render',{version:2,mode:'fixed',request:v2req});const sibling=await post('/exec',{sessionId:'package-proof',command:'printf sibling-route'});process.stdout.write(JSON.stringify({inert,exploit,v2:{request:v2req,vulnerable,fixed},sibling}));})().catch(e=>{console.error(e);process.exit(1)});`;
    const endpoint = JSON.parse((await docker(['exec',enabled,'/usr/local/bin/node','-e',endpointProgram], { timeout: 20000 })).stdout);
    if (endpoint.inert.status !== 200 || endpoint.inert.body.rendered !== 'Returns for SecureShop.'
        || endpoint.exploit.status !== 200 || endpoint.exploit.body.rendered !== 'packaged-real-nunjucks'
        || endpoint.sibling.status !== 200 || endpoint.sibling.body.stdout !== 'sibling-route') throw new Error('Packaged endpoint or sibling route failed');
    if (endpoint.v2?.request?.markdown !== effectMarkdown) throw new Error('Packaged v2 request was substituted');
    const { isolated, literal } = validateV2Pair(endpoint.v2);
    result.enabled = { health: health.policyRenderer, inert: { status: endpoint.inert.status, renderedSha256: endpoint.inert.body.renderedSha256 },
      realNunjucks: { status: endpoint.exploit.status, renderedSha256: endpoint.exploit.body.renderedSha256 },
      protocolV2: { isolatedTemplate: { status: endpoint.v2.vulnerable.status, kind: isolated.kind,
        requestSha256: isolated.requestSha256, executionSha256: isolated.executionSha256,
        renderedSha256: isolated.renderedSha256, effectWitness: isolated.effectWitness },
      fixedLiteral: { status: endpoint.v2.fixed.status, kind: literal.kind,
        requestSha256: literal.requestSha256, executionSha256: literal.executionSha256,
        renderedSha256: literal.renderedSha256, literalEqualsSource: literal.rendered === endpoint.v2.request.markdown } },
      siblingExec: { status: endpoint.sibling.status, exitCode: endpoint.sibling.body.exitCode } };

    const stalledProgram = `const h=require('node:http');const r=h.request({host:'127.0.0.1',port:8090,path:'/exec',method:'POST',headers:{'content-type':'application/json'}});r.on('error',()=>{});r.write('{');setInterval(()=>{},1000);`;
    await docker(['exec','--detach',enabled,'/usr/local/bin/node','-e',stalledProgram]);
    await new Promise(resolve => setTimeout(resolve, 200));
    const longProgram = `const c=require('node:crypto');fetch('http://127.0.0.1:8090/secureshop/policy-render',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({operationId:c.randomUUID(),name:'shutdown',markdown:\"{{ process.mainModule.require('node:child_process').execFileSync('/bin/sh',['-c',\\\"exec sh -c 'sleep 30 & wait'\\\"]).toString() }}\",targets:['admin']})}).catch(()=>{});setInterval(()=>{},1000);`;
    await docker(['exec','--detach',enabled,'/usr/local/bin/node','-e',longProgram]);
    let active = false;
    for (let i = 0; i < 50; i++) {
      const top = (await docker(['top',enabled], { timeout: 10000 })).stdout;
      if (/dvaia-policy-render-supervisor|\/usr\/bin\/bwrap/.test(top)) { active = true; break; }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!active) throw new Error('Packaged shutdown descendant was not observed');
    const stopStart = Date.now(); await docker(['stop','--time','5',enabled], { timeout: 15000 });
    const stopDurationMs = Date.now() - stopStart;
    const stopped = JSON.parse((await docker(['inspect',enabled])).stdout)[0];
    if (stopped.State.Running || stopDurationMs > 8000) throw new Error('Packaged graceful shutdown failed');
    result.shutdown = { descendantObserved: true, stalledNonPolicyTransport: true,
      transportCutoffBoundMs: 1000, durationMs: stopDurationMs, exitCode: stopped.State.ExitCode, running: stopped.State.Running };

    unavailableAttempted = true;
    await docker(['run','--detach','--name',unavailable,'--label',`dvaia.qualification=${suffix}`,
      '--network','none','--security-opt','seccomp=unconfined','--security-opt','apparmor=dvaia-mcp-sandbox',
      '--env','SECURESHOP_POLICY_RENDER_ENABLED=true','--entrypoint','/bin/sh',image,'-c',
      'chmod 0777 /usr/local/libexec/dvaia-policy-render-init && exec gosu 10001:10001 /usr/local/bin/node /app/index.js']);
    const failedHealth = await waitHealth(unavailable, false);
    const unavailableStatus = Number((await docker(['exec',unavailable,'/usr/local/bin/node','-e',
      "fetch('http://127.0.0.1:8090/secureshop/policy-render',{method:'POST',headers:{'content-type':'application/json'},body:'{}'}).then(r=>process.stdout.write(String(r.status)))"])).stdout);
    if (unavailableStatus !== 503) throw new Error('Failed preflight endpoint did not remain unavailable');
    result.failedPreflight = { health: failedHealth.policyRenderer, endpointStatus: unavailableStatus,
      disposableHelperIntegrityViolated: true };
    result.passed = true;
  } catch (error) {
    result.passed = false; result.error = { name: error.name, code: error.code || null, message: String(error.message).slice(0, 3000) }; throw error;
  } finally {
    if (enabledAttempted) await docker(['rm','-f',enabled], { timeout: 30000 }).catch(() => {});
    if (unavailableAttempted) await docker(['rm','-f',unavailable], { timeout: 30000 }).catch(() => {});
    if (imageAttempted) await docker(['image','rm','-f',image], { timeout: 60000 }).catch(() => {});
    result.cleanup = { enabledAbsent: await absentContainer(enabled).catch(() => false), unavailableAbsent: await absentContainer(unavailable).catch(() => false), imageAbsent: await absentImage().catch(() => false) };
    result.sourceUnchanged = JSON.stringify(hashes()) === JSON.stringify(before);
    if (!Object.values(result.cleanup).every(Boolean) || !result.sourceUnchanged) result.passed = false;
    result.completedAt = new Date().toISOString(); await atomic(path.join(evidence, 'result.json'), result); await atomic(resultFile, result);
    process.stdout.write(`${JSON.stringify({ passed: result.passed, resultFile, evidence, cleanup: result.cleanup, sourceUnchanged: result.sourceUnchanged })}\n`);
    if (!result.passed && !result.error) throw new Error('Package qualification cleanup or source closure failed');
  }
}
if (require.main === module) main().catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });
module.exports = { NODE_IMAGE, NODE_DIGEST, TRACKED, effectMarkdown, validateV2Pair, verifyPackageSource };
