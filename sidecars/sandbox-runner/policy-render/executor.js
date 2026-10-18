'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn: defaultSpawn, spawnSync: defaultSpawnSync } = require('node:child_process');
const { CONTRACT_VERSION: VERSION, ISOLATION, normalizeRenderRequest, requestDigest, validateRenderResult,
  normalizeRenderExecution, renderExecutionDigest, validateRenderExecutionResult, createLiteralRenderResult }
  = require('../../../server/services/secureshopPromptPolicyContract');

const COMPILER_SHA256 = 'e6d212d621f5f38de578c929afb5d2ac835f0b95bcd3fd0d61511eab1c8112d2';
const WORKER_SHA256 = '037fcf025f7534a727fb235c7f1ccb7a4e4164112bf877381b75f5f065dd5c13';
const MAX_RENDERED_BYTES = 64 * 1024;
const MAX_CAPTURE_BYTES = 96 * 1024;
const MAX_STDERR_BYTES = 16 * 1024;
const DEFAULT_TIMEOUT_MS = 1500;
const DEFAULT_DRAIN_GRACE_MS = 1000;
const DEFAULT_SUPERVISOR = '/usr/local/libexec/dvaia-policy-render-supervisor';
const DEFAULT_INIT = '/usr/local/libexec/dvaia-policy-render-init';
const effectWitnesses = new WeakMap();

const directory = __dirname;
const COMPILER_PATH = path.join(directory, 'assets', 'nunjucks-3.2.4.js');
const WORKER_PATH = path.join(directory, 'worker.js');
const TARGET_COMPILER = '/opt/policy-render/nunjucks-3.2.4.js';
const TARGET_WORKER = '/opt/policy-render/worker.js';
const CLEAN_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
const SYNTHETIC_ENV = 'SECURESHOP_POLICY_FIXTURE=owned-policy-render\nPOLICY_RENDER_SECRET=synthetic-only\n';
const SYNTHETIC_KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nSECURESHOP-OWNED-POLICY-RENDER-FIXTURE\n-----END OPENSSH PRIVATE KEY-----\n';
const INIT_ATTESTATION = Buffer.from('policy-init-v1 uid=10001 gid=10001 caps=zero bounding=zero ambient=zero nnp=1\n');
// bubblewrap 0.8 prunes the new user namespace's bounding set to its
// requested caps before configuring loopback. Retain only the two setup caps;
// the fixed policy init drops every set and independently attests the result
// before Node or learner-controlled template bytes run.
const BWRAP_NAMESPACE = Object.freeze(['--cap-drop', 'ALL', '--cap-add', 'CAP_NET_ADMIN',
  '--cap-add', 'CAP_SETPCAP', '--unshare-user', '--unshare-net', '--unshare-pid',
  '--unshare-uts', '--unshare-ipc']);

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function availableRuntimeMounts(existsSync = fs.existsSync) {
  return ['/usr', '/bin', '/lib', '/lib64'].filter(entry => existsSync(entry));
}
function loadCheckedAssets(readFileSync = fs.readFileSync) {
  const compiler = readFileSync(COMPILER_PATH);
  if (sha256(compiler) !== COMPILER_SHA256) throw Object.assign(new Error('Pinned Nunjucks asset checksum mismatch'), { code: 'POLICY_RENDER_ASSET_INVALID' });
  const banner = compiler.subarray(0, 80).toString('utf8');
  if (!banner.includes('nunjucks 3.2.4')) throw Object.assign(new Error('Pinned Nunjucks version mismatch'), { code: 'POLICY_RENDER_ASSET_INVALID' });
  const worker = readFileSync(WORKER_PATH);
  if (sha256(worker) !== WORKER_SHA256) throw Object.assign(new Error('Policy render worker checksum mismatch'), { code: 'POLICY_RENDER_ASSET_INVALID' });
  return { compiler: Buffer.from(compiler), worker: Buffer.from(worker) };
}
function checkAssets(readFileSync = fs.readFileSync) {
  loadCheckedAssets(readFileSync);
  return Object.freeze({ compilerSha256: COMPILER_SHA256, workerSha256: WORKER_SHA256 });
}
function buildProbeArgv(runtimeMounts = availableRuntimeMounts()) {
  return [...BWRAP_NAMESPACE,
    '--die-with-parent', '--new-session', '--clearenv', ...runtimeMounts.flatMap(entry => ['--ro-bind', entry, entry]),
    '--tmpfs', '/usr/local/libexec', '--ro-bind', DEFAULT_INIT, DEFAULT_INIT,
    '--dev', '/dev', '--dir', '/proc', '--tmpfs', '/tmp', '--tmpfs', '/work', '--chdir', '/work',
    '--setenv', 'PATH', CLEAN_PATH, DEFAULT_INIT, '--probe'];
}
function namespaceName(operationId) { return `policy-${sha256(operationId).slice(0, 20)}`; }
function buildRenderArgv(rawRequest, marker, runtimeMounts = availableRuntimeMounts(), effectRoot = '/tmp/dvaia-policy-render-effect') {
  const request = normalizeRenderRequest(rawRequest);
  const encoded = Buffer.from(JSON.stringify({ ...request, requestSha256: requestDigest(request) })).toString('base64');
  return [...BWRAP_NAMESPACE,
    '--die-with-parent', '--new-session', '--clearenv', ...runtimeMounts.flatMap(entry => ['--ro-bind', entry, entry]),
    '--tmpfs', '/usr/local/libexec', '--ro-bind', DEFAULT_INIT, DEFAULT_INIT,
    '--dev', '/dev', '--dir', '/proc', '--tmpfs', '/tmp', '--tmpfs', '/work', '--chdir', '/work',
    '--dir', '/opt', '--dir', '/opt/policy-render', '--file', '4', TARGET_COMPILER,
    '--file', '5', TARGET_WORKER,
    '--dir', '/app', '--dir', '/app/config', '--dir', '/home', '--dir', '/home/secureshop',
    '--dir', '/home/secureshop/.ssh', '--file', '6', '/app/config/.env', '--file', '7', '/home/secureshop/.ssh/id_rsa',
    '--dir', '/owned-source', '--file', '8', '/owned-source/effect-canary',
    '--dir', '/owned-effect', '--bind', effectRoot, '/owned-effect',
    '--hostname', namespaceName(request.operationId), '--setenv', 'PATH', CLEAN_PATH,
    '--setenv', 'HOME', '/work', '--setenv', 'USER', 'policy-render', '--setenv', 'LANG', 'C.UTF-8',
    DEFAULT_INIT, '--render', encoded, marker];
}
function strictProbe(spawnSyncImpl = defaultSpawnSync, runtimeMounts) {
  const result = spawnSyncImpl('bwrap', buildProbeArgv(runtimeMounts), { timeout: 5000, env: { PATH: CLEAN_PATH } });
  return result?.status === 0;
}
function decodeEnvelope(stdout, marker) {
  const text = stdout.toString('utf8');
  const index = text.lastIndexOf(marker);
  if (index < 0) return null;
  try { return JSON.parse(Buffer.from(text.slice(index + marker.length).trim(), 'base64').toString('utf8')); }
  catch { return null; }
}
function observeEffect(root, expected) {
  const filename = path.join(root, 'command-effect');
  try {
    const names = fs.readdirSync(root);
    if (names.length !== 1 || names[0] !== 'command-effect') return Object.freeze({ commandEffectObserved: false });
    const before = fs.lstatSync(filename);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
        || (before.mode & 0o777) !== 0o600 || before.size !== expected.length) return Object.freeze({ commandEffectObserved: false });
    const bytes = fs.readFileSync(filename);
    const after = fs.lstatSync(filename);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size) return Object.freeze({ commandEffectObserved: false });
    return Object.freeze({ commandEffectObserved: crypto.timingSafeEqual(bytes, expected),
      effectSha256: sha256(bytes) });
  } catch (error) {
    if (error?.code === 'ENOENT') return Object.freeze({ commandEffectObserved: false });
    throw error;
  }
}
function cleanupEffectRoot(root) {
  try { fs.chmodSync(root, 0o700); } catch {}
  fs.rmSync(root, { recursive: true, force: true });
}
function createPolicyRenderExecutor({ spawnImpl = defaultSpawn, spawnSyncImpl = defaultSpawnSync,
  readFileSync = fs.readFileSync, existsSync = fs.existsSync, timeoutMs = DEFAULT_TIMEOUT_MS,
  drainGraceMs = DEFAULT_DRAIN_GRACE_MS, supervisorPath = DEFAULT_SUPERVISOR,
  randomBytes = crypto.randomBytes } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) throw new TypeError('Bounded policy render timeout required');
  if (!Number.isInteger(drainGraceMs) || drainGraceMs < 100 || drainGraceMs > 5000
      || typeof supervisorPath !== 'string' || !path.isAbsolute(supervisorPath)) throw new TypeError('Policy render subreaper required');
  const assets = loadCheckedAssets(readFileSync);
  const runtimeMounts = availableRuntimeMounts(existsSync);
  let probed = false;
  function assertStrict() {
    if (!probed) {
      if (!existsSync(DEFAULT_INIT) || !strictProbe(spawnSyncImpl, runtimeMounts)) throw Object.assign(new Error('Strict policy render namespace unavailable'), { code: 'POLICY_RENDER_ISOLATION_UNAVAILABLE' });
      probed = true;
    }
  }
  return Object.freeze({
    isolation: ISOLATION,
    render(rawRequest, { signal } = {}) {
      const execution = rawRequest?.version === 2 ? normalizeRenderExecution(rawRequest) : null;
      const request = execution ? execution.request : normalizeRenderRequest(rawRequest);
      signal?.throwIfAborted();
      if (execution?.mode === 'fixed') return Promise.resolve(createLiteralRenderResult(request));
      assertStrict();
      const marker = `__POLICY_RENDER_${randomBytes(32).toString('hex')}__`;
      const effectCanary = randomBytes(32);
      const effectRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-policy-render-'));
      fs.chmodSync(effectRoot, 0o700);
      const argv = buildRenderArgv(request, marker, runtimeMounts, effectRoot);
      return new Promise((resolve, reject) => {
        let child;
        try { child = spawnImpl(supervisorPath, argv, { detached: false,
          env: { PATH: CLEAN_PATH }, stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe'] }); }
        catch (error) { cleanupEffectRoot(effectRoot); reject(error); return; }
        for (const [index, content] of [[3, Buffer.alloc(0)], [4, assets.compiler], [5, assets.worker],
          [6, SYNTHETIC_ENV], [7, SYNTHETIC_KEY], [8, effectCanary]]) {
          child.stdio?.[index]?.on('error', () => {});
          child.stdio?.[index]?.end(content);
        }
        let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), truncated = false, timedOut = false;
        let settled = false, spawnFailed = false, forced = false, stopping = false, drainTimer = null;
        const append = (current, chunk, maximum) => {
          if (current.length >= maximum) { truncated = true; return current; }
          const next = Buffer.concat([current, Buffer.from(chunk)]);
          if (next.length > maximum) { truncated = true; return next.subarray(0, maximum); }
          return next;
        };
        child.stdout.on('data', chunk => { stdout = append(stdout, chunk, MAX_CAPTURE_BYTES); });
        child.stderr.on('data', chunk => { stderr = append(stderr, chunk, MAX_STDERR_BYTES); });
        const stop = () => {
          if (stopping) return;
          stopping = true;
          try { child.kill('SIGTERM'); } catch {}
          drainTimer = setTimeout(() => { forced = true; try { child.kill('SIGKILL'); } catch {} }, drainGraceMs);
        };
        const abort = () => stop();
        signal?.addEventListener('abort', abort, { once: true });
        if (signal?.aborted) abort();
        const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
        child.once('error', error => {
          spawnFailed = true; stderr = append(stderr, Buffer.from(error.message || 'spawn failed'), MAX_STDERR_BYTES);
        });
        child.once('close', code => {
          if (settled) return; settled = true; clearTimeout(timer); if (drainTimer) clearTimeout(drainTimer); signal?.removeEventListener('abort', abort);
          let result, effect, failure = null;
          try {
            const drained = !spawnFailed && !forced;
            const workerAttested = drained && stdout.length >= INIT_ATTESTATION.length
              && crypto.timingSafeEqual(stdout.subarray(0, INIT_ATTESTATION.length), INIT_ATTESTATION);
            effect = drained ? Object.freeze({ ...observeEffect(effectRoot, effectCanary), workerAttested })
              : Object.freeze({ commandEffectObserved: false, workerAttested: false });
            if (spawnFailed) throw Object.assign(new Error(stderr.toString('utf8') || 'Policy render supervisor failed'), { code: 'POLICY_RENDER_SUPERVISOR_FAILED' });
            if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new DOMException('Aborted', 'AbortError');
            const envelope = decodeEnvelope(stdout, marker);
            let rendered = '';
            try { rendered = Buffer.from(envelope?.renderedBase64 || '', 'base64').toString('utf8'); } catch {}
            const renderedBytes = Buffer.from(rendered, 'utf8');
            const requestSha256 = requestDigest(request);
            const valid = workerAttested && envelope && envelope.version === VERSION && envelope.operationId === request.operationId
              && envelope.requestSha256 === requestSha256 && envelope.isolation === ISOLATION
              && envelope.renderedSha256 === sha256(renderedBytes) && renderedBytes.length <= MAX_RENDERED_BYTES;
            const legacyResult = Object.freeze({ version: VERSION, operationId: request.operationId,
              requestSha256, isolation: ISOLATION,
              rendered: valid ? rendered : '', renderedSha256: valid ? envelope.renderedSha256 : sha256(Buffer.alloc(0)),
              exitCode: Number.isInteger(code) ? code : 1, timedOut, truncated, drained,
              ...(valid ? {} : { error: stderr.toString('utf8').slice(0, 4096) || 'Invalid policy render worker result' }) });
            if (valid && legacyResult.exitCode === 0 && !timedOut && !truncated && drained) validateRenderResult(request, legacyResult);
            result = execution ? Object.freeze({ version: 2, kind: 'isolated_template',
              operationId: request.operationId, requestSha256, executionSha256: renderExecutionDigest(execution),
              rendered: legacyResult.rendered, renderedSha256: legacyResult.renderedSha256,
              isolation: ISOLATION, exitCode: legacyResult.exitCode, timedOut, truncated, drained,
              effectWitness: Object.freeze({ version: 1, workerAttested: effect.workerAttested,
                commandEffectObserved: effect.commandEffectObserved,
                effectSha256: effect.commandEffectObserved ? effect.effectSha256 : null,
                compilerSha256: COMPILER_SHA256, workerSha256: WORKER_SHA256 }),
              ...(valid ? {} : { error: legacyResult.error }) }) : legacyResult;
            if (execution && valid && result.exitCode === 0 && !timedOut && !truncated && drained)
              validateRenderExecutionResult(execution, result);
          } catch (error) { failure = error; }
          try { cleanupEffectRoot(effectRoot); }
          catch (error) { failure = failure ? new AggregateError([failure, error], 'Policy renderer finalization failed') : error; }
          if (failure) reject(failure);
          else { effectWitnesses.set(result, effect); resolve(result); }
        });
      });
    },
  });
}

module.exports = { VERSION, ISOLATION, COMPILER_SHA256, WORKER_SHA256, MAX_RENDERED_BYTES, MAX_CAPTURE_BYTES,
  COMPILER_PATH, WORKER_PATH, DEFAULT_SUPERVISOR, DEFAULT_INIT, checkAssets, buildProbeArgv, buildRenderArgv,
  strictProbe, decodeEnvelope, createPolicyRenderExecutor,
  policyRenderEffectWitnessFor: result => effectWitnesses.get(result) || null };
