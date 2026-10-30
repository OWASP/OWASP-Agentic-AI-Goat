'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn: defaultSpawn, spawnSync: defaultSpawnSync } = require('node:child_process');
const strict = require('./strict-helpers');
const { VERSION, ISOLATION, digest, normalizeListingTemplateExecution,
  listingTemplateExecutionDigest, validateListingTemplateExecutionResult }
  = require('../../../server/services/secureshopListingTemplateExecutorContract');

const WORKER_PATH = path.join(__dirname, 'worker.js');
const CONTRACT_PATH = path.join(__dirname, 'secureshopListingTemplateExecutorContract.js');
const WORKER_SHA256 = '635ab2798d83c0a504a7880af06eb8939a1701c78da2aaad1532d3c44e2ba2fe';
const CONTRACT_SHA256 = 'a892c1dc22550a1351d5b9292cf98fcbe4365f47a3788a7cff05d3c7c7597aaa';
const INIT_ATTESTATION = Buffer.from('listing-template-init-v1 uid=10001 gid=10001 caps=zero bounding=zero ambient=zero nnp=1\n');
const CLEAN_PATH = strict.CLEAN_PATH;
const SYNTHETIC_ENV = 'SECURESHOP_LISTING_TEMPLATE_FIXTURE=owned-template\n';
const SYNTHETIC_KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nSECURESHOP-OWNED-TEMPLATE-FIXTURE\n-----END OPENSSH PRIVATE KEY-----\n';
const witnesses = new WeakMap();

function checkedAssets(readFileSync = fs.readFileSync) {
  const compiler = strict.checkedCompiler(readFileSync);
  const worker = readFileSync(WORKER_PATH);
  const contract = readFileSync(CONTRACT_PATH);
  if (digest(worker) !== WORKER_SHA256
      || digest(contract) !== CONTRACT_SHA256) throw Object.assign(new Error('Listing template assets unavailable'), { code: 'LISTING_TEMPLATE_ASSET_INVALID' });
  return { compiler, worker, contract };
}
function buildListingTemplateArgv(raw, marker, mounts = strict.runtimeMounts(), effectRoot = '/tmp/owasp-ai-goat-listing-template-effect') {
  const request = normalizeListingTemplateExecution(raw);
  const encoded = Buffer.from(JSON.stringify({ ...request, requestSha256: listingTemplateExecutionDigest(request) })).toString('base64');
  if (encoded.length > 131072) throw new TypeError('Listing template request exceeds namespace limit');
  return [...strict.namespace, '--die-with-parent', '--new-session',
    '--clearenv', ...mounts.flatMap(entry => ['--ro-bind', entry, entry]),
    '--tmpfs', '/usr/local/libexec', '--ro-bind', strict.DEFAULT_INIT, strict.DEFAULT_INIT,
    '--dev', '/dev', '--dir', '/proc', '--tmpfs', '/tmp', '--tmpfs', '/work', '--chdir', '/work',
    '--dir', '/opt', '--dir', '/opt/listing-template', '--file', '4', '/opt/listing-template/nunjucks-3.2.4.js',
    '--file', '5', '/opt/listing-template/worker.js',
    '--dir', '/server', '--dir', '/server/services', '--file', '9', '/server/services/secureshopListingTemplateExecutorContract.js',
    '--dir', '/app', '--dir', '/app/config', '--dir', '/home', '--dir', '/home/secureshop',
    '--dir', '/home/secureshop/.ssh', '--file', '6', '/app/config/.env', '--file', '7', '/home/secureshop/.ssh/id_rsa',
    '--dir', '/owned-source', '--file', '8', '/owned-source/effect-canary',
    '--dir', '/owned-effect', '--bind', effectRoot, '/owned-effect',
    '--hostname', `listing-${digest(request.operationId).slice(0, 20)}`, '--setenv', 'PATH', CLEAN_PATH,
    '--setenv', 'HOME', '/work', '--setenv', 'USER', 'listing-template', '--setenv', 'LANG', 'C.UTF-8',
    strict.DEFAULT_INIT, '--render', encoded, marker];
}
function createListingTemplateExecutor({ spawnImpl = defaultSpawn, spawnSyncImpl = defaultSpawnSync,
  readFileSync = fs.readFileSync, existsSync = fs.existsSync, randomBytes = crypto.randomBytes,
  observeEffect = strict.observeEffect, cleanupEffectRoot = strict.cleanupEffectRoot,
  timeoutMs = 1500, drainGraceMs = 1000, supervisorPath = strict.DEFAULT_SUPERVISOR } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000
      || !Number.isInteger(drainGraceMs) || drainGraceMs < 100 || drainGraceMs > 5000
      || typeof supervisorPath !== 'string' || !path.isAbsolute(supervisorPath)) throw new TypeError('Bounded listing template executor required');
  const assets = checkedAssets(readFileSync);
  const mounts = strict.runtimeMounts(existsSync);
  let probed = false;
  const ensureStrict = () => {
    if (!probed) {
      if (!existsSync(strict.DEFAULT_INIT) || !strict.strictProbe(spawnSyncImpl, mounts)) throw Object.assign(new Error('Strict template namespace unavailable'), { code: 'LISTING_TEMPLATE_ISOLATION_UNAVAILABLE' });
      probed = true;
    }
  };
  return Object.freeze({
    isolation: ISOLATION,
    execute(raw, { signal } = {}) {
      const request = normalizeListingTemplateExecution(raw);
      signal?.throwIfAborted();
      ensureStrict();
      const marker = `__LISTING_TEMPLATE_${randomBytes(32).toString('hex')}__`;
      const canary = randomBytes(32);
      const effectRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-listing-template-'));
      fs.chmodSync(effectRoot, 0o700);
      const argv = buildListingTemplateArgv(request, marker, mounts, effectRoot);
      return new Promise((resolve, reject) => {
        let child;
        try { child = spawnImpl(supervisorPath, argv, { detached: false, env: { PATH: CLEAN_PATH },
          stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe'] }); }
        catch (error) { try { cleanupEffectRoot(effectRoot); } catch {} reject(error); return; }
        for (const [index, content] of [[3, Buffer.alloc(0)], [4, assets.compiler], [5, assets.worker],
          [6, SYNTHETIC_ENV], [7, SYNTHETIC_KEY], [8, canary], [9, assets.contract]]) {
          child.stdio?.[index]?.on('error', () => {});
          child.stdio?.[index]?.end(content);
        }
        let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), truncated = false;
        let timedOut = false, failed = false, forced = false, stopping = false, settled = false, drainTimer;
        const append = (previous, chunk, maximum) => {
          const next = Buffer.concat([previous, Buffer.from(chunk)]);
          if (next.length > maximum) { truncated = true; return next.subarray(0, maximum); }
          return next;
        };
        child.stdout.on('data', chunk => { stdout = append(stdout, chunk, 96 * 1024); });
        child.stderr.on('data', chunk => { stderr = append(stderr, chunk, 16 * 1024); });
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
        child.once('error', () => { failed = true; });
        child.once('close', code => {
          if (settled) return; settled = true; clearTimeout(timer); clearTimeout(drainTimer); signal?.removeEventListener('abort', abort);
          const drained = !failed && !forced;
          const workerAttested = drained && stdout.length >= INIT_ATTESTATION.length
            && crypto.timingSafeEqual(stdout.subarray(0, INIT_ATTESTATION.length), INIT_ATTESTATION);
          let effect, effectError = false;
          try { effect = drained ? observeEffect(effectRoot, canary) : { commandEffectObserved: false }; }
          catch { effectError = true; }
          try { cleanupEffectRoot(effectRoot); }
          catch { effectError = true; }
          if (effectError) { reject(Object.assign(new Error('Listing template effect unavailable'), { code: 'LISTING_TEMPLATE_EFFECT_UNAVAILABLE' })); return; }
          if (failed) { reject(Object.assign(new Error('Listing template supervisor unavailable'), { code: 'LISTING_TEMPLATE_SUPERVISOR_FAILED' })); return; }
          if (signal?.aborted) { reject(signal.reason instanceof Error ? signal.reason : new DOMException('Aborted', 'AbortError')); return; }
          const envelope = strict.decodeEnvelope(stdout, marker);
          let rendered = '';
          try { rendered = Buffer.from(envelope?.renderedBase64 || '', 'base64').toString('utf8'); } catch {}
          const requestSha256 = listingTemplateExecutionDigest(request);
          const valid = workerAttested && envelope?.version === VERSION && envelope.operationId === request.operationId
            && envelope.productId === request.productId && envelope.requestSha256 === requestSha256
            && envelope.sourceSha256 === request.sourceSha256 && envelope.isolation === ISOLATION
            && envelope.renderedSha256 === digest(Buffer.from(rendered, 'utf8'))
            && Buffer.byteLength(rendered, 'utf8') <= 65536;
          if (code === 0 && !valid) { reject(Object.assign(new Error('Listing template execution unavailable'), { code: 'LISTING_TEMPLATE_EXECUTION_INVALID' })); return; }
          const success = valid && code === 0 && !timedOut && !truncated && drained;
          const result = Object.freeze({ version: VERSION, operationId: request.operationId,
            productId: request.productId, requestSha256, sourceSha256: request.sourceSha256, isolation: ISOLATION,
            rendered: success ? rendered : '', renderedSha256: digest(Buffer.from(success ? rendered : '', 'utf8')),
            exitCode: Number.isInteger(code) ? code : 1, timedOut, truncated, drained,
            workerAttested, commandEffectObserved: Boolean(success && effect.commandEffectObserved),
            effectSha256: success && effect.commandEffectObserved ? effect.effectSha256 : null });
          try {
            const validated = validateListingTemplateExecutionResult(request, result);
            witnesses.set(validated, Object.freeze({ workerAttested, commandEffectObserved: validated.commandEffectObserved,
              effectSha256: validated.effectSha256 }));
            resolve(validated);
          }
          catch { reject(Object.assign(new Error('Listing template execution unavailable'), { code: 'LISTING_TEMPLATE_EXECUTION_INVALID' })); }
        });
      });
    },
  });
}

module.exports = { WORKER_SHA256, CONTRACT_SHA256, WORKER_PATH, CONTRACT_PATH, checkedAssets,
  buildListingTemplateArgv, createListingTemplateExecutor,
  listingTemplateEffectWitnessFor: result => witnesses.get(result) || null };
