'use strict';

// Header estimates only. This never grants artifact integrity, build approval,
// or platform filtering. The caller must own the admitted private relay/VM.
const fs = require('node:fs/promises');
const path = require('node:path');
const closure = require('./ownedMcpDependencyClosure');
const LIMITS = Object.freeze({ requests: 122, milliseconds: 300000, requestMs: 15000,
  headerBytes: 8192, totalHeaderBytes: 122 * 8192, receiptBytes: 128 * 1024 });
const fail = code => Object.assign(Error(code), { code });

function lengthClass(value) {
  if (value === undefined) return 'missing';
  if (value === '0') return 'nonpositive';
  if (!/^[1-9][0-9]*$/.test(value)) return 'invalid-decimal';
  return Number.isSafeInteger(Number(value)) ? 'valid' : 'unsafe-integer';
}
function estimate(response, mode = 'HEAD') {
  if (response.status !== (mode === 'HEAD' ? 200 : 206) || !Array.isArray(response.rawHeaders) || response.rawHeaders.length > 256
    || response.rawHeaders.length % 2 || !Number.isSafeInteger(response.headerBytes)
    || response.headerBytes < 1 || response.headerBytes > LIMITS.headerBytes) throw fail('CENSUS_RESPONSE');
  const fields = new Map(); let bytes = 0;
  for (let i = 0; i < response.rawHeaders.length; i += 2) {
    const key = response.rawHeaders[i], value = response.rawHeaders[i + 1];
    if (typeof key !== 'string' || typeof value !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(key)
      || /[\r\n\0]/.test(value)) throw fail('CENSUS_HEADERS');
    bytes += Buffer.byteLength(key) + Buffer.byteLength(value) + 4;
    const name = key.toLowerCase(); if (fields.has(name)) throw fail('CENSUS_DUPLICATE_HEADER');
    fields.set(name, value);
  }
  if (bytes > response.headerBytes || fields.has('location') || mode === 'HEAD' && fields.has('content-range')
    || fields.has('content-encoding') || fields.has('transfer-encoding')) throw fail('CENSUS_HEADERS');
  const length = fields.get('content-length');
  if (lengthClass(length) !== 'valid') throw Object.assign(fail('CENSUS_LENGTH'), { censusHeaderClass: lengthClass(length) });
  if (mode === 'RANGE_0') {
    const match = /^bytes 0-0\/([1-9][0-9]*)$/.exec(fields.get('content-range') || '');
    if (length !== '1' || !match || !Number.isSafeInteger(Number(match[1]))) throw fail('CENSUS_CONTENT_RANGE');
    return Number(match[1]);
  }
  // This is an estimate, not authorization to enlarge any artifact/body cap.
  return Number(length);
}

async function privateParent(directory) {
  const parent = path.dirname(directory);
  if (!path.isAbsolute(directory) || path.resolve(directory) !== directory || directory === '/'
    || await fs.realpath(parent) !== parent) throw fail('CENSUS_DIRECTORY');
  const stat = await fs.lstat(parent);
  if (!stat.isDirectory() || (stat.mode & 0o777) !== 0o700 || stat.uid !== process.getuid()) throw fail('CENSUS_DIRECTORY');
}
async function record(directory, name, value) {
  const bytes = Buffer.from(JSON.stringify(value)); if (bytes.length > LIMITS.receiptBytes) throw fail('CENSUS_RECEIPT_LIMIT');
  const partial = path.join(directory, name + '.partial'), final = path.join(directory, name);
  const fd = await fs.open(partial, 'wx', 0o400);
  try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
  await fs.link(partial, final); await fs.unlink(partial);
  const parent = await fs.open(directory, 'r'); try { await parent.sync(); } finally { await parent.close(); }
}

async function runSizeCensus({ npmLock, directory, authority, signal, mode = 'HEAD', request = closure.requestViaPrivateRelay,
  now = () => performance.now(), deadline } = {}) {
  if (!['HEAD', 'RANGE_0'].includes(mode)) throw fail('CENSUS_MODE');
  const artifacts = closure._internals.npmArtifacts(npmLock);
  if (artifacts.length !== LIMITS.requests || artifacts.reduce((n, row) => n + row.lockPaths.length, 0) !== 124) throw fail('CENSUS_LOCK_COUNT');
  const started = now(), end = deadline ?? started + LIMITS.milliseconds;
  if (!Number.isFinite(end) || end <= started || end - started > LIMITS.milliseconds) throw fail('CENSUS_DEADLINE');
  await privateParent(directory); await fs.mkdir(directory, { mode: 0o700 });
  const controller = new AbortController(), rows = []; let headerBytes = 0, totalEstimatedBytes = 0, current = null;
  const abort = () => controller.abort(); signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  const timer = setTimeout(abort, end - started);
  const check = () => { if (controller.signal.aborted || now() >= end) throw fail('CENSUS_ABORTED'); };
  try {
    for (const [index, artifact] of artifacts.entries()) {
      current = { index, digest: artifact.digest, stage: 'request', status: null, headerBytes: null }; check();
      const perRequest = new AbortController(), cancel = () => perRequest.abort();
      controller.signal.addEventListener('abort', cancel, { once: true }); if (controller.signal.aborted) cancel();
      const requestTimer = setTimeout(cancel, Math.min(LIMITS.requestMs, end - now())); let response, estimatedBytes, primary, retirementError;
      try {
        response = await request(artifact.urls[0], { authority, signal: perRequest.signal, method: mode === 'HEAD' ? 'HEAD' : 'GET', rangeProbe: mode === 'RANGE_0' }); check();
        current.stage = 'headers'; current.status = Number.isInteger(response.status) && response.status >= 100 && response.status <= 599 ? response.status : null;
        current.headerBytes = Number.isInteger(response.headerBytes) && response.headerBytes >= 0 && response.headerBytes <= LIMITS.headerBytes ? response.headerBytes : null;
        estimatedBytes = estimate(response, mode); current.stage = 'body'; let bodyBytes = 0;
        for await (const chunk of response.body) { bodyBytes += chunk.length; if (bodyBytes > (mode === 'HEAD' ? 0 : 1)) throw fail('CENSUS_BODY'); }
        if (bodyBytes !== (mode === 'HEAD' ? 0 : 1)) throw fail('CENSUS_BODY');
        check();
        if (perRequest.signal.aborted) throw fail('CENSUS_REQUEST_TIMEOUT');
        headerBytes += response.headerBytes;
        if (headerBytes > LIMITS.totalHeaderBytes || !Number.isSafeInteger(totalEstimatedBytes + estimatedBytes)) throw fail('CENSUS_LIMIT');
        totalEstimatedBytes += estimatedBytes;
      } catch (error) { primary = error; }
      let retirementTimer;
      try {
        response?.destroy();
        await Promise.race([response?.closed, new Promise((_resolve, reject) => {
          retirementTimer = setTimeout(() => reject(fail('CENSUS_RETIREMENT_UNPROVEN')), 1000);
        })]);
      } catch (error) { retirementError = error; }
      finally { clearTimeout(retirementTimer); clearTimeout(requestTimer); controller.signal.removeEventListener('abort', cancel); }
      if (retirementError) { const error = new AggregateError([primary, retirementError].filter(Boolean), 'Census transport retirement unproven'); error.retirementUnproven = true; throw error; }
      if (primary) throw primary;
      check(); if (perRequest.signal.aborted) throw fail('CENSUS_REQUEST_TIMEOUT');
      rows.push({ ...artifact, estimatedBytes, headerBytes: response.headerBytes });
    }
    const receipt = { version: 1, kind: mode === 'HEAD' ? 'original-npm-head-size-estimates' : 'original-npm-range-size-estimates', mode, npmLockSha256: closure.NPM_LOCK_SHA256,
      requests: rows.length, lockPaths: 124, headerBytes, totalEstimatedBytes, artifacts: rows,
      controlled: request !== closure.requestViaPrivateRelay,
      packageBodiesDownloaded: mode === 'RANGE_0', packageBodyBytes: mode === 'RANGE_0' ? rows.length : 0,
      artifactBytesVerified: false, metadataAuthenticated: false, buildApproved: false, qualificationComplete: false };
    await record(directory, 'estimates.json', receipt); return receipt;
  } catch (primary) {
    const diagnostic = { version: 1, error: /^[A-Z0-9_]{1,80}$/.test(primary.code || '') ? primary.code : 'CENSUS_FAILED',
      mode, current, headerClass: ['missing', 'nonpositive', 'invalid-decimal', 'unsafe-integer'].includes(primary.censusHeaderClass) ? primary.censusHeaderClass : null,
      completed: rows.length, headerBytes, totalEstimatedBytes, qualificationComplete: false };
    try { primary.censusDiagnostic = diagnostic; } catch { /* Preserve the primary error. */ }
    try { await record(directory, 'failure.json', diagnostic); }
    catch (cleanup) { throw new AggregateError([primary, cleanup], 'Census failed and diagnostic publication failed'); }
    throw primary;
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); controller.abort(); }
}

function validateReceipt(receipt, npmLock, mode = 'HEAD') {
  const rows = closure._internals.npmArtifacts(npmLock);
  if (receipt?.version !== 1 || receipt.kind !== (mode === 'HEAD' ? 'original-npm-head-size-estimates' : 'original-npm-range-size-estimates') || receipt.npmLockSha256 !== closure.NPM_LOCK_SHA256
    || receipt.requests !== 122 || receipt.lockPaths !== 124 || !Array.isArray(receipt.artifacts) || receipt.artifacts.length !== 122
    || typeof receipt.controlled !== 'boolean' || receipt.mode !== mode || !['HEAD', 'RANGE_0'].includes(mode)
    || receipt.packageBodiesDownloaded !== (mode === 'RANGE_0') || receipt.packageBodyBytes !== (mode === 'RANGE_0' ? 122 : 0)
    || ['artifactBytesVerified', 'metadataAuthenticated', 'buildApproved', 'qualificationComplete'].some(key => receipt[key] !== false)) throw fail('CENSUS_RECEIPT');
  let bytes = 0, headers = 0;
  for (const [index, row] of receipt.artifacts.entries()) {
    const { estimatedBytes, headerBytes, ...binding } = row;
    if (JSON.stringify(binding) !== JSON.stringify(rows[index]) || !Number.isSafeInteger(estimatedBytes) || estimatedBytes < 1
      || !Number.isSafeInteger(headerBytes) || headerBytes < 1 || headerBytes > LIMITS.headerBytes) throw fail('CENSUS_RECEIPT');
    bytes += estimatedBytes; headers += headerBytes;
  }
  if (!Number.isSafeInteger(bytes) || bytes !== receipt.totalEstimatedBytes || headers !== receipt.headerBytes
    || headers > LIMITS.totalHeaderBytes) throw fail('CENSUS_RECEIPT');
  return receipt;
}

const COMPLETION = String.raw`attempt=0
while :; do
 running=$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")
 case "$running" in false) break;; true) ;; *) exit 97;; esac
 attempt=$((attempt+1)); [ "$attempt" -lt 1500 ]; sleep .2
done
closure_identity
if [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Status}}' "$cid")" != exited ] || [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.ExitCode}}' "$cid")" != 0 ]; then
 docker --host "unix://$root/fs/docker.sock" logs --tail 64 "$cid" >&2; exit 97
fi
[ -f "$root/fs/closure/ready.json" ]
[ ! -L "$root/fs/closure/ready.json" ]
`;

// The same pinned-base metadata/private-daemon lifecycle is used without any
// build, load, image activation or runtime consumer operation. Only the fixed
// census guest replaces the artifact-acquisition guest and its matching hash.
async function censusPlan(root, runId, mode = 'HEAD') {
  if (!['HEAD', 'RANGE_0'].includes(mode)) throw fail('CENSUS_MODE');
  const adapter = require('./ownedMcpOriginalBuildAdapter'), crypto = require('node:crypto');
  const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
  const base = await adapter.originalBuildPlan(root, runId, { budgetProfile: 'default' }), modules = {}, helperHashes = { ...base.helperHashes };
  for (const name of ['ownedMcpDependencyClosure', 'ownedMcpNpmSizeCensus']) {
    const file = 'tests/postgres/' + name + '.js', bytes = await fs.readFile(path.join(root, file));
    if (bytes.length > 262144) throw fail('CENSUS_SOURCE_LIMIT'); modules[name] = bytes.toString(); helperHashes[file] = hash(bytes);
  }
  const npmLock = await fs.readFile(path.join(root, 'sidecars/sandbox-runner/owned-mcp-registry/package-lock.json'));
  closure._internals.npmArtifacts(npmLock);
  const guestSource = `'use strict';const modules=${JSON.stringify(modules)},cache=new Map();
function load(name){if(!Object.hasOwn(modules,name))throw Error('CENSUS_MODULE');if(cache.has(name))return cache.get(name).exports;const module={exports:{}};cache.set(name,module);new Function('require','module','exports',modules[name])(id=>id.startsWith('node:')?require(id):load(id.replace(/^\\.\\//,'')),module,module.exports);return module.exports;}
(async()=>{const controller=new AbortController(),stop=()=>controller.abort();process.once('SIGTERM',stop);process.once('SIGINT',stop);
try{const deadline=Number(process.env.DVAIA_ARTIFACT_DEADLINE_SECONDS)*1000,port=Number(process.env.DVAIA_ARTIFACT_PROXY_PORT);
const receipt=await load('ownedMcpNpmSizeCensus').runSizeCensus({npmLock:Buffer.from('${npmLock.toString('base64')}','base64'),directory:'/closure/census',mode:'${mode}',authority:{host:'127.0.0.1',port},signal:controller.signal,now:()=>Number(process.hrtime.bigint())/1000000,deadline});
await load('ownedMcpNpmSizeCensus')._internals.record('/closure','ready.json',{binding:${JSON.stringify(base.binding)},receipt});
}finally{process.removeListener('SIGTERM',stop);process.removeListener('SIGINT',stop);}})().catch(error=>{const value=JSON.stringify({error:error.code||'CENSUS_GUEST_FAILED',retirementUnproven:error.retirementUnproven===true,diagnostic:error.censusDiagnostic||null});process.stderr.write((Buffer.byteLength(value)<=4096?value:JSON.stringify({error:'CENSUS_DIAGNOSTIC_LIMIT'}))+'\\n');process.exitCode=1;});`;
  if (Buffer.byteLength(guestSource) > 1024 ** 2) throw fail('CENSUS_SOURCE_LIMIT');
  const commands = {};
  for (const name of ['inventory', 'preflight', 'prepare', 'namespace', 'relayStart', 'daemonStart', 'inspect', 'metadataFetch',
    'startArtifacts', 'retireArtifacts', 'stop', 'evidence', 'retainedExport', 'cleanup']) commands[name] = base.commands[name];
  commands.startArtifacts = adapter._internals.replaceOnce(commands.startArtifacts, base.guestSourceSha256, hash(guestSource));
  const oldPoll = commands.startArtifacts.slice(commands.startArtifacts.indexOf('attempt=0\nuntil [ -f'));
  if (!oldPoll.endsWith('cat "$root/fs/closure/ready.json"\n')) throw fail('CENSUS_POLL_SOURCE_SHAPE');
  commands.startArtifacts = adapter._internals.replaceOnce(commands.startArtifacts, oldPoll, COMPLETION + 'cat "$root/fs/closure/ready.json"\n');
  commands.censusEvidence = adapter._internals.guardFrom(base) + String.raw`
check_mount; check_runtime
/usr/bin/python3 -I -S -B - "$root/fs/closure/census" <<'DVAIA_CENSUS_EVIDENCE'
import os,sys,stat,json,hashlib
root=sys.argv[1];assert os.path.realpath(root)==root
result={}
for name in ('failure.json','estimates.json'):
 file=root+'/'+name
 if not os.path.lexists(file):result[name]=None;continue
 fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o400 and 0<a.st_size<=131072
  data=f.read(131073);b=os.fstat(f.fileno());assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and len(data)==a.st_size
 result[name]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),raw=data.decode('utf-8'))
encoded=json.dumps(result);assert len(encoded.encode())<=1048576
print(encoded)
DVAIA_CENSUS_EVIDENCE
`;
  return { ...base, kind: 'original-npm-head-size-census', mode, helperHashes, commands, guestSource, guestSourceSha256: hash(guestSource),
    censusLimits: LIMITS, buildApproved: false, qualificationComplete: false };
}

async function runOwnedCensus({ root, runId, expectedPlanSha256, mode = 'HEAD', runner, verifyHost } = {}) {
  const adapter = require('./ownedMcpOriginalBuildAdapter'), bounded = require('./ownedMcpBoundedBuild'), metadata = require('./ownedPolicySystemMetadata');
  const { Readable } = require('node:stream'), crypto = require('node:crypto');
  const execute = runner || adapter._internals.createPhaseExecutor(), plan = await censusPlan(root, runId, mode);
  if (!/^[a-f0-9]{64}$/.test(expectedPlanSha256 || '') || adapter.planDigest(plan) !== expectedPlanSha256) throw fail('CENSUS_REVIEWED_PLAN_REQUIRED');
  await adapter._internals.verifyPlanSources(plan); await (verifyHost || bounded._internals.verifyHost)(plan.spec);
  const npmLock = await fs.readFile(path.join(root, 'sidecars/sandbox-runner/owned-mcp-registry/package-lock.json'));
  await fs.mkdir(plan.spec.artifact, { mode: 0o700 });
  const controller = new AbortController(), interruptions = [], handlers = {};
  for (const name of ['SIGTERM', 'SIGINT', 'SIGHUP']) { handlers[name] = () => { interruptions.push(name); controller.abort(); }; process.on(name, handlers[name]); }
  let sequence = 0, journalBytes = 0, intended = false, artifactsIntended = false, retired = false, before, primary, receipt, daemonId;
  const cleanupErrors = [];
  const durable = async (name, value) => {
    const bytes = Buffer.from(JSON.stringify(value)); journalBytes += bytes.length;
    if (bytes.length > 2 * 1024 ** 2 || journalBytes > 16 * 1024 ** 2) throw fail('CENSUS_JOURNAL_LIMIT');
    const fd = await fs.open(path.join(plan.spec.artifact, name), 'wx', 0o600);
    try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
    const parent = await fs.open(plan.spec.artifact, 'r'); try { await parent.sync(); } finally { await parent.close(); }
  };
  const step = async (name, options = {}, cleanup = false) => {
    if (!cleanup) { await adapter._internals.verifyPlanSources(plan); if (controller.signal.aborted) throw fail('CENSUS_INTERRUPTED'); }
    const prefix = String(++sequence).padStart(3, '0') + '-' + name;
    await durable(prefix + '-intent.json', { name, planSha256: expectedPlanSha256 });
    const diagnostic = await fs.open(path.join(plan.spec.artifact, prefix + '-stderr.log'), 'wx', 0o600); let value, error, closeError;
    try {
      if (!cleanup && controller.signal.aborted) throw fail('CENSUS_INTERRUPTED');
      value = await execute(plan, name, { ...options, ...(cleanup ? {} : { signal: controller.signal }), diagnosticSink: async bytes => {
        journalBytes += bytes.length; if (journalBytes > 16 * 1024 ** 2) throw fail('CENSUS_JOURNAL_LIMIT'); await diagnostic.writeFile(bytes);
      } });
      await durable(prefix + '-result.json', { name, output: value });
    } catch (cause) { error = cause; }
    try { try { await diagnostic.sync(); } finally { await diagnostic.close(); } } catch (cause) { closeError = cause; }
    if (error && closeError) throw new AggregateError([error, closeError], 'Census phase and diagnostic retirement failed');
    if (error || closeError) throw error || closeError; return value;
  };
  try {
    try {
      before = bounded._internals.checkInventory(await step('inventory')); await step('preflight'); intended = true;
      for (const name of ['prepare', 'namespace', 'relayStart', 'daemonStart']) await step(name);
      daemonId = bounded._internals.checkDaemon(JSON.parse(await step('inspect')), plan.spec);
      const raw = await step('metadataFetch', { input: Readable.from([plan.metadataGuestSource]) });
      const envelope = metadata.validateResultEnvelope(raw, plan.binding);
      if (envelope.version !== 3 || !envelope.ok) throw fail('CENSUS_METADATA_FAILED');
      await durable('metadata-result.json', envelope);
      if (bounded._internals.checkDaemon(JSON.parse(await step('inspect')), plan.spec) !== daemonId) throw fail('CENSUS_DAEMON_CHANGED');
      artifactsIntended = true;
      const packet = JSON.parse(await step('startArtifacts', { input: Readable.from([plan.guestSource]) }));
      if (bounded._internals.checkDaemon(JSON.parse(await step('inspect')), plan.spec) !== daemonId) throw fail('CENSUS_DAEMON_CHANGED');
      if (JSON.stringify(packet.binding) !== JSON.stringify(plan.binding)) throw fail('CENSUS_BINDING');
      receipt = validateReceipt(packet.receipt, npmLock, mode);
      if (!runner && receipt.controlled) throw fail('CENSUS_CONTROLLED_RECEIPT');
      await durable('header-estimates.json', packet);
    } catch (error) { primary = error; }
    if (artifactsIntended) try { retired = (await step('retireArtifacts', {}, true)).trim() === 'absent'; if (!retired) throw fail('CENSUS_CONTAINER_RETIREMENT'); }
    catch (error) { cleanupErrors.push(error.code || error.message); }
    if (artifactsIntended) try { await durable('census-evidence.json', JSON.parse(await step('censusEvidence', {}, true))); }
    catch (error) { cleanupErrors.push(error.code || error.message); }
    if (intended && (!artifactsIntended || retired)) {
      try { await step('stop', {}, true); } catch (error) { cleanupErrors.push(error.code || error.message); }
      try { await durable('retirement-evidence.json', JSON.parse(await step('evidence', {}, true))); } catch (error) { cleanupErrors.push(error.code || error.message); }
      try {
        const fd = await fs.open(path.join(plan.spec.artifact, 'metadata-retained.tar'), 'wx', 0o600), hash = crypto.createHash('sha256'); let bytes = 0;
        try { await step('retainedExport', { sink: async chunk => {
          if (!Buffer.isBuffer(chunk) || bytes + chunk.length > 145 * 1024 ** 2) throw fail('CENSUS_ARCHIVE_LIMIT'); bytes += chunk.length; hash.update(chunk); await fd.writeFile(chunk);
        } }, true); await fd.sync(); } finally { await fd.close(); }
        if (!bytes) throw fail('CENSUS_ARCHIVE_EMPTY'); await durable('metadata-archive.json', { bytes, sha256: hash.digest('hex') });
      } catch (error) { cleanupErrors.push(error.code || error.message); }
      if (!cleanupErrors.length) try { if ((await step('cleanup', {}, true)).trim() !== 'absent') throw fail('CENSUS_CLEANUP'); } catch (error) { cleanupErrors.push(error.code || error.message); }
    }
    try { if (before !== undefined && bounded._internals.checkInventory(await step('inventory', {}, true)) !== before) throw fail('CENSUS_SHARED_STATE_CHANGED'); }
    catch (error) { cleanupErrors.push(error.code || error.message); }
    if (interruptions.length && !primary) primary = fail('CENSUS_INTERRUPTED');
    const result = { version: 1, runId, mode, planSha256: expectedPlanSha256, daemonId: daemonId || null, controlled: Boolean(runner), cleanupVerified: cleanupErrors.length === 0,
      error: primary?.code || primary?.message || null, cleanupErrors, interruptions, buildApproved: false, qualificationComplete: false };
    await durable('result.json', result);
    if (interruptions.length && !primary) { primary = fail('CENSUS_INTERRUPTED'); await durable('terminal-interruption.json', { error: primary.code, interruptions }); }
    if (primary || cleanupErrors.length) throw new AggregateError([primary, ...cleanupErrors.map(fail)].filter(Boolean), 'Owned census failed; retained journal is authoritative');
    return { receipt, result, artifact: plan.spec.artifact };
  } finally { for (const [name, handler] of Object.entries(handlers)) process.removeListener(name, handler); }
}

module.exports = { LIMITS, runSizeCensus, validateReceipt, censusPlan, runOwnedCensus, _internals: { estimate, lengthClass, record, COMPLETION } };
