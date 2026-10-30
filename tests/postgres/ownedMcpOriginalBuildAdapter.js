'use strict';

// Explicit original-image qualification adapter. Nothing runs on import.
// All build effects stay in the reviewed private daemon/netns/6-GiB mount.
// The original twenty-file context and Dockerfile are never rewritten.
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { spawn } = require('node:child_process');
const { Readable } = require('node:stream');
const { performance } = require('node:perf_hooks');
const bounded = require('./ownedMcpBoundedBuild');
const closure = require('./ownedMcpDependencyClosure');
const source = require('../../scripts/install/secureshop-owned-mcp-registry-setup')._internals;
const manifest = require('../../scripts/install/manifests/secureshop-owned-mcp-registry-build.json');
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const fail = code => Object.assign(new Error(code), { code });
const joinedConsumerFailures = new WeakSet(), failedRetirements = new WeakMap();
const LISTINGS_PRIVATE_ENABLED = true;
async function captureListings(root) {
  const planner=require('../../scripts/install/secureshop-owned-listings');
  const before=planner.sourceManifest(root),files=[];let total=0;
  for(const [name,digest] of Object.entries(before.files)){
    const file=path.join(root,name);
    if(await fs.realpath(file)!==file)throw fail('LISTINGS_BUILD_SOURCE');
    const fd=await fs.open(file,require('node:fs').constants.O_RDONLY|require('node:fs').constants.O_NOFOLLOW);
    try{
      const a=await fd.stat();if(!a.isFile()||a.nlink!==1||a.size>1024**2)throw fail('LISTINGS_BUILD_SOURCE');
      const bytes=await fd.readFile(),b=await fd.stat();total+=bytes.length;
      if(total>8*1024**2||sha(bytes)!==digest||['dev','ino','size','mtimeMs','ctimeMs'].some(k=>a[k]!==b[k]))throw fail('LISTINGS_BUILD_SOURCE');
      files.push({name,bytes});
    }finally{await fd.close();}
  }
  if(JSON.stringify(planner.sourceManifest(root))!==JSON.stringify(before))throw fail('LISTINGS_BUILD_SOURCE');
  const lock=files.find(row=>row.name==='sidecars/sandbox-runner/owned-mcp-registry/package-lock.json');
  if(!lock||sha(lock.bytes)!==closure.NPM_LOCK_SHA256)throw fail('LISTINGS_BUILD_LOCK');
  const qualified=require('../../scripts/install/secureshop-owned-listings-qualified-candidate').qualifiedPackage({root,architecture:'arm64'});
  if(qualified.qualifiedSourceSha256!==before.sha256)throw fail('LISTINGS_BUILD_QUALIFICATION');
  return {digest:before.sha256,runtimeDigest:qualified.runtimeDigest,files,dockerfile:'sidecars/sandbox-runner/owned-listings/Dockerfile.candidate',
    entrypoint:['node','sidecars/sandbox-runner/owned-listings/manager-entry.js'],user:'10001:10001'};
}
function sourceBindingDigest(plan) {
  return sha(JSON.stringify({ buildSources: plan.buildSources, helperHashes: plan.helperHashes,
    packageDigest: plan.packageDigest, guestSourceSha256: plan.guestSourceSha256 }));
}
// One-shot, same-process failure authority. Disk bytes are a required join, not
// an authority source. A copied error/receipt, controlled runner, or late claim
// cannot mint this proof.
async function claimFailedRetirement(error, callbackFailure, { root, runId, expectedPlanSha256, outerDeadline }) {
  const row = failedRetirements.get(error);
  if (!row || row.primary !== callbackFailure || root !== row.plan.spec.root || runId !== row.plan.spec.runId
    || expectedPlanSha256 !== row.planSha256 || outerDeadline !== row.outerDeadline || !Number.isFinite(outerDeadline) || performance.now() >= outerDeadline)
    throw fail('ORIGINAL_BUILD_FAILED_RETIREMENT_REQUIRED');
  failedRetirements.delete(error);
  await verifyPlanSources(row.plan);
  const file = path.join(row.plan.spec.artifact, 'result.json');
  if (await fs.realpath(row.plan.spec.artifact) !== row.plan.spec.artifact) throw fail('ORIGINAL_BUILD_FAILED_RETIREMENT_PATH');
  const directory = await fs.lstat(row.plan.spec.artifact);
  if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== process.getuid()
    || (directory.mode & 0o777) !== 0o700) throw fail('ORIGINAL_BUILD_FAILED_RETIREMENT_PATH');
  const fd = await fs.open(file, require('node:fs').constants.O_RDONLY | require('node:fs').constants.O_NOFOLLOW);
  let bytes;
  try {
    const stat = await fd.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600
      || stat.size !== row.bytes || stat.size > 1024 * 1024) throw fail('ORIGINAL_BUILD_FAILED_RETIREMENT_FILE');
    const buffer = Buffer.alloc(row.bytes + 1); let offset = 0;
    while (offset < buffer.length) {
      const read = await fd.read(buffer, offset, buffer.length - offset, offset);
      if (!read.bytesRead) break;
      offset += read.bytesRead;
    }
    bytes = buffer.subarray(0, offset);
  } finally { await fd.close(); }
  if (sha(bytes) !== row.sha256 || performance.now() >= outerDeadline) throw fail('ORIGINAL_BUILD_FAILED_RETIREMENT_CHANGED');
  return Object.freeze({ version: 1, runId, planSha256: expectedPlanSha256, artifact: row.plan.spec.artifact,
    cleanupVerified: true, consumerCleanupVerified: true, sharedStatePreserved: true,
    producerReceipt: Object.freeze({ file: 'result.json', sha256: row.sha256, bytes: row.bytes }),
    sourceSha256: row.sourceSha256 });
}
const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
// Census 66f98b625e5bc3f56ccbe2ed39e3f2ef: all 122 URLs / 124 paths,
// 119,192,855 estimated body bytes; receipt SHA256
// 990e052848150063b7ac799eb053a0bfd1f8286116800a6c3f8a09ed6a23f061.
// 114 MiB stored + 2 MiB wire overhead; aggregate budgets stay unchanged.
const NPM_WIRE_BYTES = 116 * 1024 ** 2;
// A registry phase retains the existing 150 s remote timeout, 30 s local
// watchdog allowance, 10 s log join and 170 s remote-uncertainty wait.
// Retirement can join one interrupted work phase and two exact cleanup phases.
const REGISTRY_PHASE_JOIN_MS = (150 + 30 + 10 + 170) * 1000;
const REGISTRY_RETIREMENT_MS = 3 * REGISTRY_PHASE_JOIN_MS;
const ORIGINAL_SERVICE_ENABLED = true; // Reviewed composition; exact fresh plan/host admission remains mandatory.
const V39_PRIVATE_ENABLED = true; // Exact fresh plan, private owner IPC and retirement remain mandatory.
const Q05_PRIVATE_ENABLED = true; // Separate original handoff admission is not live until owner review.
// Lima/SSH shell escaping can multiply a quote-heavy script's argv size even
// when its raw bytes are below Linux MAX_ARG_STRLEN. Only the transport changes:
// the verified original bytes execute with the same shell arguments and stdin.
const PHASE_TRANSPORT_LIMITS = Object.freeze({ decodedBytes: 131071, encodedBytes: 32768, limaScriptBytes: 65535 });
// Pinned Lima 27bc4c4b shell.go312-334/428-435 and shellescape v1.6.0:
// Quote each guest argv, join, Quote the joined command for login bash, then
// transport the whole script as one SSH argument. Include its terminating NUL.
const limaQuote = value => /^[A-Za-z0-9_@%+=:,./-]+$/.test(value) ? value : "'" + value.replace(/'/g, "'\"'\"'") + "'";
function limaArgvEnvelope(argv) {
  if (!Array.isArray(argv) || !argv.length || argv.some(value => typeof value !== 'string' || value.includes('\0')))
    throw fail('ORIGINAL_BUILD_TRANSPORT_ARG');
  const joined = argv.map(limaQuote).join(' ');
  const script = 'cd / || exit 1 ; exec /bin/bash -l -c ' + limaQuote(joined);
  const scriptBytes = Buffer.byteLength(script) + 1, joinedBytes = Buffer.byteLength(joined) + 1;
  if (scriptBytes > PHASE_TRANSPORT_LIMITS.limaScriptBytes || joinedBytes > PHASE_TRANSPORT_LIMITS.limaScriptBytes)
    throw fail('ORIGINAL_BUILD_TRANSPORT_ARG_LIMIT');
  return Object.freeze({ scriptBytes, joinedBytes });
}
const PHASE_DECODER = String.raw`import sys,base64,zlib,hashlib,os,re
assert len(sys.argv) in (6,7) and 0<len(sys.argv[1])<=32768
assert re.fullmatch('[0-9a-f]{64}',sys.argv[2]) and sys.argv[3]=='owned-original-build'
assert re.fullmatch('[0-9a-f]{32}',sys.argv[5]) and sys.argv[4]=='/var/tmp/owasp-ai-goat-v23-build-'+sys.argv[5]
if len(sys.argv)==7:assert re.fullmatch('sha256:[0-9a-f]{64}',sys.argv[6])
packed=base64.b64decode(sys.argv[1],validate=True)
d=zlib.decompressobj(31);b=d.decompress(packed,131072)
assert 0<len(b)<=131071 and d.eof and not d.unused_data and not d.unconsumed_tail
assert hashlib.sha256(b).hexdigest()==sys.argv[2] and b'\0' not in b
script=b.decode('utf-8')
os.execv('/bin/sh',['/bin/sh','-c',script,*sys.argv[3:]])
`;
const PHASE_TRANSPORT = Object.freeze({ version: 1, kind: 'gzip-sha256-shell-exec-v1',
  ...PHASE_TRANSPORT_LIMITS, decoderSha256: sha(PHASE_DECODER) });
function phaseTransport(script, ownerTag = 'owned-original-build') {
  if (ownerTag !== 'owned-original-build' && ownerTag !== 'owned-system-build')
    throw fail('ORIGINAL_BUILD_TRANSPORT_OWNER');
  if (typeof script !== 'string' || !script || script.includes('\0')) throw fail('ORIGINAL_BUILD_TRANSPORT_SCRIPT');
  const bytes = Buffer.from(script, 'utf8');
  if (bytes.toString('utf8') !== script || bytes.length > PHASE_TRANSPORT_LIMITS.decodedBytes)
    throw fail('ORIGINAL_BUILD_TRANSPORT_SCRIPT');
  const encoded = zlib.gzipSync(bytes).toString('base64');
  if (encoded.length > PHASE_TRANSPORT_LIMITS.encodedBytes) throw fail('ORIGINAL_BUILD_TRANSPORT_ENCODED_LIMIT');
  const scriptSha256 = sha(bytes);
  const decoder = ownerTag === 'owned-original-build' ? PHASE_DECODER
    : replaceOnce(PHASE_DECODER, "sys.argv[3]=='owned-original-build'", "sys.argv[3]=='owned-system-build'");
  const command = '/usr/bin/python3 -I -S -B -c ' + quote(decoder) + ' ' + quote(encoded)
    + ' ' + quote(scriptSha256) + ' "$0" "$@"';
  const commandEnvelopeBytes = limaArgvEnvelope([command]).scriptBytes;
  return Object.freeze({ command, scriptSha256, decodedBytes: bytes.length, encodedBytes: encoded.length, commandEnvelopeBytes });
}
function replaceOnce(text, before, after) {
  if (typeof text !== 'string' || text.split(before).length !== 2) throw fail('ORIGINAL_BUILD_SOURCE_SHAPE');
  return text.replace(before, after);
}
function derivedRelaySource(original, budgetProfile = 'default') {
  closure.acquisitionLimits(budgetProfile);
  const npmWireBytes = budgetProfile === closure.ORIGINAL_BUILD_PROFILE ? NPM_WIRE_BYTES : closure.LIMITS.npm;
  const match = /^CHILDREN=json\.loads\((.*)\)$/m.exec(original);
  const hosts = /^HOSTS=json\.loads\((.*)\)$/m.exec(original);
  if (!match || !hosts) throw fail('ORIGINAL_BUILD_RELAY_SHAPE');
  const children = JSON.parse(JSON.parse(match[1]));
  if (Object.keys(children).sort().join(',') !== 'adapter,connector') throw fail('ORIGINAL_BUILD_RELAY_SHAPE');
  for (const mode of ['connector', 'adapter']) {
    children[mode] = replaceOnce(children[mode], "if self.connections>=32: raise Denied('connections')", "if self.connections>=192: raise Denied('connections')");
    children[mode] = replaceOnce(children[mode], "'deb.debian.org':138412032}", "'deb.debian.org':138412032,'registry.npmjs.org':" + npmWireBytes + "}");
    if (!children[mode].includes('TOTAL=273678336') || !children[mode].includes('threading.BoundedSemaphore(4)')) throw fail('ORIGINAL_BUILD_RELAY_BUDGET');
    children[mode] = children[mode].replaceAll('metadata-idle-barrier-v4', 'v23-artifact-acquisition-v1');
  }
  const names = JSON.parse(JSON.parse(hosts[1]));
  if (names.includes('registry.npmjs.org')) throw fail('ORIGINAL_BUILD_RELAY_SHAPE');
  names.push('registry.npmjs.org');
  return replaceOnce(replaceOnce(original, match[0], `CHILDREN=json.loads(${JSON.stringify(JSON.stringify(children))})`),
    hosts[0], `HOSTS=json.loads(${JSON.stringify(JSON.stringify(names))})`).replaceAll('metadata-idle-barrier-v4', 'v23-artifact-acquisition-v1');
}

// One lifetime for failure notification and owner-requested retirement. The
// first observation is persisted before automatic close; a signal racing a
// failure shares the same write and join. No callback is awaited by a reader.
function createReplayFinalizer(service, publish, binding, report) {
  let firstWrite, finishing, expired = false;
  const persistFirst = () => {
    const first = service.failureRecord();
    return first ? firstWrite ||= publish('replay-failure.json', JSON.stringify({ binding, ...first })) : Promise.resolve();
  };
  const finish = () => finishing ||= (async () => {
    let timer;
    const publicationErrors = [];
    const remember = code => { if (!publicationErrors.includes(code)) publicationErrors.push(code); };
    const preserve = async () => { try { await persistFirst(); } catch { remember('ORIGINAL_BUILD_REPLAY_FAILURE_PUBLICATION'); } };
    const work = (async () => {
      await preserve();
      let result;
      try { result = await service.close(); }
      catch { result = { ...service.state(), firstFailure: service.failureRecord(), closed: false, absenceVerified: false }; remember('ORIGINAL_BUILD_REPLAY_CLOSE'); }
      await preserve();
      if (expired) return;
      const terminal = { version: 1, binding, ...result, publicationErrors: [...publicationErrors], finalizerComplete: true };
      try { await publish('replay-terminal.json', JSON.stringify(terminal)); }
      catch { remember('ORIGINAL_BUILD_REPLAY_TERMINAL_PUBLICATION'); }
      return { ...terminal, publicationErrors: [...publicationErrors], absenceVerified: result.absenceVerified === true && !publicationErrors.length };
    })();
    const result = await Promise.race([work, new Promise(resolve => { timer = setTimeout(() => {
      expired = true;
      resolve({ ...service.state(), firstFailure: service.failureRecord(), closed: false, absenceVerified: false,
        finalizerComplete: false, publicationErrors: ['ORIGINAL_BUILD_REPLAY_FINALIZER_TIMEOUT'] });
    }, 5000); })]);
    clearTimeout(timer); report(result); return result;
  })();
  // Registered synchronously before listen. Promise reactions run outside the
  // failing request, so close() cannot deadlock waiting for that request.
  service.firstFailure.then(() => { persistFirst().catch(() => {}); return finish(); }).catch(() => {});
  return finish;
}

// Runs in the pinned base, not on the host. load() admits only the exact
// repository modules embedded by guestSource; no npm install or source clone.
async function guestMain(load, binding, npmLockBase64, budgetProfile) {
  const fs = require('node:fs/promises'), nativeFs = require('node:fs'), crypto = require('node:crypto');
  const { spawn } = require('node:child_process'), { Readable } = require('node:stream');
  const closure = load('ownedMcpDependencyClosure'), replay = load('ownedMcpArtifactReplay'), metadata = load('ownedPolicySystemMetadata');
  const hash = data => crypto.createHash('sha256').update(data).digest('hex');
  const error = code => Object.assign(new Error(code), { code });
  const now = () => Number(process.hrtime.bigint()) / 1000000;
  const deadline = Number(process.env.OWASP_AI_GOAT_ARTIFACT_DEADLINE_SECONDS) * 1000;
  const port = Number(process.env.OWASP_AI_GOAT_ARTIFACT_PROXY_PORT);
  if (!Number.isFinite(deadline) || deadline <= now() || deadline - now() > 300000
    || !Number.isInteger(port) || port < 1 || port > 65535) throw error('ORIGINAL_BUILD_GUEST_AUTHORITY');
  const controller = new AbortController(), children = new Set(); let commandBytes = 0, expandedBytes = 0;
  const timer = setTimeout(() => controller.abort(), deadline - now());
  const stop = () => { controller.abort(); for (const child of children) try { process.kill(-child.pid, 'SIGKILL'); } catch (e) { if (e.code !== 'ESRCH') throw e; } };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  let offline, frozen, finish, readyPublished = false, guestStage = 'retained-input', authenticationWitness = null;
  try {
  async function read(file, maximum, mode = 0o444) {
    if (await fs.realpath(file) !== file) throw error('ORIGINAL_BUILD_RETAINED_PATH');
    const fd = await fs.open(file, nativeFs.constants.O_RDONLY | nativeFs.constants.O_NOFOLLOW);
    try { const before = await fd.stat();
      if (!before.isFile() || before.nlink !== 1 || before.uid !== 0 || (before.mode & 0o777) !== mode || before.size < 1 || before.size > maximum) throw error('ORIGINAL_BUILD_RETAINED_FILE');
      const bytes = await fd.readFile(), after = await fd.stat();
      if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw error('ORIGINAL_BUILD_RETAINED_CHANGED');
      return bytes;
    } finally { await fd.close(); }
  }
  const raw = await read('/metadata-retained/result.json', 1024 ** 2);
  const envelope = metadata.validateResultEnvelope(raw.toString(), binding);
  const candidate = envelope.candidate, retained = metadata.validateRetainedMetadata(candidate, binding);
  const retainedBytes = await read('/metadata-retained/manifest.json', 1024 ** 2);
  if (JSON.stringify(JSON.parse(retainedBytes)) !== JSON.stringify(retained)) throw error('ORIGINAL_BUILD_RETAINED_MANIFEST');
  const byUrl = new Map();
  for (const row of retained.objects) {
    const bytes = await read('/metadata-retained/' + row.file, 32 * 1024 ** 2);
    if (bytes.length !== row.bytes || hash(bytes) !== row.sha256) throw error('ORIGINAL_BUILD_RETAINED_INTEGRITY');
    if (row.kind === 'upstream') byUrl.set(row.url, row);
  }
  const metadataRead = async url => {
    const row = byUrl.get(url); if (!row) throw error('ORIGINAL_BUILD_UNLISTED_METADATA');
    const bytes = await read('/metadata-retained/' + row.file, 32 * 1024 ** 2);
    if (bytes.length !== row.bytes || hash(bytes) !== row.sha256) throw error('ORIGINAL_BUILD_RETAINED_INTEGRITY');
    return { bytes: bytes.length, sha256: row.sha256, stream: Readable.from([bytes]) };
  };
  if (hash(await fs.readFile(candidate.keyringPath)) !== candidate.keyringSha256
    || hash(await fs.readFile('/var/lib/dpkg/status')) !== candidate.installedStatusSha256) throw error('ORIGINAL_BUILD_BASE_WITNESS');
  for (const entry of envelope.sourceSnapshot.files) {
    const bytes = await fs.readFile(entry.path);
    if (hash(bytes) !== entry.sha256 || bytes.length !== entry.bytes) throw error('ORIGINAL_BUILD_BASE_SOURCES');
  }
  guestStage = 'npm-policy-source';
  const npmSourceWitness = await replay.verifyNpmUpdateSources(file => read(file, 131072, 0o644));
  for (const name of ['/metadata/sources', '/metadata/lists/partial', '/metadata/cache/archives/partial']) await fs.mkdir(name, { recursive: true });
  for (const entry of envelope.sourceSnapshot.files) {
    const name = entry.path === '/etc/apt/sources.list' ? 'main.list' : entry.path.split('/').pop();
    await fs.writeFile('/metadata/sources/' + name, metadata.canonicalSources(name, entry.text, binding.target==='listings-package'?'listings-trixie-freshness-v1':'v23-trixie-freshness-v1'), { flag: 'wx', mode: 0o600 });
  }
  async function command(file, args, { expanded = false } = {}) {
    if (controller.signal.aborted || now() >= deadline) throw error('ORIGINAL_BUILD_DEADLINE');
    if (!['/usr/bin/apt-get', '/usr/bin/apt-cache', '/usr/lib/apt/apt-helper'].includes(file)) throw error('ORIGINAL_BUILD_COMMAND');
    return new Promise((resolve, reject) => {
      const child = spawn(file, args, { detached: true, stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin', LC_ALL: 'C', DEBIAN_FRONTEND: 'noninteractive' } });
      children.add(child); let failure, chunks = [], size = 0;
      const kill = cause => { failure ||= cause; if (child.pid) try { process.kill(-child.pid, 'SIGKILL'); } catch (e) { if (e.code !== 'ESRCH') failure ||= e; } };
      const abort = () => kill(error('ORIGINAL_BUILD_DEADLINE')); controller.signal.addEventListener('abort', abort, { once: true });
      child.on('error', kill);
      child.stdout.on('data', chunk => {
        if (expanded) { expandedBytes += chunk.length; if (expandedBytes > 512 * 1024 ** 2) kill(error('ORIGINAL_BUILD_EXPANSION')); }
        else { size += chunk.length; commandBytes += chunk.length; if (size > 1024 ** 2 || commandBytes > 2 * 1024 ** 2) kill(error('ORIGINAL_BUILD_OUTPUT')); else chunks.push(chunk); }
      });
      child.stderr.on('data', chunk => { commandBytes += chunk.length; if (commandBytes > 2 * 1024 ** 2) kill(error('ORIGINAL_BUILD_OUTPUT')); });
      child.once('close', (code, signal) => {
        children.delete(child); controller.signal.removeEventListener('abort', abort);
        if (child.pid) try { process.kill(-child.pid, 0); failure ||= error('ORIGINAL_BUILD_DESCENDANTS'); } catch (e) { if (e.code !== 'ESRCH') failure ||= e; }
        if (failure || code !== 0 || signal) reject(failure || error('ORIGINAL_BUILD_APT_FAILED'));
        else resolve(Buffer.concat(chunks).toString());
      });
    });
  }
  guestStage = 'apt-authentication';
  const certificate = replay.replayCertificate(), replayBudget = replay.createReplayBudget();
  offline = replay.createReplay({ ...certificate, read: metadataRead, budget: replayBudget });
  let authenticated, authenticationError;
  try {
    const authority = await offline.listen(), options = metadata.metadataAptOptions(authority.port);
    await command('/usr/bin/apt-get', [...options, 'update', '--error-on=any']);
    for (const row of candidate.indices) {
      const bytes = await fs.readFile('/metadata/lists/' + row.name);
      if (bytes.length !== row.bytes || hash(bytes) !== row.sha256) throw error('ORIGINAL_BUILD_AUTHENTICATED_INDEX_CHANGED');
      await command('/usr/lib/apt/apt-helper', ['cat-file', '/metadata/lists/' + row.name], { expanded: true });
    }
    for (const row of candidate.releaseFreshness) {
      const bytes = await fs.readFile('/metadata/lists/' + row.name);
      metadata.authenticatedReleaseFreshness(row.name, bytes.toString(), Date.now());
    }
    const uriLines = value => value.split('\n').filter(line => line.startsWith("'")).sort();
    for (const stage of retained.stages) {
      const selection = await command('/usr/bin/apt-get', [...options, '--print-uris', '--download-only', '--yes', '--no-install-recommends', 'install', ...stage.packages]);
      if (JSON.stringify(uriLines(selection)) !== JSON.stringify(uriLines(stage.selection))) throw error('ORIGINAL_BUILD_APT_SELECTION_CHANGED');
      const simulation = await command('/usr/bin/apt-get', [...options, '--simulate', '--no-install-recommends', 'install', ...stage.packages]);
      const installed = value => value.split('\n').filter(line => line.startsWith('Inst '));
      if (JSON.stringify(installed(simulation)) !== JSON.stringify(installed(stage.simulation))) throw error('ORIGINAL_BUILD_APT_SIMULATION_CHANGED');
      for (const row of stage.selected) {
        const text = await command('/usr/bin/apt-cache', [...options, 'show', `${row.name}=${row.version}`]);
        const records = text.trim().split(/\n\n+/).map(block => Object.fromEntries(block.split('\n').filter(line => /^[A-Za-z][A-Za-z0-9-]*: /.test(line)).map(line => { const split = line.indexOf(': '); return [line.slice(0, split), line.slice(split + 2)]; })));
        if (!records.some(record => record.Package === row.name && record.Version === row.version && record.Architecture === row.architecture
          && record.Filename === row.filename && record.SHA256 === row.sha256 && Number(record.Size) === row.bytes)) throw error('ORIGINAL_BUILD_APT_PACKAGE_CHANGED');
      }
    }
    if (hash(await fs.readFile('/var/lib/dpkg/status')) !== candidate.installedStatusSha256) throw error('ORIGINAL_BUILD_APT_BASE_CHANGED');
    authenticated = { version: 1, method: 'original-base-apt-closed-replay', retainedManifestSha256: hash(retainedBytes),
      keyringSha256: candidate.keyringSha256, installedStatusSha256: candidate.installedStatusSha256,
      stages: retained.stages.map(stage => ({ name: stage.name, selectionSha256: hash(stage.selection) })), expandedBytes };
  } catch (cause) { authenticationError = cause; throw cause; }
  finally {
    try {
      const result = await offline.close();
      if (result.failure || !result.absenceVerified) throw error('ORIGINAL_BUILD_APT_REPLAY_RETIREMENT');
    } catch (cause) {
      if (authenticationError) authenticationError.replayCleanupError = cause.code || 'ORIGINAL_BUILD_APT_REPLAY_RETIREMENT';
      else throw cause;
    }
  }
  authenticationWitness = { binding, ...authenticated };
  guestStage = 'artifact-plan';
  const plan = closure.planArtifacts({ npmLock: Buffer.from(npmLockBase64, 'base64'), stages: retained.stages, base: binding.base });
  guestStage = 'artifact-acquisition';
  const receipt = await closure.acquireArtifacts({ artifacts: plan.artifacts, budgetProfile, directory: '/closure/artifacts', authority: { host: '127.0.0.1', port },
    signal: controller.signal, now, deadline });
  clearTimeout(timer);
  guestStage = 'frozen-replay';
  const artifactRead = closure.artifactReader('/closure/artifacts', receipt);
  async function publish(name, bytes) {
    const file = await fs.open('/closure/' + name + '.partial', 'wx', 0o400);
    try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
    await fs.link('/closure/' + name + '.partial', '/closure/' + name);
    await fs.unlink('/closure/' + name + '.partial');
    const parent = await fs.open('/closure', 'r'); try { await parent.sync(); } finally { await parent.close(); }
  }
  await publish('replay-intent.json', JSON.stringify({ version: 1, binding, npmSourceWitness, admissionPolicy: replay.FIFO_POLICY }));
  frozen = replay.createReplay({ ...certificate, budget: replayBudget,
    diagnosticUrls: receipt.artifacts.flatMap(row => row.urls),
    npmUpdatePolicy: replay.NPM_UPDATE_POLICY.id, npmSourceWitness, admissionPolicy: replay.FIFO_POLICY.id,
    read: url => byUrl.has(url) ? metadataRead(url) : artifactRead(url) });
  finish = createReplayFinalizer(frozen, publish, binding, result => {
    // Distinct process status makes a failed fsync after link observable even
    // if the terminal file itself contains an earlier clean declaration.
    process.exitCode = !result.absenceVerified || result.publicationErrors.length ? 2 : result.failure ? 1 : 0;
    if (process.exitCode) process.stderr.write(JSON.stringify({ error: result.failure || 'ORIGINAL_BUILD_REPLAY_RETIREMENT',
      firstFailure: result.firstFailure, publicationErrors: result.publicationErrors, absenceVerified: result.absenceVerified }) + '\n');
  });
  const authority = await frozen.listen();
  if (frozen.state().failure) throw error('ORIGINAL_BUILD_REPLAY_FAILED');
  guestStage = 'publication';
  await publish('npm-ca.pem', certificate.cert);
  await publish('closure.json', JSON.stringify({ version: 1, binding, authenticated, receipt, npmSourceWitness }));
  await publish('ready.json', JSON.stringify({ version: 1, binding, authority, closureSha256: hash(await fs.readFile('/closure/closure.json')),
    npmCaSha256: hash(certificate.cert), artifactBytesVerified: true, metadataAuthenticated: true, buildApproved: false }));
  const directory = await fs.open('/closure', 'r'); try { await directory.sync(); } finally { await directory.close(); }
  if (frozen.state().failure) throw error('ORIGINAL_BUILD_REPLAY_FAILED');
  // Owner retirement and automatic failure use the same finalizer.
  process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
  process.once('SIGTERM', finish); process.once('SIGINT', finish);
  readyPublished = true;
  } catch (primary) {
    // Only trusted bounded enum/hash witnesses; no remote messages, headers,
    // URL credentials or stack text enter the retained diagnostic record.
    try { primary.diagnostic = { version: 1, guestStage, ...closure.failureDiagnostic(primary),
      aptReplayFailure: offline?.failureRecord() || null, authenticationWitness }; }
    catch { /* Diagnostic attachment cannot replace the original failure. */ }
    const cleanupErrors = primary.replayCleanupError ? [primary.replayCleanupError] : [];
    clearTimeout(timer);
    try { stop(); } catch (cause) { cleanupErrors.push(cause.code || 'ORIGINAL_BUILD_CHILD_STOP'); }
    if (children.size) {
      let joinTimer;
      await Promise.race([Promise.all([...children].map(child => new Promise(resolve => child.once('close', resolve)))),
        new Promise(resolve => { joinTimer = setTimeout(resolve, 1000); })]); clearTimeout(joinTimer);
      if (children.size) cleanupErrors.push('ORIGINAL_BUILD_CHILD_JOIN_UNPROVEN');
    }
    if (finish) {
      const result = await finish(); cleanupErrors.push(...result.publicationErrors);
      if (!result.absenceVerified) cleanupErrors.push('ORIGINAL_BUILD_REPLAY_JOIN_UNPROVEN');
    }
    for (const service of [finish ? null : frozen, offline]) if (service) try {
      const result = await service.close(); if (!result.absenceVerified) cleanupErrors.push('ORIGINAL_BUILD_REPLAY_JOIN_UNPROVEN');
    } catch (cause) { cleanupErrors.push(cause.code || 'ORIGINAL_BUILD_REPLAY_CLOSE'); }
    primary.cleanupErrors = cleanupErrors; throw primary;
  } finally {
    if (!readyPublished) {
      clearTimeout(timer); process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
      if (finish) { process.removeListener('SIGTERM', finish); process.removeListener('SIGINT', finish); }
    }
  }
}

const GUEST_MODULES = Object.freeze(['ownedMcpDependencyClosure', 'ownedMcpArtifactReplay', 'ownedPolicySystemMetadata', 'ownedPolicySystemBuild']);
async function guestSource(root, binding, budgetProfile = closure.ORIGINAL_BUILD_PROFILE) {
  closure.acquisitionLimits(budgetProfile);
  const modules = {}, hashes = {};
  for (const name of GUEST_MODULES) {
    const file = path.join(root, 'tests/postgres', name + '.js');
    if (await fs.realpath(file) !== file) throw fail('ORIGINAL_BUILD_HELPER_PATH');
    const bytes = await fs.readFile(file); if (bytes.length > 262144) throw fail('ORIGINAL_BUILD_HELPER_SIZE');
    modules[name] = bytes.toString(); hashes['tests/postgres/' + name + '.js'] = sha(bytes);
  }
  const files = await source.capture(root);
  const npmLock = files.find(row => row.name === 'sidecars/sandbox-runner/owned-mcp-registry/package-lock.json').bytes;
  closure._internals.npmArtifacts(npmLock);
  const loader = `const modules=${JSON.stringify(modules)},cache=new Map();\nfunction load(name){if(!Object.hasOwn(modules,name))throw Error('ORIGINAL_BUILD_MODULE');if(cache.has(name))return cache.get(name).exports;const module={exports:{}};cache.set(name,module);new Function('require','module','exports',modules[name])(id=>id.startsWith('node:')?require(id):load(id.replace(/^\\.\\//,'')),module,module.exports);return module.exports;}\n`;
  const text = "'use strict';\n" + loader + `const createReplayFinalizer=${createReplayFinalizer.toString()};\n(${guestMain.toString()})(load,${JSON.stringify(binding)},${JSON.stringify(npmLock.toString('base64'))},${JSON.stringify(budgetProfile)}).catch(error=>{const record={error:error.code||'ORIGINAL_BUILD_GUEST_FAILED',cleanupErrors:error.cleanupErrors||[],diagnostic:error.diagnostic||null};const encoded=JSON.stringify(record);process.stderr.write((Buffer.byteLength(encoded)<=4096?encoded:JSON.stringify({error:record.error,diagnosticTruncated:true}))+'\\n');process.exitCode=process.exitCode===2||record.cleanupErrors.length?2:1;});\n`;
  if (Buffer.byteLength(text) > 1024 ** 2) throw fail('ORIGINAL_BUILD_GUEST_SIZE');
  return { text, sha256: sha(text), hashes };
}
async function registryConsumerPlan(root, spec, guard) {
  const runtime = require('./ownedMcpRuntimeQualification')._internals;
  const template = await fs.readFile(path.join(root, runtime.TEMPLATE));
  if (sha(template) !== runtime.TEMPLATE_SHA) throw fail('ORIGINAL_BUILD_RUNTIME_PROFILE_CHANGED');
  const nonce = spec.runId.slice(0, 12), name = 'owasp-ai-goat-owned-mcp-registry-' + nonce;
  const profile = template.toString().replaceAll('@@SUPERVISOR_PROFILE@@', name);
  if (!profile.endsWith('\n') || profile.split('\n').includes('OWASP_AI_GOAT_ORIGINAL_REGISTRY_PROFILE'))
    throw fail('ORIGINAL_BUILD_RUNTIME_PROFILE_DELIVERY');
  const profileRoot = '/var/tmp/owasp-ai-goat-v23-runtime-' + nonce;
  const policy = action => guard + `\ncheck_mount; check_runtime\n/bin/sh -c ${quote(runtime.scripts[action])} original-registry-profile '${profileRoot}' '${nonce}' '${name}' '${sha(profile)}'` +
    (action === 'install' ? ` <<'OWASP_AI_GOAT_ORIGINAL_REGISTRY_PROFILE'\n${profile}OWASP_AI_GOAT_ORIGINAL_REGISTRY_PROFILE\n` : '\n');
  const identity = String.raw`
registry_identity() {
 [ -f "$root/fs/registry.cid" ] && [ ! -L "$root/fs/registry.cid" ]
 registry_cid=$(cat "$root/fs/registry.cid")
 [ "$(printf '%s' "$registry_cid" | wc -c | tr -d ' ')" = 64 ]; case "$registry_cid" in *[!a-f0-9]*) return 97;; esac
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Id}}' "$registry_cid")" = "$registry_cid" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{index .Config.Labels "owasp-ai-goat.original.registry"}}' "$registry_cid")" = "$nonce" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Image}}' "$registry_cid")" = "$(docker --host "unix://$root/fs/docker.sock" image inspect --format '{{.Id}}' "owasp-ai-goat-v23-build:$nonce")" ]
}
registry_process_absent() {
 /usr/bin/python3 -I -S -B - "$root/fs" <<'OWASP_AI_GOAT_REGISTRY_ABSENCE'
import sys,os,json,stat
root=sys.argv[1]
if not os.path.lexists(root+'/registry.started'):sys.exit(0)
fd=os.open(root+'/registry.process',os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd) as f:
 s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and 0<s.st_size<4096
 row=json.load(f)
assert set(row)=={'pid','startTicks','exe'} and type(row['pid']) is int and row['pid']>1
try:
 with open('/proc/'+str(row['pid'])+'/stat') as f: fields=f.read().rsplit(')',1)[1].split()
 assert fields[19]!=row['startTicks']
except FileNotFoundError:pass
OWASP_AI_GOAT_REGISTRY_ABSENCE
}
`;
  const create = guard + `\ncheck_mount; check_runtime; check_network
[ ! -e "$root/fs/registry.cid" ] && [ ! -L "$root/fs/registry.cid" ]
image=$(docker --host "unix://$root/fs/docker.sock" image inspect --format '{{.Id}}' "owasp-ai-goat-v23-build:$nonce")
docker --host "unix://$root/fs/docker.sock" create --cidfile "$root/fs/registry.cid" --name '${name}' --label "owasp-ai-goat.original.registry=$nonce" --pull never --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m --memory 512m --cpus 1 --pids-limit 128 --log-driver none --cap-drop ALL --security-opt 'apparmor=${name}' --security-opt seccomp=unconfined --user 10001:10001 --env 'SECURESHOP_MCP_REGISTRY_PROFILE=${name}' --entrypoint node -i "$image" - >/dev/null
cid=$(cat "$root/fs/registry.cid")
docker --host "unix://$root/fs/docker.sock" inspect "$cid"
`;
  const start = guard + identity + `\ncheck_mount; check_runtime; registry_identity
/usr/bin/python3 -I -S -B -c 'import os,sys;fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400);os.write(fd,b"started");os.fsync(fd);os.close(fd);fd=os.open(os.path.dirname(sys.argv[1]),os.O_RDONLY);os.fsync(fd);os.close(fd)' "$root/fs/registry.started"
docker --host "unix://$root/fs/docker.sock" start "$registry_cid" >/dev/null
pid=$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Pid}}' "$registry_cid")
/usr/bin/python3 -I -S -B - "$root/fs" "$pid" <<'OWASP_AI_GOAT_REGISTRY_BIRTH'
import os,sys,json
root,pid=sys.argv[1:];assert pid.isdecimal() and int(pid)>1
with open('/proc/'+pid+'/stat') as f:start=f.read().rsplit(')',1)[1].split()[19]
exe=os.readlink('/proc/'+pid+'/exe');assert exe=='/usr/local/bin/node'
with open('/proc/'+pid+'/status') as f:assert any(line.startswith('Uid:') and line.split()[1:] == ['10001']*4 for line in f)
data=json.dumps(dict(pid=int(pid),startTicks=start,exe=exe)).encode()
fd=os.open(root+'/registry.process',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
try:os.write(fd,data);os.fsync(fd)
finally:os.close(fd)
fd=os.open(root,os.O_RDONLY)
try:os.fsync(fd)
finally:os.close(fd)
OWASP_AI_GOAT_REGISTRY_BIRTH
docker --host "unix://$root/fs/docker.sock" attach --sig-proxy=false "$registry_cid"
registry_identity
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$registry_cid")" = false ]
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.ExitCode}}' "$registry_cid")" = 0 ]
registry_process_absent
`;
  const retire = guard + identity + `\ncheck_mount; check_runtime; registry_identity
docker --host "unix://$root/fs/docker.sock" stop --time 5 "$registry_cid" >/dev/null
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$registry_cid")" = false ]
docker --host "unix://$root/fs/docker.sock" rm "$registry_cid" >/dev/null
ids=$(docker --host "unix://$root/fs/docker.sock" ps -aq --no-trunc)
for id in $ids; do [ "$id" != "$registry_cid" ]; done
registry_process_absent
printf 'absent\\n'
`;
  const profileRetire = guard + identity + `\ncheck_mount; check_runtime
if [ -e "$root/fs/registry.cid" ] || [ -L "$root/fs/registry.cid" ]; then
 cid=$(cat "$root/fs/registry.cid"); ids=$(docker --host "unix://$root/fs/docker.sock" ps -aq --no-trunc)
 for id in $ids; do [ "$id" != "$cid" ]; done
 registry_process_absent
fi
ids=$(docker --host "unix://$root/fs/docker.sock" ps -aq --no-trunc)
for id in $ids; do [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.AppArmorProfile}}' "$id")" != '${name}' ]; done
` + policy('cleanup').slice(guard.length) + "printf 'absent\\n'\n";
  return { name, profile, identity, helperHashes: { [runtime.TEMPLATE]: sha(template),
    'tests/postgres/ownedMcpRuntimeQualification.js': sha(await fs.readFile(path.join(root, 'tests/postgres/ownedMcpRuntimeQualification.js'))) },
    input: "require('/app/tests/fixtures/secureshopOwnedMcpRegistryPackaged.native.cjs').main().then(value=>process.stdout.write(JSON.stringify({...value,qualificationComplete:false}))).catch(error=>{process.stderr.write(String(error.stack||error)+'\\n');process.exitCode=1;});\n",
    commands: { registryProfileInstall: policy('install'), registryCreate: create, registryStart: start, registryRetire: retire, registryProfileRetire: profileRetire } };
}
function guardFrom(plan) {
  const suffix = '\ncheck_mount; check_runtime\ndocker --host "unix://$root/fs/docker.sock" info --format \'{{json .}}\'\n';
  if (!plan.commands.inspect.endsWith(suffix)) throw fail('ORIGINAL_BUILD_PHASE_SHAPE');
  return plan.commands.inspect.slice(0, -suffix.length);
}
async function listingsConsumerPlan(root,spec,guard,captured=null,mode='package',v03Health=false){
  if(v03Health&&mode!=='manager')throw fail('V03_LISTINGS_HEALTH_MODE');
  const runtime=require('./ownedMcpRuntimeQualification')._internals;
  const templatePath='sidecars/sandbox-runner/owned-listings/profile.apparmor.in';
  const template=await fs.readFile(path.join(root,templatePath));
  const nonce=mode==='manager'?require('../../scripts/application-data-root').workspaceId(root):spec.runId.slice(0,12),name='owasp-ai-goat-owned-listings-'+nonce;
  const profile=template.toString().replaceAll('@@SUPERVISOR_PROFILE@@',name);
  if(!profile.endsWith('\n')||profile.includes('\nOWASP_AI_GOAT_LISTINGS_PROFILE\n'))throw fail('LISTINGS_PROFILE_DELIVERY');
  const profileRoot=spec.mount+'/listings-profile';
  const policy=action=>{
    let script=replaceOnce(runtime.scripts[action],'[ "$root" = "/var/tmp/owasp-ai-goat-v23-runtime-$nonce" ]',`[ "$root" = '${profileRoot}' ]`);
    script=replaceOnce(script,'[ "$profile" = "owasp-ai-goat-owned-mcp-registry-$nonce" ]','[ "$profile" = "owasp-ai-goat-owned-listings-$nonce" ]');
    return guard+'\ncheck_mount; check_runtime\n/bin/sh -c '+quote(script)+' listings-profile '+quote(profileRoot)+' '+quote(nonce)+' '+quote(name)+' '+quote(sha(profile))+
      (action==='install'?" <<'OWASP_AI_GOAT_LISTINGS_PROFILE'\n"+profile+'OWASP_AI_GOAT_LISTINGS_PROFILE\n':'\n');
  };
  const identity=String.raw`
listings_identity() {
 [ -f "$root/fs/listings.cid" ] && [ ! -L "$root/fs/listings.cid" ]
 cid=$(cat "$root/fs/listings.cid"); [ "${'${#cid}'}" = 64 ]; case "$cid" in *[!a-f0-9]*) return 97;; esac
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Id}}' "$cid")" = "$cid" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{index .Config.Labels "owasp-ai-goat.listings.owner"}}' "$cid")" = "$nonce" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Image}}' "$cid")" = "$(docker --host "unix://$root/fs/docker.sock" image inspect --format '{{.Id}}' "owasp-ai-goat-v23-build:$nonce")" ]
}
`;
  const prefix=guard+identity+'\ncheck_mount; check_runtime\n';
  const volume='owasp-ai-goat-listings-journal-'+spec.runId;
  const create=prefix+`
[ ! -e "$root/fs/listings.cid" ] && [ ! -L "$root/fs/listings.cid" ]
[ -z "$(docker --host "unix://$root/fs/docker.sock" volume ls -q --filter name=^${volume}$)" ]
docker --host "unix://$root/fs/docker.sock" volume create --label "owasp-ai-goat.listings.owner=$nonce" '${volume}' >/dev/null
docker --host "unix://$root/fs/docker.sock" create --cidfile "$root/fs/listings.cid" --name '${name}' --label "owasp-ai-goat.listings.owner=$nonce" --pull never --network none --read-only --user 10001:10001 --memory 512m --cpus 1 --pids-limit 128 --cap-drop ALL --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m --security-opt 'apparmor=${name}' --security-opt seccomp=unconfined --log-driver local --log-opt max-size=1m --log-opt max-file=1 --log-opt compress=false --mount type=volume,source=${volume},target=/journal --env 'LISTINGS_PROFILE=${name}' --entrypoint node "owasp-ai-goat-v23-build:$nonce" /app/tests/fixtures/secureshopOwnedListingsPackaged.native.cjs >/dev/null
listings_identity
`;
  const start=state=>prefix+`listings_identity
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Status}}' "$cid")" = '${state}' ]
docker --host "unix://$root/fs/docker.sock" start --attach "$cid"
listings_identity
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Status}}' "$cid")" = exited ]
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.ExitCode}}' "$cid")" = 0 ]
`;
  const retire=prefix+`listings_identity
docker --host "unix://$root/fs/docker.sock" stop --time 5 "$cid" >/dev/null
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")" = false ]
docker --host "unix://$root/fs/docker.sock" rm "$cid" >/dev/null
ids=$(docker --host "unix://$root/fs/docker.sock" ps -aq --no-trunc)
for id in $ids; do [ "$id" != "$cid" ]; done
[ "$(docker --host "unix://$root/fs/docker.sock" volume inspect --format '{{index .Labels "owasp-ai-goat.listings.owner"}}' '${volume}')" = "$nonce" ]
docker --host "unix://$root/fs/docker.sock" volume rm '${volume}' >/dev/null
[ -z "$(docker --host "unix://$root/fs/docker.sock" volume ls -q --filter name=^${volume}$)" ]
printf 'absent\\n'
`;
  const profileRetire=prefix+`ids=$(docker --host "unix://$root/fs/docker.sock" ps -aq --no-trunc)
for id in $ids; do [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.AppArmorProfile}}' "$id")" != '${name}' ]; done
`+policy('cleanup').slice(guard.length)+"printf 'absent\\n'\n";
  const result={name,mode,helperHashes:{[templatePath]:sha(template),'tests/postgres/ownedMcpRuntimeQualification.js':sha(await fs.readFile(path.join(root,'tests/postgres/ownedMcpRuntimeQualification.js')))},
    commands:{listingsProfileInstall:policy('install'),listingsCreate:create,listingsFresh:start('created'),listingsRestart:start('exited'),listingsRetire:retire,listingsProfileRetire:profileRetire}};
  if(mode==='manager'){
    if(!captured)throw fail('LISTINGS_MANAGER_SOURCE');
    const resourcePath='tests/postgres/listings_native_resources.py',resource=await fs.readFile(path.join(root,resourcePath),'utf8');
    result.helperHashes[resourcePath]=sha(resource);
    for(const helper of ['tests/postgres/listingsPhaseEndpoint.js','tests/postgres/ownedMcpOriginalServiceProducer.js','scripts/application-data-root.js'])
      result.helperHashes[helper]=sha(await fs.readFile(path.join(root,helper)));
    for(const operation of ['create','start','channels'])result.commands['listingsManager'+operation[0].toUpperCase()+operation.slice(1)]=
      prefix+'/usr/bin/python3 -I -S -B -c '+quote(listingsManagerProgram(spec,name,volume,{...captured,workspaceId:nonce,profileSha256:sha(profile),v03Health},resource,operation))+'\n';
    if(v03Health){
      const helper='tests/postgres/ownedV03ListingsHealth.js';
      result.helperHashes[helper]=sha(await fs.readFile(path.join(root,helper)));
    }
    result.commands.listingsManagerRetire=prefix+`[ -f "$root/fs/listings-channels-retired.json" ] && [ ! -L "$root/fs/listings-channels-retired.json" ]\n`+
      retire.slice(prefix.length);
  }else if(mode!=='package')throw fail('LISTINGS_CONSUMER_MODE');
  return result;
}
function listingsManagerProgram(spec,name,volume,captured,resource,operation){
  return `import ast,json,os,re,hashlib,stat,subprocess,sys\nfrom pathlib import Path
ROOT=${JSON.stringify(spec.mount)};RUN=${JSON.stringify(spec.runId)};NAME=${JSON.stringify(name)};VOLUME=${JSON.stringify(volume)}
SOURCE=${JSON.stringify(captured.digest)};RUNTIME=${JSON.stringify(captured.runtimeDigest)};OP=${JSON.stringify(operation)}
WORKSPACE=${JSON.stringify(captured.workspaceId)};PROFILE_SHA=${JSON.stringify(captured.profileSha256)}
tree=ast.parse(${JSON.stringify(resource)})
names={'private_handoff','private_channels_retirement_program','_PRIVATE_CHANNEL','HEX'}
nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in names or isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in names for t in n.targets)]
assert len(nodes)==4
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pinned-listings-resource>','exec'))
root=Path(ROOT)
def save(name,value):
 raw=json.dumps(value,sort_keys=True).encode();assert len(raw)<=16384
 fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  while raw:
   n=os.write(fd,raw);assert n>0;raw=raw[n:]
  os.fsync(fd)
 finally:os.close(fd)
def read(name):
 fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and s.st_size<=16384
  raw=os.read(fd,16385);assert len(raw)==s.st_size;return json.loads(raw)
 finally:os.close(fd)
def docker(*args):
 # Reuse the reviewed actual streaming/cancellation loop, not capture_output.
 begin=_PRIVATE_CHANNEL.index('child=subprocess.Popen');end=_PRIVATE_CHANNEL.index('rows=json.loads(buffers[child.stdout])')
 body=_PRIVATE_CHANNEL[begin:end];anchor="['/usr/bin/docker','--host','unix://'+str(root/'docker.sock'),'inspect',H['containerId']]"
 assert body.count(anchor)==1;body=body.replace(anchor,'argv')
 import select,time
 def need(ok):
  if not ok:raise RuntimeError('LISTINGS_MANAGER_DOCKER')
 scope=dict(argv=['/usr/bin/docker','--host','unix://'+ROOT+'/docker.sock',*args],subprocess=subprocess,os=os,select=select,time=time,need=need)
 exec(compile(body,'<pinned-bounded-docker>','exec'),scope)
 return bytes(scope['buffers'][scope['child'].stdout]).decode().strip()
if OP=='create':
 raw=sys.stdin.buffer.read(8193);assert len(raw)<=8192
 data=json.loads(raw);assert set(data)=={'origin','token'}
 assert re.fullmatch(r'http://127\\.0\\.0\\.1:[0-9]{4,5}',data['origin']) and 1024<=int(data['origin'].rsplit(':',1)[1])<=65535
 assert re.fullmatch(r'[A-Za-z0-9_-]{43,128}',data['token'])
 env=['LISTINGS_MANAGER_ENABLED=true','LISTINGS_PROFILE='+NAME,'LISTINGS_PUBLIC_ORIGIN='+data['origin'],'LISTINGS_CONTROL_TOKEN='+data['token']]
 raw=('\\n'.join(env)+'\\n').encode();fd=os.open(root/'listings-manager.env',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  while raw:
   n=os.write(fd,raw);assert n>0;raw=raw[n:]
  os.fsync(fd)
 finally:os.close(fd)
 assert not docker('ps','-aq','--filter','name=^/'+NAME+'$') and not docker('volume','ls','-q','--filter','name=^'+VOLUME+'$')
 docker('volume','create','--label','owasp-ai-goat.listings.owner='+RUN,VOLUME)
 cid=docker('create','--cidfile',ROOT+'/listings.cid','--name',NAME,'--label','owasp-ai-goat.listings.owner='+RUN,'--label','owasp-ai-goat.test.owner='+RUN,'--label','owasp-ai-goat.listings.source='+SOURCE,'--label','owasp-ai-goat.listings.runtime='+RUNTIME,'--pull','never','--network','host','--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--security-opt','apparmor='+NAME,'--security-opt','seccomp=unconfined','--log-driver','local','--log-opt','max-size=1m','--log-opt','max-file=1','--log-opt','compress=false','--mount','type=volume,source='+VOLUME+',target=/journal','--env-file',ROOT+'/listings-manager.env','--entrypoint','node','owasp-ai-goat-v23-build:'+RUN,'/app/sidecars/sandbox-runner/owned-listings/manager-entry.js')
 assert re.fullmatch('[a-f0-9]{64}',cid)
 save('listings-manager-created.json',dict(containerId=cid,publicOrigin=data['origin'],environmentSha256=hashlib.sha256('\\n'.join(sorted(env)).encode()).hexdigest()))
 print('created')
elif OP=='start':
 created=read('listings-manager-created.json');cid=created['containerId']
 daemon=docker('info','--format','{{.ID}}');assert re.fullmatch('[a-f0-9-]{16,}',daemon)
 docker('start',cid);rows=json.loads(docker('inspect',cid));assert len(rows)==1
 row=rows[0];assert row['Image']==docker('image','inspect','--format','{{.Id}}','owasp-ai-goat-v23-build:'+RUN)
 pid=row['State']['Pid'];holder=int((root/'namespace.pid').read_text());s=root.stat()
 def birth(p):return int(Path('/proc/'+str(p)+'/stat').read_text().rsplit(')',1)[1].split()[19])
 assert birth(holder)==int((root/'namespace.start').read_text())
 assert docker('info','--format','{{.ID}}')==daemon
 fd=os.open(root/'listings-profile'/'policy',os.O_RDONLY|os.O_NOFOLLOW)
 try:
  ps=os.fstat(fd);assert stat.S_ISREG(ps.st_mode) and ps.st_uid==0 and ps.st_nlink==1 and ps.st_size<=65536
  raw=os.read(fd,65537);assert len(raw)==ps.st_size and hashlib.sha256(raw).hexdigest()==PROFILE_SHA
 finally:os.close(fd)
 H=private_handoff(dict(runId=RUN,root=ROOT,filesystemDevice=s.st_dev,filesystemInode=s.st_ino,namespaceInode=os.stat('/proc/'+str(holder)+'/ns/net').st_ino,holderPid=holder,holderStart=birth(holder),containerPid=pid,containerStart=birth(pid),containerId=cid,imageId=row['Image'],sourceSha256=SOURCE,runtimeSha256=RUNTIME,environmentSha256=created['environmentSha256'],publicOrigin=created['publicOrigin'],workspaceId=WORKSPACE,profileName=NAME,profileSha256=PROFILE_SHA,containerName=NAME,privateDockerHost='unix://'+ROOT+'/docker.sock',daemonId=daemon))
 exec(_PRIVATE_CHANNEL[:_PRIVATE_CHANNEL.index('import fcntl')])
${captured.v03Health?require('./ownedV03ListingsHealth').program():''} save('listings-manager-handoff.json',H);print(json.dumps(H,sort_keys=True))
elif OP=='channels':
 raw=sys.stdin.buffer.read(8193);assert len(raw)<=8192;data=json.loads(raw)
 assert set(data)=={'channelIds','listenerClosed','localChannelsRetired'} and data['listenerClosed'] is True and data['localChannelsRetired'] is True
 H=read('listings-manager-handoff.json')
 import io,contextlib
 output=io.StringIO()
 with contextlib.redirect_stdout(output):exec(private_channels_retirement_program(H,data['channelIds']))
 receipt=json.loads(output.getvalue());assert receipt['remoteChannelsAbsent'] is True
 save('listings-channels-retired.json',receipt);print(json.dumps(receipt,sort_keys=True))
else:raise RuntimeError('LISTINGS_MANAGER_OPERATION')
`;
}
async function originalBuildPlan(root, runId, { budgetProfile = closure.ORIGINAL_BUILD_PROFILE, consumerMode = 'fixture', target = 'mcp-registry', listingsMode='package' } = {}) {
  if(!['mcp-registry','listings-package'].includes(target)||target==='listings-package'&&consumerMode!=='fixture')throw fail('ORIGINAL_BUILD_TARGET');
  const listings=target==='listings-package'?await captureListings(root):null;
  if (!['fixture', 'original-service', 'v39-atomic-pair','q05-registered-pair'].includes(consumerMode)) throw fail('ORIGINAL_BUILD_CONSUMER_MODE');
  const serviceMode = consumerMode !== 'fixture', pairMode=['v39-atomic-pair','q05-registered-pair'].includes(consumerMode);
  const v03Mode=target==='listings-package'&&listingsMode==='v03-manager';
  const managerMode=target==='listings-package'&&['manager','v03-manager'].includes(listingsMode),leaseMode=(serviceMode||managerMode)&&!v03Mode;
  const leaseProfile=managerMode?'listings-manager-browser':consumerMode;
  const selectedBounded = v03Mode ? (await require('./ownedV03ListingsDerivation').loadListingsBounded()).bounded
    : leaseMode ? (await require('./ownedMcpOriginalServiceDerivation').loadOriginalServiceBounded(leaseProfile)).bounded : bounded;
  const artifactLimits = closure.acquisitionLimits(budgetProfile);
  const metadataPlan = await (listings?selectedBounded._internals.listingsMetadataQualificationPlan:selectedBounded._internals.metadataQualificationPlan)(root, runId);
  const spec = selectedBounded.specification(root, runId), phase = metadataPlan.phases;
  if (phase?.version !== 1 || metadataPlan.metadataRetention?.guestPath !== spec.mount + '/metadata-retained'
    || metadataPlan.metadataRetention?.bytes !== 144 * 1024 ** 2) throw fail('ORIGINAL_BUILD_RETENTION_PHASES_REQUIRED');
  for (const name of ['preflight', 'prepare', 'namespace', 'relayStart', 'daemonStart', 'metadataFetch', 'stop', 'evidence', 'retainedExport', 'cleanup'])
    if (typeof phase[name] !== 'string') throw fail('ORIGINAL_BUILD_PHASE_SHAPE');
  const originalRelay = await selectedBounded._internals.privateRelayPlan(spec, metadataPlan.admission, { transportOnly: true, metadataOnly: true });
  const relay = derivedRelaySource(originalRelay.source, budgetProfile), relaySha256 = sha(relay);
  const relayStart = replaceOnce(replaceOnce(phase.relayStart, originalRelay.source, relay), originalRelay.sourceSha256, relaySha256);
  const guest = await guestSource(root, metadataPlan.binding, budgetProfile), guard = guardFrom(metadataPlan);
  const registry = listings?await listingsConsumerPlan(root,spec,guard,listings,v03Mode?'manager':listingsMode,v03Mode):await registryConsumerPlan(root, spec, guard);
  const storeProgram = "import sys,os,hashlib; p,digest=sys.argv[1:]; data=sys.stdin.buffer.read(1048577); assert 0<len(data)<=1048576 and hashlib.sha256(data).hexdigest()==digest; fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400); f=os.fdopen(fd,'wb'); f.write(data); f.flush(); os.fsync(f.fileno()); f.close()";
  const ownedContainer = String.raw`
closure_identity() {
 [ -f "$root/fs/closure.cid" ] && [ ! -L "$root/fs/closure.cid" ]
 cid=$(cat "$root/fs/closure.cid")
 [ "$(printf '%s' "$cid" | wc -c | tr -d ' ')" = 64 ]; case "$cid" in *[!a-f0-9]*) return 97;; esac
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Id}}' "$cid")" = "$cid" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{index .Config.Labels "owasp-ai-goat.closure.owner"}}' "$cid")" = "$nonce" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Image}}' "$cid")" = "$(docker --host "unix://$root/fs/docker.sock" image inspect --format '{{.Id}}' 'node@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1')" ]
}
check_replay_exit() {
 if [ ! -e "$root/fs/closure/replay-intent.json" ] && [ ! -L "$root/fs/closure/replay-intent.json" ]; then return 0; fi
 replay_exit=$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.ExitCode}}' "$cid")
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.OOMKilled}}' "$cid")" = false ]
 /usr/bin/python3 -I -S -B - "$root/fs/closure" "$nonce" "$replay_exit" <<'OWASP_AI_GOAT_REPLAY_EXIT'
import sys,os,stat,json
root,run,code=sys.argv[1:];assert code in ('0','1') and os.path.realpath(root)==root
fd=os.open(root+'/replay-terminal.json',os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as f:
 a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o400 and 0<a.st_size<=16384
 data=f.read(16385);b=os.fstat(f.fileno());assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
r=json.loads(data);assert r['version']==1 and r['binding']['runId']==run and r['finalizerComplete'] is True
assert r['closed'] is True and r['active']==0 and r['admission']['pending']==0 and r['absenceVerified'] is True and r['publicationErrors']==[]
assert r['tlsRetirement']['pendingHandshakes']==0 and r['tlsRetirement']['establishedSockets']==0 and r['tlsRetirement']['unjoinedTlsSockets']==0 and r['tlsRetirement']['callbackDebt']==0 and r['tlsRetirement']['ownerIntents']==r['tlsRetirement']['ownerErrors']
assert int(code)==(0 if r['failure'] is None else 1)
OWASP_AI_GOAT_REPLAY_EXIT
}
`;
  const install = guard + ownedContainer + `
check_mount; check_runtime
[ ! -e "$root/fs/closure" ] && [ ! -L "$root/fs/closure" ]
mkdir -m 0700 "$root/fs/closure"
/usr/bin/python3 -I -S -B -c ${quote(storeProgram)} "$root/fs/closure-guest.js" '${guest.sha256}'
proxy_port=$(relay_control authority)
deadline=$(cat "$root/acquisition.deadline")
printf '%s' "$nonce" > "$root/fs/closure.intent"
docker --host "unix://$root/fs/docker.sock" create --cidfile "$root/fs/closure.cid" --name "owasp-ai-goat-v23-closure-$nonce" --label "owasp-ai-goat.closure.owner=$nonce" --pull never --network host --read-only --memory 768m --cpus 1 --pids-limit 64 --cap-drop ALL --security-opt no-new-privileges --log-driver local --log-opt max-size=1m --log-opt max-file=1 --log-opt compress=false --mount "type=bind,source=$root/fs/metadata-retained,target=/metadata-retained,readonly" --mount "type=bind,source=$root/fs/closure,target=/closure" --mount "type=bind,source=$root/fs/closure-guest.js,target=/closure-guest.js,readonly" --tmpfs /metadata:rw,nosuid,nodev,noexec,size=512m --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m --env "OWASP_AI_GOAT_ARTIFACT_DEADLINE_SECONDS=$deadline" --env "OWASP_AI_GOAT_ARTIFACT_PROXY_PORT=$proxy_port" --entrypoint /usr/local/bin/node 'node@${closure.BASE}' /closure-guest.js >/dev/null
closure_identity
docker --host "unix://$root/fs/docker.sock" start "$cid" >/dev/null
attempt=0
until [ -f "$root/fs/closure/ready.json" ]; do
 if [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")" != true ]; then docker --host "unix://$root/fs/docker.sock" logs --tail 64 "$cid" >&2; exit 97; fi
 attempt=$((attempt+1)); [ "$attempt" -lt 1500 ]; sleep .2
done
closure_identity
cat "$root/fs/closure/ready.json"
`;
  const ready = String.raw`
read_ready() {
 /usr/bin/python3 -I -S -B - "$root/fs/closure" "$nonce" <<'OWASP_AI_GOAT_CLOSURE_READY'
import sys,os,stat,json,hashlib
root,run=sys.argv[1:]
assert os.path.realpath(root)==root
def read(name):
 fd=os.open(root+'/'+name,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and 0<s.st_size<=1048576
  return f.read()
r=json.loads(read('ready.json'))
assert set(r)=={'version','binding','authority','closureSha256','npmCaSha256','artifactBytesVerified','metadataAuthenticated','buildApproved'}
assert r['version']==1 and r['artifactBytesVerified'] is True and r['metadataAuthenticated'] is True and r['buildApproved'] is False
assert r['binding']=={'runId':run,'target':${JSON.stringify(metadataPlan.binding.target)},'base':'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1'}
assert set(r['authority'])=={'host','port'} and r['authority']['host']=='127.0.0.1' and type(r['authority']['port']) is int and 1<=r['authority']['port']<=65535
assert hashlib.sha256(read('closure.json')).hexdigest()==r['closureSha256'] and hashlib.sha256(read('npm-ca.pem')).hexdigest()==r['npmCaSha256']
print(r['authority']['port'])
OWASP_AI_GOAT_CLOSURE_READY
}
`;
  const build = guard + ownedContainer + ready + `
check_mount; check_runtime; closure_identity
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")" = true ]
port=$(read_ready)
stop_private_relay
proxy="http://127.0.0.1:$port"
timeout --signal=TERM --kill-after=10 300 docker --host "unix://$root/fs/docker.sock" build --pull=false --network=host --platform linux/arm64 --build-arg "HTTP_PROXY=$proxy" --build-arg "HTTPS_PROXY=$proxy" --build-arg "http_proxy=$proxy" --build-arg "https_proxy=$proxy" --build-arg NO_PROXY= --build-arg no_proxy= --secret "id=npm_ca,src=$root/fs/closure/npm-ca.pem" --label '${listings?'owasp-ai-goat.listings.source':'owasp-ai-goat.registry.package'}=${listings?listings.digest:source.packageDigest()}' --label "owasp-ai-goat.build-run=$nonce" -f '${listings?listings.dockerfile:manifest.dockerfile}' -t "owasp-ai-goat-v23-build:$nonce" -
closure_identity
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")" = true ]
`;
  const retire = guard + ownedContainer + `
if [ ! -e "$root/fs/closure.intent" ] && [ ! -L "$root/fs/closure.intent" ]; then printf 'absent\\n'; exit 0; fi
check_mount; check_runtime; closure_identity
docker --host "unix://$root/fs/docker.sock" stop --time 10 "$cid" >/dev/null
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")" = false ]
check_replay_exit
docker --host "unix://$root/fs/docker.sock" rm "$cid" >/dev/null
remaining=$(docker --host "unix://$root/fs/docker.sock" ps --all --quiet --no-trunc)
for remaining_cid in $remaining; do
 [ "$(printf '%s' "$remaining_cid" | wc -c | tr -d ' ')" = 64 ]; case "$remaining_cid" in *[!a-f0-9]*) exit 97;; esac
 [ "$remaining_cid" != "$cid" ]
done
printf 'absent\\n'
`;
  const image = guard + '\ncheck_mount; check_runtime\ndocker --host "unix://$root/fs/docker.sock" image inspect "owasp-ai-goat-v23-build:$nonce"\n';
  const closureEvidence = guard + String.raw`
check_mount
/usr/bin/python3 -I -S -B - "$root/fs/closure" <<'OWASP_AI_GOAT_CLOSURE_EVIDENCE'
import sys,os,stat,json
root=sys.argv[1];assert os.path.realpath(root)==root
result={}
for name in ('ready.json','closure.json','replay-intent.json','replay-failure.json','replay-terminal.json'):
 file=root+'/'+name
 if not os.path.lexists(file):result[name]=None;continue
 fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and 0<s.st_size<=1048576
  data=f.read();after=os.fstat(f.fileno())
  assert (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
  result[name]=data.decode('utf-8')
encoded=json.dumps(result);assert len(encoded.encode())<=2097152
print(encoded)
OWASP_AI_GOAT_CLOSURE_EVIDENCE
`;
  const handoff = guard + String.raw`
check_mount; check_runtime; check_network
/usr/bin/python3 -I -S -B - "$root" "$nonce" <<'OWASP_AI_GOAT_PRIVATE_HANDOFF'
import sys,os,json
root,run=sys.argv[1:]
def text(name):
 with open(root+'/fs/'+name) as f:return f.read().strip()
def process(name,exe):
 pid=int(text(name+'.pid'));assert pid>1
 with open('/proc/'+str(pid)+'/stat') as f: fields=f.read().rsplit(')',1)[1].split()
 start=text(name+'.start');assert fields[19]==start and os.readlink('/proc/'+str(pid)+'/exe')==exe
 inode=os.readlink('/proc/'+str(pid)+'/ns/net');assert inode==text('namespace.inode')
 return dict(pid=pid,startTicks=start,exe=exe)
namespace=text('namespace.inode');assert namespace!=text('shared.inode') and namespace!=os.readlink('/proc/1/ns/net')
st=os.stat(root+'/fs')
print(json.dumps(dict(version=1,target='original-v23-registry',runId=run,privateDockerHost='unix://'+root+'/fs/docker.sock',namespaceInode=namespace,
 filesystemIdentity=dict(device=st.st_dev,inode=st.st_ino),daemonProcess=process('daemon','/usr/bin/dockerd'),namespaceHolder=process('namespace','/usr/bin/sleep'))))
OWASP_AI_GOAT_PRIVATE_HANDOFF
`;
  const helperHashes = { ...guest.hashes, ...registry.helperHashes };
  if (leaseMode) for (const file of ['ownedMcpOriginalService', 'ownedMcpOriginalServiceLease', 'ownedMcpOriginalServiceDerivation', 'ownedMcpOriginalServiceProducer', 'ownedMcpRegistryService']) {
    const relative = 'tests/postgres/' + file + '.js'; helperHashes[relative] = sha(await fs.readFile(path.join(root, relative)));
  }
  if (serviceMode) for (const relative of ['server/services/secureshopOwnedMcpRegistryClient.js',
    'server/services/mcp/ownedManagedConfiguration.js', 'server/services/secureshopOwnedMcpInvocationContract.js',
    'server/services/mcp/protocolContext.js']) helperHashes[relative] = sha(await fs.readFile(path.join(root, relative)));
  if(pairMode)for(const relative of ['server/services/secureshopMcpRegistryContract.js',
    'server/services/secureshopMcpRegistryDiscoveryContract.js','sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol.js'])
    helperHashes[relative]=sha(await fs.readFile(path.join(root,relative)));
  for (const file of ['tests/postgres/ownedMcpOriginalBuildAdapter.js', 'tests/postgres/ownedMcpBoundedBuild.js', 'tests/postgres/ownedMcpPrivateEgress.js',
    'scripts/install/secureshop-owned-mcp-registry-setup.js', 'scripts/install/manifests/secureshop-owned-mcp-registry-build.json'])
    helperHashes[file] = sha(await fs.readFile(path.join(root, file)));
  const plan = { version: 1, kind: 'original-v23-build-closed-artifact-replay', runId, spec, binding: metadataPlan.binding,
    packageDigest: listings?listings.digest:source.packageDigest(), buildSources: metadataPlan.buildSources, helperHashes,
    scriptTransport: PHASE_TRANSPORT,
    npmUpdatePolicy: require('./ownedMcpArtifactReplay').NPM_UPDATE_POLICY,
    replayAdmissionPolicy: require('./ownedMcpArtifactReplay').FIFO_POLICY,
    guestSource: guest.text, guestSourceSha256: guest.sha256, relaySourceSha256: relaySha256,
    registryConsumer: { name: registry.name, input: registry.input },
    metadataGuestSource: require('./ownedPolicySystemMetadata').guestMetadataSource(metadataPlan.binding, { retention: listings?'listings-metadata-retention-v1':'v23-metadata-retention-v1' }),
    limits: { disk: bounded.LIMITS.disk, acquisitionMs: 300000, acquisitionConnects: 192, acquisitionBytes: 261 * 1024 ** 2,
      artifactBudgetProfile: budgetProfile, artifactBytes: artifactLimits.total,
      npmStoredBytes: artifactLimits.npm, npmWireBytes: budgetProfile === closure.ORIGINAL_BUILD_PROFILE ? NPM_WIRE_BYTES : closure.LIMITS.npm,
      replayMs: 300000, replayRequests: 512, replayConnections: 256, replayBytes: 512 * 1024 ** 2,
      consumerWorkMs: 120000, consumerRetirementMs: REGISTRY_RETIREMENT_MS, registryPhaseJoinMs: REGISTRY_PHASE_JOIN_MS },
    commands: { ...registry.commands, inventory: metadataPlan.commands.inventory, preflight: phase.preflight, prepare: phase.prepare,
      namespace: phase.namespace, relayStart, daemonStart: phase.daemonStart, metadataFetch: phase.metadataFetch,
      startArtifacts: install, build, image, handoff, closureEvidence, inspect: metadataPlan.commands.inspect, retireArtifacts: retire,
      stop: phase.stop, evidence: phase.evidence, retainedExport: phase.retainedExport, cleanup: phase.cleanup },
    buildApproved: false, qualificationComplete: false };
  if(listings){
    plan.target=target;plan.kind='original-listings-build-closed-artifact-replay';
    plan.imageContract={entrypoint:listings.entrypoint,user:listings.user,label:'owasp-ai-goat.listings.source',runtimeDigest:listings.runtimeDigest};
    plan.consumerIntegrationComplete=false;plan.sharedImageLoadAllowed=false;
    plan.helperHashes['scripts/install/secureshop-owned-listings.js']=sha(await fs.readFile(path.join(root,'scripts/install/secureshop-owned-listings.js')));
    for(const file of ['scripts/install/secureshop-owned-listings-qualified-candidate.js','scripts/install/manifests/owned-listings-arm64.candidate.json','scripts/install/qualification/secureshop-listings-package-2026-10-17.json'])plan.helperHashes[file]=sha(await fs.readFile(path.join(root,file)));
    plan.commands.build=replaceOnce(plan.commands.build,'--label "owasp-ai-goat.build-run=$nonce"',`--label "owasp-ai-goat.build-run=$nonce" --label 'owasp-ai-goat.listings.runtime=${listings.runtimeDigest}'`);
    delete plan.registryConsumer;
    plan.listingsConsumer={name:registry.name,mode:registry.mode};
    plan.commands.handoff=replaceOnce(plan.commands.handoff,"target='original-v23-registry'","target='original-listings-package'");
  }
  if (leaseMode) {
    const lease = require('./ownedMcpOriginalServiceDerivation');
    const selectedLease=require('./ownedMcpOriginalServiceLease').specification(leaseProfile);
    const leaseCommand=op=>lease.leaseCommand(op,leaseProfile);
    plan.consumerMode = consumerMode;
    plan.limits.serviceLeaseMs = selectedLease.totalMs;
    plan.limits.consumerWorkMs = managerMode||pairMode?600000:1320000;
    if(managerMode)plan.listingsLease={profile:leaseProfile,target:selectedLease.target,totalMs:selectedLease.totalMs,
      startupMs:60000,browserMs:540000,retirementMs:selectedLease.phases.retirement,cleanupMs:selectedLease.phases.cleanup};
    if(pairMode){
      const v39=consumerMode==='v39-atomic-pair';
      for (const name of ['tests/postgres/run-owned-mcp-assembly-isolated.py',
        ...(v39?['tests/postgres/v39_atomic_pair_receipt.py']:[]),
        'tests/postgres/secureshopOwnedMcpRegistryRendered.native.js',
        'tests/postgres/secureshopMailActualTransport.js',
        'tests/fixtures/secureshopMcpDescriptionRenderedQualification.js',
        ...(v39?['tests/fixtures/secureshopMcpDescriptionAtomicPairRenderedQualification.js']:
          ['tests/postgres/test_owned_mcp_assembly_launcher.py'])])
        plan.helperHashes[name]=sha(await fs.readFile(path.join(root,name)));
      plan.kind=v39?'original-registry-build-v39-atomic-pair':'original-registry-build-q05-registered-pair';
      plan.consumerBinding={version:1,profile:consumerMode,leaseTarget:selectedLease.target,
        proxySha256:require('./ownedMcpOriginalService').fixedProxy(consumerMode).sourceSha256,
        requests:256,concurrent:2,requestBytes:196608,responseBytes:524288,
        fixtureMs:v39?240000:480000,childMs:480000,parentWorkMs:960000,
        ...(v39?{arms:2,modelCallsPerArm:14,modelCalls:28}:{arms:1,modelCalls:12}),
        qualificationComplete:false,liveEnabled:v39?V39_PRIVATE_ENABLED:Q05_PRIVATE_ENABLED};
    }
    if(serviceMode)Object.assign(plan.commands, require('./ownedMcpOriginalServiceProducer').commands(registry, guard,consumerMode));
    for (const phaseName of ['build', 'settlement', 'cleanup'])
      plan.commands['serviceLease' + phaseName] = guard + '\n' + leaseCommand('claim-' + phaseName) + '\n';
    // A failed startup may have already claimed final cleanup. Checking that
    // immutable record reuses it; exclusive claim cannot renew an expired one.
    plan.commands.serviceLeasecleanup = guard + '\n' + leaseCommand('check-cleanup') + ' 2>/dev/null || ' + leaseCommand('claim-cleanup') + '\n';
    // Prepare exclusively publishes the absolute lease before allocation; the
    // first build claim follows that publication within the same fixed phase.
    plan.commands.prepare += '\n' + leaseCommand('claim-build') + ' >/dev/null\n';
    const phaseBound = (guard,script,phase)=>require('./ownedMcpOriginalServiceProducer').boundedPhase(guard,script,phase,leaseProfile);
    for (const name of ['namespace', 'relayStart', 'daemonStart', 'metadataFetch', 'startArtifacts', 'build', 'image', 'inspect'])
      plan.commands[name] = phaseBound(guard,plan.commands[name],'build');
    plan.commands.handoff = phaseBound(guard,plan.commands.handoff,'settlement');
    for (const name of ['stop', 'evidence', 'retainedExport', 'cleanup'])
      plan.commands[name] = phaseBound(guard,plan.commands[name],'cleanup');
    plan.commands.retireArtifacts = phaseBound(guard,plan.commands.retireArtifacts,'artifact-retirement');
    if(managerMode){
      for(const phase of ['startup','cohort'])plan.commands['serviceLease'+phase]=guard+'\n'+leaseCommand('claim-'+phase)+'\n';
      plan.commands.serviceLeaseretirement=guard+'\nif [ -f "$root/original-service-phase-cohort.json" ]; then\n'+leaseCommand('claim-retirement')+'\nelse\n'+leaseCommand('claim-cleanup')+'\nfi\n';
      for(const name of ['listingsProfileInstall','listingsManagerCreate','listingsManagerStart'])plan.commands[name]=phaseBound(guard,plan.commands[name],'startup');
      for(const name of ['listingsManagerChannels','listingsManagerRetire','listingsProfileRetire'])plan.commands[name]=phaseBound(guard,plan.commands[name],'retirement');
    }
  }
  if(v03Mode){
    const lease=require('./ownedV03ListingsLease');
    plan.kind='original-v03-listings-build-closed-artifact-replay';
    plan.consumerMode='v03-manager';
    plan.listingsLease={...require('./ownedV03ListingsProfile').SPECIFICATION};
    plan.limits.consumerWorkMs=1200000;
    plan.limits.serviceLeaseMs=11096000;
    // This is an inspectable source plan, not admission to the old600s owner.
    // withPrivateBuiltImage still rejects v03-manager until the distinct
    // combined producer/driver receives composed review.
    plan.consumerIntegrationComplete=false;
    for(const file of ['ownedV03ListingsDerivation.js','ownedV03DiagnosticDerivation.js',
      'ownedV03ListingsLease.js','ownedV03ListingsProfile.js','ownedV03CombinedLease.js',
      'ownedV03PrivateExecutors.js','ownedV03GuestClock.js']){
      const relative='tests/postgres/'+file;
      plan.helperHashes[relative]=sha(await fs.readFile(path.join(root,relative)));
    }
    for(const phase of Object.keys(lease.PHASES))
      plan.commands['serviceLease'+phase]=guard+'\n'+lease.command('claim',phase)+'\n';
    // prepare consumes only the fixed absolute parent lease input. Its first
    // separate build claim consumes the mapped phase input, never the same
    // stdin twice and never a fresh local duration.
    for(const name of ['namespace','relayStart','daemonStart','metadataFetch','startArtifacts','build','image','inspect'])
      plan.commands[name]=lease.boundedPhase(plan.commands[name],'build');
    plan.commands.handoff=lease.boundedPhase(plan.commands.handoff,'settlement');
    plan.commands.retireArtifacts=lease.boundedPhase(plan.commands.retireArtifacts,'artifact-retirement');
    for(const name of ['stop','evidence','retainedExport','cleanup'])plan.commands[name]=lease.boundedPhase(plan.commands[name],'cleanup');
    for(const name of ['listingsProfileInstall','listingsManagerCreate','listingsManagerStart'])
      plan.commands[name]=lease.boundedPhase(plan.commands[name],'startup');
    for(const name of ['listingsManagerChannels','listingsManagerRetire','listingsProfileRetire'])
      plan.commands[name]=lease.boundedPhase(plan.commands[name],'retirement');
  }
  return plan;
}

function planDigest(plan) { return sha(JSON.stringify(plan)); }
function limaAccountHome() {
  // MAIN deliberately strips HOME from application workers. Lima needs the
  // authentic account identity, not an environment-derived or task-local home.
  // Its VM state/temp paths remain explicitly repository-bound below.
  try {
    const account = os.userInfo(), uid = process.getuid(), euid = process.geteuid();
    if (!Number.isSafeInteger(uid) || uid <= 0 || euid !== uid || account.uid !== uid
      || typeof account.homedir !== 'string' || !account.homedir || account.homedir.includes('\0')
      || !path.isAbsolute(account.homedir) || path.normalize(account.homedir) !== account.homedir) {
      throw fail('ORIGINAL_BUILD_ACCOUNT_HOME');
    }
    return account.homedir;
  } catch { throw fail('ORIGINAL_BUILD_ACCOUNT_HOME'); }
}
function createPhaseExecutor({ launch = spawn, delay = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
  return async function execute(plan, name, { input, sink, diagnosticSink, signal } = {}) {
    if (!Object.hasOwn(plan.commands, name)) throw fail('ORIGINAL_BUILD_PHASE');
    const spec = plan.spec, timeout = ['metadataFetch', 'startArtifacts', 'build'].includes(name) ? 310 : 150;
    if (signal?.aborted) throw fail('ORIGINAL_BUILD_INTERRUPTED');
    const accountHome = limaAccountHome();
    const transported = phaseTransport(plan.commands[name]);
    const guestArgv = ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=10', String(timeout),
      '/bin/sh', '-c', transported.command, 'owned-original-build', spec.guest, spec.runId,
      ...(name === 'metadataFetch' ? [plan.binding.base] : [])];
    limaArgvEnvelope(guestArgv); // Validate the actual complete command, not raw script size.
    return new Promise((resolve, reject) => {
      const child = launch(spec.lima, ['shell', '--workdir', '/', 'colima-goat-q', ...guestArgv],
      { cwd: spec.root, detached: true, stdio: ['pipe', 'pipe', 'pipe'],
        env: { PATH: '/usr/bin:/bin', HOME: accountHome, TMPDIR: path.join(spec.root, 'tasks/tmp'), LIMA_HOME: spec.limaHome } });
      let failure, total = 0, diagnostic = 0, chunks = [], pending = Promise.resolve(), diagnosticPending = Promise.resolve();
      const stop = error => { failure ||= error; input?.destroy();
        if (child.pid && child.exitCode === null && child.signalCode === null) try { process.kill(-child.pid, 'SIGKILL'); } catch (cause) { if (cause.code !== 'ESRCH') failure ||= cause; } };
      const interrupted = () => stop(fail('ORIGINAL_BUILD_INTERRUPTED'));
      signal?.addEventListener('abort', interrupted, { once: true });
      const timer = setTimeout(() => stop(fail('ORIGINAL_BUILD_PHASE_TIMEOUT')), (timeout + 30) * 1000);
      child.on('error', stop); child.stdin.on('error', stop);
      child.stderr.on('data', bytes => {
        diagnostic += bytes.length; if (diagnostic > 2 * 1024 ** 2) return stop(fail('ORIGINAL_BUILD_OUTPUT_LIMIT'));
        if (diagnosticSink) { child.stderr.pause(); diagnosticPending = diagnosticPending.then(() => diagnosticSink(bytes)); diagnosticPending.then(() => child.stderr.resume(), stop); }
      });
      child.stdout.on('data', bytes => {
        total += bytes.length;
        if (total > (name === 'retainedExport' ? 145 * 1024 ** 2 : 2 * 1024 ** 2)) return stop(fail('ORIGINAL_BUILD_OUTPUT_LIMIT'));
        if (sink) { child.stdout.pause(); pending = pending.then(() => sink(bytes)); pending.then(() => child.stdout.resume(), stop); }
        else chunks.push(bytes);
      });
      child.once('close', async (code, termination) => {
        clearTimeout(timer); signal?.removeEventListener('abort', interrupted); input?.destroy();
        let drainTimer;
        try { await Promise.race([Promise.all([pending, diagnosticPending]), new Promise((_resolve, reject) => {
          drainTimer = setTimeout(() => reject(fail('ORIGINAL_BUILD_LOG_DRAIN_TIMEOUT')), 10000);
        })]); } catch (cause) { failure ||= cause; } finally { clearTimeout(drainTimer); }
        if (failure || code !== 0 || termination) {
          // A lost SSH reply is not remote retirement. Leave enough time for
          // the fixed guest timeout before attempting identity-bound cleanup.
          if (child.pid) await delay((timeout + 20) * 1000);
          reject(failure || fail('ORIGINAL_BUILD_PHASE_' + name.toUpperCase()));
        } else resolve(Buffer.concat(chunks).toString());
      });
      if (input) { input.on('error', stop); input.pipe(child.stdin); } else child.stdin.end();
    });
  };
}
const executePhase = createPhaseExecutor();
const liveHandoffs = new WeakSet();
function assertLiveHandoff(value) {
  if (!liveHandoffs.has(value)) throw fail('ORIGINAL_BUILD_HANDOFF_NOT_LIVE');
  return value;
}
function validatePhysicalHandoff(value, plan) {
  const keys = ['version', 'target', 'runId', 'privateDockerHost', 'namespaceInode', 'filesystemIdentity', 'daemonProcess', 'namespaceHolder'];
  if (!value || Object.keys(value).sort().join(',') !== keys.sort().join(',') || value.version !== 1
    || value.target !== (plan.target==='listings-package'?'original-listings-package':'original-v23-registry') || value.runId !== plan.runId || value.privateDockerHost !== 'unix://' + plan.spec.socket
    || !/^net:\[[1-9][0-9]*\]$/.test(value.namespaceInode)) throw fail('ORIGINAL_BUILD_HANDOFF');
  for (const [key, exe] of [['daemonProcess', '/usr/bin/dockerd'], ['namespaceHolder', '/usr/bin/sleep']]) {
    const row = value[key];
    if (!row || Object.keys(row).sort().join(',') !== 'exe,pid,startTicks' || row.exe !== exe
      || !Number.isInteger(row.pid) || row.pid <= 1 || !/^[1-9][0-9]*$/.test(row.startTicks)) throw fail('ORIGINAL_BUILD_HANDOFF');
  }
  if (value.daemonProcess.pid === value.namespaceHolder.pid || !value.filesystemIdentity
    || Object.keys(value.filesystemIdentity).sort().join(',') !== 'device,inode'
    || !Number.isSafeInteger(value.filesystemIdentity.device) || value.filesystemIdentity.device < 0
    || !Number.isSafeInteger(value.filesystemIdentity.inode) || value.filesystemIdentity.inode < 1) throw fail('ORIGINAL_BUILD_HANDOFF');
  return value;
}
function validateReplayTerminal(packet, binding, { allowFailedReplay = false, diagnosticUrls = [] } = {}) {
  const replay = require('./ownedMcpArtifactReplay');
  const parse = name => {
    if (typeof packet[name] !== 'string' || Buffer.byteLength(packet[name]) > 16384) throw fail('ORIGINAL_BUILD_REPLAY_TERMINAL');
    return JSON.parse(packet[name]);
  };
  const intent = parse('replay-intent.json'), result = parse('replay-terminal.json');
  const tls = result.tlsRetirement;
  if (JSON.stringify(intent) !== JSON.stringify({ version: 1, binding, npmSourceWitness: replay.expectedNpmSourceWitness(), admissionPolicy: replay.FIFO_POLICY })
    || result.version !== 1 || JSON.stringify(result.binding) !== JSON.stringify(binding)
    || result.closed !== true || result.active !== 0 || result.absenceVerified !== true
    || result.finalizerComplete !== true || !Array.isArray(result.publicationErrors) || result.publicationErrors.length
    || result.offlineOnly !== true || result.qualificationComplete !== false
    || ['requests', 'connections', 'bytes'].some(key => !Number.isSafeInteger(result[key]) || result[key] < 0)
    || !result.admission || Object.keys(result.admission).sort().join(',') !== 'peakPending,pending,policy'
    || result.admission.policy !== replay.FIFO_POLICY.id || result.admission.pending !== 0
    || !Number.isSafeInteger(result.admission.peakPending) || result.admission.peakPending < 0 || result.admission.peakPending > replay.FIFO_POLICY.pending
    || !tls || Object.keys(tls).sort().join(',') !== 'callbackDebt,diagnostics,establishedSockets,firstError,ownerErrors,ownerIntents,pendingHandshakes,unjoinedTlsSockets'
    || tls.pendingHandshakes !== 0 || tls.establishedSockets !== 0 || tls.unjoinedTlsSockets !== 0 || tls.callbackDebt !== 0 || tls.ownerIntents !== tls.ownerErrors
    || !Number.isSafeInteger(tls.ownerIntents) || tls.ownerIntents < 0 || tls.ownerIntents > result.connections
    || !replay.validateTlsDiagnostics(tls.diagnostics, result.connections, tls.firstError, tls.ownerIntents)
    || tls.firstError !== null && (!tls.firstError || Object.keys(tls.firstError).sort().join(',') !== 'code,ownerError,phase'
      || !['ECONNRESET', 'ERR_TLS_HANDSHAKE_TIMEOUT', 'ERR_SSL_WRONG_VERSION_NUMBER', 'ERR_SSL_UNEXPECTED_MESSAGE', 'TLS_OTHER'].includes(tls.firstError.code)
      || !['serving', 'owner-retiring'].includes(tls.firstError.phase) || typeof tls.firstError.ownerError !== 'boolean' || result.failure === null)
    || !replay.validateNpmUpdateReceipt(result.npmUpdate, result.requests, replay.NPM_UPDATE_POLICY.id))
    throw fail('ORIGINAL_BUILD_REPLAY_TERMINAL');
  if (result.failure === null) {
    if (result.firstFailure !== null || packet['replay-failure.json'] !== null
      || result.requests > 512 || result.connections > 256 || result.bytes > 512 * 1024 ** 2)
      throw fail('ORIGINAL_BUILD_REPLAY_TERMINAL');
  } else {
    const first = result.firstFailure;
    if (!first || Object.keys(first).sort().join(',') !== (first.cause === 'CLOSURE_UNLISTED_URL' ? 'cause,counters,request,version' : 'cause,counters,version') || first.version !== 1
      || first.cause !== result.failure || !replay.FAILURE_CODES.includes(first.cause)
      || first.cause === 'CLOSURE_UNLISTED_URL' && !replay.validateRequestIdentity(first.request, diagnosticUrls)
      || !first.counters || Object.keys(first.counters).sort().join(',') !== 'active,bytes,connections,requests'
      || Object.values(first.counters).some(value => !Number.isSafeInteger(value) || value < 0)
      || ['requests', 'connections', 'bytes'].some(key => first.counters[key] > result[key])
      || JSON.stringify(parse('replay-failure.json')) !== JSON.stringify({ binding, ...first }))
      throw fail('ORIGINAL_BUILD_REPLAY_TERMINAL');
    if (!allowFailedReplay) throw fail('ORIGINAL_BUILD_REPLAY_FAILED');
  }
  return result;
}
function validateClosureEvidence(packet, ready, envelope, npmLock, { terminal = false, allowFailedReplay = false } = {}) {
  if (!packet || Object.keys(packet).sort().join(',') !== 'closure.json,ready.json,replay-failure.json,replay-intent.json,replay-terminal.json'
    || typeof packet['closure.json'] !== 'string' || typeof packet['ready.json'] !== 'string'
    || Buffer.byteLength(packet['closure.json']) > 1024 ** 2 || Buffer.byteLength(packet['ready.json']) > 1024 ** 2
    || sha(packet['closure.json']) !== ready.closureSha256
    || JSON.stringify(JSON.parse(packet['ready.json'])) !== JSON.stringify(ready)) throw fail('ORIGINAL_BUILD_CLOSURE_EVIDENCE');
  const record = JSON.parse(packet['closure.json']), auth = record.authenticated;
  const expected = closure.planArtifacts({ npmLock, stages: envelope.candidate.retainedMetadata.stages });
  if (record.version !== 1 || JSON.stringify(record.binding) !== JSON.stringify(envelope.binding)
    || JSON.stringify(record.npmSourceWitness) !== JSON.stringify(require('./ownedMcpArtifactReplay').expectedNpmSourceWitness())
    || auth?.version !== 1 || auth.method !== 'original-base-apt-closed-replay'
    || auth.keyringSha256 !== envelope.candidate.keyringSha256 || auth.installedStatusSha256 !== envelope.candidate.installedStatusSha256
    || auth.retainedManifestSha256 !== sha(JSON.stringify(envelope.candidate.retainedMetadata))
    || !Number.isSafeInteger(auth.expandedBytes) || auth.expandedBytes < 1 || auth.expandedBytes > 512 * 1024 ** 2
    || JSON.stringify(auth.stages) !== JSON.stringify(envelope.candidate.retainedMetadata.stages.map(stage => ({ name: stage.name, selectionSha256: sha(stage.selection) })))
    || record.receipt?.version !== 1 || record.receipt.budgetProfile !== closure.ORIGINAL_BUILD_PROFILE
    || record.receipt.artifactBytesVerified !== true || record.receipt.metadataAuthenticated !== false
    || record.receipt.buildApproved !== false || record.receipt.qualificationComplete !== false
    || record.receipt.artifacts?.length !== expected.artifacts.length) throw fail('ORIGINAL_BUILD_CLOSURE_EVIDENCE');
  const totals = { deb: 0, npm: 0, total: 0 };
  for (let index = 0; index < expected.artifacts.length; index++) {
    const row = record.receipt.artifacts[index], { actualBytes, file, ...selection } = row;
    if (JSON.stringify(selection) !== JSON.stringify(expected.artifacts[index]) || !Number.isSafeInteger(actualBytes)
      || actualBytes < 1 || actualBytes > closure.LIMITS.artifact || row.bytes !== null && row.bytes !== actualBytes
      || file !== 'objects/' + closure._internals.objectName(row)) throw fail('ORIGINAL_BUILD_CLOSURE_EVIDENCE');
    totals[row.kind] += actualBytes; totals.total += actualBytes;
  }
  if (JSON.stringify(record.receipt.bytes) !== JSON.stringify(totals) || Object.keys(totals).some(key => totals[key] > closure.ORIGINAL_BUILD_LIMITS[key])) throw fail('ORIGINAL_BUILD_CLOSURE_EVIDENCE');
  if (terminal) {
    const result = validateReplayTerminal(packet, envelope.binding,
      { allowFailedReplay, diagnosticUrls: expected.artifacts.flatMap(row => row.urls) });
    if (!allowFailedReplay && (result.requests < 1 || result.connections < 1 || result.bytes < 1)) throw fail('ORIGINAL_BUILD_REPLAY_TERMINAL');
  }
  return record;
}
async function boundedConsumer(consumer, handoff, { signal, milliseconds = 120000, graceMs = 10000,
  retirementMs = graceMs, phaseJoinMs = 0, serviceMode = false } = {}) {
  if (typeof serviceMode !== 'boolean' || !Number.isInteger(milliseconds) || milliseconds < 1 || milliseconds > (serviceMode ? 1320000 : 120000)
    || !Number.isInteger(graceMs) || graceMs < 1 || graceMs > 10000
    || !Number.isInteger(retirementMs) || retirementMs < 1 || retirementMs > REGISTRY_RETIREMENT_MS
    || !Number.isInteger(phaseJoinMs) || phaseJoinMs < 0 || phaseJoinMs > REGISTRY_PHASE_JOIN_MS
    || phaseJoinMs > retirementMs) throw fail('ORIGINAL_BUILD_CONSUMER_BUDGET');
  if (signal?.aborted) return { error: fail('ORIGINAL_BUILD_CONSUMER_INTERRUPTED'), retired: true };
  const controller = new AbortController(), retirement = new AbortController(), phases = new Set();
  const workDeadline = performance.now() + milliseconds;
  let settled = false, invoked = false, confirmed = false, authorityOpen = true, retiring = false,
    interrupted = false, expired = false, outcome, timer, retirementTimer, retirementDeadline, expireResolve, retirementStartedInTime = false;
  const expiry = new Promise(resolve => { expireResolve = resolve; });
  const assertOpen = () => { if (!authorityOpen) throw fail('ORIGINAL_BUILD_RETIREMENT_CAPABILITY_CLOSED'); };
  const beginRetirement = () => {
    assertOpen();
    if (retiring) return;
    retiring = true; retirementStartedInTime = performance.now() < workDeadline;
    clearTimeout(timer); retirementDeadline = performance.now() + retirementMs;
    retirementTimer = setTimeout(() => {
      expired = true; authorityOpen = false; retirement.abort(); controller.abort(); expireResolve();
    }, retirementMs);
  };
  const abort = () => {
    if (!authorityOpen) return;
    interrupted = true; beginRetirement(); controller.abort();
  };
  // Epoch deadline is informational for existing consumers; only monotonic
  // elapsed time governs admission and the independent relative timers.
  const lifetime = Object.freeze({ signal: controller.signal, deadline: Date.now() + milliseconds,
    assertActive() {
      if (!authorityOpen || retiring || controller.signal.aborted || performance.now() >= workDeadline) throw fail('ORIGINAL_BUILD_CONSUMER_INTERRUPTED');
    },
    assertOpen, beginRetirement, retirementSignal: retirement.signal, expireWork: abort,
    retirementDeadline() { beginRetirement(); assertOpen(); return retirementDeadline; },
    assertRetirementAdmission() {
      beginRetirement(); assertOpen();
      if (performance.now() + phaseJoinMs > retirementDeadline) throw fail('ORIGINAL_BUILD_RETIREMENT_BUDGET');
    },
    joinPhase(operation) {
      assertOpen();
      const pending = Promise.resolve().then(() => { assertOpen(); return operation(); });
      phases.add(pending);
      return pending.finally(() => phases.delete(pending));
    },
    // Capability only for the trusted target consumer. It must be invoked
    // after that consumer's actual teardown verifier, never from report data.
    confirmRetired() {
      assertOpen(); beginRetirement();
      if (phases.size) throw fail('ORIGINAL_BUILD_CONSUMER_PHASE_JOIN_UNPROVEN');
      confirmed = true;
    } });
  const debt = error => {
    const pending = [error], seen = new Set();
    while (pending.length) {
      const item = pending.pop(); if (!item || typeof item !== 'object' || seen.has(item)) continue;
      seen.add(item); if (seen.size > 32) return true;
      try {
        if (item.retirementUnproven === true || item.pricingRetirementUnproven === true) return true;
        if (item.cause) pending.push(item.cause);
        if (Array.isArray(item.errors)) { if (item.errors.length > 32) return true; pending.push(...item.errors); }
      } catch { return true; }
    }
    return false;
  };
  timer = setTimeout(abort, milliseconds);
  signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  const work = Promise.resolve().then(() => {
    if (controller.signal.aborted) throw fail('ORIGINAL_BUILD_CONSUMER_INTERRUPTED');
    invoked = true; return consumer(handoff, lifetime);
  }).then(value => {
    settled = true;
    outcome = confirmed ? { value, retired: true } : { error: fail('ORIGINAL_BUILD_CONSUMER_RETIREMENT_UNPROVEN'), retired: false };
  }, error => { settled = true; outcome = { error, retired: !invoked || confirmed && !debt(error) }; });
  try {
    await Promise.race([work, expiry]);
    // Even a consumer which returns without awaiting a dispatched phase may
    // not strand a journal writer behind the outer terminal publication.
    if (!expired && phases.size) {
      beginRetirement();
      await Promise.race([Promise.allSettled([...phases]), expiry]);
    }
    if (expired) return { error: outcome?.error || fail(interrupted
      ? 'ORIGINAL_BUILD_CONSUMER_INTERRUPTED' : 'ORIGINAL_BUILD_CONSUMER_RETIREMENT_TIMEOUT'), retired: false };
    if (interrupted) return { error: outcome?.error || fail('ORIGINAL_BUILD_CONSUMER_INTERRUPTED'), retired: settled && outcome.retired };
    if (outcome?.error && settled && confirmed && outcome.retired && phases.size === 0
      && retirementStartedInTime && performance.now() < retirementDeadline) joinedConsumerFailures.add(outcome);
    return outcome;
  } finally {
    authorityOpen = false; retirement.abort(); controller.abort();
    clearTimeout(timer); clearTimeout(retirementTimer); signal?.removeEventListener('abort', abort);
  }
}
function registryLifetime(lifetime, plan, step) {
  const called = new Set(), completed = new Set(); let activePhase = false;
  return Object.freeze({ ...lifetime, registryName: plan.registryConsumer.name,
    confirmRetired() {
      lifetime.assertOpen();
      if (activePhase || called.has('registryCreate') && !completed.has('registryRetire')
        || called.has('registryProfileInstall') && !completed.has('registryProfileRetire'))
        throw fail('ORIGINAL_BUILD_CONSUMER_RETIREMENT_UNPROVEN');
      lifetime.confirmRetired();
    },
    runRegistryPhase(name) {
      if (!['registryProfileInstall', 'registryCreate', 'registryStart', 'registryRetire', 'registryProfileRetire'].includes(name)) throw fail('ORIGINAL_BUILD_CONSUMER_PHASE');
      const cleanup = ['registryRetire', 'registryProfileRetire'].includes(name);
      lifetime.assertOpen();
      if (called.has(name) || activePhase) throw fail('ORIGINAL_BUILD_CONSUMER_PHASE_ORDER');
      if (cleanup) lifetime.assertRetirementAdmission(); else lifetime.assertActive();
      called.add(name); activePhase = true;
      return lifetime.joinPhase(async () => {
        try {
          const value = await step(name, { ...(name === 'registryStart' ? { input: Readable.from([plan.registryConsumer.input]) } : {}),
            assertOpen: lifetime.assertOpen, signal: cleanup ? lifetime.retirementSignal : lifetime.signal,
            ...(!cleanup ? { assertActive: lifetime.assertActive } : {}) }, cleanup);
          lifetime.assertOpen();
          if (cleanup && value.trim() !== 'absent') throw fail('ORIGINAL_BUILD_CONSUMER_RETIREMENT_UNPROVEN');
          completed.add(name); return value;
        } finally { activePhase = false; }
      });
    } });
}
function listingsLifetime(lifetime,plan,step){
  const manager=plan.listingsConsumer.mode==='manager';
  const work=manager?['listingsProfileInstall','listingsManagerCreate','listingsManagerStart']:['listingsProfileInstall','listingsCreate','listingsFresh','listingsRestart'];
  const cleanup=manager?['listingsManagerChannels','listingsManagerRetire','listingsProfileRetire']:['listingsRetire','listingsProfileRetire'];
  const created=manager?'listingsManagerCreate':'listingsCreate',retired=manager?'listingsManagerRetire':'listingsRetire';
  const called=new Set(),completed=new Set();let active=false,next=0,retirementClaimed=false;
  return Object.freeze({...lifetime,listingsName:plan.listingsConsumer.name,
    confirmRetired(){
      lifetime.assertOpen();
      if(active||called.has(created)&&!completed.has(retired)
        ||called.has('listingsProfileInstall')&&!completed.has('listingsProfileRetire'))throw fail('LISTINGS_RETIREMENT_UNPROVEN');
      lifetime.confirmRetired();
    },
    runListingsPhase(name,input){
      lifetime.assertOpen();const retiring=cleanup.includes(name);
      if(!work.includes(name)&&!retiring||called.has(name)||active
        ||!retiring&&name!==work[next]
        ||name==='listingsProfileRetire'&&called.has(created)&&!completed.has(retired)
        ||name==='listingsManagerRetire'&&!completed.has('listingsManagerChannels'))throw fail('LISTINGS_PHASE_ORDER');
      const needsInput=manager&&['listingsManagerCreate','listingsManagerChannels'].includes(name);
      let body;
      if(needsInput){
        if(!input||typeof input!=='object'||Array.isArray(input))throw fail('LISTINGS_MANAGER_INPUT');
        if(name==='listingsManagerCreate'){
          if(Object.keys(input).sort().join(',')!=='origin,token'||!/^http:\/\/127\.0\.0\.1:\d{4,5}$/.test(input.origin)||! /^[A-Za-z0-9_-]{43,128}$/.test(input.token))throw fail('LISTINGS_MANAGER_INPUT');
        }else if(Object.keys(input).sort().join(',')!=='channelIds,listenerClosed,localChannelsRetired'||input.listenerClosed!==true||input.localChannelsRetired!==true||!Array.isArray(input.channelIds)||input.channelIds.length>32||new Set(input.channelIds).size!==input.channelIds.length||input.channelIds.some(c=>! /^[a-f0-9]{32}$/.test(c)))throw fail('LISTINGS_MANAGER_INPUT');
        body=Buffer.from(JSON.stringify(input));if(body.length>8192)throw fail('LISTINGS_MANAGER_INPUT');
      }else if(input!==undefined)throw fail('LISTINGS_MANAGER_INPUT');
      if(retiring)lifetime.assertRetirementAdmission();else lifetime.assertActive();
      called.add(name);active=true;
      return lifetime.joinPhase(async()=>{
        try{
          if(plan.listingsLease){
            if(name==='listingsProfileInstall')await step('serviceLeasestartup',{assertOpen:lifetime.assertOpen,signal:lifetime.signal,assertActive:lifetime.assertActive});
            if(retiring&&!retirementClaimed){
              retirementClaimed=true;
              await step('serviceLeaseretirement',{assertOpen:lifetime.assertOpen,signal:lifetime.retirementSignal},true);
            }
          }
          const value=await step(name,{assertOpen:lifetime.assertOpen,
            ...(body?{input:Readable.from([body])}:{}),
            signal:retiring?lifetime.retirementSignal:lifetime.signal,
            ...(!retiring?{assertActive:lifetime.assertActive}:{})},retiring);
          lifetime.assertOpen();
          if(plan.listingsLease&&name==='listingsManagerStart')await step('serviceLeasecohort',{assertOpen:lifetime.assertOpen,signal:lifetime.signal,assertActive:lifetime.assertActive});
          if(name==='listingsManagerChannels'){
            let proof;try{proof=JSON.parse(value);}catch{throw fail('LISTINGS_RETIREMENT_UNPROVEN');}
            if(proof?.version!==1||proof.runId!==plan.spec.runId||proof.remoteChannelsAbsent!==true||!Array.isArray(proof.channels)
              ||JSON.stringify(proof.channels.map(c=>c.channelId))!==JSON.stringify(input.channelIds))throw fail('LISTINGS_RETIREMENT_UNPROVEN');
          }else if(retiring&&value.trim()!=='absent')throw fail('LISTINGS_RETIREMENT_UNPROVEN');
          completed.add(name);if(!retiring)next++;return value;
        }finally{active=false;}
      });
    }});
}
function createConsumerJournal() {
  const pending = new Set();
  return Object.freeze({
    async run(operation) {
      const token = {}; pending.add(token);
      try { return await operation(); } finally { pending.delete(token); }
    },
    snapshot() { return Object.freeze({ sealed: pending.size === 0, pendingOperations: pending.size }); },
  });
}
async function durableJson(directory, name, value, assertOpen = () => {}, io = operation => operation()) {
  assertOpen();
  const fd = await io(() => fs.open(path.join(directory, name), 'wx', 0o600));
  try { assertOpen(); await io(() => fd.writeFile(JSON.stringify(value))); assertOpen(); await io(() => fd.sync()); }
  finally { await io(() => fd.close()); }
  assertOpen();
  const parent = await io(() => fs.open(directory, 'r'));
  try { assertOpen(); await io(() => parent.sync()); } finally { await io(() => parent.close()); }
}
async function verifyPlanSources(plan) {
  for (const [name, digest] of Object.entries({ ...plan.buildSources, ...plan.helperHashes })) {
    const file = path.join(plan.spec.root, name);
    if (await fs.realpath(file) !== file || sha(await fs.readFile(file)) !== digest) throw fail('ORIGINAL_BUILD_SOURCE_CHANGED');
  }
  const currentDigest=plan.target==='listings-package'?(await captureListings(plan.spec.root)).digest:source.packageDigest();
  if (currentDigest !== plan.packageDigest || sha(plan.guestSource) !== plan.guestSourceSha256) throw fail('ORIGINAL_BUILD_SOURCE_CHANGED');
}
async function withPrivateBuiltImage({ root, runId, expectedPlanSha256, consumer,
  runner = executePhase, verifyHost = bounded._internals.verifyHost, consumerMode = 'fixture', target = 'mcp-registry', listingsMode='package', workDeadline, outerDeadline } = {}) {
  if (typeof consumer !== 'function' || !/^[a-f0-9]{64}$/.test(expectedPlanSha256 || '')) throw fail('ORIGINAL_BUILD_REVIEWED_PLAN_REQUIRED');
  if(!['mcp-registry','listings-package'].includes(target))throw fail('ORIGINAL_BUILD_TARGET');
  // Only the reviewed manager lifetime is admitted; package fixtures stay closed.
  if(target==='listings-package'&&(!LISTINGS_PRIVATE_ENABLED||listingsMode!=='manager'))throw fail('LISTINGS_PRIVATE_CONSUMER_NOT_ADMITTED');
  // Prospective composition only. No runner override or receipt opens this mode.
  if (consumerMode === 'v39-atomic-pair' && !V39_PRIVATE_ENABLED) throw fail('V39_PRIVATE_CONSUMER_NOT_ADMITTED');
  if (consumerMode === 'q05-registered-pair' && !Q05_PRIVATE_ENABLED) throw fail('Q05_PRIVATE_CONSUMER_NOT_ADMITTED');
  const pairMode = ['v39-atomic-pair','q05-registered-pair'].includes(consumerMode), serviceMode = consumerMode !== 'fixture';
  const managerMode=target==='listings-package'&&listingsMode==='manager',leaseMode=serviceMode||managerMode;
  if (pairMode && (!Number.isFinite(workDeadline) || workDeadline <= performance.now()
    || workDeadline - performance.now() > 960000)) throw fail('V39_PRIVATE_DEADLINE');
  if (consumerMode === 'original-service' && !ORIGINAL_SERVICE_ENABLED) throw fail('ORIGINAL_SERVICE_NOT_ADMITTED');
  const plan = await originalBuildPlan(root, runId, { consumerMode, target, listingsMode });
  if (planDigest(plan) !== expectedPlanSha256) throw fail('ORIGINAL_BUILD_PLAN_CHANGED');
  await verifyPlanSources(plan); await verifyHost(plan.spec);
  if (pairMode && performance.now() >= workDeadline) throw fail('V39_PRIVATE_DEADLINE');
  const npmLock = await fs.readFile(path.join(root, 'sidecars/sandbox-runner/owned-mcp-registry/package-lock.json'));
  await fs.mkdir(plan.spec.artifact, { mode: 0o700 });
  const controller = new AbortController(), interruptions = [];
  const workTimer = pairMode ? setTimeout(() => controller.abort(), Math.max(0, workDeadline - performance.now())) : null;
  const interrupt = signal => { interruptions.push(signal); controller.abort(); };
  const handlers = Object.fromEntries(['SIGTERM', 'SIGINT', 'SIGHUP'].map(signal => [signal, () => interrupt(signal)]));
  for (const [signal, handler] of Object.entries(handlers)) process.on(signal, handler);
  let sequence = 0, intended = false, artifactsIntended = false, artifactRetired = false,
    consumerRetired = true, buildCompleted = false, primary, result, before, envelope, ready, consumerJournalAtRelease, retiredServiceFailure;
  const cleanupErrors = [];
  const consumerJournal = createConsumerJournal();
  let journalBytes = 0;
  const charge = (bytes, terminal = false) => {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || journalBytes + bytes > (terminal ? 64 : 60) * 1024 ** 2) throw fail('ORIGINAL_BUILD_JOURNAL_LIMIT');
    journalBytes += bytes;
  };
  const record = async (name, value, terminal = false, assertOpen = () => {}, io = operation => operation()) => {
    assertOpen();
    charge(Buffer.byteLength(JSON.stringify(value)), terminal); await durableJson(plan.spec.artifact, name, value, assertOpen, io);
  };
  const step = async (name, options = {}, cleanup = false) => {
    const open = () => options.assertOpen?.();
    const io = options.assertOpen ? consumerJournal.run : operation => operation();
    const active = () => { open(); if (!cleanup) { if (controller.signal.aborted || options.signal?.aborted
      || pairMode && performance.now() >= workDeadline) throw fail('ORIGINAL_BUILD_INTERRUPTED'); options.assertActive?.(); } };
    open();
    if (!cleanup) { active(); await verifyPlanSources(plan); active(); }
    const prefix = String(++sequence).padStart(3, '0') + '-' + name;
    await record(prefix + '-intent.json', { version: 1, name, planSha256: expectedPlanSha256 }, cleanup, open, io);
    open();
    const diagnostic = await io(() => fs.open(path.join(plan.spec.artifact, prefix + '-stderr.log'), 'wx', 0o600));
    let value, phaseError, closeError;
    try {
      active();
      value = await runner(plan, name, { ...options, diagnosticSink: async bytes => {
        open();
        if (!Buffer.isBuffer(bytes)) throw fail('ORIGINAL_BUILD_LOG_BYTES'); charge(bytes.length, cleanup); await io(() => diagnostic.writeFile(bytes));
      }, ...(cleanup ? {} : { signal: options.signal || controller.signal }) });
      await record(prefix + '-result.json', { version: 1, name, bytes: Buffer.byteLength(value || ''), sha256: sha(value || ''), output: value || '' }, cleanup, open, io);
    } catch (error) { phaseError = error; }
    try { try { open(); await io(() => diagnostic.sync()); } finally { await io(() => diagnostic.close()); } } catch (error) { closeError = error; }
    if (phaseError && closeError) throw new AggregateError([phaseError, closeError], 'Original phase and diagnostic retirement failed');
    if (phaseError || closeError) throw phaseError || closeError;
    return value;
  };
  const captureClosure = async (terminal, cleanup = false) => {
    const packet = JSON.parse(await step('closureEvidence', {}, cleanup));
    // Retain original bytes even when validation fails; never upgrade a hash
    // observation into independent authentication or successful retirement.
    await record(terminal ? 'closure-terminal-evidence.json' : 'closure-ready-evidence.json', packet, cleanup);
    if (ready && envelope) return validateClosureEvidence(packet, ready, envelope, npmLock, { terminal, allowFailedReplay: cleanup });
    // Before readiness, absence of intent proves replay was not entered. Once
    // intent exists, missing/unpublished terminal evidence remains explicit debt.
    if (packet['replay-intent.json'] !== null) return validateReplayTerminal(packet, plan.binding, { allowFailedReplay: cleanup });
    if (packet['replay-terminal.json'] !== null || packet['replay-failure.json'] !== null) throw fail('ORIGINAL_BUILD_REPLAY_TERMINAL');
  };
  try {
   try {
    before = bounded._internals.checkInventory(await step('inventory'));
    await step('preflight'); intended = true;
    await step('prepare'); await step('namespace'); await step('relayStart'); await step('daemonStart');
    const daemon = bounded._internals.checkDaemon(JSON.parse(await step('inspect')), plan.spec);
    const metadataRaw = await step('metadataFetch', { input: Readable.from([plan.metadataGuestSource]) });
    envelope = require('./ownedPolicySystemMetadata').validateResultEnvelope(metadataRaw, plan.binding);
    if (envelope.version !== 3 || envelope.ok !== true) throw fail('ORIGINAL_BUILD_RETAINED_METADATA_REQUIRED');
    await record('metadata-result.json', JSON.parse(metadataRaw));
    artifactsIntended = true;
    ready = JSON.parse(await step('startArtifacts', { input: Readable.from([plan.guestSource]) }));
    if (ready?.version !== 1 || JSON.stringify(ready.binding) !== JSON.stringify(plan.binding)
      || ready.artifactBytesVerified !== true || ready.metadataAuthenticated !== true || !/^[a-f0-9]{64}$/.test(ready.closureSha256)) throw fail('ORIGINAL_BUILD_NOT_READY');
    await record('artifact-ready.json', ready);
    await captureClosure(false);
    if (bounded._internals.checkDaemon(JSON.parse(await step('inspect')), plan.spec) !== daemon) throw fail('ORIGINAL_BUILD_DAEMON_CHANGED');
    await step('build', { input: source.contextStream(target==='listings-package'?(await captureListings(root)).files:await source.capture(root)) });
    const images = JSON.parse(await step('image')), image = images?.[0];
    if (images.length !== 1 || !/^sha256:[a-f0-9]{64}$/.test(image?.Id) || image.Architecture !== 'arm64' || image.Os !== 'linux'
      || image.Config?.Labels?.[plan.imageContract?.label||'owasp-ai-goat.registry.package'] !== plan.packageDigest || image.Config?.Labels?.['owasp-ai-goat.build-run'] !== runId
      || plan.imageContract&&(image.Config?.User!==plan.imageContract.user||JSON.stringify(image.Config?.Entrypoint)!==JSON.stringify(plan.imageContract.entrypoint)
        ||image.Config?.Labels?.['owasp-ai-goat.listings.runtime']!==plan.imageContract.runtimeDigest)) throw fail('ORIGINAL_BUILD_IMAGE');
    if (bounded._internals.checkDaemon(JSON.parse(await step('inspect')), plan.spec) !== daemon) throw fail('ORIGINAL_BUILD_DAEMON_CHANGED');
    // No replay/acquisition authority survives into the consumer's lifetime.
    if (leaseMode) await step('serviceLeasesettlement');
    artifactRetired = (await step('retireArtifacts')).trim() === 'absent';
    if (!artifactRetired) throw fail('ORIGINAL_BUILD_ARTIFACT_RETIREMENT');
    await captureClosure(true);
    buildCompleted = true;
    const physical = validatePhysicalHandoff(JSON.parse(await step('handoff')), plan);
    for (const name of ['daemonProcess', 'namespaceHolder', 'filesystemIdentity']) Object.freeze(physical[name]);
    const handoff = Object.freeze({ ...physical, daemonId: daemon, sourcePackageDigest: plan.packageDigest,
      imageId: image.Id, closureDigest: ready.closureSha256, controlled: runner !== executePhase });
    await record('image-handoff.json', { version: 1, image, handoff, qualificationComplete: false });
    if (runner === executePhase) liveHandoffs.add(handoff);
    consumerRetired = false;
    try {
      const outcome = await boundedConsumer((value, lifetime) => serviceMode
        ? originalServiceConsumer(value, lifetime, { plan, step, cohort: consumer, charge })
        : consumer(value, target==='listings-package'?listingsLifetime(lifetime,plan,step):registryLifetime(lifetime, plan, step)), handoff,
        { signal: controller.signal, retirementMs: REGISTRY_RETIREMENT_MS, phaseJoinMs: REGISTRY_PHASE_JOIN_MS,
          ...(serviceMode||managerMode ? { milliseconds: managerMode?600000:pairMode ? Math.max(1, Math.min(600000, Math.floor(workDeadline - performance.now()))) : 1320000, serviceMode: true } : {}) });
      consumerRetired = outcome.retired;
      if (consumerMode === 'original-service' && joinedConsumerFailures.has(outcome)
        && require('./ownedMcpOriginalServiceProducer').isRetiredFailure(outcome.error, handoff, plan)) retiredServiceFailure = outcome.error;
      consumerJournalAtRelease = consumerJournal.snapshot();
      if (!consumerJournalAtRelease.sealed) {
        consumerRetired = false;
        cleanupErrors.push('ORIGINAL_BUILD_CONSUMER_JOURNAL_UNJOINED');
      }
      if (outcome.error) throw outcome.error;
      result = outcome.value;
    } finally { liveHandoffs.delete(handoff); }
    await verifyPlanSources(plan);
   } catch (error) { primary = error; }
  let cleanupLeaseAdmitted = !leaseMode;
  if (leaseMode && intended && consumerRetired) try {
    await step('serviceLeasecleanup', {}, true); cleanupLeaseAdmitted = true;
  } catch (error) { cleanupErrors.push(error.code || error.message); }
  let retirementProven = !artifactsIntended || artifactRetired;
  if (cleanupLeaseAdmitted && artifactsIntended && !artifactRetired) try { retirementProven = (await step('retireArtifacts', {}, true)).trim() === 'absent';
    if (!retirementProven) throw fail('ORIGINAL_BUILD_ARTIFACT_RETIREMENT'); } catch (error) { cleanupErrors.push(error.code || error.message); }
  if (!consumerRetired) cleanupErrors.push('ORIGINAL_BUILD_CONSUMER_RETIREMENT_UNPROVEN');
  if (intended && retirementProven && consumerRetired && cleanupLeaseAdmitted) {
    if (artifactsIntended && !artifactRetired) try { await captureClosure(true, true); }
    catch (error) { cleanupErrors.push(error.code || error.message); }
    try { await step('stop', {}, true); } catch (error) { cleanupErrors.push(error.code || error.message); }
    try { await record('retirement-evidence.json', JSON.parse(await step('evidence', {}, true)), true); } catch (error) { cleanupErrors.push(error.code || error.message); }
    // Preserve the actual retained signature/index material, not just hashes.
    try {
      const archive = await fs.open(path.join(plan.spec.artifact, 'metadata-retained.tar'), 'wx', 0o600);
      let bytes = 0; const hash = crypto.createHash('sha256');
      try { await step('retainedExport', { sink: chunk => {
        if (!Buffer.isBuffer(chunk) || bytes + chunk.length > 145 * 1024 ** 2) throw fail('ORIGINAL_BUILD_ARCHIVE_LIMIT');
        bytes += chunk.length; hash.update(chunk); return archive.writeFile(chunk);
      } }, true); await archive.sync(); } finally { await archive.close(); }
      if (bytes < 1) throw fail('ORIGINAL_BUILD_ARCHIVE_EMPTY');
      await record('metadata-archive.json', { version: 1, file: 'metadata-retained.tar', bytes, sha256: hash.digest('hex'), qualificationComplete: false }, true);
    } catch (error) { cleanupErrors.push(error.code || error.message); }
    if (!cleanupErrors.length) try { if ((await step('cleanup', {}, true)).trim() !== 'absent') throw fail('ORIGINAL_BUILD_CLEANUP'); }
    catch (error) { cleanupErrors.push(error.code || error.message); }
  }
  try { if (before !== undefined && bounded._internals.checkInventory(await step('inventory', {}, true)) !== before) throw fail('ORIGINAL_BUILD_SHARED_STATE_CHANGED'); }
  catch (error) { cleanupErrors.push(error.code || error.message); }
  // Failure must not skip the source-after check that the success path performs.
  if (retiredServiceFailure) try { await verifyPlanSources(plan); }
  catch (error) { cleanupErrors.push(error.code || error.message); }
  if (interruptions.length && !primary) primary = fail('ORIGINAL_BUILD_INTERRUPTED');
  const receipt = { version: 1, runId, planSha256: expectedPlanSha256, controlled: runner !== executePhase,
    buildCompleted, qualificationComplete: false, cleanupVerified: cleanupErrors.length === 0,
    error: primary?.code || primary?.message || null, cleanupErrors, interruptions,
    // An outstanding filesystem promise cannot be cancelled by revoking a
    // capability. This is a debt-bearing, unsealed observation, not an
    // immutable-complete journal; resources remain retained above.
    consumerJournal: consumerJournalAtRelease || consumerJournal.snapshot() };
  await record('result.json', receipt, true);
  // Keep handlers installed through terminal publication. A late interruption
  // is separately durable and cannot silently return a successful callback.
  if (interruptions.length && !primary) {
    primary = fail('ORIGINAL_BUILD_INTERRUPTED');
    await record('terminal-interruption.json', { version: 1, error: primary.code, interruptions }, true);
  }
  if (primary || cleanupErrors.length) {
    const error = new AggregateError([primary, ...cleanupErrors.map(fail)].filter(Boolean), 'Original private build failed; retained journal is authoritative');
    if (runner === executePhase && consumerMode === 'original-service' && primary === retiredServiceFailure
      && primary && Number.isFinite(outerDeadline) && performance.now() < outerDeadline
      && buildCompleted && consumerRetired && cleanupLeaseAdmitted && retirementProven && before !== undefined
      && !cleanupErrors.length && !interruptions.length && !controller.signal.aborted
      && receipt.consumerJournal.sealed === true && receipt.consumerJournal.pendingOperations === 0) {
      const bytes = Buffer.from(JSON.stringify(receipt));
      failedRetirements.set(error, Object.freeze({ primary, plan, outerDeadline, planSha256: expectedPlanSha256,
        bytes: bytes.length, sha256: sha(bytes), sourceSha256: sourceBindingDigest(plan) }));
    }
    throw error;
  }
  return { result, receipt, artifact: plan.spec.artifact };
  } finally { clearTimeout(workTimer); for (const [signal, handler] of Object.entries(handlers)) process.removeListener(signal, handler); }
}

async function originalRegistryConsumer(handoff, lifetime) {
  if (handoff?.controlled === false) assertLiveHandoff(handoff);
  else if (handoff?.controlled !== true) throw fail('ORIGINAL_BUILD_HANDOFF_NOT_LIVE');
  const phase = lifetime.runRegistryPhase; let profileIntended = false, containerIntended = false, primary, result;
  const cleanupErrors = [];
  try {
    profileIntended = true; await phase('registryProfileInstall');
    containerIntended = true;
    const rows = JSON.parse(await phase('registryCreate')), row = rows?.[0];
    if (!Array.isArray(rows) || rows.length !== 1 || !/^[a-f0-9]{64}$/.test(row?.Id) || row.Image !== handoff.imageId
      || row.Name !== '/' + lifetime.registryName || row.Config?.Labels?.['owasp-ai-goat.original.registry'] !== handoff.runId) throw fail('ORIGINAL_BUILD_REGISTRY_IDENTITY');
    require('./ownedMcpRuntimeQualification')._internals.verifyBoundary({ profile: lifetime.registryName }, row);
    result = JSON.parse((await phase('registryStart')).trim());
    if (result?.status !== 'passed' || result.modelCalls !== 0 || result.qualificationComplete !== false
      || !/^[a-f0-9]{64}$/.test(result.runtimeDigest) || !Array.isArray(result.cases) || result.cases.length !== 12
      || result.cases.at(-1) !== 'immutable assets and all namespace descendants joined') throw fail('ORIGINAL_BUILD_REGISTRY_RECEIPT');
  } catch (error) { primary = error; }
  lifetime.beginRetirement();
  if (containerIntended) try { if ((await phase('registryRetire')).trim() !== 'absent') throw fail('ORIGINAL_BUILD_REGISTRY_RETIREMENT'); }
  catch (error) { cleanupErrors.push(error); }
  if (profileIntended && !cleanupErrors.length) try { if ((await phase('registryProfileRetire')).trim() !== 'absent') throw fail('ORIGINAL_BUILD_PROFILE_RETIREMENT'); }
  catch (error) { cleanupErrors.push(error); }
  if (cleanupErrors.length) {
    const error = new AggregateError([primary, ...cleanupErrors].filter(Boolean), 'Original registry consumer retirement unproven');
    error.retirementUnproven = true; throw error;
  }
  // This is the real call site: exact container/PID absence and profile unload
  // have completed through the reviewed private-runtime phases above.
  lifetime.confirmRetired();
  if (primary) throw primary;
  return { ...result, controlled: handoff.controlled, cleanupVerified: true, qualificationComplete: false };
}
function withOriginalRegistryFixture(options) {
  return withPrivateBuiltImage({ ...options, consumerMode: 'fixture', consumer: originalRegistryConsumer });
}

async function originalServiceConsumer(handoff, lifetime, { plan, step, cohort, charge, relayFactory }) {
  if (handoff?.controlled === false) assertLiveHandoff(handoff);
  else if (handoff?.controlled !== true) throw fail('ORIGINAL_BUILD_HANDOFF_NOT_LIVE');
  const native = require('node:fs'); let sequence = 0;
  const record = value => {
    lifetime.assertOpen();
    const bytes = Buffer.from(JSON.stringify(value)); charge(bytes.length);
    const file = path.join(plan.spec.artifact, 'service-' + String(++sequence).padStart(4, '0') + '.json');
    const fd = native.openSync(file, native.constants.O_WRONLY | native.constants.O_CREAT | native.constants.O_EXCL | native.constants.O_NOFOLLOW, 0o600);
    try {
      for (let offset = 0; offset < bytes.length;) {
        lifetime.assertOpen(); const count = native.writeSync(fd, bytes, offset, bytes.length - offset);
        if (count <= 0) throw fail('ORIGINAL_SERVICE_JOURNAL_WRITE'); offset += count;
      }
      native.fsyncSync(fd);
    } finally { native.closeSync(fd); }
    const directory = native.openSync(plan.spec.artifact, native.constants.O_RDONLY | native.constants.O_DIRECTORY);
    try { native.fsyncSync(directory); } finally { native.closeSync(directory); }
    lifetime.assertOpen();
  };
  return require('./ownedMcpOriginalServiceProducer').consume({ handoff, lifetime, plan, step, record, cohort, relayFactory });
}
function withOriginalRegistryService(options) {
  return withPrivateBuiltImage({ ...options, consumerMode: 'original-service' });
}

function withListingsManagerPhases(options) {
  if(!options||typeof options!=='object'||!options.socket||typeof options.socket.write!=='function')
    throw fail('LISTINGS_ENDPOINT_SOCKET');
  const {socket,...build}=options;
  // Uses the same builder and lifetime callback; no second image owner/daemon.
  return withPrivateBuiltImage({...build,target:'listings-package',listingsMode:'manager',consumerMode:'fixture',
    consumer:(handoff,lifetime)=>{
      if(handoff.controlled!==true)assertLiveHandoff(handoff);
      return require('./listingsPhaseEndpoint').serveListingsPhases(socket,
        {runId:build.runId,planSha256:build.expectedPlanSha256},lifetime);
    }});
}

async function pairEntry(argv) {
  const root = path.resolve(__dirname, '../..');
  const selected={'--v39-pair-plan':'v39-atomic-pair','--v39-pair-run':'v39-atomic-pair',
    '--q05-pair-plan':'q05-registered-pair','--q05-pair-run':'q05-registered-pair'};
  if (!Array.isArray(argv) || !Object.hasOwn(selected,argv[0])
    || !/^[a-f0-9]{32}$/.test(argv[1] || '') || argv.length !== (argv[0].endsWith('-plan') ? 2 : 4))
    throw fail(argv?.[0]?.startsWith('--q05-')?'Q05_PRIVATE_ENTRY_ARGUMENTS':'V39_PRIVATE_ENTRY_ARGUMENTS');
  const consumerMode=selected[argv[0]],q05=consumerMode==='q05-registered-pair';
  const runId = argv[1];
  if (argv[0].endsWith('-plan')) {
    const plan = await originalBuildPlan(root, runId, { consumerMode });
    process.stdout.write(JSON.stringify({ version: 1, runId, planSha256: planDigest(plan), plan }) + '\n'); return;
  }
  if (!/^[a-f0-9]{64}$/.test(argv[2]) || !/^(?:[3-9]|[1-9][0-9]{1,2})$/.test(argv[3])) throw fail(q05?'Q05_PRIVATE_ENTRY_ARGUMENTS':'V39_PRIVATE_ENTRY_ARGUMENTS');
  if (q05?!Q05_PRIVATE_ENABLED:!V39_PRIVATE_ENABLED) throw fail(q05?'Q05_PRIVATE_CONSUMER_NOT_ADMITTED':'V39_PRIVATE_CONSUMER_NOT_ADMITTED');
  const producer = require('./ownedMcpOriginalServiceProducer');
  const socket = new (require('node:net').Socket)({ fd: Number(argv[3]), readable: true, writable: true });
  const channel = producer.pairChannel(socket, { runId, planSha256: argv[2] });
  const started = performance.now(); let receipt = null, primary, workDeadline, freshArtifact = false;
  try {
    await channel.send('hello', {}, started + 15000);
    const admission = await channel.read('admit', ['remainingMs'], started + 15000);
    if (!Number.isSafeInteger(admission.remainingMs) || admission.remainingMs < 1 || admission.remainingMs > 960000)
      throw fail('V39_PRIVATE_DEADLINE');
    workDeadline = started + admission.remainingMs;
    try { await fs.lstat(path.join(root, 'tasks/tmp/v23-build-' + runId)); throw fail('V39_PRIVATE_ARTIFACT_EXISTS'); }
    catch(error) { if(error.code!=='ENOENT')throw error; freshArtifact=true; }
    const result = await withPrivateBuiltImage({ root, runId, expectedPlanSha256: argv[2], consumerMode,
      workDeadline, consumer: value => producer.pairCohort(channel, value) });
    receipt = result.receipt;
  } catch (error) { primary = error;
    // Exact freshly-owned producer path only; neither this receipt nor IPC
    // reconstructs a live handoff. The parent also requires process exit/join.
    try {
      if (!freshArtifact) throw fail('V39_PRIVATE_RESULT');
      const file = path.join(root, 'tasks/tmp/v23-build-' + runId, 'result.json');
      const handle = await fs.open(file, require('node:fs').constants.O_RDONLY | require('node:fs').constants.O_NOFOLLOW);
      try { const stat = await handle.stat();
        if (!stat.isFile() || stat.uid !== process.getuid() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || stat.size > 16384) throw fail('V39_PRIVATE_RESULT');
        receipt = JSON.parse(await handle.readFile('utf8'));
      } finally { await handle.close(); }
    } catch { receipt = null; }
  }
  try { await channel.send('terminal', { receipt, passed: !primary }, performance.now() + 5000); }
  finally { channel.close(); }
  if (primary) throw fail('V39_PRIVATE_RUN_FAILED');
}

async function listingsEntry(argv) {
  const root=path.resolve(__dirname,'../..');
  if(!Array.isArray(argv)||!['--listings-manager-plan','--listings-manager-run'].includes(argv[0])
    ||! /^[a-f0-9]{32}$/.test(argv[1]||'')||argv.length!==(argv[0].endsWith('-plan')?2:4))
    throw fail('LISTINGS_PRIVATE_ENTRY_ARGUMENTS');
  const runId=argv[1];
  if(argv[0].endsWith('-plan')){
    const plan=await originalBuildPlan(root,runId,{target:'listings-package',listingsMode:'manager'});
    process.stdout.write(JSON.stringify({version:1,runId,planSha256:planDigest(plan),plan})+'\n');return;
  }
  if(! /^[a-f0-9]{64}$/.test(argv[2])||! /^(?:[3-9]|[1-9][0-9]{1,2})$/.test(argv[3]))throw fail('LISTINGS_PRIVATE_ENTRY_ARGUMENTS');
  // Keep the admission switch before inherited capability access or allocation.
  if(!LISTINGS_PRIVATE_ENABLED)throw fail('LISTINGS_PRIVATE_CONSUMER_NOT_ADMITTED');
  const plan=await originalBuildPlan(root,runId,{target:'listings-package',listingsMode:'manager'});
  if(planDigest(plan)!==argv[2])throw fail('ORIGINAL_BUILD_PLAN_CHANGED');
  await verifyPlanSources(plan);
  const socket=new (require('node:net').Socket)({fd:Number(argv[3]),readable:true,writable:true});
  try{
    // The original endpoint begins only inside the retained image callback.
    // Its close is not builder retirement: the parent must also join process
    // exit and the original durable result after export/cleanup completes.
    await withListingsManagerPhases({root,runId,expectedPlanSha256:argv[2],socket});
  }finally{socket.destroy();}
}

module.exports = { derivedRelaySource, originalBuildPlan, planDigest, sourceBindingDigest, withPrivateBuiltImage, withOriginalRegistryFixture, withOriginalRegistryService, withListingsManagerPhases, assertLiveHandoff, claimFailedRetirement,
  _internals: { replaceOnce, guestMain, guestSource, createReplayFinalizer, guardFrom, createPhaseExecutor, verifyPlanSources,
    phaseTransport, PHASE_TRANSPORT, PHASE_DECODER, limaArgvEnvelope,
    validatePhysicalHandoff, validateClosureEvidence, validateReplayTerminal, boundedConsumer, registryLifetime, listingsLifetime, listingsConsumerPlan, listingsManagerProgram, captureListings, originalRegistryConsumer, registryConsumerPlan,
    REGISTRY_PHASE_JOIN_MS, REGISTRY_RETIREMENT_MS, createConsumerJournal, durableJson, originalServiceConsumer, pairEntry, listingsEntry } };
if (require.main === module) {
  const argv=process.argv.slice(2);
  (argv[0]?.startsWith('--listings-manager-')?listingsEntry(argv):pairEntry(argv)).catch(() => { process.exitCode = 1; });
}
