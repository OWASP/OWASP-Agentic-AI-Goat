'use strict';

// Guest-side artifact acquisition/reader for the ORIGINAL packaged registry
// Dockerfile. Import is inert. This is not metadata signature verification or
// permission to start a VM/build: the adapter must first replay original APT
// authentication using the retained signed indexes and pinned base keyring.
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');
const BASE = 'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1';
const NPM_LOCK_SHA256 = '9cc260a6311211f57d78282ff233b0145ec1a45bc26a0b1eb5de2179a2ba5488';
const LIMITS = Object.freeze({ artifact: 64 * 1024 ** 2, deb: 128 * 1024 ** 2,
  npm: 64 * 1024 ** 2, total: 192 * 1024 ** 2, artifacts: 250, milliseconds: 300000 });
// The complete original lock census reports 119,192,855 compressed bytes.
// Round only this closed profile's npm storage allowance to 114 MiB. Header
// estimates never replace body hashing; default/pricing policies are unchanged.
const ORIGINAL_BUILD_PROFILE = 'original-v23-registry';
const ORIGINAL_BUILD_LIMITS = Object.freeze({ ...LIMITS, npm: 114 * 1024 ** 2 });
function acquisitionLimits(profile = 'default') {
  if (profile === 'default') return LIMITS;
  if (profile === ORIGINAL_BUILD_PROFILE) return ORIGINAL_BUILD_LIMITS;
  throw fail('CLOSURE_BUDGET_PROFILE');
}
const STAGES = Object.freeze({ build: Object.freeze(['gcc', 'libc6-dev', 'libseccomp-dev']),
  runtime: Object.freeze(['bubblewrap', 'libseccomp2']) });
const fail = code => Object.assign(new Error(code), { code });
const hash = (bytes, algorithm = 'sha256') => crypto.createHash(algorithm).update(bytes).digest('hex');
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const digest = (value, algorithm) => typeof value === 'string'
  && new RegExp(`^[a-f0-9]{${algorithm === 'sha512' ? 128 : 64}}$`).test(value);
const objectName = row => hash(Buffer.from(`${row.algorithm}:${row.digest}`));
const TRANSPORT_STAGES = Object.freeze(['connect', 'tls', 'request', 'body']);
const ARTIFACT_STAGES = Object.freeze(['open', 'request', 'body', 'verify', 'publish']);
// Only the real private transport may attest a pre-response reset after all
// of its owned sockets have closed. Caller-supplied error fields are not proof.
const retiredPreResponseResets = new WeakSet();
function failureDiagnostic(error) {
  const row = error?.closureArtifact;
  const artifact = row && Number.isInteger(row.index) && row.index >= 0 && row.index < LIMITS.artifacts
    && ['deb', 'npm'].includes(row.kind) && ['sha256', 'sha512'].includes(row.algorithm)
    && digest(row.digest, row.algorithm) && ARTIFACT_STAGES.includes(row.stage)
    ? { index: row.index, kind: row.kind, algorithm: row.algorithm, digest: row.digest, stage: row.stage } : null;
  return { artifact, transport: TRANSPORT_STAGES.includes(error?.closureTransport) ? error.closureTransport : null };
}
function artifactUrl(value, kind) {
  let url;
  try { url = new URL(value); } catch { throw fail('CLOSURE_URL'); }
  if (url.href !== value || url.port || url.username || url.password || url.search || url.hash
    || /\\/.test(url.pathname) || url.pathname.split('/').some(part => part === '.' || part === '..')) throw fail('CLOSURE_URL');
  if (kind === 'npm') {
    if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.pathname.includes('%')
      || !/^\/(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+\/-\/[A-Za-z0-9._+-]+\.tgz$/.test(url.pathname)) throw fail('CLOSURE_URL');
  } else if (kind === 'deb') {
    // APT encodes version punctuation, but never permit an encoded path
    // delimiter, traversal character, percent, or arbitrary octet. Requests
    // keep the exact selected URL; only the Packages Filename join decodes it.
    const decoded = url.pathname.replace(/%(?:2b|7e|3a)/gi, value => decodeURIComponent(value));
    if (!['http:', 'https:'].includes(url.protocol) || url.hostname !== 'deb.debian.org'
      || !/^\/(?:debian|debian-security)\/pool\/[A-Za-z0-9_./+~:-]+\.deb$/.test(decoded)) throw fail('CLOSURE_URL');
  } else throw fail('CLOSURE_KIND');
  return url;
}
function npmArtifacts(bytes, expectedDigest = NPM_LOCK_SHA256) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 1024 ** 2 || hash(bytes) !== expectedDigest) throw fail('CLOSURE_NPM_LOCK_CHANGED');
  let lock;
  try { lock = JSON.parse(bytes); } catch { throw fail('CLOSURE_NPM_LOCK'); }
  if (lock.lockfileVersion !== 3 || !lock.packages || Array.isArray(lock.packages)) throw fail('CLOSURE_NPM_LOCK');
  const urls = new Map();
  for (const [name, row] of Object.entries(lock.packages)) {
    if (name === '') continue;
    if (!/^node_modules\/(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+(?:\/node_modules\/(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)*$/.test(name)
      || !row || row.link || typeof row.integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(row.integrity)) throw fail('CLOSURE_NPM_LOCK');
    artifactUrl(row.resolved, 'npm');
    const integrity = Buffer.from(row.integrity.slice(7), 'base64');
    if (integrity.length !== 64 || integrity.toString('base64') !== row.integrity.slice(7)) throw fail('CLOSURE_NPM_LOCK');
    const value = integrity.toString('hex'), existing = urls.get(row.resolved);
    if (existing && existing.digest !== value) throw fail('CLOSURE_NPM_CONFLICT');
    if (existing) existing.lockPaths.push(name);
    else urls.set(row.resolved, { kind: 'npm', algorithm: 'sha512', digest: value, bytes: null,
      urls: [row.resolved], lockPaths: [name] });
  }
  const result = [...urls.values()].sort((a, b) => a.urls[0].localeCompare(b.urls[0]));
  if (!result.length || result.length > 160) throw fail('CLOSURE_NPM_COUNT');
  for (const row of result) row.lockPaths.sort();
  return result;
}
function debArtifacts(stages) {
  if (!Array.isArray(stages) || stages.length !== 2) throw fail('CLOSURE_APT_STAGES');
  const artifacts = new Map(), names = new Map();
  for (let index = 0; index < stages.length; index++) {
    const stage = stages[index], name = ['build', 'runtime'][index];
    if (stage?.name !== name || !equal(stage.packages, STAGES[name]) || typeof stage.selection !== 'string'
      || Buffer.byteLength(stage.selection) > 1024 ** 2 || !Array.isArray(stage.selected)
      || !stage.selected.length || stage.selected.length > 128) throw fail('CLOSURE_APT_STAGES');
    const selected = new Map();
    for (const line of stage.selection.split('\n')) {
      if (!line.startsWith("'")) continue;
      const match = /^'([^']+)' \S+ ([0-9]+)(?: (?:SHA256:[a-f0-9]{64}|MD5Sum:[a-f0-9]{32}))?$/.exec(line.trim());
      if (!match) throw fail('CLOSURE_APT_SELECTION');
      const url = artifactUrl(match[1], 'deb');
      const filename = decodeURIComponent(url.pathname).replace(/^\/(?:debian|debian-security)\//, '');
      if (selected.has(filename)) throw fail('CLOSURE_APT_SELECTION');
      selected.set(filename, { url: url.href, bytes: Number(match[2]) });
    }
    if (selected.size !== stage.selected.length) throw fail('CLOSURE_APT_SELECTION');
    const stageNames = new Set();
    for (const row of stage.selected) {
      const choice = selected.get(row?.filename);
      if (!row || !/^[a-z0-9][a-z0-9+.-]*$/.test(row.name) || stageNames.has(row.name)
        || typeof row.version !== 'string' || !/^[A-Za-z0-9.+:~_-]+$/.test(row.version)
        || !['arm64', 'all'].includes(row.architecture) || !digest(row.sha256, 'sha256')
        || !Number.isSafeInteger(row.bytes) || row.bytes <= 0 || row.bytes > LIMITS.artifact
        || !choice || choice.bytes !== row.bytes) throw fail('CLOSURE_APT_PACKAGE');
      stageNames.add(row.name);
      const identity = JSON.stringify([row.version, row.architecture, row.filename, row.bytes, row.sha256]);
      if (names.has(row.name) && names.get(row.name) !== identity) throw fail('CLOSURE_APT_CONFLICT');
      names.set(row.name, identity);
      const existing = artifacts.get(row.sha256);
      if (existing && existing.bytes !== row.bytes) throw fail('CLOSURE_APT_CONFLICT');
      if (existing) {
        if (!existing.urls.includes(choice.url)) existing.urls.push(choice.url);
        existing.stages.push(name);
      } else artifacts.set(row.sha256, { kind: 'deb', algorithm: 'sha256', digest: row.sha256,
        bytes: row.bytes, urls: [choice.url], stages: [name] });
    }
  }
  return [...artifacts.values()].sort((a, b) => a.urls[0].localeCompare(b.urls[0]));
}
function planArtifacts({ npmLock, stages, base = BASE }) {
  if (base !== BASE) throw fail('CLOSURE_BASE');
  const npm = npmArtifacts(npmLock);
  if (npm.length !== 122 || npm.reduce((n, row) => n + row.lockPaths.length, 0) !== 124) throw fail('CLOSURE_NPM_COUNT');
  const artifacts = [...debArtifacts(stages), ...npm];
  validateArtifacts(artifacts);
  return { version: 1, target: 'original-v23-registry', base, npmLockSha256: hash(npmLock),
    artifacts, metadataAuthenticated: false, buildApproved: false };
}
function validateArtifacts(artifacts) {
  if (!Array.isArray(artifacts) || !artifacts.length || artifacts.length > LIMITS.artifacts) throw fail('CLOSURE_ARTIFACTS');
  const urls = new Set(), objects = new Set(); let debBytes = 0;
  for (const row of artifacts) {
    if (!row || row.algorithm !== (row.kind === 'npm' ? 'sha512' : 'sha256') || !digest(row.digest, row.algorithm)
      || !Array.isArray(row.urls) || !row.urls.length || row.urls.length > 4
      || row.kind === 'npm' && row.bytes !== null
      || row.kind === 'deb' && (!Number.isSafeInteger(row.bytes) || row.bytes <= 0 || row.bytes > LIMITS.artifact)) throw fail('CLOSURE_ARTIFACTS');
    const key = objectName(row);
    if (objects.has(key)) throw fail('CLOSURE_ARTIFACTS');
    objects.add(key);
    for (const url of row.urls) { artifactUrl(url, row.kind); if (urls.has(url)) throw fail('CLOSURE_ARTIFACTS'); urls.add(url); }
    if (row.kind === 'deb') debBytes += row.bytes;
  }
  if (debBytes > LIMITS.deb) throw fail('CLOSURE_BYTE_LIMIT');
}
async function privateDirectory(directory) {
  if (!path.isAbsolute(directory) || path.resolve(directory) !== directory || directory === '/'
    || await fs.realpath(directory) !== directory) throw fail('CLOSURE_DIRECTORY');
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || (stat.mode & 0o777) !== 0o700 || stat.uid !== process.getuid()) throw fail('CLOSURE_DIRECTORY');
}

// No direct socket or ambient proxy fallback. Caller supplies the admitted
// private namespace loopback CONNECT authority. URLs remain lock-bound; TLS
// validates the public origin even when Debian's original URI uses HTTP.
async function requestViaPrivateRelay(value, { authority, signal, method = 'GET', rangeProbe = false }) {
  const http = require('node:http'), tls = require('node:tls');
  const url = new URL(value);
  artifactUrl(value, url.hostname === 'registry.npmjs.org' ? 'npm' : 'deb');
  if (!['GET', 'HEAD'].includes(method) || method === 'HEAD' && url.hostname !== 'registry.npmjs.org') throw fail('CLOSURE_METHOD');
  if (typeof rangeProbe !== 'boolean' || rangeProbe && (method !== 'GET' || url.hostname !== 'registry.npmjs.org')) throw fail('CLOSURE_METHOD');
  const probe = method === 'HEAD' || rangeProbe, bodyLimit = rangeProbe ? 1 : 0;
  if (!exact(authority, ['host', 'port']) || authority.host !== '127.0.0.1'
    || !Number.isInteger(authority.port) || authority.port < 1 || authority.port > 65535) throw fail('CLOSURE_PRIVATE_RELAY_REQUIRED');
  if (signal.aborted) throw fail('CLOSURE_ABORTED');
  return new Promise((resolve, reject) => {
    const active = new Set(); let done = false, response, timer, transportStage = 'connect', headData = Buffer.alloc(0), headComplete = false, probeBody = 0;
    let closedResolve, closedReject, retirementError, httpEnded = false, tlsEnded = false;
    const closed = new Promise((resolve, reject) => { closedResolve = resolve; closedReject = reject; });
    // The response may still be consumed when retirement fails. Observe now;
    // acquireArtifacts still awaits this same promise before publication.
    closed.catch(() => {});
    const close = () => { if (!active.size && done) {
      if (!probe && retirementError) closedReject(retirementError); else closedResolve();
    } };
    const track = socket => { active.add(socket); socket.once('close', () => { active.delete(socket); close(); }); return socket; };
    const stop = error => {
      if (done) { if (!probe && error) retirementError ||= error; return; }
      retirementError = error; done = true; clearTimeout(timer); signal.removeEventListener('abort', abort);
      if (error) try { error.closureTransport = transportStage; } catch { /* Diagnostics never replace the primary error. */ }
      for (const item of active) item.destroy(error); close();
      if (!response) {
        const primary = error || fail('CLOSURE_TRANSPORT_CLOSED');
        if (probe || primary.code === 'ECONNRESET' && !signal.aborted) {
          // Header census must not report terminal failure while an owned
          // transport is silently left behind. A failed transfer's closed
          // promise rejects with the primary error, but either settlement
          // proves that its tracked sockets are absent.
          let settled = false;
          const retirement = setTimeout(() => { settled = true; primary.retirementUnproven = true; reject(primary); }, 1000);
          const joined = () => {
            if (settled) return;
            settled = true; clearTimeout(retirement);
            if (!probe && ['connect', 'tls', 'request'].includes(transportStage)) retiredPreResponseResets.add(primary);
            reject(primary);
          };
          closed.then(joined, joined);
        } else reject(primary);
      }
    };
    const abort = () => stop(fail('CLOSURE_ABORTED'));
    signal.addEventListener('abort', abort, { once: true });
    timer = setTimeout(() => stop(fail('CLOSURE_TRANSPORT_TIMEOUT')), 15000);
    const connect = track(http.request({ host: authority.host, port: authority.port, method: 'CONNECT',
      path: `${url.hostname}:443`, agent: false, maxHeaderSize: 8192,
      headers: { Host: `${url.hostname}:443` } }));
    connect.once('response', incoming => { incoming.destroy(); stop(fail('CLOSURE_CONNECT_STATUS')); });
    connect.on('error', stop);
    connect.once('connect', (incoming, socket, head) => {
      if (done) { socket.destroy(); return; }
      track(socket); socket.on('error', stop);
      if (incoming.statusCode !== 200 || head.length) return stop(fail('CLOSURE_CONNECT_STATUS'));
      transportStage = 'tls';
      const secure = track(tls.connect({ socket, servername: url.hostname, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] }));
      secure.on('error', stop);
      if (!probe) {
        // HTTP's Connection:close response handler invokes destroySoon after
        // body end. End only the TLS write side here, retaining the readable
        // side for the peer's pending TLS close_notify/EOF. The unchanged
        // acquisition AbortSignal bounds a peer that never finishes retiring.
        secure.destroySoon = () => secure.end();
        // TLS EOF may precede consumption of an already-buffered HTTP body.
        // Do not destroy IncomingMessage until its consumer has reached end.
        secure.once('end', () => {
          tlsEnded = true;
          if (!response) stop(fail('CLOSURE_TRANSPORT_CLOSED'));
          else if (httpEnded) stop();
        });
      }
      if (probe) secure.on('data', chunk => {
        // Node's HEAD parser deliberately ignores payload semantics. Meter the
        // authenticated tunnel bytes too, rejecting any response body instead
        // of treating it as a successful metadata-only acquisition.
        if (headComplete) { probeBody += chunk.length; if (probeBody > bodyLimit) stop(fail(rangeProbe ? 'CLOSURE_RANGE_BODY' : 'CLOSURE_HEAD_BODY')); return; }
        if (headData.length + chunk.length > 8192 + bodyLimit) return stop(fail('CLOSURE_HEAD_HEADERS'));
        headData = Buffer.concat([headData, chunk]);
        const end = headData.indexOf('\r\n\r\n');
        if (end >= 0) { headComplete = true; probeBody = headData.length - end - 4; headData = headData.subarray(0, end + 4);
          if (headData.length > 8192) return stop(fail('CLOSURE_HEAD_HEADERS'));
          if (probeBody > bodyLimit) stop(fail(rangeProbe ? 'CLOSURE_RANGE_BODY' : 'CLOSURE_HEAD_BODY')); }
      });
      secure.once('secureConnect', () => {
        if (done) return;
        if (!secure.authorized || secure.alpnProtocol && secure.alpnProtocol !== 'http/1.1') return stop(fail('CLOSURE_TLS_AUTHORITY'));
        transportStage = 'request';
        clearTimeout(timer);
        // Omit agent:false here: Node otherwise ignores createConnection and
        // creates an unintended direct connection instead of this TLS tunnel.
        const request = track(http.request({ method, host: url.hostname, port: 443, path: url.pathname,
          maxHeaderSize: 8192, createConnection: () => secure,
          headers: { Host: url.hostname, Connection: 'close', 'Accept-Encoding': 'identity', ...(rangeProbe ? { Range: 'bytes=0-0' } : {}) } }, incoming => {
          if (done) { incoming.on('error', () => {}); incoming.destroy(); return; }
          if (rangeProbe && incoming.statusCode !== 206) { incoming.on('error', () => {}); incoming.destroy(); stop(fail('CLOSURE_RANGE_STATUS')); return; }
          transportStage = 'body'; response = track(incoming);
          incoming.once('end', () => {
            if (probe) stop();
            else { httpEnded = true; secure.end(); secure.resume(); if (tlsEnded) stop(); }
          }); incoming.on('error', stop);
          resolve({ status: incoming.statusCode, headers: incoming.headers, rawHeaders: incoming.rawHeaders,
            headerBytes: probe ? headData.length : null, body: incoming, closed, destroy: stop });
        }));
        request.on('error', stop); request.end();
      });
    });
    connect.end();
  });
}
async function acquireArtifacts({ artifacts, directory, authority, signal, request = requestViaPrivateRelay,
  now = () => performance.now(), deadline, budgetProfile = 'default', attemptProof = false }) {
  if (typeof attemptProof !== 'boolean') throw fail('CLOSURE_ATTEMPT_PROFILE');
  const attempts = [];
  const limits = acquisitionLimits(budgetProfile);
  artifacts = structuredClone(artifacts);
  validateArtifacts(artifacts);
  await privateDirectory(path.dirname(directory));
  await fs.mkdir(directory, { mode: 0o700 });
  await privateDirectory(directory);
  await fs.mkdir(path.join(directory, 'objects'), { mode: 0o700 });
  const controller = new AbortController(), started = now(), bytes = { deb: 0, npm: 0, total: 0 }, rows = [];
  const end = deadline ?? started + LIMITS.milliseconds;
  if (!Number.isFinite(end) || end <= started || end - started > LIMITS.milliseconds) throw fail('CLOSURE_DEADLINE');
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  const timer = setTimeout(abort, end - started);
  const check = () => { if (controller.signal.aborted || now() >= end) throw fail('CLOSURE_ABORTED'); };
  let currentArtifact;
  try {
    for (const [index, row] of artifacts.entries()) {
      currentArtifact = { index, kind: row.kind, algorithm: row.algorithm, digest: row.digest, stage: 'open' };
      check();
      const key = objectName(row), partial = path.join(directory, 'objects', key + '.partial'), final = path.join(directory, 'objects', key);
      const fd = await fs.open(partial, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      let incoming, count = 0; const digestor = crypto.createHash(row.algorithm);
      try {
        currentArtifact.stage = 'request';
        const attempt = ordinal => {
          const item = { index, kind: row.kind, digest: row.digest, ordinal, outcome: 'started' };
          if (attemptProof) attempts.push(item);
          return item;
        };
        let activeAttempt = attempt(1);
        try { incoming = await request(row.urls[0], { authority, signal: controller.signal }); }
        catch (error) {
          if (request !== requestViaPrivateRelay || !retiredPreResponseResets.has(error)) {
            activeAttempt.outcome = 'failed'; throw error;
          }
          activeAttempt.outcome = 'retired-pre-response-reset';
          check();
          // This one extra GET is the same pinned URL and uses the same
          // cumulative relay budgets, AbortSignal and artifact digest.
          activeAttempt = attempt(2);
          try { incoming = await request(row.urls[0], { authority, signal: controller.signal }); }
          catch (error) { activeAttempt.outcome = 'failed'; throw error; }
        }
        check();
        if (incoming.status !== 200 || incoming.headers?.location || incoming.headers?.['content-encoding']
          || incoming.headers?.['content-range']) throw fail('CLOSURE_RESPONSE');
        const length = incoming.headers?.['content-length'];
        if (length !== undefined && (!/^[1-9][0-9]*$/.test(String(length)) || Number(length) > LIMITS.artifact
          || row.bytes !== null && Number(length) !== row.bytes)) throw fail('CLOSURE_RESPONSE_LENGTH');
        currentArtifact.stage = 'body';
        for await (const chunk of incoming.body) {
          check(); if (!Buffer.isBuffer(chunk)) throw fail('CLOSURE_NONBINARY');
          count += chunk.length; bytes[row.kind] += chunk.length; bytes.total += chunk.length;
          if (count > limits.artifact || row.bytes !== null && count > row.bytes || bytes[row.kind] > limits[row.kind]
            || bytes.total > limits.total) throw fail('CLOSURE_BYTE_LIMIT');
          digestor.update(chunk); await fd.writeFile(chunk);
        }
        await incoming.closed; check(); currentArtifact.stage = 'verify';
        if (!count || row.bytes !== null && count !== row.bytes || length !== undefined && count !== Number(length)
          || digestor.digest('hex') !== row.digest) throw fail('CLOSURE_INTEGRITY');
        await fd.chmod(0o400); await fd.sync();
        activeAttempt.outcome = 'verified';
      } finally {
        try { incoming?.destroy?.(); } finally {
          try { await incoming?.closed; } finally { await fd.close(); }
        }
      }
      // Exclusive publication: never replace an existing object or expose a
      // partially verified package under its final content-addressed name.
      currentArtifact.stage = 'publish';
      await fs.link(partial, final); await fs.unlink(partial);
      const directoryFd = await fs.open(path.dirname(final), constants.O_RDONLY);
      try { await directoryFd.sync(); } finally { await directoryFd.close(); }
      rows.push({ ...row, actualBytes: count, file: `objects/${key}` });
    }
    return { version: 1, ...(budgetProfile === 'default' ? {} : { budgetProfile }), artifactBytesVerified: true, metadataAuthenticated: false,
      buildApproved: false, qualificationComplete: false, bytes, artifacts: rows,
      ...(attemptProof ? { attemptProof: { version: 1, attempts } } : {}) };
  } catch (error) {
    try { error.closureArtifact = currentArtifact; if (attemptProof) error.closureAttempts = { version: 1, attempts }; } catch { /* Preserve a nonextensible primary error. */ }
    throw error;
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); controller.abort(); }
}
async function readVerifiedArtifact(directory, row) {
  await privateDirectory(directory); await privateDirectory(path.join(directory, 'objects'));
  if (row.file !== `objects/${objectName(row)}` || !Number.isSafeInteger(row.actualBytes)
    || row.actualBytes <= 0 || row.actualBytes > LIMITS.artifact) throw fail('CLOSURE_OBJECT');
  const fd = await fs.open(path.join(directory, row.file), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await fd.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size !== row.actualBytes || (before.mode & 0o777) !== 0o400
      || before.uid !== process.getuid()) throw fail('CLOSURE_OBJECT');
    const data = await fd.readFile(), after = await fd.stat();
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || data.length !== row.actualBytes
      || hash(data, row.algorithm) !== row.digest) throw fail('CLOSURE_OBJECT_CHANGED');
    return data;
  } finally { await fd.close(); }
}
function artifactReader(directory, receipt) {
  if (receipt?.version !== 1 || receipt.artifactBytesVerified !== true) throw fail('CLOSURE_RECEIPT');
  const rows = structuredClone(receipt.artifacts); validateArtifacts(rows);
  const byUrl = new Map(rows.flatMap(row => row.urls.map(url => [url, row])));
  return async url => { const row = byUrl.get(url); if (!row) throw fail('CLOSURE_UNLISTED_URL');
    const bytes = await readVerifiedArtifact(directory, row);
    return { bytes: bytes.length, stream: Readable.from([bytes]), sha256: hash(bytes) }; };
}
module.exports = { BASE, NPM_LOCK_SHA256, LIMITS, ORIGINAL_BUILD_PROFILE, ORIGINAL_BUILD_LIMITS, acquisitionLimits, STAGES, planArtifacts, acquireArtifacts, artifactReader,
  requestViaPrivateRelay, readVerifiedArtifact, failureDiagnostic,
  _internals: { npmArtifacts, debArtifacts, validateArtifacts, artifactUrl, objectName, hash } };
