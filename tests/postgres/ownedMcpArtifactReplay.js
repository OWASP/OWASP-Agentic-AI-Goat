'use strict';

// Offline-only replay for the unchanged Dockerfile's HTTP_PROXY/HTTPS_PROXY
// arguments and existing npm_ca secret. There is deliberately no upstream
// client, DNS lookup, cache miss fallback, or caller-selected CONNECT target.
const http = require('node:http');
const tls = require('node:tls');
const crypto = require('node:crypto');
const { once } = require('node:events');
const LIMITS = Object.freeze({ milliseconds: 300000, connections: 256, concurrent: 4,
  requests: 512, bytes: 512 * 1024 ** 2, headers: 8192 });
// An explicit local denial, never synthesized registry metadata. Source hashes
// are from the validated retained Node 26.10.0 original-image layer; the guest
// must independently match its actual installed files before selecting it.
const NPM_UPDATE_POLICY = Object.freeze({ version: 1, id: 'deny-npm-update-check-v1',
  url: 'https://registry.npmjs.org/npm', status: 403, maxDenials: 1, npmVersion: '11.19.1',
  sources: Object.freeze({
    'package.json': 'f6478d5600180a23f73e4217610c7709a71cedb4ae13f6c3e15ecb457f5d4fd6',
    'lib/cli/entry.js': '667a44c1fa8795fdbba8ad843736ca7f8f24e64511985e9a7060b002123560c6',
    'lib/cli/update-notifier.js': 'e91d75e236f1f9975f4f7ef5ddf424b8b60bf294c6d13d2b261088fd73e480f8',
    'node_modules/pacote/lib/registry.js': '306ffe4b4176c78c1118f09ee594616e843b7d708780dba930a82965a56c3d31',
    'node_modules/@npmcli/config/lib/definitions/definitions.js': 'f9cffb281460dfc5aa98f4f2e91a47052b814faece72fc9a80eaf3fff2ceb8eb'
  }) });
// The pinned npm definition has maxsockets=15. Waiting capacity is explicit;
// it does not increase the four simultaneous immutable artifact readers.
const FIFO_POLICY = Object.freeze({ version: 1, id: 'npm-fifo-4-plus-11-v1', active: 4, pending: 11, waitMilliseconds: 15000 });
const TLS_DECISIONS = Object.freeze(['no-connect', 'prior-failure', 'peer-terminal', 'parser-failure', 'destroyed', 'ended', 'errored', 'application-work', 'unfinished-http', 'established', 'callback-state', 'owner-branded']);
function validateTlsDiagnostics(value, connections, firstError, ownerIntents) {
  if (!value || Object.keys(value).sort().join(',') !== 'closeRequested,decisions,events,firstErrorSocket,saturated'
    || !Number.isSafeInteger(value.events) || value.events < 1 || value.events > 4096 || typeof value.saturated !== 'boolean'
    || value.saturated && value.events !== 4096 || !Number.isSafeInteger(value.closeRequested) || value.closeRequested < 1 || value.closeRequested > value.events
    || !value.decisions || Object.keys(value.decisions).sort().join(',') !== [...TLS_DECISIONS].sort().join(',')
    || Object.values(value.decisions).some(n => !Number.isSafeInteger(n) || n < 0)
    || Object.values(value.decisions).reduce((sum, n) => sum + n, 0) > connections
    || value.decisions['owner-branded'] !== ownerIntents) return false;
  const row = value.firstErrorSocket;
  if (firstError === null) return row === null;
  if (!row || Object.keys(row).sort().join(',') !== 'binding,connectBytes,connectionOrdinal,destroyed,ended,errored,eventBytes,eventOrdinal,peerTerminal,retirementBytes,retirementDecision'
    || !Number.isSafeInteger(row.eventOrdinal) || row.eventOrdinal < 1 || row.eventOrdinal > value.events) return false;
  const nullable = ['connectBytes', 'connectionOrdinal', 'destroyed', 'ended', 'errored', 'eventBytes', 'peerTerminal', 'retirementBytes', 'retirementDecision'];
  if (row.binding === 'unknown') return nullable.every(key => row[key] === null);
  return row.binding === 'exact-owned-connect' && Number.isSafeInteger(row.connectionOrdinal) && row.connectionOrdinal > 0 && row.connectionOrdinal <= connections
    && ['connectBytes', 'eventBytes', 'retirementBytes'].every(key => row[key] === null || Number.isSafeInteger(row[key]) && row[key] >= 0)
    && ['destroyed', 'ended', 'errored', 'peerTerminal'].every(key => typeof row[key] === 'boolean')
    && (row.retirementDecision === null ? row.retirementBytes === null : TLS_DECISIONS.includes(row.retirementDecision));
}
const npmWitnesses = new WeakSet();
async function verifyNpmUpdateSources(read) {
  if (typeof read !== 'function') throw fail('REPLAY_NPM_SOURCE');
  for (const [name, digest] of Object.entries(NPM_UPDATE_POLICY.sources)) {
    const bytes = await read('/usr/local/lib/node_modules/npm/' + name);
    if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 131072
      || crypto.createHash('sha256').update(bytes).digest('hex') !== digest
      || name === 'package.json' && JSON.parse(bytes).version !== NPM_UPDATE_POLICY.npmVersion) throw fail('REPLAY_NPM_SOURCE');
  }
  const witness = Object.freeze({ version: 1, policy: NPM_UPDATE_POLICY.id,
    npmVersion: NPM_UPDATE_POLICY.npmVersion, sources: NPM_UPDATE_POLICY.sources });
  npmWitnesses.add(witness); return witness;
}
function expectedNpmSourceWitness() {
  return { version: 1, policy: NPM_UPDATE_POLICY.id, npmVersion: NPM_UPDATE_POLICY.npmVersion, sources: NPM_UPDATE_POLICY.sources };
}
function validateNpmUpdateReceipt(value, requests, policy = 'strict') {
  if (!value || Object.keys(value).sort().join(',') !== 'denials,policy,sourceWitness'
    || value.policy !== policy || !Number.isSafeInteger(requests) || requests < 0
    || !Array.isArray(value.denials) || value.denials.length > NPM_UPDATE_POLICY.maxDenials) return false;
  if (policy === 'strict') return value.sourceWitness === null && value.denials.length === 0;
  if (policy !== NPM_UPDATE_POLICY.id || JSON.stringify(value.sourceWitness) !== JSON.stringify(expectedNpmSourceWitness())) return false;
  return value.denials.every(row => row && Number.isSafeInteger(row.requestOrdinal) && row.requestOrdinal > 0 && row.requestOrdinal <= requests
    && JSON.stringify(row) === JSON.stringify({ version: 1, sequence: 1, requestOrdinal: row.requestOrdinal,
      method: 'GET', url: NPM_UPDATE_POLICY.url, decision: 'local-deny', status: 403, bodyBytes: 0 }));
}
const fail = code => Object.assign(new Error(code), { code });
const FAILURE_CODES = Object.freeze(['REPLAY_FAILURE', 'REPLAY_REQUEST', 'REPLAY_URL', 'REPLAY_CONNECT',
  'REPLAY_RETIRED', 'REPLAY_REQUEST_LIMIT', 'REPLAY_OBJECT', 'REPLAY_NONBINARY', 'REPLAY_BYTE_LIMIT',
  'REPLAY_CLIENT_CLOSED', 'REPLAY_LENGTH', 'REPLAY_SNI', 'REPLAY_TLS', 'REPLAY_HTTP', 'REPLAY_UPGRADE',
  'REPLAY_IDLE', 'REPLAY_CONNECTION_LIMIT', 'REPLAY_DEADLINE', 'REPLAY_LISTEN', 'REPLAY_NPM_UPDATE_LIMIT',
  'CLOSURE_URL', 'CLOSURE_KIND', 'CLOSURE_DIRECTORY', 'CLOSURE_OBJECT', 'CLOSURE_OBJECT_CHANGED',
  'CLOSURE_RECEIPT', 'CLOSURE_UNLISTED_URL']);
const budgets = new WeakMap();
const queues = new WeakMap();
function createReplayBudget() {
  const token = Object.freeze({}); budgets.set(token, { requests: 0, connections: 0, bytes: 0, active: 0 });
  queues.set(token, []); return token;
}
// Per-run trust material, only for the already locked registry hostname. No
// system trust store changes and no external openssl/package dependency.
function replayCertificate(now = new Date()) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw fail('REPLAY_CERTIFICATE_TIME');
  const der = (tag, ...parts) => { const data = Buffer.concat(parts);
    let length = data.length, size = [];
    do { size.unshift(length & 255); length >>>= 8; } while (length);
    return Buffer.concat([Buffer.from([tag, ...(data.length < 128 ? [data.length] : [128 | size.length, ...size])]), data]); };
  const sequence = (...parts) => der(0x30, ...parts), oid = hex => der(6, Buffer.from(hex, 'hex'));
  const algorithm = sequence(oid('2a864886f70d01010b'), der(5));
  const name = sequence(der(0x31, sequence(oid('550403'), der(0x0c, Buffer.from('registry.npmjs.org')))));
  const time = date => der(0x18, Buffer.from(date.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z')));
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const serial = crypto.randomBytes(16); serial[0] &= 0x7f; serial[0] |= 1;
  const extension = (id, contents, critical = false) => sequence(oid(id), ...(critical ? [der(1, Buffer.from([255]))] : []), der(4, contents));
  const extensions = der(0xa3, sequence(
    extension('551d13', sequence(der(1, Buffer.from([255]))), true),
    extension('551d0f', der(3, Buffer.from([2, 0x84])), true),
    extension('551d25', sequence(oid('2b06010505070301'))),
    extension('551d11', sequence(der(0x82, Buffer.from('registry.npmjs.org'))))));
  const tbs = sequence(der(0xa0, der(2, Buffer.from([2]))), der(2, serial), algorithm, name,
    sequence(time(new Date(now.getTime() - 60000)), time(new Date(now.getTime() + 600000))), name,
    publicKey.export({ type: 'spki', format: 'der' }), extensions);
  const encoded = sequence(tbs, algorithm, der(3, Buffer.from([0]), crypto.sign('sha256', tbs, privateKey)));
  const cert = Buffer.from('-----BEGIN CERTIFICATE-----\n' + encoded.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n');
  const key = privateKey.export({ type: 'pkcs8', format: 'pem' });
  return { cert, key: Buffer.from(key) };
}
function target(request, encrypted = false) {
  if (request.method !== 'GET' || typeof request.url !== 'string' || request.url.length > 4096
    || request.headers?.authorization || request.headers?.['proxy-authorization'] || request.headers?.cookie
    || request.headers?.range || request.headers?.['transfer-encoding']
    || request.headers?.['content-length'] && request.headers['content-length'] !== '0') throw fail('REPLAY_REQUEST');
  let url;
  try { url = new URL(request.url, encrypted ? 'https://registry.npmjs.org' : undefined); } catch { throw fail('REPLAY_URL'); }
  if (url.username || url.password || url.port || url.search || url.hash || /\\/.test(url.pathname)
    || request.headers?.host !== url.host) throw fail('REPLAY_URL');
  if (encrypted) {
    if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.pathname.includes('%') || !request.url.startsWith('/') || request.url.startsWith('//')) throw fail('REPLAY_URL');
  } else if (url.protocol !== 'http:' || url.hostname !== 'deb.debian.org' || request.url !== url.href) throw fail('REPLAY_URL');
  if (!encrypted && url.pathname.includes('%')) require('./ownedMcpDependencyClosure')._internals.artifactUrl(url.href, 'deb');
  return url.href;
}
function connectTarget(request, head) {
  if (request.method !== 'CONNECT' || request.url !== 'registry.npmjs.org:443'
    || request.headers?.host !== request.url || head.length || request.headers?.authorization
    || request.headers?.['proxy-authorization'] || request.headers?.cookie
    || request.headers?.['transfer-encoding'] || request.headers?.['content-length']) throw fail('REPLAY_CONNECT');
}
// Disclosure authority comes from the frozen artifact selection, not lexical
// resemblance to a public package. This set NEVER authorizes a replay read.
function diagnosticTargets(urls) {
  if (!Array.isArray(urls) || urls.length > 1000) throw fail('REPLAY_DIAGNOSTIC_CONFIGURATION');
  const targets = new Set();
  for (const value of urls) {
    if (typeof value !== 'string' || value.length > 4096) throw fail('REPLAY_DIAGNOSTIC_CONFIGURATION');
    const url = new URL(value), npm = url.hostname === 'registry.npmjs.org';
    require('./ownedMcpDependencyClosure')._internals.artifactUrl(value, npm ? 'npm' : 'deb');
    targets.add(value);
    // Package metadata identity is derived only from a source-declared tarball.
    if (npm) targets.add(url.origin + url.pathname.slice(0, url.pathname.indexOf('/-/')));
  }
  return targets;
}
// Called only after target() rejects credentials, queries and foreign hosts.
// Unknown paths retain a hash/classification, never arbitrary path text.
function requestIdentity(value, diagnosticUrls = []) {
  const url = new URL(value), pathname = url.pathname;
  const declared = diagnosticTargets(diagnosticUrls);
  let pathClass = 'other';
  if (url.hostname === 'registry.npmjs.org') {
    if (/^\/(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+\/-\/[A-Za-z0-9._+-]+\.tgz$/.test(pathname)) pathClass = 'npm-tarball';
    else if (pathname.length <= 215 && /^\/(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(pathname)) pathClass = 'npm-package';
  } else if (/^\/(?:debian|debian-security)\/pool\/[A-Za-z0-9_./+~:%-]+\.deb$/.test(pathname)
    && !pathname.replace(/%(?:2b|7e|3a)/gi, '').includes('%')) pathClass = 'debian-artifact';
  return Object.freeze({ version: 1, method: 'GET', host: url.hostname, pathClass,
    path: pathClass !== 'other' && declared.has(value) ? pathname : null, pathBytes: Buffer.byteLength(pathname),
    urlSha256: crypto.createHash('sha256').update(value).digest('hex') });
}
function validateRequestIdentity(value, diagnosticUrls = []) {
  if (!value || Object.keys(value).sort().join(',') !== 'host,method,path,pathBytes,pathClass,urlSha256,version'
    || value.version !== 1 || value.method !== 'GET' || !['registry.npmjs.org', 'deb.debian.org'].includes(value.host)
    || !Number.isSafeInteger(value.pathBytes) || value.pathBytes < 1 || value.pathBytes > 4096
    || !/^[a-f0-9]{64}$/.test(value.urlSha256)) return false;
  if (!['other', 'npm-package', 'npm-tarball', 'debian-artifact'].includes(value.pathClass)
    || value.host === 'registry.npmjs.org' && value.pathClass === 'debian-artifact'
    || value.host === 'deb.debian.org' && value.pathClass.startsWith('npm-')) return false;
  if (value.path === null) return true;
  if (typeof value.path !== 'string' || Buffer.byteLength(value.path) !== value.pathBytes) return false;
  try {
    const encrypted = value.host === 'registry.npmjs.org';
    const url = `${encrypted ? 'https' : 'http'}://${value.host}${value.path}`;
    if (target({ method: 'GET', url: encrypted ? value.path : url, headers: { host: value.host } }, encrypted) !== url) return false;
    const expected = requestIdentity(url, diagnosticUrls);
    return Object.keys(expected).every(key => expected[key] === value[key]);
  } catch { return false; }
}
function createReplay({ read, key, cert, now = () => performance.now(), budget = createReplayBudget(), diagnosticUrls = [],
  npmUpdatePolicy = 'strict', npmSourceWitness = null, admissionPolicy = 'strict' }) {
  if (typeof read !== 'function' || !Buffer.isBuffer(key) || !Buffer.isBuffer(cert)
    || key.length > 16384 || cert.length > 16384 || !budgets.has(budget)) throw fail('REPLAY_CONFIGURATION');
  if (npmUpdatePolicy !== 'strict' && npmUpdatePolicy !== NPM_UPDATE_POLICY.id
    || npmUpdatePolicy === 'strict' && npmSourceWitness !== null
    || npmUpdatePolicy === NPM_UPDATE_POLICY.id && !npmWitnesses.has(npmSourceWitness)) throw fail('REPLAY_NPM_POLICY');
  if (admissionPolicy !== 'strict' && admissionPolicy !== FIFO_POLICY.id
    || admissionPolicy === FIFO_POLICY.id && (npmUpdatePolicy !== NPM_UPDATE_POLICY.id || !npmWitnesses.has(npmSourceWitness))) throw fail('REPLAY_NPM_POLICY');
  diagnosticTargets(diagnosticUrls);
  diagnosticUrls = Object.freeze([...diagnosticUrls]);
  const usage = budgets.get(budget), queue = queues.get(budget), waiting = new Set();
  const secureContext = tls.createSecureContext({ key, cert, minVersion: 'TLSv1.2' });
  const sockets = new Set(), responses = new Set(), work = new Set(), started = now();
  const connects = new WeakMap(), ownerErrors = new WeakMap();
  const connectionOrdinals = new WeakMap();
  const tlsDiagnostics = { events: 0, saturated: false, closeRequested: null,
    decisions: Object.fromEntries(TLS_DECISIONS.map(key => [key, 0])), firstErrorSocket: null };
  const eventOrdinal = () => { if (tlsDiagnostics.events < 4096) tlsDiagnostics.events++; else tlsDiagnostics.saturated = true; return tlsDiagnostics.events; };
  const boundedBytes = value => Number.isSafeInteger(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER ? value : null;
  const tlsRetirement = { ownerIntents: 0, ownerErrors: 0, firstError: null, callbackDebt: 0 };
  const establishedTls = new Set(), liveTls = new Set(), tlsServers = new Set(), tlsWaiters = new Set();
  let pendingHandshakes = 0;
  const tlsIdle = () => {
    if (!pendingHandshakes && !liveTls.size) { for (const resolve of tlsWaiters) resolve(); tlsWaiters.clear(); }
  };
  const finishHandshake = record => {
    if (!record.handshakeResolved) { record.handshakeResolved = true; pendingHandshakes--; }
  };
  const state = { active: 0, failure: null, closed: false }, denials = [];
  let peakPending = 0;
  const snapshot = () => ({ ...usage, ...state, tlsRetirement: { ...tlsRetirement, pendingHandshakes, establishedSockets: establishedTls.size, unjoinedTlsSockets: liveTls.size,
    diagnostics: { ...tlsDiagnostics, decisions: { ...tlsDiagnostics.decisions } } }, admission: { policy: admissionPolicy, pending: waiting.size, peakPending }, npmUpdate: { policy: npmUpdatePolicy,
    sourceWitness: npmSourceWitness, denials: [...denials] } });
  let timer, firstFailureRecord = null, notifyFailure;
  const firstFailure = new Promise(resolve => { notifyFailure = resolve; });
  const failClosed = (error, validatedUrl) => {
    if (!firstFailureRecord) {
      state.failure = FAILURE_CODES.includes(error?.code) ? error.code : 'REPLAY_FAILURE';
      firstFailureRecord = Object.freeze({ version: 1, cause: state.failure,
        ...(state.failure === 'CLOSURE_UNLISTED_URL' && validatedUrl ? { request: requestIdentity(validatedUrl, diagnosticUrls) } : {}),
        counters: Object.freeze({ requests: usage.requests, connections: usage.connections, bytes: usage.bytes, active: usage.active }) });
      notifyFailure(firstFailureRecord);
    }
    for (const entry of [...waiting]) entry.cancel(fail('REPLAY_RETIRED'));
    for (const response of responses) response.destroy();
    for (const socket of sockets) socket.destroy();
    // Admission and sockets close immediately. Keep the existing lifetime
    // timer until close(): the owner must durably preserve firstFailure and
    // join work, even when no later SIGTERM arrives.
    server.close();
  };
  const check = () => { if (state.closed || state.failure || now() - started >= LIMITS.milliseconds) throw fail('REPLAY_RETIRED'); };
  const drain = () => {
    while (usage.active < LIMITS.concurrent && queue.length) queue[0].grant();
  };
  const admit = (request, response) => new Promise((resolve, reject) => {
    let settled = false, deadline;
    const unlink = () => {
      clearTimeout(deadline); waiting.delete(entry);
      const index = queue.indexOf(entry); if (index >= 0) queue.splice(index, 1);
      request.removeListener('aborted', aborted); response.removeListener('close', aborted);
    };
    const aborted = () => entry.cancel(fail('REPLAY_CLIENT_CLOSED'));
    const entry = {
      cancel(error) { if (settled) return; settled = true; unlink(); reject(error); },
      grant() {
        if (settled) return;
        try { check(); if (request.aborted || response.destroyed || request.socket?.destroyed) throw fail('REPLAY_CLIENT_CLOSED'); }
        catch (error) { entry.cancel(error); return; }
        settled = true; unlink(); usage.active++; state.active++;
        let released = false;
        resolve(() => { if (released) return; released = true; usage.active--; state.active--; drain(); });
      }
    };
    if (usage.active < LIMITS.concurrent && !queue.length) return entry.grant();
    if (queue.length >= FIFO_POLICY.pending) return entry.cancel(fail('REPLAY_REQUEST_LIMIT'));
    waiting.add(entry); queue.push(entry); peakPending = Math.max(peakPending, waiting.size);
    request.once('aborted', aborted); response.once('close', aborted);
    deadline = setTimeout(() => entry.cancel(fail('REPLAY_IDLE')), Math.min(FIFO_POLICY.waitMilliseconds, Math.max(1, LIMITS.milliseconds - (now() - started))));
    if (request.aborted || response.destroyed || request.socket?.destroyed) aborted();
  });
  async function handle(request, response, encrypted) {
    let entered = false, release, stream, url;
    try {
      check(); url = target(request, encrypted);
      const requestOrdinal = ++usage.requests; responses.add(response);
      if (admissionPolicy === FIFO_POLICY.id) {
        if (usage.requests > LIMITS.requests) throw fail('REPLAY_REQUEST_LIMIT');
        release = await admit(request, response); check();
        if (request.aborted || response.destroyed || request.socket?.destroyed) throw fail('REPLAY_CLIENT_CLOSED');
      } else {
        usage.active++; state.active++; entered = true;
        if (usage.requests > LIMITS.requests || usage.active > LIMITS.concurrent || queue.length) throw fail('REPLAY_REQUEST_LIMIT');
      }
      if (npmUpdatePolicy === NPM_UPDATE_POLICY.id && encrypted && request.url === '/npm' && url === NPM_UPDATE_POLICY.url) {
        if (denials.length >= NPM_UPDATE_POLICY.maxDenials) throw fail('REPLAY_NPM_UPDATE_LIMIT');
        denials.push(Object.freeze({ version: 1, sequence: 1, requestOrdinal,
          method: 'GET', url: NPM_UPDATE_POLICY.url, decision: 'local-deny', status: 403, bodyBytes: 0 }));
        response.writeHead(403, { 'content-length': '0', 'cache-control': 'no-store', connection: 'close' });
        response.end(); return;
      }
      const value = await read(url); check();
      if (!value || !Number.isSafeInteger(value.bytes) || value.bytes <= 0 || value.bytes > 64 * 1024 ** 2
        || !/^[a-f0-9]{64}$/.test(value.sha256) || !value.stream?.[Symbol.asyncIterator]) throw fail('REPLAY_OBJECT');
      stream = value.stream;
      // Reader verifies complete immutable bytes before returning a stream.
      response.writeHead(200, { 'content-length': String(value.bytes), 'content-type': 'application/octet-stream',
        'cache-control': 'no-store', connection: 'close' });
      let count = 0;
      for await (const chunk of stream) {
        check(); if (!Buffer.isBuffer(chunk)) throw fail('REPLAY_NONBINARY');
        count += chunk.length; usage.bytes += chunk.length;
        if (count > value.bytes || usage.bytes > LIMITS.bytes) throw fail('REPLAY_BYTE_LIMIT');
        if (!response.write(chunk)) await Promise.race([once(response, 'drain'), once(response, 'close').then(() => { throw fail('REPLAY_CLIENT_CLOSED'); })]);
      }
      if (count !== value.bytes) throw fail('REPLAY_LENGTH');
      response.end();
    } catch (error) { failClosed(error, url); }
    finally { stream?.destroy?.(); responses.delete(response); release?.(); if (entered) { state.active--; usage.active--; drain(); } }
  }
  const dispatch = encrypted => (request, response) => {
    const pending = handle(request, response, encrypted); work.add(pending);
    pending.then(() => work.delete(pending), error => { work.delete(pending); failClosed(error); });
  };
  const server = http.createServer({ maxHeaderSize: LIMITS.headers }, dispatch(false));
  const inside = http.createServer({ maxHeaderSize: LIMITS.headers }, dispatch(true));
  server.on('error', () => failClosed(fail('REPLAY_LISTEN')));
  const retireRecord = record => {
    if (record.rawClosed && record.tlsClosed && record.handshakeResolved) record.phase = 'retired';
  };
  const callbackDebt = () => { tlsRetirement.callbackDebt = Math.min(4096, tlsRetirement.callbackDebt + 1); failClosed(fail('REPLAY_TLS')); };
  const trackTlsSocket = (record, socket) => {
    if (!socket || typeof socket.once !== 'function' || record.tlsSocket && record.tlsSocket !== socket) { callbackDebt(); return false; }
    if (!record.tlsSocket) {
      record.tlsSocket = socket;
      const closed = () => { record.tlsClosed = true; liveTls.delete(socket); establishedTls.delete(socket); retireRecord(record); tlsIdle(); };
      if (socket.closed) closed(); else {
        liveTls.add(socket); socket.once('close', closed);
        // tlsClientError can be emitted inside Node's current close event;
        // a listener added there may miss that dispatch. Observe the public
        // completed-close flag after the stack, never infer it from destroy().
        setImmediate(() => { if (socket.closed) closed(); });
      }
    }
    return true;
  };
  const tlsError = (record, error, socket) => {
    if (!trackTlsSocket(record, socket)) return;
    const errorOrdinal = eventOrdinal();
    const owned = ownerErrors.get(error);
    const firstCallback = !record.handshakeResolved;
    if (!firstCallback || !['pending', 'owner-cancelling'].includes(record.phase)) { callbackDebt(); return; }
    finishHandshake(record);
    // This server's callback closes over the exact accepted CONNECT record.
    // No private Node parent field, error code, or global closed flag confers
    // authority. Only the same owner's unique cancellation object can match.
    if (owned === record && state.closed && record.phase === 'owner-cancelling'
      && record.socket.destroyed && !record.counted && !record.peerTerminal && !record.parserFailure) {
      record.counted = true; record.phase = 'cancelled'; tlsRetirement.ownerErrors++; retireRecord(record); tlsIdle(); return;
    }
    record.parserFailure = true; record.phase = 'failed';
    if (!tlsRetirement.firstError) {
      const raw = record.socket;
      tlsDiagnostics.firstErrorSocket = Object.freeze({ eventOrdinal: errorOrdinal,
        binding: 'exact-owned-connect', connectionOrdinal: connectionOrdinals.get(raw),
        connectBytes: boundedBytes(record.bytesRead),
        retirementBytes: record?.retirement?.bytes ?? null,
        eventBytes: boundedBytes(raw.bytesRead),
        retirementDecision: record?.retirement?.decision ?? null,
        peerTerminal: record.peerTerminal, destroyed: Boolean(raw.destroyed),
        ended: Boolean(raw.readableEnded), errored: Boolean(raw.errored) });
      tlsRetirement.firstError = Object.freeze({
      code: ['ECONNRESET', 'ERR_TLS_HANDSHAKE_TIMEOUT', 'ERR_SSL_WRONG_VERSION_NUMBER', 'ERR_SSL_UNEXPECTED_MESSAGE'].includes(error?.code) ? error.code : 'TLS_OTHER',
      phase: state.closed ? 'owner-retiring' : 'serving', ownerError: Boolean(owned)
      });
    }
    failClosed(fail('REPLAY_TLS'));
    retireRecord(record); tlsIdle();
  };
  const startTls = record => {
    // One unlistening server per admitted CONNECT gives callbacks exact raw
    // ownership without widening the existing global connection budget.
    const secure = tls.createServer({ key, cert, minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'],
      SNICallback(name, callback) {
        if (name !== 'registry.npmjs.org') record.parserFailure = true;
        callback(name === 'registry.npmjs.org' ? null : fail('REPLAY_SNI'), secureContext);
      } });
    tlsServers.add(secure);
    secure.on('secureConnection', socket => {
      if (!trackTlsSocket(record, socket)) return;
      if (record.handshakeResolved || record.phase !== 'pending') { callbackDebt(); socket.destroy(); return; }
      finishHandshake(record); record.phase = 'established'; establishedTls.add(socket);
      if (socket.servername !== 'registry.npmjs.org' || socket.alpnProtocol && socket.alpnProtocol !== 'http/1.1') {
        record.parserFailure = true; failClosed(fail('REPLAY_SNI')); return;
      }
      // Transition precedes HTTP dispatch; a secureConnection racing close
      // cannot create new application work or become a pending cancellation.
      if (state.closed || state.failure) { socket.destroy(); return; }
      inside.emit('connection', socket);
    });
    secure.on('tlsClientError', (error, socket) => tlsError(record, error, socket));
    secure.on('error', () => { record.parserFailure = true; failClosed(fail('REPLAY_TLS')); });
    secure.emit('connection', record.socket);
  };
  for (const value of [server, inside]) {
    value.requestTimeout = 15000; value.headersTimeout = 10000;
    value.on('clientError', () => failClosed(fail('REPLAY_HTTP')));
    value.on('upgrade', (_request, socket) => { socket.destroy(); failClosed(fail('REPLAY_UPGRADE')); });
  }
  server.on('connection', socket => {
    eventOrdinal(); connectionOrdinals.set(socket, usage.connections + 1);
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => {}); socket.setTimeout(15000, () => failClosed(fail('REPLAY_IDLE')));
    usage.connections++;
    if (state.closed || state.failure) socket.destroy();
    else if (usage.connections > LIMITS.connections) failClosed(fail('REPLAY_CONNECTION_LIMIT'));
  });
  server.on('connect', (request, socket, head) => {
    try { check(); connectTarget(request, head);
      const record = { socket, bytesRead: socket.bytesRead, peerTerminal: false, parserFailure: false,
        counted: false, ownerIssued: false, phase: 'pending', handshakeResolved: false, rawClosed: false, tlsClosed: false, tlsSocket: null };
      connects.set(socket, record);
      eventOrdinal();
      socket.once('end', () => { eventOrdinal(); record.peerTerminal = true; });
      socket.on('error', error => { eventOrdinal(); if (ownerErrors.get(error) !== record) record.peerTerminal = true; });
      socket.once('close', () => { record.rawClosed = true; retireRecord(record); });
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); pendingHandshakes++; startTls(record); }
    catch (error) { socket.destroy(); failClosed(error); }
  });
  let closing;
  const close = () => closing ||= (async () => {
    state.closed = true; clearTimeout(timer);
    tlsDiagnostics.closeRequested = eventOrdinal();
    const quiescent = () => !state.failure && !usage.active && !state.active && !waiting.size && !queue.length && !work.size && !responses.size;
    const initiallyQuiescent = quiescent();
    for (const entry of [...waiting]) entry.cancel(fail('REPLAY_RETIRED'));
    // Let already queued peer EOF/TLS parser events become observable before
    // issuing owner error objects. A same-turn peer failure is not retirement.
    await new Promise(resolve => setImmediate(resolve));
    const retired = [...sockets].map(socket => new Promise(resolve => {
      socket.once('close', resolve);
      const record = connects.get(socket);
      const decision = !record ? 'no-connect' : state.failure ? 'prior-failure' : record.peerTerminal ? 'peer-terminal'
        : record.parserFailure ? 'parser-failure' : socket.destroyed ? 'destroyed' : socket.readableEnded ? 'ended' : socket.errored ? 'errored'
          : !initiallyQuiescent || !quiescent() ? 'application-work'
            // HTTP's native parser may consume decrypted input without JS
            // data events. The public TLS byte counter observes that input.
            // Responses use Connection: close; a still-open, input-bearing
            // established socket cannot be force-retired as an idle channel.
            : record.phase === 'established' ? record.tlsSocket?.bytesRead !== 0 ? 'unfinished-http' : 'established'
            : record.phase !== 'pending' || record.handshakeResolved ? 'callback-state' : 'owner-branded';
      eventOrdinal(); tlsDiagnostics.decisions[decision]++;
      if (record) record.retirement = Object.freeze({ decision, bytes: boundedBytes(socket.bytesRead) });
      if (decision === 'unfinished-http') failClosed(fail('REPLAY_HTTP'));
      if (decision === 'owner-branded') {
        const ownerError = fail('REPLAY_OWNER_RETIREMENT');
        record.phase = 'owner-cancelling'; record.ownerIssued = true; ownerErrors.set(ownerError, record); tlsRetirement.ownerIntents++;
        socket.destroy(ownerError);
      } else socket.destroy();
    }));
    for (const response of responses) response.destroy();
    retired.push(new Promise(resolve => { tlsWaiters.add(resolve); tlsIdle(); }));
    let listenerClosed = false;
    retired.push(new Promise(resolve => server.close(() => { listenerClosed = true; resolve(); })), ...work);
    for (const secure of tlsServers) secure.close(); inside.close();
    let deadline;
    await Promise.race([Promise.allSettled(retired), new Promise(resolve => { deadline = setTimeout(resolve, 1000); })]);
    clearTimeout(deadline);
    return { ...snapshot(), firstFailure: firstFailureRecord,
      absenceVerified: listenerClosed && sockets.size === 0 && work.size === 0 && state.active === 0 && waiting.size === 0
        && pendingHandshakes === 0 && establishedTls.size === 0 && liveTls.size === 0 && tlsRetirement.callbackDebt === 0
        && tlsRetirement.ownerErrors === tlsRetirement.ownerIntents,
      offlineOnly: true, qualificationComplete: false };
  })();
  async function listen() {
    check(); if (server.listening) throw fail('REPLAY_ALREADY_LISTENING');
    timer = setTimeout(() => failClosed(fail('REPLAY_DEADLINE')), LIMITS.milliseconds);
    try { await new Promise((resolve, reject) => {
      server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
    }); } catch (error) { failClosed(fail('REPLAY_LISTEN')); throw error; }
    const address = server.address();
    if (!address || address.address !== '127.0.0.1' || !Number.isInteger(address.port)) { failClosed(fail('REPLAY_LISTEN')); throw fail('REPLAY_LISTEN'); }
    return { host: '127.0.0.1', port: address.port };
  }
  return Object.freeze({ listen, close, state: snapshot, firstFailure, failureRecord: () => firstFailureRecord,
    // In-memory socket seam exercises actual HTTP/TLS parsers without opening a
    // listener in controlled tests. It is not evidence of guest containment.
    acceptSocket: socket => server.emit('connection', socket) });
}
module.exports = { LIMITS, FAILURE_CODES, NPM_UPDATE_POLICY, FIFO_POLICY, TLS_DECISIONS, validateTlsDiagnostics, verifyNpmUpdateSources, expectedNpmSourceWitness, validateNpmUpdateReceipt,
  replayCertificate, createReplay, createReplayBudget, validateRequestIdentity,
  _internals: { target, connectTarget, requestIdentity } };
