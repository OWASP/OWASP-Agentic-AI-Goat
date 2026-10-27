'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { Duplex, Readable } = require('node:stream');
const { once } = require('node:events');
const crypto = require('node:crypto'), tls = require('node:tls');
const replay = require('./postgres/ownedMcpArtifactReplay');
const certificate = replay.replayCertificate();
test('controlled actual Node TLS distinguishes an explicit owner destroy error from peer termination', async () => {
  for (const mode of ['plain-owner-close', 'branded-owner-close', 'peer-close']) {
    const [raw, peer] = pair(), server = tls.createServer(certificate);
    raw.allowHalfOpen = false;
    const ownerError = Object.assign(new Error('controlled owner retirement'), { code: 'CONTROLLED_OWNER_RETIREMENT' });
    const event = new Promise(resolve => server.once('tlsClientError', (error, socket) => resolve({ error, socket })));
    server.emit('connection', raw);
    await new Promise(resolve => setImmediate(resolve));
    if (mode === 'peer-close') peer.end(); else raw.destroy(mode === 'branded-owner-close' ? ownerError : undefined);
    let timer;
    const observed = await Promise.race([event, new Promise((_, reject) => { timer = setTimeout(() => reject(Error('missing controlled TLS event')), 1000); })]);
    clearTimeout(timer); raw.destroy(); peer.destroy(); server.close();
    console.log(JSON.stringify({ controlledTls: mode, code: observed.error.code, exactOwnerError: observed.error === ownerError }));
    assert.equal(observed.error === ownerError, mode === 'branded-owner-close');
    if (mode !== 'branded-owner-close') assert.equal(observed.error.code, 'ECONNRESET');
  }
});
const payload = Buffer.from('controlled immutable replay bytes');
const sha256 = crypto.createHash('sha256').update(payload).digest('hex');
let npmSourcesPromise;
function pinnedNpmSources() {
  return npmSourcesPromise ||= (async () => {
    const fs = require('node:fs'), { pipeline } = require('node:stream/promises'), tar = require('tar-stream');
    const archive = require('node:path').join(__dirname, '../tasks/tmp/v23-build-f7314e2a960b4d88a9c32700ecb615f2/image.tar');
    const layer = '0701fef3c44d4ae061dac2e423732cc12045666636991ea9ff6fe90ac30f02aa';
    const wanted = new Set(Object.keys(replay.NPM_UPDATE_POLICY.sources).map(name => 'usr/local/lib/node_modules/npm/' + name));
    const found = new Map(), outer = tar.extract(), hash = crypto.createHash('sha256'); let total = 0;
    outer.on('entry', (header, stream, next) => {
      (async () => {
        if (header.name === 'blobs/sha256/' + layer) {
          const inner = tar.extract(), digest = crypto.createHash('sha256'); stream.on('data', chunk => digest.update(chunk));
          inner.on('entry', (entry, value, done) => {
            (async () => {
              if (wanted.has(entry.name)) {
                assert.equal(entry.type, 'file'); assert.equal(entry.mode, 0o644); assert.ok(entry.size <= 131072); assert.ok(!found.has('/' + entry.name));
                const chunks = []; for await (const chunk of value) chunks.push(chunk);
                found.set('/' + entry.name, Buffer.concat(chunks));
              } else for await (const chunk of value) { /* bounded existing layer, no extraction */ }
              done();
            })().catch(error => inner.destroy(error));
          });
          await pipeline(stream, inner); assert.equal(digest.digest('hex'), layer);
        } else for await (const chunk of stream) { /* existing archive only */ }
        next();
      })().catch(error => outer.destroy(error));
    });
    const input = fs.createReadStream(archive); input.on('data', chunk => { total += chunk.length; hash.update(chunk); if (total > 438994944) input.destroy(Error('archive bound')); });
    await pipeline(input, outer); assert.equal(total, 438994944);
    assert.equal(hash.digest('hex'), 'c0c9404e2e69cb52c8159c59538eb35d103111ece109ff6c400dd1f0fcb66bfa');
    assert.equal(found.size, wanted.size); return found;
  })();
}
async function policyOptions() {
  const files = await pinnedNpmSources();
  return { npmUpdatePolicy: replay.NPM_UPDATE_POLICY.id,
    npmSourceWitness: await replay.verifyNpmUpdateSources(async file => files.get(file)) };
}
function pair() {
  let left, right;
  const endpoint = other => new Duplex({ allowHalfOpen: false, read() {}, write(chunk, _encoding, callback) { other().bytesRead += chunk.length; other().push(Buffer.from(chunk)); callback(); },
    final(callback) { other().push(null); callback(); }, destroy(error, callback) { other().push(null); callback(error); } });
  left = endpoint(() => right); right = endpoint(() => left);
  left.bytesRead = right.bytesRead = 0;
  left.setTimeout = right.setTimeout = () => {}; left.setNoDelay = right.setNoDelay = () => {};
  left.on('error', () => {}); right.on('error', () => {});
  return [left, right];
}
async function collect(stream) { const chunks = []; for await (const chunk of stream) chunks.push(chunk); return Buffer.concat(chunks); }
function service(t, read, options = {}) {
  const value = replay.createReplay({ ...certificate, read, ...options }); t.after(() => value.close()); return value;
}
async function tlsRequest(value, requestPath = '/npm', { method = 'GET', host = 'registry.npmjs.org', extra = '' } = {}) {
  const [server, client] = pair(); value.acceptSocket(server); const connected = once(client, 'data');
  client.write('CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n'); await connected;
  const secure = tls.connect({ socket: client, servername: 'registry.npmjs.org', ca: certificate.cert, ALPNProtocols: ['http/1.1'] });
  secure.on('error', () => {}); await once(secure, 'secureConnect');
  const output = collect(secure);
  secure.write(`${method} ${requestPath} HTTP/1.1\r\nHost: ${host}\r\n${extra}\r\n`);
  return (await output).toString();
}
async function pendingConnect(value) {
  const [raw, peer] = pair(); value.acceptSocket(raw); const connected = once(peer, 'data');
  peer.write('CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n'); await connected;
  return { raw, peer };
}
test('owner retirement joins untouched TLS handshakes without creating a semantic TLS failure', async t => {
  const value = service(t, async () => { throw Error('unexpected reader'); });
  const { peer } = await pendingConnect(value);
  const first = value.close(), second = value.close(); assert.equal(first, second);
  const result = await first; peer.destroy();
  assert.equal(result.failure, null); assert.equal(result.firstFailure, null); assert.equal(result.absenceVerified, true);
  const { diagnostics, ...retirement } = result.tlsRetirement;
  assert.deepEqual(retirement, { ownerIntents: 1, ownerErrors: 1, firstError: null, pendingHandshakes: 0, establishedSockets: 0, unjoinedTlsSockets: 0, callbackDebt: 0 });
  assert.equal(diagnostics.decisions['owner-branded'], 1);
  assert.equal(replay.validateTlsDiagnostics(diagnostics, result.connections, null, 1), true);
});
test('peer EOF, malformed TLS and both close races remain genuine immutable TLS failures', async t => {
  for (const mode of ['peer-first', 'malformed-first', 'peer-race', 'owner-peer-race', 'malformed-race', 'reset-first', 'reset-race', 'owner-reset-race']) {
    const value = service(t, async () => { throw Error('unexpected reader'); }), { raw, peer } = await pendingConnect(value);
    let closing;
    if (mode.startsWith('owner-')) closing = value.close();
    if (mode.includes('reset')) raw.destroy(Object.assign(Error('controlled peer reset'), { code: 'ECONNRESET' }));
    else if (mode.startsWith('malformed')) peer.write('not a TLS record\r\n'); else peer.end();
    if (mode.endsWith('first')) await value.firstFailure;
    closing ||= value.close(); const result = await closing; raw.destroy(); peer.destroy();
    assert.equal(result.failure, 'REPLAY_TLS', mode); assert.equal(result.firstFailure.cause, 'REPLAY_TLS', mode);
    assert.equal(result.tlsRetirement.ownerIntents, 0, mode); assert.equal(result.tlsRetirement.ownerErrors, 0, mode);
    assert.equal(result.tlsRetirement.firstError.ownerError, false, mode);
    assert.equal(result.tlsRetirement.pendingHandshakes, 0, mode); assert.equal(result.absenceVerified, true, mode);
    assert.equal(replay.validateTlsDiagnostics(result.tlsRetirement.diagnostics, result.connections, result.tlsRetirement.firstError, 0), true, mode);
    // Per-CONNECT server callbacks own the actual raw record even for Duplex.
    assert.equal(result.tlsRetirement.diagnostics.firstErrorSocket.binding, 'exact-owned-connect');
    assert.equal(result.tlsRetirement.diagnostics.firstErrorSocket.connectionOrdinal, 1);
    const first = result.firstFailure; assert.equal((await value.close()).firstFailure, first);
  }
});
test('actual ClientHello followed by stalled handshake is cancelled only by exact owner error', async t => {
  const value = service(t, async () => { throw Error('unexpected reader'); }), { raw, peer } = await pendingConnect(value);
  const baseline = raw.bytesRead; let heldBytes = 0;
  // The actual Node client sends ClientHello. Hold only the server reply in
  // this controlled transport (no listener/upstream), with a strict byte cap.
  raw._write = (chunk, _encoding, callback) => { heldBytes += chunk.length; callback(heldBytes <= 65536 ? undefined : Error('controlled reply cap')); };
  const client = tls.connect({ socket: peer, servername: 'registry.npmjs.org', ca: certificate.cert, ALPNProtocols: ['http/1.1'] });
  client.on('error', () => {});
  await until(() => raw.bytesRead > baseline && heldBytes > 0);
  assert.equal(value.state().tlsRetirement.pendingHandshakes, 1);
  const result = await value.close(); client.destroy(); peer.destroy();
  assert.equal(result.failure, null); assert.equal(result.tlsRetirement.firstError, null);
  assert.equal(result.tlsRetirement.ownerIntents, 1); assert.equal(result.tlsRetirement.ownerErrors, 1);
  assert.equal(result.tlsRetirement.diagnostics.decisions['owner-branded'], 1);
  assert.equal(result.tlsRetirement.diagnostics.firstErrorSocket, null);
  assert.equal(replay.validateTlsDiagnostics(result.tlsRetirement.diagnostics, result.connections, null, 1), true);
  assert.equal(result.absenceVerified, true);
  const first = result.tlsRetirement.diagnostics.firstErrorSocket;
  assert.equal((await value.close()).tlsRetirement.diagnostics.firstErrorSocket, first);
  assert.doesNotMatch(JSON.stringify(first), /ClientHello|BEGIN|secret|registry/);
});
test('TLS diagnostic validator rejects fabricated unknown socket bindings and unbounded fields', () => {
  const value = { events: 4, saturated: false, closeRequested: 3,
    decisions: Object.fromEntries(replay.TLS_DECISIONS.map(key => [key, key === 'established' ? 1 : 0])),
    firstErrorSocket: { eventOrdinal: 4, binding: 'unknown', connectionOrdinal: null, connectBytes: null,
      retirementBytes: null, eventBytes: null, retirementDecision: null, peerTerminal: null, destroyed: null, ended: null, errored: null } };
  assert.equal(replay.validateTlsDiagnostics(value, 1, {}, 0), true);
  for (const edit of [x => x.firstErrorSocket.connectionOrdinal = 1, x => x.firstErrorSocket.peerTerminal = false,
    x => x.firstErrorSocket.message = 'untrusted', x => x.events = 4097, x => x.saturated = true,
    x => x.decisions.established = 2, x => x.firstErrorSocket.eventOrdinal = 5]) {
    const changed = structuredClone(value); edit(changed); assert.equal(replay.validateTlsDiagnostics(changed, 1, {}, 0), false);
  }
});
test('incomplete ClientHello can be owner-cancelled without accepting any application request', async t => {
  const value = service(t, async () => { throw Error('unexpected reader'); }), { peer } = await pendingConnect(value);
  peer.write(Buffer.from([0x16]));
  const result = await value.close(); peer.destroy();
  assert.equal(result.failure, null); assert.equal(result.tlsRetirement.ownerIntents, 1); assert.equal(result.tlsRetirement.ownerErrors, 1);
  assert.equal(result.requests, 0); assert.equal(result.tlsRetirement.firstError, null); assert.equal(result.absenceVerified, true);
});
test('established TLS socket retirement is joined without branding a completed handshake', async t => {
  const value = service(t, async () => { throw Error('unexpected reader'); }), { peer } = await pendingConnect(value);
  const secure = tls.connect({ socket: peer, servername: 'registry.npmjs.org', ca: certificate.cert, ALPNProtocols: ['http/1.1'] });
  secure.on('error', () => {}); await once(secure, 'secureConnect');
  await until(() => value.state().tlsRetirement.establishedSockets === 1);
  const result = await value.close(); secure.destroy(); peer.destroy();
  assert.equal(result.failure, null); assert.equal(result.tlsRetirement.ownerIntents, 0);
  assert.equal(result.tlsRetirement.pendingHandshakes, 0); assert.equal(result.tlsRetirement.establishedSockets, 0);
  assert.equal(result.absenceVerified, true);
});
test('established partial HTTP headers and prohibited body cannot become owner handshake cancellation', async t => {
  for (const mode of ['headers', 'body']) {
    let reads = 0, serverSocket;
    const implementation = instrumentReplay(server => server.on('secureConnection', socket => { serverSocket = socket; }));
    const value = implementation.createReplay({ ...certificate, read: async () => { reads++; throw Error('unexpected read'); } });
    t.after(() => value.close());
    const { peer } = await pendingConnect(value);
    const client = tls.connect({ socket: peer, servername: 'registry.npmjs.org', ca: certificate.cert, ALPNProtocols: ['http/1.1'] });
    client.on('error', () => {}); await once(client, 'secureConnect');
    await until(() => value.state().tlsRetirement.establishedSockets === 1);
    const initialBytes = serverSocket.bytesRead;
    client.write(mode === 'headers' ? 'GET /fixture/-/fixture-1.tgz HTTP/1.1\r\nHost: registry.npmjs.org\r\n'
      : 'GET /fixture/-/fixture-1.tgz HTTP/1.1\r\nHost: registry.npmjs.org\r\nContent-Length: 1\r\n\r\n');
    await until(() => serverSocket.bytesRead > initialBytes || value.state().failure);
    const result = await value.close(); client.destroy(); peer.destroy();
    console.log(JSON.stringify({ controlledHttp: mode, initialBytes, bytesRead: serverSocket.bytesRead, decisions: result.tlsRetirement.diagnostics.decisions }));
    assert.ok(result.failure, mode); assert.equal(reads, 0); assert.equal(result.tlsRetirement.ownerIntents, 0);
    assert.equal(result.tlsRetirement.ownerErrors, 0); assert.equal(result.absenceVerified, true);
  }
});
function instrumentReplay(tlsHook, httpHook) {
  const source = require('node:fs').readFileSync(require.resolve('./postgres/ownedMcpArtifactReplay'), 'utf8'), module = { exports: {} };
  const actualHttp = require('node:http');
  new Function('require', 'module', 'exports', source)(id => id === 'node:tls'
    ? { ...tls, createServer: (...args) => { const value = tls.createServer(...args); tlsHook?.(value); return value; } }
    : id === 'node:http' && httpHook ? { ...actualHttp, createServer: (...args) => { const value = actualHttp.createServer(...args); httpHook(value); return value; } }
      : id.startsWith('./') ? require('./postgres/' + id.slice(2)) : require(id), module, module.exports);
  return module.exports;
}
test('owner error clone, missing callback, and duplicate callback cannot produce proven retirement', async () => {
  for (const mode of ['clone', 'missing', 'duplicate']) {
    const implementation = instrumentReplay(server => {
      const emit = server.emit;
      server.emit = function (name, error, ...args) {
        if (name === 'tlsClientError' && error?.code === 'REPLAY_OWNER_RETIREMENT') {
          if (mode === 'missing') return false;
          if (mode === 'clone') return emit.call(this, name, Object.assign(Error('controlled clone'), { code: error.code }), ...args);
          const result = emit.call(this, name, error, ...args); emit.call(this, name, error, ...args); return result;
        }
        return emit.call(this, name, error, ...args);
      };
    });
    const value = implementation.createReplay({ ...certificate, read: async () => { throw Error('unexpected read'); } }), { peer } = await pendingConnect(value);
    const result = await value.close(); peer.destroy();
    assert.equal(result.absenceVerified, false, mode); assert.equal(result.tlsRetirement.ownerIntents, 1);
    if (mode === 'duplicate') { assert.equal(result.tlsRetirement.callbackDebt, 1); assert.equal(result.tlsRetirement.pendingHandshakes, 0); }
    else assert.equal(result.tlsRetirement.ownerErrors, 0);
    if (mode === 'missing') assert.equal(result.tlsRetirement.pendingHandshakes, 1); else assert.equal(result.failure, 'REPLAY_TLS');
  }
});
test('secureConnection racing owner close transitions to established before any HTTP dispatch', async () => {
  let value, closePromise, reads = 0;
  const implementation = instrumentReplay(server => {
    const emit = server.emit;
    server.emit = function (name, ...args) { if (name === 'secureConnection') closePromise = value.close(); return emit.call(this, name, ...args); };
  });
  value = implementation.createReplay({ ...certificate, read: async () => { reads++; throw Error('unexpected read'); } });
  const { peer } = await pendingConnect(value), client = tls.connect({ socket: peer, servername: 'registry.npmjs.org', ca: certificate.cert, ALPNProtocols: ['http/1.1'] });
  client.on('error', () => {}); await until(() => Boolean(closePromise)); const result = await closePromise;
  client.destroy(); peer.destroy(); assert.equal(reads, 0); assert.equal(result.tlsRetirement.ownerIntents, 0);
  assert.equal(result.tlsRetirement.pendingHandshakes, 0); assert.equal(result.tlsRetirement.establishedSockets, 0); assert.equal(result.absenceVerified, true);
});
test('active request/body work forbids pending-handshake owner cancellation', async t => {
  let release, reads = 0;
  const value = service(t, async () => { reads++; await new Promise(resolve => { release = resolve; });
    return { bytes: payload.length, sha256, stream: Readable.from([payload]) }; });
  const output = tlsRequest(value, '/fixture/-/fixture-1.tgz').catch(() => '');
  await until(() => reads === 1); const { peer } = await pendingConnect(value);
  const closing = value.close(); release(); const result = await closing; await output; peer.destroy();
  assert.ok(result.failure); assert.equal(result.tlsRetirement.ownerIntents, 0); assert.equal(result.tlsRetirement.ownerErrors, 0);
  assert.equal(result.active, 0); assert.equal(result.absenceVerified, true);
});
test('queued HTTP completion with active zero is not full application quiescence', async () => {
  const servers = [], implementation = instrumentReplay(null, server => servers.push(server));
  const files = await pinnedNpmSources(), witness = await implementation.verifyNpmUpdateSources(async file => files.get(file));
  const value = implementation.createReplay({ ...certificate, npmUpdatePolicy: implementation.NPM_UPDATE_POLICY.id,
    npmSourceWitness: witness, read: async () => { throw Error('unexpected read'); } });
  const { peer } = await pendingConnect(value), { EventEmitter } = require('node:events');
  const response = Object.assign(new EventEmitter(), { writeHead() {}, end() {}, destroy() { this.destroyed = true; this.emit('close'); } });
  // Direct HTTP event seam is controlled, not an observed native request.
  // The actual async handler has settled, but dispatch's work-removal reaction
  // is still queued. active===0 alone must not authorize TLS cancellation.
  servers[1].emit('request', { method: 'GET', url: '/npm', headers: { host: 'registry.npmjs.org' } }, response);
  assert.equal(value.state().active, 0); assert.equal(value.state().failure, null);
  const result = await value.close(); peer.destroy();
  assert.equal(result.failure, 'REPLAY_TLS'); assert.equal(result.tlsRetirement.ownerIntents, 0);
  assert.equal(result.tlsRetirement.diagnostics.decisions['application-work'], 1); assert.equal(result.absenceVerified, true);
});
test('npm updater denial requires actual retained source hashes and an unforgeable local verification witness', async t => {
  const files = await pinnedNpmSources(), options = await policyOptions();
  assert.equal(options.npmSourceWitness.npmVersion, '11.19.1'); assert.ok(Object.isFrozen(options.npmSourceWitness));
  for (const name of files.keys()) await assert.rejects(replay.verifyNpmUpdateSources(async file => file === name ? Buffer.from('changed') : files.get(file)), { code: 'REPLAY_NPM_SOURCE' });
  for (const opt of [{ npmUpdatePolicy: 'other' }, { npmUpdatePolicy: replay.NPM_UPDATE_POLICY.id },
    { ...options, npmSourceWitness: structuredClone(options.npmSourceWitness) }, { npmSourceWitness: options.npmSourceWitness }])
    assert.throws(() => service(t, async () => {}, opt), { code: 'REPLAY_NPM_POLICY' });
  const value = service(t, async () => { throw Object.assign(Error('missing'), { code: 'CLOSURE_UNLISTED_URL' }); });
  assert.equal(await tlsRequest(value), ''); assert.equal(value.state().failure, 'CLOSURE_UNLISTED_URL');
  assert.equal(value.state().npmUpdate.policy, 'strict'); assert.deepEqual(value.state().npmUpdate.denials, []);
});
test('actual pinned updater source treats denied metadata as optional and supports explicit config opt-out', async () => {
  const files = await pinnedNpmSources(), source = files.get('/usr/local/lib/node_modules/npm/lib/cli/update-notifier.js').toString();
  let calls = 0, writes = 0;
  const modules = { 'ci-info': { isCI: false }, 'semver/functions/gt': () => { throw Error('unexpected version comparison'); },
    'semver/functions/gte': () => { throw Error('unexpected version comparison'); }, 'semver/functions/parse': () => ({ prerelease: [] }),
    'node:fs/promises': { stat: async () => { throw Error('controlled absent'); }, writeFile: async () => { writes++; } },
    'node:path': require('node:path'), pacote: { manifest: async (spec, options) => { calls++; assert.equal(spec, 'npm@*');
      assert.equal(options.cache, false); throw Object.assign(Error('local denied'), { code: 'E403' }); } } };
  const module = { exports: {} };
  new Function('require', 'module', 'exports', source)(name => { assert.ok(Object.hasOwn(modules, name)); return modules[name]; }, module, module.exports);
  const npm = { version: '11.19.1', config: { get: key => { assert.equal(key, 'update-notifier'); return true; } },
    flatOptions: { cache: '/controlled/cache', global: false }, command: 'ci', argv: [] };
  assert.equal(await module.exports(npm), null); assert.equal(calls, 1); assert.equal(writes, 1);
  npm.config.get = () => false; assert.equal(await module.exports(npm), null); assert.equal(calls, 1); assert.equal(writes, 1);
});
const turn = () => new Promise(resolve => setImmediate(resolve));
async function until(predicate) {
  for (let i = 0; i < 100; i++) { if (predicate()) return; await turn(); }
  assert.fail('controlled replay did not reach expected state');
}
function queuedRequest(value, index) {
  const [server, client] = pair(); value.acceptSocket(server);
  const output = collect(client).catch(() => Buffer.alloc(0));
  client.write(`GET http://deb.debian.org/debian/pool/main/f/f${index}.deb HTTP/1.1\r\nHost: deb.debian.org\r\nConnection: close\r\n\r\n`);
  return { server, client, output };
}
test('source-gated FIFO shares four readers and eleven waiting slots, then drains in arrival order', async t => {
  const options = { ...await policyOptions(), admissionPolicy: replay.FIFO_POLICY.id, budget: replay.createReplayBudget() };
  const sources = await pinnedNpmSources();
  assert.match(sources.get('/usr/local/lib/node_modules/npm/node_modules/@npmcli/config/lib/definitions/definitions.js').toString(), /maxsockets: new Definition\('maxsockets', \{\s+default: 15,/);
  for (const invalid of [{ admissionPolicy: replay.FIFO_POLICY.id }, { ...options, npmSourceWitness: structuredClone(options.npmSourceWitness) },
    { ...options, admissionPolicy: 'unbounded' }]) assert.throws(() => service(t, async () => {}, invalid), { code: 'REPLAY_NPM_POLICY' });
  const reads = [], releases = new Map();
  const read = async url => { reads.push(Number(/f(\d+)\.deb$/.exec(url)[1]));
    await new Promise(resolve => releases.set(reads.at(-1), resolve));
    return { bytes: payload.length, sha256, stream: Readable.from([payload]) }; };
  const a = service(t, read, options), b = service(t, read, options), requests = [];
  for (let i = 0; i < 15; i++) { requests.push(queuedRequest(i % 2 ? b : a, i)); await until(() => a.state().requests === i + 1); }
  assert.deepEqual(reads, [0, 1, 2, 3]); assert.equal(a.state().active + b.state().active, 4);
  assert.equal(a.state().admission.pending + b.state().admission.pending, 11);
  for (let i = 0; i < 15; i++) {
    releases.get(i)(); await requests[i].output;
    await until(() => reads.length === Math.min(15, i + 5));
    assert.ok(a.state().active + b.state().active <= 4);
  }
  assert.deepEqual(reads, Array.from({ length: 15 }, (_, i) => i));
  for (const value of [a, b]) { const result = await value.close(); assert.equal(result.absenceVerified, true);
    assert.equal(result.admission.pending, 0); assert.equal(result.failure, null); }
});
test('FIFO overflow preserves first failure, retires all waiting work, and never starts a fifth reader', async t => {
  const releases = [], options = { ...await policyOptions(), admissionPolicy: replay.FIFO_POLICY.id };
  const value = service(t, async () => { await new Promise(resolve => releases.push(resolve));
    return { bytes: payload.length, sha256, stream: Readable.from([payload]) }; }, options);
  const requests = [];
  for (let i = 0; i < 16; i++) { requests.push(queuedRequest(value, i)); await until(() => value.state().requests === i + 1); }
  const first = await value.firstFailure; assert.equal(first.cause, 'REPLAY_REQUEST_LIMIT'); assert.equal(first.counters.active, 4);
  assert.equal(value.state().admission.peakPending, 11); assert.equal(releases.length, 4);
  releases.forEach(resolve => resolve()); await Promise.all(requests.map(row => row.output));
  const result = await value.close(); assert.equal(result.absenceVerified, true); assert.equal(result.admission.pending, 0);
  assert.equal(result.active, 0); assert.equal(result.firstFailure, first); assert.equal(releases.length, 4);
});
test('FIFO socket abort before grant and release/abort race cannot dispatch queued artifact reads', async t => {
  for (const race of [false, true]) {
    const releases = [], value = service(t, async () => { await new Promise(resolve => releases.push(resolve));
      return { bytes: payload.length, sha256, stream: Readable.from([payload]) }; }, { ...await policyOptions(), admissionPolicy: replay.FIFO_POLICY.id });
    const requests = [];
    for (let i = 0; i < 5; i++) { requests.push(queuedRequest(value, i)); await until(() => value.state().requests === i + 1); }
    assert.equal(releases.length, 4); if (race) releases[0]();
    requests[4].server.destroy();
    await value.firstFailure; releases.forEach(resolve => resolve()); await Promise.all(requests.map(row => row.output));
    const result = await value.close(); assert.equal(releases.length, 4); assert.equal(result.admission.pending, 0);
    assert.equal(result.active, 0); assert.equal(result.absenceVerified, true);
  }
});
test('explicit retirement cancels every queued waiter without new reads and reports real join', async t => {
  const releases = [], value = service(t, async () => { await new Promise(resolve => releases.push(resolve));
    return { bytes: payload.length, sha256, stream: Readable.from([payload]) }; }, { ...await policyOptions(), admissionPolicy: replay.FIFO_POLICY.id });
  const requests = [];
  for (let i = 0; i < 15; i++) { requests.push(queuedRequest(value, i)); await until(() => value.state().requests === i + 1); }
  const closing = value.close(); releases.forEach(resolve => resolve()); const result = await closing;
  await Promise.all(requests.map(row => row.output)); assert.equal(releases.length, 4);
  assert.equal(result.admission.pending, 0); assert.equal(result.active, 0); assert.equal(result.absenceVerified, true);
});
test('FIFO grant/resume cancellation and elapsed deadline reject before reader invocation', async () => {
  const source = require('node:fs').readFileSync(require.resolve('./postgres/ownedMcpArtifactReplay'), 'utf8');
  const { EventEmitter } = require('node:events'), files = await pinnedNpmSources();
  for (const scenario of ['grant-abort', 'deadline']) {
    const servers = [], module = { exports: {} };
    const fakeHttp = { createServer(_options, handler) {
      const server = new EventEmitter(); server.on('request', handler); server.close = callback => callback?.(); servers.push(server); return server;
    } };
    new Function('require', 'module', 'exports', source)(id => id === 'node:http' ? fakeHttp : require(id), module, module.exports);
    const implementation = module.exports, witness = await implementation.verifyNpmUpdateSources(async file => files.get(file));
    let time = 0, reads = 0;
    const value = implementation.createReplay({ ...certificate, now: () => time, admissionPolicy: implementation.FIFO_POLICY.id,
      npmUpdatePolicy: implementation.NPM_UPDATE_POLICY.id, npmSourceWitness: witness, read: async () => { reads++; throw Error('must not read'); } });
    const request = Object.assign(new EventEmitter(), { method: 'GET', url: 'http://deb.debian.org/debian/fixture', headers: { host: 'deb.debian.org' }, socket: { destroyed: false } });
    const response = Object.assign(new EventEmitter(), { destroyed: false, destroy() { this.destroyed = true; this.emit('close'); } });
    servers[0].emit('request', request, response);
    // The slot is synchronously reserved but handle() has not resumed from
    // await admit(). Neither cancellation nor deadline may admit the read.
    assert.equal(value.state().active, 1);
    if (scenario === 'grant-abort') response.destroy(); else time = implementation.LIMITS.milliseconds;
    await value.firstFailure; const result = await value.close();
    assert.equal(reads, 0); assert.equal(result.active, 0); assert.equal(result.admission.pending, 0); assert.equal(result.absenceVerified, true);
  }
});
test('exact npm update check gets one truthful local empty403 without reader; locked artifacts still replay', async t => {
  let reads = 0;
  const value = service(t, async url => { reads++; assert.equal(url, 'https://registry.npmjs.org/fixture/-/fixture-1.tgz');
    return { bytes: payload.length, sha256, stream: Readable.from([payload]) }; }, await policyOptions());
  const denied = await tlsRequest(value);
  assert.match(denied, /^HTTP\/1\.1 403 Forbidden\r\n/); assert.match(denied, /content-length: 0\r\n/);
  assert.match(denied, /cache-control: no-store\r\n/); assert.equal(denied.split('\r\n\r\n')[1], '');
  assert.equal(reads, 0); assert.equal(value.state().failure, null); assert.equal(value.state().requests, 1); assert.equal(value.state().bytes, 0);
  const served = await tlsRequest(value, '/fixture/-/fixture-1.tgz'); assert.ok(served.endsWith(payload.toString())); assert.equal(reads, 1);
  const done = await value.close(); assert.equal(done.absenceVerified, true); assert.equal(done.npmUpdate.denials.length, 1);
  assert.equal(replay.validateNpmUpdateReceipt(done.npmUpdate, done.requests, replay.NPM_UPDATE_POLICY.id), true);
  assert.deepEqual(done.npmUpdate.denials[0], { version: 1, sequence: 1, requestOrdinal: 1, method: 'GET',
    url: 'https://registry.npmjs.org/npm', decision: 'local-deny', status: 403, bodyBytes: 0 });
});
test('second update check exhausts tight denial count and still fails closed without reader', async t => {
  let reads = 0; const value = service(t, async () => { reads++; }, await policyOptions());
  await tlsRequest(value); assert.equal(await tlsRequest(value), '');
  assert.equal(reads, 0); assert.equal(value.state().failure, 'REPLAY_NPM_UPDATE_LIMIT');
  assert.equal(value.state().requests, 2); assert.equal(value.state().npmUpdate.denials.length, 1);
});
test('updater denial never admits encoded, query, method, host, path-normalized or neighboring requests', async t => {
  for (const [requestPath, options] of [['/%6epm', {}], ['/npm?token=secret', {}], ['/npm/', {}], ['/npm/-/npm-1.tgz', {}],
    ['/x/../npm', {}], ['//npm', {}], ['/npm', { method: 'HEAD' }], ['/npm', { method: 'POST' }],
    ['/npm', { host: 'other.example' }], ['/npm', { extra: 'Authorization: Bearer secret\r\n' }]]) {
    let reads = 0; const value = service(t, async () => { reads++; throw Object.assign(Error('missing'), { code: 'CLOSURE_UNLISTED_URL' }); }, await policyOptions());
    assert.equal(await tlsRequest(value, requestPath, options), ''); assert.ok(value.state().failure);
    assert.deepEqual(value.state().npmUpdate.denials, []); assert.ok(reads <= 1);
  }
});
test('per-run certificate is self-signed, fixed to registry.npmjs.org, and temporary', () => {
  const cert = new crypto.X509Certificate(certificate.cert);
  assert.ok(cert.verify(cert.publicKey)); assert.equal(cert.checkHost('registry.npmjs.org'), 'registry.npmjs.org');
  assert.equal(cert.checkHost('other.npmjs.org'), undefined); assert.equal(cert.checkHost('localhost'), undefined);
  assert.ok(new Date(cert.validTo).getTime() - new Date(cert.validFrom).getTime() <= 660000);
  assert.notDeepEqual(replay.replayCertificate().cert, certificate.cert);
});
test('actual HTTP parser replays only exact plaintext Debian GET; bytes come from reader', async t => {
  let seen;
  const value = service(t, async url => { seen = url; return { bytes: payload.length, sha256, stream: Readable.from([payload]) }; });
  const [server, client] = pair(); value.acceptSocket(server);
  const result = collect(client);
  client.write('GET http://deb.debian.org/debian/pool/main/f/fixture.deb HTTP/1.1\r\nHost: deb.debian.org\r\nConnection: close\r\n\r\n');
  const output = (await result).toString();
  assert.equal(seen, 'http://deb.debian.org/debian/pool/main/f/fixture.deb');
  assert.match(output, /^HTTP\/1\.1 200 OK/); assert.ok(output.endsWith(payload.toString()));
  assert.equal(value.state().bytes, payload.length); assert.equal(value.state().failure, null);
});
test('actual CONNECT + TLS + HTTP parsers serve frozen npm bytes without DNS or a network listener', async t => {
  let seen;
  const value = service(t, async url => { seen = url; return { bytes: payload.length, sha256, stream: Readable.from([payload]) }; });
  const [server, client] = pair(); value.acceptSocket(server);
  const ready = once(client, 'data');
  client.write('CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n');
  assert.equal((await ready)[0].toString(), 'HTTP/1.1 200 Connection Established\r\n\r\n');
  const secure = tls.connect({ socket: client, servername: 'registry.npmjs.org', ca: certificate.cert, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] });
  secure.on('error', () => {}); await once(secure, 'secureConnect'); assert.equal(secure.authorized, true);
  const result = collect(secure);
  secure.write('GET /fixture/-/fixture-1.0.0.tgz HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n');
  const output = (await result).toString();
  assert.equal(seen, 'https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz');
  assert.match(output, /^HTTP\/1\.1 200 OK/); assert.ok(output.endsWith(payload.toString()));
  assert.equal(value.state().failure, null);
});
test('unknown frozen object terminates replay, never delegates to network or another reader', async t => {
  let calls = 0;
  const value = service(t, async () => { calls++; throw Object.assign(new Error('missing'), { code: 'CLOSURE_UNLISTED_URL' }); });
  const [server, client] = pair(); value.acceptSocket(server); const result = collect(client);
  client.write('GET http://deb.debian.org/debian/unlisted HTTP/1.1\r\nHost: deb.debian.org\r\n\r\n');
  assert.equal((await result).length, 0); assert.equal(calls, 1); assert.equal(value.state().failure, 'CLOSURE_UNLISTED_URL');
  const first = await value.firstFailure;
  assert.deepEqual(first, { version: 1, cause: 'CLOSURE_UNLISTED_URL',
    request: { version: 1, method: 'GET', host: 'deb.debian.org', pathClass: 'other', path: null, pathBytes: 16,
      urlSha256: crypto.createHash('sha256').update('http://deb.debian.org/debian/unlisted').digest('hex') },
    counters: { requests: 1, connections: 1, bytes: 0, active: 1 } });
  assert.ok(Object.isFrozen(first)); assert.ok(Object.isFrozen(first.counters)); assert.ok(Object.isFrozen(first.request));
  const [late, peer] = pair(); value.acceptSocket(late); peer.destroy();
  assert.equal(value.failureRecord(), first);
  assert.equal((await value.close()).firstFailure, first);
});
test('actual unlisted TLS package request survives serialized finalizer and a later retry cannot replace it', async t => {
  const { createReplayFinalizer } = require('./postgres/ownedMcpOriginalBuildAdapter')._internals;
  // Same serialized function used by guestSource, with actual replay parsers.
  const finalizer = new Function('return (' + createReplayFinalizer.toString() + ')')();
  const records = new Map(), binding = { runId: 'e'.repeat(32) }; let reads = 0;
  const diagnosticUrls = ['https://registry.npmjs.org/@scope/fixture/-/fixture-1.0.0.tgz'];
  const value = service(t, async () => { reads++; throw Object.assign(Error('untrusted error text'), { code: 'CLOSURE_UNLISTED_URL' }); }, { diagnosticUrls });
  diagnosticUrls.push('https://registry.npmjs.org/later/-/later-1.0.0.tgz');
  const finish = finalizer(value, async (name, bytes) => { assert.ok(!records.has(name)); records.set(name, JSON.parse(bytes)); }, binding, () => {});
  const [server, client] = pair(); value.acceptSocket(server);
  const connected = once(client, 'data');
  client.write('CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n'); await connected;
  const secure = tls.connect({ socket: client, servername: 'registry.npmjs.org', ca: certificate.cert, ALPNProtocols: ['http/1.1'] });
  secure.on('error', () => {}); await once(secure, 'secureConnect');
  const output = collect(secure);
  secure.write('GET /@scope/fixture/-/fixture-1.0.0.tgz HTTP/1.1\r\nHost: registry.npmjs.org\r\nX-Private: secret-header\r\n\r\n');
  const first = await value.firstFailure; await output; await finish();
  assert.equal(reads, 1); assert.equal(first.request.path, '/@scope/fixture/-/fixture-1.0.0.tgz');
  assert.equal(first.request.host, 'registry.npmjs.org'); assert.equal(first.request.pathClass, 'npm-tarball');
  assert.equal(first.request.urlSha256, crypto.createHash('sha256').update('https://registry.npmjs.org/@scope/fixture/-/fixture-1.0.0.tgz').digest('hex'));
  assert.equal(replay.validateRequestIdentity(first.request, diagnosticUrls), true);
  assert.equal(replay.validateRequestIdentity(first.request), false);
  const [late, retry] = pair(); value.acceptSocket(late); retry.write('GET http://deb.debian.org/debian/later HTTP/1.1\r\nHost: deb.debian.org\r\n\r\n'); retry.destroy();
  await new Promise(resolve => setImmediate(resolve)); assert.equal(value.failureRecord(), first);
  const terminal = records.get('replay-terminal.json');
  assert.deepEqual(terminal.firstFailure, first); assert.deepEqual(records.get('replay-failure.json'), { binding, ...first });
  assert.equal(terminal.absenceVerified, true); assert.equal(terminal.active, 0); assert.equal(terminal.failure, 'CLOSURE_UNLISTED_URL');
  assert.doesNotMatch(JSON.stringify([...records]), /secret-header|untrusted error text|later/);
});
test('request identity exposes only closed package grammar, validates hashes, and bounds fallback paths', () => {
  const diagnosticUrls = ['https://registry.npmjs.org/npm/-/npm-1.0.0.tgz',
    'https://registry.npmjs.org/@scope/fixture/-/fixture-1.0.0.tgz',
    'http://deb.debian.org/debian/pool/main/f/f_1%2bb1%7eu1_arm64.deb'];
  for (const [url, encrypted, pathClass] of [
    ['https://registry.npmjs.org/npm', true, 'npm-package'],
    ['https://registry.npmjs.org/@scope/fixture', true, 'npm-package'],
    ['http://deb.debian.org/debian/pool/main/f/f_1%2bb1%7eu1_arm64.deb', false, 'debian-artifact'],
    ['https://registry.npmjs.org/private/token/secret-value', true, 'other'],
    ['https://registry.npmjs.org/.npmrc', true, 'other'],
    ['https://registry.npmjs.org/_token_value', true, 'other'],
    ['https://registry.npmjs.org/unknown-secret-name', true, 'npm-package'],
    ['https://registry.npmjs.org/' + 'a'.repeat(4095), true, 'other']]) {
    const parsed = new URL(url), validated = replay._internals.target({ method: 'GET', url: encrypted ? parsed.pathname : url, headers: { host: parsed.host } }, encrypted);
    const identity = replay._internals.requestIdentity(validated, diagnosticUrls);
    assert.equal(identity.pathClass, pathClass); assert.equal(replay.validateRequestIdentity(identity, diagnosticUrls), true);
    if (url.includes('unknown-secret-name')) { assert.equal(identity.path, null); assert.doesNotMatch(JSON.stringify(identity), /unknown-secret-name/); }
    if (pathClass === 'other') { assert.equal(identity.path, null); assert.doesNotMatch(JSON.stringify(identity), /secret-value/); }
    for (const edit of [x => x.method = 'POST', x => x.host = 'private.example', x => x.pathBytes = 4097,
      x => x.headers = {}, x => x.urlSha256 = 'bad', x => x.path = '/?secret=value']) {
      const bad = structuredClone(identity); edit(bad); assert.equal(replay.validateRequestIdentity(bad, diagnosticUrls), false);
    }
  }
  // A syntactically valid unknown path, even with a matching digest, must not
  // become readable through caller-controlled diagnostic fields.
  const unknown = replay._internals.requestIdentity('https://registry.npmjs.org/unknown-secret-name', diagnosticUrls);
  assert.equal(replay.validateRequestIdentity({ ...unknown, path: '/unknown-secret-name' }, diagnosticUrls), false);
});
test('invalid secret-bearing requests fail before reader and never acquire an identity', async t => {
  for (const raw of [
    'GET http://deb.debian.org/debian/file?secret=query HTTP/1.1\r\nHost: deb.debian.org\r\n\r\n',
    'GET http://user:secret@deb.debian.org/debian/file HTTP/1.1\r\nHost: deb.debian.org\r\n\r\n',
    'GET http://deb.debian.org/debian/file HTTP/1.1\r\nHost: deb.debian.org\r\nAuthorization: Bearer secret\r\n\r\n',
    'GET http://deb.debian.org/debian/file HTTP/1.1\r\nHost: deb.debian.org\r\nCookie: secret\r\n\r\n']) {
    let calls = 0; const value = service(t, async () => { calls++; throw Object.assign(Error('secret'), { code: 'CLOSURE_UNLISTED_URL' }); });
    const [server, client] = pair(); value.acceptSocket(server); const output = collect(client); client.write(raw);
    const first = await value.firstFailure; await output; assert.equal(calls, 0);
    assert.equal(Object.hasOwn(first, 'request'), false); assert.doesNotMatch(JSON.stringify(first), /secret|user|Bearer|query/);
  }
});
test('diagnostic disclosure set is snapshotted and cannot make an unknown artifact readable or acceptable', async t => {
  const diagnosticUrls = [], url = 'http://deb.debian.org/debian/pool/main/s/secret.deb';
  let reads = 0;
  const value = service(t, async () => { reads++; throw Object.assign(Error('missing'), { code: 'CLOSURE_UNLISTED_URL' }); }, { diagnosticUrls });
  diagnosticUrls.push(url);
  const [server, client] = pair(); value.acceptSocket(server); const output = collect(client);
  client.write(`GET ${url} HTTP/1.1\r\nHost: deb.debian.org\r\n\r\n`);
  const first = await value.firstFailure; await output;
  assert.equal(reads, 1); assert.equal(first.cause, 'CLOSURE_UNLISTED_URL');
  assert.equal(first.request.path, null); assert.equal(first.request.pathClass, 'debian-artifact');
  assert.doesNotMatch(JSON.stringify(first), /secret\.deb/);
});
test('automatic first-failure notification never exposes arbitrary reader codes, messages or URLs', async t => {
  const secret = 'credential=https://private.example/token';
  const value = service(t, async () => { throw Object.assign(Error(secret), { code: secret }); });
  const [server, client] = pair(); value.acceptSocket(server); const output = collect(client);
  client.write('GET http://deb.debian.org/debian/file HTTP/1.1\r\nHost: deb.debian.org\r\n\r\n');
  const first = await value.firstFailure; await output;
  assert.equal(first.cause, 'REPLAY_FAILURE'); assert.doesNotMatch(JSON.stringify(first), /private|credential|token/);
  assert.equal(first.counters.active, 1); assert.equal(value.state().active, 0);
});
test('credentials, redirects, ranges, foreign authorities and non-GET operations fail before reader', () => {
  const request = { method: 'GET', url: 'http://deb.debian.org/debian/file', headers: { host: 'deb.debian.org' } };
  for (const change of [x => { x.method = 'POST'; }, x => { x.headers.authorization = 'Bearer fixture'; },
    x => { x.headers.range = 'bytes=1-2'; }, x => { x.url += '?redirect=other'; }, x => { x.headers.host = 'localhost'; },
    x => { x.url = 'http://localhost/debian/file'; }, x => { x.headers['transfer-encoding'] = 'chunked'; }]) {
    const value = structuredClone(request); change(value); assert.throws(() => replay._internals.target(value));
  }
  for (const url of ['localhost:443', 'registry.npmjs.org:80', 'auth.docker.io:443'])
    assert.throws(() => replay._internals.connectTarget({ method: 'CONNECT', url, headers: { host: url } }, Buffer.alloc(0)));
  assert.throws(() => replay._internals.connectTarget({ method: 'CONNECT', url: 'registry.npmjs.org:443', headers: { host: 'registry.npmjs.org:443' } }, Buffer.from('extra')));
});
test('caller success flags and forged stream lengths cannot substitute for exact replay bytes', async t => {
  const value = service(t, async () => ({ passed: true }));
  const [server, client] = pair(); value.acceptSocket(server); const result = collect(client);
  client.write('GET http://deb.debian.org/debian/file HTTP/1.1\r\nHost: deb.debian.org\r\n\r\n');
  assert.equal((await result).length, 0); assert.equal(value.state().failure, 'REPLAY_OBJECT');
});
test('two services share one sealed cumulative budget and retire actual sockets before absence', async () => {
  const budget = replay.createReplayBudget(); assert.ok(Object.isFrozen(budget));
  assert.throws(() => replay.createReplay({ ...certificate, read() {}, budget: { requests: 0 } }), { code: 'REPLAY_CONFIGURATION' });
  const read = async () => ({ bytes: payload.length, sha256, stream: Readable.from([payload]) });
  const first = replay.createReplay({ ...certificate, read, budget });
  const [server, client] = pair(); first.acceptSocket(server); const output = collect(client);
  client.write('GET http://deb.debian.org/debian/pool/main/f/f_1%2bb1%7eu1_arm64.deb HTTP/1.1\r\nHost: deb.debian.org\r\nConnection: close\r\n\r\n');
  await output; const retired = await first.close(); assert.equal(retired.absenceVerified, true); assert.equal(retired.active, 0);
  const second = replay.createReplay({ ...certificate, read, budget });
  assert.equal(second.state().bytes, payload.length); assert.equal(second.state().requests, 1);
  const peers = [];
  for (let n = 0; n < 256; n++) { const [socket, peer] = pair(); peers.push(peer); second.acceptSocket(socket); }
  assert.equal(second.state().connections, 257); assert.equal(second.state().failure, 'REPLAY_CONNECTION_LIMIT');
  const done = await second.close(); assert.equal(done.absenceVerified, true); assert.equal(done.failure, 'REPLAY_CONNECTION_LIMIT');
  for (const peer of peers) peer.destroy();
});
test('shared concurrency cap fails closed; an unresolved reader cannot claim retirement', async () => {
  const budget = replay.createReplayBudget(), resolves = [];
  const read = () => new Promise(resolve => resolves.push(resolve));
  const services = [0, 1].map(() => replay.createReplay({ ...certificate, read, budget }));
  const peers = [];
  for (let n = 0; n < 5; n++) {
    const [server, client] = pair(); peers.push(client); services[n % 2].acceptSocket(server);
    client.write('GET http://deb.debian.org/debian/file HTTP/1.1\r\nHost: deb.debian.org\r\n\r\n');
  }
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(resolves.length, 4); assert.equal(services[0].state().failure, 'REPLAY_REQUEST_LIMIT');
  const first = await services[0].firstFailure;
  assert.equal(first.cause, 'REPLAY_REQUEST_LIMIT'); assert.equal(first.counters.active, 5);
  const close = services.map(value => value.close());
  for (const resolve of resolves) resolve({ bytes: payload.length, sha256, stream: Readable.from([payload]) });
  for (const pending of close) assert.equal((await pending).absenceVerified, true);
  for (const peer of peers) peer.destroy();
});
test('actual replay accounting enforces cumulative 512-request and 512-MiB ceilings across services', async () => {
  const source = require('node:fs').readFileSync(require.resolve('./postgres/ownedMcpArtifactReplay'), 'utf8');
  const { EventEmitter } = require('node:events');
  for (const scenario of ['requests', 'bytes']) {
    const servers = [], module = { exports: {} };
    const fakeHttp = { createServer(_options, handler) {
      const server = new EventEmitter(); server.on('request', handler); server.close = callback => { callback?.(); }; servers.push(server); return server;
    } };
    new Function('require', 'module', 'exports', source)(id => id === 'node:http' ? fakeHttp : require(id), module, module.exports);
    const implementation = module.exports, budget = implementation.createReplayBudget(); let reads = 0;
    const chunk = Buffer.alloc(scenario === 'bytes' ? 1024 ** 2 : 1), objectBytes = scenario === 'bytes' ? 64 * 1024 ** 2 : 1;
    const read = async () => { reads++; return { bytes: objectBytes, sha256, stream: Readable.from(Array(objectBytes / chunk.length).fill(chunk)) }; };
    const request = async (service, server) => {
      const response = new EventEmitter(); Object.assign(response, { writeHead() {}, write() { return true; }, end() {}, destroy() { this.emit('close'); } });
      server.emit('request', { method: 'GET', url: 'http://deb.debian.org/debian/fixture', headers: { host: 'deb.debian.org' } }, response);
      while (service.state().active) await new Promise(resolve => setImmediate(resolve));
    };
    const first = implementation.createReplay({ ...certificate, budget, read });
    const half = scenario === 'bytes' ? 4 : 256;
    for (let n = 0; n < half; n++) await request(first, servers[0]);
    assert.equal((await first.close()).absenceVerified, true);
    const second = implementation.createReplay({ ...certificate, budget, read });
    for (let n = 0; n < half; n++) await request(second, servers[2]);
    assert.equal(second.state().failure, null);
    assert.equal(scenario === 'bytes' ? second.state().bytes : second.state().requests, scenario === 'bytes' ? 512 * 1024 ** 2 : 512);
    await request(second, servers[2]);
    assert.equal(second.state().failure, scenario === 'bytes' ? 'REPLAY_BYTE_LIMIT' : 'REPLAY_REQUEST_LIMIT');
    assert.equal(reads, scenario === 'bytes' ? 9 : 512);
    assert.equal((await second.close()).absenceVerified, true);
  }
});
