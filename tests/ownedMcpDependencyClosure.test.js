'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs/promises'), path = require('node:path'), os = require('node:os');
const { Readable } = require('node:stream');
const closure = require('./postgres/ownedMcpDependencyClosure');
const { hash, npmArtifacts, debArtifacts } = closure._internals;
const npmUrl = 'https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz';
const debUrl = 'http://deb.debian.org/debian/pool/main/f/fixture/fixture_1_arm64.deb';
const bytes = Buffer.from('controlled compressed artifact, not a real package');
function artifact(kind = 'npm') { const algorithm = kind === 'npm' ? 'sha512' : 'sha256';
  return { kind, algorithm, digest: hash(bytes, algorithm), bytes: kind === 'npm' ? null : bytes.length,
    urls: [kind === 'npm' ? npmUrl : debUrl] }; }
async function temporary(t) { const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-closure-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true })); return directory; }
function response(data = bytes, overrides = {}) { return { status: 200, headers: {}, body: Readable.from([data]),
  closed: Promise.resolve(), destroy() { this.body.destroy(); }, ...overrides }; }
test('original lock binds all 124 paths to 122 unique SHA512 URLs without platform filtering', async () => {
  const lock = await fs.readFile(path.join(__dirname, '../sidecars/sandbox-runner/owned-mcp-registry/package-lock.json'));
  const rows = npmArtifacts(lock);
  assert.equal(rows.length, 122); assert.equal(rows.reduce((n, row) => n + row.lockPaths.length, 0), 124);
  assert.equal(rows.find(row => row.lockPaths.length === 3).urls[0], 'https://registry.npmjs.org/content-type/-/content-type-2.1.0.tgz');
  assert.ok(rows.some(row => row.urls[0].includes('aix-ppc64')));
  assert.throws(() => npmArtifacts(Buffer.concat([lock, Buffer.from(' ')])), { code: 'CLOSURE_NPM_LOCK_CHANGED' });
});
test('lock rejects redirect authorities, credentials, query strings, noncanonical hashes and conflicting aliases', () => {
  function lock(change) { const row = { resolved: npmUrl, integrity: 'sha512-' + Buffer.alloc(64).toString('base64') };
    const value = { lockfileVersion: 3, packages: { '': {}, 'node_modules/fixture': row } }; change(value, row);
    const encoded = Buffer.from(JSON.stringify(value)); return () => npmArtifacts(encoded, hash(encoded)); }
  for (const change of [(_v, row) => { row.resolved = npmUrl + '?token=x'; }, (_v, row) => { row.resolved = npmUrl.replace('registry.npmjs.org', 'localhost'); },
    (_v, row) => { row.resolved = npmUrl.replace('https://', 'https://credential@'); }, (_v, row) => { row.integrity += ' '; },
    (v, row) => { v.packages['node_modules/other'] = { ...row, integrity: 'sha512-' + Buffer.alloc(64, 1).toString('base64') }; }]) assert.throws(lock(change));
});
test('two separate original APT stage selections join exact URL, size and SHA256 rows', () => {
  const stages = Object.entries(closure.STAGES).map(([name, packages], index) => ({ name, packages: [...packages],
    selection: `'${debUrl}' fixture.deb ${bytes.length}${index ? '' : ' MD5Sum:' + 'a'.repeat(32)}\n`,
    selected: [{ name: 'fixture', version: '1', architecture: 'arm64', filename: 'pool/main/f/fixture/fixture_1_arm64.deb', bytes: bytes.length, sha256: hash(bytes) }] }));
  const rows = debArtifacts(stages); assert.equal(rows.length, 1); assert.deepEqual(rows[0].stages, ['build', 'runtime']);
  for (const change of [x => x.reverse(), x => x[0].packages.pop(), x => x[1].selected[0].bytes++,
    x => { x[1].selected[0].sha256 = 'b'.repeat(64); }, x => { x[1].selection = x[1].selection.replace('http:', 'file:'); }]) {
    const value = structuredClone(stages); change(value); assert.throws(() => debArtifacts(value));
  }
});
test('Debian version punctuation encodings join exact authenticated filename, never path or authority encodings', () => {
  const url = 'http://deb.debian.org/debian/pool/main/f/fixture/fixture_1%3a2%2bb3%7eu1_arm64.deb';
  const filename = 'pool/main/f/fixture/fixture_1:2+b3~u1_arm64.deb';
  const stages = Object.entries(closure.STAGES).map(([name, packages]) => ({ name, packages: [...packages],
    selection: `'${url}' fixture.deb ${bytes.length}\n`, selected: [{ name: 'fixture', version: '1:2+b3~u1', architecture: 'arm64', filename, bytes: bytes.length, sha256: hash(bytes) }] }));
  assert.deepEqual(debArtifacts(stages)[0].urls, [url]);
  const wrong = structuredClone(stages); wrong[0].selected[0].filename = filename.replace('+', '-');
  assert.throws(() => debArtifacts(wrong));
  for (const octet of ['%2f', '%5c', '%2e', '%25', '%252b', '%00', '%3f', '%23', '%40']) {
    assert.throws(() => closure._internals.artifactUrl(url.replace('%2b', octet), 'deb'));
  }
  for (const suffix of ['?x=1', '#fragment']) assert.throws(() => closure._internals.artifactUrl(url + suffix, 'deb'));
});
test('actual stream bytes are hashed, durably published and rechecked before replay', async t => {
  const root = await temporary(t), directory = path.join(root, 'artifacts'); let calls = 0;
  const receipt = await closure.acquireArtifacts({ artifacts: [artifact()], directory,
    request: async url => { calls++; assert.equal(url, npmUrl); return response(); } });
  assert.equal(calls, 1); assert.equal(receipt.artifactBytesVerified, true);
  assert.equal(receipt.metadataAuthenticated, false); assert.equal(receipt.buildApproved, false);
  const result = await closure.artifactReader(directory, receipt)(npmUrl);
  const chunks = []; for await (const chunk of result.stream) chunks.push(chunk);
  assert.deepEqual(Buffer.concat(chunks), bytes);
  await assert.rejects(closure.artifactReader(directory, receipt)(npmUrl + '?other'), { code: 'CLOSURE_UNLISTED_URL' });
  const target = path.join(directory, receipt.artifacts[0].file);
  await fs.chmod(target, 0o600); await fs.writeFile(target, Buffer.alloc(bytes.length)); await fs.chmod(target, 0o400);
  await assert.rejects(closure.artifactReader(directory, receipt)(npmUrl), { code: 'CLOSURE_OBJECT_CHANGED' });
});
test('wrong bytes, truncated bodies, redirects, compression and forged lengths never publish', async t => {
  const root = await temporary(t); let index = 0;
  for (const [data, overrides] of [[Buffer.alloc(bytes.length), {}], [bytes.subarray(1), {}], [bytes, { status: 302, headers: { location: npmUrl } }],
    [bytes, { headers: { 'content-encoding': 'gzip' } }], [bytes, { headers: { 'content-length': String(bytes.length + 1) } }]]) {
    const directory = path.join(root, String(index++));
    await assert.rejects(closure.acquireArtifacts({ artifacts: [artifact('deb')], directory, request: async () => response(data, overrides) }));
    const names = await fs.readdir(path.join(directory, 'objects'));
    assert.ok(names.every(name => name.endsWith('.partial')));
  }
});
test('cancel and shared deadline fail before further requests; no opaque request result grants readiness', async t => {
  const root = await temporary(t), controller = new AbortController(); controller.abort(); let called = false;
  await assert.rejects(closure.acquireArtifacts({ artifacts: [artifact()], directory: path.join(root, 'cancel'), signal: controller.signal,
    request: async () => { called = true; return response(); } }), { code: 'CLOSURE_ABORTED' });
  assert.equal(called, false);
  let clock = 0;
  await assert.rejects(closure.acquireArtifacts({ artifacts: [artifact()], directory: path.join(root, 'deadline'), now: () => clock,
    request: async () => { clock = closure.LIMITS.milliseconds; return response(); } }), { code: 'CLOSURE_ABORTED' });
  await assert.rejects(closure.acquireArtifacts({ artifacts: [artifact()], directory: path.join(root, 'opaque'), request: async () => ({ passed: true }) }));
});
test('byte cap is enforced during streaming, not after buffering or publication', async t => {
  const root = await temporary(t); let consumed = 0;
  const stream = Readable.from((async function* () { for (let i = 0; i < 66; i++) { consumed++; yield Buffer.alloc(1024 ** 2); } })());
  await assert.rejects(closure.acquireArtifacts({ artifacts: [artifact()], directory: path.join(root, 'cap'),
    request: async () => response(bytes, { body: stream }) }), { code: 'CLOSURE_BYTE_LIMIT' });
  assert.ok(consumed <= 66);
  assert.ok((await fs.readdir(path.join(root, 'cap', 'objects'))).every(name => name.endsWith('.partial')));
});
test('original build profile streams through exact stored limits; default and aggregate limits stay closed', async t => {
  assert.equal(closure.acquisitionLimits(), closure.LIMITS);
  assert.equal(closure.acquisitionLimits(closure.ORIGINAL_BUILD_PROFILE), closure.ORIGINAL_BUILD_LIMITS);
  assert.deepEqual(closure.ORIGINAL_BUILD_LIMITS, { ...closure.LIMITS, npm: 114 * 1024 ** 2 });
  assert.ok(Object.isFrozen(closure.ORIGINAL_BUILD_LIMITS));
  for (const profile of ['pricing', 'original-v23-registry-extra', {}, 114, null])
    assert.throws(() => closure.acquisitionLimits(profile), { code: 'CLOSURE_BUDGET_PROFILE' });
  const root = await temporary(t), MiB = 1024 ** 2;
  // Exercise the real stream counter/hash implementation with a controlled
  // disk sink, avoiding hundreds of MiB of test-only writes. Other tests above
  // exercise actual durable publication/readback; this is not native evidence.
  let written = 0, published = 0;
  const disk = { ...fs, open: async (name, flags, mode) => String(name).endsWith('.partial')
    ? { writeFile: async chunk => { written += chunk.length; }, chmod: async () => {}, sync: async () => {}, close: async () => {} }
    : fs.open(name, flags, mode), link: async () => { published++; }, unlink: async () => {} };
  const module = { exports: {} };
  new Function('require', 'module', 'exports', await fs.readFile(path.join(__dirname, 'postgres/ownedMcpDependencyClosure.js'), 'utf8'))(
    id => id === 'node:fs/promises' ? disk : require(id), module, module.exports);
  let scenario = 0;
  async function exercise(specs, budgetProfile, fails) {
    written = 0; published = 0;
    const inputs = specs.map(([kind, size], index) => {
      const chunk = Buffer.alloc(MiB, index + 1), algorithm = kind === 'deb' ? 'sha256' : 'sha512';
      function* chunks() { for (let left = size; left > 0; left -= MiB) yield chunk.subarray(0, Math.min(left, MiB)); }
      const digestor = require('node:crypto').createHash(algorithm); for (const part of chunks()) digestor.update(part);
      const url = kind === 'deb' ? `http://deb.debian.org/debian/pool/main/f/fixture/fixture_${index}_arm64.deb`
        : `https://registry.npmjs.org/fixture-${index}/-/fixture-${index}-1.tgz`;
      return { row: { kind, algorithm, digest: digestor.digest('hex'), bytes: kind === 'deb' ? size : null, urls: [url] }, chunks };
    });
    const result = module.exports.acquireArtifacts({ artifacts: inputs.map(x => x.row), budgetProfile,
      directory: path.join(root, String(scenario++)), request: async url => ({ status: 200, headers: {},
        body: Readable.from(inputs.find(x => x.row.urls[0] === url).chunks()), closed: Promise.resolve(), destroy() {} }) });
    if (fails) {
      await assert.rejects(result, { code: 'CLOSURE_BYTE_LIMIT' });
      assert.equal(published, inputs.length - 1);
      assert.equal(written, specs.slice(0, -1).reduce((n, x) => n + x[1], 0));
    } else {
      const receipt = await result; assert.equal(receipt.bytes.total, specs.reduce((n, x) => n + x[1], 0));
      assert.equal(receipt.budgetProfile, budgetProfile); assert.equal(published, inputs.length);
    }
  }
  const npmBoundary = [['npm', 38 * MiB], ['npm', 38 * MiB], ['npm', 38 * MiB]];
  await exercise(npmBoundary, closure.ORIGINAL_BUILD_PROFILE, false);
  await exercise([...npmBoundary, ['npm', 1]], closure.ORIGINAL_BUILD_PROFILE, true);
  const aggregateBoundary = [['deb', 64 * MiB], ['deb', 64 * MiB], ['npm', 64 * MiB]];
  await exercise(aggregateBoundary, closure.ORIGINAL_BUILD_PROFILE, false);
  await exercise([...aggregateBoundary, ['npm', 1]], closure.ORIGINAL_BUILD_PROFILE, true);
  await exercise([['npm', 64 * MiB], ['npm', 1]], undefined, true);
});
test('existing directories, symlinks and hardlinked objects cannot be adopted', async t => {
  const root = await temporary(t), directory = path.join(root, 'objects');
  await fs.mkdir(directory, { mode: 0o700 }); let called = false;
  await assert.rejects(closure.acquireArtifacts({ artifacts: [artifact()], directory, request: async () => { called = true; return response(); } }));
  assert.equal(called, false);
  const link = path.join(root, 'link'); await fs.symlink(directory, link);
  await assert.rejects(closure.acquireArtifacts({ artifacts: [artifact()], directory: path.join(link, 'child'), request: async () => response() }), { code: 'CLOSURE_DIRECTORY' });
  const valid = path.join(root, 'valid');
  const receipt = await closure.acquireArtifacts({ artifacts: [artifact()], directory: valid, request: async () => response() });
  await fs.link(path.join(valid, receipt.artifacts[0].file), path.join(root, 'second-link'));
  await assert.rejects(closure.artifactReader(valid, receipt)(npmUrl), { code: 'CLOSURE_OBJECT' });
});
test('default transport rejects missing private relay before opening any socket', async () => {
  await assert.rejects(closure.requestViaPrivateRelay(npmUrl, { authority: null, signal: new AbortController().signal }), { code: 'CLOSURE_PRIVATE_RELAY_REQUIRED' });
  await assert.rejects(closure.requestViaPrivateRelay('https://localhost/file.tgz', { authority: { host: '127.0.0.1', port: 443 }, signal: new AbortController().signal }), { code: 'CLOSURE_URL' });
});
test('failed artifact diagnostics preserve exact primary and bounded lock identity without arbitrary remote fields', async t => {
  const root = await temporary(t), row = artifact();
  const primary = Object.assign(Error('remote arbitrary text must not be serialized'), { code: 'ECONNRESET', closureTransport: 'tls',
    remoteHeader: 'secret', url: 'https://credential@invalid/?token=secret' });
  await assert.rejects(closure.acquireArtifacts({ artifacts: [row], directory: path.join(root, 'failed'), request: async () => { throw primary; } }), error => {
    assert.equal(error, primary); assert.equal(error.code, 'ECONNRESET');
    assert.deepEqual(closure.failureDiagnostic(error), { artifact: { index: 0, kind: 'npm', algorithm: 'sha512', digest: row.digest, stage: 'request' }, transport: 'tls' });
    assert.doesNotMatch(JSON.stringify(closure.failureDiagnostic(error)), /secret|credential|remote/); return true;
  });
  for (const change of [value => value.index = 250, value => value.kind = 'foreign', value => value.stage = 'arbitrary', value => value.digest += 'x']) {
    const value = structuredClone(primary.closureArtifact); change(value);
    assert.deepEqual(closure.failureDiagnostic({ closureArtifact: value, closureTransport: 'arbitrary' }), { artifact: null, transport: null });
  }
  const fixed = Object.freeze(Object.assign(Error('nonextensible'), { code: 'ECONNRESET' }));
  await assert.rejects(closure.acquireArtifacts({ artifacts: [row], directory: path.join(root, 'frozen'), request: async () => { throw fixed; } }), error => error === fixed);
});
test('actual HTTP/TLS parsers issue HEAD only through CONNECT and reject payload/oversized/duplicate headers', async () => {
  const http = require('node:http'), tls = require('node:tls'), { Duplex } = require('node:stream');
  const certificate = require('./postgres/ownedMcpArtifactReplay').replayCertificate();
  const source = await fs.readFile(require.resolve('./postgres/ownedMcpDependencyClosure'), 'utf8');
  for (const scenario of ['HEAD', 'GET', 'body', 'oversized', 'duplicate', 'range-good', 'range-200', 'range-body']) {
    const rangeProbe = scenario.startsWith('range-');
    let client, serverSocket, observed, connects = 0; const events = [];
    const endpoint = other => new Duplex({ read() {}, write(chunk, _encoding, done) { queueMicrotask(() => { if (!other().destroyed) other().push(Buffer.from(chunk)); done(); }); },
      final(done) { other().push(null); done(); }, destroy(error, done) { other().push(null); done(error); } });
    client = endpoint(() => serverSocket); serverSocket = endpoint(() => client);
    for (const socket of [client, serverSocket]) { socket.on('error', () => {}); socket.setTimeout = socket.setNoDelay = () => {}; }
    const proxy = http.createServer(), secure = tls.createServer({ ...certificate, ALPNProtocols: ['http/1.1'] }), inner = http.createServer();
    secure.on('tlsClientError', error => { events.push(error.code); });
    proxy.on('connect', (request, socket) => { connects++; events.push('CONNECT'); assert.equal(request.url, 'registry.npmjs.org:443'); socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); secure.emit('connection', socket); });
    secure.on('secureConnection', socket => { events.push('TLS'); socket.on('error', () => {}); inner.emit('connection', socket); });
    inner.on('request', request => {
      observed = request.method;
      assert.equal(request.headers.range, rangeProbe ? 'bytes=0-0' : undefined);
      const extra = scenario === 'oversized' ? 'X-Large: ' + 'x'.repeat(8192) + '\r\n' : scenario === 'duplicate' ? 'Content-Length: 5\r\n' : '';
      request.socket.end(rangeProbe
        ? `HTTP/1.1 ${scenario === 'range-200' ? '200 OK' : '206 Partial Content'}\r\nContent-Length: ${scenario === 'range-body' ? '2' : '1'}\r\nContent-Range: bytes 0-0/100\r\nConnection: close\r\n\r\n${scenario === 'range-body' ? 'xx' : 'x'}`
        : 'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n' + extra + 'Connection: close\r\n\r\n' + (['GET', 'body'].includes(scenario) ? 'data' : ''));
    });
    const module = { exports: {} };
    new Function('require', 'module', 'exports', source)(id => id === 'node:http' ? { ...http, request(options, callback) {
      events.push('request:' + options.method);
      return http.request(options.method === 'CONNECT' ? { ...options, agent: undefined, createConnection: () => client } : options, callback);
    } } : id === 'node:tls' ? { ...tls, connect: options => tls.connect({ ...options, ca: certificate.cert }) } : require(id), module, module.exports);
    proxy.emit('connection', serverSocket);
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 1000);
    const work = (async () => {
      const response = await module.exports.requestViaPrivateRelay(npmUrl, { method: scenario === 'GET' || rangeProbe ? 'GET' : 'HEAD', rangeProbe, authority: { host: '127.0.0.1', port: 12345 }, signal: controller.signal });
      const chunks = []; for await (const chunk of response.body) chunks.push(chunk);
      await response.closed;
      assert.equal(Buffer.concat(chunks).toString(), scenario === 'GET' ? 'data' : rangeProbe ? 'x' : '');
      if (scenario === 'HEAD') assert.ok(response.headerBytes > 0 && response.headerBytes < 8192);
    })();
    try {
      if (['HEAD', 'GET', 'range-good'].includes(scenario)) await work.catch(error => { throw new Error(scenario + ':' + events.join(','), { cause: error }); });
      else await assert.rejects(work);
      assert.equal(observed, scenario === 'GET' || rangeProbe ? 'GET' : 'HEAD'); assert.equal(connects, 1);
    } finally { clearTimeout(timer); client.destroy(); serverSocket.destroy(); proxy.close(); secure.close(); inner.close(); }
  }
  await assert.rejects(closure.requestViaPrivateRelay(npmUrl, { method: 'POST', authority: null, signal: new AbortController().signal }), { code: 'CLOSURE_METHOD' });
});
function privateLoopback(onRequest, { resetFirstConnect = false, rejectCertificate = false } = {}) {
  const http = require('node:http'), tls = require('node:tls'), { Duplex } = require('node:stream');
  const certificate = require('./postgres/ownedMcpArtifactReplay').replayCertificate();
  const proxy = http.createServer(), secure = tls.createServer({ ...certificate, ALPNProtocols: ['http/1.1'] });
  const inner = http.createServer(), pairs = [], clientTls = [], connectRequests = [];
  const endpoint = other => new Duplex({ read() {}, write(chunk, _encoding, done) {
    queueMicrotask(() => { if (!other().destroyed) other().push(Buffer.from(chunk)); done(); });
  }, final(done) { other().push(null); done(); }, destroy(error, done) { other().push(null); done(error); } });
  let connectCount = 0;
  proxy.on('connect', (request, socket) => {
    assert.equal(request.url, 'registry.npmjs.org:443');
    if (resetFirstConnect && ++connectCount === 1) { socket.destroy(); return; }
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); secure.emit('connection', socket);
  });
  secure.on('tlsClientError', () => {});
  secure.on('secureConnection', socket => { socket.on('error', () => {}); inner.emit('connection', socket); });
  inner.on('request', onRequest);
  const source = require('node:fs').readFileSync(require.resolve('./postgres/ownedMcpDependencyClosure'), 'utf8');
  const module = { exports: {} };
  new Function('require', 'module', 'exports', source)(id => id === 'node:http' ? { ...http, request(options, callback) {
    if (options.method !== 'CONNECT') return http.request(options, callback);
    let client, server;
    client = endpoint(() => server); server = endpoint(() => client);
    for (const socket of [client, server]) { socket.on('error', () => {}); socket.setTimeout = socket.setNoDelay = () => {}; }
    const pair = { client, server, clientClosed: false, serverClosed: false, requestClosed: false };
    client.once('close', () => { pair.clientClosed = true; });
    server.once('close', () => { pair.serverClosed = true; });
    pairs.push(pair); proxy.emit('connection', server);
    const outbound = http.request({ ...options, agent: undefined, createConnection: () => client }, callback);
    outbound.once('close', () => { pair.requestClosed = true; }); connectRequests.push(outbound);
    return outbound;
  } } : id === 'node:tls' ? { ...tls, connect: options => {
    const socket = tls.connect({ ...options, ca: rejectCertificate ? [] : certificate.cert });
    socket.retiredByClose = false; socket.once('close', () => { socket.retiredByClose = true; });
    clientTls.push(socket); return socket;
  } } : require(id), module, module.exports);
  return { closure: module.exports, pairs, clientTls, connectRequests, close() {
    for (const pair of pairs) { pair.client.destroy(); pair.server.destroy(); }
    for (const socket of clientTls) socket.destroy();
    proxy.close(); secure.close(); inner.close();
  } };
}
test('real private CONNECT reset retires every first transport before one same-URL pinned GET retry', async t => {
  const root = await temporary(t); let requests = 0;
  const loop = privateLoopback(request => {
    requests++;
    if (requests === 1) {
      loop.clientTls[0].destroy(Object.assign(new Error('controlled pre-response reset'), { code: 'ECONNRESET' }));
      request.socket.destroy(); return;
    }
    assert.equal(request.url, new URL(npmUrl).pathname);
    assert.equal(loop.pairs[0].clientClosed, true);
    assert.equal(loop.pairs[0].requestClosed, true);
    assert.equal(loop.clientTls[0].retiredByClose, true);
    request.socket.end(`HTTP/1.1 200 OK\r\nContent-Length: ${bytes.length}\r\nConnection: close\r\n\r\n${bytes}`);
  });
  t.after(() => loop.close());
  const receipt = await loop.closure.acquireArtifacts({ artifacts: [artifact()], directory: path.join(root, 'retry'),
    authority: { host: '127.0.0.1', port: 12345 } });
  assert.equal(requests, 2);
  assert.equal(receipt.artifacts.length, 1);
  const verified = await loop.closure.artifactReader(path.join(root, 'retry'), receipt)(npmUrl);
  const chunks = []; for await (const chunk of verified.stream) chunks.push(chunk);
  assert.deepEqual(Buffer.concat(chunks), bytes);
});
test('private retry never widens status, body, integrity, EOF, second-reset or deadline failures', async t => {
  const root = await temporary(t);
  for (const scenario of ['status', 'body', 'integrity', 'eof', 'second-reset', 'retry-integrity', 'deadline']) {
    let requests = 0, clock = 0;
    const loop = privateLoopback(request => {
      requests++;
      const reset = scenario === 'second-reset' || scenario === 'retry-integrity' && requests === 1
        || scenario === 'deadline';
      if (reset) {
        if (scenario === 'deadline') clock = 300000;
        loop.clientTls[requests - 1].destroy(Object.assign(new Error('controlled reset'), { code: 'ECONNRESET' }));
        request.socket.destroy(); return;
      }
      if (scenario === 'eof') { request.socket.destroy(); return; }
      if (scenario === 'status') request.socket.end('HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
      else if (scenario === 'body') request.socket.end('HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\npartial');
      else {
        const wrong = Buffer.alloc(bytes.length);
        request.socket.end(`HTTP/1.1 200 OK\r\nContent-Length: ${wrong.length}\r\nConnection: close\r\n\r\n${wrong}`);
      }
    });
    try {
      await assert.rejects(loop.closure.acquireArtifacts({ artifacts: [artifact()], directory: path.join(root, scenario),
        authority: { host: '127.0.0.1', port: 12345 },
        ...(scenario === 'deadline' ? { now: () => clock, deadline: 300000 } : {}) }));
      assert.equal(requests, ['second-reset', 'retry-integrity'].includes(scenario) ? 2 : 1, scenario);
      assert.equal(loop.pairs.length, requests, scenario);
      const names = await fs.readdir(path.join(root, scenario, 'objects'));
      assert.ok(names.every(name => name.endsWith('.partial')), scenario);
    } finally { loop.close(); }
  }
});
test('caller-forged reset retirement fields cannot authorize another request', async t => {
  const root = await temporary(t), primary = Object.assign(new Error('injected reset'), {
    code: 'ECONNRESET', closureTransport: 'request', retiredByClose: true,
    preResponse: true, retirementProven: true });
  let calls = 0;
  await assert.rejects(closure.acquireArtifacts({ artifacts: [artifact()], directory: path.join(root, 'forged'),
    request: async () => { calls++; throw primary; } }), error => error === primary);
  assert.equal(calls, 1);
});
test('pre-response CONNECT reset retires its socket before one TLS-verified same-URL GET', async t => {
  const root = await temporary(t);
  let requests = 0;
  const loop = privateLoopback(request => {
    requests++;
    assert.equal(loop.pairs.length, 2);
    assert.equal(loop.pairs[0].clientClosed, true);
    assert.equal(loop.pairs[0].serverClosed, true);
    assert.equal(loop.pairs[0].requestClosed, true);
    assert.equal(request.url, new URL(npmUrl).pathname);
    request.socket.end(`HTTP/1.1 200 OK\r\nContent-Length: ${bytes.length}\r\nConnection: close\r\n\r\n${bytes}`);
  }, { resetFirstConnect: true });
  try {
    const receipt = await loop.closure.acquireArtifacts({ artifacts: [artifact()], directory: path.join(root, 'connect'),
      authority: { host: '127.0.0.1', port: 12345 } });
    assert.equal(requests, 1);
    assert.equal(loop.pairs.length, 2);
    assert.equal(loop.clientTls.length, 1);
    const verified = await loop.closure.artifactReader(path.join(root, 'connect'), receipt)(npmUrl);
    const chunks = []; for await (const chunk of verified.stream) chunks.push(chunk);
    assert.deepEqual(Buffer.concat(chunks), bytes);
  } finally { loop.close(); }
});
test('TLS certificate authority failure does not retry a pinned artifact', async t => {
  const root = await temporary(t);
  let requests = 0;
  const loop = privateLoopback(() => { requests++; }, { rejectCertificate: true });
  try {
    await assert.rejects(loop.closure.acquireArtifacts({ artifacts: [artifact()], directory: path.join(root, 'tls-authority'),
      authority: { host: '127.0.0.1', port: 12345 } }), error => error.code !== 'ECONNRESET');
    assert.equal(loop.pairs.length, 1);
    assert.equal(requests, 0);
  } finally { loop.close(); }
});
test('an unretired pre-response reset preserves the primary error and never retries', async t => {
  const { EventEmitter } = require('node:events'), http = require('node:http');
  const source = require('node:fs').readFileSync(require.resolve('./postgres/ownedMcpDependencyClosure'), 'utf8');
  const module = { exports: {} }; let attempts = 0;
  new Function('require', 'module', 'exports', source)(id => id === 'node:http' ? { ...http, request() {
    attempts++;
    const outbound = new EventEmitter(), primary = Object.assign(new Error('controlled reset'), { code: 'ECONNRESET' });
    outbound.end = () => queueMicrotask(() => outbound.emit('error', primary));
    outbound.destroy = () => {}; // Deliberately never emits close: no retirement proof.
    return outbound;
  } } : require(id), module, module.exports);
  const root = await temporary(t);
  await assert.rejects(module.exports.acquireArtifacts({ artifacts: [artifact()], directory: path.join(root, 'unretired'),
    authority: { host: '127.0.0.1', port: 12345 } }), error => {
    assert.equal(error.code, 'ECONNRESET'); assert.equal(error.retirementUnproven, true); return true;
  });
  assert.equal(attempts, 1);
});
