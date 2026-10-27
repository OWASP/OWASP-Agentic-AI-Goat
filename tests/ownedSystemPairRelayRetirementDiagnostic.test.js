'use strict';
// Controlled transport diagnosis only. No registry, model, browser, VM, or
// qualification authority. The retained native exception remains unknown.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs/promises'), path = require('node:path');
const crypto = require('node:crypto'), http = require('node:http'), tls = require('node:tls');
const { Duplex } = require('node:stream'), { spawnSync } = require('node:child_process');
const adapter = require('./postgres/ownedSystemConfigBuildAdapter');
const input = require('./postgres/ownedSystemConfigPrivateBuild')._internals;
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const PAYLOAD = Buffer.from('Synthetic complete artifact; not a real Debian package.\n'.repeat(64));
const URL = 'http://deb.debian.org/debian/pool/main/f/fixture/fixture_1_arm64.deb';

async function emittedController() {
  const source = await fs.readFile(path.join(input.ROOT, input.PROVIDER), 'utf8');
  const body = /def original_dockerfile\(\):\n  return '''FROM node@'''\+BASE\+'''([\s\S]*?)'''/.exec(source)[1];
  const dockerfile = 'FROM node@' + input.BASE + body;
  const plan = await adapter.systemPolicyBuildPlan(input.ROOT, 'd'.repeat(32), {
    version: 1, target: 'v24-system', base: input.BASE, platform: 'linux/arm64', sourceRoot: input.SOURCE,
    dockerfile, dockerfileSha256: sha(dockerfile), packages: [...input.PACKAGES],
    user: '10001:10001', entrypoint: [...input.ENTRYPOINT]
  });
  const match = /<<'DVAIA_RELAY_LIFECYCLE'\n([\s\S]*?)\nDVAIA_RELAY_LIFECYCLE\n/.exec(plan.commands.relayStart);
  assert(match); return match[1];
}

// HISTORICAL FAILURE CONTROL ONLY: restore the exact pre-fix close-on-body-end
// implementation in memory. The repaired controls execute checked-in source
// without substitutions; neither branch claims the retained native errno.
function legacyDestroyExperiment(source) {
  source = eofOnlyExperiment(source);
  const replace = (before, after) => {
    assert.equal(source.split(before).length, 2, 'unique experimental source anchor');
    source = source.replace(before, after);
  };
  const start = source.indexOf('    let closedResolve, closedReject, retirementError;');
  const end = source.indexOf('    const track = ', start);
  assert(start > 0 && end > start);
  source = source.slice(0, start) + '    let closedResolve; const closed = new Promise(value => { closedResolve = value; });\n' +
    '    const close = () => { if (!active.size && done) closedResolve(); };\n' + source.slice(end);
  replace('if (done) { if (!probe && error) retirementError ||= error; return; }\n      retirementError = error; done = true; clearTimeout(timer);',
    'if (done) return; done = true; clearTimeout(timer);');
  const branch = source.indexOf('      if (!probe) {\n        // HTTP');
  const probe = source.indexOf("      if (probe) secure.on('data'", branch);
  assert(branch > 0 && probe > branch);
  source = source.slice(0, branch) + source.slice(probe);
  replace("incoming.once('end', () => {\n            if (probe) stop();\n            else { secure.end(); secure.resume(); }\n          }); incoming.on('error', stop);",
    "incoming.once('end', () => stop()); incoming.on('error', stop);");
  return source;
}

// Exact prior ordinary-GET implementation, retained solely to demonstrate the
// EOF-before-consumer regression. Production controls use unmodified source.
function eofOnlyExperiment(source) {
  const before = "        // TLS EOF may precede consumption of an already-buffered HTTP body.\n        // Do not destroy IncomingMessage until its consumer has reached end.\n        secure.once('end', () => {\n          tlsEnded = true;\n          if (!response) stop(fail('CLOSURE_TRANSPORT_CLOSED'));\n          else if (httpEnded) stop();\n        });";
  assert.equal(source.split(before).length, 2);
  return source.replace(before, "        secure.once('end', () => stop());")
    .replace('let closedResolve, closedReject, retirementError, httpEnded = false, tlsEnded = false;', 'let closedResolve, closedReject, retirementError;')
    .replace('else { httpEnded = true; secure.end(); secure.resume(); if (tlsEnded) stop(); }', 'else { secure.end(); secure.resume(); }');
}

async function captureClient(t, { wrongHash = false, graceful = false, fault = null, eofFirst = false, priorEofOnly = false } = {}) {
  const payload = eofFirst ? Buffer.from('Synthetic complete artifact; not a real Debian package.\n'.repeat(4096)) : PAYLOAD;
  const parent = await fs.realpath(process.env.TMPDIR || path.join(input.ROOT, 'tasks/tmp'));
  assert(parent.startsWith(input.ROOT + path.sep));
  const root = await fs.mkdtemp(path.join(parent, 'pair-retirement-control-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  // Existing ephemeral certificate generator, with only this test's SAN/CN
  // changed to Debian. No trust-store change or verification bypass.
  const generator = require('./postgres/ownedMcpArtifactReplay').replayCertificate.toString();
  const certificate = new Function('crypto', 'fail', 'return (' + generator.replaceAll('registry.npmjs.org', 'deb.debian.org') + ')();')(
    crypto, code => Object.assign(Error(code), { code }));
  let client, upstream, wirePending = Buffer.alloc(0), connects = 0, gets = 0;
  const delivered = [], held = [], events = [], sockets = new Set();
  let alertReleased = false, bodyEnded = false, clientSecure;
  const releaseAlert = () => {
    assert(held.length > 0); assert(!local[0].destroyed, 'transport retained until delayed TLS alert');
    events.push('release-tls-alert'); alertReleased = true;
    for (const record of held) client.push(record);
    client.push(null);
  };
  const endpoint = (side, peer) => new Duplex({
    read() {},
    write(chunk, _encoding, done) {
      if (side === 'server') {
        wirePending = Buffer.concat([wirePending, chunk]);
        while (wirePending.length >= 5) {
          const length = 5 + wirePending.readUInt16BE(3);
          if (wirePending.length < length) break;
          const record = Buffer.from(wirePending.subarray(0, length)); wirePending = wirePending.subarray(length);
          // TLS1.2 makes the actual encrypted alert record independently
          // identifiable without decoding it. Hold only its delivery, not the
          // client's HTTP parser or body/close handlers.
          if (record[0] === 21) { held.push(record); events.push('held-tls-alert');
            if (graceful && (fault === 'truncated' || eofFirst)) setImmediate(releaseAlert); }
          else { delivered.push(record); queueMicrotask(() => { if (!peer().destroyed) peer().push(record); }); }
        }
      } else queueMicrotask(() => { if (!peer().destroyed) peer().push(Buffer.from(chunk)); });
      done();
    },
    // EOF follows queued bytes, as on a real stream; it cannot overtake writes.
    final(done) { events.push(side + '-final'); queueMicrotask(() => { if (side === 'client' && !peer().destroyed) peer().push(null); done(); }); },
    destroy(error, done) {
      events.push(side + '-destroy');
      if (!(side === 'server' && graceful && !alertReleased) && !peer().destroyed) peer().push(null);
      done(error);
    }
  });
  client = endpoint('client', () => upstream); upstream = endpoint('server', () => client);
  for (const socket of [client, upstream]) {
    socket.on('error', () => {}); socket.setTimeout = socket.setNoDelay = () => {};
  }
  // CONNECT is terminated in memory before handing the raw endpoint to TLS;
  // there is no listener, connect(), DNS lookup, or public socket here.
  const secure = tls.createServer({ ...certificate, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'] });
  const inner = http.createServer();
  secure.on('tlsClientError', () => {});
  secure.on('secureConnection', socket => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {});
    inner.emit('connection', socket);
  });
  inner.on('request', request => {
    gets++; assert.equal(request.method, 'GET'); assert.equal(request.headers.host, 'deb.debian.org');
    request.socket.end(Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: ' + payload.length + '\r\nConnection: close\r\n\r\n'), fault === 'truncated' ? payload.subarray(0, -1) : payload]));
  });
  const original = await fs.readFile(require.resolve('./postgres/ownedMcpDependencyClosure'), 'utf8');
  const source = priorEofOnly ? eofOnlyExperiment(original) : graceful ? original : legacyDestroyExperiment(original);
  const module = { exports: {} };
  // Only the local CONNECT endpoint and ephemeral CA are substituted. Actual
  // HTTP/TLS and acquireArtifacts/disk verification run. The legacy branch is
  // separately identified and reverses only the reviewed retirement delta.
  new Function('require', 'module', 'exports', source)(id => id === 'node:http' ? {
    ...http, request(options, callback) {
      if (options.method !== 'CONNECT') return http.request(options, incoming => {
        callback(incoming);
        incoming.once('end', () => {
          bodyEnded = true; events.push('body-end');
          if (graceful) setImmediate(() => {
            if (fault === 'late-error') clientSecure.destroy(Object.assign(Error('controlled late TLS error'), { code: 'CONTROLLED_LATE_TLS' }));
            else if (fault === 'abort') abort.abort();
            else if (fault !== 'stalled' && !alertReleased) releaseAlert();
          });
        });
      });
      connects++; assert.equal(options.path, 'deb.debian.org:443');
      // Use the real CONNECT parser on a separate in-memory pair so plain
      // headers never enter the TLS record collector.
      let requestSide, proxySide;
      const simple = peer => new Duplex({ read() {}, write(b, _e, next) { queueMicrotask(() => { if (!peer().destroyed) peer().push(b); }); next(); },
        final(next) { queueMicrotask(() => { if (!peer().destroyed) peer().push(null); next(); }); }, destroy(error, next) { if (!peer().destroyed) peer().push(null); next(error); } });
      requestSide = simple(() => proxySide); proxySide = simple(() => requestSide);
      for (const s of [requestSide, proxySide]) { s.on('error', () => {}); s.setTimeout = s.setNoDelay = () => {}; }
      const proxy = http.createServer();
      proxy.on('connect', (_req, socket) => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        // After CONNECT, bridge actual TLS bytes into the collector endpoint.
        socket.pipe(client).pipe(socket); secure.emit('connection', upstream);
      });
      proxy.emit('connection', proxySide);
      local.push(requestSide, proxySide); servers.push(proxy);
      return http.request({ ...options, agent: undefined, createConnection: () => requestSide }, callback);
    }
  } : id === 'node:tls' ? { ...tls, connect: options => {
    clientSecure = tls.connect({ ...options, ca: certificate.cert, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' });
    clientSecure.once('end', () => {
      events.push('tls-end');
      if (fault === 'eof-late-error') queueMicrotask(() => clientSecure.emit('error', Object.assign(Error('controlled error after TLS EOF'), { code: 'CONTROLLED_LATE_TLS' })));
      if (fault === 'eof-abort') queueMicrotask(() => abort.abort());
    });
    return clientSecure;
  } } : id === 'node:fs/promises' && eofFirst ? { ...fs, open: async (...args) => {
    const handle = await fs.open(...args), write = handle.writeFile.bind(handle);
    handle.writeFile = async (...values) => { events.push('write-start'); await new Promise(resolve => setTimeout(resolve, fault === 'consumer-stalled' ? 400 : 20)); await write(...values); events.push('write-end'); };
    return handle;
  } } : require(id), module, module.exports);
  const local = [], servers = [], abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 3000);
  let outcome;
  try {
    const operation = module.exports.acquireArtifacts({
      artifacts: [{ kind: 'deb', algorithm: 'sha256', digest: wrongHash ? '0'.repeat(64) : sha(payload), bytes: payload.length, urls: [URL] }],
      directory: path.join(root, 'artifacts'), authority: { host: '127.0.0.1', port: 12345 }, signal: abort.signal,
      ...(['stalled', 'consumer-stalled'].includes(fault) ? { deadline: performance.now() + 250 } : {})
    });
    if (priorEofOnly) await assert.rejects(operation, { code: 'ERR_STREAM_PREMATURE_CLOSE' });
    else if (fault) await assert.rejects(operation, error => {
      if (fault === 'late-error' || fault === 'eof-late-error') assert.equal(error.code, 'CONTROLLED_LATE_TLS');
      else if (['abort', 'stalled', 'eof-abort', 'consumer-stalled'].includes(fault)) assert.equal(error.code, 'CLOSURE_ABORTED');
      else assert(['ECONNRESET', 'CLOSURE_TRANSPORT_CLOSED', 'ERR_STREAM_PREMATURE_CLOSE'].includes(error.code), error.code);
      return true;
    });
    else if (wrongHash) await assert.rejects(operation, { code: 'CLOSURE_INTEGRITY' });
    else {
      outcome = await operation;
      const bytes = await fs.readFile(path.join(root, 'artifacts', outcome.artifacts[0].file));
      assert.equal(sha(bytes), sha(payload)); assert.equal(outcome.artifactBytesVerified, true);
    }
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(connects, 1); assert.equal(gets, 1);
    assert(held.length > 0, 'real TLS alert was generated and deliberately delayed');
    assert(local[0].destroyed, 'owned CONNECT socket retired before acquisition settles');
    assert(clientSecure.destroyed, 'client-owned TLS endpoint closed');
    if (!fault && !priorEofOnly) {
      assert(local.every(socket => socket.destroyed));
      assert(client.destroyed && upstream.destroyed);
      assert.equal(sockets.size, 0, 'successful retirement closes both controlled peers');
    }
    assert.equal(wirePending.length, 0);
    if (graceful && !fault && !priorEofOnly) {
      assert(bodyEnded); assert(alertReleased);
      if (eofFirst) { assert(events.indexOf('tls-end') < events.indexOf('body-end')); assert(events.indexOf('tls-end') < events.lastIndexOf('write-end')); }
      else assert(events.indexOf('body-end') < events.indexOf('release-tls-alert'));
    }
    if (priorEofOnly) { assert(events.includes('tls-end')); assert(!bodyEnded); }
    if (wrongHash || fault || priorEofOnly) assert((await fs.readdir(path.join(root, 'artifacts', 'objects'))).every(name => name.endsWith('.partial')), 'failure never publishes verified object');
    return { prefix: Buffer.concat(delivered), suffix: Buffer.concat(held), payloadSha256: sha(payload), events, outcome };
  } finally {
    clearTimeout(timer); abort.abort();
    for (const socket of [...sockets, ...local, client, upstream]) socket.destroy();
    for (const server of [...servers, inner, secure]) server.close();
    await new Promise(resolve => setImmediate(resolve));
    // Fault controls deliberately hold the peer's EOF. Client rejection is not
    // remote-absence proof; the test owner independently retires those peers.
    assert(local.every(socket => socket.destroyed));
    assert(client.destroyed && upstream.destroyed);
    assert.equal(sockets.size, 0);
  }
}

const PYTHON = String.raw`
import ast,base64,errno,hashlib,json,socket,sys,threading,time
p=json.load(sys.stdin);tree=ast.parse(p['controller']);children=None
for node in tree.body:
 if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CHILDREN' for t in node.targets):children=json.loads(ast.literal_eval(node.value.args[0]))
assert set(children)=={'adapter','connector'}
prefix=base64.b64decode(p['prefix'],validate=True);suffix=base64.b64decode(p['suffix'],validate=True)
assert 0<len(prefix)<65536 and 0<len(suffix)<1024 and suffix[0]==21
reports=[]
for mode,source in children.items():
 tree=ast.parse(source);body=[]
 for node in tree.body:
  if isinstance(node,(ast.Import,ast.ImportFrom,ast.FunctionDef,ast.ClassDef)):body.append(node)
  elif isinstance(node,ast.Assign):
   try:ast.literal_eval(node.value)
   except (ValueError,TypeError):continue
   body.append(node)
 ns={};exec(compile(ast.Module(body=body,type_ignores=[]),'actual-'+mode,'exec'),ns)
 for early in (False,True):
  left,client=socket.socketpair();right,upstream=socket.socketpair()
  for s in (client,upstream):s.settimeout(2)
  stop=threading.Event();budget=ns['Budget']();result={}
  def worker():
   try:ns['pump'](left,right,'deb.debian.org',budget,time.monotonic()+3,stop);result['status']='closed'
   except Exception as error:
    tb=error.__traceback__
    while tb and tb.tb_frame.f_code.co_name!='pump':tb=tb.tb_next
    frame=tb.tb_frame.f_locals if tb else {}
    result.update(status='denied',error=type(error).__name__,errno=getattr(error,'errno',None),
      pendingToClient=len(frame.get('pending',{}).get(left,b'')),clientEof=left not in frame.get('readers',set()))
  thread=threading.Thread(target=worker);thread.start()
  try:
   upstream.sendall(prefix);received=bytearray()
   while len(received)<len(prefix):
    b=client.recv(len(prefix)-len(received));assert b;received.extend(b)
   assert bytes(received)==prefix
   if early:client.close()
   upstream.sendall(suffix);upstream.shutdown(socket.SHUT_WR)
   if not early:
    while True:
     b=client.recv(4096)
     if not b:break
     received.extend(b)
    assert bytes(received)==prefix+suffix
    client.shutdown(socket.SHUT_WR)
   thread.join(4);assert not thread.is_alive()
   if early:
    assert result['status']=='denied' and result['errno']==errno.EPIPE and result['pendingToClient']==len(suffix)
   else:assert result['status']=='closed'
   reports.append(dict(mode=mode,early=early,deliveredPrefixSha256=hashlib.sha256(prefix).hexdigest(),charged=budget.total,**result))
  finally:
   stop.set()
   for s in (client,upstream,left,right):s.close()
   thread.join(1);assert not thread.is_alive()
print(json.dumps(reports))
`;

test('historical client verifies complete body before TLS alert; actual emitted pump rejects late delivery to closed peer', { timeout: 15000 }, async t => {
  const transcript = await captureClient(t);
  const controller = await emittedController();
  const result = spawnSync('/opt/homebrew/bin/python3', ['-I', '-S', '-B', '-c', PYTHON], {
    input: JSON.stringify({ controller, prefix: transcript.prefix.toString('base64'), suffix: transcript.suffix.toString('base64') }),
    encoding: 'utf8', timeout: 10000, maxBuffer: 65536
  });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.signal, null);
  const rows = JSON.parse(result.stdout); assert.equal(rows.length, 4);
  for (const row of rows) {
    assert.equal(row.deliveredPrefixSha256, sha(transcript.prefix));
    assert.equal(row.status, row.early ? 'denied' : 'closed');
  }
  assert.equal(transcript.outcome.artifactBytesVerified, true);
  assert.equal(transcript.outcome.qualificationComplete, false);
  t.diagnostic(JSON.stringify({ scope: 'controlled-client-plus-captured-wire-replay-not-native-cause', payloadBytes: PAYLOAD.length,
    payloadSha256: transcript.payloadSha256, delayedTlsAlertBytes: transcript.suffix.length, rows }));
});

test('historical client rejects wrong artifact hash despite complete response and socket retirement', { timeout: 5000 }, async t => {
  await captureClient(t, { wrongHash: true });
});

test('actual repaired acquisition waits for delayed TLS EOF before publication', { timeout: 5000 }, async t => {
  const result = await captureClient(t, { graceful: true });
  assert.equal(result.outcome.artifactBytesVerified, true);
  t.diagnostic(JSON.stringify({ scope: 'actual-client-controlled-memory-TLS-not-native-proof', events: result.events }));
});

for (const fault of ['truncated', 'late-error', 'abort', 'stalled']) test('actual repaired client: ' + fault + ' cannot publish full-body transport success', { timeout: 5000 }, async t => {
  await captureClient(t, { graceful: true, fault });
});
test('actual repaired client: graceful TLS EOF never admits a mismatched artifact hash', { timeout: 5000 }, async t => {
  await captureClient(t, { graceful: true, wrongHash: true });
});

test('prior EOF-only stop destroys the buffered body before consumer end', { timeout: 5000 }, async t => {
  await captureClient(t, { graceful: true, eofFirst: true, priorEofOnly: true });
});
test('actual client drains a backpressured complete body after TLS EOF', { timeout: 5000 }, async t => {
  await captureClient(t, { graceful: true, eofFirst: true });
});
for (const fault of ['truncated', 'eof-late-error', 'eof-abort', 'consumer-stalled']) test('EOF-first acquisition rejects ' + fault, { timeout: 5000 }, async t => {
  await captureClient(t, { graceful: true, eofFirst: true, fault });
});
test('EOF-first complete body still requires its authenticated digest', { timeout: 5000 }, async t => {
  await captureClient(t, { graceful: true, eofFirst: true, wrongHash: true });
});
