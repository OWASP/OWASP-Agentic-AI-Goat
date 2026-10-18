const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const http = require('node:http');
const { runChatTurn } = require('../server/services/secureshop/streaming');

function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}
function fixture(run, exclusive = (_id, callback) => callback(), localTools) {
  const req = Object.assign(new EventEmitter(), { ssUser: { role: 'customer', id: 7 } });
  const res = Object.assign(new EventEmitter(), {
    chunks: [], writableFinished: false, destroyed: false,
    writeHead(code, headers) { this.code = code; this.headers = headers; },
    write(chunk) { this.chunks.push(chunk); },
    end() { this.writableFinished = true; this.emit('close'); },
  });
  const start = () => runChatTurn(req, res, {
    sessionId: 'owned-session', message: 'hello', supervisor: { run }, localTools,
    agentSession: { runExclusive: exclusive }, provider: 'fixture', pool: {}, manifest: [],
  });
  return { req, res, start };
}

test('normal request close does not cancel the graph; completion removes listeners', async () => {
  const started = deferred(); const finish = deferred(); let signal;
  const f = fixture(async (id, message, opts) => {
    assert.equal(id, 'owned-session'); assert.equal(message, 'hello');
    assert.equal(opts.callerId, 7); assert.equal(opts.callerRole, 'customer');
    signal = opts.signal; started.resolve(); await finish.promise;
    opts.stream.send('done', { sessionId: id });
  });
  const running = f.start(); await started.promise;
  f.req.emit('close');
  assert.equal(signal.aborted, false);
  finish.resolve(); await running;
  assert.equal(signal.aborted, false);
  assert.match(f.res.chunks.join(''), /event: done/);
  assert.equal(f.req.listenerCount('aborted'), 0);
  assert.equal(f.res.listenerCount('close'), 0);
});

test('disconnect during queue wait prevents supervisor invocation', async () => {
  const queued = deferred(); const release = deferred(); let calls = 0;
  const f = fixture(() => { calls++; }, async (_id, callback) => {
    queued.resolve(); await release.promise; return callback();
  });
  const running = f.start(); await queued.promise;
  f.res.emit('close'); release.resolve(); await running;
  assert.equal(calls, 0);
  assert.doesNotMatch(f.res.chunks.join(''), /event: error/);
});

test('disconnect propagates abort without releasing exclusivity before graph settles', async () => {
  const started = deferred(); const finish = deferred(); let signal; let released = false;
  const f = fixture(async (_id, _message, opts) => {
    signal = opts.signal; started.resolve(); await finish.promise;
  }, async (_id, callback) => { try { return await callback(); } finally { released = true; } });
  const running = f.start(); await started.promise;
  f.res.emit('close');
  assert.equal(signal.aborted, true);
  assert.equal(released, false);
  finish.resolve(); await running;
  assert.equal(released, true);
});

test('aborted input and an already destroyed connection never start a graph', async () => {
  for (const state of ['request', 'response']) {
    let calls = 0;
    const f = fixture(() => { calls++; });
    if (state === 'request') f.req.aborted = true;
    else f.res.destroyed = true;
    await f.start();
    assert.equal(calls, 0);
    assert.equal(f.res.chunks.length, 0);
    assert.equal(f.req.listenerCount('aborted'), 0);
  }
});

test('connected graph failure retains the existing SSE error contract', async () => {
  const f = fixture(async () => { throw new Error('provider unavailable'); });
  await f.start();
  assert.equal(f.res.code, 200);
  assert.equal(f.res.headers['content-type'], 'text/event-stream');
  assert.match(f.res.chunks.join(''), /event: error\ndata: {"message":"provider unavailable"}/);
  assert.equal(f.res.writableFinished, true);
});

test('real HTTP response disconnect aborts the graph after request body completion', { timeout: 5000 }, async () => {
  const observed = deferred(); const settled = deferred();
  const server = http.createServer((req, res) => {
    req.ssUser = { id: 7, role: 'customer' };
    req.resume();
    req.on('end', () => {
      runChatTurn(req, res, {
        sessionId: 'owned-http-session', message: 'fixture',
        agentSession: { runExclusive: (_id, operation) => operation() },
        supervisor: { async run(_id, _message, { signal }) {
          assert.equal(signal.aborted, false);
          await new Promise(resolve => signal.addEventListener('abort', resolve, { once: true }));
          observed.resolve(signal.aborted);
        } },
      }).then(settled.resolve, settled.resolve);
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let client;
  try {
    await new Promise((resolve, reject) => {
      client = http.request({ host: '127.0.0.1', port: server.address().port, method: 'POST' }, response => {
        response.once('data', () => { response.destroy(); resolve(); });
      });
      client.once('error', reject);
      client.end('synthetic request body');
    });
    assert.equal(await observed.promise, true);
    assert.equal(await settled.promise, undefined);
  } finally {
    client?.destroy();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('queued chat carries only server-supplied executor closures and snapshots their selection', async () => {
  const queued = deferred(), release = deferred();
  const execute = async () => 'owned bytes';
  const registry = new Map([['system.read_config', execute]]);
  const f = fixture(async (_id, _message, opts) => {
    assert.equal(opts.localTools.get('system.read_config'), execute);
    assert.equal(opts.localTools.size, 1);
  }, async (_id, operation) => { queued.resolve(); await release.promise; return operation(); }, registry);
  f.req.body = { localTools: { 'system.read_config': 'attacker value' }, platformOwnerId: 999 };
  const running = f.start(); await queued.promise;
  registry.clear(); release.resolve(); await running;
  assert.doesNotMatch(f.res.chunks.join(''), /attacker value|platformOwnerId|owned bytes/);
});
