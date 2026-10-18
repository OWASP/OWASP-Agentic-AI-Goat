'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { allowedDatabaseConnect, waitForChild, createOwnedChildren } = require('./fixtures/fullBackendBootControls');
const endpoint = { host: '127.0.0.1', port: 54321 };
test('socket guard accepts exact database forms and denies alternate transports', () => {
  for (const args of [[54321, '127.0.0.1'], ['54321', '127.0.0.1'], [{ port: 54321, host: '127.0.0.1' }], [[{ port: 54321, host: '127.0.0.1' }, null]]]) assert.equal(allowedDatabaseConnect(args, endpoint), true);
  for (const args of [[54321], [54321, 'localhost'], [54322, '127.0.0.1'], [54321, 'example.invalid'], ['/tmp/postgres'], [{ path: '/tmp/postgres', host: '127.0.0.1', port: 54321 }], [{ port: 54321 }]]) assert.equal(allowedDatabaseConnect(args, endpoint), false);
});
function child() { return Object.assign(new EventEmitter(), { exitCode: null, signalCode: null }); }
test('wait cleans listeners on exit, error, abort and deadline', async () => {
  for (const outcome of ['exit', 'error', 'abort', 'timeout']) {
    const value = child(), controller = new AbortController();
    const waiting = waitForChild(value, { timeoutMs: 10, signal: controller.signal });
    if (outcome === 'exit') value.emit('exit', 0);
    if (outcome === 'error') value.emit('error', Error('controlled'));
    if (outcome === 'abort') controller.abort(Error('controlled'));
    if (outcome === 'exit') assert.equal(await waiting, 0);else await assert.rejects(waiting);
    assert.equal(value.listenerCount('exit'), 0);assert.equal(value.listenerCount('error'), 0);
  }
});
test('registered children remain in outer group and cleaned handles are never signalled again', async () => {
  const value = child(), signals = [];
  value.kill = signal => { signals.push(signal);value.signalCode = signal;value.emit('exit', null); };
  const owned = createOwnedChildren((_command, _args, options) => { assert.equal(options.detached, false);return value; });
  owned.launch('controlled', [], { detached: true });
  await owned.cleanup();await owned.cleanup();assert.deepEqual(signals, ['SIGTERM']);
});

test('explicit service configuration is finite, exact loopback and independent of ambient env', () => {
  const { validateNetworkConfiguration, networkGuardSource } = require('./fixtures/fullBackendBootControls');
  const config = { version: 1, services: [{ name: 'agent_host', host: '127.0.0.1', port: 38082 },
    { name: 'model', host: '127.0.0.1', port: 11434 }, { name: 'fixture_ssrf', host: '127.0.0.1', port: 38083 }] };
  assert.equal(validateNetworkConfiguration(endpoint).services.length, 0);
  assert.equal(validateNetworkConfiguration(endpoint, config).services.length, 3);
  for (const delta of [{ host: 'localhost' }, { host: '::1' }, { host: '127.1' }, { port: 0 },
    { port: 65536 }, { port: '038082' }, { port: 54321 }, { name: 'any' }, { path: '/tmp/socket' },
    { name: "model';process.exit();//" }]) {
    assert.throws(() => networkGuardSource(endpoint, { ...config, services: [{ ...config.services[0], ...delta }] }));
  }
  assert.throws(() => networkGuardSource(endpoint, { ...config, services: [config.services[0], config.services[0]] }));
  assert.throws(() => networkGuardSource(endpoint, { ...config, allowAll: true }));
  assert.ok(!networkGuardSource(endpoint, config).includes('process.env'));
});

test('generated guard enforces sockets and fetch destinations without network IO', async () => {
  const vm = require('node:vm');
  const { networkGuardSource } = require('./fixtures/fullBackendBootControls');
  for (const services of [[], [{ name: 'model', host: '127.0.0.1', port: 11434 }]]) {
    const calls = [];
    function Socket() {}
    Socket.prototype.connect = (...args) => { calls.push(args);return 'connected'; };
    const context = { URL, Request, require: name => { assert.equal(name, 'node:net');return { Socket }; },
      fetch: async (...args) => { calls.push(args);return 'fetched'; } };
    context.global = context;
    vm.runInNewContext(networkGuardSource(endpoint, { version: 1, services }), context);
    assert.equal(new Socket().connect(54321, '127.0.0.1'), 'connected');
    for (const args of [[11435, '127.0.0.1'], [11434, 'localhost'], [11434], ['/tmp/socket'],
      [{ host: '127.0.0.1', port: 11434, path: '/tmp/socket' }]]) assert.throws(() => new Socket().connect(...args));
    if (services.length) {
      assert.equal(new Socket().connect({ host: '127.0.0.1', port: 11434 }), 'connected');
      assert.equal(await context.fetch('http://127.0.0.1:11434/api/chat', { redirect: 'follow' }), 'fetched');
      assert.equal(calls.at(-1)[1].redirect, 'error');
      const request = new Request('http://127.0.0.1:11434/api/chat');
      assert.equal(await context.fetch(request), 'fetched');
      assert.equal(calls.at(-1)[0], request);
      await assert.rejects(context.fetch({ url: request.url, toString: () => 'http://external.invalid/' }));
      await assert.rejects(context.fetch(request.url, { dispatcher: {} }));
    } else {
      assert.throws(() => new Socket().connect(11434, '127.0.0.1'));
      await assert.rejects(context.fetch('http://127.0.0.1:11434/api/chat'));
    }
    for (const url of ['http://localhost:11434/', 'https://127.0.0.1:11434/',
      'http://127.0.0.1:54321/', 'http://user@127.0.0.1:11434/', 'http://127.0.0.1:11434/#fragment',
      'http://127.1:11434/', 'http://2130706433:11434/', 'http://external.invalid/']) await assert.rejects(context.fetch(url));
  }
});

test('real HTTP and fetch clients use admitted TCP forms; foreign listeners receive no requests', async () => {
  const http = require('node:http'), net = require('node:net'), vm = require('node:vm');
  const { networkGuardSource } = require('./fixtures/fullBackendBootControls');
  const hits = [0, 0], servers = hits.map((_, index) => http.createServer((req, res) => {
    hits[index]++;res.end('owned');
  }));
  const originalConnect = net.Socket.prototype.connect;
  const originalFetch = global.fetch;
  const sockets = new Set();
  for (const server of servers) server.on('connection', socket => {
    sockets.add(socket);socket.on('close', () => sockets.delete(socket));
  });
  let context;
  try {
    for (const server of servers) await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const allowedPort = servers[0].address().port, deniedPort = servers[1].address().port;
    const forms = [];
    net.Socket.prototype.connect = function (...args) {
      const options = Array.isArray(args[0]) ? args[0][0] : args[0];
      forms.push(typeof options === 'object' ? { host: options.host, port: options.port, path: options.path } : options);
      return originalConnect.apply(this, args);
    };
    context = { URL, Request, require, fetch: originalFetch };context.global = context;
    vm.runInNewContext(networkGuardSource(endpoint, { version: 1,
      services: [{ name: 'fixture_http', host: '127.0.0.1', port: allowedPort }] }), context);
    const get = port => new Promise((resolve, reject) => {
      const request = http.get({ host: '127.0.0.1', port, path: '/owned', agent: false }, response => {
        response.resume();response.on('end', () => resolve(response.statusCode));
      });
      request.on('error', reject);
    });
    assert.equal(await get(allowedPort), 200);
    assert.equal((await context.fetch(`http://127.0.0.1:${allowedPort}/owned`)).status, 200);
    await assert.rejects(get(deniedPort), /QUALIFICATION_NETWORK_BLOCKED/);
    await assert.rejects(context.fetch(`http://127.0.0.1:${deniedPort}/owned`), /QUALIFICATION_PROVIDER_BLOCKED/);
    assert.deepEqual(hits, [2, 0]);
    assert.ok(forms.some(form => Number(form.port) === allowedPort));
    assert.equal(allowedDatabaseConnect([{ host: endpoint.host, port: endpoint.port, path: null }], endpoint), true);
    assert.equal(allowedDatabaseConnect([{ host: endpoint.host, port: endpoint.port, path: undefined }], endpoint), true);
    assert.equal(allowedDatabaseConnect([{ host: endpoint.host, port: endpoint.port, path: '' }], endpoint), false);
  } finally {
    net.Socket.prototype.connect = originalConnect;
    for (const socket of sockets) socket.destroy();
    for (const server of servers) await new Promise(resolve => server.close(resolve));
  }
});
