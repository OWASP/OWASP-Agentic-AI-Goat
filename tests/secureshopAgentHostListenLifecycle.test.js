'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');

async function boot({ listenError, address = { port: 8082 }, flushError, bindHost } = {}) {
  const entry = path.resolve(__dirname, '../agent-host/index.js');
  const calls = [], listenArguments = [], stdout = [], stderr = [], exits = [], signals = new Map();
  const server = new EventEmitter();
  server.address = () => { calls.push('address'); return listenError ? null : address; };
  server.close = callback => { calls.push('close'); callback(listenError ?
    Object.assign(new Error('not listening'), { code: 'ERR_SERVER_NOT_RUNNING' }) : undefined); };
  const app = { use() {}, get() {}, post() {}, listen(...argumentsList) {
    listenArguments.push(argumentsList.slice(0, -1));
    const callback = argumentsList.at(-1);
    queueMicrotask(() => callback(listenError)); return server;
  } };
  const express = () => app; express.json = () => () => {};
  vm.runInNewContext(fs.readFileSync(entry, 'utf8'), {
    __dirname: path.dirname(entry), Error, setTimeout, clearTimeout,
    require(name) {
      if (name === 'node:path') return path;
      if (name === 'node:fs') return { existsSync: () => true };
      if (name === 'express') return express;
      if (name === '@modelcontextprotocol/sdk/server/sse.js') return {};
      if (name === '../server/services/applicationDatabaseEngine') return { assertApplicationDatabaseEngine() {} };
      if (name === '../server/database/postgres/secureshopInitialization') return { async verifySecureShopRuntime() { calls.push('verify'); } };
      if (name.startsWith('./agents/')) return { createServer() {} };
      if (name === './shared/trace') return { async flush() { calls.push('flush'); if (flushError) throw flushError; } };
      if (name === '../server/database/postgres/secureshopPools') return { async closeSecureShopPools() { calls.push('pools'); } };
      throw new Error('Unexpected import: ' + name);
    },
    process: { env: bindHost === undefined ? {} : { SS_AGENT_HOST_BIND_HOST: bindHost }, stdout: { write: value => stdout.push(value) }, stderr: { write: value => stderr.push(value) },
      exit: code => exits.push(code), on: (name, callback) => signals.set(name, callback) },
  }, { filename: entry });
  await new Promise(resolve => setImmediate(resolve));
  return { calls, listenArguments, stdout, stderr, exits, signals, server };
}

test('default listener keeps the single-port Express invocation', async () => {
  const f = await boot();
  assert.deepEqual(f.listenArguments, [[8082]]);
});

test('explicit loopback host uses the two-argument bind overload', async () => {
  const f = await boot({ bindHost: '127.0.0.1' });
  assert.deepEqual(f.listenArguments, [[8082, '127.0.0.1']]);
});

test('invalid explicit listener hosts fail before runtime verification or bind', async () => {
  for (const bindHost of ['0.0.0.0', 'localhost', '::1', '127.0.0.2']) {
    const f = await boot({ bindHost });
    assert.deepEqual(f.listenArguments, []);
    assert.deepEqual(f.calls, []);
    assert.deepEqual(f.exits, [1]);
    assert.match(f.stderr.join(''), /SS_AGENT_HOST_BIND_HOST must be exactly 127\.0\.0\.1/);
  }
});

test('an empty optional host keeps default bind behavior', async () => {
  const f = await boot({ bindHost: '' });
  assert.deepEqual(f.listenArguments, [[8082]]);
});

test('Express bind error is retained, never dereferences address or announces ready, and closes owned pools', async () => {
  const f = await boot({ listenError: Object.assign(new Error('listen EADDRINUSE'), { code: 'EADDRINUSE' }) });
  assert.deepEqual(f.calls, ['verify', 'close', 'flush', 'pools']);
  assert.deepEqual(f.stdout, []); assert.deepEqual(f.exits, [1]);
  assert.match(f.stderr.join(''), /EADDRINUSE/); assert.doesNotMatch(f.stderr.join(''), /TypeError/);
});

test('listener without a bound address fails readiness and still closes pools after trace failure', async () => {
  const f = await boot({ address: null, flushError: new Error('controlled flush failure') });
  assert.deepEqual(f.stdout, []); assert.deepEqual(f.exits, [1]);
  assert.ok(f.calls.includes('pools'));
  assert.match(f.stderr.join(''), /listener has no bound address/);
  assert.match(f.stderr.join(''), /startup cleanup failed/);
});

test('successful listener publishes its bound port and repeated signals close only owned resources once', async () => {
  const f = await boot({ address: { port: 40123 } });
  assert.deepEqual(f.stdout, ['agent-host: ready on 40123\n']);
  f.signals.get('SIGTERM')(); f.signals.get('SIGINT')();
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(f.exits, [0]);
  assert.equal(f.calls.filter(call => call === 'close').length, 1);
  assert.equal(f.calls.filter(call => call === 'pools').length, 1);
});
