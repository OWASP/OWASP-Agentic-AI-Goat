'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { main } = require('../scripts/owned-child-guardian');

function harness({ platform = 'win32', channel = 'ipc', shell = 'direct', spawnError = false } = {}) {
  const runtime = new EventEmitter(), child = new EventEmitter();
  const messages = [], callbacks = [], exits = [], kills = [], spawns = [];
  Object.assign(runtime, { pid: 314, connected: true, env: { CONTROLLED: 'yes' },
    stderr: { write() {} }, exit: code => exits.push(code),
    send(message, callback) { messages.push(message); if (callback) callbacks.push(callback); },
  });
  child.kill = signal => kills.push(signal);
  main(['controlled-node', JSON.stringify(['controlled-application.js']), channel, shell], {
    platform, runtime, retain() {}, spawnProcess(...args) {
      spawns.push(args); if (spawnError) throw Error('controlled spawn denied'); return child;
    },
  });
  const hello = () => {
    runtime.emit('message', { type: 'dvaia-owned-guardian-hello' });
    return messages.at(-1).challenge;
  };
  const prove = () => {
    const challenge = hello(), nonce = 'ab'.repeat(32);
    runtime.emit('message', { type: 'dvaia-owned-guardian-probe', challenge, nonce });
    return { challenge, nonce };
  };
  const activate = () => {
    const proof = prove();
    runtime.emit('message', { type: 'dvaia-owned-guardian-activate', ...proof });
    return proof;
  };
  return { runtime, child, messages, callbacks, exits, kills, spawns, hello, prove, activate };
}

test('controlled Windows guardian launches only after activation delivery following proof', () => {
  const h = harness();
  assert.deepEqual(h.spawns, []); assert.deepEqual(h.messages, []);
  const challenge = h.hello(), nonce = '12'.repeat(32);
  assert.match(challenge, /^[a-f0-9]{64}$/);
  assert.deepEqual(h.messages.at(-1), { type: 'dvaia-owned-guardian-ready', pid: 314, challenge });
  h.runtime.emit('message', { type: 'dvaia-owned-guardian-probe', challenge, nonce });
  assert.deepEqual(h.messages.at(-1), { type: 'dvaia-owned-guardian-proof', pid: 314, challenge, nonce });
  assert.deepEqual(h.spawns, []);
  h.runtime.emit('message', { type: 'dvaia-owned-guardian-activate', challenge, nonce });
  assert.deepEqual(h.messages.at(-1), { type: 'dvaia-owned-guardian-active', pid: 314, challenge, nonce });
  assert.deepEqual(h.spawns, []);
  h.callbacks.shift()();
  assert.deepEqual(h.spawns, [['controlled-node', ['controlled-application.js'], {
    env: h.runtime.env, stdio: ['inherit', 'inherit', 'inherit', 'ipc'], shell: false,
  }]]);
});

test('controlled Windows disconnect or stop at every admission stage never launches workload', () => {
  for (const phase of ['waiting', 'hello', 'proof', 'activation-delivery']) {
    for (const termination of ['disconnect', 'stop']) {
      const h = harness();
      if (phase === 'hello') h.hello();
      if (phase === 'proof') h.prove();
      if (phase === 'activation-delivery') h.activate();
      if (termination === 'disconnect') { h.runtime.connected = false; h.runtime.emit('disconnect'); }
      else h.runtime.emit('message', { type: 'dvaia-owned-guardian-stop' });
      for (const callback of h.callbacks) callback();
      assert.deepEqual(h.spawns, []); assert.deepEqual(h.exits, [0]); assert.deepEqual(h.kills, []);
    }
  }
});

test('controlled Windows invalid, stale and out-of-order admission messages fail closed', () => {
  const cases = [
    h => h.runtime.emit('message', { type: 'dvaia-owned-guardian-activate', challenge: 'a'.repeat(64), nonce: 'b'.repeat(64) }),
    h => h.runtime.emit('message', { type: 'dvaia-owned-guardian-hello', extra: true }),
    h => { const challenge = h.hello(); h.runtime.emit('message', { type: 'dvaia-owned-guardian-probe', challenge, nonce: 'short' }); },
    h => { h.hello(); h.runtime.emit('message', { type: 'dvaia-owned-guardian-probe', challenge: 'wrong', nonce: 'a'.repeat(64) }); },
    h => { const proof = h.prove(); h.runtime.emit('message', { type: 'dvaia-owned-guardian-activate', ...proof, nonce: 'f'.repeat(64) }); },
    h => { const proof = h.prove(); h.runtime.emit('message', { type: 'dvaia-owned-guardian-activate', ...proof, extra: true }); },
    h => { h.hello(); h.hello(); },
  ];
  for (const invalid of cases) { const h = harness(); invalid(h); assert.deepEqual(h.spawns, []); assert.deepEqual(h.exits, [2]); }
});

test('controlled Windows activation IPC failure never launches work', () => {
  const h = harness(); h.activate(); h.callbacks.shift()(Error('controlled IPC loss'));
  assert.deepEqual(h.spawns, []); assert.deepEqual(h.exits, [2]);
  const thrown = harness(); const proof = thrown.prove(); thrown.runtime.send = () => { throw Error('closed IPC'); };
  thrown.runtime.emit('message', { type: 'dvaia-owned-guardian-activate', ...proof });
  assert.deepEqual(thrown.spawns, []); assert.deepEqual(thrown.exits, [2]);
});

test('controlled activated guardian forwards backend readiness and one child outcome', () => {
  const h = harness(); h.activate(); h.callbacks.shift()();
  h.child.emit('message', { type: 'other' });
  h.child.emit('message', { type: 'dvaia-backend-ready', pid: 999, port: 8081 });
  assert.deepEqual(h.messages.at(-1), { type: 'dvaia-backend-ready', pid: 314, port: 8081 });
  h.child.emit('exit', 7, null); h.child.emit('error', Error('late failure'));
  assert.deepEqual(h.messages.filter(message => message.type === 'dvaia-owned-child-outcome'),
    [{ type: 'dvaia-owned-child-outcome', outcome: { type: 'exit', code: 7, signal: null } }]);
  assert.deepEqual(h.exits, []);
});

test('controlled activated guardian requests direct child stop then exits for owning job drain', () => {
  for (const event of ['stop', 'disconnect', 'SIGTERM']) {
    const h = harness(); h.activate(); h.callbacks.shift()();
    if (event === 'stop') h.runtime.emit('message', { type: 'dvaia-owned-guardian-stop' });
    else h.runtime.emit(event);
    assert.deepEqual(h.kills, ['SIGTERM']); assert.deepEqual(h.exits, [0]);
    h.runtime.emit('disconnect'); assert.deepEqual(h.kills, ['SIGTERM']);
  }
});

test('controlled spawn failures report outcomes only after activation and retain guardian', () => {
  const h = harness({ spawnError: true }); assert.deepEqual(h.messages, []);
  h.activate(); h.callbacks.shift()();
  assert.deepEqual(h.messages.at(-1), { type: 'dvaia-owned-child-outcome', outcome: { type: 'error' } });
  assert.deepEqual(h.exits, []);
});

test('POSIX controlled guardian retains immediate launch and plain shell options', () => {
  const h = harness({ platform: 'linux', channel: 'plain', shell: 'shell' });
  assert.equal(h.spawns.length, 1); assert.equal(h.spawns[0][2].shell, true); assert.equal(h.spawns[0][2].stdio, 'inherit');
  h.runtime.emit('SIGTERM'); assert.deepEqual(h.kills, ['SIGTERM']); assert.deepEqual(h.exits, [0]);
});
