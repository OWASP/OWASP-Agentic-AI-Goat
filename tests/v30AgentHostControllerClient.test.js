'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { V30HostControllerClient, parseUniqueJson, checkState, MAX_FRAME } = require('./fixtures/v30AgentHostControllerClient');

const ROOT = path.resolve(__dirname, '..');
const NONCE = 'a'.repeat(64);
const POLICY_SHA = 'b'.repeat(64);
const RECEIPT_SHA = 'c'.repeat(64);
const PORT = 54321;
const proof = { version: 1, policySha256: POLICY_SHA, probePid: 9991,
  probeTerminal: { exitCode: 0, signalCode: null }, postgresAllowed: true,
  modelDenied: true, externalDenied: true, loopbackBound: true, loopbackInboundVerified: true };
function state(phase = 'granted', instanceId = null) {
  const spawned = phase !== 'granted' && phase !== 'bound';
  return { phase, pid: spawned ? 9992 : null, birth: spawned ? [100, 1234] : null,
    instanceId: spawned ? instanceId : null, hostPort: PORT,
    terminal: phase === 'terminal' ? { exitCode: 0, signalCode: null } : null,
    networkProof: spawned ? proof : null, cleanupVerified: phase === 'terminal',
    receiptSha256: phase === 'terminal' ? RECEIPT_SHA : null };
}
function frame(value) {
  const body = Buffer.from(JSON.stringify(value)); const out = Buffer.alloc(body.length + 4);
  out.writeUInt32BE(body.length, 0); body.copy(out, 4); return out;
}
function fakeSocket(reply) {
  const socket = new EventEmitter(); socket.write = bytes => {
    const length = bytes.readUInt32BE(0); assert.equal(length, bytes.length - 4);
    const request = parseUniqueJson(bytes.subarray(4));
    setImmediate(() => { const response = reply(request); if (response) socket.emit('data', frame(response)); });
    return true;
  };
  socket.end = () => socket.emit('close');
  return socket;
}
function response(request, value) {
  return { version: 1, sequence: request.sequence, nonce: request.nonce, op: request.op,
    ok: true, result: value, error: null };
}
function newClient(reply) { return new V30HostControllerClient({ socket: fakeSocket(reply), nonce: NONCE,
  workerPid: 2345, hostPort: PORT }); }
function spawnOptions(instanceId) { return { cwd: ROOT, env: { SS_AGENT_HOST_PORT: String(PORT),
  SS_AGENT_HOST_INSTANCE_ID: instanceId, SS_AGENT_HOST_BIND_HOST: '127.0.0.1' },
  stdio: ['ignore', 'inherit', 'inherit'] }; }

test('authority frames reject duplicate nested keys, malformed lengths, and extra fields', () => {
  assert.throws(() => parseUniqueJson(Buffer.from('{"a":1,"a":2}')));
  assert.throws(() => parseUniqueJson(Buffer.from('{"a":{"b":1,"b":2}}')));
  assert.throws(() => parseUniqueJson(Buffer.from('{"a":1} x')));
  assert.throws(() => parseUniqueJson(Buffer.alloc(MAX_FRAME + 1)));
  assert.throws(() => parseUniqueJson(Buffer.from([0x7b,0x22,0xff,0x22,0x3a,0x31,0x7d])));
  const crashed=state('terminal',randomUUID());crashed.terminal={exitCode:null,signalCode:'SIGABRT'};
  assert.deepEqual(checkState(crashed).terminal,crashed.terminal);
  crashed.terminal.signalCode='SIGFAKE';assert.throws(()=>checkState(crashed));
});

test('one fixed-command proxy reflects only actual controller-reaped state', async () => {
  const id = randomUUID(); let actual = state('bound'), signals = 0, starts = 0;
  const client = newClient(request => {
    assert.equal(request.version, 1); assert.equal(request.nonce, NONCE);
    assert.equal(request.pid, 2345);
    if (request.op === 'hello') assert.deepEqual(request.payload, {});
    if (request.op === 'start') { starts++; assert.deepEqual(request.payload, { instanceId: id }); actual = state('running', id); }
    if (request.op === 'signal') { signals++; assert.deepEqual(request.payload, { signal: 'SIGTERM' }); actual = state('terminal', id); }
    if (request.op === 'release') assert.equal(actual.cleanupVerified, true);
    return response(request, actual);
  });
  assert.equal((await client.hello()).phase, 'bound');
  await client.prepare(id);
  const proxy = client.spawnProcess(process.execPath, ['agent-host/index.js'], spawnOptions(id));
  assert.equal(proxy.pid, 9992); assert.deepEqual(proxy.birth, [100, 1234]);
  assert.throws(() => client.spawnProcess(process.execPath, ['agent-host/index.js'], spawnOptions(id)));
  assert.throws(() => proxy.kill('SIGHUP'));
  const terminal = new Promise(resolve => proxy.once('close', (exitCode, signalCode) => resolve({ exitCode, signalCode })));
  assert.equal(proxy.kill('SIGTERM'), true);
  assert.deepEqual(await terminal, { exitCode: 0, signalCode: null });
  assert.equal(starts, 1); assert.equal(signals, 1);
  assert.equal(proxy.kill('SIGTERM'), false);
  assert.equal((await client.release()).cleanupVerified, true);
});

test('wrong command, executable, cwd, instance, and bind host never reach controller', async () => {
  const id = randomUUID(); let calls = 0;
  const client = newClient(request => { calls++; return response(request,
    request.op === 'start' ? state('running', id) : state('bound')); });
  await client.hello(); await client.prepare(id); assert.equal(calls, 2);
  for (const [command, args, options] of [
    ['/bin/sh', ['agent-host/index.js'], spawnOptions(id)],
    [process.execPath, ['other.js'], spawnOptions(id)],
    [process.execPath, ['agent-host/index.js'], { ...spawnOptions(id), cwd: '/tmp' }],
    [process.execPath, ['agent-host/index.js'], { ...spawnOptions(id), env: { ...spawnOptions(id).env, SS_AGENT_HOST_BIND_HOST: '0.0.0.0' } }],
    [process.execPath, ['agent-host/index.js'], { ...spawnOptions(id), env: { ...spawnOptions(id).env, SS_AGENT_HOST_INSTANCE_ID: randomUUID() } }],
  ]) assert.throws(() => client.spawnProcess(command, args, options));
  assert.equal(calls, 2);
  // The test has no process to retire; simulate an uncertain channel instead.
  client.socket.emit('close'); assert.throws(() => client.assertHealthy(), { code: 'V30_CONTROLLER_UNQUALIFIED' });
});

test('IPC loss and false terminal responses never fabricate an exit', async () => {
  const id = randomUUID(); let actual = state('bound');
  const socket = fakeSocket(request => response(request, request.op === 'start' ? (actual = state('running', id)) : actual));
  const client = new V30HostControllerClient({ socket, nonce: NONCE, workerPid: 2345, hostPort: PORT });
  await client.hello(); await client.prepare(id);
  const proxy = client.spawnProcess(process.execPath, ['agent-host/index.js'], spawnOptions(id));
  let exits = 0; proxy.on('exit', () => exits++); proxy.on('error', () => {});
  socket.emit('close');
  assert.equal(exits, 0); assert.equal(proxy.exitCode, null);
  assert.throws(() => client.assertHealthy(), { code: 'V30_CONTROLLER_UNQUALIFIED' });
  await assert.rejects(client.release(), { code: 'V30_CONTROLLER_UNQUALIFIED' });
});
