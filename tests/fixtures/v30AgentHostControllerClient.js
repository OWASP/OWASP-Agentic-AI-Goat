'use strict';
// The controller owns the actual child. This proxy deliberately cannot spawn a
// command or infer process termination from a closed IPC channel.
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const net = require('node:net');
const { constants: osConstants } = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '../..');
const MAX_FRAME = 16384;
const RPC_TIMEOUT_MS = 30000;
const POLL_MS = 250;
const PHASES = new Set(['granted', 'bound', 'running', 'terminal', 'failed']);
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const exact = (value, keys) => {
  assert(value && Object.getPrototypeOf(value) === Object.prototype);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
};
const failure = code => Object.assign(new Error(code), { code });

// JSON.parse keeps the last duplicate key. A controller frame is authority,
// so first validate object keys recursively, including nested state objects.
function parseUniqueJson(bytes) {
  assert(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= MAX_FRAME);
  const source = bytes.toString('utf8');
  assert(Buffer.from(source, 'utf8').equals(bytes), 'Controller JSON must be canonical UTF-8');
  let at = 0;
  const space = () => { while (/\s/.test(source[at] || '')) at++; };
  const string = () => {
    const start = at++;
    assert.equal(source[start], '"');
    while (at < source.length) {
      if (source[at] === '\\') { at += 2; continue; }
      if (source[at++] === '"') return JSON.parse(source.slice(start, at));
    }
    throw failure('V30_CONTROLLER_REJECTED');
  };
  const value = depth => {
    assert(depth <= 16); space();
    if (source[at] === '{') {
      at++; space(); const keys = new Set();
      if (source[at] === '}') { at++; return; }
      while (at < source.length) {
        const key = string(); assert(!keys.has(key), 'Duplicate controller JSON key'); keys.add(key);
        space(); assert.equal(source[at++], ':'); value(depth + 1); space();
        const separator = source[at++]; if (separator === '}') return;
        assert.equal(separator, ','); space();
      }
    } else if (source[at] === '[') {
      at++; space(); if (source[at] === ']') { at++; return; }
      while (at < source.length) { value(depth + 1); space(); const separator = source[at++];
        if (separator === ']') return; assert.equal(separator, ','); }
    } else if (source[at] === '"') string();
    else {
      const rest = source.slice(at), match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(rest);
      assert(match, 'Invalid controller JSON value'); at += match[0].length;
    }
  };
  value(0); space(); assert.equal(at, source.length);
  return JSON.parse(source);
}

function checkState(state) {
  exact(state, ['phase', 'pid', 'birth', 'instanceId', 'hostPort', 'terminal', 'networkProof', 'cleanupVerified', 'receiptSha256']);
  assert(PHASES.has(state.phase));
  assert(state.pid === null || (Number.isSafeInteger(state.pid) && state.pid > 0));
  assert(state.birth === null || (Array.isArray(state.birth) && state.birth.length === 2 &&
    state.birth.every(v => Number.isSafeInteger(v) && v >= 0)));
  assert(state.instanceId === null || (typeof state.instanceId === 'string' && UUID.test(state.instanceId)));
  assert(Number.isInteger(state.hostPort) && state.hostPort >= 1024 && state.hostPort <= 65535);
  if (state.pid === null) assert.equal(state.birth, null);
  else assert(state.birth !== null);
  if (state.phase === 'granted' || state.phase === 'bound') {
    assert.equal(state.pid, null); assert.equal(state.instanceId, null); assert.equal(state.terminal, null);
  }
  if (state.phase === 'running') assert(state.pid !== null && state.instanceId !== null && state.terminal === null);
  if (state.terminal !== null) {
    exact(state.terminal, ['exitCode', 'signalCode']);
    assert(state.terminal.exitCode === null || Number.isInteger(state.terminal.exitCode));
    assert(state.terminal.signalCode === null || Object.hasOwn(osConstants.signals, state.terminal.signalCode));
    assert(state.terminal.exitCode !== null || state.terminal.signalCode !== null);
  }
  assert.equal(typeof state.cleanupVerified, 'boolean');
  assert(state.receiptSha256 === null || /^[a-f0-9]{64}$/.test(state.receiptSha256));
  if (state.networkProof !== null) {
    exact(state.networkProof, ['version', 'policySha256', 'probePid', 'probeTerminal', 'postgresAllowed',
      'modelDenied', 'externalDenied', 'loopbackBound', 'loopbackInboundVerified']);
    assert.equal(state.networkProof.version, 1);
    assert.match(state.networkProof.policySha256, /^[a-f0-9]{64}$/);
    assert(Number.isSafeInteger(state.networkProof.probePid) && state.networkProof.probePid > 0);
    exact(state.networkProof.probeTerminal, ['exitCode', 'signalCode']);
    assert.equal(state.networkProof.probeTerminal.exitCode, 0);
    assert.equal(state.networkProof.probeTerminal.signalCode, null);
    for (const key of ['postgresAllowed', 'modelDenied', 'externalDenied', 'loopbackBound',
      'loopbackInboundVerified']) assert.equal(state.networkProof[key], true);
  }
  return state;
}

class HostProxy extends EventEmitter {
  constructor(client, state) {
    super(); this.client = client; this.pid = state.pid; this.birth = state.birth;
    this.exitCode = null; this.signalCode = null; this._terminalEmitted = false;
  }
  kill(signal = 'SIGTERM') {
    if (!['SIGTERM', 'SIGKILL'].includes(signal)) throw failure('V30_CONTROLLER_REJECTED');
    if (this._terminalEmitted) return false;
    this.client.rpc('signal', { signal }).then(state => this.client.acceptState(state)).catch(error => this.client.fail(error));
    return true;
  }
  accept(state) {
    if (state.pid !== this.pid || JSON.stringify(state.birth) !== JSON.stringify(this.birth))
      throw failure('V30_CONTROLLER_REJECTED');
    if (state.terminal === null || this._terminalEmitted) return;
    this._terminalEmitted = true;
    this.exitCode = state.terminal.exitCode; this.signalCode = state.terminal.signalCode;
    // start() and _spawn() install their listeners synchronously after the
    // spawnProcess callback. A controller that reaps immediately cannot race.
    setImmediate(() => { this.emit('exit', this.exitCode, this.signalCode); this.emit('close', this.exitCode, this.signalCode); });
  }
}

class V30HostControllerClient {
  constructor({ socket, nonce, workerPid = process.pid, hostPort, expectedHostEnvironment = null }) {
    assert(socket && typeof socket.write === 'function' && typeof socket.on === 'function');
    assert.match(nonce, /^[0-9a-f]{64}$/);
    assert(Number.isSafeInteger(workerPid) && workerPid > 0);
    assert(Number.isInteger(hostPort) && hostPort >= 1024 && hostPort <= 65535);
    this.socket = socket; this.nonce = nonce; this.workerPid = workerPid; this.hostPort = hostPort;
    this.expectedHostEnvironment = expectedHostEnvironment;
    this.sequence = 0; this.buffer = Buffer.alloc(0); this.pending = null; this.failed = null; this.queue = Promise.resolve();
    this.proxy = null; this.started = null; this.pollTimer = null; this.closed = false; this.lastState = null;
    socket.on('data', chunk => this.onData(chunk));
    socket.on('error', error => this.fail(error));
    socket.on('close', () => { if (!this.closed) this.fail(failure('V30_CONTROLLER_UNQUALIFIED')); });
  }
  fail(error) {
    if (this.failed) return;
    this.failed = failure('V30_CONTROLLER_UNQUALIFIED'); this.failed.cause = error;
    if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; }
    if (this.pending) { const pending = this.pending; this.pending = null; clearTimeout(pending.timer); pending.reject(this.failed); }
    // An IPC failure is not an actual child exit. Never emit exit/close here.
    if (this.proxy) this.proxy.emit('error', this.failed);
  }
  onData(chunk) {
    if (this.failed || this.closed) return;
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > MAX_FRAME + 4) { this.fail(failure('V30_CONTROLLER_REJECTED')); return; }
    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);
      if (length === 0 || length > MAX_FRAME) { this.fail(failure('V30_CONTROLLER_REJECTED')); return; }
      if (this.buffer.length < length + 4) return;
      const frame = this.buffer.subarray(4, length + 4); this.buffer = this.buffer.subarray(length + 4);
      try { this.onFrame(parseUniqueJson(frame)); } catch (error) { this.fail(error); return; }
    }
  }
  onFrame(response) {
    exact(response, ['version', 'sequence', 'nonce', 'op', 'ok', 'result', 'error']);
    const pending = this.pending;
    assert(pending && response.version === 1 && response.sequence === pending.sequence &&
      response.nonce === this.nonce && response.op === pending.op);
    assert.equal(typeof response.ok, 'boolean');
    if (response.ok) { assert.equal(response.error, null); checkState(response.result); }
    else { assert.equal(response.result, null); assert(['V30_CONTROLLER_REJECTED', 'V30_CONTROLLER_UNQUALIFIED'].includes(response.error)); }
    this.pending = null; clearTimeout(pending.timer);
    response.ok ? pending.resolve(response.result) : pending.reject(failure(response.error));
  }
  rpc(op, payload = {}) {
    // A status poll may already be in flight when Supervisor calls kill().
    // Serialize requests; rejecting the signal would strand a live child.
    const task = this.queue.then(() => this._rpcNow(op, payload));
    this.queue = task.catch(() => {});
    return task;
  }
  _rpcNow(op, payload) {
    if (this.failed) return Promise.reject(this.failed);
    if (this.closed || this.pending) return Promise.reject(failure('V30_CONTROLLER_REJECTED'));
    assert(['hello', 'start', 'status', 'signal', 'release'].includes(op));
    const sequence = ++this.sequence, request = { version: 1, sequence, nonce: this.nonce, pid: this.workerPid, op, payload };
    const body = Buffer.from(JSON.stringify(request)); assert(body.length <= MAX_FRAME);
    const frame = Buffer.allocUnsafe(4 + body.length); frame.writeUInt32BE(body.length, 0); body.copy(frame, 4);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail(failure('V30_CONTROLLER_UNQUALIFIED')),
        op === 'start' ? 60000 : RPC_TIMEOUT_MS);
      this.pending = { sequence, op, timer, resolve, reject };
      try { this.socket.write(frame); } catch (error) { this.fail(error); }
    });
  }
  acceptState(state) {
    checkState(state); assert.equal(state.hostPort, this.hostPort);
    if (this.started && state.instanceId !== this.started.instanceId) throw failure('V30_CONTROLLER_REJECTED');
    if (this.proxy) this.proxy.accept(state);
    this.lastState = state; return state;
  }
  async hello() {
    const state = this.acceptState(await this.rpc('hello'));
    assert.equal(state.phase, 'bound'); return state;
  }
  async prepare(instanceId) {
    assert.match(instanceId, UUID);
    assert(!this.started && !this.proxy);
    const state = this.acceptState(await this.rpc('start', { instanceId }));
    assert.equal(state.phase, 'running'); assert.equal(state.instanceId, instanceId);
    assert(state.pid > 0 && state.networkProof !== null);
    this.started = { instanceId, pid: state.pid, birth: state.birth };
    this.lastState = state;
    return state;
  }
  spawnProcess(command, args, options) {
    if (this.failed) throw this.failed;
    assert(this.started && !this.proxy);
    assert.equal(command, process.execPath); assert.deepEqual(args, ['agent-host/index.js']);
    assert.equal(options.cwd, ROOT); assert.equal(options.env.SS_AGENT_HOST_PORT, String(this.hostPort));
    assert.equal(options.env.SS_AGENT_HOST_INSTANCE_ID, this.started.instanceId);
    assert.equal(options.env.SS_AGENT_HOST_BIND_HOST, '127.0.0.1');
    assert.deepEqual(options.stdio, ['ignore', 'inherit', 'inherit']);
    if (this.expectedHostEnvironment) assert.deepEqual(options.env,
      { ...this.expectedHostEnvironment, SS_AGENT_HOST_PORT: String(this.hostPort),
        SS_AGENT_HOST_INSTANCE_ID: this.started.instanceId });
    this.proxy = new HostProxy(this, this.lastState);
    this.pollTimer = setInterval(() => {
      if (this.pending || this.failed || this.closed || this.proxy?._terminalEmitted) return;
      this.rpc('status').then(state => this.acceptState(state)).catch(error => this.fail(error));
    }, POLL_MS);
    return this.proxy;
  }
  async release() {
    if (this.failed) throw this.failed;
    if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; }
    const state = this.acceptState(await this.rpc('release'));
    assert(state.terminal && state.cleanupVerified === true && /^[a-f0-9]{64}$/.test(state.receiptSha256));
    this.closed = true; this.socket.end(); return state;
  }
  closeUncertain() {
    if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; }
    this.closed = true; this.socket.destroy?.();
  }
  assertHealthy() { if (this.failed) throw this.failed; }
}

function consumeInheritedController(env = process.env, expectedHostEnvironment = null) {
  const fd = Number(env.DVAIA_V30_HOST_WORKER_FD), nonce = env.DVAIA_V30_HOST_NONCE;
  const hostPort = Number(env.V30_AGENT_HOST_PORT);
  assert(Number.isSafeInteger(fd) && fd >= 3 && Number.isSafeInteger(hostPort));
  delete env.DVAIA_V30_HOST_WORKER_FD; delete env.DVAIA_V30_HOST_NONCE;
  return new V30HostControllerClient({ socket: new net.Socket({ fd, readable: true, writable: true }),
    nonce, hostPort, expectedHostEnvironment });
}

module.exports = { V30HostControllerClient, consumeInheritedController, parseUniqueJson, checkState, MAX_FRAME, POLL_MS };
