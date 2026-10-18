'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter, once } = require('node:events');
const { spawn } = require('node:child_process');
const { AgentHostSupervisor } = require('../server/services/secureshop/agentHostSupervisor');
const { settleSecureShopCleanup } = require('../server/services/secureshop');

test('agent host uses the current Node executable and a per-instance readiness identity', () => {
  let captured;
  const child = new EventEmitter();
  const supervisor = new AgentHostSupervisor({ spawnProcess: (...args) => { captured = args; return child; } });
  supervisor._spawn();
  assert.equal(captured[0], process.execPath);
  assert.equal(captured[2].env.SS_AGENT_HOST_INSTANCE_ID, supervisor.instanceId);
  assert.notEqual(captured[2].detached, true, 'the host must remain in its outer owned process group');
  assert.notEqual(new AgentHostSupervisor().instanceId, supervisor.instanceId);
});

test('agent host restarts preserve the originally selected provider and model environment', () => {
  const selected = { AI_PROVIDER: 'ollama', OLLAMA_BASE_URL: 'http://127.0.0.1:11434',
    OLLAMA_MODEL: 'qualified-local-model', SS_AGENT_HOST_PORT: '9999',
    SS_AGENT_HOST_INSTANCE_ID: 'caller-value' };
  const children = []; const spawns = [];
  const supervisor = new AgentHostSupervisor({ port: 48182, env: selected, spawnProcess: (...args) => {
    const child = new EventEmitter(); child.exitCode = null; child.signalCode = null;
    child.kill = () => {};
    children.push(child); spawns.push(args); return child;
  } });
  supervisor.status = 'running';
  supervisor.proc = supervisor._spawn();
  selected.AI_PROVIDER = 'mock'; selected.OLLAMA_MODEL = 'changed-after-construction';
  children[0].emit('exit', 1);
  assert.equal(spawns.length, 2);
  for (const [, , options] of spawns) {
    assert.equal(options.env.AI_PROVIDER, 'ollama');
    assert.equal(options.env.OLLAMA_BASE_URL, 'http://127.0.0.1:11434');
    assert.equal(options.env.OLLAMA_MODEL, 'qualified-local-model');
    assert.equal(options.env.SS_AGENT_HOST_PORT, '48182');
    assert.equal(options.env.SS_AGENT_HOST_INSTANCE_ID, supervisor.instanceId);
  }
});

test('restart exhaustion notifies its terminal owner exactly once and intentional stop does not notify it', async () => {
  const children = [];
  const failures = [];
  const supervisor = new AgentHostSupervisor({ restartLimit: 1, onTerminalFailure: error => failures.push(error),
    spawnProcess: () => {
      const child = new EventEmitter();
      child.exitCode = null; child.signalCode = null;
      child.kill = () => { child.signalCode = 'SIGTERM'; child.emit('exit', null, 'SIGTERM'); };
      children.push(child);
      return child;
    } });
  supervisor.status = 'running';
  supervisor.proc = supervisor._spawn();
  children[0].exitCode = 1; children[0].emit('exit', 1);
  assert.equal(children.length, 2, 'one bounded restart is permitted');
  children[1].exitCode = 1; children[1].emit('exit', 1);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(supervisor.status, 'dead');
  assert.equal(failures.length, 1);
  assert.equal(failures[0].code, 'SS_AGENT_HOST_RESTART_LIMIT');
  children[1].emit('exit', 1);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(failures.length, 1);

  const stopped = new AgentHostSupervisor({ onTerminalFailure: error => failures.push(error) });
  const child = new EventEmitter(); child.exitCode = null; child.signalCode = null;
  child.kill = () => { child.signalCode = 'SIGTERM'; child.emit('exit', null, 'SIGTERM'); };
  stopped.status = 'running'; stopped.proc = child;
  await stopped.stop();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(failures.length, 1, 'an owned shutdown is not a terminal failure');
});

test('a stalled health request is destroyed and never accepted as readiness', async () => {
  let destroyed = false;
  const supervisor = new AgentHostSupervisor({ get: () => {
    const request = new EventEmitter();
    request.setTimeout = (_ms, callback) => { queueMicrotask(callback); return request; };
    request.destroy = error => { destroyed = true; supervisor.status = 'dead'; request.emit('error', error); };
    return request;
  } });
  supervisor.status = 'starting';
  await assert.rejects(supervisor._waitHealthy(), /never healthy/);
  assert.equal(destroyed, true);
});

test('health from an unrelated process cannot mark the spawned host ready', async () => {
  const supervisor = new AgentHostSupervisor({ get: (_url, callback) => {
    const request = new EventEmitter();
    request.setTimeout = () => request;
    queueMicrotask(() => {
      const response = new EventEmitter(); response.statusCode = 200;
      callback(response);
      response.emit('data', JSON.stringify({ ok: true, instanceId: 'another-process' }));
      supervisor.status = 'dead'; response.emit('end');
    });
    return request;
  } });
  supervisor.status = 'starting';
  await assert.rejects(supervisor._waitHealthy(), /never healthy/);
});

test('stop handles already exited children and bounds an unresponsive child', async () => {
  const supervisor = new AgentHostSupervisor({ stopTimeoutMs: 10 });
  const exited = new EventEmitter(); exited.exitCode = 1; exited.signalCode = null;
  exited.kill = () => assert.fail('An exited process must not be signalled');
  supervisor.proc = exited;
  await supervisor.stop();
  const signals = [];
  const stuck = new EventEmitter(); stuck.exitCode = null; stuck.signalCode = null;
  stuck.kill = signal => {
    signals.push(signal);
    if (signal === 'SIGKILL') queueMicrotask(() => {
      stuck.signalCode = 'SIGKILL'; stuck.emit('exit', null, 'SIGKILL');
    });
  };
  supervisor.proc = stuck;
  await supervisor.stop();
  assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(supervisor.status, 'stopped');
  assert.equal(supervisor.proc, null);
});

test('stop never reports success or loses ownership while a killed child remains live', async () => {
  const supervisor = new AgentHostSupervisor({ stopTimeoutMs: 5 });
  const child = new EventEmitter(); child.exitCode = null; child.signalCode = null;
  const signals = []; child.kill = signal => signals.push(signal);
  supervisor.proc = child;
  await assert.rejects(supervisor.stop(), { code: 'SS_AGENT_HOST_STOP_TIMEOUT' });
  assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(supervisor.status, 'dead');
  assert.equal(supervisor.proc, child, 'the outer owner must retain the live child handle');
});

test('stop observes SIGKILL exit from a real owned Node child that ignores SIGTERM', {
  timeout: 5000,
}, async t => {
  let child;
  const supervisor = new AgentHostSupervisor({ stopTimeoutMs: 25, spawnProcess: () => {
    child = spawn(process.execPath, ['-e', [
      "process.on('SIGTERM',()=>process.stdout.write('term\\n'));",
      "process.stdout.write('ready\\n');",
      'setInterval(()=>{},1000);',
    ].join('')], { stdio: ['ignore', 'pipe', 'pipe'] });
    return child;
  } });
  t.after(async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await Promise.race([once(child, 'exit'), new Promise(resolve => setTimeout(resolve, 1000))]);
    }
  });
  supervisor.status = 'running'; supervisor.proc = supervisor._spawn();
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('owned child readiness timeout')), 2000);
    child.stdout.once('data', bytes => {
      clearTimeout(timer);
      String(bytes).includes('ready') ? resolve() : reject(new Error('owned child readiness invalid'));
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
  });
  const pid = child.pid;
  await supervisor.stop();
  assert.equal(child.signalCode, 'SIGKILL');
  assert.equal(supervisor.proc, null);
  assert.throws(() => process.kill(pid, 0), error => error?.code === 'ESRCH');
});

test('aggregate shutdown attempts every owned cleanup and rejects if the child remains live', async () => {
  const calls = [];
  const childError = Object.assign(new Error('child still live'), { code: 'SS_AGENT_HOST_STOP_TIMEOUT' });
  await assert.rejects(settleSecureShopCleanup([
    async () => { calls.push('pool'); },
    async () => { calls.push('host'); throw childError; },
  ]), error => error instanceof AggregateError && error.errors.length === 1
    && error.errors[0] === childError);
  assert.deepEqual(calls, ['pool', 'host']);
});


test('concurrent starts wait for the same owned host readiness', async () => {
  let release, spawns = 0;
  const child = new EventEmitter(); child.exitCode = null; child.signalCode = null;
  const supervisor = new AgentHostSupervisor({ spawnProcess: () => { spawns++; return child; } });
  supervisor._waitHealthy = () => new Promise(resolve => { release = resolve; });
  let firstDone = false, secondDone = false;
  const first = supervisor.start().then(() => { firstDone = true; });
  const second = supervisor.start().then(() => { secondDone = true; });
  await Promise.resolve();
  assert.equal(spawns, 1); assert.equal(firstDone, false); assert.equal(secondDone, false);
  release(); await Promise.all([first, second]);
  assert.equal(supervisor.status, 'running');
});

test('same-instance unhealthy response cannot satisfy readiness', async () => {
  const supervisor = new AgentHostSupervisor({ get: (_url, callback) => {
    const request = new EventEmitter(); request.setTimeout = () => request;
    queueMicrotask(() => {
      const response = new EventEmitter(); response.statusCode = 200; callback(response);
      response.emit('data', JSON.stringify({ ok: false, instanceId: supervisor.instanceId }));
      supervisor.status = 'dead'; response.emit('end');
    });
    return request;
  } });
  supervisor.status = 'starting';
  await assert.rejects(supervisor._waitHealthy(), /never healthy/);
});

test('health completion after stop cannot revive the stopped host', async () => {
  let respond;
  const supervisor = new AgentHostSupervisor({ get: (_url, callback) => {
    const request = new EventEmitter(); request.setTimeout = () => request;
    respond = () => {
      const response = new EventEmitter(); response.statusCode = 200; callback(response);
      response.emit('data', JSON.stringify({ ok: true, instanceId: supervisor.instanceId }));
      response.emit('end');
    };
    return request;
  } });
  supervisor.status = 'starting';
  const waiting = supervisor._waitHealthy();
  await new Promise(resolve => setTimeout(resolve, 220));
  await supervisor.stop(); respond();
  await assert.rejects(waiting, /never healthy/);
  assert.equal(supervisor.status, 'stopped');
});


test('spawn error plus close without exit preserves primary failure, releases ownership, and permits retry', async () => {
  const failure = Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' });
  let spawns = 0;
  const supervisor = new AgentHostSupervisor({ stopTimeoutMs: 5, spawnProcess: () => {
    const child = new EventEmitter(); child.exitCode = null; child.signalCode = null;
    child.kill = () => assert.fail('Never signal a process that did not spawn');
    spawns++;
    queueMicrotask(() => { child.emit('error', failure); child.emit('close', -2, null); });
    return child;
  }, get: () => assert.fail('Failed spawn must never be accepted by a health request') });
  await assert.rejects(supervisor.start(), error => error === failure && !error.cleanupError);
  assert.equal(supervisor.proc, null); assert.equal(supervisor.status, 'stopped');
  await assert.rejects(supervisor.start(), error => error === failure);
  assert.equal(spawns, 2); assert.equal(supervisor.proc, null);
});

test('failed spawn still waits for close and retains primary error if terminal proof never arrives', async () => {
  const failure = Object.assign(new Error('spawn EACCES'), { code: 'EACCES' });
  let child;
  const supervisor = new AgentHostSupervisor({ stopTimeoutMs: 5, spawnProcess: () => {
    child = new EventEmitter(); child.exitCode = null; child.signalCode = null;
    child.kill = () => assert.fail('Never signal a process that did not spawn');
    queueMicrotask(() => { child.exitCode = -13; child.emit('error', failure); }); return child;
  } });
  await assert.rejects(supervisor.start(), error => error === failure
    && error.cleanupError.code === 'SS_AGENT_HOST_STOP_TIMEOUT');
  assert.equal(supervisor.proc, child);
  child.emit('close', -13, null); await supervisor.stop();
  assert.equal(supervisor.proc, null);
});

test('runtime child error and close without exit cannot discard a spawned process handle', async () => {
  const signals = [], child = new EventEmitter(); child.pid = 12345;
  child.exitCode = null; child.signalCode = null; child.kill = signal => signals.push(signal);
  const supervisor = new AgentHostSupervisor({ stopTimeoutMs: 5, spawnProcess: () => child });
  supervisor.status = 'running'; supervisor.proc = supervisor._spawn();
  child.emit('error', Object.assign(new Error('send EPIPE'), { code: 'EPIPE' }));
  assert.equal(supervisor.status, 'running');
  child.emit('close');
  await assert.rejects(supervisor.stop(), { code: 'SS_AGENT_HOST_STOP_TIMEOUT' });
  assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']); assert.equal(supervisor.proc, child);
  child.exitCode = 1; await supervisor.stop(); assert.equal(supervisor.proc, null);
});
