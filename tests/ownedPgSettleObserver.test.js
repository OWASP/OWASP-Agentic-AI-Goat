'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { EventEmitter } = require('node:events');
const { observe, groupAbsent } = require('./postgres/ownedPgSettleObserver');

test('successful exact nested retirement carries bounded raw inventory', async () => {
  const terminal = await observe({ workMs: 1000, retirementMs: 100,
    execute: (_signal, launch) => new Promise((resolve, reject) => {
      const child = launch(process.execPath, ['-e', 'process.stdout.write("inventory")'],
        { detached: true, stdio: ['ignore', 'pipe', 'ignore'] });
      let raw = '';
      child.stdout.on('data', bytes => { raw += bytes; });
      child.on('error', reject);
      child.on('close', () => resolve(raw));
    }) });
  assert.equal(terminal.localRetirementVerified, true);
  assert.equal(terminal.failureCode, null);
  assert.equal(Buffer.from(terminal.inventoryBase64, 'base64').toString(), 'inventory');
});

test('real detached child ignoring TERM is not retired until KILL and close', async () => {
  const child = spawn(process.execPath,
    ['-e', 'process.on("SIGTERM",()=>{}); process.stdout.write("ready"); setInterval(()=>{},1000)'],
    { detached: true, stdio: ['ignore', 'pipe', 'ignore'] });
  await new Promise((resolve, reject) => {
    child.stdout.once('data', bytes => bytes.toString().includes('ready') ? resolve() : reject(new Error('not ready')));
    child.once('error', reject);
  });
  let killSent = false, closeSignal = null, killTimer;
  let terminal;
  try {
    terminal = await observe({ workMs: 25, retirementMs: 500,
      launch: () => child,
      execute: (signal, launch) => new Promise((resolve, reject) => {
      launch('already-ready', [], { detached: true });
      child.on('error', reject);
      child.on('close', (_code, termination) => {
        clearTimeout(killTimer); closeSignal = termination; resolve('too late');
      });
      signal.addEventListener('abort', () => {
        try { process.kill(-child.pid, 'SIGTERM'); } catch {}
        killTimer = setTimeout(() => {
          if (!groupAbsent(child.pid) && child.exitCode === null && child.signalCode === null) {
            killSent = true;
            try { process.kill(-child.pid, 'SIGKILL'); } catch {}
          }
        }, 25);
      }, { once: true });
    }) });
  } finally {
    clearTimeout(killTimer);
    if (!groupAbsent(child.pid)) try { process.kill(-child.pid, 'SIGKILL'); } catch {}
  }
  assert.equal(terminal.workExpired, true);
  assert.equal(terminal.completed, true);
  assert.equal(terminal.localRetirementVerified, true);
  assert.equal(terminal.inventoryBase64, null);
  assert.equal(killSent, true);
  assert.equal(closeSignal, 'SIGKILL');
  assert.equal(groupAbsent(child.pid), true);
});

test('never-settling child retains debt and never publishes inventory', async () => {
  const terminal = await observe({ workMs: 10, retirementMs: 25,
    absent: () => false,
    execute: (_signal, launch) => {
      launch('unused', [], { detached: true });
      return new Promise(() => {});
    }, launch: () => Object.assign(new EventEmitter(), { pid: 999999 }) });
  assert.equal(terminal.completed, false);
  assert.equal(terminal.localRetirementVerified, false);
  assert.equal(terminal.failureCode, 'PG_OBSERVER_RETIREMENT_TIMEOUT');
  assert.equal(terminal.inventoryBase64, null);
});

test('missing owned child close or group absence cannot certify retirement', async () => {
  for (const closed of [false, true]) {
    const terminal = await observe({ workMs: 50, retirementMs: 20,
      absent: () => closed ? false : true,
      launch: () => Object.assign(new EventEmitter(), { pid: 100 }),
      execute: (_signal, launch) => {
        const child = launch('unused', [], { detached: true });
        if (closed) child.emit('close', 0, null);
        return 'inventory';
      } });
    assert.equal(terminal.localRetirementVerified, false);
    assert.equal(terminal.inventoryBase64, null);
  }
});
