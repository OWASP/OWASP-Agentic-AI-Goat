'use strict';
// Controlled protocol and source checks. No PowerShell/Win32 APIs are executed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough, Writable } = require('node:stream');
const fs = require('node:fs');
const path = require('node:path');
const { createWindowsOwnedProcess } = require('../scripts/lib/windows-owned-process');
const denial = { code: 'WINDOWS_OWNED_PROCESS_DENIED' };
const challenge = 'a'.repeat(64), birth = '18446744073709551615';
function controlled({ transform, proof, active, retained = false, ready = true, helperExit = true } = {}) {
  const requests = [], events = [];
  let members = [], assigned = false, pins = 0;
  const helper = new EventEmitter(); helper.stdout = new PassThrough();
  helper.kill = () => { events.push('helper-close'); members = []; helper.emit('close', 1); };
  helper.stdin = new Writable({ write(chunk, _encoding, done) {
    const request = JSON.parse(chunk); requests.push(request); events.push(request.operation);
    let data;
    if (request.operation === 'pin') { pins++; data = { pid: request.data.pid, creationFileTime: birth }; }
    if (request.operation === 'assign') { assigned = true; members = [123]; data = { assigned: true }; }
    if (request.operation === 'members') data = { activeCount: members.length, pids: [...members] };
    if (request.operation === 'guardianOnly') data = { guardianOnly: assigned && members.length === 1 && members[0] === 123 };
    if (request.operation === 'terminate') { if (!retained) members = []; data = { terminated: true }; }
    const response = { version: 1, id: request.id, operation: request.operation, ok: true, data };
    const changed = transform?.(response, request);
    setImmediate(() => helper.stdout.write((typeof changed === 'string' ? changed : JSON.stringify(changed || response)) + '\n'));
    done();
  } });
  helper.stdin.on('finish', () => { if (helperExit) setImmediate(() => helper.emit('close', 0)); });
  const child = new EventEmitter(); child.pid = 123; child.connected = true;
  child.exitCode = null; child.signalCode = null;
  child.disconnect = () => { child.connected = false; events.push('guardian-disconnect'); child.emit('disconnect'); };
  child.send = (message, callback) => {
    events.push(message.type);
    if (message.type === 'owasp-ai-goat-owned-guardian-hello') setImmediate(() => child.emit('message', { type: 'owasp-ai-goat-owned-guardian-ready', pid: 123, challenge }));
    if (message.type === 'owasp-ai-goat-owned-guardian-probe') {
      assert.equal(pins, 1, 'native handle opens before IPC proof');
      setImmediate(() => proof ? proof(child, message) : child.emit('message', { type: 'owasp-ai-goat-owned-guardian-proof', pid: 123, challenge, nonce: message.nonce }));
    }
    if (message.type === 'owasp-ai-goat-owned-guardian-activate') {
      assert(assigned, 'job assignment must precede activation');
      setImmediate(() => active ? active(child, message) : child.emit('message', { type: 'owasp-ai-goat-owned-guardian-active', pid: 123, challenge, nonce: message.nonce }));
    }
    callback?.();
  };
  let launch;
  const create = () => createWindowsOwnedProcess({ platform: 'win32', systemRoot: 'C:\\Windows', timeoutMs: 200, pollMs: 1,
    spawnProcess(executable, args, options) {
      launch = { executable, args, options };
      if (ready) setImmediate(() => helper.stdout.write('{"version":1,"event":"ready"}\n'));
      return helper;
    } });
  const admit = async adapter => {
    const result = adapter.admitGuardian(child);
    return result;
  };
  return { create, admit, child, helper, requests, events, setMembers(value) { members = value; }, get launch() { return launch; } };
}

test('held-handle challenge and activation order, exact identity, safe helper executable', async () => {
  const c = controlled(), adapter = await c.create();
  assert.deepEqual(await c.admit(adapter), { pid: 123, creationFileTime: birth });
  assert.deepEqual(c.events, ['owasp-ai-goat-owned-guardian-hello', 'pin', 'owasp-ai-goat-owned-guardian-probe', 'assign', 'members', 'owasp-ai-goat-owned-guardian-activate']);
  assert.equal(c.launch.executable, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.deepEqual(c.launch.options.stdio, ['pipe', 'pipe', 'ignore']);
  assert.equal(c.launch.options.shell, false); assert.equal(c.launch.options.windowsHide, true);
  assert.equal(c.launch.args.length, 5); assert.equal(c.launch.args[4], path.resolve(__dirname, '../scripts/windows/windows-owned-process.ps1'));
  assert.equal(await adapter.assertGuardianOnly().then(value => value.creationFileTime), birth);
  assert(Object.isFrozen(await adapter.members()));
  await adapter.stop({ graceMs: 0 }); await adapter.close();
});

test('PID reuse/preactivation exit cannot assign after proof failure', async () => {
  for (const proof of [(child) => child.emit('exit', 0), (child, message) => child.emit('message', { type: 'owasp-ai-goat-owned-guardian-proof', pid: 456, challenge, nonce: message.nonce }),
    (child, message) => child.emit('message', { type: 'owasp-ai-goat-owned-guardian-proof', pid: 123, challenge, nonce: 'b'.repeat(64) })]) {
    const c = controlled({ proof }), adapter = await c.create();
    await assert.rejects(c.admit(adapter), denial);
    assert(!c.requests.some(value => value.operation === 'assign'));
    assert(c.events.includes('helper-close')); assert(c.events.includes('guardian-disconnect'));
  }
});

test('native assignment denial/nested-job conflict rejects and never activates', async () => {
  const c = controlled({ transform(response, request) { if (request.operation === 'assign') return { ...response, ok: false, data: { nativeDiagnostic: 'synthetic private error' } }; } });
  const adapter = await c.create();
  await assert.rejects(c.admit(adapter), error => error.code === denial.code && !JSON.stringify(error).includes('synthetic'));
  assert(!c.events.includes('owasp-ai-goat-owned-guardian-activate'));
  await assert.rejects(adapter.members(), denial);
});

test('64-bit FILETIME stays exact and malformed identities cannot reach assignment', async () => {
  for (const creationFileTime of [18446744073709551615, '18446744073709551616', '01', '0', '-1', null]) {
    const c = controlled({ transform(response, request) { if (request.operation === 'pin') return { ...response, data: { pid: 123, creationFileTime } }; } });
    const adapter = await c.create(); await assert.rejects(c.admit(adapter), denial);
    assert(!c.requests.some(value => value.operation === 'assign'));
  }
});

test('surviving grandchild blocks phase-only authorization, close and drain even after root exits', async () => {
  const c = controlled({ retained: true }), adapter = await c.create(); await c.admit(adapter);
  c.setMembers([123, 456]); await assert.rejects(adapter.assertGuardianOnly(), denial);
  c.setMembers([456]);
  await assert.rejects(adapter.close(), denial);
  const stopping = adapter.stop({ graceMs: 0, drainTimeoutMs: 3 }); c.child.emit('exit', 0);
  await assert.rejects(stopping, denial);
  assert(c.requests.some(value => value.operation === 'terminate'));
  c.setMembers([]); await adapter.waitForDrain(); await adapter.close();
});

test('graceful stop and repeated forced stop are idempotent, never terminate foreign PIDs', async () => {
  const c = controlled(), adapter = await c.create(); await c.admit(adapter);
  c.setMembers([123, 456]);
  const first = adapter.stop({ graceMs: 0 }); assert.equal(adapter.stop({ graceMs: 0 }), first);
  await first;
  assert.equal(c.requests.filter(value => value.operation === 'terminate').length, 1);
  assert.deepEqual(c.requests.find(value => value.operation === 'terminate').data, {});
  assert(!c.requests.some(value => ['kill','taskkill'].includes(value.operation)));
  await adapter.close();
  const d = controlled(), graceful = await d.create(); await d.admit(graceful); d.setMembers([]);
  await graceful.stop({ graceMs: 3 }); assert(!d.requests.some(value => value.operation === 'terminate')); await graceful.close();
});

test('helper EOF, crash and malformed query fail closed and reject lifetime authority', async () => {
  for (const mode of ['eof','crash','query']) {
    const c = controlled({ transform(response, request) { if (mode === 'query' && request.operation === 'members') return { ...response, data: { activeCount: 0, pids: [123] } }; } });
    const adapter = await c.create();
    if (mode === 'query') await assert.rejects(c.admit(adapter), denial);
    else { await c.admit(adapter); mode === 'eof' ? c.helper.stdout.end() : c.helper.emit('close', 1); }
    await assert.rejects(adapter.failure, denial); await assert.rejects(adapter.members(), denial);
  }
});

test('protocol rejects unmatched response, surplus fields and duplicate messages', async () => {
  for (const change of [response => ({ ...response, id: '0'.repeat(32) }), response => ({ ...response, extra: true }), () => 'not-json']) {
    const c = controlled({ transform: change }), adapter = await c.create(); await assert.rejects(c.admit(adapter), denial);
  }
  const c = controlled(), adapter = await c.create(); c.helper.stdout.write('{"version":1,"event":"ready"}\n');
  await assert.rejects(adapter.failure, denial);
});

test('unsupported host and unsafe installation path allocate no helper; startup timeout rejects', async () => {
  let calls = 0;
  for (const options of [{platform:'linux',systemRoot:'C:\\Windows'}, {platform:'win32',systemRoot:'\\\\host\\share'}, {platform:'win32',systemRoot:'C:\\Windows\\..\\Other'}]) {
    await assert.rejects(createWindowsOwnedProcess({ ...options, spawnProcess() { calls++; } }), denial);
  }
  assert.equal(calls, 0);
  const c = controlled({ ready: false }); await assert.rejects(c.create(), denial); assert(c.events.includes('helper-close'));
});

test('native source contracts: unnamed job, pinned handle, no breakaway, bounded membership and EOF disposal', () => {
  const cs = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-owned-process.cs'), 'utf8');
  const ps = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-owned-process.ps1'), 'utf8');
  assert(cs.includes('CreateJobObject(IntPtr.Zero,null)'));
  assert(cs.includes('LimitFlags=0x00002000'));
  assert(cs.includes('OpenProcess(') && cs.includes('false,pid'));
  assert(cs.includes('AssignProcessToJobObject(job,guardian)'));
  assert(cs.includes('IsProcessInJob(guardian,IntPtr.Zero,out inJob) && !inJob'));
  assert(cs.includes('WaitForSingleObject(guardian, 0) == 258'));
  assert(cs.includes('attempt<8') && cs.includes('count != assignedCount') && cs.includes('count != after.ActiveProcesses'));
  assert(cs.includes('value.TotalProcesses != after.TotalProcesses'));
  assert(!/TerminateProcess|CreateRemoteThread|taskkill/.test(cs));
  assert(ps.includes('#Requires -Version 5.1') && ps.includes('[Console]::In.Read()') && ps.includes('$buffer.Length -ge 4096'));
  assert(ps.includes('finally { if ($null -ne $job) { $job.Dispose() } }'));
});


test('close joins helper exit, shares its completion and refuses unresolved handle release', async () => {
  const c = controlled({ helperExit: false }), adapter = await c.create();
  let finished = false;
  const first = adapter.close(); assert.equal(adapter.close(), first);
  first.then(() => { finished = true; });
  await new Promise(resolve => setTimeout(resolve, 3)); assert.equal(finished, false);
  c.helper.emit('close', 0); await first; assert.equal(finished, true);
  const d = controlled({ helperExit: false }), unavailable = await d.create();
  await assert.rejects(unavailable.close(), denial);
  assert(d.events.includes('helper-close'));
});


test('unexpected guardian exit or disconnect closes helper authority after activation', async () => {
  for (const event of ['exit', 'disconnect', 'error']) {
    const c = controlled(), adapter = await c.create(); await c.admit(adapter);
    c.setMembers([123, 456]); c.child.emit(event, 1);
    await assert.rejects(adapter.failure, denial); await assert.rejects(adapter.members(), denial);
    assert(c.events.includes('helper-close'));
  }
});


test('expected natural phase exit requires sole-guardian barrier and preserves descendant drain authority', async () => {
  const c = controlled({ retained: true }), adapter = await c.create();
  assert.throws(() => adapter.expectGuardianExit(), denial);
  await c.admit(adapter); assert.throws(() => adapter.expectGuardianExit(), denial);
  c.setMembers([123, 456]); await assert.rejects(adapter.assertGuardianOnly(), denial);
  assert.throws(() => adapter.expectGuardianExit(), denial);
  c.setMembers([123]); await adapter.assertGuardianOnly();
  assert.deepEqual(adapter.expectGuardianExit(), { pid: 123, creationFileTime: birth });
  assert.throws(() => adapter.expectGuardianExit(), denial);
  c.setMembers([456]); c.child.emit('disconnect'); c.child.emit('exit', 0);
  assert.deepEqual((await adapter.members()).pids, [456]);
  await assert.rejects(adapter.waitForDrain(3), denial); await assert.rejects(adapter.close(), denial);
  c.setMembers([]); await adapter.waitForDrain(); await adapter.close();
});

test('expected natural exit does not admit guardian errors, helper failure or renewed failed barriers', async () => {
  const c = controlled(), adapter = await c.create(); await c.admit(adapter);
  await adapter.assertGuardianOnly(); adapter.expectGuardianExit(); c.child.emit('error', Error('controlled'));
  await assert.rejects(adapter.failure, denial); await assert.rejects(adapter.members(), denial);
  const d = controlled(), stale = await d.create(); await d.admit(stale);
  await stale.assertGuardianOnly(); d.setMembers([123, 456]); await assert.rejects(stale.assertGuardianOnly(), denial);
  assert.throws(() => stale.expectGuardianExit(), denial);
  await stale.stop({ graceMs: 0 }); await stale.close();
});
