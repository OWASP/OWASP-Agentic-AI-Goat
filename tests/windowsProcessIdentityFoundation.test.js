'use strict';
// Controlled protocol/source checks only: no PowerShell or Win32 execution.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { captureWindowsProcessIdentity, verifyWindowsRecordedProcessesAbsent } = require('../scripts/lib/windows-process-identity');
const denial = { code: 'WINDOWS_PROCESS_IDENTITY_DENIED' };
const sid = 'S-1-5-21-123-456-789-1001';
const processTuple = (pid, ppid, creationFileTime, owner = sid) => ({ pid, ppid, sid: owner, creationFileTime });
function response() {
  return { version: 1, ok: true, operation: 'capture', data: {
    platform: 'win32', hostSha256: 'a'.repeat(64), bootFileTime: '133000000000000001', currentSid: sid,
    ancestors: [processTuple(123, 456, '133000000000000004'), processTuple(456, 789, '133000000000000003')],
    boundary: { kind: 'foreign-sid', process: processTuple(789, 4, '133000000000000002', 'S-1-5-18') },
    ancestry: 'observed-supported-chain',
  } };
}
function capture(value = response(), overrides = {}) {
  return captureWindowsProcessIdentity({ platform: 'win32', systemRoot: 'C:\\Windows', currentPid: 123, parentPid: 456,
    execute: () => typeof value === 'string' ? value : JSON.stringify(value), ...overrides });
}
function absenceResponse(record = capture()) {
  return { version: 1, operation: 'absence', ok: true, data: {
    platform: 'win32', hostSha256: record.hostSha256, bootFileTime: record.bootFileTime,
    currentSid: record.currentSid, recordedPids: record.ancestors.map(p => p.pid),
    observer: processTuple(900, 901, '133000000000000010'), recordedProcessesAbsent: true,
  } };
}
function absent(record = capture(), value = absenceResponse(record), options = {}) {
  return verifyWindowsRecordedProcessesAbsent(record, { platform: 'win32', systemRoot: 'C:\\Windows',
    currentPid: 900, parentPid: 901, execute: () => JSON.stringify(value), ...options });
}
test('capture binds caller PID, exact FILETIME strings, SID and bounded absolute helper protocol', () => {
  let launch;
  const value = response(); value.data.ancestors[0].creationFileTime = '18446744073709551615';
  const result = capture(value, { execute(executable, args, options) {
    launch = { executable, args, options }; return JSON.stringify(value);
  } });
  assert.equal(launch.executable, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.deepEqual(launch.args, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', path.resolve(__dirname, '../scripts/windows/windows-process-identity.ps1')]);
  assert.deepEqual(JSON.parse(launch.options.input), { version: 1, operation: 'capture', pid: 123 });
  assert.equal(launch.options.shell, false); assert.equal(launch.options.windowsHide, true);
  assert.equal(launch.options.timeout, 15000); assert.equal(launch.options.maxBuffer, 65536);
  assert.equal(result.ancestors[0].creationFileTime, '18446744073709551615');
  assert.equal(result.currentSid, sid); assert.equal(result.platform, 'win32');
  for (const object of [result, result.ancestors, ...result.ancestors, result.boundary, result.boundary.process]) assert(Object.isFrozen(object));
  for (const key of ['uid', 'pgid', 'pidNamespace', 'userNamespace', 'recoveryAuthorized']) assert(!Object.hasOwn(result, key));
});
test('observed root boundary needs same SID and zero parent; foreign SID is not an owned ancestor', () => {
  const value = response(); value.data.boundary = { kind: 'root', process: processTuple(789, 0, '133000000000000002') };
  assert.equal(capture(value).boundary.kind, 'root');
  value.data.boundary.process.ppid = 4; assert.throws(() => capture(value), denial);
  value.data.boundary.process.ppid = 0; value.data.boundary.process.sid = 'S-1-5-18'; assert.throws(() => capture(value), denial);
  value.data.boundary.kind = 'foreign-sid'; assert.equal(capture(value).boundary.kind, 'foreign-sid');
  value.data.ancestors[1].sid = 'S-1-5-18'; assert.throws(() => capture(value), denial);
});
test('inaccessible, unstable or helper-denied observations are unknown, never absence', () => {
  for (const value of [null, { ...response(), ok: false }, '{"version":1,"event":"denied"}', 'not JSON', '', 'x'.repeat(65537)]) assert.throws(() => capture(value), denial);
  assert.throws(() => capture(response(), { execute() { const e = Error('private-token-and-native-diagnostic'); e.stdout = 'private-data'; throw e; } }), error => {
    assert.equal(error.code, denial.code); assert(!error.message.includes('private'));
    assert(!Object.hasOwn(error, 'cause')); assert(!JSON.stringify(error).includes('private')); return true;
  });
});
test('wrong caller, changed parent, cycles and disconnected links fail closed', () => {
  for (const mutate of [v => { v.data.ancestors[0].pid = 122; }, v => { v.data.ancestors[0].ppid = 455; },
    v => { v.data.ancestors[1].ppid = 123; }, v => { v.data.boundary.process.pid = 123; },
    v => { v.data.ancestors[1].pid = 123; }]) {
    const value = response(); mutate(value); assert.throws(() => capture(value), denial);
  }
});
test('PID reuse birth inversions, equal creation times, preboot identities and lossy FILETIMEs deny', () => {
  for (const birth of ['133000000000000004', '133000000000000005', '133000000000000000',
    '18446744073709551616', '01', '0', '-1', 133000000000000003, null]) {
    const value = response(); value.data.ancestors[1].creationFileTime = birth; assert.throws(() => capture(value), denial);
  }
  const value = response(); value.data.bootFileTime = value.data.ancestors[0].creationFileTime;
  assert.throws(() => capture(value), denial);
});
test('SID grammar, bounds and closed Windows-only identity fields are enforced', () => {
  for (const invalid of ['uid:1000', 'S-1-05-18', 'S-1-5-01', 'S-2-5-18', 'S-1-5-4294967296',
    'S-1-281474976710656-18', 'S-1-5' + '-1'.repeat(16), null, 1000]) {
    const value = response(); value.data.currentSid = invalid; assert.throws(() => capture(value), denial);
  }
  for (const mutate of [v => { v.data.uid = 0; }, v => { v.data.ancestors[0].uid = 0; },
    v => { v.data.pidNamespace = null; }, v => { v.data.bootId = 'invented'; },
    v => { v.data.hostSha256 = ['a'.repeat(64)]; }, v => { v.data.platform = 'linux'; },
    v => { v.data.boundary.kind = 'init'; }, v => { v.data.ancestry = 'complete-supported-chain'; },
    v => { v.data.ancestors[0].pid = 2147483648; }, v => { v.data.ancestors[0].ppid = -1; },
    v => { v.operation = 'terminate'; }, v => { v.data.boundary.extra = true; }]) {
    const value = response(); mutate(value); assert.throws(() => capture(value), denial);
  }
});
test('32 ancestor limit, platform and executable path admission cannot launch unsafe requests', () => {
  const maximum = response();
  maximum.data.ancestors = Array.from({ length: 32 }, (_, i) => processTuple(
    i === 0 ? 123 : 455 + i, i === 0 ? 456 : 456 + i,
    String(133000000000000100n - BigInt(i))));
  maximum.data.boundary.process = processTuple(487, 4, '133000000000000068', 'S-1-5-18');
  assert.equal(capture(maximum).ancestors.length, 32);
  maximum.data.ancestors.push(processTuple(487, 488, '133000000000000068'));
  maximum.data.boundary.process = processTuple(488, 4, '133000000000000067', 'S-1-5-18');
  assert.throws(() => capture(maximum), denial);
  const value = response(); value.data.ancestors = []; assert.throws(() => capture(value), denial);
  value.data.ancestors = Array.from({ length: 33 }, () => response().data.ancestors[0]); assert.throws(() => capture(value), denial);
  let launches = 0;
  for (const overrides of [{ platform: 'darwin' }, { systemRoot: 'powershell.exe' }, { systemRoot: 'C:\\Windows\\..\\Other' },
    { currentPid: 0 }, { currentPid: 123.5 }, { parentPid: 0 }, { execute: null }]) {
    assert.throws(() => capture(response(), { execute() { launches++; return JSON.stringify(response()); }, ...overrides }), denial);
  }
  assert.equal(launches, 0);
});
test('native source retains read-only handles, complete bounded observations and official host/boot sources', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-process-identity.cs'), 'utf8');
  const helper = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-process-identity.ps1'), 'utf8');
  assert.match(source, /QueryLimitedAndSynchronize = 0x00001000 \| 0x00100000/);
  assert.match(source, /OpenProcess\(QueryLimitedAndSynchronize, false, pid\)/);
  assert.match(source, /OpenProcessToken\(process, 0x0008, out token\)/);
  assert.match(source, /GetProcessTimes\(handle/); assert.match(source, /WaitForSingleObject\(handle, 0\) == 258/);
  assert.match(source, /process\.Birth < pinned\[pinned\.Count - 2\]\.Birth/);
  assert.match(source, /fresh\.Birth == Birth && fresh\.Sid == Sid/);
  assert.match(source, /parent == ParentPid/); assert.match(source, /helperParent == ownerPid/);
  assert.match(source, /seen\.Add\(pid\)/); assert.match(source, /ancestors\.Count < MaxAncestors/);
  assert.match(source, /clock\.ElapsedMilliseconds < 10000/);
  assert.match(source, /finally \{ foreach \(Pinned process in pinned\) process\.Dispose\(\); \}/);
  assert.equal((source.match(/process\.Stable\(after\)/g) || []).length, 2);
  assert.match(source, /later\[0\] == host\[0\] && later\[1\] == host\[1\]/);
  assert.match(source, /Win32_ComputerSystemProduct", "UUID/);
  assert.match(source, /Win32_OperatingSystem", "LastBootUpTime/);
  assert.match(source, /00000000-0000-0000-0000-000000000000/);
  assert.match(source, /ffffffff-ffff-ffff-ffff-ffffffffffff/);
  assert.match(source, /ToFileTimeUtc\(\)/);
  assert.doesNotMatch(source + helper, /TerminateProcess|TerminateJobObject|taskkill|Stop-Process|SetTokenInformation|AdjustTokenPrivileges|PROCESS_ALL_ACCESS|GetEnvironmentVariable/);
  assert.match(helper, /buffer\.Length -ge 4096/); assert.match(helper, /System\.Management\.dll/);
  assert.match(helper, /request\.pid -isnot \[int\]/); assert.match(helper, /exit 1/);
});
test('absence observation sends only recorded owned PIDs and exact host/boot/SID binding, granting no recovery', () => {
  const record = capture(), value = absenceResponse(record);
  let request;
  const result = absent(record, value, { execute(executable, args, options) {
    assert.equal(executable, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    assert.equal(options.timeout, 15000); assert.equal(options.shell, false);
    request = JSON.parse(options.input); return JSON.stringify(value);
  } });
  assert.deepEqual(request, { version: 1, operation: 'absence', pid: 900,
    binding: { hostSha256: record.hostSha256, bootFileTime: record.bootFileTime, currentSid: record.currentSid },
    recordedPids: [123, 456] });
  assert(!request.recordedPids.includes(record.boundary.process.pid));
  assert.deepEqual(result, { recordedProcessesAbsent: true, recoveryAuthorized: false,
    ancestry: 'observed-supported-chain', boundary: 'foreign-sid', databaseDrain: 'not-checked' });
  assert(Object.isFrozen(result));
});
test('absence refuses malformed chain/record before any native request', () => {
  let calls = 0;
  for (const mutate of [r => { r.version = 2; }, r => { r.extra = true; }, r => { r.ancestors = []; },
    r => { r.ancestors[0].creationFileTime = '01'; }, r => { r.ancestors[1].pid = 123; },
    r => { r.ancestors[1].sid = 'S-1-5-18'; }, r => { r.boundary.process.pid = 456; },
    r => { r.ancestors[0].ppid = 999; }, r => { r.platform = 'linux'; }, r => { r.ancestry = 'complete-supported-chain'; }]) {
    const record = structuredClone(capture()); mutate(record);
    assert.throws(() => absent(record, null, { execute() { calls++; return '{}'; } }), denial);
  }
  assert.equal(calls, 0);
});
test('absence binding changes, observer reuse/mismatch and reordered or missing PID acknowledgments deny', () => {
  const record = capture();
  for (const mutate of [v => { v.data.hostSha256 = 'b'.repeat(64); }, v => { v.data.bootFileTime = '133000000000000002'; },
    v => { v.data.currentSid = 'S-1-5-18'; }, v => { v.data.observer.sid = 'S-1-5-18'; },
    v => { v.data.observer.pid = 123; }, v => { v.data.observer.ppid = 902; },
    v => { v.data.observer.creationFileTime = '133000000000000000'; },
    v => { v.data.recordedPids = [456, 123]; }, v => { v.data.recordedPids = [123]; },
    v => { v.data.recordedPids.push(789); }, v => { v.operation = 'capture'; },
    v => { v.data.recordedProcessesAbsent = false; }, v => { v.data.recoveryAuthorized = true; }]) {
    const value = absenceResponse(record); mutate(value); assert.throws(() => absent(record, value), denial);
  }
  const value = absenceResponse(record); value.data.observer = processTuple(123, 456, '133000000000000004');
  assert.throws(() => absent(record, value, { currentPid: 123, parentPid: 456 }), denial);
});
test('native presence/reuse, access denial, partial snapshots and transport failure never become absence', () => {
  const record = capture();
  for (const reason of ['recorded-pid-present', 'reused-pid-present', 'ERROR_ACCESS_DENIED',
    'ERROR_PARTIAL_COPY', 'ERROR_BAD_LENGTH', 'incomplete-enumeration', 'observer-unstable']) {
    assert.throws(() => absent(record, { version: 1, operation: 'absence', ok: false,
      data: { recordedProcessesAbsent: false, reason } }), denial);
  }
  assert.throws(() => absent(record, null, { execute() { throw Error('private-error'); } }), denial);
  assert.throws(() => absent(record, null, { execute: () => 'x'.repeat(65537) }), denial);
  assert.throws(() => absent(record, null, { platform: 'darwin', execute() { assert.fail('must not execute'); } }), denial);
});
test('native absence uses complete system snapshots, stable observer and repeated host/boot binding only', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-process-identity.cs'), 'utf8');
  const absence = source.slice(source.indexOf('static void Absent('));
  assert.match(source, /CreateToolhelp32Snapshot\(2, 0\)/);
  assert.match(source, /Need\(Process32First\(snapshot, ref entry\)\)/);
  assert.match(source, /Marshal\.GetLastWin32Error\(\) == 18/);
  assert.match(source, /result\.Count < 65536 && !result\.ContainsKey/);
  assert.match(absence, /foreach \(uint pid in recordedPids\) Need\(!snapshot\.ContainsKey\(pid\)\)/);
  assert.equal((absence.match(/= Parents\(clock\)/g) || []).length, 3);
  for (const snapshot of ['before', 'after', 'final']) assert(absence.includes(`Absent(${snapshot}, recordedPids)`));
  assert.match(absence, /observer\.Stable\(after\)/); assert.match(absence, /observer\.Stable\(final\)/);
  assert.match(absence, /Need\(expectedSid == currentSid\)/);
  assert.match(absence, /host\[0\] == hostSha256 && host\[1\] == bootFileTime/);
  assert.match(absence, /later\[0\] == host\[0\] && later\[1\] == host\[1\]/);
  assert.match(absence, /recordedPids\.Length <= MaxAncestors/); assert.match(absence, /seen\.Add\(pid\)/);
  assert.match(absence, /using \(Pinned observer = new Pinned\(observerPid, observerParent\)\)/);
  assert.doesNotMatch(absence, /OpenProcess\(|new Pinned\(pid|GetLastWin32Error\(\)|\.Birth ==|\.Sid == expectedSid/);
  const helper = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-process-identity.ps1'), 'utf8');
  assert.match(helper, /request\.recordedPids -isnot \[Array\]/);
  assert.match(helper, /request\.recordedPids\.Count -gt 32/);
  assert.match(helper, /recordedPid -isnot \[int\]/);
  assert.match(helper, /OwaspAiGoatWindowsProcessIdentity\]::ObserveAbsence/);
});
