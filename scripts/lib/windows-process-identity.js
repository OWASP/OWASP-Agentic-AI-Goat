'use strict';
// Read-only foundation. Observed parentage is not descendant-drain, workspace
// ownership, recovery permission or a termination capability.
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { normalizePrivatePath } = require('./windows-private-state');
const HELPER = path.resolve(__dirname, '../windows/windows-process-identity.ps1');
const CODE = 'WINDOWS_PROCESS_IDENTITY_DENIED';
const denied = () => Object.assign(Error('Windows process identity unavailable.'), { code: CODE });
const exact = (o, fields) => o && typeof o === 'object' && !Array.isArray(o)
  && Object.keys(o).sort().join(',') === fields.slice().sort().join(',');
const pid = n => Number.isSafeInteger(n) && n > 0 && n <= 0x7fffffff;
const fileTime = n => typeof n === 'string' && /^[1-9][0-9]{0,19}$/.test(n) && BigInt(n) <= 18446744073709551615n;
const sid = n => typeof n === 'string' && n.length <= 184 && /^S-1-[0-9]+(?:-[0-9]+){1,15}$/.test(n)
  && /^(0|[1-9][0-9]*)$/.test(n.split('-')[2])
  && n.split('-').slice(3).every(v => /^(0|[1-9][0-9]*)$/.test(v) && BigInt(v) <= 4294967295n)
  && BigInt(n.split('-')[2]) <= 281474976710655n;
function tuple(p) {
  if (!exact(p, ['pid', 'ppid', 'sid', 'creationFileTime']) || !pid(p.pid)
    || !(p.ppid === 0 || pid(p.ppid)) || !sid(p.sid) || !fileTime(p.creationFileTime)) throw denied();
}
function validate(data, currentPid, parentPid) {
  if (!exact(data, ['platform', 'hostSha256', 'bootFileTime', 'currentSid', 'ancestors', 'boundary', 'ancestry'])
    || data.platform !== 'win32' || typeof data.hostSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(data.hostSha256)
    || !fileTime(data.bootFileTime) || !sid(data.currentSid) || data.ancestry !== 'observed-supported-chain'
    || !Array.isArray(data.ancestors) || data.ancestors.length < 1 || data.ancestors.length > 32
    || !exact(data.boundary, ['kind', 'process'])) throw denied();
  const all = [...data.ancestors, data.boundary.process], seen = new Set();
  for (const p of all) {
    tuple(p);
    if (seen.has(p.pid) || BigInt(p.creationFileTime) < BigInt(data.bootFileTime)) throw denied();
    seen.add(p.pid);
  }
  if (all[0].pid !== currentPid || all[0].ppid !== parentPid) throw denied();
  for (let i = 0; i < data.ancestors.length; i++) {
    if (all[i].sid !== data.currentSid || all[i].ppid !== all[i + 1].pid
      || BigInt(all[i + 1].creationFileTime) >= BigInt(all[i].creationFileTime)) throw denied();
  }
  const boundary = data.boundary;
  if (!(boundary.kind === 'root' && boundary.process.ppid === 0 && boundary.process.sid === data.currentSid
    || boundary.kind === 'foreign-sid' && boundary.process.sid !== data.currentSid)) throw denied();
  return Object.freeze({ version: 1, ...data,
    ancestors: Object.freeze(data.ancestors.map(p => Object.freeze({ ...p }))),
    boundary: Object.freeze({ kind: boundary.kind, process: Object.freeze({ ...boundary.process }) }) });
}
// Executor/current PID injection is a controlled-test seam, never native proof.
function invoke(operation, input, { platform = process.platform, systemRoot = process.env.SystemRoot,
  execute = execFileSync, currentPid = process.pid, parentPid = process.ppid } = {}) {
    if (platform !== 'win32' || typeof execute !== 'function' || !pid(currentPid) || !pid(parentPid)) throw denied();
    const executable = path.win32.join(normalizePrivatePath(systemRoot), 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const output = execute(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', HELPER], {
      input: JSON.stringify({ version: 1, operation, pid: currentPid, ...input }), encoding: 'utf8',
      timeout: 15000, maxBuffer: 65536, windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'pipe'],
    });
    if (typeof output !== 'string' || Buffer.byteLength(output) > 65536) throw denied();
    const response = JSON.parse(output);
    if (!exact(response, ['version', 'ok', 'operation', 'data']) || response.version !== 1
      || response.ok !== true || response.operation !== operation) throw denied();
    return { data: response.data, currentPid, parentPid };
}
function captureWindowsProcessIdentity(options) {
  try {
    const { data, currentPid, parentPid } = invoke('capture', {}, options);
    return validate(data, currentPid, parentPid);
  } catch { throw denied(); } // Never attach child diagnostics or environment data.
}
function validateWindowsProcessIdentityRecord(record) {
  try {
    if (!exact(record, ['version', 'platform', 'hostSha256', 'bootFileTime', 'currentSid', 'ancestors', 'boundary', 'ancestry']) || record.version !== 1) throw denied();
    const { version, ...unvalidated } = record;
    return validate(unvalidated, record.ancestors?.[0]?.pid, record.ancestors?.[0]?.ppid);
  } catch { throw denied(); }
}
function verifyWindowsRecordedProcessesAbsent(record, options) {
  try {
    const recorded = validateWindowsProcessIdentityRecord(record);
    const recordedPids = recorded.ancestors.map(p => p.pid);
    const binding = { hostSha256: recorded.hostSha256, bootFileTime: recorded.bootFileTime, currentSid: recorded.currentSid };
    const { data, currentPid, parentPid } = invoke('absence', { binding, recordedPids }, options);
    if (!exact(data, ['platform', 'hostSha256', 'bootFileTime', 'currentSid', 'recordedPids', 'observer', 'recordedProcessesAbsent'])
      || data.platform !== 'win32' || data.recordedProcessesAbsent !== true
      || Object.entries(binding).some(([key, value]) => data[key] !== value)
      || JSON.stringify(data.recordedPids) !== JSON.stringify(recordedPids)) throw denied();
    tuple(data.observer);
    if (data.observer.pid !== currentPid || data.observer.ppid !== parentPid || data.observer.sid !== recorded.currentSid
      || recordedPids.includes(currentPid) || BigInt(data.observer.creationFileTime) < BigInt(recorded.bootFileTime)) throw denied();
    return Object.freeze({ recordedProcessesAbsent: true, recoveryAuthorized: false,
      ancestry: recorded.ancestry, boundary: recorded.boundary.kind, databaseDrain: 'not-checked' });
  } catch { throw denied(); }
}
module.exports = { captureWindowsProcessIdentity, verifyWindowsRecordedProcessesAbsent, validateWindowsProcessIdentityRecord };
