'use strict';
// Own only a closed SSH local-forward grammar via the existing guardian/Job.
// OpenSSH logs listener intent before bind succeeds; readiness additionally
// requires its later client-loop marker with ExitOnForwardFailure enabled.
// https://github.com/openssh/openssh-portable/blob/master/channels.c
// https://github.com/openssh/openssh-portable/blob/master/clientloop.c
const path = require('node:path'), net = require('node:net');
const { spawn } = require('node:child_process');
const { normalizePrivatePath } = require('./windows-private-state');
const { createWindowsOwnedProcess } = require('./windows-owned-process');
const { boundedLineReader, stopOwnedChild } = require('../start-application');
const GUARDIAN = path.resolve(__dirname, '../owned-child-guardian.js');
const denied = () => Object.assign(Error('Owned Windows lab forwarding unavailable.'), { code: 'WINDOWS_LAB_FORWARD_DENIED' });
const cleanupDenied = () => Object.assign(Error('Owned Windows lab forwarding cleanup unproved.'), { code: 'WINDOWS_LAB_FORWARD_CLEANUP_UNPROVED' });
function parseForwardRequest(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)
    || Object.keys(request).sort().join(',') !== 'args,executable') throw denied();
  const executable = normalizePrivatePath(request.executable);
  if (path.win32.basename(executable).toLowerCase() !== 'ssh.exe' || !Array.isArray(request.args)
    || request.args.length > 110 || request.args.some(value => typeof value !== 'string' || value.length > 512 || /[\x00\r\n]/.test(value))) throw denied();
  const args = request.args.slice(); let cursor = 0;
  const take = expected => { if (args[cursor++] !== expected) throw denied(); };
  const option = expected => { take('-o'); take(expected); };
  take('-F'); take('NUL'); take('-i');
  const key = normalizePrivatePath(args[cursor++]);
  if (path.win32.basename(key) !== 'windows-owned-lab.pem') throw denied();
  for (const value of ['BatchMode=yes','IdentitiesOnly=yes','StrictHostKeyChecking=yes']) option(value);
  take('-o'); const hostsArg = args[cursor++];
  const hostsMatch = /^UserKnownHostsFile="([^"\\]+)"$/.exec(hostsArg || '');
  if (!hostsMatch) throw denied();
  const hosts = normalizePrivatePath(path.win32.normalize(hostsMatch[1]));
  if (hostsMatch[1] !== hosts.replace(/\\/g, '/')) throw denied();
  if (path.win32.basename(hosts) !== 'windows-owned-lab.hosts' || path.win32.dirname(hosts) !== path.win32.dirname(key)) throw denied();
  option('GlobalKnownHostsFile=NUL');
  take('-o'); const alias = args[cursor++];
  if (typeof alias !== 'string' || !/^HostKeyAlias=owasp-ai-goat-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(alias)
    || alias.endsWith('00000000-0000-0000-0000-000000000000')) throw denied();
  for (const value of ['ConnectTimeout=10','ServerAliveInterval=15','ServerAliveCountMax=2','ForwardAgent=no',
    'PermitLocalCommand=no','ProxyCommand=none','ProxyJump=none','ControlMaster=no','RequestTTY=no','ExitOnForwardFailure=yes']) option(value);
  take('-N'); const ports = [];
  while (args[cursor] === '-L') {
    cursor++; const match = /^127\.0\.0\.1:([1-9][0-9]{3,4}):127\.0\.0\.1:([1-9][0-9]{3,4})$/.exec(args[cursor++]);
    if (!match || match.slice(1).some(value => Number(value) < 1024 || Number(value) > 65535)) throw denied();
    ports.push(Number(match[1]));
  }
  const destination = args[cursor++], address = destination?.slice('owasp-ai-goat@'.length);
  if (!destination?.startsWith('owasp-ai-goat@') || net.isIP(address) !== 4 || /^(?:0|127)\./.test(address)
    || Number(address.split('.')[0]) >= 224 || cursor !== args.length || !ports.length || ports.length > 32 || new Set(ports).size !== ports.length) throw denied();
  // These fixed options are launcher-owned, never caller-configurable.
  return { executable, args: ['-v', ...args], ports };
}
function createWindowsLabForwardOwner({ platform = process.platform, environment = process.env,
  signal, timeoutMs = 15000, joinMs = 10000, spawnProcess = spawn,
  createJob = createWindowsOwnedProcess } = {}) {
  return async function ownChild(request) {
    let spec, childEnvironment;
    try {
      const snapshot = {...environment}; childEnvironment = {};
      if (platform !== 'win32' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000
        || !Number.isSafeInteger(joinMs) || joinMs < 1 || joinMs > 30000
        || Object.entries(snapshot).some(([key,value]) => key.toLowerCase() === 'node_options' && value)
        || signal && (typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function')) throw denied();
      // Both executables are absolute and SSH reads only explicit config/key
      // paths. Do not hand application, database or provider secrets to them.
      const essentials = {systemroot:'SystemRoot',windir:'WINDIR',temp:'TEMP',tmp:'TMP',userprofile:'USERPROFILE'};
      for (const [key,value] of Object.entries(snapshot)) {
        const canonical = essentials[key.toLowerCase()];
        if (!canonical || value === undefined) continue;
        if (typeof value !== 'string' || /[\x00\r\n]/.test(value)
          || Object.hasOwn(childEnvironment,canonical) && childEnvironment[canonical] !== value) throw denied();
        childEnvironment[canonical] = value;
      }
      spec = parseForwardRequest(request);
    } catch { throw denied(); }
    let job, child, admission, liveCheck, admitted = false, published = false, closing = false, failed = false, ended = false, stopPromise;
    let rejectFailure, resolveMarkers, resolveClosed;
    const failure = new Promise((_,reject) => { rejectFailure = reject; }); failure.catch(() => {});
    const markers = new Promise(resolve => { resolveMarkers = resolve; });
    const closed = new Promise(resolve => { resolveClosed = resolve; });
    const fail = () => {
      if (failed || closing) return; failed = true; rejectFailure(denied());
      if (published) stopAndJoin().catch(() => {});
    };
    const timer = setTimeout(fail, timeoutMs);
    signal?.addEventListener('abort',fail,{once:true});
    const waitClosed = async () => {
      let timer; try { await Promise.race([closed,new Promise((_,reject) => { timer=setTimeout(()=>reject(cleanupDenied()),joinMs); })]); }
      finally { clearTimeout(timer); }
    };
    async function stopAndJoin() {
      if (stopPromise) return stopPromise;
      closing = true; clearTimeout(timer); signal?.removeEventListener('abort',fail);
      stopPromise = (async () => {
        // Join late admission before deciding which authority may terminate.
        if (admission) await admission.catch(() => {});
        if (liveCheck) await liveCheck.catch(() => {});
        if (admitted) await stopOwnedChild({child,job,admission},{platform:'win32',graceMs:1000,commandTimeoutMs:joinMs});
        else {
          if (child) { try { child.kill(); } catch {} await waitClosed(); }
          if (job) await job.close();
        }
      })().catch(() => { throw cleanupDenied(); });
      return stopPromise;
    }
    try {
      if (signal?.aborted) fail();
      if (failed) throw denied();
      // Native helper startup/admission is itself bounded. Cancellation still
      // joins a late helper/admission, rather than abandoning its job handle.
      job = await createJob({platform:'win32',timeoutMs:Math.min(timeoutMs,10000)});
      job.failure.catch(fail);
      if (failed) throw denied();
      child = spawnProcess(process.execPath,[GUARDIAN,spec.executable,JSON.stringify(spec.args),'plain','direct'], {
        env:childEnvironment,stdio:['ignore','ignore','pipe','ipc'],shell:false,windowsHide:true,detached:false,
      });
      child.once('close',() => { ended=true;resolveClosed();fail(); });
      child.once('exit',() => { ended=true;fail(); }); child.once('error',fail); child.once('disconnect',fail);
      child.on('message',value => { if(value?.type==='owasp-ai-goat-owned-child-outcome'){ended=true;fail();} });
      if (!child.stderr || typeof child.stderr.on !== 'function') throw denied();
      let bytes = 0; const seen = new Set();
      const readLine = boundedLineReader(line => {
        const match = /^debug1: Local forwarding listening on 127\.0\.0\.1 port ([1-9][0-9]{3,4})\.$/.exec(line);
        if (match) { const port=Number(match[1]); if(!spec.ports.includes(port))fail();else seen.add(port); }
        else if (line === 'debug1: Entering interactive session.') {
          if(seen.size!==spec.ports.length)fail();else resolveMarkers();
        }
      },{maxBytes:4096});
      const onData = chunk => { bytes += chunk.length; if(bytes>65536)fail();else readLine(chunk); };
      child.stderr.on('data',onData); child.stderr.once('error',fail); child.stderr.once('end',fail);
      admission = Promise.resolve(job.admitGuardian(child)).then(value => { admitted=true;return value; });
      await admission;
      await Promise.race([markers,failure]);
      liveCheck = job.members();
      const members = await Promise.race([liveCheck,failure]);
      if (failed || ended || !child.connected || child.exitCode != null || child.signalCode != null
        || !members || !Array.isArray(members.pids) || members.activeCount !== members.pids.length
        || members.activeCount < 2 || !members.pids.includes(child.pid)) throw denied();
      clearTimeout(timer); published=true; child.stderr.removeListener('data',onData);child.stderr.resume?.();
      return Object.freeze({stopAndJoin,failurePromise:failure});
    } catch {
      const error = denied();
      try { await stopAndJoin(); } catch { error.cleanupError=cleanupDenied(); }
      throw error;
    }
  };
}
module.exports = { createWindowsLabForwardOwner };
