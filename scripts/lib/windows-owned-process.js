'use strict';
// Foundation only: callers must use a guardian that waits for this handshake.
// One helper holds an unnamed non-inheritable job and a pinned process handle.
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { normalizePrivatePath } = require('./windows-private-state');
const HELPER = path.resolve(__dirname, '../windows/windows-owned-process.ps1');
const CODE = 'WINDOWS_OWNED_PROCESS_DENIED';
const denied = () => Object.assign(Error('Windows owned process authority unavailable.'), { code: CODE });
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === fields.slice().sort().join(',');
const fileTime = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value)
  && BigInt(value) <= 18446744073709551615n;
const pid = value => Number.isSafeInteger(value) && value > 1 && value <= 0x7fffffff;

async function createWindowsOwnedProcess({ platform = process.platform, systemRoot = process.env.SystemRoot,
  spawnProcess = spawn, timeoutMs = 10000, pollMs = 25 } = {}) {
  let executable;
  try {
    if (platform !== 'win32' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1
      || !Number.isSafeInteger(pollMs) || pollMs < 1) throw denied();
    executable = path.win32.join(normalizePrivatePath(systemRoot), 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  } catch { throw denied(); }
  let helper;
  try { helper = spawnProcess(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', HELPER],
    { stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true, shell: false }); }
  catch { throw denied(); }
  let broken, closing = false, ready = false, buffer = '', pending, guardian, identity, admitted = false, admissionStarted = false, stopping = false, stopPromise, closePromise, guardianOnlyBarrier = false, expectedExit = false;
  let failReady, resolveReady, failLifetime;
  const lifetime = new Promise((_, reject) => { failLifetime = reject; });
  lifetime.catch(() => {});
  const readiness = new Promise((resolve, reject) => { resolveReady = resolve; failReady = reject; });
  const startupTimer = setTimeout(() => fail(), timeoutMs);
  function fail() {
    if (broken) return;
    broken = denied(); clearTimeout(startupTimer);
    failReady(broken); failLifetime(broken);
    if (pending) { clearTimeout(pending.timer); pending.reject(broken); pending = undefined; }
    // Only the helper ChildProcess is signalled. Its last job handle closes.
    // Never issue taskkill, process.kill(PID), or adopt a recorded PID.
    try { helper.stdin.destroy(); } catch {}
    try { helper.kill(); } catch {}
    try { guardian?.disconnect?.(); } catch {}
  }
  helper.once('error', fail);
  helper.once('close', () => { if (!closing) fail(); });
  helper.stdin.on('error', fail);
  helper.stdout.on('error', fail);
  helper.stdout.on('end', () => { if (!closing) fail(); });
  helper.stdout.on('data', chunk => {
    if (broken) return;
    buffer += chunk.toString('utf8');
    if (Buffer.byteLength(buffer) > 131072) return fail();
    while (buffer.includes('\n')) {
      const end = buffer.indexOf('\n'), line = buffer.slice(0, end).replace(/\r$/, '');
      buffer = buffer.slice(end + 1);
      let value;
      try { value = JSON.parse(line); } catch { fail(); return; }
      if (!ready) {
        if (!exact(value, ['version', 'event']) || value.version !== 1 || value.event !== 'ready') return fail();
        ready = true; clearTimeout(startupTimer); resolveReady();
      } else {
        if (!pending || !exact(value, ['version', 'id', 'operation', 'ok', 'data']) || value.version !== 1
          || value.id !== pending.id || value.operation !== pending.operation || value.ok !== true) return fail();
        const item = pending; pending = undefined; clearTimeout(item.timer); item.resolve(value.data);
      }
    }
  });
  await readiness;
  async function request(operation, data = {}) {
    if (broken || closing || pending) throw broken || denied();
    const id = crypto.randomBytes(16).toString('hex');
    return new Promise((resolve, reject) => {
      pending = { id, operation, resolve, reject, timer: setTimeout(fail, timeoutMs) };
      try { helper.stdin.write(JSON.stringify({ version: 1, id, operation, data }) + '\n', error => { if (error) fail(); }); }
      catch { fail(); }
    });
  }
  function guardianMessage(type, validate, send) {
    return new Promise((resolve, reject) => {
      let finished = false;
      const finish = (error, value) => {
        if (finished) return; finished = true; clearTimeout(timer);
        guardian.removeListener('message', onMessage); guardian.removeListener('exit', onExit);
        guardian.removeListener('error', onExit); guardian.removeListener('disconnect', onExit);
        error ? reject(error) : resolve(value);
      };
      const onExit = () => finish(denied());
      const onMessage = value => {
        if (value?.type !== type) return;
        validate(value) ? finish(null, value) : finish(denied());
      };
      const timer = setTimeout(onExit, timeoutMs);
      guardian.on('message', onMessage); guardian.once('exit', onExit);
      guardian.once('error', onExit); guardian.once('disconnect', onExit);
      lifetime.catch(onExit);
      if (send) {
        try { guardian.send(send, error => { if (error) onExit(); }); } catch { onExit(); }
      }
    });
  }
  async function members() {
    const data = await request('members');
    if (!exact(data, ['pids', 'activeCount']) || !Array.isArray(data.pids) || data.pids.length > 4096
      || data.activeCount !== data.pids.length || data.pids.some((value, i) => !pid(value) || i > 0 && value <= data.pids[i - 1])) {
      fail(); throw broken;
    }
    return Object.freeze({ activeCount: data.activeCount, pids: Object.freeze(data.pids.slice()) });
  }
  async function waitForDrain(drainTimeoutMs = timeoutMs) {
    if (!Number.isSafeInteger(drainTimeoutMs) || drainTimeoutMs < 1) throw denied();
    const end = Date.now() + drainTimeoutMs;
    while (true) {
      if ((await members()).activeCount === 0) return;
      if (Date.now() >= end) throw denied();
      await new Promise(resolve => setTimeout(resolve, pollMs));
    }
  }
  return Object.freeze({
    failure: lifetime,
    async admitGuardian(child) {
      if (admissionStarted || !child || !pid(child.pid) || !child.connected || child.exitCode != null || child.signalCode != null) throw denied();
      admissionStarted = true; guardian = child;
      const unexpectedGuardianLoss = () => { if (!stopping && !closing && !expectedExit) fail(); };
      child.once('exit', unexpectedGuardianLoss);
      child.once('error', () => { if (!stopping && !closing) fail(); });
      child.once('disconnect', unexpectedGuardianLoss);
      try {
        const hello = await guardianMessage('owasp-ai-goat-owned-guardian-ready', value => exact(value, ['type', 'pid', 'challenge'])
          && value.pid === child.pid && typeof value.challenge === 'string' && /^[a-f0-9]{64}$/.test(value.challenge),
        { type: 'owasp-ai-goat-owned-guardian-hello' });
        const pinned = await request('pin', { pid: child.pid });
        if (!exact(pinned, ['pid', 'creationFileTime']) || pinned.pid !== child.pid || !fileTime(pinned.creationFileTime)) throw denied();
        identity = Object.freeze({ ...pinned });
        // The guardian must answer a fresh challenge AFTER the native handle opens.
        const nonce = crypto.randomBytes(32).toString('hex');
        await guardianMessage('owasp-ai-goat-owned-guardian-proof', value => exact(value, ['type', 'pid', 'challenge', 'nonce'])
          && value.pid === identity.pid && value.challenge === hello.challenge && value.nonce === nonce,
        { type: 'owasp-ai-goat-owned-guardian-probe', challenge: hello.challenge, nonce });
        const assigned = await request('assign', { creationFileTime: identity.creationFileTime });
        if (!exact(assigned, ['assigned']) || assigned.assigned !== true) throw denied();
        const state = await members();
        if (state.activeCount !== 1 || state.pids[0] !== identity.pid) throw denied();
        await guardianMessage('owasp-ai-goat-owned-guardian-active', value => exact(value, ['type', 'pid', 'challenge', 'nonce'])
          && value.pid === identity.pid && value.challenge === hello.challenge && value.nonce === nonce,
        { type: 'owasp-ai-goat-owned-guardian-activate', challenge: hello.challenge, nonce });
        admitted = true;
        return identity;
      } catch { fail(); throw broken; }
    },
    members,
    async assertGuardianOnly() {
      if (!admitted) throw denied();
      const result = await request('guardianOnly');
      if (!exact(result, ['guardianOnly']) || typeof result.guardianOnly !== 'boolean') { fail(); throw broken; }
      if (!result.guardianOnly) { guardianOnlyBarrier = false; throw denied(); }
      guardianOnlyBarrier = true;
      return identity;
    },
    // Dedicated phase callers invoke this synchronously on a validated result,
    // after the publication barrier. This permits natural owner exit only; it
    // cannot prove descendant absence or authorize publication/recovery.
    expectGuardianExit() {
      if (!admitted || broken || stopping || closing || expectedExit || !guardianOnlyBarrier) throw broken || denied();
      guardianOnlyBarrier = false; expectedExit = true;
      return identity;
    },
    waitForDrain,
    stop({ graceMs = 5000, drainTimeoutMs = timeoutMs } = {}) {
      if (stopPromise) return stopPromise;
      stopPromise = (async () => {
        if (!admitted || broken || !Number.isSafeInteger(graceMs) || graceMs < 0) throw broken || denied();
        stopping = true;
        if (guardian.connected) {
          try { guardian.send({ type: 'owasp-ai-goat-owned-guardian-stop' }); } catch { /* Job authority still drains. */ }
        }
        if (graceMs > 0) {
          try { await waitForDrain(graceMs); return; } catch { if (broken) throw broken; }
        }
        const result = await request('terminate');
        if (!exact(result, ['terminated']) || result.terminated !== true) { fail(); throw broken; }
        await waitForDrain(drainTimeoutMs);
      })();
      return stopPromise;
    },
    close() {
      if (closePromise) return closePromise;
      closePromise = (async () => {
      if (broken) throw broken;
      if ((await members()).activeCount !== 0) throw denied();
      closing = true;
      // Join helper exit as well as job drain; EOF alone is not handle-release proof.
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { fail(); reject(broken); }, timeoutMs);
        helper.once('close', code => {
          clearTimeout(timer);
          if (code !== 0 || broken) { fail(); reject(broken); } else resolve();
        });
        try { helper.stdin.end(); } catch { clearTimeout(timer); fail(); reject(broken); }
      });
      })().catch(error => { if (!closing) closePromise = undefined; throw error; });
      return closePromise;
    },
  });
}
module.exports = { createWindowsOwnedProcess };
