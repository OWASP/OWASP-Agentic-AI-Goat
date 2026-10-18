'use strict';

/**
 * Client for the sandbox-runner sidecar (real isolated command execution).
 * On any transport error the methods return { ok:false, ... } so the caller can
 * fail HONESTLY (an exploit that can't reach its backend does not score) — the
 * lab never fabricates a result. There is no simulation fallback.
 */

const { SANDBOX_RUNNER_URL, BACKEND_TIMEOUT_MS } = require('./config');

async function fetchWithTimeout(url, opts = {}, timeoutMs = BACKEND_TIMEOUT_MS, read = response => response) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const signal = opts.signal ? AbortSignal.any([ctrl.signal, opts.signal]) : ctrl.signal;
    return await read(await fetch(url, { ...opts, signal }));
  } finally {
    clearTimeout(t);
  }
}

async function health() {
  try {
    const r = await fetchWithTimeout(`${SANDBOX_RUNNER_URL}/health`, {}, 2000);
    if (!r.ok) return { ok: false };
    const body = await r.json();
    return { ok: true, ...body };
  } catch {
    return { ok: false };
  }
}

/**
 * Execute a real command in the isolated sandbox.
 * @returns {Promise<{ok:boolean, stdout?:string, stderr?:string, exitCode?:number, isolation?:string, error?:string}>}
 */
async function exec(sessionId, command) {
  try {
    const r = await fetchWithTimeout(`${SANDBOX_RUNNER_URL}/exec`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionId, command }),
    });
    if (!r.ok) return { ok: false, error: `runner HTTP ${r.status}` };
    const body = await r.json();
    return { ok: true, ...body };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function reset(sessionId) {
  try {
    const r = await fetchWithTimeout(`${SANDBOX_RUNNER_URL}/reset`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionId }),
    });
    if (!r.ok) return { ok: false };
    return { ok: true, ...(await r.json()) };
  } catch {
    return { ok: false };
  }
}

// Fixed operation: caller supplies invocation identity, never a path or command.
async function configSnapshot(sessionId, invocationId, { signal } = {}) {
  try {
    const response = await fetchWithTimeout(`${SANDBOX_RUNNER_URL}/config/snapshot`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, signal,
      body: JSON.stringify({ sessionId, invocationId }),
    }, BACKEND_TIMEOUT_MS, async res => ({ status: res.status,
      body: res.ok ? await res.json() : null }));
    if (response.status === 404) {
      // Existing installations already provide Node and /exec. Run the same
      // fixed snapshot implementation there; do not simulate data or downgrade
      // to trusting arbitrary stdout. No image/restart or learner reset needed.
      const { buildConfigSnapshotProgram } = require('./configSnapshotProgram');
      const program = buildConfigSnapshotProgram(invocationId);
      const command = `node -e '${program.replaceAll("'", "'\\''")}'`;
      const execution = await fetchWithTimeout(`${SANDBOX_RUNNER_URL}/exec`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, signal,
        body: JSON.stringify({ sessionId, command }),
      }, BACKEND_TIMEOUT_MS, async res => res.ok ? res.json() : null);
      if (!execution || execution.exitCode !== 0 || execution.truncated !== false
        || execution.timedOut !== false || typeof execution.stdout !== 'string') {
        return { ok: false, error: 'CONFIG_SNAPSHOT_UNAVAILABLE' };
      }
      return JSON.parse(execution.stdout);
    }
    if (!response.body) return { ok: false, error: 'CONFIG_SNAPSHOT_UNAVAILABLE' };
    return response.body;
  } catch (error) {
    if (signal?.aborted) throw signal.reason || error;
    return { ok: false, error: 'CONFIG_SNAPSHOT_UNAVAILABLE' };
  }
}

module.exports = { health, exec, reset, configSnapshot };
