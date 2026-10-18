'use strict';

/**
 * Transport adapter for CodeBot's fictional pkg-parse@1.2.0 teaching sink.
 * The submitted transform is evaluated only by the sandbox-runner's dedicated,
 * bwrap-only endpoint. There is no application-process or simulation fallback.
 */
const crypto = require('node:crypto');
const { CODEBOT_SANDBOX_RUNNER_URL, BACKEND_TIMEOUT_MS } = require('../mcp/config');

const REQUIRED_ISOLATION = 'bwrap-codebot-v1';

function sessionIdForOwner(ownerId) {
  if (ownerId === undefined || ownerId === null || String(ownerId).trim() === '') return null;
  const digest = crypto.createHash('sha256').update(String(ownerId)).digest('hex').slice(0, 32);
  return `codebot-${digest}`;
}

function sessionIdForScope(scope) {
  const values = [scope?.platformOwnerId, scope?.platformSessionId, scope?.generation, scope?.runId];
  if (values.some(value => value === undefined || value === null || String(value).trim() === '')) return null;
  // Keep the sidecar's existing allowlisted CodeBot identifier shape while
  // deriving the opaque namespace from every platform fence component.
  const digest = crypto.createHash('sha256').update(JSON.stringify(values.map(String))).digest('hex').slice(0, 32);
  return `codebot-${digest}`;
}

async function post(path, body, { signal } = {}) {
  const ctrl = new AbortController();
  const abort = () => ctrl.abort(signal?.reason);
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) abort();
  const timer = setTimeout(() => ctrl.abort(), BACKEND_TIMEOUT_MS);
  try {
    const response = await fetch(`${CODEBOT_SANDBOX_RUNNER_URL}${path}`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body), signal: ctrl.signal,
    });
    if (!response.ok) return { ok: false, error: `runner HTTP ${response.status}` };
    return await response.json();
  } catch (error) {
    return { ok: false, error: error.message || 'sandbox runner unavailable' };
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}

function unavailable(error, runner = {}) {
  return {
    security: 'unavailable', status: 'backend_unavailable', transform_executed: false,
    message: 'The isolated CodeBot execution lab is unavailable. No transform was executed.',
    runner: { source: 'sandbox_runner', isolation: runner.isolation || null, error: error || runner.error || 'runner unavailable' },
  };
}

async function executeTransform({ ownerId, scope, transform, signal, runner = post }) {
  const sessionId = scope ? sessionIdForScope(scope) : sessionIdForOwner(ownerId);
  if (!sessionId) return unavailable('authenticated owner context is required');
  if (typeof transform !== 'string' || transform.length === 0) {
    return { security: 'error', status: 'invalid_transform', transform_executed: false, error: 'transform must be a non-empty string' };
  }
  const result = await runner('/codebot/transform', { sessionId, transform }, { signal });
  if (result.isolation !== REQUIRED_ISOLATION) return unavailable(`required isolation ${REQUIRED_ISOLATION} was not attested`, result);
  // A runner-attested exit code means execution was attempted. Preserve that
  // distinction even when it timed out or the learner transform threw.
  if (Number.isInteger(result.exitCode) && (result.exitCode !== 0 || result.executed !== true)) {
    return {
      security: 'error', status: result.timedOut ? 'execution_timeout' : 'execution_failed', transform_executed: false,
      execution_attempted: true,
      error: result.error || result.stderr || 'transform execution failed',
      runner: { source: 'sandbox_runner', session_id: sessionId, isolation: result.isolation, exit_code: result.exitCode, timed_out: Boolean(result.timedOut) },
    };
  }
  if (!result?.ok) return unavailable(result?.error, result);
  if (result.exitCode !== 0 || result.executed !== true) return unavailable('runner returned incomplete execution evidence', result);
  return {
    security: 'rce_executed', status: 'processed', transform_executed: true,
    transform_output: typeof result.transformOutput === 'string' ? result.transformOutput : '',
    runner: {
      source: 'sandbox_runner', session_id: sessionId, isolation: result.isolation,
      exit_code: result.exitCode, duration_ms: result.durationMs,
      observations: {
        env_file_read: result.observations?.envFileRead === true,
        ssh_file_read: result.observations?.sshFileRead === true,
        javascript_evaluated: result.observations?.javascriptEvaluated === true,
      },
    },
  };
}

async function resetOwner(ownerId, runner = post) {
  const sessionId = sessionIdForOwner(ownerId);
  if (!sessionId) return { ok: false, error: 'authenticated owner context is required' };
  const result = await runner('/codebot/reset', { sessionId });
  return result?.ok === true ? { ok: true, sessionId } : { ok: false, error: result?.error || 'runner unavailable' };
}

async function resetOwnerBeforeProgress(ownerId, resetProgress, runner = post) {
  const result = await resetOwner(ownerId, runner);
  if (!result.ok) {
    const error = new Error(`CodeBot lab reset unavailable: ${result.error}`);
    error.code = 'CODEBOT_RESET_UNAVAILABLE';
    throw error;
  }
  await resetProgress();
  return result;
}

module.exports = { REQUIRED_ISOLATION, sessionIdForOwner, sessionIdForScope, executeTransform, resetOwner, resetOwnerBeforeProgress };
