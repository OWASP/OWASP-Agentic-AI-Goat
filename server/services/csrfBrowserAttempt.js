'use strict';
const { createHash } = require('node:crypto');

const OBJECTIVES = Object.freeze({ csrf_g2: 'get', csrf_g3: 'get', csrf_p1: 'post', csrf_p2: 'post', csrf_p3: 'post' });

// Internal authority only. Neither the consume function nor execution scope may
// be exposed to learner JavaScript or reconstructed from an HTTP request body.
function createCsrfBrowserAttempt({ execution, objectiveId, tab, html, dispatch, ttlMs = 30000, now = Date.now }) {
  if (!execution || typeof execution.check !== 'function' || !execution.signal
    || typeof execution.runId !== 'string' || typeof execution.ownerKey !== 'string'
    || !Number.isSafeInteger(execution.generation)) throw new TypeError('Owner execution required');
  if (OBJECTIVES[objectiveId] !== tab || !Object.hasOwn(OBJECTIVES, objectiveId)) throw new TypeError('Invalid browser objective');
  if (typeof html !== 'string' || !html.trim() || Buffer.byteLength(html) > 65536) throw new TypeError('Invalid browser payload');
  if (typeof dispatch !== 'function' || !Number.isInteger(ttlMs) || ttlMs < 1 || ttlMs > require('./csrfRuntimeBudget').workflowMs) throw new TypeError('Invalid attempt configuration');
  const binding = Object.freeze({ runId: execution.runId, ownerKey: execution.ownerKey,
    generation: execution.generation, objectiveId, tab,
    payloadDigest: createHash('sha256').update(html).digest('hex') });
  const expiresAt = now() + ttlMs;
  let state = 'ready';
  const revoke = () => { state = 'revoked'; execution.signal.removeEventListener('abort', revoke); };
  execution.signal.addEventListener('abort', revoke, { once: true });
  if (execution.signal.aborted) revoke();
  const check = async () => {
    if (state !== 'running' || now() >= expiresAt || execution.signal.aborted) {
      revoke(); const error = new Error('Browser attempt expired or cancelled'); error.name = 'AbortError'; throw error;
    }
    await execution.check();
    if (execution.runId !== binding.runId || execution.ownerKey !== binding.ownerKey || execution.generation !== binding.generation) {
      revoke(); throw new Error('Browser attempt scope changed');
    }
    if (state !== 'running' || now() >= expiresAt || execution.signal.aborted) {
      revoke(); const error = new Error('Browser attempt expired or cancelled'); error.name = 'AbortError'; throw error;
    }
  };
  return Object.freeze({
    binding,
    revoke,
    // Passed only to the trusted browser observer. It does not itself prove a
    // browser request: the executor must supply independent browser observation.
    async consume(observation) {
      if (state !== 'ready') throw new Error('Browser attempt already consumed or revoked');
      state = 'running'; // Reserve before any await; parallel requests cannot execute twice.
      try {
        await check();
        const result = await dispatch({ observation, binding, execution, check });
        await check();
        state = 'completed';
        return result;
      } catch (error) { state = 'revoked'; throw error; }
      finally { execution.signal.removeEventListener('abort', revoke); }
    },
  });
}

module.exports = { createCsrfBrowserAttempt };
