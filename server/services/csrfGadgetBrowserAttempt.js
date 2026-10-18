'use strict';

const { createHash } = require('node:crypto');

const GADGET_OBJECTIVES = Object.freeze({
  csrf_x3: Object.freeze({ tab: 'xss', vector: 'xss' }),
  csrf_i2: Object.freeze({ tab: 'indirect', vector: 'indirect' }),
  csrf_i3: Object.freeze({ tab: 'indirect', vector: 'indirect' }),
});

function createCsrfGadgetBrowserAttempt({ execution, objectiveId, tab, html, dispatch,
  ttlMs = 30000, now = Date.now }) {
  const selected = GADGET_OBJECTIVES[objectiveId];
  if (!execution || typeof execution.check !== 'function' || !(execution.signal instanceof AbortSignal)
    || typeof execution.runId !== 'string' || typeof execution.ownerKey !== 'string'
    || !Number.isSafeInteger(execution.generation)) throw new TypeError('Owner execution required');
  if (!selected || selected.tab !== tab) throw new TypeError('Invalid gadget browser objective');
  if (typeof html !== 'string' || !html.trim() || Buffer.byteLength(html) > 65536) {
    throw new TypeError('Invalid gadget browser payload');
  }
  if (typeof dispatch !== 'function' || !Number.isInteger(ttlMs) || ttlMs < 1 || ttlMs > 120000
    || typeof now !== 'function') throw new TypeError('Invalid gadget attempt configuration');

  const binding = Object.freeze({ runId: execution.runId, ownerKey: execution.ownerKey,
    generation: execution.generation, objectiveId, tab, expectedVector: selected.vector,
    payloadDigest: createHash('sha256').update(html).digest('hex') });
  const expiresAt = now() + ttlMs;
  let state = 'ready';
  const revoke = () => { state = 'revoked'; execution.signal.removeEventListener('abort', revoke); };
  execution.signal.addEventListener('abort', revoke, { once: true });
  if (execution.signal.aborted) revoke();
  const check = async () => {
    if (execution.signal.aborted) {
      const reason = execution.signal.reason || Object.assign(new Error('Gadget browser attempt cancelled'), { name: 'AbortError' });
      revoke(); throw reason;
    }
    if (state !== 'running' || now() >= expiresAt) {
      revoke(); const error = new Error('Gadget browser attempt expired or cancelled'); error.name = 'AbortError'; throw error;
    }
    await execution.check();
    if (execution.runId !== binding.runId || execution.ownerKey !== binding.ownerKey
      || execution.generation !== binding.generation) {
      revoke(); throw new Error('Gadget browser attempt scope changed');
    }
    if (execution.signal.aborted) {
      const reason = execution.signal.reason || Object.assign(new Error('Gadget browser attempt cancelled'), { name: 'AbortError' });
      revoke(); throw reason;
    }
    if (state !== 'running' || now() >= expiresAt) {
      revoke(); const error = new Error('Gadget browser attempt expired or cancelled'); error.name = 'AbortError'; throw error;
    }
  };
  return Object.freeze({
    binding,
    revoke,
    async consume(observation) {
      if (state !== 'ready') throw new Error('Gadget browser attempt already consumed or revoked');
      state = 'running';
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

module.exports = { createCsrfGadgetBrowserAttempt, GADGET_OBJECTIVES };
