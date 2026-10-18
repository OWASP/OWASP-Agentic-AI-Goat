'use strict';

async function waitForObservedCount({ read, expected, timeoutMs, intervalMs = 25,
  now = Date.now, delay = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
  if (typeof read !== 'function' || !Number.isSafeInteger(expected) || expected < 1
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1
      || !Number.isSafeInteger(intervalMs) || intervalMs < 1
      || typeof now !== 'function' || typeof delay !== 'function') {
    throw new TypeError('Observed count wait configuration required');
  }
  const started = now();
  let observed = read();
  while (observed < expected) {
    const elapsed = now() - started;
    if (!Number.isFinite(elapsed) || elapsed >= timeoutMs) {
      throw Object.assign(new Error(`Observed count remained ${observed}; expected ${expected}`), {
        code: 'OBSERVATION_TIMEOUT', observed, expected,
      });
    }
    await delay(Math.min(intervalMs, timeoutMs - elapsed));
    observed = read();
  }
  return observed;
}

module.exports = { waitForObservedCount };
