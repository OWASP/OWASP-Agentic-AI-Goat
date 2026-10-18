'use strict';
const { validateOwnedSystemMetrics: validateSystemHealthMetrics } = require('../../sidecars/sandbox-runner/owned-system/health-contract');
const fail = code => Object.assign(new Error('Bound System health unavailable'), { code });
function createBoundSystemHealthService({ repository, metrics } = {}) {
  if (typeof repository?.administration !== 'function' || typeof metrics?.snapshot !== 'function') throw new TypeError('Bound System health dependencies required');
  return Object.freeze({
    async health(context, { signal } = {}) {
      signal?.throwIfAborted();
      const input = structuredClone(context);
      const before = await repository.administration(input);
      if (typeof before?.scopeKey !== 'string' || !/^[a-f0-9]{64}$/.test(before.scopeKey)) throw fail('SYSTEM_HEALTH_AUTH_INVALID');
      signal?.throwIfAborted();
      const raw = await metrics.snapshot({ signal });
      signal?.throwIfAborted();
      const value = validateSystemHealthMetrics(raw);
      signal?.throwIfAborted();
      const after = await repository.administration(input);
      if (after?.scopeKey !== before.scopeKey) throw fail('STALE_AUTHORITY');
      signal?.throwIfAborted();
      return value;
    },
  });
}
module.exports = { createBoundSystemHealthService };
