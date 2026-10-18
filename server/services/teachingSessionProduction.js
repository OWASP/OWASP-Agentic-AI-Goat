'use strict';
// Construction is lazy and never applies migrations. Startup must initialize
// the canonical identity store before awaiting this runtime's readiness.
function createTeachingSessionProduction({ env = process.env, load = require } = {}) {
  if (env.PLATFORM_DATABASE_ENGINE !== 'postgres') throw new TypeError('PostgreSQL teaching sessions required');
  let runtime, effectPool, closed = false;
  function getRuntime() {
    if (closed) throw new Error('Teaching session production is closed');
    if (!runtime) {
      const adapter = load('./postgresIdentityAdapter').getPostgresIdentityAdapter();
      effectPool = load('../database/postgres').createPool(env, 'IDENTITY_DATABASE_URL', { purpose: 'teaching' });
      try {
        runtime = load('./teachingSessionRuntime').createTeachingSessionRuntime({ adapter, effectPool });
      } catch (error) {
        // Retain the allocated pool for orderly shutdown even if construction
        // fails. A failed factory cannot be retried into another allocation.
        closed = true;
        throw error;
      }
    }
    return runtime;
  }
  let closing;
  return Object.freeze({
    middleware(req, res, next) {
      if (closed || !runtime) return res.status(503).json({ error: 'Teaching session store unavailable' });
      return runtime.middleware(req, res, next);
    },
    async initialize() { const current = getRuntime(); await current.initialize(); return current; },
    close() {
      closed = true;
      if (!closing) closing = (async () => {
        try { await runtime?.close(); } finally { await effectPool?.end(); }
      })();
      return closing;
    },
  });
}
module.exports = { createTeachingSessionProduction };
