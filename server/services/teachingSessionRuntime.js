'use strict';
const session = require('express-session');
const { createHmac } = require('node:crypto');
const { assertPlatformSigningConfiguration } = require('./platformSigningConfiguration');
const { PostgresTeachingSessionStore } = require('./postgresTeachingSessionStore');
const { assertTeachingSessionReadiness } = require('./teachingSessionReadiness');
const { createTeachingSessionAuthority } = require('./teachingSessionAuthority');

function createTeachingSessionRuntime({ adapter, effectPool, onCleanupError = () => {} } = {}) {
  if (typeof adapter?.pool?.connect !== 'function' || typeof adapter?.validateSession !== 'function') {
    throw new TypeError('Canonical PostgreSQL identity adapter required');
  }
  if (typeof effectPool?.connect !== 'function' || effectPool === adapter.pool) throw new TypeError('Separate teaching effect pool required');
  const { jwtSecret } = assertPlatformSigningConfiguration({ JWT_SECRET: adapter.jwtSecret });
  const secret = createHmac('sha256', jwtSecret).update('owasp-ai-goat-private-teaching-session-issuance-v1').digest('base64url');
  const store = new PostgresTeachingSessionStore({ pool: adapter.pool, effectPool, secret });
  let ready = false, closed = false, interval, pending, initialization;
  const middleware = session({ store, genid: store.genid,
    secret: 'vulnerable-secret-key', resave: false, saveUninitialized: false,
    cookie: { secure: false, httpOnly: false, sameSite: 'lax', maxAge: 4 * 60 * 60 * 1000 } });
  const resolveAuthority = createTeachingSessionAuthority({
    validateSession: token => adapter.validateSession(token),
    assertBinding: binding => adapter.pool.query('SELECT identity.assert_legacy_platform_mutation($1,$2)', [binding.ownerId, binding.sessionId]),
    assertCookieBinding: (sid, binding) => store.assertSession(sid, binding),
  });
  const bindBearer = require('./teachingSessionBearerBinding').createTeachingSessionBearerBinding({
    resolveAuthority,
    assertCookieBinding: (sid, binding) => store.assertSession(sid, binding),
    readTrustedUsername: async binding => (await adapter.repository.getUserById(binding.ownerId))?.username,
  });
  const cleanup = () => {
    if (closed || pending) return pending;
    pending = store.pruneExpired().catch(() => { onCleanupError('Teaching session expiry cleanup failed'); })
      .finally(() => { pending = undefined; });
    return pending;
  };
  return Object.freeze({
    store, resolveAuthority, bindBearer,
    middleware(req, res, next) {
      if (!ready || closed) return res.status(503).json({ error: 'Teaching session store unavailable' });
      return middleware(req, res, next);
    },
    async initialize() {
      if (closed) throw new Error('Teaching session runtime is closed');
      if (ready) return { ready: true };
      if (!initialization) initialization = (async () => {
        await assertTeachingSessionReadiness(adapter.pool);
        if (closed) throw new Error('Teaching session runtime is closed');
        await cleanup();
        if (closed) throw new Error('Teaching session runtime is closed');
        ready = true;
        interval = setInterval(cleanup, 60000); interval.unref();
        return { ready: true };
      })().finally(() => { initialization = undefined; });
      return initialization;
    },
    async close() {
      closed = true; ready = false; clearInterval(interval);
      await initialization?.catch(() => {});
      await pending;
    },
  });
}
module.exports = { createTeachingSessionRuntime };
