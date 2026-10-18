'use strict';

const { AsyncLocalStorage } = require('async_hooks');

const als = new AsyncLocalStorage();

/**
 * Express middleware that initialises a per-request ALS store.
 * Mount after requestId + session middleware, before routes.
 */
function requestContextMiddleware(req, _res, next) {
  const store = {
    requestId: req.requestId || null,
    ip: req.ip || req.socket?.remoteAddress || null,
    userId: null,
    username: null
  };
  als.run(store, () => next());
}

/**
 * Call after req.user is populated (e.g. inside authenticateToken or after
 * session-based auth) to copy user info into the ALS store.
 */
function syncUserToContext(req) {
  const store = als.getStore();
  if (!store) return;
  if (req.user) {
    store.userId   = req.user.id   ?? req.user.userId ?? store.userId;
    store.username = req.user.username ?? store.username;
  } else if (req.session?.userId) {
    store.userId = req.session.userId;
  }
}

/**
 * Read current request context. Returns {} outside a request (background jobs).
 */
function getRequestContext() {
  return als.getStore() || {};
}

module.exports = { requestContextMiddleware, syncUserToContext, getRequestContext };
