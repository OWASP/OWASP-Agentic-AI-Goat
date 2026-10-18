'use strict';

const { readBearerAuthorization } = require('../middleware/bearerToken');

function denied(statusCode = 401) {
  return Object.assign(new Error('Teaching session authority unavailable'), {
    code: 'TEACHING_SESSION_AUTHORITY_UNAVAILABLE', statusCode,
  });
}
function id(value) {
  if ((typeof value !== 'number' && typeof value !== 'string')
      || !/^[1-9][0-9]*$/.test(String(value))) throw denied();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw denied();
  return parsed;
}
function normalizeError(error) {
  if (error?.code === 'TEACHING_SESSION_AUTHORITY_UNAVAILABLE') return error;
  if (error?.name === 'AccountLocked') return denied(423);
  if (['JsonWebTokenError', 'TokenExpiredError', 'NotBeforeError'].includes(error?.name)
      || error?.code === '55000') return denied();
  return denied(503);
}

// A narrowly selected teaching sink may accept its server-side cookie binding.
// Never use this resolver to authenticate platform/admin routes. assertBinding
// must check canonical account/session/deletion state, including on every check.
function createTeachingSessionAuthority({ validateSession, assertBinding, assertCookieBinding }) {
  if (typeof validateSession !== 'function' || typeof assertBinding !== 'function') {
    throw new TypeError('Canonical session validation and binding check required');
  }
  return async function resolve(req, { allowCookie = false } = {}) {
    const authorization = readBearerAuthorization(req);
    const cookieId = req?.sessionID;
    let ownerId, sessionId;
    const readToken = async () => {
      if (!authorization.token) throw denied();
      const found = await validateSession(authorization.token);
      if (!found?.user || !found?.session) throw denied();
      const binding = { ownerId: id(found.user.id), sessionId: id(found.session.id) };
      if (id(found.session.user_id) !== binding.ownerId) throw denied();
      return binding;
    };
    try {
      if (authorization.present) {
        ({ ownerId, sessionId } = await readToken());
      } else {
        if (!allowCookie || typeof assertCookieBinding !== 'function' || typeof cookieId !== 'string' || !cookieId) throw denied();
        ownerId = id(req?.session?.platformOwnerId);
        sessionId = id(req?.session?.platformSessionId);
        if (id(req?.session?.userId) !== ownerId) throw denied();
      }
      const binding = Object.freeze({ ownerId, sessionId });
      const check = async () => {
        try {
          if (authorization.present) {
            const current = await readToken();
            if (current.ownerId !== ownerId || current.sessionId !== sessionId) throw denied();
          }
          await assertBinding(binding);
          if (!authorization.present) await assertCookieBinding(cookieId, binding);
        } catch (error) { throw normalizeError(error); }
      };
      await check();
      return Object.freeze({ ...binding, source: authorization.present ? 'bearer' : 'teaching-cookie', check });
    } catch (error) { throw normalizeError(error); }
  };
}
module.exports = { createTeachingSessionAuthority };
