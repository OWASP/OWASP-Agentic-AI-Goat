'use strict';
const { readBearerAuthorization } = require('../middleware/bearerToken');

// Private request context; cookie authority is deliberately limited to the
// explicit teaching sink and must never populate platform roles on req.user.
function createCsrfTeachingAuthority({ runtime }) {
  if (typeof runtime?.bindBearer !== 'function' || typeof runtime?.resolveAuthority !== 'function'
      || typeof runtime?.store?.withAuthority !== 'function') throw new TypeError('Teaching runtime required');
  const contexts = new WeakMap();
  const unavailable = (statusCode = 503) => Object.assign(new Error('Teaching session authority unavailable'), { code: 'CSRF_TEACHING_AUTHORITY_UNAVAILABLE', statusCode });
  function get(req) {
    const context = contexts.get(req);
    if (!context) throw unavailable();
    return context;
  }
  function middleware({ allowCookie = false } = {}) {
    return async (req, res, next) => {
      contexts.delete(req);
      try {
        const authority = readBearerAuthorization(req).present
          ? await runtime.bindBearer(req)
          : await runtime.resolveAuthority(req, { allowCookie });
        if (req.user?.id != null && String(req.user.id) !== String(authority.ownerId)) throw unavailable(401);
        const sid = req.sessionID;
        if (typeof sid !== 'string' || !sid) throw unavailable();
        const binding = Object.freeze({ ownerId: authority.ownerId, sessionId: authority.sessionId });
        const check = async () => {
          if (req.sessionID !== sid) throw unavailable(401);
          await authority.check();
        };
        await check();
        contexts.set(req, Object.freeze({ ...binding, check,
          async withTeachingEffect(work) {
            if (typeof work !== 'function') throw new TypeError('Teaching effect callback required');
            await check();
            // Never save/touch the HTTP session or call the model in work.
            // Nested session assertions inside this row lease can self-block
            // behind a concurrent revocation; the store checks its own lease.
            const result = await runtime.store.withAuthority(sid, binding, work);
            await check();
            return result;
          },
        }));
        next();
      } catch (error) {
        const status = [401, 423, 503].includes(error?.statusCode) ? error.statusCode : 503;
        res.status(status).json({ error: 'Teaching session authority unavailable' });
      }
    };
  }
  return Object.freeze({ middleware, get });
}
module.exports = { createCsrfTeachingAuthority };
