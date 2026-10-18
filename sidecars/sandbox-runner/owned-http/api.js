'use strict';
// Factory only: deliberately not mounted until packaged executor readiness is qualified.
const crypto = require('node:crypto');
function createOwnedHttpApi({ token, store, authority } = {}) {
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(token || '') || typeof store?.execute !== 'function'
      || typeof authority !== 'function') throw TypeError('Private HTTP transport configuration required');
  return Object.freeze({ async execute(authorization, body, options) {
    const actual = Buffer.from(typeof authorization === 'string' ? authorization : '');
    const expected = Buffer.from(`Bearer ${token}`);
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) throw Object.assign(Error('HTTP_TRANSPORT_UNAUTHORIZED'), {code:'HTTP_TRANSPORT_UNAUTHORIZED'});
    if (!body || Object.keys(body).sort().join(',') !== 'capability,request'
        || typeof body.capability !== 'string' || body.capability.length > 256) throw Object.assign(Error('HTTP_REQUEST_INVALID'),{code:'HTTP_REQUEST_INVALID'});
    // The private server channel supplies the execution coordinates. Learner
    // requests must never be routed directly to this internal endpoint.
    return store.execute(body.capability, authority, body.request, options);
  } });
}
module.exports = { createOwnedHttpApi };
