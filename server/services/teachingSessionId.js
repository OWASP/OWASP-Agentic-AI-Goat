'use strict';
const { createHmac, randomBytes, timingSafeEqual, createHash } = require('node:crypto');
const MAX_CLOCK_SKEW_MS = 30000;
const MAX_AGE_MS = 4 * 60 * 60 * 1000;

// The weak express-session signing secret remains a teaching sink. This private
// issuance MAC only prevents late writes from recreating an expired tombstone;
// it is not exposed as a platform bearer credential or a replacement for it.
function createTeachingSessionIds({ secret, now = Date.now, random = randomBytes } = {}) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) {
    throw new TypeError('A persisted private teaching-session issuance key is required');
  }
  if (typeof now !== 'function' || typeof random !== 'function') throw new TypeError('Session clock and entropy required');
  const sign = payload => createHmac('sha256', secret).update('dvaia-teaching-session-v1\0').update(payload).digest();
  const decode = sid => {
    if (typeof sid !== 'string' || !/^t1\.[0-9]{13}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/.test(sid)) return null;
    const parts = sid.split('.');
    const payload = parts.slice(0, 3).join('.');
    const signature = Buffer.from(parts[3], 'base64url');
    const expected = sign(payload);
    if (signature.length !== expected.length || !timingSafeEqual(signature, expected)
        || signature.toString('base64url') !== parts[3]) return null;
    const issuedAt = Number(parts[1]);
    const timestamp = now();
    if (!Number.isSafeInteger(timestamp) || issuedAt > timestamp + MAX_CLOCK_SKEW_MS || issuedAt + MAX_AGE_MS <= timestamp) return null;
    return Object.freeze({ hash: createHash('sha256').update(sid).digest('hex'),
      issuedAt, expiresAt: new Date(issuedAt + MAX_AGE_MS) });
  };
  return Object.freeze({
    generate() {
      const issuedAt = now();
      if (!Number.isSafeInteger(issuedAt) || String(issuedAt).length !== 13) throw new TypeError('Valid session clock required');
      const entropy = random(32);
      if (!Buffer.isBuffer(entropy) || entropy.length !== 32) throw new TypeError('Session entropy must contain 32 bytes');
      const payload = `t1.${issuedAt}.${entropy.toString('base64url')}`;
      return `${payload}.${sign(payload).toString('base64url')}`;
    },
    decode,
  });
}
module.exports = { createTeachingSessionIds, MAX_AGE_MS, MAX_CLOCK_SKEW_MS };
