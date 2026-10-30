'use strict';

const { createHmac, hkdfSync, timingSafeEqual } = require('node:crypto');
const { createLaunchScope } = require('./secureshopConversationBinding');

const ISSUER = 'owasp-ai-goat-secureshop-v01-practice';
const AUDIENCE = 'owned-checkout-audit-read';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEYS = ['iss','aud','sub','role','orderId','bindingTag'];
const denied = () => Object.assign(new Error('Practice audit token denied'), { code: 'V01_TEACHING_TOKEN_DENIED' });

function decodePart(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw denied();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || bytes.length > 2048) throw denied();
  let object;
  try { object = JSON.parse(bytes.toString('utf8')); } catch { throw denied(); }
  if (!object || Array.isArray(object) || Object.getPrototypeOf(object) !== Object.prototype) throw denied();
  if (JSON.stringify(object) !== bytes.toString('utf8')) throw denied();
  return object;
}
function b64(value) { return Buffer.from(JSON.stringify(value)).toString('base64url'); }
function context(scope, targetId, shopUserId, orderId) {
  const s = createLaunchScope(scope);
  if (!UUID.test(targetId || '') || !Number.isSafeInteger(shopUserId) || shopUserId < 1
      || !Number.isSafeInteger(orderId) || orderId < 1) throw denied();
  return Object.freeze({ ...s, targetId: targetId.toLowerCase(), shopUserId, orderId });
}
function createV01TeachingTokenAuthority({ secretMaterial } = {}) {
  if (!Buffer.isBuffer(secretMaterial) || secretMaterial.length < 32) {
    throw new TypeError('Private V01 teaching secret material required');
  }
  const privateMaterial = Buffer.from(secretMaterial);
  function key(c) {
    const salt = Buffer.from(JSON.stringify([c.targetId,c.launchId,c.scenarioId,c.generation,
      c.platformOwnerId,c.platformSessionId]), 'utf8');
    return Buffer.from(hkdfSync('sha256', privateMaterial, salt,
      Buffer.from('owasp-ai-goat/secureshop/v01/checkout-audit-teaching-jwt/v1'), 32));
  }
  function claims(c, role) {
    // The public token only carries an opaque binding. Launch, owner, session,
    // generation and target coordinates stay private in the derived key.
    const bindingTag = createHmac('sha256', key(c))
      .update('owasp-ai-goat/secureshop/v01/public-binding-tag/v1').digest('base64url');
    return { iss: ISSUER, aud: AUDIENCE, sub: `shop-user:${c.shopUserId}`, role,
      orderId: c.orderId, bindingTag };
  }
  return Object.freeze({
    issueCustomer(scope, targetId, shopUserId, orderId) {
      const c = context(scope, targetId, shopUserId, orderId);
      const input = `${b64({ typ: 'JWT', alg: 'HS256' })}.${b64(claims(c, 'customer'))}`;
      return `${input}.${createHmac('sha256', key(c)).update(input).digest('base64url')}`;
    },
    verifyAdmin(token, mode, scope, targetId, shopUserId, orderId) {
      const c = context(scope, targetId, shopUserId, orderId);
      if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > 4096
          || !['vuln','fixed'].includes(mode)) throw denied();
      const parts = token.split('.');
      if (parts.length !== 3) throw denied();
      const header = decodePart(parts[0]), payload = decodePart(parts[1]);
      if (Object.keys(header).sort().join() !== 'alg,typ' || header.typ !== 'JWT'
          || !['none','HS256'].includes(header.alg)
          || Object.keys(payload).sort().join() !== [...KEYS].sort().join()) throw denied();
      const expected = claims(c, 'admin');
      if (KEYS.some(name => payload[name] !== expected[name])) throw denied();
      if (header.alg === 'none') {
        // @intentional-vulnerability v01-auth-bypass-jwt-none: isolated lesson
        // verifier, never a platform or SecureShop persona authentication path.
        if (mode !== 'vuln' || parts[2] !== '') throw denied();
      } else {
        if (!/^[A-Za-z0-9_-]+$/.test(parts[2])) throw denied();
        const supplied = Buffer.from(parts[2], 'base64url');
        const expectedSignature = createHmac('sha256', key(c))
          .update(`${parts[0]}.${parts[1]}`).digest();
        if (supplied.toString('base64url') !== parts[2]
            || supplied.length !== expectedSignature.length
            || !timingSafeEqual(supplied, expectedSignature)) throw denied();
      }
      return Object.freeze({ algorithm: header.alg, role: 'admin', subject: expected.sub });
    },
  });
}
module.exports = { createV01TeachingTokenAuthority };
