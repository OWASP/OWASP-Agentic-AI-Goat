'use strict';

const {
  createHmac,
  timingSafeEqual,
  createHash,
  createCipheriv,
  createDecipheriv,
  randomBytes
} = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  SHA = /^[a-f0-9]{64}$/;
function binding(value) {
  if (!value || ![value.effectId, value.operationId, value.targetId, value.sceneId].every(v => UUID.test(v || '')) || !Number.isSafeInteger(value.generation) || value.generation < 1 || !Number.isSafeInteger(value.sceneGeneration) || value.sceneGeneration < 1 || !['vuln', 'fixed'].includes(value.mode) || !Number.isSafeInteger(value.modeGeneration) || value.modeGeneration < 0 || !SHA.test(value.modeStamp || '')) return null;
  return Object.freeze({
    effectId: value.effectId.toLowerCase(),
    operationId: value.operationId.toLowerCase(),
    targetId: value.targetId.toLowerCase(),
    generation: value.generation,
    sceneId: value.sceneId.toLowerCase(),
    sceneGeneration: value.sceneGeneration,
    mode: value.mode,
    modeGeneration: value.modeGeneration,
    modeStamp: value.modeStamp
  });
}
function createSecureShopUploadAssetCapability({
  secret,
  now = () => Date.now(),
  ttlMs = 60000
} = {}) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32 || !Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > 300000) throw new TypeError('Private upload asset capability configuration required');
  const key = createHash('sha256').update(secret).digest();
  const seal = value => {
    const iv = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', key, iv),
      body = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url');
  };
  const sign = (value, expiresAt) => createHmac('sha256', secret).update(JSON.stringify(['secureshop-upload-asset-v2', value, expiresAt])).digest('hex');
  return Object.freeze({
    mint(value) {
      const bound = binding(value);
      if (!bound) throw new TypeError('Invalid upload asset binding');
      const expiresAt = now() + ttlMs,
        signature = sign(bound, expiresAt);
      return Object.freeze({
        ...bound,
        expiresAt,
        signature,
        path: `/assets/${seal({
          ...bound,
          expiresAt,
          signature
        })}`
      });
    },
    read(token) {
      try {
        if (typeof token !== 'string' || token.length > 2048 || !/^[A-Za-z0-9_-]+$/.test(token)) return null;
        const data = Buffer.from(token, 'base64url');
        if (data.length < 29) return null;
        const decipher = createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
        decipher.setAuthTag(data.subarray(12, 28));
        return JSON.parse(Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8'));
      } catch {
        return null;
      }
    },
    verify(value) {
      const bound = binding(value);
      if (!bound || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= now() || value.expiresAt > now() + ttlMs || !SHA.test(value.signature || '')) return false;
      const expected = Buffer.from(sign(bound, value.expiresAt), 'hex'),
        actual = Buffer.from(value.signature, 'hex');
      return timingSafeEqual(expected, actual);
    }
  });
}
module.exports = {
  createSecureShopUploadAssetCapability
};
