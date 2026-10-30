import { flushShopStorage, shopStorage, SHOP_ACCOUNT_AVATAR_PENDING_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const TOKEN_PART = /^[A-Za-z0-9_-]+$/;
const ISSUER = 'owasp-ai-goat-secureshop-bound';
const AUDIENCE = 'owasp-ai-goat-secureshop-bound-persona';
const positiveId = value => typeof value === 'string' && /^[1-9][0-9]*$/.test(value)
  && Number.isSafeInteger(Number(value)) && Number(value) <= 2147483647;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const fail = () => { throw new TypeError('Invalid account avatar recovery state'); };

async function digest(value) {
  const bytes = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// The decoded claims are a local equality hint, never authentication. The
// server verifies the signature and current session again on every GET.
function stableSessionClaims(token) {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(part => !TOKEN_PART.test(part))) fail();
  let header, claims;
  try {
    const decode = part => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(
      Uint8Array.from(atob(part.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0))));
    header = decode(parts[0]); claims = decode(parts[1]);
  } catch { fail(); }
  if (!exact(header, ['alg', 'typ']) || header.alg !== 'HS256' || header.typ !== 'JWT'
    || !exact(claims, ['role', 'username', 'ss_authority_version', 'ss_launch_id',
      'ss_scenario_id', 'ss_generation', 'ss_owner_id', 'ss_platform_session_id',
      'iat', 'exp', 'iss', 'aud', 'sub', 'jti'])
    || claims.iss !== ISSUER || claims.aud !== AUDIENCE
    || !positiveId(claims.sub) || !['customer', 'merchant', 'admin'].includes(claims.role)
    || typeof claims.username !== 'string' || !claims.username
    || !UUID.test(claims.ss_launch_id) || !UUID.test(claims.ss_scenario_id)
    || !UUID.test(claims.jti) || !Number.isSafeInteger(claims.ss_generation)
    || claims.ss_generation < 1 || !Number.isSafeInteger(claims.ss_owner_id)
    || claims.ss_owner_id < 1 || !Number.isSafeInteger(claims.ss_platform_session_id)
    || claims.ss_platform_session_id < 1
    || typeof claims.ss_authority_version !== 'string'
    || !/^[1-9][0-9]*$/.test(claims.ss_authority_version)
    || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)
    || claims.exp <= claims.iat) fail();
  return [ISSUER, AUDIENCE, claims.sub, claims.role, claims.ss_launch_id,
    claims.ss_scenario_id, claims.ss_generation, claims.ss_owner_id,
    claims.ss_platform_session_id, claims.jti, String(claims.ss_authority_version)];
}

export async function accountAvatarSessionFingerprint(token, version = 2) {
  if (typeof token !== 'string' || !token || token.length > 8192 || /[\r\n]/.test(token)
    || !globalThis.crypto?.subtle) fail();
  if (version === 1) return digest(token);
  if (version !== 2) fail();
  return digest(JSON.stringify(['account-avatar-session-v2', ...stableSessionClaims(token)]));
}

export function decodeAccountAvatarPending(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || raw.length > 4096) fail();
  let value;
  try { value = JSON.parse(raw); } catch { fail(); }
  if (!exact(value, ['version', 'ownerId', 'sessionFingerprint', 'requestId', 'filename', 'mime', 'sizeBytes', 'public'])
    || ![1, 2].includes(value.version) || !positiveId(value.ownerId) || !SHA.test(value.sessionFingerprint)
    || !UUID.test(value.requestId) || typeof value.filename !== 'string' || !value.filename
    || !value.filename.isWellFormed() || value.filename.length > 4096 || /[\0\r\n]/.test(value.filename)
    || typeof value.mime !== 'string' || !value.mime || !value.mime.isWellFormed()
    || value.mime.length > 1024 || /[\0\r\n]/.test(value.mime)
    || !Number.isSafeInteger(value.sizeBytes) || value.sizeBytes < 1 || value.sizeBytes > 20 * 1024 * 1024
    || typeof value.public !== 'boolean') fail();
  return Object.freeze(value);
}

export function verifyAccountAvatarReceipt(reference, receipt) {
  const pending = decodeAccountAvatarPending(JSON.stringify(reference));
  const required = ['ok', 'kind', 'scope_id', 'requestId', 'operationId', 'status', 'filename', 'mime',
    'size_bytes', 'is_traversal', 'replayed', 'public'];
  const keys = receipt && Object.hasOwn(receipt, 'denialCode') ? [...required, 'denialCode'] : required;
  const absent = receipt?.status === 'uncertain' && receipt?.operationId === null
    && receipt?.ok === false && receipt?.filename === '' && receipt?.mime === ''
    && receipt?.size_bytes === 0 && receipt?.public === false;
  if (!exact(receipt, keys) || typeof receipt.ok !== 'boolean' || receipt.kind !== 'avatar'
    || receipt.scope_id !== pending.ownerId || receipt.requestId !== pending.requestId
    || !['completed', 'denied', 'uncertain'].includes(receipt.status)
    || (!absent && (receipt.filename !== pending.filename || receipt.mime !== pending.mime
      || receipt.size_bytes !== pending.sizeBytes || receipt.public !== pending.public))
    || typeof receipt.is_traversal !== 'boolean' || typeof receipt.replayed !== 'boolean'
    || !(receipt.operationId === null || UUID.test(receipt.operationId))
    || (receipt.status === 'completed' && (receipt.ok !== true || receipt.operationId === null))
    || (receipt.status !== 'completed' && receipt.ok !== false)
    || (receipt.status === 'denied' && (typeof receipt.denialCode !== 'string' || !receipt.denialCode))
    || (receipt.status !== 'denied' && Object.hasOwn(receipt, 'denialCode'))) fail();
  return Object.freeze({ ...receipt });
}

export function createAccountAvatarPendingStore({ storage = shopStorage, flush = flushShopStorage } = {}) {
  if (!storage || ['getItem', 'setItem', 'removeItem'].some(key => typeof storage[key] !== 'function')
    || typeof flush !== 'function') fail();
  const read = () => decodeAccountAvatarPending(storage.getItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY));
  const assertCurrent = check => { if (typeof check !== 'function' || check() !== true) fail(); };
  const acknowledge = async expected => {
    await flush();
    if (storage.getItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY) !== expected) fail();
  };
  let busy = false;
  return Object.freeze({
    read,
    async reserve(reference, check) {
      if (busy || read() !== null) fail();
      busy = true;
      try {
        const admitted = decodeAccountAvatarPending(JSON.stringify(reference));
        const raw = JSON.stringify(admitted);
        assertCurrent(check);
        storage.setItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY, raw);
        await acknowledge(raw);
        assertCurrent(check);
        return admitted;
      } finally { busy = false; }
    },
    async clear(reference, receipt, check) {
      if (busy) fail();
      busy = true;
      try {
        const saved = read();
        if (!saved || saved.requestId !== reference.requestId
          || saved.ownerId !== reference.ownerId || saved.sessionFingerprint !== reference.sessionFingerprint) fail();
        const verified = verifyAccountAvatarReceipt(saved, receipt);
        if (verified.status === 'uncertain') return false;
        assertCurrent(check);
        storage.removeItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY);
        await acknowledge(null);
        assertCurrent(check);
        return true;
      } finally { busy = false; }
    },
  });
}
