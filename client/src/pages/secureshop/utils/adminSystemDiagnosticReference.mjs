import { shopStorage, flushShopStorage, SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const KEYS = ['version', 'shopUserId', 'sessionId', 'requestId', 'proposalId',
  'scopeKey', 'proposalSha256', 'startedAt'];
const exact = value => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...KEYS].sort().join(',');
const same = (left, right) => !!left && !!right && KEYS.every(key => left[key] === right[key]);
const invalid = () => { throw Error('Invalid saved System diagnostic confirmation'); };

export function decodeAdminSystemDiagnosticReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 640) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!exact(value) || value.version !== 1
    || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1
    || ![value.sessionId, value.requestId, value.proposalId].every(id => UUID.test(id))
    || !SHA.test(value.scopeKey) || !SHA.test(value.proposalSha256)
    || !Number.isSafeInteger(value.startedAt) || value.startedAt < 1) invalid();
  return Object.freeze(value);
}

export function createAdminSystemDiagnosticReferenceStore({ storage, flush,
  key = SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY } = {}) {
  if (key !== SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY
    || !['getItem', 'setItem', 'removeItem'].every(name => typeof storage?.[name] === 'function')
    || typeof flush !== 'function') invalid();
  const read = () => decodeAdminSystemDiagnosticReference(storage.getItem(key));
  return Object.freeze({
    read(shopUserId) {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
      const value = read();
      return value?.shopUserId === shopUserId ? value : null;
    },
    async save(reference, current = () => true) {
      const value = decodeAdminSystemDiagnosticReference(JSON.stringify({ version: 1, ...reference }));
      if (current() !== true || read() !== null) invalid();
      storage.setItem(key, JSON.stringify(value));
      await flush();
      if (current() !== true || !same(read(), value)) invalid();
      return value;
    },
    async clear(reference, current = () => true) {
      const value = decodeAdminSystemDiagnosticReference(JSON.stringify(reference));
      if (current() !== true || !same(read(), value)) invalid();
      storage.removeItem(key);
      await flush();
      if (current() !== true || read() !== null) invalid();
    },
  });
}

export const adminSystemDiagnosticReferenceStore = createAdminSystemDiagnosticReferenceStore({
  storage: shopStorage, flush: flushShopStorage, key: SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY,
});
