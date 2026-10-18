import { flushShopStorage, shopStorage, SHOP_PRODUCT_SUMMARY_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const FIELDS = ['version', 'shopUserId', 'productId', 'sessionId', 'requestId', 'startedAt'];
const KEY = /^[a-f0-9]{64}$/;
const scoped = row => `${row.shopUserId}:${row.productId}:${row.recoveryKey || 'legacy'}`;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const invalid = () => { throw new TypeError('Saved product summary unavailable'); };
const equal = (a, b) => [...FIELDS,'recoveryKey'].every(key => a?.[key] === b?.[key]);
export function decodeProductSummaryReference(value) {
  if (!(value?.version === 1 && exact(value, FIELDS)
      || value?.version === 2 && exact(value, [...FIELDS,'recoveryKey']) && KEY.test(value.recoveryKey))
    || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1
    || !Number.isSafeInteger(value.productId) || value.productId < 1 || value.productId > 2147483647
    || !UUID.test(value.sessionId || '') || !UUID.test(value.requestId || '')
    || !Number.isSafeInteger(value.startedAt) || value.startedAt < 1) invalid();
  return Object.freeze({ ...value });
}
export function decodeProductSummaryReferences(raw) {
  if (raw === null) return Object.freeze({ version: 2, entries: Object.freeze([]) });
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 16384) invalid();
  let value; try { value = JSON.parse(raw); } catch { invalid(); }
  if (!exact(value, ['version','entries']) || ![1,2].includes(value.version)
    || !Array.isArray(value.entries) || value.entries.length > 32) invalid();
  const entries = value.entries.map(decodeProductSummaryReference);
  if (value.version === 1 && entries.some(row => row.version !== 1)) invalid();
  if (new Set(entries.map(scoped)).size !== entries.length
    || new Set(entries.map(row => `${row.sessionId}:${row.requestId}`)).size !== entries.length) invalid();
  return Object.freeze({ version: value.version, entries: Object.freeze(entries) });
}
export function createProductSummaryReferenceStore({ storage, flush } = {}) {
  if (typeof storage?.getItem !== 'function' || typeof storage?.setItem !== 'function'
    || typeof flush !== 'function') invalid();
  const all = () => decodeProductSummaryReferences(storage.getItem(SHOP_PRODUCT_SUMMARY_KEY));
  return Object.freeze({
    read(shopUserId, productId, recoveryKey) {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1 || !Number.isSafeInteger(productId) || productId < 1 || !KEY.test(recoveryKey || '')) invalid();
      const matches = all().entries.filter(row => row.shopUserId === shopUserId && row.productId === productId);
      // Legacy pending identities remain recoverable; never pretend their unknown
      // mode was the new mode or silently allocate a replacement.
      return matches.find(row => row.recoveryKey === recoveryKey) || matches.find(row => row.version === 1) || null;
    },
    async save(input, current = () => true) {
      const value = decodeProductSummaryReference({ version: 2, ...input });
      const before = all();
      if (before.entries.length >= 32) throw Object.assign(new Error('Summary recovery storage is full. Existing summaries remain available.'),
        { code:'PRODUCT_SUMMARY_RECOVERY_FULL' });
      if (current() !== true || before.entries.some(row => scoped(row) === scoped(value) || row.version === 1 && row.shopUserId === value.shopUserId && row.productId === value.productId)) invalid();
      const next = { version: 2, entries: [...before.entries, value] };
      decodeProductSummaryReferences(JSON.stringify(next));
      storage.setItem(SHOP_PRODUCT_SUMMARY_KEY, JSON.stringify(next)); await flush();
      const after = all();
      if (current() !== true || after.entries.length !== next.entries.length
        || !after.entries.every((row, index) => equal(row, next.entries[index]))) invalid();
      return value;
    },
  });
}
export const productSummaryReferenceStore = createProductSummaryReferenceStore({ storage: shopStorage, flush: flushShopStorage });
