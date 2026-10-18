import { flushShopStorage, shopStorage, SHOP_PRODUCT_SIMILAR_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const KEYS = ['version', 'shopUserId', 'productId', 'sessionId', 'requestId', 'startedAt'];
const exact = value => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...KEYS].sort().join(',');
const same = (a, b) => !!a && !!b && KEYS.every(key => a[key] === b[key]);
const invalid = () => { throw new TypeError('Invalid saved similar-products request'); };

export function decodeProductSimilarReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 512) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!exact(value) || value.version !== 1
    || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1
    || !Number.isSafeInteger(value.productId) || value.productId < 1 || value.productId > 2147483647
    || !UUID.test(value.sessionId) || !UUID.test(value.requestId)
    || !Number.isSafeInteger(value.startedAt) || value.startedAt < 1) invalid();
  return Object.freeze(value);
}

export function createProductSimilarReferenceStore({ storage, flush,
  key = SHOP_PRODUCT_SIMILAR_KEY } = {}) {
  if (key !== SHOP_PRODUCT_SIMILAR_KEY || typeof storage?.getItem !== 'function'
    || typeof storage?.setItem !== 'function' || typeof storage?.removeItem !== 'function'
    || typeof flush !== 'function') invalid();
  const read = () => decodeProductSimilarReference(storage.getItem(key));
  return Object.freeze({
    read(shopUserId) {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
      const value = read(); return value?.shopUserId === shopUserId ? value : null;
    },
    async save(input, current = () => true) {
      const value = decodeProductSimilarReference(JSON.stringify({ version: 1, ...input }));
      if (current() !== true || read() !== null) invalid();
      storage.setItem(key, JSON.stringify(value)); await flush();
      if (current() !== true || !same(read(), value)) invalid();
      return value;
    },
    async clear(input, current = () => true) {
      const value = decodeProductSimilarReference(JSON.stringify(input));
      if (current() !== true || !same(read(), value)) invalid();
      try {
        storage.removeItem(key); await flush();
        if (current() !== true || read() !== null) invalid();
      } catch (error) {
        if (current() === true) try {
          if (read() === null) { storage.setItem(key, JSON.stringify(value)); await flush(); }
        } catch { /* Keep the unresolved reference in the hook. */ }
        throw error;
      }
    },
  });
}

export const productSimilarReferenceStore = createProductSimilarReferenceStore({ storage: shopStorage,
  flush: flushShopStorage });
