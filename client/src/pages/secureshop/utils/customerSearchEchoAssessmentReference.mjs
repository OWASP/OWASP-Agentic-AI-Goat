import { flushShopStorage, shopStorage, SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const FIELDS = ['version', 'shopUserId', 'sessionId', 'requestId', 'step', 'startedAt'];
const exact = value => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...FIELDS].sort().join(',');
const same = (a, b) => !!a && !!b && FIELDS.every(key => a[key] === b[key]);
const invalid = () => { throw TypeError('Invalid saved search assessment'); };

export function decodeSearchEchoAssessmentReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 512) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!exact(value) || value.version !== 1
    || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1
    || !UUID.test(value.sessionId) || !UUID.test(value.requestId)
    || !Number.isInteger(value.step) || value.step < 1 || value.step > 4
    || !Number.isSafeInteger(value.startedAt) || value.startedAt < 1) invalid();
  return Object.freeze(value);
}

export function createSearchEchoAssessmentStore({ storage, flush,
  key = SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY } = {}) {
  if (key !== SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY
    || typeof storage?.getItem !== 'function' || typeof storage?.setItem !== 'function'
    || typeof storage?.removeItem !== 'function' || typeof flush !== 'function') invalid();
  const read = () => decodeSearchEchoAssessmentReference(storage.getItem(key));
  return Object.freeze({
    read(shopUserId) {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
      const current = read(); return current?.shopUserId === shopUserId ? current : null;
    },
    async save(input, current = () => true) {
      const value = decodeSearchEchoAssessmentReference(JSON.stringify({ version: 1, ...input }));
      if (current() !== true || read() !== null) invalid();
      storage.setItem(key, JSON.stringify(value)); await flush();
      if (current() !== true || !same(read(), value)) invalid();
      return value;
    },
    async clear(input, current = () => true) {
      const value = decodeSearchEchoAssessmentReference(JSON.stringify(input));
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

export const searchEchoAssessmentStore = createSearchEchoAssessmentStore({ storage: shopStorage,
  flush: flushShopStorage });
