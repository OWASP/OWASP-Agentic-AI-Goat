import { flushShopStorage, shopStorage, SHOP_CUSTOMER_COUPON_PROBE_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const KEY = SHOP_CUSTOMER_COUPON_PROBE_KEY;
const MAX_REFERENCES = 32;
const encoder = new TextEncoder();

const invalid = () => { throw new Error('Saved coupon chat reference unavailable'); };
const same = (left, right) => !!left && !!right
  && ['shopUserId', 'sessionId', 'requestId', 'startedAt'].every(key => left[key] === right[key]);

export function decodeCustomerCouponProbeReferences(raw) {
  if (raw === null) return [];
  if (typeof raw !== 'string' || encoder.encode(raw).byteLength > 8192) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== 'references,version' || value.version !== 1
    || !Array.isArray(value.references) || value.references.length > MAX_REFERENCES) invalid();
  const owners = new Set(), requests = new Set();
  return value.references.map(reference => {
    if (!reference || Object.getPrototypeOf(reference) !== Object.prototype
      || Object.keys(reference).sort().join(',') !== 'requestId,sessionId,shopUserId,startedAt'
      || !Number.isSafeInteger(reference.shopUserId) || reference.shopUserId < 1
      || ![reference.sessionId, reference.requestId].every(id => typeof id === 'string' && UUID.test(id))
      || !Number.isSafeInteger(reference.startedAt) || reference.startedAt < 1
      || owners.has(reference.shopUserId) || requests.has(reference.requestId)) invalid();
    owners.add(reference.shopUserId); requests.add(reference.requestId);
    return Object.freeze({ ...reference });
  });
}

export function createCustomerCouponProbeStore({ storage, flush = async () => {}, key = KEY } = {}) {
  if (key !== KEY || typeof storage?.getItem !== 'function' || typeof storage?.setItem !== 'function'
    || typeof storage?.removeItem !== 'function' || typeof flush !== 'function') {
    throw new TypeError('Coupon chat reference storage required');
  }
  const all = () => decodeCustomerCouponProbeReferences(storage.getItem(key));
  const write = async references => {
    if (references.length) storage.setItem(key, JSON.stringify({ version: 1, references }));
    else storage.removeItem(key);
    await flush();
  };
  return Object.freeze({
    read(shopUserId) {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
      return all().find(reference => reference.shopUserId === shopUserId) || null;
    },
    async save(reference, current = () => true) {
      const candidate = decodeCustomerCouponProbeReferences(JSON.stringify({ version: 1,
        references: [reference] }))[0];
      const references = all();
      if (current() !== true || references.some(row => row.shopUserId === candidate.shopUserId)) invalid();
      await write([...references, candidate]);
      if (current() !== true || !same(this.read(candidate.shopUserId), candidate)) invalid();
      return candidate;
    },
    async clear(reference, current = () => true) {
      const candidate = decodeCustomerCouponProbeReferences(JSON.stringify({ version: 1,
        references: [reference] }))[0];
      const references = all();
      const existing = references.find(row => row.shopUserId === candidate.shopUserId);
      if (current() !== true || !same(existing, candidate)) invalid();
      try {
        await write(references.filter(row => row.shopUserId !== candidate.shopUserId));
        if (current() !== true || this.read(candidate.shopUserId) !== null) invalid();
      } catch (error) {
        if (current() === true) try {
          if (!this.read(candidate.shopUserId)) await write([...all(), candidate]);
        } catch { /* Keep the reference latched if restoration cannot be proved. */ }
        throw error;
      }
    },
  });
}

export const customerCouponProbeReferenceStore = createCustomerCouponProbeStore({
  storage: shopStorage, flush: flushShopStorage, key: KEY,
});

export const CUSTOMER_COUPON_PROBE_REFERENCE_KEY = KEY;
