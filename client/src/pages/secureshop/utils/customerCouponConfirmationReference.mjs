const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const KEYS = ['version', 'shopUserId', 'sessionId', 'requestId', 'proposalId', 'startedAt'];
export const CUSTOMER_COUPON_CONFIRMATION_KEY = 'secureshop.customer-coupon.confirmation.v1';

const exact = value => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...KEYS].sort().join(',');
const same = (left, right) => !!left && !!right
  && KEYS.every(key => left[key] === right[key]);
const invalid = () => { throw Error('Invalid saved customer coupon confirmation'); };

export function decodeCustomerCouponConfirmationReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 512) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!exact(value) || value.version !== 1
    || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1
    || ![value.sessionId, value.requestId, value.proposalId]
      .every(id => typeof id === 'string' && UUID.test(id))
    || !Number.isSafeInteger(value.startedAt) || value.startedAt < 1) invalid();
  return Object.freeze(value);
}

export function createCustomerCouponConfirmationStore({ storage, flush,
  key = CUSTOMER_COUPON_CONFIRMATION_KEY } = {}) {
  if (typeof storage?.getItem !== 'function' || typeof storage?.setItem !== 'function'
    || typeof storage?.removeItem !== 'function' || typeof flush !== 'function'
    || key !== CUSTOMER_COUPON_CONFIRMATION_KEY)
    throw new TypeError('Acknowledged coupon confirmation storage required');
  const read = () => decodeCustomerCouponConfirmationReference(storage.getItem(key));
  return Object.freeze({
    read(shopUserId) {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
      const value = read();
      return value?.shopUserId === shopUserId ? value : null;
    },
    async save(reference, current = () => true) {
      const value = decodeCustomerCouponConfirmationReference(JSON.stringify({ version: 1, ...reference }));
      if (current() !== true || read() !== null) invalid();
      storage.setItem(key, JSON.stringify(value));
      await flush();
      if (current() !== true || !same(read(), value)) invalid();
      return value;
    },
    async clear(reference, current = () => true) {
      const value = decodeCustomerCouponConfirmationReference(JSON.stringify({ version: 1, ...reference }));
      if (current() !== true || !same(read(), value)) invalid();
      try {
        storage.removeItem(key);
        await flush();
        if (current() !== true || read() !== null) invalid();
      } catch (error) {
        if (current() === true) try {
          if (read() === null) { storage.setItem(key, JSON.stringify(value)); await flush(); }
        } catch { /* The hook retains the unresolved reference. */ }
        throw error;
      }
    },
  });
}
