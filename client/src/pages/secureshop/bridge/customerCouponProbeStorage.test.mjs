import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_CUSTOMER_COUPON_PROBE_KEY,
  createShopStorage } from '../utils/shopStorage.mjs';
import { CUSTOMER_COUPON_PROBE_REFERENCE_KEY } from '../utils/customerCouponProbeReference.mjs';

const reference = JSON.stringify({ version: 1, references: [{ shopUserId: 7,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 }] });

test('parent state accepts only the closed opaque coupon-probe references', () => {
  expect(SHOP_CUSTOMER_COUPON_PROBE_KEY).toBe(CUSTOMER_COUPON_PROBE_REFERENCE_KEY);
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CUSTOMER_COUPON_PROBE_KEY]: reference })[SHOP_CUSTOMER_COUPON_PROBE_KEY]).toBe(reference);
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CUSTOMER_COUPON_PROBE_KEY]: JSON.stringify({ version: 1, references: [{
      shopUserId: 7, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234, text: 'private',
    }] }) })).toThrow();
});

test('coupon-probe references have no page-memory fallback after storage failure', () => {
  const storage = createShopStorage({ getStorage: () => ({
    getItem: () => { throw Error('offline'); }, setItem: () => { throw Error('offline'); },
    removeItem: () => { throw Error('offline'); },
  }) });
  expect(() => storage.getItem(SHOP_CUSTOMER_COUPON_PROBE_KEY)).toThrow('offline');
  expect(() => storage.setItem(SHOP_CUSTOMER_COUPON_PROBE_KEY, reference)).toThrow('offline');
  expect(() => storage.removeItem(SHOP_CUSTOMER_COUPON_PROBE_KEY)).toThrow('offline');
});
