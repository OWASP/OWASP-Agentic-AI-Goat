import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_CUSTOMER_IDOR_KEY,
  createShopStorage } from '../utils/shopStorage.mjs';
import { CUSTOMER_IDOR_LESSON_REFERENCE_KEY } from '../utils/customerIdorLessonReference.mjs';

const raw = JSON.stringify({ version: 1, shopUserId: 7,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 });

test('parent state persists only a closed IDs-only lesson reference', () => {
  expect(SHOP_CUSTOMER_IDOR_KEY).toBe(CUSTOMER_IDOR_LESSON_REFERENCE_KEY);
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CUSTOMER_IDOR_KEY]: raw })[SHOP_CUSTOMER_IDOR_KEY]).toBe(raw);
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CUSTOMER_IDOR_KEY]: JSON.stringify({ ...JSON.parse(raw), answer: 'private result' }) })).toThrow();
});

test('lesson reference storage fails closed without browser storage', () => {
  const storage = createShopStorage({ getStorage: () => ({
    getItem: () => { throw Error('offline'); },
    setItem: () => { throw Error('offline'); },
    removeItem: () => { throw Error('offline'); },
  }) });
  expect(() => storage.getItem(SHOP_CUSTOMER_IDOR_KEY)).toThrow('offline');
  expect(() => storage.setItem(SHOP_CUSTOMER_IDOR_KEY, raw)).toThrow('offline');
  expect(() => storage.removeItem(SHOP_CUSTOMER_IDOR_KEY)).toThrow('offline');
});
