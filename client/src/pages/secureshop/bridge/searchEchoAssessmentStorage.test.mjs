import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY,
  createShopStorage } from '../utils/shopStorage.mjs';

const raw = JSON.stringify({ version: 1, shopUserId: 7,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', step: 2, startedAt: 1234 });

test('parent state accepts only the closed IDs-only search assessment reference', () => {
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY]: raw })[SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY]).toBe(raw);
  for (const extra of [{ echoHtml: '<img>' }, { mode: 'vuln' }, { ownerId: 'fake' }])
    expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
      [SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY]: JSON.stringify({ ...JSON.parse(raw), ...extra }) }))
      .toThrow();
});

test('search reference has no memory fallback after storage failure', () => {
  const storage = createShopStorage({ getStorage: () => ({
    getItem: () => { throw Error('offline'); }, setItem: () => { throw Error('offline'); },
    removeItem: () => { throw Error('offline'); },
  }) });
  expect(() => storage.getItem(SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY)).toThrow('offline');
  expect(() => storage.setItem(SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY, raw)).toThrow('offline');
  expect(() => storage.removeItem(SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY)).toThrow('offline');
});
