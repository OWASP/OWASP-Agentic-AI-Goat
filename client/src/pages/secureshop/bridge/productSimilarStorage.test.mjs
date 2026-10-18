import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_PRODUCT_SIMILAR_KEY,
  createShopStorage } from '../utils/shopStorage.mjs';

const raw = JSON.stringify({ version: 1, shopUserId: 7, productId: 12,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 });

test('parent state accepts only the IDs-only saved similar-products reference', () => {
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_PRODUCT_SIMILAR_KEY]: raw })[SHOP_PRODUCT_SIMILAR_KEY]).toBe(raw);
  for (const extra of [{ recommendation: 'private result' }, { mode: 'vuln' },
    { ownerId: 'other' }])
    expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
      [SHOP_PRODUCT_SIMILAR_KEY]: JSON.stringify({ ...JSON.parse(raw), ...extra }) }))
      .toThrow();
});

test('saved similar-products reference has no memory fallback after storage failure', () => {
  const storage = createShopStorage({ getStorage: () => ({
    getItem: () => { throw Error('offline'); }, setItem: () => { throw Error('offline'); },
    removeItem: () => { throw Error('offline'); },
  }) });
  expect(() => storage.getItem(SHOP_PRODUCT_SIMILAR_KEY)).toThrow('offline');
  expect(() => storage.setItem(SHOP_PRODUCT_SIMILAR_KEY, raw)).toThrow('offline');
  expect(() => storage.removeItem(SHOP_PRODUCT_SIMILAR_KEY)).toThrow('offline');
});
