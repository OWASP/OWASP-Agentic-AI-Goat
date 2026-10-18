import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_REGISTERED_ADMIN_CHAT_KEY,
  SHOP_REGISTERED_ADMIN_COMPLETED_KEY } from '../utils/shopStorage.mjs';

const reference = JSON.stringify({ version: 1, shopUserId: 7,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 });

test('trusted parent snapshot admits only the closed opaque registered request', () => {
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_REGISTERED_ADMIN_CHAT_KEY]: reference })[SHOP_REGISTERED_ADMIN_CHAT_KEY]).toBe(reference);
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_REGISTERED_ADMIN_CHAT_KEY]: JSON.stringify({ ...JSON.parse(reference), message: 'private prompt' }) }))
    .toThrow('Invalid saved registered-tools request');
});

test('completed registered page stores IDs only and rejects transcript content', () => {
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_REGISTERED_ADMIN_COMPLETED_KEY]: reference })[SHOP_REGISTERED_ADMIN_COMPLETED_KEY]).toBe(reference);
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_REGISTERED_ADMIN_COMPLETED_KEY]: JSON.stringify({ ...JSON.parse(reference),
      text: 'private saved result' }) })).toThrow('Invalid saved registered-tools request');
});
