import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY,
  createShopStorage } from '../utils/shopStorage.mjs';
import { CUSTOMER_TICKET_CONFIRMATION_KEY } from '../utils/customerTicketConfirmationReference.mjs';

const raw = JSON.stringify({ version: 1, shopUserId: 7,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  proposalId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', startedAt: 1234 });

test('parent state accepts only the closed IDs-only ticket reference', () => {
  expect(SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY).toBe(CUSTOMER_TICKET_CONFIRMATION_KEY);
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY]: raw })[SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY]).toBe(raw);
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY]: JSON.stringify({ ...JSON.parse(raw), body: 'PRIVATE' }) })).toThrow();
});

test('ticket reference has no memory fallback after storage failure', () => {
  const storage = createShopStorage({ getStorage: () => ({
    getItem: () => { throw Error('offline'); }, setItem: () => { throw Error('offline'); },
    removeItem: () => { throw Error('offline'); },
  }) });
  expect(() => storage.getItem(SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY)).toThrow('offline');
  expect(() => storage.setItem(SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY, raw)).toThrow('offline');
  expect(() => storage.removeItem(SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY)).toThrow('offline');
});
