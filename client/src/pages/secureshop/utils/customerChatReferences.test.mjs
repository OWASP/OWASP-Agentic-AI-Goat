import { attachShopStorage, SHOP_CUSTOMER_CHAT_KEY } from './shopStorage.mjs';
import { readCustomerChatReference, saveCustomerChatReference,
  clearCustomerChatReference } from './customerChatReferences.mjs';

const row = { shopUserId: 5, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 100 };
let values, releaseStorage, failRemove;
beforeEach(() => {
  values = new Map(); failRemove = false;
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { if (failRemove) { failRemove = false; throw Error('Parent remove ACK lost'); } } });
});
afterEach(() => releaseStorage());

test('lost removal ACK restores the exact customer request for remount recovery', async () => {
  await saveCustomerChatReference(row);
  failRemove = true;
  await expect(clearCustomerChatReference(row)).rejects.toThrow('Parent remove ACK lost');
  expect(readCustomerChatReference(5)).toEqual(row);
  expect(values.get(SHOP_CUSTOMER_CHAT_KEY)).toContain(row.requestId);
});

test('normal acknowledged removal deletes the key entirely', async () => {
  await saveCustomerChatReference(row);
  await clearCustomerChatReference(row);
  expect(values.has(SHOP_CUSTOMER_CHAT_KEY)).toBe(false);
});
