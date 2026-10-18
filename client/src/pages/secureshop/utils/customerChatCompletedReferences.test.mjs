import { attachShopStorage, SHOP_CUSTOMER_CHAT_KEY,
  SHOP_CUSTOMER_CHAT_COMPLETED_KEY } from './shopStorage.mjs';
import { readCustomerChatCompletedReference, saveCustomerChatCompletedReference,
  clearCustomerChatCompletedReference } from './customerChatCompletedReferences.mjs';

const row = { shopUserId: 7, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 42 };
const raw = value => JSON.stringify({ version: 1, references: [value] });

test('completed pointer stores only opaque IDs after the exact pending request is acknowledged', async () => {
  const values = new Map([[SHOP_CUSTOMER_CHAT_KEY, raw(row)]]);
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => {} });
  try {
    await expect(saveCustomerChatCompletedReference(row)).resolves.toEqual(row);
    expect(readCustomerChatCompletedReference(7)).toEqual(row);
    expect(values.get(SHOP_CUSTOMER_CHAT_COMPLETED_KEY)).toBe(raw(row));
    expect(values.get(SHOP_CUSTOMER_CHAT_COMPLETED_KEY)).not.toMatch(/message|token|productName/i);
    values.set(SHOP_CUSTOMER_CHAT_KEY, raw({ ...row, requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' }));
    await expect(saveCustomerChatCompletedReference(row)).rejects.toThrow('changed');
    expect(readCustomerChatCompletedReference(7)).toEqual(row);
    await expect(clearCustomerChatCompletedReference(row)).resolves.toBe(true);
    expect(readCustomerChatCompletedReference(7)).toBeNull();
  } finally { release(); }
});

test('failed parent save acknowledgment keeps the pending request and denies completed claim', async () => {
  const values = new Map([[SHOP_CUSTOMER_CHAT_KEY, raw(row)]]);
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { throw new Error('Parent ACK unavailable'); } });
  try {
    await expect(saveCustomerChatCompletedReference(row)).rejects.toThrow('Parent ACK unavailable');
    expect(values.get(SHOP_CUSTOMER_CHAT_KEY)).toBe(raw(row));
    expect(values.get(SHOP_CUSTOMER_CHAT_COMPLETED_KEY)).toBe(raw(row));
  } finally { release(); }
});
