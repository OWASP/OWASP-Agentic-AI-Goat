import { attachShopStorage, SHOP_REGISTERED_ADMIN_CHAT_KEY,
  SHOP_REGISTERED_ADMIN_COMPLETED_KEY } from './shopStorage.mjs';
import { readRegisteredAdminCompletedReference, saveRegisteredAdminCompletedReference,
  clearRegisteredAdminCompletedReference } from './registeredAdminCompletedReference.mjs';

const row = { shopUserId: 7, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 42 };
const raw = value => JSON.stringify({ version: 1, ...value });

test('completed registered-admin pointer saves only the acknowledged pending identity', async () => {
  const values = new Map([[SHOP_REGISTERED_ADMIN_CHAT_KEY, raw(row)]]);
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => {} });
  try {
    await expect(saveRegisteredAdminCompletedReference(row)).resolves.toEqual({ version: 1, ...row });
    expect(readRegisteredAdminCompletedReference()).toEqual({ version: 1, ...row });
    expect(values.get(SHOP_REGISTERED_ADMIN_COMPLETED_KEY)).toBe(raw(row));
    expect(values.get(SHOP_REGISTERED_ADMIN_COMPLETED_KEY)).not.toMatch(/message|token|hops|reply/i);
    values.set(SHOP_REGISTERED_ADMIN_CHAT_KEY, raw({ ...row,
      requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' }));
    await expect(saveRegisteredAdminCompletedReference(row)).rejects.toThrow('changed');
    await expect(clearRegisteredAdminCompletedReference(row)).resolves.toBe(true);
    expect(readRegisteredAdminCompletedReference()).toBeNull();
  } finally { release(); }
});

test('failed parent ACK cannot release the pending registered-admin request', async () => {
  const values = new Map([[SHOP_REGISTERED_ADMIN_CHAT_KEY, raw(row)]]);
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { throw Error('Parent ACK unavailable'); } });
  try {
    await expect(saveRegisteredAdminCompletedReference(row)).rejects.toThrow('Parent ACK unavailable');
    expect(values.get(SHOP_REGISTERED_ADMIN_CHAT_KEY)).toBe(raw(row));
  } finally { release(); }
});
