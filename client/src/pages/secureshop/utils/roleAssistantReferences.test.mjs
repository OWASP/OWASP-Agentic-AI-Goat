import { attachShopStorage, SHOP_ROLE_ASSISTANT_KEY } from './shopStorage.mjs';
import { decodeRoleAssistantReferences, readRoleAssistantReference,
  saveRoleAssistantReference, clearRoleAssistantReference } from './roleAssistantReferences.mjs';
import { validateShopSnapshot } from '../bridge/stateStore.mjs';

const merchant = { role: 'merchant', shopUserId: 7,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
const admin = { ...merchant, role: 'admin', shopUserId: 8,
  requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' };

test('role assistant references are exact opaque parent state with no prompt or token', async () => {
  const values = new Map(); let acknowledged = 0;
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { acknowledged++; } });
  try {
    await saveRoleAssistantReference(merchant);
    expect(acknowledged).toBe(1);
    expect(readRoleAssistantReference('merchant', 7)).toEqual(merchant);
    expect(readRoleAssistantReference('admin', 8)).toBeNull();
    expect(values.get(SHOP_ROLE_ASSISTANT_KEY)).not.toMatch(/prompt|token|password/i);
    await saveRoleAssistantReference(admin);
    expect(decodeRoleAssistantReferences(values.get(SHOP_ROLE_ASSISTANT_KEY))).toHaveLength(2);
    await expect(saveRoleAssistantReference({ ...merchant,
      requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' })).rejects.toThrow('Check the saved');
    expect(validateShopSnapshot({ secureshop_v2_token: null, ss_guest_cart: null,
      [SHOP_ROLE_ASSISTANT_KEY]: values.get(SHOP_ROLE_ASSISTANT_KEY) })[SHOP_ROLE_ASSISTANT_KEY])
      .toBe(values.get(SHOP_ROLE_ASSISTANT_KEY));
    await clearRoleAssistantReference(merchant);
    expect(readRoleAssistantReference('merchant', 7)).toBeNull();
    expect(readRoleAssistantReference('admin', 8)).toEqual(admin);
    await clearRoleAssistantReference(admin);
    expect(values.has(SHOP_ROLE_ASSISTANT_KEY)).toBe(false);
  } finally { release(); }
});

test('role assistant decoder rejects forged fields, duplicate owners and malformed identity', () => {
  const raw = rows => JSON.stringify({ version: 1, references: rows });
  expect(() => decodeRoleAssistantReferences(raw([{ ...merchant, message: 'raw prompt' }]))).toThrow();
  expect(() => decodeRoleAssistantReferences(raw([{ ...merchant, token: 'secret' }]))).toThrow();
  expect(() => decodeRoleAssistantReferences(raw([{ ...merchant, role: 'customer' }]))).toThrow();
  expect(() => decodeRoleAssistantReferences(raw([{ ...merchant, sessionId: 'not-a-uuid' }]))).toThrow();
  expect(() => decodeRoleAssistantReferences(raw([merchant, { ...merchant,
    requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' }]))).toThrow();
  expect(() => decodeRoleAssistantReferences(raw([]))).toThrow();
  expect(() => validateShopSnapshot({ secureshop_v2_token: null, ss_guest_cart: null,
    [SHOP_ROLE_ASSISTANT_KEY]: raw([{ ...merchant, message: 'raw prompt' }]) })).toThrow();
});

test('failed removal ACK restores only the exact role reference across remount', async () => {
  const values = new Map([[SHOP_ROLE_ASSISTANT_KEY, JSON.stringify({ version: 1,
    references: [merchant, admin] })]]);
  let flushes = 0;
  const adapter = { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { if (++flushes === 1) throw new Error('Parent removal ACK lost'); } };
  const release = attachShopStorage(adapter);
  try {
    await expect(clearRoleAssistantReference(merchant)).rejects.toThrow('Parent removal ACK lost');
    expect(readRoleAssistantReference('merchant', 7)).toEqual(merchant);
    expect(readRoleAssistantReference('admin', 8)).toEqual(admin);
  } finally { release(); }
  const remounted = attachShopStorage(adapter);
  try {
    expect(readRoleAssistantReference('merchant', 7)).toEqual(merchant);
    expect(readRoleAssistantReference('admin', 8)).toEqual(admin);
  } finally { remounted(); }
});

test('failed removal ACK never overwrites a replacement for the same role owner', async () => {
  const replacement = { ...merchant, requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  const values = new Map([[SHOP_ROLE_ASSISTANT_KEY, JSON.stringify({ version: 1,
    references: [merchant, admin] })]]);
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { values.set(SHOP_ROLE_ASSISTANT_KEY, JSON.stringify({ version: 1,
      references: [replacement, admin] })); throw new Error('Parent removal ACK lost'); } });
  try {
    await expect(clearRoleAssistantReference(merchant)).rejects.toThrow('Parent removal ACK lost');
    expect(readRoleAssistantReference('merchant', 7)).toEqual(replacement);
    expect(readRoleAssistantReference('admin', 8)).toEqual(admin);
  } finally { release(); }
});
