import { attachShopStorage, SHOP_CUSTOMER_COUPON_PROBE_KEY } from './shopStorage.mjs';
import { createCustomerCouponProbeStore, customerCouponProbeReferenceStore,
  decodeCustomerCouponProbeReferences } from './customerCouponProbeReference.mjs';

const first = { shopUserId: 7, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
const second = { shopUserId: 8, sessionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', startedAt: 1235 };

function fixture() {
  const values = new Map();
  return { values, store: createCustomerCouponProbeStore({ storage: {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  } }) };
}

test('coupon probe references persist only owner and opaque request IDs', async () => {
  const { store, values } = fixture();
  await store.save(first);
  await store.save(second);
  expect(store.read(first.shopUserId)).toEqual(first);
  expect(store.read(second.shopUserId)).toEqual(second);
  expect([...values.values()].join()).not.toContain('coupon code');
  await expect(store.save(first)).rejects.toThrow();
  await store.clear(first);
  expect(store.read(first.shopUserId)).toBeNull();
  expect(store.read(second.shopUserId)).toEqual(second);
});

test('coupon probe reference rejects public text, probes, and malformed IDs', () => {
  expect(() => decodeCustomerCouponProbeReferences(JSON.stringify({ version: 1,
    references: [{ ...first, text: 'coupon reply' }] }))).toThrow();
  expect(() => decodeCustomerCouponProbeReferences(JSON.stringify({ version: 1,
    references: [{ ...first, probes: [] }] }))).toThrow();
  expect(() => decodeCustomerCouponProbeReferences(JSON.stringify({ version: 1,
    references: [{ ...first, requestId: 'not-a-uuid' }] }))).toThrow();
});

test('a lost save acknowledgement leaves the opaque reference latched', async () => {
  let raw = null;
  const store = createCustomerCouponProbeStore({ storage: {
    getItem: () => raw, setItem: (_key, value) => { raw = value; }, removeItem: () => { raw = null; },
  }, flush: async () => { throw Error('ack lost'); } });
  await expect(store.save(first)).rejects.toThrow('ack lost');
  expect(store.read(first.shopUserId)).toEqual(first);
  await expect(store.save(first)).rejects.toThrow();
});

test('the default probe store uses the acknowledged scoped shop storage', async () => {
  const values = new Map();
  const flush = jest.fn(async () => {});
  const release = attachShopStorage({
    getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key), flush,
  });
  try {
    await customerCouponProbeReferenceStore.save(first);
    expect(flush).toHaveBeenCalledTimes(1);
    expect(values.get(SHOP_CUSTOMER_COUPON_PROBE_KEY)).toContain(first.sessionId);
  } finally { release(); }
});
