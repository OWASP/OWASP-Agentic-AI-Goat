import { createCustomerCouponConfirmationStore,
  decodeCustomerCouponConfirmationReference } from './customerCouponConfirmationReference.mjs';

const row = { shopUserId: 7, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  proposalId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', startedAt: 1234 };

test('coupon confirmation reference stores only original turn and proposal IDs', async () => {
  const values = new Map();
  const store = createCustomerCouponConfirmationStore({ storage: {
    getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  }, flush: async () => {} });
  expect(await store.save(row)).toMatchObject(row);
  expect(store.read(7)).toMatchObject(row);
  expect(store.read(8)).toBeNull();
  await expect(store.save(row)).rejects.toThrow();
  await store.clear({ version: 1, ...row });
  expect(store.read(7)).toBeNull();
});

test('coupon reference rejects copied code, result and malformed identities', () => {
  expect(() => decodeCustomerCouponConfirmationReference(JSON.stringify({ version: 1, ...row,
    code: 'private coupon' }))).toThrow();
  expect(() => decodeCustomerCouponConfirmationReference(JSON.stringify({ version: 1, ...row,
    proposalId: 'not-a-uuid' }))).toThrow();
  expect(() => decodeCustomerCouponConfirmationReference(JSON.stringify({ version: 1, ...row,
    result: { ok: true } }))).toThrow();
});

test('lost save acknowledgement retains the reference and forbids another write', async () => {
  let raw = null;
  const store = createCustomerCouponConfirmationStore({ storage: {
    getItem: () => raw, setItem: (_key, value) => { raw = value; }, removeItem: () => { raw = null; },
  }, flush: async () => { throw Error('ack lost'); } });
  await expect(store.save(row)).rejects.toThrow('ack lost');
  expect(store.read(7)).toMatchObject(row);
  await expect(store.save(row)).rejects.toThrow();
});
