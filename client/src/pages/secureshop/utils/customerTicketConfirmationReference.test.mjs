import { CUSTOMER_TICKET_CONFIRMATION_KEY, decodeCustomerTicketConfirmationReference,
  createCustomerTicketConfirmationStore } from './customerTicketConfirmationReference.mjs';

const reference = { shopUserId: 7,
  sessionId: '10000000-0000-4000-8000-000000000001',
  requestId: '20000000-0000-4000-8000-000000000001',
  proposalId: '30000000-0000-4000-8000-000000000001', startedAt: 1720000000000 };
const fixture = () => {
  const values = new Map();
  let failFlush = false;
  return { values, setFailFlush(value) { failFlush = value; }, store:
    createCustomerTicketConfirmationStore({ storage: {
      getItem: key => values.get(key) ?? null,
      setItem: (key, value) => values.set(key, value),
      removeItem: key => values.delete(key),
    }, flush: async () => { if (failFlush) throw Error('Storage unavailable'); } }) };
};

test('ticket confirmation reference stores only owner and original IDs with acknowledged persistence', async () => {
  const f = fixture();
  const saved = await f.store.save(reference);
  expect(saved).toEqual({ version: 1, ...reference });
  expect(Object.keys(saved).sort()).toEqual([
    'version', 'shopUserId', 'sessionId', 'requestId', 'proposalId', 'startedAt',
  ].sort());
  expect(f.store.read(reference.shopUserId)).toEqual(saved);
  expect(f.store.read(8)).toBeNull();
  await expect(f.store.save(reference)).rejects.toThrow();
  await f.store.clear(saved);
  expect(f.store.read(reference.shopUserId)).toBeNull();
});

test('ticket reference rejects extra source/body fields and does not forget on failed removal', async () => {
  const f = fixture(), saved = await f.store.save(reference);
  expect(() => decodeCustomerTicketConfirmationReference(JSON.stringify({ ...saved, body: '<b>x</b>' }))).toThrow();
  expect(() => decodeCustomerTicketConfirmationReference(JSON.stringify({ ...saved, shopUserId: 0 }))).toThrow();
  expect(() => createCustomerTicketConfirmationStore({ storage: f.store, flush: async () => {},
    key: 'untrusted-key' })).toThrow();
  f.setFailFlush(true);
  await expect(f.store.clear(saved)).rejects.toThrow();
  expect(f.values.has(CUSTOMER_TICKET_CONFIRMATION_KEY)).toBe(true);
});
