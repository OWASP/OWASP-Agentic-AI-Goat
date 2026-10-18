import { createAdminTicketAssessmentStore, decodeAdminTicketAssessmentReference,
  ADMIN_TICKET_ASSESSMENT_KEY } from './adminTicketAssessmentReference.mjs';
import { validateShopSnapshot } from '../bridge/stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_ADMIN_TICKET_ASSESSMENT_KEY } from './shopStorage.mjs';
const ref = { shopUserId: 7, ticketId: '42', requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  startedAt: 1234 };
test('acknowledged admin assessment reference is IDs only and closed in parent snapshot', async () => {
  const memory = new Map(), flush = jest.fn(async () => {});
  const storage = { getItem: key => memory.get(key) ?? null,
    setItem: (key, value) => memory.set(key, value), removeItem: key => memory.delete(key) };
  const store = createAdminTicketAssessmentStore({ storage, flush });
  const saved = await store.save(ref);
  expect(store.read(7)).toEqual({ version: 1, ...ref });
  expect(store.read(8)).toBeNull();
  expect(flush).toHaveBeenCalledTimes(1);
  const raw = memory.get(ADMIN_TICKET_ASSESSMENT_KEY);
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_ADMIN_TICKET_ASSESSMENT_KEY]: raw })[SHOP_ADMIN_TICKET_ASSESSMENT_KEY]).toBe(raw);
  expect(() => decodeAdminTicketAssessmentReference(JSON.stringify({ version: 1, ...ref,
    body: '<img>' }))).toThrow();
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_ADMIN_TICKET_ASSESSMENT_KEY]: JSON.stringify({ version: 1, ...ref,
      answer: 'private model output' }) })).toThrow();
  await store.clear(saved);
  expect(store.read(7)).toBeNull();
});
