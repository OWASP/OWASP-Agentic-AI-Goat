import { decodeRefundReferences, readRefundReferences, saveRefundReference } from './refundReferences.mjs';
import { SHOP_REFUND_KEY } from './shopStorage.mjs';
import { validateShopSnapshot } from '../bridge/stateStore.mjs';

const first = { orderId: 7, sessionId: '11111111-1111-4111-8111-111111111111',
  requestId: '22222222-2222-4222-8222-222222222222' };
const second = { orderId: 8, sessionId: '33333333-3333-4333-8333-333333333333',
  requestId: '44444444-4444-4444-8444-444444444444' };

beforeEach(() => localStorage.removeItem(SHOP_REFUND_KEY));
afterEach(() => localStorage.removeItem(SHOP_REFUND_KEY));

test('opaque refund references are stored without reason, token, or ticket', async () => {
  await saveRefundReference(first);
  await saveRefundReference(second);
  expect(readRefundReferences()).toEqual([first, second]);
  expect(localStorage.getItem(SHOP_REFUND_KEY)).toBe(JSON.stringify({ version: 1, references: [first, second] }));
  expect(validateShopSnapshot({ secureshop_v2_token: null, ss_guest_cart: null,
    [SHOP_REFUND_KEY]: localStorage.getItem(SHOP_REFUND_KEY) })[SHOP_REFUND_KEY])
    .toBe(localStorage.getItem(SHOP_REFUND_KEY));
  await expect(saveRefundReference(first)).resolves.toEqual(first);
  await expect(saveRefundReference({ ...first, requestId: second.requestId })).rejects.toThrow();
  expect(readRefundReferences()).toEqual([first, second]);
});

test.each([
  '{}',
  JSON.stringify({ version: 1, references: [{ ...first, reason: 'secret' }] }),
  JSON.stringify({ version: 1, references: [{ ...first, requestId: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }] }),
  JSON.stringify({ version: 1, references: [first, { ...first, sessionId: second.sessionId }] }),
  JSON.stringify({ version: 1, references: [first, { ...second, requestId: first.requestId }] }),
])('malformed or conflicting persisted refund reference fails closed', raw => {
  expect(() => decodeRefundReferences(raw)).toThrow('Invalid saved refund references');
  expect(() => validateShopSnapshot({ secureshop_v2_token: null, ss_guest_cart: null,
    [SHOP_REFUND_KEY]: raw })).toThrow();
});
