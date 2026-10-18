import { decodeSelectedOrderDetails } from './customerOrderDetails.mjs';

const choiceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const mode = { version: 1, featureId: 'customer_chat', policyVersion: 'owned-catalog-and-cart-read-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
const card = { version: 1, kind: 'order', choiceId, title: 'Order #3',
  detail: 'USD 20.03 · delivered · approved' };
const order = { order_id: '3', total_amount: '20.03', status: 'delivered', payment_status: 'approved',
  order_date: '2026-10-11T01:02:03.123456Z', shipping_address: 'Owned synthetic address',
  items: [{ product_id: 7, product_name: '<b>Safe product text</b>', quantity: 2, price: '10.01' }] };
const result = { order, cards: [card], scopeKey: 'a'.repeat(64) };
const turn = () => ({ status: 'done', stopReason: 'end_turn', modeCapability: mode, cards: [card],
  hops: [{ tool: 'orders.details', status: 'ok', params: { choiceId }, modeCapability: mode,
    result: { content: [{ type: 'text', text: JSON.stringify(result) }] } }] });

test('decodes only the current protected selected order and all saved detail fields', () => {
  expect(decodeSelectedOrderDetails(turn())).toEqual({ orderNumber: '3', date: '2026-10-11',
    status: 'delivered', paymentStatus: 'approved', total: '$20.03',
    shippingAddress: 'Owned synthetic address',
    items: [{ name: '<b>Safe product text</b>', quantity: 2, unitPrice: '$10.01' }] });
});

test('retains readable details for historical millisecond UTC order dates', () => {
  const historical = turn();
  historical.hops[0].result.content[0].text = JSON.stringify({ ...result,
    order: { ...order, order_date: '2026-10-11T01:02:03.123Z' } });
  expect(decodeSelectedOrderDetails(historical)?.date).toBe('2026-10-11');
});

test('supports schema-valid large order totals and line counts without truncating the review', () => {
  const many = Array.from({ length: 256 }, (_, index) => ({ product_id: index + 1,
    product_name: `Owned item ${index + 1}`, quantity: 99, price: '99999999.99' }));
  const candidate = turn();
  candidate.hops[0].result.content[0].text = JSON.stringify({ ...result,
    order: { ...order, total_amount: '9999999999999.99', items: many } });
  const decoded = decodeSelectedOrderDetails(candidate);
  expect(decoded.total).toBe('$9999999999999.99');
  expect(decoded.items).toHaveLength(256);
  expect(decoded.items[255]).toEqual({ name: 'Owned item 256', quantity: 99, unitPrice: '$99999999.99' });
});

test('rejects stale or failed observations, wrong choice and malformed private/public shape', () => {
  const stale = turn(); stale.cards[0] = { ...card, choiceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
  expect(decodeSelectedOrderDetails(stale)).toBeNull();
  const failed = turn(); failed.hops[0].result.isError = true;
  expect(decodeSelectedOrderDetails(failed)).toBeNull();
  const wrongMode = turn(); wrongMode.modeCapability = { ...mode, effectiveMode: 'vuln' };
  expect(decodeSelectedOrderDetails(wrongMode)).toBeNull();
  const wrongPolicy = turn(); wrongPolicy.hops[0].modeCapability = { ...mode, policyVersion: 'different-policy' };
  expect(decodeSelectedOrderDetails(wrongPolicy)).toBeNull();
  const malformed = turn(); malformed.hops[0].result.content[0].text = JSON.stringify({ ...result, foreignTotal: 1 });
  expect(decodeSelectedOrderDetails(malformed)).toBeNull();
  const wrongOrder = turn(); wrongOrder.hops[0].result.content[0].text = JSON.stringify({ ...result,
    order: { ...order, order_id: '4' } });
  expect(decodeSelectedOrderDetails(wrongOrder)).toBeNull();
  const badStatus = turn(); badStatus.stopReason = 'tool_use';
  expect(decodeSelectedOrderDetails(badStatus)).toBeNull();
});
