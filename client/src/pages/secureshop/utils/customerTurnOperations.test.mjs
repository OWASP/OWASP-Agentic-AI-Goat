import { decodeCheckoutProposal, decodeCustomerTurnOperations, decodeCartProposal, decodeCartRejection,
  decodeCartOperation } from './customerTurnOperations.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const choice = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposal = { version: 1, proposalId: id, status: 'prepared', currency: 'USD',
  items: [{ productId: 7, name: 'Practice laptop', quantity: 2, unitPriceCents: 1200, lineTotalCents: 2400 }],
  subtotalCents: 2400, discountCents: 100, totalCents: 2300,
  address: { choiceId: choice, title: 'Home practice address', detail: 'Saved address' },
  paymentMethod: { choiceId: choice, title: 'Approved practice payment', detail: 'Synthetic only' },
  quoteSha256: 'a'.repeat(64) };
const cartProposal = { version: 1, proposalId: id, status: 'prepared', kind: 'cart.add',
  choice: { version: 1, kind: 'product', choiceId: choice, title: 'Practice laptop', detail: 'Current product' },
  quantity: 2, quoteSha256: 'b'.repeat(64) };
const cartUpdateProposal = { ...cartProposal, kind: 'cart.update',
  choice: { ...cartProposal.choice, kind: 'cart_item', quantity: 2 } };

test('saved checkout proposal is a coherent exact server quote', () => {
  expect(decodeCheckoutProposal(proposal)).toBe(proposal);
  expect(decodeCustomerTurnOperations([{ operationId: id, status: 'prepared', proposal }]))
    .toMatchObject([{ operationId: id, status: 'prepared', proposal }]);
});

test.each([
  { ...proposal, totalCents: 1 },
  { ...proposal, items: [{ ...proposal.items[0], lineTotalCents: 1 }] },
  { ...proposal, pan: '4111111111111111' },
  { ...proposal, paymentMethod: { ...proposal.paymentMethod, detail: '<script>' } },
])('invalid saved checkout quote is rejected', bad => {
  if (bad.paymentMethod?.detail === '<script>') {
    // Plain text is allowed, but never interpreted as HTML by the card view.
    expect(decodeCheckoutProposal(bad)).toBe(bad);
  } else expect(() => decodeCheckoutProposal(bad)).toThrow();
});

test('turn actions stay bounded and preserve opaque identity', () => {
  expect(decodeCustomerTurnOperations(undefined)).toEqual([]);
  expect(() => decodeCustomerTurnOperations([{ operationId: id, status: 'prepared', proposal },
    { operationId: id, status: 'completed' }])).toThrow();
  expect(() => decodeCustomerTurnOperations([{ operationId: choice, status: 'prepared', proposal }])).toThrow();
  expect(() => decodeCustomerTurnOperations(Array(5).fill({ operationId: id, status: 'completed' }))).toThrow();
});

test('cart proposal binds action, named item, quantity, and exact operation digest', () => {
  expect(decodeCartProposal(cartProposal)).toBe(cartProposal);
  expect(decodeCustomerTurnOperations([{ operationId: id, status: 'prepared', proposal: cartProposal }])[0].proposal)
    .toBe(cartProposal);
  expect(() => decodeCartProposal({ ...cartProposal, quantity: 0 })).toThrow();
  expect(() => decodeCartProposal({ ...cartProposal, kind: 'cart.remove', quantity: 2 })).toThrow();
  expect(() => decodeCartProposal({ ...cartProposal, kind: 'cart.update' })).toThrow();
  expect(() => decodeCartProposal({ ...cartProposal, productId: 7 })).toThrow();
  expect(decodeCartProposal(cartUpdateProposal)).toBe(cartUpdateProposal);
  const { quantity: _currentQuantity, ...historicalChoice } = cartUpdateProposal.choice;
  const historicalProposal = { ...cartUpdateProposal, choice: historicalChoice };
  expect(decodeCartProposal(historicalProposal)).toBe(historicalProposal);
  for (const quantity of [0, 100, '2', 1.5, undefined, null]) {
    expect(() => decodeCartProposal({ ...cartUpdateProposal,
      choice: { ...cartUpdateProposal.choice, quantity } })).toThrow();
  }
  expect(() => decodeCartProposal({ ...cartProposal,
    choice: { ...cartProposal.choice, quantity: 2 } })).toThrow();
});

test('only an exact saved stock rejection proves a cart addition was not made', () => {
  const receipt = { version: 1, operationId: id, kind: 'cart.add', status: 'rejected',
    result: { code: 'INSUFFICIENT_STOCK', choiceId: choice, quantity: 2 }, replayed: true };
  expect(decodeCartRejection(receipt, id)).toEqual(receipt.result);
  expect(decodeCustomerTurnOperations([{ operationId: id, status: 'completed', receipt }])[0])
    .toMatchObject({ status: 'completed', rejection: receipt.result, hasReceipt: true });
  for (const bad of [
    { ...receipt, replayed: false },
    { ...receipt, operationId: choice },
    { ...receipt, kind: 'cart.update' },
    { ...receipt, result: { ...receipt.result, code: 'STALE' } },
    { ...receipt, result: { ...receipt.result, quantity: 0 } },
    { ...receipt, result: { ...receipt.result, productId: 7 } },
  ]) expect(() => decodeCustomerTurnOperations([{ operationId: id, status: 'completed', receipt: bad }])).toThrow();
  expect(() => decodeCustomerTurnOperations([{ operationId: id, status: 'prepared', receipt }])).toThrow();
  expect(() => decodeCustomerTurnOperations([{ operationId: id, status: 'completed',
    receipt, proposal: cartProposal }])).toThrow();
});

test('dedicated cart readback accepts exact prepared or terminal receipt only', () => {
  const reference = { operationId: id, intentDigest: cartProposal.quoteSha256, scopeKey: 'c'.repeat(64) };
  expect(decodeCartOperation({ ...reference, status: 'prepared', proposal: cartProposal }, reference).status)
    .toBe('prepared');
  const receipt = { version: 1, operationId: id, kind: 'cart.add', status: 'completed',
    result: { id: 11 }, replayed: true };
  expect(decodeCartOperation({ ...reference, status: 'completed', proposal: cartProposal, receipt }, reference).receipt)
    .toEqual(receipt);
  expect(() => decodeCartOperation({ ...reference, status: 'completed', proposal: cartProposal,
    receipt: { ...receipt, replayed: false } }, reference)).toThrow();
  expect(() => decodeCartOperation({ ...reference, status: 'completed', proposal: cartProposal,
    receipt: { ...receipt, kind: 'cart.remove' } }, reference)).toThrow();
});
