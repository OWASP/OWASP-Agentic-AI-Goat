import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import CustomerCheckoutCard from './CustomerCheckoutCard.jsx';
import { attachShopStorage, SHOP_CHECKOUT_KEY } from '../utils/shopStorage.mjs';

const operationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const nextId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const scopeKey = 'c'.repeat(64);
const proposal = { version: 1, proposalId: operationId, status: 'prepared', currency: 'USD',
  items: [{ productId: 7, name: 'Original practice item', quantity: 1,
    unitPriceCents: 1200, lineTotalCents: 1200 }],
  subtotalCents: 1200, discountCents: 0, totalCents: 1200,
  address: { choiceId: nextId, title: 'Practice address', detail: 'Saved address' },
  paymentMethod: { choiceId: nextId, title: 'Approved practice payment', detail: 'Synthetic only' },
  quoteSha256: 'd'.repeat(64) };
const reference = { operationId, intentDigest: proposal.quoteSha256, scopeKey };
const receipt = { version: 1, operationId, kind: 'checkout.confirm', status: 'approved',
  currency: 'USD', totalCents: 1200,
  order: { orderId: 91, total: 12, subtotal: 12, discount: 0 }, replayed: true };
const response = value => ({ ok: true, json: async () => value });
const completed = () => ({ scopeKey, operationId, status: 'completed', proposal, receipt });

let root, node, releaseStorage, values, transport, flush;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  values = new Map();
  flush = jest.fn(async () => {});
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => flush() });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  transport = jest.fn();
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); releaseStorage(); });
const mount = async current => act(async () => root.render(
  <CustomerCheckoutCard proposal={current} authorityKey="original-persona" transport={transport} />));
const click = async label => act(async () => {
  const button = [...node.querySelectorAll('button')].find(row => row.textContent === label);
  expect(button).toBeDefined(); expect(button.disabled).toBe(false); button.click();
  await Promise.resolve(); await Promise.resolve();
});
const postCalls = () => transport.mock.calls.filter(([, options]) => options?.method === 'POST');

test('a replacement proposal cannot adopt or clear a delayed original recovery result', async () => {
  values.set(SHOP_CHECKOUT_KEY, JSON.stringify(reference));
  let finishOriginalRead;
  transport.mockImplementationOnce(() => new Promise(resolve => { finishOriginalRead = resolve; }));
  await mount(proposal);
  await click('Check saved checkout');
  const [originalUrl, originalOptions] = transport.mock.calls[0];
  expect(originalUrl).toBe(`/api/secureshop/customer/commerce/operations/${operationId}`);
  expect(originalOptions.method).toBe('GET');
  await mount({ ...proposal, proposalId: nextId, quoteSha256: 'e'.repeat(64),
    items: [{ ...proposal.items[0], name: 'New practice item' }] });
  expect(originalOptions.signal.aborted).toBe(true);
  await act(async () => finishOriginalRead(response(completed())));
  expect(JSON.parse(values.get(SHOP_CHECKOUT_KEY))).toEqual(reference);
  expect(node.textContent).toContain('New practice item');
  expect(node.textContent).not.toContain('Order placed');
  expect(node.textContent).not.toContain('Confirm this practice order');
  expect(transport).toHaveBeenCalledTimes(1);
  expect(postCalls()).toHaveLength(0);
});

test('changed completed quote or receipt totals retain the original recovery reference', async () => {
  for (const altered of [
    { ...completed(), proposal: { ...proposal, quoteSha256: 'e'.repeat(64) } },
    { ...completed(), receipt: { ...receipt, totalCents: 1300,
      order: { ...receipt.order, total: 13, subtotal: 13 } } },
  ]) {
    values.set(SHOP_CHECKOUT_KEY, JSON.stringify(reference));
    transport.mockResolvedValueOnce(response(altered));
    await mount(proposal);
    await click('Check saved checkout');
    expect(JSON.parse(values.get(SHOP_CHECKOUT_KEY))).toEqual(reference);
    expect(node.textContent).not.toContain('Order placed');
    expect(node.textContent).toContain('Check saved checkout');
    expect(postCalls()).toHaveLength(0);
    await act(async () => root.unmount()); root = createRoot(node);
  }
  expect(transport).toHaveBeenCalledTimes(2);
  expect(transport.mock.calls.every(([url, options]) =>
    url === `/api/secureshop/customer/commerce/operations/${operationId}`
      && options.method === 'GET')).toBe(true);
  expect(flush).not.toHaveBeenCalled();
});

test('a lost clear acknowledgment restores the exact reference and true remount recovers by GET only', async () => {
  let reads = 0, lostRemoveAcknowledgment = false;
  flush.mockImplementation(async () => {
    if (!values.has(SHOP_CHECKOUT_KEY) && !lostRemoveAcknowledgment) {
      lostRemoveAcknowledgment = true;
      throw Error('Parent remove acknowledgment lost');
    }
  });
  transport.mockImplementation((url, options) => {
    if (options.method === 'GET') {
      expect(url).toBe(`/api/secureshop/customer/commerce/operations/${operationId}`);
      return Promise.resolve(response(++reads === 1
        ? { scopeKey, operationId, status: 'prepared', proposal } : completed()));
    }
    expect(url).toBe('/api/secureshop/customer/commerce/checkout/confirm');
    expect(JSON.parse(options.body)).toEqual({ proposalId: operationId });
    expect(JSON.parse(values.get(SHOP_CHECKOUT_KEY))).toEqual(reference);
    return Promise.resolve(response({ ...receipt, scopeKey, replayed: false }));
  });
  await mount(proposal);
  await click('Confirm this practice order');
  expect(lostRemoveAcknowledgment).toBe(true);
  expect(JSON.parse(values.get(SHOP_CHECKOUT_KEY))).toEqual(reference);
  expect(node.textContent).toContain('Parent remove acknowledgment lost');
  expect(postCalls()).toHaveLength(1);
  const beforeRemount = transport.mock.calls.length;
  await act(async () => root.unmount()); root = createRoot(node);
  await mount(proposal);
  expect(transport).toHaveBeenCalledTimes(beforeRemount);
  await click('Check saved checkout');
  expect(transport.mock.calls.slice(beforeRemount)).toEqual([
    [`/api/secureshop/customer/commerce/operations/${operationId}`,
      expect.objectContaining({ method: 'GET' })],
  ]);
  expect(postCalls()).toHaveLength(1);
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(false);
  expect(node.textContent).toContain('Order confirmed from the saved receipt');
  expect(node.textContent).toContain('Order placed');
});
