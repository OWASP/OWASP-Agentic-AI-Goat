import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import CustomerCheckoutCard from './CustomerCheckoutCard.jsx';
import { attachShopStorage, SHOP_CHECKOUT_KEY } from '../utils/shopStorage.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const choice = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const scopeKey = 'c'.repeat(64);
const proposal = { version: 1, proposalId: id, status: 'prepared', currency: 'USD',
  items: [{ productId: 7, name: 'Practice laptop', quantity: 1, unitPriceCents: 1200, lineTotalCents: 1200 }],
  subtotalCents: 1200, discountCents: 0, totalCents: 1200,
  address: { choiceId: choice, title: 'Home practice address', detail: 'Saved address' },
  paymentMethod: { choiceId: choice, title: 'Approved practice payment', detail: 'Synthetic only' },
  quoteSha256: 'd'.repeat(64) };
const receipt = { version: 1, operationId: id, kind: 'checkout.confirm', status: 'approved',
  currency: 'USD', totalCents: 1200, order: { orderId: 91, total: 12, subtotal: 12, discount: 0 }, replayed: true };
const response = value => ({ ok: true, json: async () => value });

let root, node, releaseStorage, values, transport;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  values = new Map();
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key), flush: async () => {} });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  transport = jest.fn();
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); releaseStorage(); });
const mount = async (current, extra = {}) => act(async () => root.render(
  <CustomerCheckoutCard proposal={current} authorityKey="persona-a" transport={transport} {...extra} />));
const click = async label => act(async () => {
  const button = [...node.querySelectorAll('button')].find(row => row.textContent === label);
  expect(button).toBeDefined(); button.click();
  await Promise.resolve(); await Promise.resolve();
});

test('exact quote is shown and parent ACK precedes the sole confirmation POST', async () => {
  let reads = 0;
  transport.mockImplementation((url, options) => {
    if (url.endsWith(`/operations/${id}`)) return Promise.resolve(response({ scopeKey, operationId: id,
      status: ++reads === 1 ? 'prepared' : 'completed', proposal,
      ...(reads === 1 ? {} : { receipt }) }));
    expect(url).toBe('/api/secureshop/customer/commerce/checkout/confirm');
    expect(options.method).toBe('POST');
    expect(JSON.parse(options.body)).toEqual({ proposalId: id });
    expect(JSON.parse(values.get(SHOP_CHECKOUT_KEY))).toEqual({ operationId: id,
      intentDigest: proposal.quoteSha256, scopeKey });
    return Promise.resolve(response({ ...receipt, scopeKey, replayed: false }));
  });
  await mount(proposal);
  expect(node.textContent).toContain('Practice laptop');
  expect(node.textContent).toContain('Total $12.00');
  await click('Confirm this practice order');
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(false);
  expect(node.textContent).toContain('Order placed');
});

test('unknown confirmation remains GET-only with the exact saved UUID', async () => {
  let reads = 0;
  transport.mockImplementation((url, options) => {
    if (url.endsWith(`/operations/${id}`)) {
      reads += 1;
      if (reads === 2) return Promise.resolve({ ok: false, status: 503 });
      return Promise.resolve(response({ scopeKey, operationId: id,
        status: reads === 1 ? 'prepared' : 'completed', proposal,
        ...(reads === 1 ? {} : { receipt }) }));
    }
    expect(options.method).toBe('POST');
    return Promise.reject(new Error('Connection lost'));
  });
  await mount(proposal);
  await click('Confirm this practice order');
  expect(JSON.parse(values.get(SHOP_CHECKOUT_KEY)).operationId).toBe(id);
  await click('Check saved checkout');
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(false);
  expect(node.textContent).toContain('Order placed');
});

test('a saved attempted confirmation remains GET-only when its proposal is no longer current', async () => {
  values.set(SHOP_CHECKOUT_KEY, JSON.stringify({ operationId: id,
    intentDigest: proposal.quoteSha256, scopeKey }));
  transport.mockResolvedValue(response({ scopeKey, operationId: id, status: 'completed',
    proposal, receipt }));
  await mount(null);
  expect(node.querySelector('section[aria-label="Customer checkout confirmation"]')).not.toBeNull();
  expect(node.textContent).not.toContain('Review your order');
  await click('Check saved checkout');
  expect(transport).toHaveBeenCalledTimes(1);
  expect(transport).toHaveBeenCalledWith(`/api/secureshop/customer/commerce/operations/${id}`,
    expect.objectContaining({ method: 'GET' }));
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(false);
  expect(node.textContent).toContain('Order placed');
});

test('hydrating the same saved proposal does not abort its in-flight recovery GET', async () => {
  values.set(SHOP_CHECKOUT_KEY, JSON.stringify({ operationId: id,
    intentDigest: proposal.quoteSha256, scopeKey }));
  let finishRead;
  transport.mockImplementation(() => new Promise(resolve => { finishRead = resolve; }));
  await mount(null);
  await act(async () => {
    node.querySelector('button').click();
    await Promise.resolve();
  });
  expect(transport).toHaveBeenCalledTimes(1);
  const signal = transport.mock.calls[0][1].signal;
  expect(node.textContent).toContain('Check saved checkout');
  await mount(proposal);
  expect(signal.aborted).toBe(false);
  expect(transport).toHaveBeenCalledTimes(1);
  await act(async () => finishRead(response({ scopeKey, operationId: id,
    status: 'completed', proposal, receipt })));
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(false);
  expect(node.textContent).toContain('Order placed');
  expect(node.textContent).toContain('Order confirmed from the saved receipt.');
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
});

test('changing checkout authority still aborts a saved recovery GET', async () => {
  values.set(SHOP_CHECKOUT_KEY, JSON.stringify({ operationId: id,
    intentDigest: proposal.quoteSha256, scopeKey }));
  let finishRead;
  transport.mockImplementation(() => new Promise(resolve => { finishRead = resolve; }));
  await mount(null);
  await act(async () => { node.querySelector('button').click(); await Promise.resolve(); });
  const oldSignal = transport.mock.calls[0][1].signal;
  await mount(null, { authorityKey: 'persona-b' });
  expect(oldSignal.aborted).toBe(true);
  await act(async () => finishRead(response({ scopeKey, operationId: id,
    status: 'completed', proposal, receipt })));
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(true);
  expect(node.textContent).not.toContain('Order placed');
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
});

test('a different proposal cancels an in-flight confirmation preflight before POST', async () => {
  let finishRead;
  transport.mockImplementation(() => new Promise(resolve => { finishRead = resolve; }));
  await mount(proposal);
  await act(async () => { node.querySelector('button').click(); await Promise.resolve(); });
  const oldSignal = transport.mock.calls[0][1].signal;
  await mount({ ...proposal, proposalId: choice });
  expect(oldSignal.aborted).toBe(true);
  await act(async () => finishRead(response({ scopeKey, operationId: id,
    status: 'prepared', proposal })));
  expect(transport).toHaveBeenCalledTimes(1);
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(false);
  expect(node.textContent).toContain('Confirm this practice order');
});

test.each([
  ['approved', receipt, 'Order confirmed from the saved receipt'],
  ['declined', { ...receipt, status: 'declined', order: null }, 'did not place an order'],
])('a remounted %s proposal reads its completed receipt without another confirmation', async (
  _status, savedReceipt, notice,
) => {
  transport.mockResolvedValue(response({ scopeKey, operationId: id, status: 'completed',
    proposal, receipt: savedReceipt }));
  await mount(proposal);
  expect(node.textContent).toContain('Confirm this practice order');
  await click('Confirm this practice order');
  expect(transport).toHaveBeenCalledTimes(1);
  expect(transport).toHaveBeenCalledWith(`/api/secureshop/customer/commerce/operations/${id}`,
    expect.objectContaining({ method: 'GET' }));
  expect(transport.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(false);
  expect(node.textContent).toContain(notice);
  expect(node.textContent).toContain('No confirmation was sent again.');
  expect(node.textContent).not.toContain('Checkout quote changed');
  expect(node.textContent).not.toContain('Confirm this practice order');
});

test('only an exact saved declined receipt offers a fresh payment-choice chat action', async () => {
  const chooseAnother = jest.fn();
  const declined = { ...receipt, status: 'declined', order: null };
  transport.mockResolvedValue(response({ scopeKey, operationId: id, status: 'completed',
    proposal, receipt: declined }));
  await mount(proposal, { onChooseAnotherPayment: chooseAnother });
  expect(node.textContent).not.toContain('Choose another payment method');
  await click('Confirm this practice order');
  expect(transport).toHaveBeenCalledTimes(1);
  expect(transport.mock.calls[0][1].method).toBe('GET');
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(false);
  await click('Choose another payment method');
  expect(chooseAnother).toHaveBeenCalledTimes(1);
  expect(transport).toHaveBeenCalledTimes(1);

  await mount({ ...proposal, proposalId: choice }, { onChooseAnotherPayment: chooseAnother });
  expect(node.textContent).not.toContain('Choose another payment method');
  expect(node.textContent).not.toContain('Practice payment declined. No order was placed.');
  expect(node.textContent).toContain('Confirm this practice order');
  await mount(proposal, { onChooseAnotherPayment: null });
  expect(node.textContent).not.toContain('Choose another payment method');
});

test('a checkout reference saved in another tab blocks the declined-receipt chat action at click time', async () => {
  const chooseAnother = jest.fn();
  transport.mockResolvedValue(response({ scopeKey, operationId: id, status: 'completed',
    proposal, receipt: { ...receipt, status: 'declined', order: null } }));
  await mount(proposal, { onChooseAnotherPayment: chooseAnother });
  await click('Confirm this practice order');
  values.set(SHOP_CHECKOUT_KEY, JSON.stringify({ operationId: choice,
    intentDigest: 'e'.repeat(64), scopeKey }));
  await click('Choose another payment method');
  expect(chooseAnother).not.toHaveBeenCalled();
  expect(node.textContent).toContain('A checkout request is saved');
  expect(node.textContent).toContain('Check saved checkout');
  expect(transport.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});

test('a different unresolved checkout reference blocks a new proposal confirmation', async () => {
  const old = { operationId: choice, intentDigest: 'e'.repeat(64), scopeKey };
  values.set(SHOP_CHECKOUT_KEY, JSON.stringify(old));
  transport.mockResolvedValue({ ok: false, status: 503 });
  await mount(proposal);
  expect(node.textContent).toContain('A checkout request is saved');
  expect(node.querySelector('button').textContent).toBe('Check saved checkout');
  await click('Check saved checkout');
  expect(transport).toHaveBeenCalledWith(`/api/secureshop/customer/commerce/operations/${choice}`, expect.any(Object));
  expect(transport.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(true);
});

test('parent persistence refusal prevents confirmation POST', async () => {
  releaseStorage();
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { throw new Error('Parent refused'); } });
  transport.mockResolvedValue(response({ scopeKey, operationId: id, status: 'prepared', proposal }));
  await mount(proposal);
  await click('Confirm this practice order');
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(true);
});

test('a replaced reference during delayed parent ACK prevents confirmation POST', async () => {
  releaseStorage();
  let releaseAck;
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => new Promise(resolve => { releaseAck = resolve; }) });
  transport.mockResolvedValue(response({ scopeKey, operationId: id, status: 'prepared', proposal }));
  await mount(proposal);
  await act(async () => {
    node.querySelector('button').click();
    await Promise.resolve(); await Promise.resolve();
  });
  expect(values.has(SHOP_CHECKOUT_KEY)).toBe(true);
  values.set(SHOP_CHECKOUT_KEY, JSON.stringify({ operationId: choice,
    intentDigest: 'e'.repeat(64), scopeKey }));
  await act(async () => { releaseAck(); await Promise.resolve(); });
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  expect(JSON.parse(values.get(SHOP_CHECKOUT_KEY)).operationId).toBe(choice);
});
