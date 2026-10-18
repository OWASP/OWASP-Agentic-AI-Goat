import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import CustomerCartConfirmation from './CustomerCartConfirmation.jsx';
import { attachShopStorage, SHOP_CHAT_CART_KEY } from '../utils/shopStorage.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const scopeKey = 'c'.repeat(64);
const proposal = { version: 1, proposalId: id, status: 'prepared', kind: 'cart.add',
  choice: { version: 1, kind: 'product', choiceId, title: 'Practice laptop', detail: 'Current shop product' },
  quantity: 2, quoteSha256: 'd'.repeat(64) };
const receipt = { version: 1, operationId: id, kind: 'cart.add', status: 'completed',
  result: { id: 11 }, replayed: true };
const response = value => ({ ok: true, json: async () => value });

let root, node, values, releaseStorage, transport, reloadCart;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  values = new Map();
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key), flush: async () => {} });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  transport = jest.fn();
  reloadCart = jest.fn(async () => ({ items: [{ product_id: 7, quantity: 2 }], subtotal: 24 }));
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); releaseStorage(); });
const mount = async (current, authorityKey = 'persona-a') => act(async () => root.render(
  <CustomerCartConfirmation proposal={current} authorityKey={authorityKey}
    onCartApplied={reloadCart} transport={transport} />));
const click = async label => act(async () => {
  const button = [...node.querySelectorAll('button')].find(row => row.textContent === label);
  expect(button).toBeDefined(); button.click();
  await Promise.resolve(); await Promise.resolve();
});

test('physical confirmation follows visible named item and parent-ACKed exact UUID', async () => {
  let reads = 0;
  transport.mockImplementation((url, options) => {
    if (url.endsWith(`/operations/${id}`)) return Promise.resolve(response({ scopeKey, operationId: id,
      status: ++reads === 1 ? 'prepared' : 'completed', proposal,
      ...(reads === 1 ? {} : { receipt }) }));
    expect(url).toBe('/api/secureshop/customer/commerce/cart/confirm');
    expect(options.method).toBe('POST');
    expect(JSON.parse(options.body)).toEqual({ proposalId: id });
    expect(JSON.parse(values.get(SHOP_CHAT_CART_KEY))).toEqual({ operationId: id,
      intentDigest: proposal.quoteSha256, scopeKey });
    return Promise.resolve(response({ ...receipt, scopeKey, replayed: false }));
  });
  await mount(proposal);
  expect(node.querySelector('section[aria-label="Customer cart confirmation"]')).not.toBeNull();
  expect(node.textContent).toContain('Practice laptop');
  expect(node.textContent).toContain('Quantity to add: 2');
  expect(transport).not.toHaveBeenCalled();
  await click('Confirm cart change');
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(false);
  expect(node.textContent).toContain('Cart change applied');
  expect(reloadCart).toHaveBeenCalledTimes(1);
});

test('unknown confirmation survives reload and recovers by GET without a second POST', async () => {
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
    return Promise.reject(new Error('Response lost'));
  });
  await mount(proposal);
  await click('Confirm cart change');
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(true);
  await mount(null);
  await click('Check saved cart change');
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(false);
  expect(node.textContent).toContain('Cart change applied');
  expect(reloadCart).toHaveBeenCalledTimes(1);
});

test('a saved cart GET survives later same-authority proposal hydration without replay', async () => {
  values.set(SHOP_CHAT_CART_KEY, JSON.stringify({ operationId: id,
    intentDigest: proposal.quoteSha256, scopeKey }));
  let resolveRead, readSignal;
  transport.mockImplementation((url, options = {}) => {
    if (url.endsWith(`/operations/${id}`)) {
      readSignal = options.signal;
      return new Promise(resolve => { resolveRead = resolve; });
    }
    throw Error(`Unexpected ${url}`);
  });
  await mount(null);
  await click('Check saved cart change');
  expect(readSignal.aborted).toBe(false);
  await mount(proposal);
  expect(readSignal.aborted).toBe(false);
  expect([...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved cart change').disabled).toBe(true);
  await act(async () => { resolveRead(response({ scopeKey, operationId: id,
    status: 'completed', proposal, receipt })); });
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(false);
  expect(node.textContent).toContain('Cart change applied');
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
});

test('an authority change aborts a pending saved cart GET and retains the exact reference', async () => {
  values.set(SHOP_CHAT_CART_KEY, JSON.stringify({ operationId: id,
    intentDigest: proposal.quoteSha256, scopeKey }));
  let readSignal;
  transport.mockImplementation((url, options = {}) => {
    if (url.endsWith(`/operations/${id}`)) {
      readSignal = options.signal;
      return new Promise(() => {});
    }
    throw Error(`Unexpected ${url}`);
  });
  await mount(null);
  await click('Check saved cart change');
  await mount(null, 'persona-b');
  expect(readSignal.aborted).toBe(true);
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(true);
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
});

test('source replacement during cart preflight blocks saving and confirmation POST', async () => {
  let resolvePreflight, preflightSignal;
  transport.mockImplementation((url, options = {}) => {
    if (url.endsWith(`/operations/${id}`)) {
      preflightSignal = options.signal;
      return new Promise(resolve => { resolvePreflight = resolve; });
    }
    throw Error(`Unexpected ${url}`);
  });
  await mount(proposal);
  await click('Confirm cart change');
  expect(preflightSignal.aborted).toBe(false);
  await mount(null);
  expect(preflightSignal.aborted).toBe(true);
  await act(async () => { resolvePreflight(response({ scopeKey, operationId: id,
    status: 'prepared', proposal })); });
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(false);
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
});

test('a completed saved cart result leaves the next proposal actionable', async () => {
  values.set(SHOP_CHAT_CART_KEY, JSON.stringify({ operationId: id,
    intentDigest: proposal.quoteSha256, scopeKey }));
  const nextProposal = { ...proposal, proposalId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    choice: { ...proposal.choice, title: 'Practice tablet' } };
  transport.mockImplementation(url => {
    if (url.endsWith(`/operations/${id}`)) return Promise.resolve(response({ scopeKey,
      operationId: id, status: 'completed', proposal, receipt }));
    throw Error(`Unexpected ${url}`);
  });
  await mount(null);
  await click('Check saved cart change');
  expect(node.textContent).toContain('Cart change applied');
  await mount(nextProposal);
  const next = [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Confirm cart change');
  expect(next).toBeDefined(); expect(next.disabled).toBe(false);
  expect(node.textContent).toContain('Practice tablet');
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(false);
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
});

test('foreign saved cart request blocks a new confirmation', async () => {
  const old = { operationId: choiceId, intentDigest: 'e'.repeat(64), scopeKey };
  values.set(SHOP_CHAT_CART_KEY, JSON.stringify(old));
  transport.mockResolvedValue({ ok: false, status: 503 });
  await mount(proposal);
  expect(node.querySelector('button').textContent).toBe('Check saved cart change');
  await click('Check saved cart change');
  expect(transport).toHaveBeenCalledWith(`/api/secureshop/customer/commerce/operations/${choiceId}`, expect.any(Object));
  expect(transport.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(true);
});

test('replaced parent reference during save ACK prevents cart mutation', async () => {
  releaseStorage();
  let releaseAck;
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => new Promise(resolve => { releaseAck = resolve; }) });
  transport.mockResolvedValue(response({ scopeKey, operationId: id, status: 'prepared', proposal }));
  await mount(proposal);
  await act(async () => { node.querySelector('button').click(); await Promise.resolve(); await Promise.resolve(); });
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(true);
  values.set(SHOP_CHAT_CART_KEY, JSON.stringify({ operationId: choiceId,
    intentDigest: 'e'.repeat(64), scopeKey }));
  await act(async () => { releaseAck(); await Promise.resolve(); });
  expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  expect(JSON.parse(values.get(SHOP_CHAT_CART_KEY)).operationId).toBe(choiceId);
});

test('stale saved receipt explicitly reports no cart effect', async () => {
  const stale = { ...receipt, status: 'stale', result: null };
  let reads = 0;
  transport.mockImplementation(url => url.endsWith(`/operations/${id}`)
    ? Promise.resolve(response({ scopeKey, operationId: id,
      status: ++reads === 1 ? 'prepared' : 'completed', proposal,
      ...(reads === 1 ? {} : { receipt: stale }) }))
    : Promise.resolve(response({ ...stale, replayed: false, scopeKey })));
  await mount(proposal);
  await click('Confirm cart change');
  expect(node.textContent).toContain('No cart change was applied');
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(false);
  expect(reloadCart).not.toHaveBeenCalled();
});
