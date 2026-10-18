import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import Checkout from './Checkout';
import { SHOP_CHECKOUT_KEY, SHOP_PRACTICE_PAYMENT_KEY } from '../utils/shopStorage.mjs';

let auth; let cart; let toast; let persisted; let fetchMock; let confirmMode; let flushReject; let legacyReference; let operationHttp404; let malformedReceipt; let confirmDispatched;
jest.mock('../context/AuthContext', () => ({ useAuth: () => auth }));
jest.mock('../context/CartContext.jsx', () => ({ useCart: () => cart }));
jest.mock('../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../utils/shopStorage.mjs', () => ({
  SHOP_CHECKOUT_KEY: 'secureshop.checkout.operation.v1',
  SHOP_PRACTICE_PAYMENT_KEY: 'secureshop.practice-payment.operation.v1',
  shopStorage: { getItem: key => key === 'secureshop_v2_token' ? auth.token : persisted.get(key) || null,
    setItem: (key, value) => persisted.set(key, value), removeItem: key => persisted.delete(key) },
  flushShopStorage: async () => { if (flushReject) throw Error('parent acknowledgement unavailable'); },
}));
jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => ({ bound: true }) }));
jest.mock('framer-motion', () => {
  const React = require('react'); const tag = name => React.forwardRef(({ initial, animate, exit, transition, ...props }, ref) => React.createElement(name, { ...props, ref }));
  return { motion: { form: tag('form'), div: tag('div'), span: tag('span'), button: tag('button') }, AnimatePresence: ({ children }) => children, useReducedMotion: () => true };
});
const scopeKey = 'a'.repeat(64); const quoteSha256 = 'b'.repeat(64);
const conversationalScopeKey = 'c'.repeat(64);
const address = { version: 1, kind: 'address', choiceId: '123e4567-e89b-42d3-a456-426614174001', title: 'Practice home', detail: '1 Main St' };
const payment = { version: 1, kind: 'payment_method', choiceId: '123e4567-e89b-42d3-a456-426614174002', title: 'Approved practice payment', detail: 'Synthetic local choice' };
const proposalId = '123e4567-e89b-42d3-a456-426614174003';
const proposal = { version: 1, proposalId, status: 'prepared', currency: 'USD',
  items: [{ productId: 1, name: 'Item', quantity: 1, unitPriceCents: 1000, lineTotalCents: 1000 }],
  subtotalCents: 1000, discountCents: 0, totalCents: 1000,
  address: { choiceId: address.choiceId, title: address.title, detail: address.detail },
  paymentMethod: { choiceId: payment.choiceId, title: payment.title, detail: payment.detail }, quoteSha256 };
const response = (body, ok = true, status = ok ? 200 : 500) => ({ ok, status, json: async () => body });
let root; let node; let calls; let practiceOperationId; let practiceCreated; let addressCards;
const settle = async () => act(async () => { await Promise.resolve(); await Promise.resolve(); });
const input = label => [...node.querySelectorAll('input')].find(value => value.closest('.ss-input-wrap')?.querySelector('label')?.textContent === label);
const set = async (label, value) => act(async () => { const target = input(label); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(target, value); target.dispatchEvent(new Event('input', { bubbles: true })); });
const button = text => [...node.querySelectorAll('button')].find(value => value.textContent.includes(text));
const click = async text => act(async () => button(text).click());
const submit = async () => act(async () => { node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
async function reachReview() {
  await set('Address', '1 Main St'); await set('City', 'Town'); await set('State', 'CA'); await set('ZIP', '90210');
  await submit(); await settle(); await submit(); await settle();
}
beforeEach(async () => {
  jest.useFakeTimers(); global.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: require('node:crypto').webcrypto.subtle });
  auth = { user: { id: 1, full_name: 'Learner' }, token: 'token-a' };
  persisted = new Map(); confirmMode = 'approved'; flushReject = false; legacyReference = false; operationHttp404 = false; malformedReceipt = false; confirmDispatched = false; calls = []; practiceOperationId = null; practiceCreated = false;
  addressCards = [address];
  cart = { items: [{ id: 1, name: 'Item', price: 10, quantity: 1 }], subtotal: 10, total: 10, discount: 0, coupon: null, clear: jest.fn(), reload: jest.fn().mockResolvedValue({ items: [] }) };
  toast = { success: jest.fn(), error: jest.fn() };
  fetchMock = jest.fn(async (url, options = {}) => {
    calls.push([url, options.method || 'GET']);
    if (url.endsWith('/customer/commerce/addresses')) return response({ scopeKey, cards: addressCards, addresses: addressCards.map((card, index) => ({ addressId: index + 1, choiceId: card.choiceId,
      fields: { label: card.title, line1: card.detail, line2: null, city: 'Town', state: 'CA', zip: '90210', phone: null, isDefault: index === 0 } })) });
    if (url.endsWith('/customer/commerce/address-form?action=create')) return response({ scopeKey,
      action: 'create', choiceId: null, expectedSnapshotSha256: null, defaultSetSha256: quoteSha256,
      fields: { label: null, line1: '', line2: null, city: null, state: null, zip: null,
        phone: null, isDefault: false } });
    if (url.endsWith('/customer/commerce/payment-methods') && options.method === 'POST') {
      const body = JSON.parse(options.body); practiceOperationId = body.operationId; practiceCreated = true;
      return response({ scopeKey, version: 1, operationId: body.operationId, kind: 'payment.create',
        status: 'completed', result: { cards: [payment] }, replayed: false });
    }
    if (url.endsWith('/customer/commerce/payment-methods')) return response({ scopeKey, cards: [payment] });
    if (url.endsWith('/orders/summary')) return response({ summary: { item_count: 1, subtotal: 10 }, total: 10 });
    if (url.endsWith('/checkout/prepare')) return response({ scopeKey, ...proposal });
    if (url.endsWith('/checkout/confirm')) {
      confirmDispatched = true;
      if (confirmMode === 'lost') throw Error('response lost');
      return response({ scopeKey, version: 1, operationId: proposalId, kind: 'checkout.confirm', status: confirmMode, currency: 'USD', totalCents: 1000, order: confirmMode === 'approved' ? { orderId: 71, total: 10, subtotal: 10, discount: 0 } : null, replayed: false });
    }
    if (url.includes('/customer/commerce/operations/')) {
      if (!url.endsWith(`/${proposalId}`)) {
        const operationId = url.split('/').at(-1);
        return response(practiceCreated
          ? { scopeKey, operationId, status: 'completed', paymentScenario: 'approved', receipt: { version: 1, operationId,
            kind: 'payment.create', status: 'completed', result: { cards: [payment] }, replayed: true } }
          : { scopeKey, operationId, status: 'not_found' });
      }
      if (operationHttp404) return response({ error: 'not found' }, false, 404);
      if (legacyReference) return response({ scopeKey: conversationalScopeKey, operationId: proposalId, status: 'not_found' });
      const operationStatus = confirmMode === 'lost' ? 'approved' : confirmMode;
      return response({ scopeKey, operationId: proposalId, status: confirmDispatched ? 'completed' : 'prepared', proposal,
        ...(confirmDispatched ? { receipt: { version: 1, operationId: proposalId,
          kind: 'checkout.confirm', status: operationStatus, currency: 'USD', totalCents: 1000,
          order: operationStatus === 'approved' ? { orderId: 71, total: 10, subtotal: 10, discount: 0 } : null,
          replayed: malformedReceipt ? false : true } } : {}) });
    }
    if (url.includes('/orders/operations/')) return response({ scopeKey, operationId: proposalId, status: 'completed', order: { id: 72, total: 10, subtotal: 10, discount: 0 } });
    if (url.endsWith('/v2/auth/users/me/addresses')) return response({ ok: true });
    throw Error(`Unexpected ${url}`);
  });
  global.fetch = fetchMock; node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
  await act(async () => root.render(<MemoryRouter><Checkout /></MemoryRouter>));
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); jest.useRealTimers(); });

test('bound checkout exposes only server-owned address and synthetic payment choices', async () => {
  await reachReview();
  expect(node.textContent).toContain('Practice home');
  expect(node.textContent).toContain('Approved practice payment');
  expect(node.textContent).not.toContain('Card number');
  expect(node.textContent).not.toContain('CVV');
  expect(node.textContent).not.toContain('Expires');
});

test('bound checkout requires an explicit reviewed save when no delivery address exists', async () => {
  addressCards = [];
  await set('Address', '1 Main St'); await set('City', 'Town'); await set('State', 'CA'); await set('ZIP', '90210');
  await submit(); await settle();
  expect(node.querySelector('section[aria-label="Address setup"]')).not.toBeNull();
  expect(node.querySelector('input[aria-label="Street address"]').value).toBe('1 Main St');
  expect(node.textContent).toContain('Review address');
  expect(node.querySelector('section[aria-label="Practice payment setup"]')).toBeNull();
  expect(calls.filter(([url, method]) => method === 'POST' && url.endsWith('/v2/auth/users/me/addresses'))).toHaveLength(0);
  expect(calls.filter(([url, method]) => method === 'POST' && url.endsWith('/customer/commerce/addresses'))).toHaveLength(0);
});

test('checkout uses the shared acknowledged practice payment form and refreshes protected choices', async () => {
  await set('Address', '1 Main St'); await set('City', 'Town'); await set('State', 'CA'); await set('ZIP', '90210');
  await submit(); await settle();
  const initialReads = calls.filter(([url, method]) => url.endsWith('/customer/commerce/payment-methods') && method === 'GET').length;
  expect(node.querySelector('section[aria-label="Practice payment setup"]')).not.toBeNull();
  await click('Use approved practice payment');
  expect(calls.filter(([url, method]) => url.endsWith('/customer/commerce/payment-methods') && method === 'POST')).toHaveLength(0);
  await click('Create selected practice payment'); await settle();
  expect(practiceOperationId).toMatch(/^[0-9a-f-]{36}$/);
  expect(calls.filter(([url, method]) => url.endsWith('/customer/commerce/payment-methods') && method === 'POST')).toHaveLength(1);
  expect(calls.some(([url, method]) => url.endsWith(`/customer/commerce/operations/${practiceOperationId}`) && method === 'GET')).toBe(true);
  expect(persisted.has(SHOP_PRACTICE_PAYMENT_KEY)).toBe(false);
  expect(calls.filter(([url, method]) => url.endsWith('/customer/commerce/payment-methods') && method === 'GET').length)
    .toBeGreaterThan(initialReads);
  expect(node.textContent).toContain('Practice payment created from the saved result');
});

test('approved bound confirmation persists proposal identity, then uses exact GET recovery before clearing cart', async () => {
  await reachReview(); await click('Place order'); await settle();
  expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/checkout/prepare'))).toBe(true);
  expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/checkout/confirm'))).toBe(false);
  expect(node.textContent).toContain(`Quote: ${quoteSha256}`);
  await click('Confirm exact quote');
  for (let index = 0; index < 4; index += 1) {
    await settle(); await act(async () => { await jest.runOnlyPendingTimersAsync(); });
  }
  expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/checkout/confirm'))).toBe(true);
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes(`/customer/commerce/operations/${proposalId}`))).toBe(true);
  expect(fetchMock.mock.calls.filter(([url]) => String(url).includes(`/customer/commerce/operations/${proposalId}`))).toHaveLength(2);
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/orders/operations'))).toBe(false);
  expect(toast.error).not.toHaveBeenCalled();
  expect(persisted.has(SHOP_CHECKOUT_KEY)).toBe(false); expect(cart.clear).toHaveBeenCalledTimes(1);
  expect(node.textContent).toContain('Order placed.');
});

test('declined confirmation keeps the cart and removes the exact pending reference', async () => {
  confirmMode = 'declined'; await reachReview(); await click('Place order'); await settle(); await click('Confirm exact quote'); await act(async () => { await jest.advanceTimersByTimeAsync(700); }); await settle();
  expect(cart.clear).not.toHaveBeenCalled(); expect(persisted.has(SHOP_CHECKOUT_KEY)).toBe(false);
  expect(toast.error).toHaveBeenCalledWith('This synthetic practice payment was declined. Your cart is unchanged.');
});

test('missing parent storage acknowledgement blocks confirmation after preparation', async () => {
  flushReject = true; await reachReview(); await click('Place order'); await act(async () => { await jest.advanceTimersByTimeAsync(700); });
  expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/checkout/prepare'))).toBe(true);
  expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/checkout/confirm'))).toBe(false);
  expect(toast.error).toHaveBeenCalledWith('parent acknowledgement unavailable');
});

test('lost confirmation response retains the exact pending proposal and remount recovery is GET-only', async () => {
  confirmMode = 'lost'; await reachReview(); await click('Place order'); await settle(); await click('Confirm exact quote'); await act(async () => { await jest.advanceTimersByTimeAsync(700); });
  expect(JSON.parse(persisted.get(SHOP_CHECKOUT_KEY))).toEqual({ operationId: proposalId, intentDigest: quoteSha256, scopeKey });
  expect(button('Confirm exact quote').disabled).toBe(true);
  await click('Confirm exact quote');
  expect(calls.filter(([url]) => String(url).endsWith('/checkout/confirm'))).toHaveLength(1);
  const before = calls.length; await act(async () => root.unmount()); root = createRoot(node);
  await act(async () => root.render(<MemoryRouter><Checkout /></MemoryRouter>)); await settle(); await click('Check saved order'); await settle();
  expect(calls.slice(before).every(([, method]) => method === 'GET')).toBe(true);
  expect(calls.slice(before).some(([url]) => String(url).includes(`/customer/commerce/operations/${proposalId}`))).toBe(true);
});

test('an old bound checkout reference falls back only to its exact legacy receipt GET', async () => {
  legacyReference = true;
  persisted.set(SHOP_CHECKOUT_KEY, JSON.stringify({ operationId: proposalId, intentDigest: quoteSha256, scopeKey }));
  await act(async () => root.unmount()); root = createRoot(node);
  await act(async () => root.render(<MemoryRouter><Checkout /></MemoryRouter>)); await settle(); await click('Check saved order'); await settle();
  expect(calls.some(([url]) => String(url).includes(`/customer/commerce/operations/${proposalId}`))).toBe(true);
  expect(calls.some(([url]) => String(url).includes(`/orders/operations/${proposalId}`))).toBe(true);
  expect(calls.filter(([, method]) => method === 'POST')).toHaveLength(0);
  expect(toast.error).not.toHaveBeenCalled();
  expect(persisted.has(SHOP_CHECKOUT_KEY)).toBe(false);
});

test.each(['declined', 'stale'])('saved completed %s receipt clears the reference without confirmation replay', async status => {
  confirmMode = status; confirmDispatched = true;
  persisted.set(SHOP_CHECKOUT_KEY, JSON.stringify({ operationId: proposalId, intentDigest: quoteSha256, scopeKey }));
  await act(async () => root.unmount()); root = createRoot(node);
  await act(async () => root.render(<MemoryRouter><Checkout /></MemoryRouter>)); await settle(); await click('Check saved order');
  expect(calls.filter(([, method]) => method === 'POST')).toHaveLength(0);
  expect(persisted.has(SHOP_CHECKOUT_KEY)).toBe(false);
  expect(toast.error).toHaveBeenCalledWith(status === 'declined'
    ? 'This synthetic practice payment was declined. Your cart is unchanged.'
    : 'This checkout quote is stale. Request a fresh quote before trying again.');
});

test('bare operation 404 retains uncertainty and never falls back to a legacy receipt', async () => {
  operationHttp404 = true;
  persisted.set(SHOP_CHECKOUT_KEY, JSON.stringify({ operationId: proposalId, intentDigest: quoteSha256, scopeKey }));
  await act(async () => root.unmount()); root = createRoot(node);
  await act(async () => root.render(<MemoryRouter><Checkout /></MemoryRouter>)); await settle(); await click('Check saved order'); await settle();
  expect(calls.some(([url]) => String(url).includes(`/orders/operations/${proposalId}`))).toBe(false);
  expect(persisted.has(SHOP_CHECKOUT_KEY)).toBe(true);
  expect(toast.error).toHaveBeenCalledWith('Checkout outcome is not confirmed. Your saved reference is retained.');
});

test('malformed completed terminal receipt cannot clear its saved reference', async () => {
  confirmMode = 'declined'; malformedReceipt = true; confirmDispatched = true;
  persisted.set(SHOP_CHECKOUT_KEY, JSON.stringify({ operationId: proposalId, intentDigest: quoteSha256, scopeKey }));
  await act(async () => root.unmount()); root = createRoot(node);
  await act(async () => root.render(<MemoryRouter><Checkout /></MemoryRouter>)); await settle(); await click('Check saved order'); await settle();
  expect(persisted.has(SHOP_CHECKOUT_KEY)).toBe(true);
  expect(toast.error).toHaveBeenCalledWith('Checkout outcome is not confirmed. Your saved reference is retained.');
});


test('existing address A never substitutes for distinct typed delivery B', async () => {
  await set('Address', '99 Other St'); await set('City', 'Town'); await set('State', 'CA'); await set('ZIP', '90210');
  await submit(); await settle();
  expect(node.querySelector('section[aria-label="Address setup"]')).not.toBeNull();
  expect(node.querySelector('input[aria-label="Street address"]').value).toBe('99 Other St');
  expect(node.querySelector('section[aria-label="Practice payment setup"]')).toBeNull();
  expect(calls.filter(([, method]) => method === 'POST')).toHaveLength(0);
});

test('matching typed delivery B selects its protected choice, not first saved address A', async () => {
  const other = { ...address, choiceId: '123e4567-e89b-42d3-a456-426614174009', title: 'Other home', detail: '99 Other St' };
  addressCards = [address, other];
  await set('Address', other.detail); await set('City', 'Town'); await set('State', 'CA'); await set('ZIP', '90210');
  await submit(); await settle();
  expect(node.querySelector('input[name="practice-address"]:checked').value).toBe(other.choiceId);
  await submit(); await settle();
  expect(node.textContent).toContain(other.detail);
  await click('Place order'); await settle();
  const prepare = fetchMock.mock.calls.find(([url]) => url.endsWith('/checkout/prepare'));
  expect(JSON.parse(prepare[1].body).addressChoiceId).toBe(other.choiceId);
  expect(calls.filter(([url]) => url.endsWith('/checkout/confirm'))).toHaveLength(0);
});

test('a removed selected address cannot silently fall back on refresh or bypass the review button', async () => {
  await set('Address', '1 Main St'); await set('City', 'Town'); await set('State', 'CA'); await set('ZIP', '90210');
  await submit(); await settle();
  addressCards = [{ ...address, choiceId: '123e4567-e89b-42d3-a456-426614174009', detail: '99 Other St' }];
  await click('Use approved practice payment'); await click('Create selected practice payment'); await settle();
  expect(node.querySelector('input[name="practice-address"]:checked')).toBeNull();
  expect(button('Review order').disabled).toBe(true);
  await submit(); await settle();
  expect(button('Place order')).toBeUndefined();
  expect(calls.filter(([url]) => url.endsWith('/checkout/prepare'))).toHaveLength(0);
  await act(async () => node.querySelector('input[name="practice-address"]').click());
  expect(button('Review order').disabled).toBe(false);
});


test('shipping changed during a saved-address read cannot advance using the prior typed address', async () => {
  await set('Address', '1 Main St'); await set('City', 'Town'); await set('State', 'CA'); await set('ZIP', '90210');
  const original = fetchMock.getMockImplementation();
  let release;
  fetchMock.mockImplementationOnce((url, options) => new Promise(resolve => {
    release = async () => resolve(await original(url, options));
  }));
  await submit();
  await set('Address', '99 Other St');
  await act(async () => release()); await settle();
  expect(input('Address').value).toBe('99 Other St');
  expect(node.querySelector('section[aria-label="Practice payment setup"]')).toBeNull();
  expect(calls.filter(([, method]) => method === 'POST')).toHaveLength(0);
});
