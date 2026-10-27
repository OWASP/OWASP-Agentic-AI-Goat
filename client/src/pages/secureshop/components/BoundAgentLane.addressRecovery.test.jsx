import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import BoundAgentLane from './BoundAgentLane.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { attachShopStorage, SHOP_ADDRESS_SETUP_KEY, SHOP_CUSTOMER_CHAT_COMPLETED_KEY } from '../utils/shopStorage.mjs';

jest.mock('../context/AuthContext.jsx', () => ({ useAuth: jest.fn() }));

const operationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const sessionId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const sha = 'd'.repeat(64);
const saved = { version: 1, scopeKey: 'e'.repeat(64), operationId, action: 'create', choiceId: null,
  expectedSnapshotSha256: null, defaultSetSha256: sha, fieldsSha256: sha };
const json = value => ({ ok: true, status: 200,
  headers: { get: name => name.toLowerCase() === 'content-type' ? 'application/json' : null }, json: async () => value });
const completed = () => json({ scopeKey: saved.scopeKey, operationId, status: 'completed',
  receipt: { version: 1, operationId, kind: 'address.create', status: 'completed', replayed: true,
    result: { addressId: 14, fieldsSha256: sha, addressSnapshotSha256: sha, defaultSetSha256: sha } } });
const history = () => json({ sessionId, requestId, status: 'completed', text: 'Saved conversation',
  stopReason: 'end_turn', replayed: true, hops: [], cards: [], operations: [], orderPage: null,
  modeCapability: { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } } });
const originalFetch = globalThis.fetch;
let node, root, values, detach, releaseHistory, addressSignals, holdFirstAddress;
const button = () => [...node.querySelectorAll('button')].find(item => item.textContent === 'Check saved address');

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  useAuth.mockReturnValue({ user: { id: 5, role: 'customer' }, token: 'same-owner-token' });
  values = new Map([[SHOP_ADDRESS_SETUP_KEY, JSON.stringify(saved)],
    [SHOP_CUSTOMER_CHAT_COMPLETED_KEY, JSON.stringify({ version: 1, references: [
      { shopUserId: 5, sessionId, requestId, startedAt: 1 }] })]]);
  detach = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key), flush: async () => {} });
  addressSignals = [];
  releaseHistory = undefined; holdFirstAddress = true;
  globalThis.fetch = jest.fn((url, options = {}) => {
    if (url === '/api/secureshop/products?limit=8&offset=0') return Promise.resolve(json({ products: [] }));
    if (url === `/api/secureshop/agents/customer/operations/${sessionId}/${requestId}`) {
      return new Promise(resolve => { releaseHistory = () => resolve(history()); });
    }
    if (url === `/api/secureshop/customer/commerce/operations/${operationId}`) {
      expect(options.method).toBe('GET'); addressSignals.push(options.signal);
      if (!holdFirstAddress || addressSignals.length > 1) return Promise.resolve(completed());
      return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => {
        const error = new Error('Controlled cancellation'); error.name = 'AbortError'; reject(error);
      }, { once: true }));
    }
    if (url === '/api/secureshop/customer/commerce/addresses') return Promise.resolve(json({ cards: [] }));
    throw Error(`Unexpected controlled transport: ${url}`);
  });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
});
afterEach(async () => {
  await act(async () => root.unmount()); node.remove(); detach(); globalThis.fetch = originalFetch;
});
async function mount() {
  await act(async () => root.render(<MemoryRouter><BoundAgentLane role="customer" /></MemoryRouter>));
  await act(async () => { const select = node.querySelector('select'); select.value = 'chat';
    select.dispatchEvent(new Event('change', { bubbles: true })); });
  expect(typeof releaseHistory).toBe('function');
}

test('same-owner history restoration blocks recovery until the final address authority is mounted', async () => {
  await mount();
  const before = button(); expect(before.disabled).toBe(true);
  await act(async () => before.click());
  expect(addressSignals).toHaveLength(0);
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(true);
  expect(node.textContent).toContain('Wait for the current conversation');
  await act(async () => releaseHistory());
  expect(button()).not.toBe(before);
  expect(button().disabled).toBe(false);
  expect(addressSignals).toHaveLength(0);
  expect(node.textContent).toContain('An address change is saved. Check its exact outcome before another save.');
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(true);
  holdFirstAddress = false;
  await act(async () => button().click());
  expect(addressSignals).toHaveLength(1);
  expect(addressSignals[0].aborted).toBe(false);
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(false);
  expect(node.textContent).toContain('Address saved.');
  expect(globalThis.fetch.mock.calls.every(([, options]) => !options?.method || options.method === 'GET')).toBe(true);
});

test('saved address recovery is blocked while same-owner completed chat restoration is pending', async () => {
  await mount();
  expect(button().disabled).toBe(true);
});

test('without saved chat, normal saved address recovery remains available and performs one exact GET', async () => {
  values.delete(SHOP_CUSTOMER_CHAT_COMPLETED_KEY); holdFirstAddress = false;
  await act(async () => root.render(<MemoryRouter><BoundAgentLane role="customer" /></MemoryRouter>));
  await act(async () => { const select = node.querySelector('select'); select.value = 'chat';
    select.dispatchEvent(new Event('change', { bubbles: true })); });
  expect(releaseHistory).toBeUndefined(); expect(button().disabled).toBe(false);
  await act(async () => button().click());
  expect(addressSignals).toHaveLength(1); expect(addressSignals[0].aborted).toBe(false);
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(false);
  expect(node.textContent).toContain('Address saved.');
  expect(globalThis.fetch.mock.calls.every(([, options]) => !options?.method || options.method === 'GET')).toBe(true);
});

test('a real owner token change still aborts active recovery without clearing its saved reference', async () => {
  values.delete(SHOP_CUSTOMER_CHAT_COMPLETED_KEY);
  await act(async () => root.render(<MemoryRouter><BoundAgentLane role="customer" /></MemoryRouter>));
  await act(async () => button().click());
  expect(addressSignals).toHaveLength(1); expect(addressSignals[0].aborted).toBe(false);
  useAuth.mockReturnValue({ user: { id: 5, role: 'customer' }, token: 'renewed-owner-token' });
  await act(async () => root.render(<MemoryRouter><BoundAgentLane role="customer" /></MemoryRouter>));
  expect(addressSignals[0].aborted).toBe(true);
  expect(JSON.parse(values.get(SHOP_ADDRESS_SETUP_KEY))).toEqual(saved);
  expect(addressSignals).toHaveLength(1);
});
