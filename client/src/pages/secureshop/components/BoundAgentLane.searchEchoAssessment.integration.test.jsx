import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import BoundAgentLane from './BoundAgentLane.jsx';
import { createBridgeFetch } from '../bridge/fetchAdapter.mjs';
import { useAuth } from '../context/AuthContext.jsx';
import { useAgentStream } from '../hooks/useAgentStream.js';
import { useProductQuestion } from '../hooks/useProductQuestion.js';
import { useCustomerCouponConfirmation } from '../hooks/useCustomerCouponConfirmation.js';
import { useCustomerTicketConfirmation } from '../hooks/useCustomerTicketConfirmation.js';
import { useCart } from '../context/CartContext.jsx';
import { SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY } from '../utils/shopStorage.mjs';

jest.mock('../context/AuthContext.jsx', () => ({ useAuth: jest.fn() }));
jest.mock('../context/CartContext.jsx', () => ({ useCart: jest.fn() }));
jest.mock('../hooks/useAgentStream.js', () => ({ useAgentStream: jest.fn() }));
jest.mock('../hooks/useProductQuestion.js', () => ({ useProductQuestion: jest.fn() }));
jest.mock('../hooks/useCustomerCouponConfirmation.js', () => ({ useCustomerCouponConfirmation: jest.fn() }));
jest.mock('../hooks/useCustomerTicketConfirmation.js', () => ({ useCustomerTicketConfirmation: jest.fn() }));
jest.mock('./BoundProductPicker.jsx', () => () => <div data-testid="unrelated-product-picker" />);

const historical = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', step: 2 };
const current = { sessionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
const modeCapability = { version: 1, featureId: 'customer_chat',
  policyVersion: 'owned-catalog-and-cart-read-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'customer_chat' } };
const reply = value => ({ ok: true, status: 200,
  headers: { get: () => 'application/json' }, json: async () => value });
const streamWeb = require('node:stream/web');
const restoreDescriptor = (key, descriptor) => {
  if (descriptor) Object.defineProperty(globalThis, key, descriptor);
  else delete globalThis[key];
};

let root, node, globalDescriptors;

beforeEach(() => {
  globalDescriptors = new Map([...new Set([...Object.keys(streamWeb), 'MessagePort',
    'IS_REACT_ACT_ENVIRONMENT', 'fetch', 'Request', 'Headers'])].map(key =>
    [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.removeItem(SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY);
  useAuth.mockReturnValue({ user: { id: 7, role: 'customer' }, token: 'owned-token' });
  useCart.mockReturnValue({ reload: jest.fn() });
  useProductQuestion.mockReturnValue({ turns: [], validProduct: false, status: 'idle',
    error: null, send: jest.fn() });
  useCustomerCouponConfirmation.mockReturnValue({ reference: null, status: 'idle', result: null,
    assessment: null, busy: false, error: null, confirm: jest.fn(), check: jest.fn(),
    readAssessment: jest.fn(), retryAssessment: jest.fn(), clearCompleted: jest.fn() });
  useCustomerTicketConfirmation.mockReturnValue({ reference: null, status: 'idle', result: null,
    busy: false, error: null, confirm: jest.fn(), check: jest.fn(), clearCompleted: jest.fn() });
  useAgentStream.mockReturnValue({
    turns: [
      { user: 'Find notebooks', reply: 'Here are notebooks.', status: 'done', stopReason: 'end_turn',
        ...historical, modeCapability, cards: [], operations: [], hops: [
          { id: 'cart', tool: 'cart.view', status: 'ok', step: 1, params: {}, result: null },
          { id: 'search', tool: 'catalog.search', status: 'ok', step: historical.step,
            params: { search: 'notebooks' }, result: null },
        ] },
      { user: 'Show my cart', reply: 'Your cart is empty.', status: 'done', stopReason: 'end_turn',
        ...current, modeCapability, cards: [], operations: [], hops: [] },
    ], status: 'idle', error: null, pending: null, send: jest.fn(), recover: jest.fn(),
  });
  Object.assign(globalThis, streamWeb);
  globalThis.MessagePort = require('node:worker_threads').MessagePort;
  const web = require('undici');
  globalThis.Request = web.Request; globalThis.Headers = web.Headers;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
});

afterEach(async () => {
  if (root) await act(async () => root.unmount());
  node?.remove();
  for (const [key, descriptor] of globalDescriptors) restoreDescriptor(key, descriptor);
  localStorage.removeItem(SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY);
});

test('historical rendered search persists its selected IDs before the closed assessment POST and saved GET', async () => {
  const calls = [];
  const bridge = { request: jest.fn(async (name, input, options) => {
    calls.push({ name, input, saved: localStorage.getItem(SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY), options });
    return reply({ completed: false, status: 'unconfirmed', modelEvaluated: false });
  }) };
  globalThis.fetch = createBridgeFetch({ bridge, origin: 'https://shop.invalid',
    getRequestBaseUrl: () => 'https://shop.invalid', getToken: () => 'owned-token' });
  await act(async () => root.render(<MemoryRouter><BoundAgentLane role="customer" productId={7}
    instance="search-echo-integration" /></MemoryRouter>));
  const task = node.querySelector('select');
  await act(async () => { task.value = 'chat'; task.dispatchEvent(new Event('change', { bubbles: true })); });
  const oldTurn = node.querySelectorAll('[data-testid="agent-turn"]')[0];
  const search = oldTurn.querySelector('[aria-label^="Step 2: catalog.search"]');
  expect(search).not.toBeNull();
  await act(async () => search.click());
  const check = [...node.querySelectorAll('button')].find(button => button.textContent === 'Check search echo');
  expect(check).toBeDefined();
  await act(async () => { check.click(); await new Promise(resolve => setTimeout(resolve, 0)); });

  expect(calls.map(call => call.name)).toEqual([
    'agent.customer.searchEchoAssess', 'agent.customer.searchEchoAssessment',
  ]);
  expect(calls[0].input).toEqual({ body: historical, params: {}, query: {} });
  expect(calls[1].input).toEqual({ body: undefined,
    params: { ...historical, step: String(historical.step) }, query: {} });
  expect(JSON.parse(calls[0].saved)).toMatchObject({ ...historical, shopUserId: 7 });
  expect(calls.some(call => JSON.stringify(call.input).includes(current.sessionId)
    || JSON.stringify(call.input).includes(current.requestId))).toBe(false);
  expect(calls.every(call => Object.values(call.input).every(value => !Object.hasOwn(value, 'echoHtml')))).toBe(true);
  expect(node.textContent).toContain('Saved assessment: unconfirmed');
});
