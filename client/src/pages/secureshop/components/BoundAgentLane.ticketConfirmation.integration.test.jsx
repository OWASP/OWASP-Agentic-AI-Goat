import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { webcrypto } from 'node:crypto';
import BoundAgentLane from './BoundAgentLane.jsx';
import { createBridgeFetch } from '../bridge/fetchAdapter.mjs';
import { useAuth } from '../context/AuthContext.jsx';
import { useAgentStream } from '../hooks/useAgentStream.js';
import { useProductQuestion } from '../hooks/useProductQuestion.js';
import { useCustomerCouponConfirmation } from '../hooks/useCustomerCouponConfirmation.js';
import { useSearchEchoAssessment } from '../hooks/useSearchEchoAssessment.js';
import { useCart } from '../context/CartContext.jsx';
import { SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY } from '../utils/shopStorage.mjs';

jest.mock('../context/AuthContext.jsx', () => ({ useAuth: jest.fn() }));
jest.mock('../context/CartContext.jsx', () => ({ useCart: jest.fn() }));
jest.mock('../hooks/useAgentStream.js', () => ({ useAgentStream: jest.fn() }));
jest.mock('../hooks/useProductQuestion.js', () => ({ useProductQuestion: jest.fn() }));
jest.mock('../hooks/useCustomerCouponConfirmation.js', () => ({ useCustomerCouponConfirmation: jest.fn() }));
jest.mock('../hooks/useSearchEchoAssessment.js', () => ({ useSearchEchoAssessment: jest.fn() }));
jest.mock('./BoundProductPicker.jsx', () => () => <div data-testid="unrelated-product-picker" />);

const source = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
const prior = { sessionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
const proposalId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
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
const digest = async value => [...new Uint8Array(await webcrypto.subtle.digest('SHA-256',
  new TextEncoder().encode(value)))].map(byte => byte.toString(16).padStart(2, '0')).join('');

let root, node, globalDescriptors, proposal, result;

beforeEach(async () => {
  globalDescriptors = new Map([...new Set([...Object.keys(streamWeb), 'MessagePort',
    'IS_REACT_ACT_ENVIRONMENT', 'crypto', 'fetch', 'Request', 'Headers'])].map(key =>
    [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  localStorage.removeItem(SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY);
  proposal = { version: 1, kind: 'support.ticket_prepare', status: 'confirmation_required',
    proposalId, subject: 'Delivery question', body: '<b>Raw customer text</b>',
    subjectSha256: await digest('Delivery question'), bodySha256: await digest('<b>Raw customer text</b>') };
  result = { version: 1, kind: 'support_ticket', ticketId: '42', operationId: proposalId,
    requestId: source.requestId, runId: 'ffffffff-ffff-4fff-8fff-ffffffffffff', proposalId,
    status: 'open', subjectSha256: proposal.subjectSha256, bodySha256: proposal.bodySha256,
    receiptSha256: 'a'.repeat(64) };
  useAuth.mockReturnValue({ user: { id: 7, role: 'customer' }, token: 'owned-token' });
  useCart.mockReturnValue({ reload: jest.fn() });
  useProductQuestion.mockReturnValue({ turns: [], validProduct: false, status: 'idle', error: null, send: jest.fn() });
  useCustomerCouponConfirmation.mockReturnValue({ reference: null, status: 'idle', result: null,
    assessment: null, busy: false, error: null, confirm: jest.fn(), check: jest.fn(),
    readAssessment: jest.fn(), retryAssessment: jest.fn(), clearCompleted: jest.fn() });
  useSearchEchoAssessment.mockReturnValue({ reference: null, outcome: null, busy: false,
    accessLost: false, start: jest.fn(), check: jest.fn(), retryUnconfirmed: jest.fn(), clearCompleted: jest.fn() });
  useAgentStream.mockReturnValue({ turns: [
    { user: 'Show my cart', reply: 'Your cart is empty.', status: 'done', stopReason: 'end_turn',
      ...prior, modeCapability, cards: [], operations: [], hops: [] },
    { user: 'Open a support ticket', reply: 'I prepared a ticket.', status: 'done', stopReason: 'end_turn',
      ...source, modeCapability, ticketProposal: proposal, cards: [], operations: [], hops: [] },
  ], status: 'idle', error: null, pending: null, send: jest.fn(), recover: jest.fn() });
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
  localStorage.removeItem(SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY);
});

const waitFor = async assertion => {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try { assertion(); return; } catch (error) {
      if (attempt === 49) throw error;
      await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
    }
  }
};

test('rendered ticket confirmation persists the latest turn IDs before closed bridge POST and saved GET', async () => {
  const calls = [];
  const bridge = { request: jest.fn(async (name, input, options) => {
    calls.push({ name, input, saved: localStorage.getItem(SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY), options });
    if (name === 'agent.customer.operation') return reply({ ...source, status: 'completed', replayed: true,
      stopReason: 'end_turn', ticketProposal: proposal });
    if (name === 'agent.customer.ticket.confirm') return reply({ accepted: true });
    if (name === 'agent.customer.ticket.saved') return reply({ status: 'completed', result });
    throw Error(`Unexpected bridge operation ${name}`);
  }) };
  globalThis.fetch = createBridgeFetch({ bridge, origin: 'https://shop.invalid',
    getRequestBaseUrl: () => 'https://shop.invalid', getToken: () => 'owned-token' });
  await act(async () => root.render(<MemoryRouter><BoundAgentLane role="customer" productId={7}
    instance="ticket-confirmation-integration" /></MemoryRouter>));
  const task = node.querySelector('select');
  await act(async () => { task.value = 'chat'; task.dispatchEvent(new Event('change', { bubbles: true })); });
  const confirm = [...node.querySelectorAll('button')].find(button => button.textContent === 'Open support ticket');
  expect(confirm).toBeDefined();
  await act(async () => confirm.click());
  await waitFor(() => expect(node.textContent).toContain('Ticket #42 is open.'));

  expect(calls.map(call => call.name)).toEqual([
    'agent.customer.operation', 'agent.customer.ticket.confirm', 'agent.customer.ticket.saved',
  ]);
  expect(calls[0].input).toEqual({ body: undefined, params: source, query: {} });
  expect(calls[1].input).toEqual({ body: { ...source, proposalId }, params: {}, query: {} });
  expect(calls[2].input).toEqual({ body: undefined, params: { ...source, proposalId }, query: {} });
  expect(JSON.parse(calls[1].saved)).toMatchObject({ ...source, proposalId, shopUserId: 7 });
  expect(calls.some(call => JSON.stringify(call.input).includes(prior.sessionId)
    || JSON.stringify(call.input).includes(prior.requestId)
    || JSON.stringify(call.input).includes(proposal.subject)
    || JSON.stringify(call.input).includes(proposal.body))).toBe(false);
});
