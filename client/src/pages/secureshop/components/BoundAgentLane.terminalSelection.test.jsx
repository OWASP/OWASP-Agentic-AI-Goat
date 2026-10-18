import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import AgentLane from './AgentLane.jsx';
import { useAgentStream } from '../hooks/useAgentStream.js';
import { useAuth } from '../context/AuthContext.jsx';

jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => ({ boundReviews: true }) }));
jest.mock('../context/AuthContext.jsx', () => ({ useAuth: jest.fn() }));
jest.mock('../hooks/useAgentStream.js', () => ({ useAgentStream: jest.fn() }));
jest.mock('../hooks/useProductQuestion.js', () => ({ useProductQuestion: () => ({
  turns: [], status: 'idle', validProduct: true, error: null, send: jest.fn(),
}) }));
jest.mock('../hooks/useCustomerIdorLesson.js', () => ({ useCustomerIdorLesson: () => ({
  cards: null, mode: null, loading: false, busy: false, error: null, reference: null,
  status: 'idle', savedResult: null, savedText: null, assessment: null,
  prepare: jest.fn(), loadCards: jest.fn(), select: jest.fn(), recover: jest.fn(),
  readAssessment: jest.fn(), retryAssessment: jest.fn(), clearCompleted: jest.fn(),
}) }));
jest.mock('../hooks/useCustomerCouponConfirmation.js', () => ({ useCustomerCouponConfirmation: () => ({
  reference: null, status: 'idle', result: null, assessment: null, busy: false, error: null,
  confirm: jest.fn(), check: jest.fn(), readAssessment: jest.fn(), retryAssessment: jest.fn(), clearCompleted: jest.fn(),
}) }));
jest.mock('../hooks/useCustomerTicketConfirmation.js', () => ({ useCustomerTicketConfirmation: () => ({
  reference: null, status: 'idle', result: null, busy: false, error: null,
  confirm: jest.fn(), check: jest.fn(), clearCompleted: jest.fn(),
}) }));
jest.mock('../hooks/useSearchEchoAssessment.js', () => ({ useSearchEchoAssessment: () => ({
  reference: null, outcome: null, busy: false, accessLost: false, start: jest.fn(), check: jest.fn(),
}) }));
jest.mock('../pages/merchant/useBoundAnalytics.js', () => ({ __esModule: true, default: () => ({ ready: true, references: [] }) }));
jest.mock('../pages/merchant/useBoundPricing.js', () => ({ useBoundPricing: () => ({ locked: false, busy: false, references: [] }) }));
jest.mock('../pages/merchant/useBoundListings.js', () => ({ useBoundListings: () => ({ ready: true, busy: false, references: {} }) }));
jest.mock('../pages/merchant/InventoryPanel.jsx', () => () => null);
jest.mock('./BoundRoleAssistant.jsx', () => () => null);
jest.mock('./CustomerCheckoutCard.jsx', () => ({ proposal }) => proposal ? <div data-testid="checkout-proposal" /> : null);
jest.mock('./PracticePaymentSetup.jsx', () => ({ setup }) => setup ? <div data-testid="practice-payment-handoff" /> : null);
jest.mock('./PracticeAddressSetup.jsx', () => ({ setup }) => setup ? <div data-testid="practice-address-handoff" /> : null);

const originalFetch = globalThis.fetch;
let root;
let node;

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  useAuth.mockReturnValue({ user: { id: 5, role: 'customer' }, token: 'shop-token' });
  globalThis.fetch = jest.fn(async () => ({ ok: true, json: async () => ({ products: [] }) }));
  useAgentStream.mockReturnValue({
    sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', turns: [{
      sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      user: 'Find a laptop', reply: 'The result is incomplete.', status: 'done', stopReason: 'tool_limit',
      hops: [], operations: [],
      modeCapability: { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
        effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } },
      cards: [{ version: 1, kind: 'product', choiceId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        title: 'Practice laptop', detail: 'Current catalog result' }],
    }],
    status: 'idle', error: null, pending: null, send: jest.fn().mockResolvedValue(true),
    recover: jest.fn(), stopWatching: jest.fn(), canStopWatching: false,
  });
  node = document.createElement('div');
  document.body.append(node);
  root = createRoot(node);
});

afterEach(async () => {
  await act(async () => root.unmount());
  node.remove();
  globalThis.fetch = originalFetch;
  jest.clearAllMocks();
});

const terminalMode = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };

function terminalLimitedChoice(card) {
  const state = {
    sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', turns: [{
      sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      user: 'Find a choice', reply: 'The result is incomplete.', status: 'done', stopReason: 'tool_limit',
      hops: [], operations: [], modeCapability: terminalMode, cards: [card],
    }],
    status: 'idle', error: null, pending: null, send: jest.fn().mockResolvedValue(true),
    recover: jest.fn(), stopWatching: jest.fn(), canStopWatching: false,
  };
  useAgentStream.mockReturnValue(state);
  return state;
}

test.each([
  [{ version: 1, kind: 'product', choiceId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    title: 'Practice laptop', detail: 'Current catalog result' },
  ['View details: Practice laptop', 'Add to cart: Practice laptop']],
  [{ version: 1, kind: 'order', choiceId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    title: 'Order #42', detail: 'Delivered' },
  ['View details: Order #42', 'Choose order: Order #42']],
  [{ version: 1, kind: 'address', choiceId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    title: 'Home', detail: '1 Main Street' },
  ['Use for checkout: Home', 'Edit address: Home']],
])('does not offer a selection action from a terminal-limited customer turn', async (card, labels) => {
  terminalLimitedChoice(card);
  await act(async () => root.render(<MemoryRouter><AgentLane role="customer" instance="terminal-selection" /></MemoryRouter>));
  const task = node.querySelector('select');
  await act(async () => {
    task.value = 'chat';
    task.dispatchEvent(new Event('change', { bubbles: true }));
  });

  for (const label of labels) expect(node.querySelector(`[aria-label="${label}"]`)?.disabled).toBe(true);
});

test('does not expose setup, confirmation, or detail surfaces from a terminal-limited customer turn', async () => {
  const choiceId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const card = { version: 1, kind: 'product', choiceId, title: 'Practice laptop', detail: 'Current catalog result' };
  const current = terminalLimitedChoice(card);
  current.turns[0] = {
    ...current.turns[0],
    paymentSetup: { version: 1, kind: 'practice_payment_setup', suggestedScenario: 'approved' },
    addressSetup: { version: 1, kind: 'address_setup', action: 'create', choiceId: null, draft: { line1: '1 Main Street' } },
    operations: [{ status: 'prepared', proposal: { proposalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' } }],
    hops: [{ tool: 'catalog.details', status: 'ok', error: null, params: { choiceId }, modeCapability: terminalMode,
      result: { content: [{ type: 'text', text: JSON.stringify({ cards: [card], product: {
        name: 'Practice laptop', description: 'Current catalog result', price: 49, stock_quantity: 3,
      } }) }] } }],
  };
  useAgentStream.mockReturnValue(current);
  await act(async () => root.render(<MemoryRouter><AgentLane role="customer" instance="terminal-derived" /></MemoryRouter>));
  const task = node.querySelector('select');
  await act(async () => { task.value = 'chat'; task.dispatchEvent(new Event('change', { bubbles: true })); });

  expect(node.querySelector('[data-testid="checkout-proposal"]')).toBeNull();
  expect(node.querySelector('[data-testid="practice-payment-handoff"]')).toBeNull();
  expect(node.querySelector('[data-testid="practice-address-handoff"]')).toBeNull();
  expect(node.querySelector('[aria-label="Selected product details"]')).toBeNull();
});
