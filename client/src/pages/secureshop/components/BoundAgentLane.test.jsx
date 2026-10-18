import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import AgentLane from './AgentLane.jsx';
import { useProductQuestion } from '../hooks/useProductQuestion.js';
import { useAgentStream } from '../hooks/useAgentStream.js';
import { useCustomerIdorLesson } from '../hooks/useCustomerIdorLesson.js';
import { useCustomerProductSearchLesson } from '../hooks/useCustomerProductSearchLesson.js';
import { useCustomerOrderStatusLesson } from '../hooks/useCustomerOrderStatusLesson.js';
import { useCustomerCouponConfirmation } from '../hooks/useCustomerCouponConfirmation.js';
import { useCustomerTicketConfirmation } from '../hooks/useCustomerTicketConfirmation.js';
import { useSearchEchoAssessment } from '../hooks/useSearchEchoAssessment.js';
import { useAuth } from '../context/AuthContext.jsx';
import useBoundAnalytics from '../pages/merchant/useBoundAnalytics.js';
import { useBoundPricing } from '../pages/merchant/useBoundPricing.js';
import { useBoundListings } from '../pages/merchant/useBoundListings.js';

jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => ({ boundReviews: true }) }));
jest.mock('../context/AuthContext.jsx', () => ({ useAuth: jest.fn() }));
jest.mock('../hooks/useProductQuestion.js', () => ({ useProductQuestion: jest.fn() }));
jest.mock('../hooks/useAgentStream.js', () => ({ useAgentStream: jest.fn() }));
jest.mock('../hooks/useCustomerIdorLesson.js', () => ({ useCustomerIdorLesson: jest.fn() }));
jest.mock('../hooks/useCustomerProductSearchLesson.js', () => ({ useCustomerProductSearchLesson: jest.fn() }));
jest.mock('../hooks/useCustomerOrderStatusLesson.js', () => ({ useCustomerOrderStatusLesson: jest.fn() }));
jest.mock('../hooks/useCustomerCouponConfirmation.js', () => ({ useCustomerCouponConfirmation: jest.fn() }));
jest.mock('../hooks/useCustomerTicketConfirmation.js', () => ({ useCustomerTicketConfirmation: jest.fn() }));
jest.mock('../hooks/useSearchEchoAssessment.js', () => ({ useSearchEchoAssessment: jest.fn() }));
jest.mock('../pages/merchant/useBoundAnalytics.js', () => ({ __esModule: true, default: jest.fn() }));
jest.mock('../pages/merchant/useBoundPricing.js', () => ({ useBoundPricing: jest.fn() }));
jest.mock('../pages/merchant/useBoundListings.js', () => ({ useBoundListings: jest.fn() }));
jest.mock('../pages/merchant/InventoryPanel.jsx', () => () => <div>Owned inventory assistant</div>);
jest.mock('./BoundRoleAssistant.jsx', () => ({ role, composerTarget }) => <>
  <div>{role} read-only assistant</div>
  {composerTarget && require('react-dom').createPortal(
    <form data-testid="role-assistant-test-composer">Role message</form>, composerTarget)}
</>);
jest.mock('./CustomerCheckoutCard.jsx', () => ({ proposal, onChooseAnotherPayment }) =>
  <div data-testid="checkout-proposal">{proposal?.proposalId || 'none'}
    {onChooseAnotherPayment && <button type="button" onClick={onChooseAnotherPayment}>Choose another payment method</button>}
  </div>);
jest.mock('./PracticePaymentSetup.jsx', () => ({ setup, entryPoint, authorityKey, onConfirmed }) =>
  <div data-testid="practice-payment-handoff" data-entry-point={entryPoint}
    data-authority-key={authorityKey} data-scenario={setup?.suggestedScenario || ''}>
    <button type="button" onClick={() => onConfirmed?.([])}>Simulate saved payment receipt</button>
  </div>);
jest.mock('./PracticeAddressSetup.jsx', () => ({ setup, entryPoint, authorityKey, onConfirmed }) =>
  <div data-testid="practice-address-handoff" data-entry-point={entryPoint}
    data-authority-key={authorityKey} data-action={setup?.action || ''}>
    <button type="button" onClick={() => onConfirmed?.()}>Simulate saved address receipt</button>
  </div>);
jest.mock('./PracticeProfileUpdate.jsx', () => ({ proposal, entryPoint, sourceSessionId, sourceRequestId }) =>
  <div data-testid="profile-review" data-entry-point={entryPoint}
    data-proposal-id={proposal?.proposalId || ''}
    data-session-id={sourceSessionId || ''} data-request-id={sourceRequestId || ''} />);

jest.mock('./CustomerFilePathSummaryLesson.jsx', () => ({ shopUserId, authorityKey, transport }) => <div data-testid="path-summary-card" data-owner={shopUserId} data-current-authority={authorityKey === 'shop-token' ? 'yes' : 'no'} data-current-transport={transport === globalThis.fetch ? 'yes' : 'no'} />);

const originalFetch = globalThis.fetch;
let root, node, question, stream, analytics, pricing, listings;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  useAuth.mockReturnValue({ user: { id: 5, role: 'customer' }, token: 'shop-token' });
  globalThis.fetch = jest.fn(async url => {
    if (url === '/api/secureshop/products/7') return { ok: true, json: async () => ({
      product: { id: 7, name: 'Practice laptop', price: 49, stock_quantity: 3 },
    }) };
    if (String(url).startsWith('/api/secureshop/products?')) return { ok: true, json: async () => ({
      products: [{ id: 7, name: 'Practice laptop', price: 49, stock_quantity: 3 }], total: 1,
    }) };
    if (url === '/api/secureshop/orders') return { ok: true, json: async () => ({
      orders: [{ id: 42, status: 'delivered', total_amount: 49, order_date: '2026-10-01T12:00:00.000Z' }],
    }) };
    if (String(url).startsWith('/api/secureshop/merchant/products?')) return { ok: true, json: async () => ({
      products: [{ id: 8, name: 'Merchant desk lamp', price: 24, stock_quantity: 5 }], total: 1,
    }) };
    throw new Error(`Unexpected customer read: ${url}`);
  });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  question = { turns: [], status: 'idle', validProduct: true, error: null, send: jest.fn().mockResolvedValue(true) };
  stream = { turns: [], status: 'idle', error: null, pending: null,
    send: jest.fn().mockResolvedValue(true), recover: jest.fn().mockResolvedValue(false) };
  analytics = { ready: true, references: [], scopeKey: 'scope', submit: jest.fn().mockResolvedValue({ status: 'completed', answer: 'Owned rows' }) };
  pricing = { locked: false, busy: false, references: [], run: jest.fn(), result: null, notice: '' };
  listings = { ready: true, busy: false, references: {}, run: jest.fn().mockResolvedValue({ state: 'completed', html: '<b>Draft</b>' }) };
  useProductQuestion.mockReturnValue(question); useAgentStream.mockReturnValue(stream);
  useCustomerIdorLesson.mockReturnValue({ cards: null, mode: null, loading: false,
    busy: false, error: null, reference: null, status: 'idle', savedResult: null,
    savedText: null, assessment: null, prepare: jest.fn(), loadCards: jest.fn(),
    select: jest.fn(), recover: jest.fn(), readAssessment: jest.fn(),
    retryAssessment: jest.fn(), clearCompleted: jest.fn() });
  useCustomerProductSearchLesson.mockReturnValue({ ready: true, reference: null, result: null,
    assessment: null, status: 'idle', error: null, busy: false, run: jest.fn(), recover: jest.fn(),
    assess: jest.fn(), recoverAssessment: jest.fn(), startNew: jest.fn() });
  useCustomerOrderStatusLesson.mockReturnValue({ ready: true, reference: null, result: null,
    assessment: null, status: 'idle', error: null, busy: false, run: jest.fn(), recover: jest.fn(),
    assess: jest.fn(), recoverAssessment: jest.fn(), startNew: jest.fn() });
  useCustomerCouponConfirmation.mockReturnValue({ reference: null, status: 'idle', result: null,
    assessment: null, busy: false, error: null, confirm: jest.fn(), check: jest.fn(),
    readAssessment: jest.fn(), retryAssessment: jest.fn(), clearCompleted: jest.fn() });
  useCustomerTicketConfirmation.mockReturnValue({ reference: null, status: 'idle', result: null,
    busy: false, error: null, confirm: jest.fn(), check: jest.fn(), clearCompleted: jest.fn() });
  useSearchEchoAssessment.mockReturnValue({ reference: null, outcome: null, busy: false,
    accessLost: false, start: jest.fn(), check: jest.fn() });
  useBoundAnalytics.mockReturnValue(analytics); useBoundPricing.mockReturnValue(pricing); useBoundListings.mockReturnValue(listings);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); globalThis.fetch = originalFetch; });
const render = async (role = 'customer', productId = 7) => act(async () => root.render(
  <MemoryRouter><AgentLane role={role} productId={productId} instance="test" /></MemoryRouter>));
const choose = async task => act(async () => {
  const selector = node.querySelector('select'); selector.value = task;
  selector.dispatchEvent(new Event('change', { bubbles: true }));
});
const fill = async (id, value) => act(async () => {
  const input = node.querySelector(`#${id}`);
  const type = input.tagName === 'TEXTAREA' ? HTMLTextAreaElement : HTMLInputElement;
  Object.getOwnPropertyDescriptor(type.prototype, 'value').set.call(input, value);
  input.dispatchEvent(new Event('input', { bubbles: true }));
});
const submit = async (formIndex = 0) => act(async () => [...node.querySelectorAll('form')]
  .filter(form => !form.closest('[hidden]'))[formIndex]
  .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));

test('product-search lesson renders UNION rows as inert text in the existing customer lane', async () => {
  const text = '<button data-testid="not-a-choice">Unsafe</button>';
  const row = Object.fromEntries(['id', 'name', 'description', 'price', 'category', 'sku',
    'stock_quantity', 'image_url', 'rating', 'created_at', 'updated_at'].map(key => [key, 'synthetic']));
  row.name = text;
  useCustomerProductSearchLesson.mockReturnValue({ ready: true,
    reference: { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }, status: 'completed',
    result: { text, searches: [{ query: 'practice search', count: 1, results: [row] }] },
    assessment: null, error: null, busy: false, run: jest.fn(), recover: jest.fn(),
    assess: jest.fn(), recoverAssessment: jest.fn(), startNew: jest.fn() });
  await render(); await choose('product-search-lesson');
  expect(node.querySelector('[aria-label="Product-search lesson result"]')?.textContent).toContain(text);
  expect(node.querySelector('[data-testid="not-a-choice"]')).toBeNull();
  expect(node.querySelector('[aria-label="Customer conversation"]')?.closest('[hidden]')).not.toBeNull();
  expect(node.querySelector('[aria-label="Product search lesson"] button[aria-label^="Add "]')).toBeNull();
});

test('unconfirmed product-search assessment remains manually assessable, evaluated result does not', async () => {
  const assess = jest.fn();
  const lesson = { ready: true, reference: { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }, status: 'completed',
  result: { text: 'Search complete', searches: [] }, assessment: { completed: false,
    status: 'unconfirmed', modelEvaluated: false }, error: null, busy: false,
  run: jest.fn(), recover: jest.fn(), assess, recoverAssessment: jest.fn(), startNew: jest.fn() };
  useCustomerProductSearchLesson.mockReturnValue(lesson);
  await render(); await choose('product-search-lesson');
  const button = () => [...node.querySelectorAll('[aria-label="Product search lesson"] button')]
    .find(value => value.textContent === 'Assess saved search');
  expect(button()?.disabled).toBe(false);
  await act(async () => button().click());
  expect(assess).toHaveBeenCalledTimes(1);
  lesson.assessment = { completed: false,
    judgment: { evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      verdict: 'fail', canRetry: false }, replayed: false };
  await render();
  expect(button()).toBeUndefined();
});

test('order-status query error renders as inert text and unconfirmed assessment remains assessable', async () => {
  const unsafe = '<button data-testid="unsafe-order">Refund</button>';
  const assess = jest.fn();
  const lesson = { ready: true, reference: { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }, status: 'completed',
  result: { text: unsafe, lookups: [{ order_id: '1', order: null, error: unsafe,
    sql: 'SELECT * FROM orders WHERE id=1' }] }, assessment: { completed: false,
    status: 'unconfirmed', modelEvaluated: false }, error: null, busy: false,
  run: jest.fn(), recover: jest.fn(), assess, recoverAssessment: jest.fn(), startNew: jest.fn() };
  useCustomerOrderStatusLesson.mockReturnValue(lesson);
  await render(); await choose('order-status-lesson');
  expect(node.querySelector('[aria-label="Order-status lesson result"]')?.textContent).toContain(unsafe);
  expect(node.querySelector('[data-testid="unsafe-order"]')).toBeNull();
  const button = () => [...node.querySelectorAll('[aria-label="Order status lesson"] button')]
    .find(value => value.textContent === 'Assess saved request');
  expect(button()?.disabled).toBe(false);
  await act(async () => button().click());
  expect(assess).toHaveBeenCalledTimes(1);
  lesson.assessment = { completed: false,
    judgment: { evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      verdict: 'fail', canRetry: false }, replayed: false };
  await render();
  expect(button()).toBeUndefined();
});

test('general chat mounts only the protected saved coupon proposal and exact confirmation action', async () => {
  const customerMode = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const proposal = { version: 1, kind: 'cart.coupon_prepare', status: 'confirmation_required',
    proposalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', code: 'SAVE10', codeSha256: 'a'.repeat(64) };
  const confirm = jest.fn();
  useCustomerCouponConfirmation.mockReturnValue({ reference: null, status: 'idle', result: null,
    assessment: null, busy: false, error: null, confirm, check: jest.fn(),
    readAssessment: jest.fn(), retryAssessment: jest.fn(), clearCompleted: jest.fn() });
  stream.turns = [{ requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    sessionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', user: 'Use coupon',
    status: 'done', stopReason: 'end_turn', modeCapability: customerMode,
    hops: [], cards: [], operations: [], couponProposal: proposal }];
  await render(); await choose('chat');
  expect(useCustomerCouponConfirmation).toHaveBeenCalledWith(expect.objectContaining({
    sourceRequestId: stream.turns[0].requestId, sourceSessionId: stream.turns[0].sessionId,
    proposal, authorityKey: 'shop-token', shopUserId: 5,
  }));
  expect(node.querySelector('[aria-label="Customer coupon confirmation"]')).not.toBeNull();
  await act(async () => node.querySelector('[aria-label="Customer coupon confirmation"] button').click());
  expect(confirm).toHaveBeenCalledWith();
  const clearCompleted = jest.fn();
  useCustomerCouponConfirmation.mockReturnValue({ reference: {
    sessionId: stream.turns[0].sessionId, requestId: stream.turns[0].requestId,
    proposalId: proposal.proposalId }, status: 'completed',
    result: { ok: false, error: 'coupon not found' }, busy: false, error: null,
    confirm, check: jest.fn(), readAssessment: jest.fn(), retryAssessment: jest.fn(), clearCompleted });
  await render();
  expect(node.textContent).not.toContain('Review newer coupon');
  stream.turns = [{ ...stream.turns[0], requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    couponProposal: { ...proposal, proposalId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' } }];
  await render();
  expect(node.textContent).toContain('Review newer coupon');
  await act(async () => [...node.querySelectorAll('[aria-label="Customer coupon confirmation"] button')]
    .find(button => button.textContent === 'Review newer coupon').click());
  expect(clearCompleted).toHaveBeenCalledTimes(1);
  stream.turns = [{ ...stream.turns[0], status: 'unresolved' }];
  await render();
  expect(useCustomerCouponConfirmation).toHaveBeenLastCalledWith(expect.objectContaining({ proposal: null }));
  expect(node.querySelector('[aria-label="Customer coupon confirmation"]')).not.toBeNull();
  expect(node.textContent).not.toContain('Confirm coupon');
});

test('ticket form sends one exact JSON request and saved proposal exposes physical IDs-only confirmation', async () => {
  const customerMode = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const proposal = { version: 1, kind: 'support.ticket_prepare', status: 'confirmation_required',
    proposalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', subject: 'Delivery issue',
    body: '<b>Literal body</b>', subjectSha256: 'a'.repeat(64), bodySha256: 'b'.repeat(64) };
  const confirm = jest.fn();
  useCustomerTicketConfirmation.mockReturnValue({ reference: null, status: 'idle', result: null,
    busy: false, error: null, confirm, check: jest.fn(), clearCompleted: jest.fn() });
  await render(); await choose('chat');
  await fill('lane-ticket-subject-test', proposal.subject);
  await fill('lane-ticket-body-test', proposal.body);
  await act(async () => node.querySelector('section[aria-label="Prepare support ticket"] button').click());
  expect(stream.send).toHaveBeenCalledWith(JSON.stringify({ subject: proposal.subject, body: proposal.body }));
  stream.turns = [{ requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    sessionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', user: 'Saved ticket request',
    status: 'done', stopReason: 'end_turn', modeCapability: customerMode,
    hops: [], cards: [], operations: [], ticketProposal: proposal }];
  await render();
  expect(useCustomerTicketConfirmation).toHaveBeenLastCalledWith(expect.objectContaining({
    sourceSessionId: stream.turns[0].sessionId, sourceRequestId: stream.turns[0].requestId,
    proposal, authorityKey: 'shop-token', shopUserId: 5,
  }));
  expect(node.querySelector('[aria-label="Customer support ticket confirmation"] img')).toBeNull();
  await act(async () => [...node.querySelectorAll('[aria-label="Customer support ticket confirmation"] button')]
    .find(button => button.textContent === 'Open support ticket').click());
  expect(confirm).toHaveBeenCalledWith();
});

test('bound customer question uses selected catalog product and refund selects its real stream', async () => {
  await render();
  expect(node.querySelector('#lane-product-id-test')).toBeNull();
  expect(node.textContent).toContain('Selected product: Practice laptop');
  expect(globalThis.fetch).toHaveBeenCalledWith('/api/secureshop/products/7', expect.any(Object));
  expect(useProductQuestion).toHaveBeenCalledWith(expect.objectContaining({ productId: 7 }));
  await fill('lane-product-question-test', 'Does it fit?'); await submit(1);
  expect(question.send).toHaveBeenCalledWith('Does it fit?');
  await choose('refund');
  expect(useAgentStream).toHaveBeenCalledWith({ role: 'customer/refund', defaultUserId: 5,
    authorityKey: 'shop-token' });
  expect(node.querySelector('#lane-refund-order-test')).toBeNull();
  expect(globalThis.fetch).toHaveBeenCalledWith('/api/secureshop/orders', expect.any(Object));
  expect(node.querySelector('[aria-label="Owned order choices"] button strong').textContent)
    .toContain('Order #42');
  await act(async () => node.querySelector('[aria-label="Owned order choices"] button').click());
  expect(node.textContent).toContain('Selected Order #42');
  await fill('lane-refund-reason-test', 'Damaged'); await submit();
  expect(stream.send).toHaveBeenCalledWith('refund order 42: Damaged');
  expect(node.querySelector('a[href="/secureshop/orders"]')).not.toBeNull();
});

test('same-user token rotation resets the refund order picker and binds the new stream authority', async () => {
  await render(); await choose('refund');
  await act(async () => node.querySelector('[aria-label="Owned order choices"] button').click());
  expect(node.textContent).toContain('Selected Order #42');
  useAuth.mockReturnValue({ user: { id: 5, role: 'customer' }, token: 'renewed-shop-token' });
  await render();
  expect(useAgentStream).toHaveBeenCalledWith({ role: 'customer/refund', defaultUserId: 5,
    authorityKey: 'renewed-shop-token' });
  await choose('refund');
  expect(node.textContent).not.toContain('Selected Order #42');
  expect(node.querySelector('#lane-refund-reason-test').closest('form')
    .querySelector('button[type="submit"]').disabled).toBe(true);
  expect(globalThis.fetch.mock.calls.filter(([url]) => url === '/api/secureshop/orders')).toHaveLength(3);
});

test('refund order choices reveal owned product names lazily and cache the detail read', async () => {
  let finishDetail;
  const detail = new Promise(resolve => { finishDetail = resolve; });
  const baseFetch = globalThis.fetch;
  globalThis.fetch = jest.fn((url, options) => {
    if (url === '/api/secureshop/orders') return Promise.resolve({ ok: true, json: async () => ({
      orders: [42, 43].map(id => ({ id, status: 'delivered', total_amount: 49,
        order_date: '2026-10-01T12:00:00.000Z' })),
    }) });
    if (url === '/api/secureshop/orders/42') return detail;
    return baseFetch(url, options);
  });
  await render(); await choose('refund');
  expect(globalThis.fetch).not.toHaveBeenCalledWith('/api/secureshop/orders/42', expect.anything());
  const reveal = node.querySelector('[aria-label="View products in Order #42"]');
  await act(async () => reveal.click());
  expect(node.textContent).toContain('Loading products for Order #42');
  expect(node.querySelector('[aria-label="View products in Order #43"]').disabled).toBe(true);
  await act(async () => finishDetail({ ok: true, json: async () => ({
    order: { id: 42 }, items: [{ name: 'Practice laptop', quantity: 2 }],
  }) }));
  expect(node.querySelector('[aria-label="Products in Order #42"]').textContent)
    .toContain('Practice laptop × 2');
  expect(reveal.disabled).toBe(true);
  expect(globalThis.fetch.mock.calls.filter(([url]) => url === '/api/secureshop/orders/42')).toHaveLength(1);
  await act(async () => node.querySelector('[aria-label="Owned order choices"] button').click());
  await fill('lane-refund-reason-test', 'Damaged'); await submit();
  expect(stream.send).toHaveBeenCalledWith('refund order 42: Damaged');
});

test('refund detail mismatch fails visibly and a replaced transport cannot show stale products', async () => {
  let finishOld;
  const oldDetail = new Promise(resolve => { finishOld = resolve; });
  const baseFetch = globalThis.fetch;
  globalThis.fetch = jest.fn((url, options) => {
    if (url === '/api/secureshop/orders') return Promise.resolve({ ok: true, json: async () => ({
      orders: [{ id: 42, status: 'delivered', order_date: '2026-10-01T12:00:00.000Z' }],
    }) });
    if (url === '/api/secureshop/orders/42') return oldDetail;
    return baseFetch(url, options);
  });
  await render(); await choose('refund');
  await act(async () => node.querySelector('[aria-label="View products in Order #42"]').click());
  globalThis.fetch = jest.fn((url, options) => {
    if (url === '/api/secureshop/orders') return Promise.resolve({ ok: true, json: async () => ({
      orders: [{ id: 42, status: 'delivered', order_date: '2026-10-01T12:00:00.000Z' }],
    }) });
    if (url === '/api/secureshop/orders/42') return Promise.resolve({ ok: true, json: async () => ({
      order: { id: 99 }, items: [{ name: 'Foreign product', quantity: 1 }],
    }) });
    return baseFetch(url, options);
  });
  await render();
  await act(async () => finishOld({ ok: true, json: async () => ({
    order: { id: 42 }, items: [{ name: 'Stale product', quantity: 1 }],
  }) }));
  expect(node.textContent).not.toContain('Stale product');
  await act(async () => node.querySelector('[aria-label="View products in Order #42"]').click());
  expect(node.textContent).toContain('Products for Order #42 are unavailable. Try again.');
  expect(node.textContent).not.toContain('Foreign product');
});

test('general help uses the customer stream and exposes read-only recovery for an uncertain turn', async () => {
  await render();
  await choose('chat');
  expect(useAgentStream).toHaveBeenCalledWith({ role: 'customer', defaultUserId: 5,
    boundCustomerChat: true, authorityKey: 'shop-token', transport: globalThis.fetch });
  await fill('lane-general-help-test', 'Show my cart'); await submit();
  expect(stream.send).toHaveBeenCalledWith('Show my cart');
  stream.pending = { requestId: 'saved-id' };
  stream.turns = [{ user: 'Show my cart', reply: '<b>untrusted response</b>', hops: [], status: 'error', startedAt: Date.now() }];
  await render(); await choose('chat');
  expect(node.textContent).toContain('This chat may have completed');
  expect(node.querySelector('.ss-turn b')).toBeNull();
  expect(node.querySelector('button[type="submit"]').disabled).toBe(true);
  const check = [...node.querySelectorAll('button')].find(button => button.textContent === 'Check saved chat');
  await act(async () => check.click());
  expect(stream.recover).toHaveBeenCalledTimes(1);
});

test('customer chat offers a local Stop watching response control only while observation is active', async () => {
  stream.pending = { requestId: 'saved-id' };
  stream.status = 'thinking';
  stream.canStopWatching = true;
  stream.stopWatching = jest.fn(() => true);
  await render(); await choose('chat');
  const stop = [...node.querySelectorAll('button')].find(button => button.textContent === 'Stop watching response');
  expect(stop?.disabled).toBe(false);
  await act(async () => stop.click());
  expect(stream.stopWatching).toHaveBeenCalledTimes(1);

  stream.status = 'unresolved';
  stream.canStopWatching = false;
  stream.error = 'Stopped watching response. The agent may still finish. Check the saved chat before continuing.';
  await render();
  expect(node.textContent).toContain('The agent may still finish. Check the saved chat before continuing.');
  expect([...node.querySelectorAll('button')].some(button => button.textContent === 'Stop watching response')).toBe(false);
  expect([...node.querySelectorAll('button')].find(button => button.textContent === 'Check saved chat')?.disabled).toBe(false);
});

test('general help sends distinct protected product detail and cart actions without a product ID', async () => {
  const choiceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  stream.turns = [{ user: 'Find a laptop', reply: 'Choose an action.', status: 'done', stopReason: 'end_turn', hops: [],
    modeCapability: { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
      effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } },
    cards: [{ version: 1, kind: 'product', choiceId,
      title: 'Practice laptop', detail: 'USD 49.00 · 3 available' }] }];
  await render(); await choose('chat');
  expect(node.querySelector('[aria-label="Choose product: Practice laptop"]')).toBeNull();
  await act(async () => node.querySelector('[aria-label="View details: Practice laptop"]').click());
  expect(stream.send).toHaveBeenCalledWith('Show this product’s details.',
    { choiceId, intent: 'details' });
  const quantity = node.querySelector('[aria-label="Quantity for Practice laptop"]');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(quantity, '2');
    quantity.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => node.querySelector('[aria-label="Add to cart: Practice laptop"]').click());
  expect(stream.send).toHaveBeenLastCalledWith('Add 2 of this product to my cart.',
    { choiceId, intent: 'cart_add', quantity: 2 });
});

test('general help sends explicit cart-item update or removal from a trusted choice', async () => {
  const choiceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  stream.turns = [{ user: 'Show my cart', reply: 'Choose an action.', status: 'done', stopReason: 'end_turn', hops: [],
    modeCapability: { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
      effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } },
    cards: [{ version: 1, kind: 'cart_item', choiceId,
      title: 'Practice laptop', detail: 'In your cart' }] }];
  await render(); await choose('chat');
  expect(node.querySelector('[aria-label="Choose cart item: Practice laptop"]')).toBeNull();
  const quantity = node.querySelector('[aria-label="New quantity for cart item: Practice laptop"]');
  expect(quantity.value).toBe('1');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(quantity, '2');
    quantity.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => node.querySelector('[aria-label="Update quantity: Practice laptop"]').click());
  expect(stream.send).toHaveBeenCalledWith('Update this cart item to 2.',
    { choiceId, intent: 'cart_update', quantity: 2 });
  await act(async () => node.querySelector('[aria-label="Remove from cart: Practice laptop"]').click());
  expect(stream.send).toHaveBeenLastCalledWith('Remove this item from my cart.',
    { choiceId, intent: 'cart_remove' });
});

test('older owned orders require the latest completed saved page and start a plain new chat turn', async () => {
  const choiceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const modeCapability = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const page = { user: 'Show my orders', reply: 'Here are your orders.', status: 'done',
    stopReason: 'end_turn', modeCapability, orderPage: { nextCursor: choiceId }, hops: [],
    cards: [{ version: 1, kind: 'order', choiceId, title: 'Order #42', detail: 'Delivered' }] };
  stream.turns = [page];
  await render(); await choose('chat');
  expect(node.querySelector('[aria-label="Choose order: Order #42"]')).not.toBeNull();
  await act(async () => node.querySelector('[aria-label="View details: Order #42"]').click());
  expect(stream.send).toHaveBeenCalledWith('Show this order’s details.',
    { choiceId, intent: 'order_details' });
  const older = [...node.querySelectorAll('button')].find(button => button.textContent === 'Older orders');
  expect(older).toBeDefined();
  await act(async () => older.click());
  expect(stream.send).toHaveBeenCalledWith('Show older orders');
  expect(node.querySelector('#lane-refund-order-test')).toBeNull();
  stream.turns = [{ ...page, orderPage: { nextCursor: choiceId, productName: '<Practice laptop>' } }];
  await render();
  expect(node.textContent).toContain('Orders containing <Practice laptop>');
  expect(node.querySelector('img')).toBeNull();
  stream.turns = [{ ...page, orderPage: { nextCursor: null, productName: 'Practice laptop' } }];
  await render();
  expect(node.textContent).toContain('Orders containing Practice laptop');
  expect(node.textContent).not.toContain('Older orders');
  stream.pending = { requestId: 'saved-request' };
  await render();
  expect(node.textContent).not.toContain('Older orders');
  stream.pending = null;
  stream.turns = [page, { ...page, requestId: 'later', orderPage: null }];
  await render();
  expect(node.textContent).not.toContain('Older orders');
});

test('completed selected product details render from the trusted catalog detail observation', async () => {
  const choiceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  stream.turns = [{ user: 'Selected product: Practice laptop', reply: 'Here are the details.', status: 'done', stopReason: 'end_turn',
    modeCapability: { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
      effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } },
    cards: [{ version: 1, kind: 'product', choiceId, title: 'Practice laptop', detail: 'USD 49.00 · 3 available' }],
    hops: [{ tool: 'catalog.details', status: 'ok', params: { choiceId }, modeCapability: {
      version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1', effectiveMode: 'fixed',
      scope: { kind: 'launch_feature', id: 'customer_chat' } }, result: { content: [{ type: 'text', text: JSON.stringify({
        product: { product_id: 7, name: 'Practice laptop', description: 'A bounded practice product.',
          description_html: '<script>ignored</script>', price: '49.00', stock_quantity: 3 },
        cards: [{ version: 1, kind: 'product', choiceId, title: 'Practice laptop', detail: 'USD 49.00 · 3 available' }] }) }] } }] }];
  await render(); await choose('chat');
  const details = node.querySelector('[aria-label="Selected product details"]');
  expect(details).not.toBeNull();
  expect(details.textContent).toContain('Practice laptop');
  expect(details.textContent).toContain('A bounded practice product.');
  expect(details.textContent).toContain('Price: $49.00 · Stock: 3 available');
  expect(details.textContent).not.toContain('product_id');
  expect(details.querySelector('script')).toBeNull();
  const log = node.querySelector('[role="log"][aria-label="Customer conversation"]');
  expect(log.contains(details)).toBe(true);
  expect(log.lastElementChild).toBe(node.querySelector('[data-testid="customer-chat-end"]'));
});

test('selected product details stay unavailable without an exact successful selected detail hop', async () => {
  stream.turns = [{ user: 'Find a laptop', reply: 'Choose a product.', status: 'done',
    modeCapability: { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1', effectiveMode: 'fixed',
      scope: { kind: 'launch_feature', id: 'customer_chat' } },
    cards: [{ version: 1, kind: 'product', choiceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', title: 'Practice laptop', detail: 'Current' }],
    hops: [{ tool: 'catalog.details', status: 'error', params: { choiceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }, result: null }] }];
  await render(); await choose('chat');
  expect(node.querySelector('[aria-label="Selected product details"]')).toBeNull();
});

test('selected product details reject failed, ambiguous, malformed, and mismatched observations', async () => {
  const choiceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const modeCapability = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const card = { version: 1, kind: 'product', choiceId, title: 'Practice laptop', detail: 'Current' };
  const product = { product_id: 7, name: 'Practice laptop', description: 'Bounded description.', price: 49, stock_quantity: 3 };
  const validText = JSON.stringify({ product, cards: [card] });
  const observations = [
    { isError: true, content: [{ type: 'text', text: validText }] },
    { product, cards: [card] },
    { content: [{ type: 'text', text: validText }, { type: 'text', text: validText }] },
    { content: [{ type: 'text', text: '{malformed' }] },
    { content: [{ type: 'text', text: JSON.stringify({ product, cards: [{ ...card, choiceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }] }) }] },
  ];
  for (const result of observations) {
    stream.turns = [{ user: 'Find a laptop', reply: 'Choose a product.', status: 'done', modeCapability,
      cards: [card], hops: [{ tool: 'catalog.details', status: 'ok', params: { choiceId }, modeCapability, result }] }];
    await render(); await choose('chat');
    expect(node.querySelector('[aria-label="Selected product details"]')).toBeNull();
  }
});

test('selected older order shows owned saved line items, payment and shipping as plain text', async () => {
  const choiceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const modeCapability = { version: 1, featureId: 'customer_chat', policyVersion: 'owned-catalog-and-cart-read-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const card = { version: 1, kind: 'order', choiceId, title: 'Order #3',
    detail: 'USD 20.03 · delivered · approved' };
  const order = { order_id: '3', total_amount: '20.03', status: 'delivered',
    payment_status: 'approved', order_date: '2026-10-11T01:02:03.123456Z',
    shipping_address: 'Owned synthetic older order address 3',
    items: [{ product_id: 7, product_name: '<b>Practice notebook</b>', quantity: 2, price: '10.01' }] };
  const selected = { user: 'View details: Order #3', reply: 'Your order is ready.', status: 'done',
    stopReason: 'end_turn', modeCapability, cards: [card],
    hops: [{ tool: 'orders.details', status: 'ok', params: { choiceId }, modeCapability,
      result: { content: [{ type: 'text', text: JSON.stringify({ order, cards: [card], scopeKey: 'a'.repeat(64) }) }] } }] };
  stream.turns = [selected];
  await render(); await choose('chat');
  const details = node.querySelector('[aria-label="Selected order details"]');
  expect(details).not.toBeNull();
  expect(details.textContent).toContain('Order #3');
  expect(details.textContent).toContain('delivered');
  expect(details.textContent).toContain('Payment: approved · Total: $20.03');
  expect(details.textContent).toContain('<b>Practice notebook</b> · 2 × $10.01 each');
  expect(details.textContent).toContain('Owned synthetic older order address 3');
  expect(details.querySelector('b')).toBeNull();
  expect(details.textContent).not.toContain('product_id');
  const log = node.querySelector('[role="log"][aria-label="Customer conversation"]');
  expect(log.contains(details)).toBe(true);
  expect(log.lastElementChild).toBe(node.querySelector('[data-testid="customer-chat-end"]'));
  stream.turns = [selected, { ...selected, requestId: 'newer', cards: [], hops: [] }];
  await render();
  expect(node.querySelector('[aria-label="Selected order details"]')).toBeNull();
  stream.turns = [selected]; stream.pending = { requestId: 'unresolved' };
  await render();
  expect(node.querySelector('[aria-label="Selected order details"]')).toBeNull();
});

test('general help keeps a readable history and sends multiline input only on the chosen action', async () => {
  stream.turns = [
    { user: 'Find a laptop', reply: 'Searching', hops: [], status: 'done',
      modeCapability: { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
        effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } } },
    { user: 'Show my cart', reply: '', hops: [{ id: 'search-1', tool: 'catalog.search',
      status: 'in-flight', params: { search: 'laptop' } }], status: 'in-flight' },
  ];
  stream.status = 'thinking';
  await render(); await choose('chat');
  expect(node.querySelector('[role="log"][aria-label="Customer conversation"]')).not.toBeNull();
  expect(node.querySelectorAll('[role="log"] [data-testid="agent-turn"]')).toHaveLength(2);
  expect(node.textContent).toContain('Searching this shop’s products');
  expect(node.querySelector('#lane-general-help-test').tagName).toBe('TEXTAREA');
  const slot = node.querySelector('[data-testid="customer-chat-composer-slot"]');
  expect(slot).not.toBeNull();
  expect(slot.querySelector('form.ss-lane__composer')).not.toBeNull();
  expect(node.querySelector('.ss-lane__body').contains(slot.querySelector('form'))).toBe(false);

  stream.status = 'idle';
  await render(); await choose('chat');
  await fill('lane-general-help-test', 'Find a laptop\nfor coding');
  const composer = node.querySelector('#lane-general-help-test');
  composer.focus();
  await render();
  expect(document.activeElement).toBe(composer);
  await act(async () => composer.dispatchEvent(new KeyboardEvent('keydown', {
    key: 'Enter', shiftKey: true, bubbles: true, cancelable: true,
  })));
  expect(stream.send).not.toHaveBeenCalled();
  await submit();
  expect(stream.send).toHaveBeenCalledWith('Find a laptop\nfor coding');
  await fill('lane-general-help-test', 'Show my orders');
  await act(async () => composer.dispatchEvent(new KeyboardEvent('keydown', {
    key: 'Enter', bubbles: true, cancelable: true,
  })));
  expect(stream.send).toHaveBeenCalledWith('Show my orders');
});

test('opened historical search uses its own saved session and request for assessment', async () => {
  const start = jest.fn();
  useSearchEchoAssessment.mockReturnValue({ reference: null, outcome: null, busy: false,
    accessLost: false, start, check: jest.fn() });
  const modeCapability = { version: 1, featureId: 'customer_chat',
    policyVersion: 'owned-catalog-and-cart-read-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const oldSource = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', step: 2 };
  stream.sessionId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  stream.turns = [
    { user: 'Find notebooks', reply: 'Here are notebooks.', status: 'done', stopReason: 'end_turn',
      sessionId: oldSource.sessionId, requestId: oldSource.requestId, modeCapability,
      cards: [], operations: [], hops: [
        { id: 'first', tool: 'cart.view', status: 'ok', step: 1, params: {}, result: null },
        { id: 'search', tool: 'catalog.search', status: 'ok', step: 2,
          params: { search: 'notebooks' }, result: null },
      ] },
    { user: 'Show my cart', reply: 'Your cart is empty.', status: 'done', stopReason: 'end_turn',
      sessionId: stream.sessionId, requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      modeCapability, cards: [], operations: [], hops: [] },
  ];
  await render(); await choose('chat');
  const oldTurn = node.querySelectorAll('[data-testid="agent-turn"]')[0];
  const searchHop = oldTurn.querySelector('[aria-label^="Step 2: catalog.search"]');
  expect(searchHop).not.toBeNull();
  await act(async () => searchHop.click());
  const check = [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check search echo');
  expect(check).toBeDefined();
  await act(async () => check.click());
  expect(start).toHaveBeenCalledTimes(1);
  expect(start).toHaveBeenCalledWith(oldSource);
});

test('a completed customer send clears only its submitted draft, preserving later typing', async () => {
  let resolveFirst, resolveThird;
  stream.send.mockReturnValueOnce(new Promise(resolve => { resolveFirst = resolve; }))
    .mockResolvedValueOnce(false)
    .mockReturnValueOnce(new Promise(resolve => { resolveThird = resolve; }))
    .mockResolvedValueOnce(true);
  await render(); await choose('chat');
  await fill('lane-general-help-test', 'First request');
  await submit();
  await fill('lane-general-help-test', 'Second draft');
  await act(async () => resolveFirst(true));
  const input = node.querySelector('#lane-general-help-test');
  expect(input.value).toBe('Second draft');
  expect(node.querySelector('[data-testid="customer-chat-composer-slot"] button[type="submit"]').disabled).toBe(false);
  await submit();
  expect(input.value).toBe('Second draft');
  await submit();
  await fill('lane-general-help-test', '');
  await fill('lane-general-help-test', 'Second draft');
  await act(async () => resolveThird(true));
  expect(input.value).toBe('Second draft');
  await submit();
  expect(input.value).toBe('');
  expect(stream.send.mock.calls.map(([message]) => message))
    .toEqual(['First request', 'Second draft', 'Second draft', 'Second draft']);
});

test('general help presents blocked tool activity compactly above the readable reply', async () => {
  stream.turns = [{ user: 'Show my cart', reply: 'The cart still contains the headphones.',
    status: 'done', modeCapability: { version: 1, featureId: 'customer_chat',
      policyVersion: 'customer-chat-v1', effectiveMode: 'fixed',
      scope: { kind: 'launch_feature', id: 'customer_chat' } },
    hops: [
      { id: 'view', tool: 'cart.view', status: 'done', params: {} },
      { id: 'remove', tool: 'cart.remove_item', status: 'error', policyViolation: 'blocked',
        params: { choiceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' } },
    ] }];
  await render(); await choose('chat');
  const activity = node.querySelector('[role="log"] [data-testid="agent-activity"]');
  expect(activity.open).toBe(false);
  expect(activity.querySelector('summary').textContent).toContain('2 steps · 1 blocked');
  expect(activity.querySelector('summary').textContent).not.toContain('aaaaaaaa-aaaa');
  expect(node.querySelector('[data-testid="agent-turn-reply"]').textContent)
    .toBe('The cart still contains the headphones.');
});

test('customer conversation stays mounted while another task is selected', async () => {
  await render();
  expect(useAgentStream).toHaveBeenCalledWith(expect.objectContaining({ boundCustomerChat: true }));
  await choose('chat');
  await fill('lane-general-help-test', 'Draft message');
  await choose('refund');
  expect(node.querySelector('[data-testid="customer-chat-composer-slot"]')).toBeNull();
  await choose('chat');
  expect(node.querySelector('#lane-general-help-test').value).toBe('Draft message');
  expect(node.querySelector('[role="log"][aria-label="Customer conversation"]')).not.toBeNull();
});

test('customer Next products uses only the latest completed saved search page', async () => {
  const page = { version: 1, total: 14, pageSize: 12, returnedCount: 12, hasMore: true };
  const turn = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', user: 'Find laptops', reply: 'Products',
    hops: [], cards: [], status: 'done', stopReason: 'end_turn', catalogPage: page,
    modeCapability: { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
      effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } } };
  stream.turns = [turn];
  await render(); await choose('chat');
  const next = node.querySelector('[aria-label="Next customer products"]');
  expect(next).not.toBeNull();
  await act(async () => next.click());
  expect(stream.send).toHaveBeenCalledWith('Show more products', null,
    { intent: 'catalog_next', sourceRequestId: turn.requestId });
  stream.turns = [{ ...turn, catalogPage: { ...page, hasMore: false } }];
  await render();
  expect(node.querySelector('[aria-label="Next customer products"]')).toBeNull();
});

test('customer lane follows late results near bottom while preserving an earlier reading position', async () => {
  const turn = { user: 'Find a laptop', reply: '', hops: [], status: 'in-flight' };
  stream.turns = [turn];
  await render(); await choose('chat');
  const body = node.querySelector('.ss-lane__body');
  Object.defineProperty(body, 'scrollHeight', { configurable: true, value: 1000 });
  Object.defineProperty(body, 'clientHeight', { configurable: true, value: 300 });
  body.scrollTop = 700;
  await act(async () => body.dispatchEvent(new Event('scroll')));
  stream.turns = [{ ...turn, reply: 'A saved product reply', status: 'done' }];
  await render();
  expect(body.scrollTop).toBe(1000);

  body.scrollTop = 100;
  await act(async () => body.dispatchEvent(new Event('scroll')));
  stream.turns = [{ ...stream.turns[0], cards: [{ version: 1, kind: 'product',
    choiceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', title: 'Practice laptop', detail: 'Current' }] }];
  await render();
  expect(body.scrollTop).toBe(100);
  stream.pending = { requestId: 'saved-id' };
  stream.status = 'unresolved';
  stream.turns = [{ ...stream.turns[0], status: 'unresolved' }];
  await render();
  expect(body.scrollTop).toBe(100);
  expect(node.querySelector('[role="log"] button')).not.toBeNull();
});

test('merchant assistant composer uses the fixed sibling slot across task changes', async () => {
  await render('merchant'); await choose('assistant');
  const slot = node.querySelector('[data-testid="merchant-assistant-composer-slot"]');
  const composer = slot?.querySelector('[data-testid="role-assistant-test-composer"]');
  expect(composer).not.toBeNull();
  expect(node.querySelector('.ss-lane__body').contains(composer)).toBe(false);
  await choose('analytics');
  expect(node.querySelector('[data-testid="merchant-assistant-composer-slot"]')).toBeNull();
  await choose('assistant');
  expect(node.querySelector('[data-testid="merchant-assistant-composer-slot"] [data-testid="role-assistant-test-composer"]'))
    .not.toBeNull();
});

test('saved cart proposal appears as an explicit named confirmation with no automatic mutation', async () => {
  stream.turns = [{ user: 'Add a laptop', reply: 'Review the change', hops: [], status: 'done', stopReason: 'end_turn',
    modeCapability: { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
      effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } },
    operations: [{ operationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', status: 'prepared',
      proposal: { version: 1, proposalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        status: 'prepared', kind: 'cart.add',
        choice: { version: 1, kind: 'product', choiceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
          title: 'Practice laptop', detail: 'Current product' },
        quantity: 2, quoteSha256: 'a'.repeat(64) } }] }];
  await render(); await choose('chat');
  expect(node.querySelector('section[aria-label="Customer cart confirmation"]')).not.toBeNull();
  expect(node.textContent).toContain('Quantity to add: 2');
  expect(node.textContent).toContain('Confirm cart change');
  expect(globalThis.fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  stream.turns = [...stream.turns, { user: 'Show my current cart', reply: 'Current items', hops: [],
    status: 'done', modeCapability: stream.turns[0].modeCapability, operations: [] }];
  await render();
  expect(node.querySelector('section[aria-label="Customer cart confirmation"]')).toBeNull();
});

test('latest saved stock rejection shows no-effect cart guidance without a confirm action', async () => {
  const trustedMode = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const rejected = { user: 'Add two', reply: 'Model prose is not authority', hops: [],
    status: 'done', stopReason: 'end_turn', modeCapability: trustedMode,
    operations: [{ operationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', status: 'completed',
      rejection: { code: 'INSUFFICIENT_STOCK',
        choiceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', quantity: 2 } }] };
  stream.turns = [rejected];
  await render(); await choose('chat');
  const card = node.querySelector('section[aria-label="Customer cart rejection"]');
  expect(card).not.toBeNull();
  expect(card.textContent).toContain('Not added to cart');
  expect(card.textContent).toContain('Requested quantity 2 is unavailable');
  expect(node.querySelector('section[aria-label="Customer cart confirmation"]')).toBeNull();
  expect(globalThis.fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  stream.turns = [rejected, { user: 'Show my cart', reply: 'No new rejection', hops: [],
    status: 'done', stopReason: 'end_turn', modeCapability: trustedMode, operations: [] }];
  await render();
  expect(node.querySelector('section[aria-label="Customer cart rejection"]')).toBeNull();
  stream.turns = [{ ...rejected, stopReason: 'tool_limit' }];
  await render();
  expect(node.querySelector('section[aria-label="Customer cart rejection"]')).toBeNull();
});

test('a newer customer intent hides an earlier checkout proposal before and after its result', async () => {
  const previousId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const trustedMode = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const previous = { user: 'Use Home address', reply: 'Review your order', hops: [], status: 'done', stopReason: 'end_turn',
    modeCapability: trustedMode, operations: [{ operationId: previousId, status: 'prepared',
      proposal: { proposalId: previousId } }] };
  stream.turns = [previous];
  await render(); await choose('chat');
  expect(node.querySelector('[data-testid="checkout-proposal"]').textContent).toContain(previousId);

  // The previous proposal is no longer a current intent as soon as a new send begins.
  stream.status = 'thinking';
  await render();
  expect(node.querySelector('[data-testid="checkout-proposal"]').textContent).toBe('none');
  stream.status = 'idle';
  stream.turns = [previous, { user: 'Use the declined practice payment', reply: '',
    hops: [], status: 'in-flight' }];
  await render();
  expect(node.querySelector('[data-testid="checkout-proposal"]').textContent).toBe('none');
  stream.turns[1] = { user: 'Use the declined practice payment', reply: 'Ready to order',
    hops: [], status: 'done', modeCapability: trustedMode, operations: [] };
  await render();
  expect(node.querySelector('[data-testid="checkout-proposal"]').textContent).toBe('none');
  stream.pending = { requestId: 'saved-id' };
  stream.turns = [previous];
  await render();
  expect(node.querySelector('[data-testid="checkout-proposal"]').textContent).toBe('none');
});

test('the latest completed checkout keeps its saved proposal while completed cart actions stay hidden', async () => {
  const checkoutId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const cartId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const modeCapability = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  stream.turns = [{ requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', user: 'Saved customer chat request',
    reply: 'Review your order', hops: [], status: 'done', stopReason: 'end_turn', modeCapability,
    operations: [{ operationId: checkoutId, status: 'completed', proposal: { proposalId: checkoutId } },
      { operationId: cartId, status: 'completed', proposal: { proposalId: cartId, kind: 'cart.add' } }] }];
  await render(); await choose('chat');
  expect(node.querySelector('[data-testid="checkout-proposal"]').textContent).toContain(checkoutId);
  expect(node.querySelector('[data-testid="cart-proposal"]')).toBeNull();
  stream.pending = { requestId: checkoutId };
  await render();
  expect(node.querySelector('[data-testid="checkout-proposal"]').textContent).toContain('none');
});

test('the current completed checkout card can request a new payment-method chat turn', async () => {
  const proposalId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const modeCapability = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const turn = { requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', user: 'Choose payment',
    reply: 'Review your order', hops: [], status: 'done', stopReason: 'end_turn', modeCapability,
    operations: [{ operationId: proposalId, status: 'prepared', proposal: { proposalId } }] };
  stream.turns = [turn];
  await render(); await choose('chat');
  const button = [...node.querySelectorAll('button')]
    .find(row => row.textContent === 'Choose another payment method');
  expect(button).toBeDefined();
  await act(async () => button.click());
  expect(stream.send).toHaveBeenCalledWith('Show my current payment methods so I can choose another one.');
  stream.pending = { requestId: proposalId };
  await render();
  expect(node.textContent).not.toContain('Choose another payment method');
});

test('general help presents only the latest exact saved payment handoff and refreshes methods after receipt', async () => {
  const modeCapability = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const old = { requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', user: 'Add a method',
    reply: 'Choose a scenario', hops: [], status: 'done', stopReason: 'end_turn', modeCapability,
    paymentSetup: { version: 1, kind: 'practice_payment_setup', suggestedScenario: 'approved' } };
  stream.turns = [old];
  const previousFetch = globalThis.fetch.getMockImplementation();
  globalThis.fetch.mockImplementation((url, options) => String(url).endsWith('/customer/commerce/payment-methods')
    ? Promise.resolve({ ok: true, json: async () => ({ scopeKey: 'a'.repeat(64), cards: [{
      version: 1, kind: 'payment_method', choiceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      title: 'Approved practice payment', detail: 'Synthetic only',
    }] }) }) : previousFetch(url, options));
  await render(); await choose('chat');
  const handoff = node.querySelector('[data-testid="practice-payment-handoff"]');
  expect(handoff.dataset.entryPoint).toBe('chat');
  expect(handoff.dataset.scenario).toBe('approved');
  expect(handoff.dataset.authorityKey).toContain(old.requestId);
  await act(async () => handoff.querySelector('button').click());
  expect(node.textContent).toContain('Current named choices');
  expect(node.textContent).toContain('Approved practice payment');
  const useInChat = [...node.querySelectorAll('button')].find(button => button.textContent === 'Use payment in chat');
  await act(async () => useInChat.click());
  expect(stream.send).toHaveBeenCalledWith('Show my payment methods');

  stream.turns = [old, { requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', user: 'Another request',
    reply: '', hops: [], status: 'in-flight' }];
  await render();
  expect(node.querySelector('[data-testid="practice-payment-handoff"]').dataset.scenario).toBe('');
  expect(node.textContent).not.toContain('Current named choices');
  stream.turns[1] = { ...stream.turns[1], reply: 'No setup', status: 'done', modeCapability, paymentSetup: null };
  await render();
  expect(node.querySelector('[data-testid="practice-payment-handoff"]').dataset.scenario).toBe('');
});

test('general help shows only the latest trusted address handoff and refreshes protected names after receipt', async () => {
  const modeCapability = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const old = { requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', user: 'Add my address',
    reply: 'Review your address', hops: [], status: 'done', stopReason: 'end_turn', modeCapability,
    addressSetup: { version: 1, kind: 'address_setup', action: 'create', choiceId: null,
      draft: { line1: '1 Main St' } } };
  stream.turns = [old];
  const previousFetch = globalThis.fetch.getMockImplementation();
  globalThis.fetch.mockImplementation((url, options) => String(url).endsWith('/customer/commerce/addresses')
    ? Promise.resolve({ ok: true, json: async () => ({ scopeKey: 'a'.repeat(64), cards: [{
      version: 1, kind: 'address', choiceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      title: 'Home', detail: '1 Main St',
    }], addresses: [{ addressId: 11, choiceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      fields: { label: 'Home', line1: '1 Main St', line2: null, city: 'Town', state: null,
        zip: null, phone: null, isDefault: false } }] }) }) : previousFetch(url, options));
  await render(); await choose('chat');
  const handoff = node.querySelector('[data-testid="practice-address-handoff"]');
  expect(handoff.dataset.action).toBe('create');
  expect(handoff.dataset.authorityKey).toContain(old.requestId);
  await act(async () => handoff.querySelector('button').click());
  expect(node.textContent).toContain('Current named addresses');
  expect(node.textContent).toContain('Home — 1 Main St');
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Show addresses in chat').click());
  expect(stream.send).toHaveBeenCalledWith('Show my delivery addresses');
  stream.turns = [old, { requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', user: 'New request',
    reply: '', hops: [], status: 'in-flight' }];
  await render();
  expect(node.querySelector('[data-testid="practice-address-handoff"]').dataset.action).toBe('');
  expect(node.textContent).not.toContain('Current named addresses');
});

test('current named address offers distinct checkout and edit chat actions', async () => {
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const modeCapability = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  stream.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', user: 'Show my addresses',
    reply: 'Choose Home', hops: [], status: 'done', stopReason: 'end_turn', modeCapability,
    cards: [{ version: 1, kind: 'address', choiceId, title: 'Home', detail: '1 Main St' }] }];
  await render(); await choose('chat');
  const checkout = node.querySelector('[aria-label="Use for checkout: Home"]');
  const edit = node.querySelector('[aria-label="Edit address: Home"]');
  expect(checkout.disabled).toBe(false);
  expect(edit.disabled).toBe(false);
  await act(async () => checkout.click());
  expect(stream.send).toHaveBeenLastCalledWith('Use this address for checkout.',
    { choiceId, intent: 'address_checkout' });
  await act(async () => edit.click());
  expect(stream.send).toHaveBeenLastCalledWith('Prepare to edit this address.',
    { choiceId, intent: 'address_edit' });
  stream.pending = { requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' };
  await render();
  expect(node.querySelector('[aria-label="Use for checkout: Home"]').disabled).toBe(true);
  expect(node.querySelector('[aria-label="Edit address: Home"]').disabled).toBe(true);
});

test('latest clean saved refund handoff offers Orders review without filing a ticket', async () => {
  const modeCapability = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const setup = { version: 1, kind: 'refund_setup',
    choiceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', orderId: 42 };
  stream.turns = [{ requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', user: 'Refund my order',
    reply: 'Review your order', hops: [], status: 'done', stopReason: 'end_turn',
    modeCapability, refundSetup: setup }];
  await render(); await choose('chat');
  expect(node.querySelector('a[href="/secureshop/orders"]')?.textContent)
    .toContain('Review refund request in Orders');
  expect(node.textContent).not.toContain('Refund request filed');
  stream.turns.push({ requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', user: 'New intent',
    reply: '', hops: [], status: 'in-flight' });
  await render();
  expect(node.textContent).not.toContain('Review refund request in Orders');
  stream.turns[1] = { ...stream.turns[1], status: 'done', stopReason: 'end_turn', modeCapability };
  await render();
  expect(node.textContent).not.toContain('Review refund request in Orders');
});

test('bound merchant choices invoke existing task hooks and review context routes to Reviews', async () => {
  await render('merchant');
  expect(node.textContent).toContain('Owned inventory assistant');
  await choose('assistant');
  expect(node.textContent).toContain('merchant read-only assistant');
  await choose('analytics'); await fill('lane-analytics-question-test', 'Top products'); await submit();
  expect(analytics.submit).toHaveBeenCalledWith('Top products');
  await choose('pricing');
  expect(node.querySelector('#lane-pricing-product-test')).toBeNull();
  await act(async () => node.querySelector('[aria-label="Catalog product choices"] button').click());
  await fill('lane-pricing-message-test', 'Suggest a price'); await submit(1);
  expect(pricing.run).toHaveBeenCalledWith('suggest', 8, 'Suggest a price');
  await choose('listing'); await fill('lane-listing-title-test', 'Chair');
  await fill('lane-listing-description-test', 'Comfortable'); await submit();
  expect(listings.run).toHaveBeenCalledWith('rewrite', { title: 'Chair', description: 'Comfortable' });
  expect(node.querySelector('pre[role="status"] b')).toBeNull();
  await choose('reviews');
  expect(node.textContent).toContain('Choose a pending review card');
  expect(node.textContent).not.toContain('needs the review ID');
  expect(node.querySelector('a[href="/secureshop/merchant/reviews"]')).not.toBeNull();
});

test('customer access-control task uses physical prepared cards and a saved read without raw IDs', async () => {
  const lesson = { cards: null, mode: null, loading: false, busy: false, error: null,
    reference: null, status: 'idle', savedResult: null, savedText: null, assessment: null,
    prepare: jest.fn(), loadCards: jest.fn(), select: jest.fn(), recover: jest.fn(),
    readAssessment: jest.fn(), retryAssessment: jest.fn(), clearCompleted: jest.fn() };
  useCustomerIdorLesson.mockReturnValue(lesson);
  await render(); await choose('idor');
  expect(node.querySelector('[aria-label="Customer access control lesson"]')).not.toBeNull();
  expect(lesson.loadCards).toHaveBeenCalledTimes(1);
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Prepare lesson targets').click());
  expect(lesson.prepare).toHaveBeenCalledTimes(1);
  lesson.cards = [
    { action: 'cart_remove', numericId: 7, label: 'Reserved lesson cart item' },
    { action: 'order_status', numericId: 7, label: 'Reserved lesson order' },
  ];
  lesson.mode = 'fixed';
  await render();
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Read full order details').click());
  expect(lesson.select).toHaveBeenCalledWith({ action: 'order_status', numericId: 7 });
  lesson.reference = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
  lesson.status = 'completed'; lesson.savedText = 'The request was denied.';
  lesson.savedResult = { action: 'order_status', numericId: 7, status: 'denied' };
  await render();
  expect(node.textContent).toContain('The request was denied.');
  expect([...node.querySelectorAll('button')].find(button => button.textContent === 'Read full order details').disabled).toBe(true);
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved assessment').click());
  expect(lesson.readAssessment).toHaveBeenCalledTimes(1);
  expect(node.querySelector('input[placeholder*="ID"]')).toBeNull();
});

test('bound admin keeps the owned audit workflow and exposes the read-only assistant', async () => {
  await render('admin');
  expect(node.querySelector('a[href="/secureshop/admin/audit"]')).not.toBeNull();
  expect(node.textContent).toContain('admin read-only assistant');
  const slot = node.querySelector('[data-testid="admin-role-composer-slot"]');
  expect(slot.querySelector('[data-testid="role-assistant-test-composer"]')).not.toBeNull();
  expect(node.querySelector('.ss-lane__body').contains(slot)).toBe(false);
});

test('customer profile card is latest exact saved end-turn only while its recovery slot stays mounted', async () => {
  const proposalId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const modeCapability = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  stream.turns = [{ user: 'Update my name', status: 'done', stopReason: 'end_turn',
    sessionId: proposalId, requestId: proposalId, modeCapability, hops: [], cards: [],
    profileProposal: { proposalId } }];
  await render(); await choose('chat');
  expect(node.querySelector('[data-testid="profile-review"]').dataset.proposalId).toBe(proposalId);
  stream.status = 'thinking'; await render();
  expect(node.querySelector('[data-testid="profile-review"]').dataset.proposalId).toBe('');
  stream.status = 'idle'; stream.turns.push({ user: 'New request', status: 'in-flight',
    requestId: 'new', hops: [], cards: [] });
  await render();
  expect(node.querySelector('[data-testid="profile-review"]').dataset.proposalId).toBe('');
  stream.turns[1] = { ...stream.turns[1], status: 'done', stopReason: 'end_turn', modeCapability };
  await render();
  expect(node.querySelector('[data-testid="profile-review"]').dataset.proposalId).toBe('');
});


test('V44 has a separate customer task and receives the current owner and transport', async () => {
  await render();
  const values = [...node.querySelector('select').options].map(option => option.value);
  expect(values).toContain('file-summary-lesson');
  expect(values).toContain('file-path-summary-lesson');
  expect(values).toContain('avatar-traversal-lesson');
  expect(node.querySelector('[data-testid="path-summary-card"]')).toBeNull();
  await choose('file-path-summary-lesson');
  const card = node.querySelector('[data-testid="path-summary-card"]');
  expect(card.dataset.owner).toBe('5');
  expect(card.dataset.currentAuthority).toBe('yes');
  expect(card.dataset.currentTransport).toBe('yes');
  await choose('product');
  expect(node.querySelector('[data-testid="path-summary-card"]')).toBeNull();
});

test('V44 customer lesson is absent from the merchant task list', async () => {
  useAuth.mockReturnValue({ user: { id: 9, role: 'merchant' }, token: 'merchant-token' });
  await render('merchant');
  expect([...node.querySelector('select').options].map(option => option.value)).not.toContain('file-path-summary-lesson');
  expect(node.querySelector('[data-testid="path-summary-card"]')).toBeNull();
});

function roleAssessmentTurn(assessment) {
  return { user: 'Change my teaching role', reply: 'Teaching action returned', hops: [], status: 'done',
    stopReason: 'end_turn', sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    modeCapability: { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
      effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'customer_chat' } },
    agencyRole: { version: 1, teachingRole: 'admin', changed: true }, agencyAssessment: assessment };
}
test('customer role effect stays pending until canonical credit and refresh only checks saved assessment', async () => {
  stream.refreshAgencyAssessment = jest.fn().mockResolvedValue(true);
  stream.turns = [roleAssessmentTurn({ completed: false, status: 'pending', modelEvaluated: false })];
  await render();await choose('chat');
  expect(node.textContent).toContain('Role assessment pending. No objective completion confirmed.');
  expect(node.textContent).not.toContain('objective completed in canonical progress');
  const button = [...node.querySelectorAll('button')].find(button => button.textContent === 'Check saved role assessment');
  await act(async () => button.click());
  expect(stream.refreshAgencyAssessment).toHaveBeenCalledWith(stream.turns[0].sessionId, stream.turns[0].requestId);
  expect(stream.send).not.toHaveBeenCalled();
  stream.turns = [roleAssessmentTurn({ completed: true, judgment: { verdict: 'pass', canRetry: false }, replayed: true })];
  await render();
  expect(node.textContent).toContain('Teaching role objective completed in canonical progress.');
  expect(node.textContent).not.toContain('You are now an admin');
});

test.each([
  [{ completed: false, status: 'unavailable', modelEvaluated: false }, 'Saved role assessment unavailable.'],
  [{ completed: false, status: 'ineligible', modelEvaluated: false }, 'not eligible for objective completion'],
  [{ completed: false, judgment: { verdict: 'pass', canRetry: false }, replayed: true }, 'No objective completion confirmed.'],
  [{ completed: true, judgment: { verdict: 'fail', canRetry: false }, replayed: true }, 'No objective completion confirmed.'],
])('customer role assessment never infers completion from an effect or verdict alone', async (assessment, expected) => {
  stream.turns = [roleAssessmentTurn(assessment)];
  await render();await choose('chat');
  expect(node.textContent).toContain(expected);
  expect(node.textContent).not.toContain('objective completed in canonical progress');
});
