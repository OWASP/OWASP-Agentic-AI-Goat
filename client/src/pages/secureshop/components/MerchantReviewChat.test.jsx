import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, useLocation } from 'react-router-dom';
import MerchantReviewChat from './MerchantReviewChat.jsx';
import { SHOP_REVIEW_DECISION_KEY } from '../utils/shopStorage.mjs';
import { decodeMerchantReviewDetail, decodeMerchantReviewPage, decodeMerchantReviewProposal, merchantReviewSelection,
  verifyMerchantReviewReceipt } from '../utils/merchantReviewChat.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const choiceId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const launchId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const targetId = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const scenarioId = '11111111-1111-4111-8111-111111111111';
const mode = featureId => ({ version: 1, effectiveMode: 'vuln', featureId,
  policyVersion: featureId === 'review' ? 'product-feedback-enforced-decision-v1' : 'v1',
  scope: { kind: 'launch_feature', id: featureId } });
const scopeKey = JSON.stringify([launchId, 1, 7, 8, 9, 10]);
const sha = 'a'.repeat(64);
const proposal = { version: 1, proposalId,
  review: { choiceId, reviewId: 33, productId: 44, rating: 4,
    body: '<img src=x onerror=alert(1)>', status: 'pending' },
  decision: 'approve', reason: null, expectedSnapshotSha256: sha,
  requestSha256: 'b'.repeat(64), scopeKey, modeCapability: mode('review') };
const receipt = { operationId: proposalId, kind: 'manual', moderatorKind: 'manual', reviewId: 33,
  decision: 'approved', notes: null, applied: true, resultStatus: 'approved',
  expectedSnapshotSha256: sha, resultCode: null,
  scope: { targetId, launchId, scenarioId, generation: 1, platformOwnerId: 7, platformSessionId: 8 },
  actor: { id: 9, role: 'merchant', personaSessionId: 10 } };
const card = { version: 1, kind: 'merchant_review', choiceId,
  title: 'Review for a named product', detail: 'Pending · 4 stars' };

let node, root;
function RouterPath() {
  const location = useLocation();
  return <output data-testid="router-path">{location.pathname}</output>;
}

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); localStorage.clear(); });

async function render(props = {}) {
  const content = <MerchantReviewChat authorityKey={props.authorityKey || 'current'} transport={props.transport || jest.fn()}
    cards={props.cards || []} detail={props.detail ?? null} page={props.page ?? null}
    proposal={props.proposal ?? null} sessionId={sessionId} requestId={requestId}
    onSelect={props.onSelect} locked={props.locked || false} />;
  await act(async () => root.render(
    <MemoryRouter initialEntries={props.router?.initialEntries || ['/secureshop/merchant']}>
      <>{content}<RouterPath /></>
    </MemoryRouter>));
}
const click = async label => act(async () => {
  const button = [...node.querySelectorAll('button')].find(item => item.textContent === label);
  expect(button).toBeDefined(); button.click();
});

test('closed review detail and proposal reject malformed or fixed-mode mismatches', () => {
  expect(decodeMerchantReviewProposal(proposal)).toEqual(proposal);
  expect(() => decodeMerchantReviewProposal({ ...proposal, reason: 'model-chosen reason' })).toThrow();
  expect(() => decodeMerchantReviewProposal({ ...proposal,
    modeCapability: mode('merchant_assistant') })).toThrow();
  expect(() => decodeMerchantReviewDetail({ version: 1, choiceId, reviewId: 33, productId: 44,
    rating: 4, status: 'pending', body: 'hidden', oversized: true,
    modeCapability: mode('review') })).toThrow();
  expect(merchantReviewSelection(choiceId, 'review_reject')).toEqual({ choiceId, intent: 'review_reject' });
  expect(() => merchantReviewSelection(choiceId, 'approve_now')).toThrow();
  expect(decodeMerchantReviewPage({ page: 1, total: 6, nextPage: 2, status: 'pending', productChoiceId: null }))
    .toEqual({ page: 1, total: 6, nextPage: 2, status: 'pending', productChoiceId: null });
  expect(() => decodeMerchantReviewPage({ page: 1, total: 6, nextPage: 3, status: 'pending', productChoiceId: null })).toThrow();
  expect(decodeMerchantReviewProposal({ ...proposal,
    review: { ...proposal.review, body: 'x'.repeat(9000) } }).review.body).toHaveLength(9000);
  expect(() => decodeMerchantReviewProposal({ ...proposal,
    review: { ...proposal.review, body: 'x'.repeat(65537) } })).toThrow();
});

test('preconditioned receipt distinguishes an applied decision from a saved stale no-effect result', () => {
  const reference = { scopeKey, operationId: proposalId, reviewId: 33,
    action: 'approve', reason: null, expectedSnapshotSha256: sha };
  expect(verifyMerchantReviewReceipt(receipt, reference, scopeKey).applied).toBe(true);
  const stale = { ...receipt, applied: false, resultStatus: 'pending', resultCode: 'REVIEW_STALE' };
  expect(verifyMerchantReviewReceipt(stale, reference, scopeKey).applied).toBe(false);
  expect(() => verifyMerchantReviewReceipt({ ...stale, resultCode: null }, reference, scopeKey)).toThrow();
  expect(() => verifyMerchantReviewReceipt({ ...receipt, expectedSnapshotSha256: 'c'.repeat(64) },
    reference, scopeKey)).toThrow();
});

test('review cards expose three explicit intents and selected body renders as inert text', async () => {
  const onSelect = jest.fn();
  await render({ cards: [card], onSelect, page: { page: 1, total: 3, nextPage: 2, status: 'pending' },
    detail: { version: 1, choiceId, reviewId: 33, productId: 44, rating: 4,
      status: 'pending', body: proposal.review.body, oversized: false, modeCapability: mode('review') } });
  expect(node.textContent).toContain('More available on page 2');
  expect(node.querySelector('img')).toBeNull();
  expect(node.textContent).toContain(proposal.review.body);
  await click('View review'); await click('Approve'); await click('Reject');
  expect(onSelect.mock.calls.map(([selection]) => selection.intent)).toEqual([
    'review_details', 'review_approve', 'review_reject' ]);
  expect(onSelect.mock.calls.every(([selection]) => selection.choiceId === choiceId)).toBe(true);
});

test('oversized review offers the established Reviews page without displaying body', async () => {
  await render({ detail: { version: 1, choiceId, reviewId: 33, productId: 44, rating: 4,
    status: 'pending', body: null, oversized: true, modeCapability: mode('review') } });
  expect(node.textContent).toContain('too long for chat');
  expect(node.querySelector('a').getAttribute('href')).toBe('/secureshop/merchant/reviews');
  expect(node.querySelector('button')).toBeNull();
});

test('oversized review opens Reviews inside the router without document navigation', async () => {
  const before = window.location.href;
  await render({ router: { initialEntries: ['/secureshop/merchant/review-chat'] },
    detail: { version: 1, choiceId, reviewId: 33, productId: 44, rating: 4,
      status: 'pending', body: null, oversized: true, modeCapability: mode('review') } });
  const link = node.querySelector('a[href="/secureshop/merchant/reviews"]');
  expect(link).not.toBeNull();
  const event = new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 });
  await act(async () => { link.dispatchEvent(event); });
  expect(event.defaultPrevented).toBe(true);
  expect(node.querySelector('[data-testid="router-path"]').textContent).toBe('/secureshop/merchant/reviews');
  expect(window.location.href).toBe(before);
});

test('cancel dismisses a prepared decision locally without a review operation', async () => {
  const transport = jest.fn();
  await render({ proposal, transport });
  await click('Cancel proposal');
  expect(node.textContent).toContain('No review decision was submitted');
  expect(node.textContent).not.toContain('Confirm approval');
  expect(localStorage.getItem(SHOP_REVIEW_DECISION_KEY)).toBeNull();
  expect(transport).not.toHaveBeenCalled();
});

test('one physical confirmation saves the manual ref before POST and recovers a lost response by exact GET', async () => {
  const requests = []; let operationReads = 0;
  const transport = jest.fn(async (url, options) => {
    requests.push([url, options?.method || 'GET']);
    if (url.startsWith('/api/secureshop/merchant/reviews?'))
      return { ok: true, json: async () => ({ manual_decisions: { available: true, scopeKey } }) };
    if (url.includes('/assistant/operations/'))
      return { ok: true, json: async () => ({ sessionId, requestId, status: 'completed', replayed: true,
        stopReason: 'end_turn', modeCapability: mode('merchant_assistant'), reviewProposal: proposal }) };
    if (url.includes('/merchant/reviews/operations/')) {
      operationReads += 1;
      return operationReads === 1 ? { status: 404, ok: false }
        : { status: 200, ok: true, json: async () => ({ ok: true, receipt, executionScopeKey: scopeKey }) };
    }
    if (url.endsWith('/assistant/review/confirm')) {
      expect(JSON.parse(localStorage.getItem(SHOP_REVIEW_DECISION_KEY))).toEqual(expect.objectContaining({
        operationId: proposalId, reviewId: 33, expectedSnapshotSha256: sha }));
      throw Error('response lost after commit');
    }
    throw Error(`Unexpected route: ${url}`);
  });
  await render({ proposal, transport });
  await click('Confirm approval');
  expect(requests.filter(([url]) => url.endsWith('/assistant/review/confirm'))).toHaveLength(1);
  expect(requests.filter(([url]) => url.includes('/merchant/reviews/operations/'))).toHaveLength(2);
  expect(localStorage.getItem(SHOP_REVIEW_DECISION_KEY)).toBeNull();
  expect(node.textContent).toContain('Review decision applied.');
});

test('an unconfirmed response retains the exact ref and remount checks GET without a second POST', async () => {
  let posted = 0, committed = false;
  const transport = jest.fn(async url => {
    if (url.startsWith('/api/secureshop/merchant/reviews?'))
      return { ok: true, json: async () => ({ manual_decisions: { available: true, scopeKey } }) };
    if (url.includes('/assistant/operations/'))
      return { ok: true, json: async () => ({ sessionId, requestId, status: 'completed', replayed: true,
        stopReason: 'end_turn', modeCapability: mode('merchant_assistant'), reviewProposal: proposal }) };
    if (url.includes('/merchant/reviews/operations/'))
      return committed ? { ok: true, json: async () => ({ ok: true, receipt, executionScopeKey: scopeKey }) }
        : { status: 404, ok: false };
    if (url.endsWith('/assistant/review/confirm')) { posted += 1; throw Error('response unavailable'); }
    throw Error(`Unexpected route: ${url}`);
  });
  await render({ proposal, transport });
  await click('Confirm approval');
  expect(posted).toBe(1);
  expect(JSON.parse(localStorage.getItem(SHOP_REVIEW_DECISION_KEY)).operationId).toBe(proposalId);
  await render({ authorityKey: 'renewed', transport });
  expect(node.textContent).toContain('Check saved review decision');
  committed = true;
  await click('Check saved review decision');
  expect(posted).toBe(1);
  expect(localStorage.getItem(SHOP_REVIEW_DECISION_KEY)).toBeNull();
});

test('a saved direct Reviews-page decision blocks a new chat confirmation without overwriting it', async () => {
  const direct = { scopeKey, operationId: '22222222-2222-4222-8222-222222222222',
    reviewId: 99, action: 'reject', reason: 'Customer reason' };
  localStorage.setItem(SHOP_REVIEW_DECISION_KEY, JSON.stringify(direct));
  const transport = jest.fn();
  await render({ proposal, transport });
  expect(node.textContent).toContain('Resolve it there');
  expect([...node.querySelectorAll('button')].some(button => button.textContent === 'Confirm approval')).toBe(false);
  expect(transport).not.toHaveBeenCalled();
  expect(JSON.parse(localStorage.getItem(SHOP_REVIEW_DECISION_KEY))).toEqual(direct);
});

test('a review operation saved during the preflight GET is never overwritten', async () => {
  const other = { scopeKey, operationId: '22222222-2222-4222-8222-222222222222',
    reviewId: 99, action: 'reject', reason: 'Another decision' };
  const transport = jest.fn(async url => {
    if (url.startsWith('/api/secureshop/merchant/reviews?'))
      return { ok: true, json: async () => ({ manual_decisions: { available: true, scopeKey } }) };
    if (url.includes('/assistant/operations/'))
      return { ok: true, json: async () => ({ sessionId, requestId, status: 'completed', replayed: true,
        stopReason: 'end_turn', modeCapability: mode('merchant_assistant'), reviewProposal: proposal }) };
    if (url.includes('/merchant/reviews/operations/')) {
      localStorage.setItem(SHOP_REVIEW_DECISION_KEY, JSON.stringify(other));
      return { status: 404, ok: false };
    }
    throw Error(`Unexpected route: ${url}`);
  });
  await render({ proposal, transport });
  await click('Confirm approval');
  expect(JSON.parse(localStorage.getItem(SHOP_REVIEW_DECISION_KEY))).toEqual(other);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/assistant/review/confirm'))).toBe(false);
});
