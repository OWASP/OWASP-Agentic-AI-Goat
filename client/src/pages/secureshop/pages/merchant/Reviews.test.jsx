import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import MerchantReviews from './Reviews';

Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Request = web.Request;
global.Response = web.Response;
global.Headers = web.Headers;

let mockUser = { id: 77, role: 'merchant' };
let mockToken = 'merchant-token';
jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, token: mockToken }) }));

jest.mock('framer-motion', () => {
  const React = require('react');
  const element = (tag) => React.forwardRef(function MotionElement(
    { initial, animate, exit, transition, whileHover, whileTap, ...props }, ref,
  ) { return React.createElement(tag, { ...props, ref }); });
  return {
    motion: { div: element('div'), article: element('article'), section: element('section') },
    AnimatePresence: ({ children }) => <>{children}</>,
    useReducedMotion: () => true,
  };
});

let root;
let container;

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: jest.fn().mockResolvedValue(body),
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function review(id, body = `review ${id}`) {
  return { id, body, rating: 4, author_id: 9, product_id: 2, status: 'pending',
    created_at: '2026-01-01T00:00:00Z' };
}

async function settle() {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  mockUser = { id: 77, role: 'merchant' };
  mockToken = 'merchant-token';
  localStorage.setItem('secureshop_v2_token', mockToken);
  global.fetch = jest.fn((url) => {
    if (String(url).includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    return Promise.resolve(response({ reviews: [], counts: {} }));
  });
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

test('explains ordinary rule-based moderation only outside the bound workshop', async () => {
  await act(async () => root.render(<MerchantReviews />));
  await settle();
  expect(container.textContent).toContain('rule-based moderation simulation');
  expect(container.textContent).toContain('does not demonstrate an actual LLM decision');
  expect(container.textContent).not.toContain('actual model decision loop');
});

test('explains the actual model decision loop in the shop without changing controls', async () => {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  const bridge = { request: jest.fn(async operation => {
    if (operation === 'merchant.products.list') return response({ products: [] });
    if (operation === 'merchant.reviews.list') return response({ reviews: [], counts: {} });
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  await act(async () => root.render(<MerchantReviews />));
  await settle();
  expect(container.textContent).toContain('actual model decision loop');
  expect(container.textContent).toContain('This shop sends pending reviews');
  expect(container.textContent).not.toContain('This bound workshop');
  expect(container.textContent).toContain('trusted product-feedback policy');
  expect(container.textContent).toContain('lets the model approve or reject up to 100');
  expect(container.textContent).toContain('The filters only change the displayed list');
  expect(bridge.request.mock.calls.every(([operation]) => !operation.includes('moderate'))).toBe(true);
  expect(container.textContent).not.toContain('rule-based moderation simulation');
  expect(container.querySelector('[data-testid="reviews-moderate-all"]')).not.toBeNull();
});

test('a failed list request is reported and is not presented as an empty queue', async () => {
  global.fetch.mockImplementation((url) => {
    if (String(url).includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    return Promise.resolve(response({ error: 'review store unavailable' }, 503));
  });

  await act(async () => root.render(<MerchantReviews />));
  await settle();

  expect(container.querySelector('[role="alert"]').textContent).toContain('review store unavailable');
  expect(container.textContent).not.toContain('No pending reviews');
});

test('switching review status immediately hides old cards and never relabels them', async () => {
  const approved = deferred();
  global.fetch.mockImplementation((url) => {
    const value = String(url);
    if (value.includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    if (value.includes('status=approved')) return approved.promise;
    return Promise.resolve(response({ reviews: [review(4, 'pending review')],
      counts: { pending: 1, approved: 0 } }));
  });
  await act(async () => root.render(<MerchantReviews />));
  await settle();
  expect(container.textContent).toContain('pending review');

  const approvedTab = [...container.querySelectorAll('button')]
    .find(button => button.textContent.includes('Approved'));
  await act(async () => approvedTab.click());
  expect(container.textContent).not.toContain('pending review');
  expect(container.textContent).not.toContain('approved by human');
  expect(container.querySelector('[data-testid="reviews-moderate-all"]').disabled).toBe(true);

  await act(async () => approved.resolve(response({ reviews: [], counts: { pending: 1, approved: 0 } })));
  await settle();
  expect(container.textContent).toContain('No approved reviews');
  expect(container.textContent).not.toContain('pending review');
});

test('only the newest filter request may publish reviews and counts', async () => {
  const oneStar = deferred();
  const twoStar = deferred();
  global.fetch.mockImplementation((url) => {
    const value = String(url);
    if (value.includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    if (value.includes('min_rating=1')) return oneStar.promise;
    if (value.includes('min_rating=2')) return twoStar.promise;
    return Promise.resolve(response({ reviews: [review(1, 'initial')], counts: { pending: 1 } }));
  });
  await act(async () => root.render(<MerchantReviews />));
  await settle();

  const minRating = Array.from(container.querySelectorAll('select'))[1];
  await act(async () => {
    minRating.value = '1';
    minRating.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await act(async () => {
    minRating.value = '2';
    minRating.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await act(async () => {
    twoStar.resolve(response({ reviews: [review(22, 'newest')], counts: { pending: 1 } }));
    await twoStar.promise;
  });
  expect(container.textContent).toContain('newest');

  await act(async () => {
    oneStar.resolve(response({ reviews: [review(11, 'stale')], counts: { pending: 99 } }));
    await oneStar.promise;
  });
  expect(container.textContent).toContain('newest');
  expect(container.textContent).not.toContain('stale');
  expect(container.textContent).not.toContain('99');
});

test('moderation failure is bounded, does not retry, and does not publish a result', async () => {
  const moderation = deferred();
  global.fetch.mockImplementation((url) => {
    const value = String(url);
    if (value.includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    if (value.includes('/moderate-all')) return moderation.promise;
    return Promise.resolve(response({ reviews: [review(7)], counts: { pending: 1 } }));
  });
  await act(async () => root.render(<MerchantReviews />));
  await settle();

  const button = container.querySelector('[data-testid="reviews-moderate-all"]');
  await act(async () => {
    button.click();
    button.click();
  });
  expect(global.fetch.mock.calls.filter(([url]) => String(url).includes('/moderate-all'))).toHaveLength(1);

  await act(async () => {
    moderation.resolve(response({ error: 'x'.repeat(400) }, 502));
    await moderation.promise;
    await Promise.resolve();
  });
  const feedback = container.querySelector('[data-testid="reviews-feedback"]');
  expect(feedback.getAttribute('role')).toBe('alert');
  expect(feedback.textContent.length).toBeLessThanOrEqual(241);
  expect(container.textContent).not.toContain('MODERATE_PENDING');
  expect(global.fetch.mock.calls.filter(([url]) => String(url).includes('/merchant/reviews?'))).toHaveLength(1);
});

test('approve and reject failures retain the review, with reject dialog available for a manual retry', async () => {
  global.fetch.mockImplementation((url) => {
    const value = String(url);
    if (value.includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    if (value.endsWith('/approve')) return Promise.resolve(response({ error: 'approval denied' }, 409));
    if (value.endsWith('/reject')) return Promise.reject(new Error('network down'));
    return Promise.resolve(response({ reviews: [review(8, '<img src=x onerror="window.__reviewXss=1">')], counts: { pending: 1 } }));
  });
  await act(async () => root.render(<MerchantReviews />));
  await settle();

  const buttons = Array.from(container.querySelectorAll('button'));
  await act(async () => buttons.find(button => button.textContent.trim() === 'Approve').click());
  await settle();
  expect(container.textContent).toContain('approval denied');
  expect(container.textContent).toContain('REVIEW #8');

  await act(async () => Array.from(container.querySelectorAll('button')).find(button => button.textContent.trim() === 'Reject').click());
  await act(async () => container.querySelector('[role="dialog"] .ss-btn--danger').click());
  await settle();
  expect(container.textContent).toContain('network down');
  expect(container.querySelector('[role="dialog"]')).not.toBeNull();
  expect(container.textContent).toContain('REVIEW #8');
  expect(global.fetch.mock.calls.filter(([url]) => String(url).endsWith('/reject'))).toHaveLength(1);
  expect(container.querySelector('.review-body').innerHTML).toContain('onerror');
});

test('approve requires ok true and refreshes the current list when the review was not applied', async () => {
  let listCalls = 0;
  global.fetch.mockImplementation((url) => {
    const value = String(url);
    if (value.includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    if (value.endsWith('/approve')) {
      return Promise.resolve(response({ ok: false, error: 'review is no longer pending' }));
    }
    listCalls += 1;
    return Promise.resolve(response({
      reviews: listCalls === 1 ? [review(8, 'stale review')] : [review(9, 'refreshed review')],
      counts: { pending: 1 },
    }));
  });
  await act(async () => root.render(<MerchantReviews />));
  await settle();

  await act(async () => Array.from(container.querySelectorAll('button'))
    .find(button => button.textContent.trim() === 'Approve').click());
  await settle();

  expect(listCalls).toBe(2);
  expect(container.querySelector('[data-testid="reviews-feedback"]').getAttribute('role')).toBe('alert');
  expect(container.textContent).toContain('review is no longer pending');
  expect(container.textContent).not.toContain('Review #8 approved.');
  expect(container.textContent).toContain('refreshed review');
  expect(container.textContent).not.toContain('stale review');
});

test('a malformed successful approve response reports uncertainty without inventing a stale cause', async () => {
  let listCalls = 0;
  global.fetch.mockImplementation((url) => {
    const value = String(url);
    if (value.includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    if (value.endsWith('/approve')) return Promise.resolve(response({}));
    listCalls += 1;
    return Promise.resolve(response({ reviews: [review(8)], counts: { pending: 1 } }));
  });
  await act(async () => root.render(<MerchantReviews />));
  await settle();

  await act(async () => Array.from(container.querySelectorAll('button'))
    .find(button => button.textContent.trim() === 'Approve').click());
  await settle();

  expect(listCalls).toBe(2);
  expect(container.querySelector('[data-testid="reviews-feedback"]').getAttribute('role')).toBe('alert');
  expect(container.textContent).toContain('change to review #8 could not be confirmed');
  expect(container.textContent).not.toContain('no longer pending');
  expect(container.textContent).not.toContain('Review #8 approved.');
  expect(container.textContent).not.toContain('list was refreshed');
});

test('reject requires ok true and refreshes the current list without false success', async () => {
  let listCalls = 0;
  global.fetch.mockImplementation((url) => {
    const value = String(url);
    if (value.includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    if (value.endsWith('/reject')) return Promise.resolve(response({ ok: false }));
    listCalls += 1;
    return Promise.resolve(response({
      reviews: listCalls === 1 ? [review(8, 'stale review')] : [review(10, 'refreshed after reject')],
      counts: { pending: 1 },
    }));
  });
  await act(async () => root.render(<MerchantReviews />));
  await settle();

  await act(async () => Array.from(container.querySelectorAll('button'))
    .find(button => button.textContent.trim() === 'Reject').click());
  await act(async () => container.querySelector('[role="dialog"] .ss-btn--danger').click());
  await settle();

  expect(listCalls).toBe(2);
  expect(container.querySelector('[data-testid="reviews-feedback"]').getAttribute('role')).toBe('alert');
  expect(container.textContent).toContain('Review #8 was not rejected');
  expect(container.textContent).not.toContain('Review #8 rejected.');
  expect(container.textContent).toContain('refreshed after reject');
  expect(container.querySelector('[role="dialog"]')).toBeNull();
});

test('a mutation completed after a filter change refreshes only the current filter', async () => {
  const approval = deferred();
  const reviewUrls = [];
  global.fetch.mockImplementation((url) => {
    const value = String(url);
    if (value.includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    if (value.endsWith('/approve')) return approval.promise;
    reviewUrls.push(value);
    if (value.includes('min_rating=2')) {
      return Promise.resolve(response({ reviews: [review(22, 'current filter')], counts: { pending: 1 } }));
    }
    return Promise.resolve(response({ reviews: [review(8, 'original filter')], counts: { pending: 1 } }));
  });
  await act(async () => root.render(<MerchantReviews />));
  await settle();

  await act(async () => Array.from(container.querySelectorAll('button'))
    .find(button => button.textContent.trim() === 'Approve').click());
  const minRating = Array.from(container.querySelectorAll('select'))[1];
  await act(async () => {
    minRating.value = '2';
    minRating.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await settle();
  expect(container.textContent).toContain('current filter');

  await act(async () => {
    approval.resolve(response({ ok: true }));
    await approval.promise;
    await Promise.resolve();
    await Promise.resolve();
  });
  const loadsAfterInitial = reviewUrls.slice(1);
  expect(loadsAfterInitial).toHaveLength(2);
  expect(loadsAfterInitial.every(url => url.includes('min_rating=2'))).toBe(true);
  expect(container.textContent).toContain('current filter');
  expect(container.textContent).not.toContain('original filter');
});

test('partial moderation keeps real decisions and reports the stop reason as an error', async () => {
  let listCalls = 0;
  global.fetch.mockImplementation((url) => {
    const value = String(url);
    if (value.includes('/merchant/products')) return Promise.resolve(response({ products: [] }));
    if (value.includes('/moderate-all')) {
      return Promise.resolve(response({
        ok: false,
        processed: 1,
        stopReason: 'moderation budget exhausted',
        decisions: [{ review_id: 4, product_id: 2, applied_decision: 'approve', notes: 'processed before stop' }],
      }));
    }
    listCalls += 1;
    return Promise.resolve(response({ reviews: [review(4)], counts: { pending: 1 } }));
  });
  await act(async () => root.render(<MerchantReviews />));
  await settle();

  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click());
  await settle();

  expect(container.querySelector('[data-testid="reviews-feedback"]').getAttribute('role')).toBe('alert');
  expect(container.textContent).toContain('moderation budget exhausted');
  expect(container.textContent).toContain('processed before stop');
  expect(listCalls).toBe(2);
});

const moderationKey = 'b'.repeat(64);
function applied(reviewId, decision = 'approve') {
  return { review_id: reviewId, product_id: 2, applied_decision: decision,
    notes: null, applied: { ok: true, review_id: reviewId } };
}
function moderationResult(requested, considered, continuationRequired, decisions = [], ok = true) {
  return { ok, processed: decisions.length, decisions,
    stopReason: ok ? 'end_turn' : 'max_steps',
    batch: { requested, considered, complete: true, continuationRequired } };
}
async function boundModerationFixture(onPost) {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  const posts = [];
  const saved = new Map();
  const lookups = [];
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'merchant.products.list') return response({ products: [] });
    if (operation === 'merchant.reviews.list') return response({ reviews: [review(4)], counts: { pending: 1 } });
    if (operation === 'merchant.reviews.moderationReceipt') {
      const requestId = input.params.requestId;
      const requestedLimit = Number(input.query.limit);
      lookups.push({ requestId, requestedLimit, recoveryScopeKey: input.query.recoveryScopeKey || null });
      return response({ version: 1, requestId, requestedLimit, recoveryScopeKey: moderationKey,
        state: saved.has(requestId) ? 'completed' : 'not_found',
        result: saved.get(requestId) || null });
    }
    if (operation === 'merchant.reviews.moderateAll') {
      posts.push(input.body);
      return onPost(input.body, posts.length, result => saved.set(input.body.request_id, result));
    }
    throw new Error('unexpected ' + operation);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  return { posts, saved, lookups, bridge };
}

test('bound moderation persists and checks each original batch before a fresh remaining-quota POST', async () => {
  const f = await boundModerationFixture((body, index, save) => {
    const result = index === 1
      ? moderationResult(100, 2, true, [applied(1), applied(11)])
      : moderationResult(98, 1, false, [applied(2, 'reject')]);
    save(result); return response(result);
  });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  expect(f.posts).toHaveLength(0);
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click()); await settle();
  expect(f.posts.map(row => row.limit)).toEqual([100, 98]);
  expect(f.posts[1].request_id).not.toBe(f.posts[0].request_id);
  expect(f.posts.every(row => row.recoveryScopeKey === moderationKey)).toBe(true);
  expect(f.lookups.map(row => row.recoveryScopeKey)).toEqual([null, moderationKey,
    moderationKey, moderationKey]);
  expect(container.textContent).toContain('MODERATE_PENDING · 3 PROCESSED');
  expect(container.textContent).toContain('approve');
  expect(container.textContent).toContain('reject');
  expect(container.querySelector('[data-testid="reviews-moderate-all"]').disabled).toBe(false);
});

test('100 considered reviews can span twenty five-review batches without claiming every pending review', async () => {
  const f = await boundModerationFixture((body, index, save) => {
    const result = moderationResult(body.limit, 5, index < 20);
    save(result); return response(result);
  });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click()); await settle();
  expect(f.posts).toHaveLength(20);
  expect(f.posts.map(row => row.limit)).toEqual(Array.from({ length: 20 }, (_, i) => 100 - i * 5));
  expect(new Set(f.posts.map(row => row.request_id)).size).toBe(20);
  expect(container.querySelector('[data-testid="reviews-feedback"]').textContent)
    .toContain('This run reached its 100-review limit; pending reviews may remain');
});

test('lost second acknowledgement stops mutation; Check is GET-only and Continue is a separate click', async () => {
  const f = await boundModerationFixture((body, index, save) => {
    const result = index === 1 ? moderationResult(100, 5, true, [applied(1)])
      : index === 2 ? moderationResult(95, 1, true, [applied(2, 'reject')])
        : moderationResult(94, 1, false, [applied(3)]);
    save(result);
    return index === 2 ? Promise.reject(new Error('batch response lost')) : response(result);
  });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click()); await settle();
  expect(f.posts).toHaveLength(2);
  expect(container.textContent).toContain('batch response lost');
  expect(container.querySelector('[data-testid="reviews-moderate-all"]').disabled).toBe(true);
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Check saved moderation').click()); await settle();
  expect(f.posts).toHaveLength(2);
  expect(container.textContent).toContain('Continue remaining');
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Continue remaining').click()); await settle();
  expect(f.posts).toHaveLength(3);
  expect(f.posts[2].limit).toBe(94);
  expect(f.posts[2].request_id).not.toBe(f.posts[1].request_id);
  expect(container.textContent).toContain('MODERATE_PENDING · 3 PROCESSED');
});

test('malformed completed receipt leaves the saved batch unresolved and forbids another POST', async () => {
  const f = await boundModerationFixture((body, index, save) => {
    save({ ...moderationResult(body.limit, 1, false), batch: { requested: '100',
      considered: 1, complete: true, continuationRequired: false } });
    return response({ ok: true });
  });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click()); await settle();
  expect(f.posts).toHaveLength(1);
  expect(container.textContent).toContain('saved moderation batch');
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Check saved moderation').click()); await settle();
  expect(f.posts).toHaveLength(1);
  expect(container.querySelector('[data-testid="reviews-moderate-all"]').disabled).toBe(true);
});

test('reload exposes a saved unknown batch but never resends it automatically', async () => {
  const f = await boundModerationFixture((body, index, save) =>
    Promise.reject(new Error('response lost')));
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click()); await settle();
  expect(f.posts).toHaveLength(1);
  await act(async () => root.unmount());
  root = createRoot(container);
  await act(async () => root.render(<MerchantReviews />)); await settle();
  expect(f.posts).toHaveLength(1);
  expect(container.textContent).toContain('saved moderation batch');
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Check saved moderation').click()); await settle();
  expect(f.posts).toHaveLength(1);
  expect(container.textContent).toContain('No completed moderation receipt observed yet');
});

test('known completed model failure with partial effects is terminal, not a retry permit', async () => {
  const f = await boundModerationFixture((body, index, save) => {
    const result = moderationResult(100, 2, true, [applied(5)], false);
    save(result); return response(result);
  });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click()); await settle();
  expect(f.posts).toHaveLength(1);
  expect(container.textContent).toContain('MODERATE_PENDING · 1 PROCESSED');
  expect(container.textContent).not.toContain('Continue remaining');
  expect(container.querySelector('[data-testid="reviews-feedback"]').getAttribute('role')).toBe('alert');
});

test('authority A→B→A with the same transport fences stale receipt and preserves pending', async () => {
  const deferredReceipt = deferred();
  const f = await boundModerationFixture((body, index, save) => {
    save(moderationResult(100, 1, false, [applied(7)]));
    return response({ ok: true });
  });
  const original = f.bridge.request.getMockImplementation();
  f.bridge.request.mockImplementation((operation, input) => {
    if (operation === 'merchant.reviews.moderationReceipt' && input.query.recoveryScopeKey)
      return deferredReceipt.promise;
    return original(operation, input);
  });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click());
  expect(f.posts).toHaveLength(1);
  mockUser = { id: 88, role: 'merchant' };
  await act(async () => root.render(<MerchantReviews />)); await settle();
  mockUser = { id: 77, role: 'merchant' };
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => { deferredReceipt.resolve(response({ version: 1,
    requestId: f.posts[0].request_id, requestedLimit: 100, recoveryScopeKey: moderationKey,
    state: 'completed', result: moderationResult(100, 1, false, [applied(7)]) }));
    await deferredReceipt.promise; });
  expect(container.textContent).not.toContain('MODERATE_PENDING · 1 PROCESSED');
  expect(container.querySelector('[data-testid="reviews-moderate-all"]').disabled).toBe(true);
  expect(f.posts).toHaveLength(1);
});

test('storage persistence failure and StrictMode replay cannot authorize an original POST', async () => {
  const spy = jest.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw Error('storage unavailable'); });
  try {
    const f = await boundModerationFixture(() => { throw Error('POST must not run'); });
    await act(async () => root.render(<React.StrictMode><MerchantReviews /></React.StrictMode>)); await settle();
    await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click()); await settle();
    expect(f.posts).toHaveLength(0);
    expect(container.textContent).toContain('storage unavailable');
  } finally { spy.mockRestore(); }
});

test('healthy StrictMode mount and replay do not submit until one explicit click', async () => {
  const f = await boundModerationFixture((body, index, save) => {
    const result = moderationResult(100, 1, false, [applied(9)]);
    save(result); return response(result);
  });
  await act(async () => root.render(<React.StrictMode><MerchantReviews /></React.StrictMode>));
  await settle();
  expect(f.posts).toHaveLength(0);
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click());
  await settle();
  expect(f.posts).toHaveLength(1);
  expect(container.textContent).toContain('MODERATE_PENDING · 1 PROCESSED');
});

test('shop bearer changing before React rerender cannot clear a completed pending receipt', async () => {
  const pendingReceipt = deferred();
  const f = await boundModerationFixture((body, index, save) => {
    save(moderationResult(100, 1, false, [applied(10)]));
    return response({ ok: true });
  });
  const original = f.bridge.request.getMockImplementation();
  f.bridge.request.mockImplementation((operation, input) =>
    operation === 'merchant.reviews.moderationReceipt' && input.query.recoveryScopeKey
      ? pendingReceipt.promise : original(operation, input));
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click());
  expect(f.posts).toHaveLength(1);
  localStorage.setItem('secureshop_v2_token', 'different-bearer');
  await act(async () => {
    pendingReceipt.resolve(response({ version: 1, requestId: f.posts[0].request_id,
      requestedLimit: 100, recoveryScopeKey: moderationKey, state: 'completed',
      result: moderationResult(100, 1, false, [applied(10)]) }));
    await pendingReceipt.promise;
  });
  expect(container.textContent).not.toContain('MODERATE_PENDING · 1 PROCESSED');
  expect(localStorage.getItem('secureshop.review-moderation.pending.v1')).not.toBeNull();
  expect(f.posts).toHaveLength(1);
});

test('transport replacement before rerender fences the old completed receipt', async () => {
  const pendingReceipt = deferred();
  const f = await boundModerationFixture((body, index, save) => {
    save(moderationResult(100, 1, false, [applied(11)]));
    return response({ ok: true });
  });
  const oldTransport = global.fetch;
  const original = f.bridge.request.getMockImplementation();
  f.bridge.request.mockImplementation((operation, input) =>
    operation === 'merchant.reviews.moderationReceipt' && input.query.recoveryScopeKey
      ? pendingReceipt.promise : original(operation, input));
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click());
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  global.fetch = createBridgeFetch({ bridge: f.bridge, origin: window.location.origin, boundReviews: true });
  expect(global.fetch).not.toBe(oldTransport);
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => {
    pendingReceipt.resolve(response({ version: 1, requestId: f.posts[0].request_id,
      requestedLimit: 100, recoveryScopeKey: moderationKey, state: 'completed',
      result: moderationResult(100, 1, false, [applied(11)]) }));
    await pendingReceipt.promise;
  });
  expect(container.textContent).not.toContain('MODERATE_PENDING · 1 PROCESSED');
  expect(localStorage.getItem('secureshop.review-moderation.pending.v1')).not.toBeNull();
  expect(f.posts).toHaveLength(1);
});

test('storage disconnect during receipt readback cannot publish or clear the saved batch', async () => {
  const pendingReceipt = deferred();
  const f = await boundModerationFixture((body, index, save) => {
    save(moderationResult(100, 1, false, [applied(12)]));
    return response({ ok: true });
  });
  const original = f.bridge.request.getMockImplementation();
  f.bridge.request.mockImplementation((operation, input) =>
    operation === 'merchant.reviews.moderationReceipt' && input.query.recoveryScopeKey
      ? pendingReceipt.promise : original(operation, input));
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click());
  const blocked = jest.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
    throw new DOMException('Shop storage disconnected', 'AbortError');
  });
  try {
    await act(async () => {
      pendingReceipt.resolve(response({ version: 1, requestId: f.posts[0].request_id,
        requestedLimit: 100, recoveryScopeKey: moderationKey, state: 'completed',
        result: moderationResult(100, 1, false, [applied(12)]) }));
      await pendingReceipt.promise;
    });
    expect(container.textContent).not.toContain('MODERATE_PENDING · 1 PROCESSED');
    expect(container.textContent).toContain('Saved moderation storage is unavailable');
  } finally { blocked.mockRestore(); }
  expect(localStorage.getItem('secureshop.review-moderation.pending.v1')).not.toBeNull();
  expect(f.posts).toHaveLength(1);
});
test('bound manual decisions remain disabled without an explicit recovery capability', async () => {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  const bridge={request:jest.fn(async(op)=>response(op==='merchant.products.list'?{products:[]}:{reviews:[review(4)],counts:{pending:1}}))};
  global.fetch=createBridgeFetch({bridge,origin:window.location.origin,boundReviews:true});
  await act(async()=>root.render(<MerchantReviews/>));await settle();
  for(const label of ['Approve','Reject'])expect([...container.querySelectorAll('button')].find(b=>b.textContent.trim()===label).disabled).toBe(true);
});

test('lost manual acknowledgement retains the exact operation and recovers its receipt without another POST', async()=>{
 const {createBridgeFetch}=await import('../../bridge/fetchAdapter.mjs');
 const scopeKey=JSON.stringify(['12345678-1234-4123-8123-123456789abd',2,1,20,77,'12345678-1234-4123-8123-123456789abe']);let saved;let writes=0;
 const bridge={request:jest.fn(async(op,input)=>{
  if(op==='merchant.products.list')return response({products:[]});
  if(op==='merchant.reviews.list')return response({reviews:[review(4)],counts:{pending:1},manual_decisions:{available:true,scopeKey}});
  if(op==='merchant.reviews.approve'){writes++;saved=input.body.operationId;throw Error('lost acknowledgement');}
  if(op==='merchant.reviews.operation')return response({ok:true,executionScopeKey:scopeKey,receipt:{operationId:saved,kind:'manual',moderatorKind:'manual',reviewId:4,decision:'approved',notes:null,applied:true,resultStatus:'approved',scope:{targetId:'12345678-1234-4123-8123-123456789abf',launchId:'12345678-1234-4123-8123-123456789ac0',scenarioId:'12345678-1234-4123-8123-123456789ac1',generation:1,platformOwnerId:1,platformSessionId:10},actor:{id:77,role:'merchant',personaSessionId:'12345678-1234-4123-8123-123456789abe'}}});
  throw Error('unexpected '+op);
 })};
 global.fetch=createBridgeFetch({bridge,origin:window.location.origin,boundReviews:true});
 await act(async()=>root.render(<MerchantReviews/>));await settle();
 await act(async()=>[...container.querySelectorAll('button')].find(b=>b.textContent.trim()==='Approve').click());await settle();
 expect(writes).toBe(1);expect(JSON.parse(localStorage.getItem('ss_review_decision_pending')).operationId).toBe(saved);
 expect([...container.querySelectorAll('button')].find(b=>b.textContent.trim()==='Reject').disabled).toBe(true);
 await act(async()=>[...container.querySelectorAll('button')].find(b=>b.textContent==='Refresh decision status').click());await settle();
 expect(writes).toBe(1);expect(localStorage.getItem('ss_review_decision_pending')).toBe(null);expect(container.textContent).toContain('Review #4 approved.');
});
