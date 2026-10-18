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
jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser }) }));

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

test('bound moderation continues valid batches with remaining quota and fresh request IDs', async () => {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  const requests = [];
  let moderationCalls = 0;
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'merchant.products.list') return response({ products: [] });
    if (operation === 'merchant.reviews.list') return response({ reviews: [], counts: {} });
    if (operation === 'merchant.reviews.moderateAll') {
      requests.push(input.body); moderationCalls += 1;
      return response(moderationCalls === 1
        ? { ok: true, processed: 2, decisions: [{ review_id: 1, applied_decision: 'approve' }, { review_id: 11, applied_decision: 'approve' }],
          batch: { requested: 100, considered: 2, complete: true, continuationRequired: true } }
        : { ok: true, processed: 1, decisions: [{ review_id: 2, applied_decision: 'reject' }],
          batch: { requested: 98, considered: 1, complete: true, continuationRequired: false } });
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click()); await settle();
  expect(requests.map(r => r.limit)).toEqual([100, 98]);
  expect(requests[1].request_id).not.toBe(requests[0].request_id);
  expect(container.textContent).toContain('MODERATE_PENDING · 3 PROCESSED');
  expect(container.textContent).toContain('approve');
  expect(container.textContent).toContain('reject');
});

test('a full 100-review batch reports its limit without claiming every pending review was handled', async () => {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  const requests = [];
  const decisions = Array.from({ length: 100 }, (_, index) => ({
    review_id: index + 1, applied_decision: 'approve', product_id: 2,
  }));
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'merchant.products.list') return response({ products: [] });
    if (operation === 'merchant.reviews.list') return response({ reviews: [], counts: { pending: 1 } });
    if (operation === 'merchant.reviews.moderateAll') {
      requests.push(input.body);
      return response({ ok: true, processed: 100, decisions,
        batch: { requested: 100, considered: 100, complete: true, continuationRequired: false } });
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  const button = container.querySelector('[data-testid="reviews-moderate-all"]');
  expect(button.textContent).toContain('Moderate pending');
  await act(async () => button.click()); await settle();
  expect(requests).toHaveLength(1);
  expect(requests[0].limit).toBe(100);
  const feedback = container.querySelector('[data-testid="reviews-feedback"]');
  expect(feedback.getAttribute('role')).toBe('status');
  expect(feedback.textContent).toContain('Moderated 100 review(s) in this run.');
  expect(feedback.textContent).toContain('pending reviews may remain');
  expect(feedback.textContent).not.toMatch(/all pending|every pending/i);
});

test('zero-progress batch fails closed without automatically issuing another batch', async () => {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  let moderationCalls = 0;
  const bridge = { request: jest.fn(async operation => {
    if (operation === 'merchant.products.list') return response({ products: [] });
    if (operation === 'merchant.reviews.list') return response({ reviews: [], counts: {} });
    if (operation === 'merchant.reviews.moderateAll') {
      moderationCalls += 1;
      return response({ ok: true, processed: 0, decisions: [],
        batch: { requested: 100, considered: 0, complete: true, continuationRequired: true } });
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click()); await settle();
  expect(moderationCalls).toBe(1);
  expect(container.querySelector('[data-testid="reviews-feedback"]').textContent)
    .toContain('incomplete batch response');
});

test('a failed continuation resumes its own UUID and remaining quota without replaying batch one', async () => {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  const requests = [];
  let calls = 0;
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'merchant.products.list') return response({ products: [] });
    if (operation === 'merchant.reviews.list') return response({ reviews: [], counts: {} });
    if (operation === 'merchant.reviews.moderateAll') {
      requests.push(input.body); calls += 1;
      if (calls === 1) return response({ ok: true, processed: 1,
        decisions: [{ review_id: 1, applied_decision: 'approve', notes: 'first' }],
        batch: { requested: 100, considered: 5, complete: true, continuationRequired: true } });
      if (calls === 2) throw new Error('batch two response lost');
      return response({ ok: true, processed: 1,
        decisions: [{ review_id: 2, applied_decision: 'reject', notes: 'second' }],
        batch: { requested: 95, considered: 1, complete: true, continuationRequired: false } });
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  const button = container.querySelector('[data-testid="reviews-moderate-all"]');
  await act(async () => button.click()); await settle();
  expect(requests).toHaveLength(2);
  expect(requests[1].limit).toBe(95);
  expect(container.textContent).toContain('first');
  await act(async () => button.click()); await settle();
  expect(requests).toHaveLength(3);
  expect(requests[2].request_id).toBe(requests[1].request_id);
  expect(requests[2].limit).toBe(95);
  expect(container.textContent).toContain('first');
  expect(container.textContent).toContain('second');
});

test('a malformed continuation response is retryable with the same batch UUID', async () => {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  const requests = [];
  let calls = 0;
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'merchant.products.list') return response({ products: [] });
    if (operation === 'merchant.reviews.list') return response({ reviews: [], counts: {} });
    if (operation === 'merchant.reviews.moderateAll') {
      requests.push(input.body); calls += 1;
      if (calls === 1) return response({ ok: true, processed: 1,
        decisions: [{ review_id: 3, applied_decision: 'approve', notes: 'retained' }],
        batch: { requested: 100, considered: 4, complete: true, continuationRequired: true } });
      if (calls === 2) return response({ ok: true, processed: 1,
        decisions: [{ review_id: 99, applied_decision: 'approve' }],
        batch: { requested: '96', considered: null, complete: true, continuationRequired: true } });
      return response({ ok: true, processed: 1, decisions: [{ review_id: 4, applied_decision: 'approve' }],
        batch: { requested: 96, considered: 1, complete: true, continuationRequired: false } });
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  const button = container.querySelector('[data-testid="reviews-moderate-all"]');
  await act(async () => button.click()); await settle();
  const secondId = requests[1].request_id;
  expect(requests).toHaveLength(2);
  expect(container.textContent).toContain('retained');
  await act(async () => button.click()); await settle();
  expect(requests).toHaveLength(3);
  expect(requests[2].request_id).toBe(secondId);
  expect(requests[2].limit).toBe(96);
  expect(container.textContent).toContain('retained');
  expect(container.textContent).toContain('#4');
});

test('unmount during a continuation prevents later batches', async () => {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  const second = deferred();
  const requests = [];
  let calls = 0;
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'merchant.products.list') return response({ products: [] });
    if (operation === 'merchant.reviews.list') return response({ reviews: [], counts: {} });
    if (operation === 'merchant.reviews.moderateAll') {
      requests.push(input.body); calls += 1;
      if (calls === 1) return response({ ok: true, processed: 1, decisions: [{ review_id: 5, applied_decision: 'approve' }],
        batch: { requested: 100, considered: 5, complete: true, continuationRequired: true } });
      return second.promise;
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click());
  await settle();
  expect(requests).toHaveLength(2);
  await act(async () => root.unmount());
  await act(async () => {
    second.resolve(response({ ok: true, processed: 1, decisions: [{ review_id: 6, applied_decision: 'approve' }],
      batch: { requested: 95, considered: 1, complete: true, continuationRequired: true } }));
    await second.promise;
  });
  expect(requests).toHaveLength(2);
});

test('bound moderation reuses its request UUID after failure and rotates it after success', async () => {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  const calls = [];
  let attempts = 0;
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'merchant.products.list') return response({ products: [] });
    if (operation === 'merchant.reviews.list') return response({ reviews: [review(4)], counts: { pending: 1 } });
    if (operation === 'merchant.reviews.moderateAll') {
      calls.push(input.body.request_id); attempts += 1;
      if (attempts === 1) throw new Error('response lost');
      return response({ ok: true, processed: 1, decisions: [] });
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  await act(async () => root.render(<MerchantReviews />));
  await settle();
  const button = container.querySelector('[data-testid="reviews-moderate-all"]');
  await act(async () => button.click()); await settle();
  expect(container.textContent).toContain('response lost');
  await act(async () => button.click()); await settle();
  expect(calls).toHaveLength(2);
  expect(calls[1]).toBe(calls[0]);
  await act(async () => button.click()); await settle();
  expect(calls).toHaveLength(3);
  expect(calls[2]).not.toBe(calls[1]);
});

test('persona transition fences an older moderation response and rotates request identity', async () => {
  const { createBridgeFetch } = await import('../../bridge/fetchAdapter.mjs');
  const first = deferred(); const second = deferred(); const ids = [];
  let moderationCalls = 0;
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'merchant.products.list') return response({ products: [] });
    if (operation === 'merchant.reviews.list') return response({ reviews: [review(4)], counts: { pending: 1 } });
    if (operation === 'merchant.reviews.moderateAll') {
      ids.push(input.body.request_id); moderationCalls += 1;
      return moderationCalls === 1 ? first.promise : second.promise;
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click());
  mockUser = { id: 88, role: 'merchant' };
  await act(async () => root.render(<MerchantReviews />)); await settle();
  await act(async () => container.querySelector('[data-testid="reviews-moderate-all"]').click());
  expect(ids).toHaveLength(2); expect(ids[1]).not.toBe(ids[0]);
  await act(async () => { first.resolve(response({ ok: true, processed: 99, decisions: [] })); await first.promise; });
  await settle();
  expect(container.textContent).not.toContain('Moderated 99 review(s)');
  await act(async () => { second.resolve(response({ ok: true, processed: 1, decisions: [] })); await second.promise; });
  await settle();
  expect(container.textContent).toContain('Moderated 1 review(s) in this run.');
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
