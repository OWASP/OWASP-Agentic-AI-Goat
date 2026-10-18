import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Product from './Product';

Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Request = web.Request;
global.Response = web.Response;
global.Headers = web.Headers;

let mockToast = { success: jest.fn(), error: jest.fn() };
let mockProductId = '7';
let mockUser = { id: 41, role: 'customer' };
jest.mock('react-router-dom', () => ({
  useParams: () => ({ id: mockProductId }),
  Link: ({ children, ...props }) => <a {...props}>{children}</a>,
}));
jest.mock('framer-motion', () => {
  const React = require('react');
  const element = tag => React.forwardRef(function Motion(
    { initial, animate, exit, transition, whileHover, whileTap, ...props }, ref,
  ) { return React.createElement(tag, { ...props, ref }); });
  return { motion: { div: element('div'), button: element('button'), blockquote: element('blockquote'), section: element('section') },
    AnimatePresence: ({ children }) => <>{children}</>, useReducedMotion: () => true };
});
jest.mock('../context/CartContext.jsx', () => ({ useCart: () => ({ addItem: jest.fn() }) }));
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({
  user: mockUser, isAuthed: true,
}) }));
jest.mock('../context/ToastContext.jsx', () => ({ useToast: () => mockToast }));
jest.mock('../components/AgentAssist.jsx', () => () => null);

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}
async function settle() {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); });
}
function deferred() {
  let resolve; let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
beforeEach(() => {
  mockProductId = '7'; mockUser = { id: 41, role: 'customer' };
  mockToast = { success: jest.fn(), error: jest.fn() };
});

test('bound Product submission keeps one UUID across response loss and rotates after content changes', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const { createBridgeFetch } = await import('../bridge/fetchAdapter.mjs');
  const submissions = [];
  const browserAttempts = [];
  let submitAttempts = 0;
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'catalog.product.get') return json({ product: { id: 7, name: 'Headphones',
      category: 'Audio', price: 40, stock_quantity: 3, images: [], description: 'Fixture product.' } });
    if (operation === 'catalog.product.summary') return json({ summary: 'Owned fixture summary.' });
    if (operation === 'catalog.product.reviews.list') return json({ reviews: submissions.slice(1).map((row, index) => ({
      id: index + 2, body: row.body, rating: row.rating, status: 'pending', created_at: '2026-09-13T00:00:00Z',
    })) });
    if (operation === 'catalog.product.similar') return json({ results: [] });
    if (operation === 'catalog.product.reviews.create') {
      submissions.push(input.body); submitAttempts += 1;
      if (submitAttempts === 1) return json({ ok: false, error: 'response lost' }, 503);
      return json({ ok: true, review_id: submitAttempts });
    }
    if (operation === 'catalog.product.reviews.browserAttempt') {
      browserAttempts.push(input.body);
      return json({ completed: true });
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<React.StrictMode><Product /></React.StrictMode>)); await settle();
    const textarea = container.querySelector('textarea[aria-label="Review body"]');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set
        .call(textarea, '<b>raw learner review</b>');
      textarea.dispatchEvent(new Event('input', { bubbles: true }));
    });
    const form = textarea.closest('form');
    await act(async () => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await settle();
    expect(mockToast.error).toHaveBeenCalledWith('Post failed: response lost');
    await act(async () => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await settle();
    expect(submissions).toHaveLength(2);
    expect(submissions[1].submission_id).toBe(submissions[0].submission_id);
    expect(submissions[0]).toMatchObject({ author_id: 41, body: '<b>raw learner review</b>', rating: 5 });
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 5)); });
    expect(browserAttempts).toHaveLength(1);

    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set
        .call(textarea, 'a different logical review');
      textarea.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await settle();
    expect(submissions).toHaveLength(3);
    expect(submissions[2].submission_id).not.toBe(submissions[1].submission_id);
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});

test('editing during a submission fences the old response from clearing the new draft', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const { createBridgeFetch } = await import('../bridge/fetchAdapter.mjs');
  const first = deferred(); const second = deferred(); const submissions = [];
  const browserAttempts = [];
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'catalog.product.get') return json({ product: { id: 7, name: 'Headphones',
      category: 'Audio', price: 40, stock_quantity: 3, images: [] } });
    if (operation === 'catalog.product.summary') return json({ summary: 'summary' });
    if (operation === 'catalog.product.reviews.list') return json({ reviews: submissions.length < 2 ? [] : [{
      id: 2, body: 'new owner-visible draft', rating: 5, status: 'pending',
      created_at: '2026-09-13T00:00:00Z',
    }] });
    if (operation === 'catalog.product.similar') return json({ results: [] });
    if (operation === 'catalog.product.reviews.create') {
      submissions.push(input.body);
      return submissions.length === 1 ? first.promise : second.promise;
    }
    if (operation === 'catalog.product.reviews.browserAttempt') {
      browserAttempts.push(input.body); return json({ completed: true });
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    const textarea = container.querySelector('textarea[aria-label="Review body"]');
    const setValue = value => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(textarea, value);
      textarea.dispatchEvent(new Event('input', { bubbles: true }));
    };
    await act(async () => setValue('first draft'));
    const form = textarea.closest('form');
    await act(async () => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await act(async () => setValue('new owner-visible draft'));
    await act(async () => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    expect(submissions).toHaveLength(2);
    expect(submissions[1].submission_id).not.toBe(submissions[0].submission_id);
    await act(async () => { first.resolve(json({ ok: true, review_id: 1 })); await first.promise; });
    await settle();
    expect(textarea.value).toBe('new owner-visible draft');
    await act(async () => { second.resolve(json({ ok: true, review_id: 2 })); await second.promise; });
    await settle(); await act(async () => { await new Promise(resolve => setTimeout(resolve, 5)); });
    expect(textarea.value).toBe('');
    expect(browserAttempts).toHaveLength(1);
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});

test('transient browser assessment retries the same request without reposting the review', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const { createBridgeFetch } = await import('../bridge/fetchAdapter.mjs');
  const submissions = []; const attempts = [];
  const raw = '<img src=x onerror="alert(1)">';
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'catalog.product.get') return json({ product: { id: 7, name: 'Headphones',
      category: 'Audio', price: 40, stock_quantity: 3, images: [] } });
    if (operation === 'catalog.product.summary') return json({ summary: 'summary' });
    if (operation === 'catalog.product.similar') return json({ results: [] });
    if (operation === 'catalog.product.reviews.list') return json({ reviews: submissions.length ? [{
      id: 71, body: raw, rating: 5, status: 'pending', created_at: '2026-09-13T00:00:00Z',
    }] : [] });
    if (operation === 'catalog.product.reviews.create') {
      submissions.push(input.body); return json({ ok: true, review_id: 71 });
    }
    if (operation === 'catalog.product.reviews.browserAttempt') {
      attempts.push(input.body);
      return attempts.length === 1 ? json({ error: 'temporarily unavailable' }, 503)
        : json({ completed: true });
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    const textarea = container.querySelector('textarea[aria-label="Review body"]');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(textarea, raw);
      textarea.dispatchEvent(new Event('input', { bubbles: true }));
    });
    const form = textarea.closest('form');
    await act(async () => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await settle(); await act(async () => { await new Promise(resolve => setTimeout(resolve, 5)); });
    expect(submissions).toHaveLength(1); expect(attempts).toHaveLength(1);
    expect(textarea.value).toBe(raw);
    await act(async () => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await settle(); await act(async () => { await new Promise(resolve => setTimeout(resolve, 5)); });
    expect(submissions).toHaveLength(1); expect(attempts).toHaveLength(2);
    expect(attempts[1].request_id).toBe(attempts[0].request_id);
    expect(textarea.value).toBe('');
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});

test('frame teardown aborts a pending assessment and ignores its late completion', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const { createBridgeFetch } = await import('../bridge/fetchAdapter.mjs');
  const assessment = deferred(); let assessmentSignal; let posted = false;
  const raw = '<img src=x onerror="alert(2)">';
  const bridge = { request: jest.fn(async (operation, input, options) => {
    if (operation === 'catalog.product.get') return json({ product: { id: 7, name: 'Headphones',
      category: 'Audio', price: 40, stock_quantity: 3, images: [] } });
    if (operation === 'catalog.product.summary') return json({ summary: 'summary' });
    if (operation === 'catalog.product.similar') return json({ results: [] });
    if (operation === 'catalog.product.reviews.list') return json({ reviews: posted ? [{ id: 81,
      body: raw, rating: 5, status: 'pending', created_at: '2026-09-13T00:00:00Z' }] : [] });
    if (operation === 'catalog.product.reviews.create') {
      posted = true; return json({ ok: true, review_id: 81 });
    }
    if (operation === 'catalog.product.reviews.browserAttempt') {
      assessmentSignal = options.signal; return assessment.promise;
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => root.render(<React.StrictMode><Product /></React.StrictMode>)); await settle();
  const textarea = container.querySelector('textarea[aria-label="Review body"]');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(textarea, raw);
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => textarea.closest('form')
    .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await settle(); await act(async () => { await new Promise(resolve => setTimeout(resolve, 5)); });
  expect(assessmentSignal).toBeDefined(); expect(assessmentSignal.aborted).toBe(false);
  await act(async () => root.unmount());
  expect(assessmentSignal.aborted).toBe(true);
  assessment.resolve(json({ completed: true }));
  await assessment.promise; await settle();
  expect(mockToast.success).not.toHaveBeenCalledWith('Browser objective completed');
  container.remove();
});

test('presentation refresh preserves an admitted browser assessment for the same rendered review', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const { createBridgeFetch } = await import('../bridge/fetchAdapter.mjs');
  const assessment = deferred(); let assessmentSignal; let posted = false;
  const raw = '<img src=x onerror="alert(4)">';
  const bridge = { request: jest.fn(async (operation, input, options) => {
    if (operation === 'catalog.product.get') return json({ product: { id: 7, name: 'Headphones',
      category: 'Audio', price: 40, stock_quantity: 3, images: [] } });
    if (operation === 'catalog.product.summary') return json({ summary: 'summary' });
    if (operation === 'catalog.product.similar') return json({ results: [] });
    if (operation === 'catalog.product.reviews.list') return json({ reviews: posted ? [{ id: 82,
      body: raw, rating: 5, status: 'pending', created_at: '2026-09-13T00:00:00Z' }] : [] });
    if (operation === 'catalog.product.reviews.create') {
      posted = true; return json({ ok: true, review_id: 82 });
    }
    if (operation === 'catalog.product.reviews.browserAttempt') {
      assessmentSignal = options.signal; return assessment.promise;
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    const textarea = container.querySelector('textarea[aria-label="Review body"]');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(textarea, raw);
      textarea.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => textarea.closest('form')
      .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await settle(); await act(async () => { await new Promise(resolve => setTimeout(resolve, 5)); });
    expect(assessmentSignal).toBeDefined(); expect(assessmentSignal.aborted).toBe(false);
    const admittedToast = mockToast;
    mockToast = { success: jest.fn(), error: jest.fn() };
    await act(async () => root.render(<Product />)); await settle();
    expect(assessmentSignal.aborted).toBe(false);
    assessment.resolve(json({ completed: true })); await assessment.promise; await settle();
    expect(admittedToast.success).toHaveBeenCalledWith('Browser objective completed');
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});

test('product and persona transitions discard stale review reads and browser completions', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const { createBridgeFetch } = await import('../bridge/fetchAdapter.mjs');
  const oldRead = deferred(); const assessment = deferred(); let browserSignal;
  let posted = false; let oldReadIssued = false;
  const raw = '<img src=x onerror="alert(3)">';
  const bridge = { request: jest.fn(async (operation, input, options) => {
    if (operation === 'catalog.product.get') return json({ product: { id: Number(input.params.id),
      name: `Product ${input.params.id}`, category: 'Audio', price: 40, stock_quantity: 3, images: [] } });
    if (operation === 'catalog.product.summary') return json({ summary: 'summary' });
    if (operation === 'catalog.product.similar') return json({ results: [] });
    if (operation === 'catalog.product.reviews.list') {
      if (input.params.id === '7' && !posted && !oldReadIssued) {
        oldReadIssued = true; return oldRead.promise;
      }
      return json({ reviews: posted ? [{ id: 91, body: raw, rating: 5, status: 'pending',
        created_at: '2026-09-13T00:00:00Z' }] : [{ id: 92, body: 'current product review',
        rating: 4, status: 'approved', created_at: '2026-09-13T00:00:00Z' }] });
    }
    if (operation === 'catalog.product.reviews.create') {
      posted = true; return json({ ok: true, review_id: 91 });
    }
    if (operation === 'catalog.product.reviews.browserAttempt') {
      browserSignal = options.signal; return assessment.promise;
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => root.render(<Product />)); await settle();
  mockProductId = '8';
  await act(async () => root.render(<Product />)); await settle();
  oldRead.resolve(json({ reviews: [{ id: 1, body: 'stale product review' }] }));
  await oldRead.promise; await settle();
  expect(container.textContent).toContain('current product review');
  expect(container.textContent).not.toContain('stale product review');

  mockProductId = '7';
  await act(async () => root.render(<Product />)); await settle();
  const textarea = container.querySelector('textarea[aria-label="Review body"]');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(textarea, raw);
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => textarea.closest('form')
    .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await settle(); await act(async () => { await new Promise(resolve => setTimeout(resolve, 5)); });
  expect(browserSignal).toBeDefined(); expect(browserSignal.aborted).toBe(false);
  mockUser = { id: 42, role: 'customer' };
  await act(async () => root.render(<Product />)); await settle();
  expect(browserSignal.aborted).toBe(true);
  assessment.resolve(json({ completed: true })); await assessment.promise; await settle();
  expect(mockToast.success).not.toHaveBeenCalledWith('Browser objective completed');
  await act(async () => root.unmount()); container.remove();
});

test('reviews show total, page through the closed read, and reset for another product', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const { createBridgeFetch } = await import('../bridge/fetchAdapter.mjs');
  const requested = [];
  const bridge = { request: jest.fn(async (operation, input) => {
    if (operation === 'catalog.product.get') return json({ product: {
      id: Number(input.params.id), name: `Product ${input.params.id}`, category: 'Audio',
      price: 40, stock_quantity: 3, images: [], review_count: input.params.id === '7' ? 25 : 1,
    } });
    if (operation === 'catalog.product.summary') return json({ summary: 'summary' });
    if (operation === 'catalog.product.similar') return json({ results: [] });
    if (operation === 'catalog.product.reviews.list') {
      requested.push({ id: input.params.id, offset: input.query.offset });
      const offset = Number(input.query.offset);
      const total = input.params.id === '7' ? 25 : 1;
      return json({ total, reviews: Array.from({ length: Math.min(20, total - offset) }, (_, index) => ({
        id: offset + index + 1, body: `Review ${offset + index + 1}`, rating: 5,
        status: 'approved', created_at: '2026-09-13T00:00:00Z',
      })) });
    }
    throw new Error(`unexpected ${operation}`);
  }) };
  global.fetch = createBridgeFetch({ bridge, origin: window.location.origin, boundReviews: true });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    expect(container.textContent).toContain('Reviews (25)');
    expect(container.textContent).toContain('Showing 1–20 of 25');
    const next = [...container.querySelectorAll('button')].find(button => button.textContent === 'Next');
    await act(async () => next.click()); await settle();
    expect(requested).toContainEqual({ id: '7', offset: '20' });
    expect(container.textContent).toContain('Review 25');
    expect(container.textContent).toContain('Showing 21–25 of 25');
    mockProductId = '8';
    await act(async () => root.render(<Product />)); await settle();
    expect(requested).toContainEqual({ id: '8', offset: '0' });
    expect(container.textContent).toContain('Reviews (1)');
    expect(container.textContent).not.toContain('Review 25');
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});
