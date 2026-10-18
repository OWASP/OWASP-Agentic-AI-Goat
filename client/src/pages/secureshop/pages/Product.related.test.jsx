import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Product from './Product';
import { useProductSimilar } from '../hooks/useProductSimilar.js';

Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Request = web.Request;
global.Response = web.Response;
global.Headers = web.Headers;

let mockProductId = '7';
let mockSummaryText = new Map();
let mockSummaryReadDenied = false;
let mockSummaryAssessment = {completed:false,status:'ineligible',modelEvaluated:false};
let mockToast = { success: jest.fn(), error: jest.fn() };
let mockAuthState = { user: { id: 41, role: 'customer' }, isAuthed: true };
jest.mock('react-router-dom', () => ({
  useParams: () => ({ id: mockProductId }),
  Link: ({ children, to, ...props }) => <a href={to} {...props}>{children}</a>,
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
jest.mock('../context/AuthContext', () => ({ useAuth: () => mockAuthState }));
jest.mock('../context/ToastContext.jsx', () => ({ useToast: () => mockToast }));
jest.mock('../components/AgentAssist.jsx', () => () => null);
jest.mock('../hooks/useProductSimilar.js', () => ({ useProductSimilar: jest.fn() }));
jest.mock('../components/ProductCard.jsx', () => ({ product }) => (
  <div data-testid={`related-${product.id}`}>{product.name}</div>
));

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}
function deferred() {
  let resolve;
  const promise = new Promise(yes => { resolve = yes; });
  return { promise, resolve };
}
async function settle() {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); });
}
function ordinary(url) {
  if (String(url).endsWith('/summary/session')) return json({sessionId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',recoveryKey:'a'.repeat(64)});
  const saved = /\/products\/(\d+)\/summary\/sessions\/([^/]+)\/requests\/([^/]+)$/.exec(String(url));
  if (saved) {
    if (mockSummaryReadDenied) return json({error:'Shop session unavailable'},401);
    return json({status:'completed',result:{product_id:Number(saved[1]),name:'Owned',price:12,category:'Home',stock_quantity:3,
      description:'Original source',description_html:null,summary:mockSummaryText.get(Number(saved[1])) || 'Current summary',
      provider:'ollama',model:'controlled',sessionId:saved[2],requestId:saved[3]}});
  }
  if (String(url).endsWith('/product-summary/assessment')) return json(mockSummaryAssessment);
  const match = /\/products\/(\d+)$/.exec(String(url));
  if (match) return json({ product: { id: Number(match[1]), name: `Product ${match[1]}`,
    category: 'Home', price: 12, stock_quantity: 3, images: [] } });
  if (String(url).endsWith('/summary')) return json({ summary: 'Current summary' });
  if (String(url).includes('/reviews?')) return json({ reviews: [] });
  return null;
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockProductId = '7';
  localStorage.clear(); mockSummaryText = new Map(); mockSummaryReadDenied = false;
  mockSummaryAssessment = {completed:false,status:'ineligible',modelEvaluated:false};
  mockToast = { success: jest.fn(), error: jest.fn() };
  mockAuthState = { user: { id: 41, role: 'customer' }, isAuthed: true };
  useProductSimilar.mockReturnValue({ reference: null, outcome: null, busy: false, error: null,
    accessLost: false, validProduct: true, start: jest.fn(), check: jest.fn(),
    retryNotFound: jest.fn(), clearCompleted: jest.fn() });
});

test('guest product view does not claim an agent summary or run the model on load', async () => {
  mockAuthState = { user: null, isAuthed: false };
  global.fetch = jest.fn(async url => ordinary(url)
    || (String(url).endsWith('/similar') ? json({ results: [], recommendation: '' }) : json({ reviews: [] })));
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    expect(container.querySelector('nav[aria-label="Breadcrumb"] a').getAttribute('href')).toBe('/secureshop');
    expect(container.textContent).toContain('Sign in to generate an AI summary');
    expect(container.textContent).not.toContain('Summarized by SUMMARIZER agent');
    expect(global.fetch.mock.calls.some(([url]) => String(url).endsWith('/summary'))).toBe(false);
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});

test.each([
  ['customer', '/secureshop/home'],
  ['merchant', '/secureshop/merchant'],
  ['admin', '/secureshop/admin'],
])('authenticated %s product breadcrumb targets its role home', async (role, expected) => {
  mockAuthState = { user: { id: 41, role }, isAuthed: true };
  global.fetch = jest.fn(async url => ordinary(url)
    || (String(url).endsWith('/similar') ? json({ results: [], recommendation: '' }) : json({ reviews: [] })));
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    expect(container.querySelector('nav[aria-label="Breadcrumb"] a').getAttribute('href')).toBe(expected);
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});

test.each([404, 503])('product %s distinguishes missing products from service failures and recovers on navigation', async status => {
  mockAuthState = { user: null, isAuthed: false };
  global.fetch = jest.fn(async url => String(url).endsWith('/products/7')
    ? json({ error: status === 404 ? 'not found' : 'Catalog temporarily unavailable' }, status)
    : ordinary(url) || json({ results: [], reviews: [] }));
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    expect(container.textContent).toContain(status === 404 ? 'Product not found' : 'Product unavailable');
    expect(container.textContent).toContain(status === 404
      ? "The product you're looking for doesn't exist or was removed." : 'Catalog temporarily unavailable');
    mockProductId = '8';
    await act(async () => root.render(<Product />)); await settle();
    expect(container.textContent).toContain('Product 8');
    expect(container.textContent).not.toContain('Product not found');
    expect(container.textContent).not.toContain('Product unavailable');
    expect(global.fetch.mock.calls.some(([url]) => String(url).endsWith('/summary'))).toBe(false);
  } finally { await act(async () => root.unmount()); container.remove(); }
});

test('gallery collapses repeated resolved placeholder URLs into one real display', async () => {
  mockAuthState = { user: null, isAuthed: false };
  mockProductId = '4';
  global.fetch = jest.fn(async url => String(url).endsWith('/products/4')
    ? json({ product: { id: 4, name: 'Product 4', category: 'Home', price: 12,
      stock_quantity: 3, images: [
        'https://picsum.photos/seed/ss_100_a/600/800',
        'https://picsum.photos/seed/ss_100_b/600/800',
        'https://picsum.photos/seed/ss_101_a/600/800',
      ] } })
    : json({ results: [], recommendation: '' }));
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    expect(container.querySelector('img[alt="Product 4"]').getAttribute('src')).toBe('/secureshop/product-placeholder.svg');
    expect(container.querySelector('button[aria-label="Next image"]')).toBeNull();
    expect(container.querySelector('button[aria-label="Previous image"]')).toBeNull();
    expect(container.querySelector('button[aria-label^="Show image"]')).toBeNull();
  } finally { await act(async () => root.unmount()); container.remove(); }
});

test('gallery preserves distinct images and resets its selected index on product change', async () => {
  mockAuthState = { user: null, isAuthed: false };
  const first='/api/secureshop/uploads/static/first.png',second='/api/secureshop/uploads/static/second.png';
  const next='/api/secureshop/uploads/static/next.png';
  global.fetch = jest.fn(async url => {
    const match = /\/products\/(\d+)$/.exec(String(url));
    if (match) return json({ product: { id: Number(match[1]), name: `Product ${match[1]}`,
      category: 'Home', price: 12, stock_quantity: 3,
      images: match[1] === '7' ? [first, first, second] : match[1] === '8' ? [next, first] : [next] } });
    return json({ results: [], recommendation: '' });
  });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    expect(container.querySelectorAll('button[aria-label^="Show image"]')).toHaveLength(2);
    expect(container.querySelector('img[alt="Product 7"]').getAttribute('src')).toBe(first);
    await act(async () => container.querySelector('button[aria-label="Next image"]').click());
    expect(container.querySelector('img[alt="Product 7"]').getAttribute('src')).toBe(second);
    mockProductId = '8'; await act(async () => root.render(<Product />)); await settle();
    expect(container.querySelector('img[alt="Product 8"]').getAttribute('src')).toBe(next);
    expect(container.querySelectorAll('button[aria-label^="Show image"]')).toHaveLength(2);
    await act(async () => container.querySelector('button[aria-label="Next image"]').click());
    mockProductId = '9'; await act(async () => root.render(<Product />)); await settle();
    expect(container.querySelector('img[alt="Product 9"]').getAttribute('src')).toBe(next);
    expect(container.querySelector('button[aria-label="Next image"]')).toBeNull();
  } finally { await act(async () => root.unmount()); container.remove(); }
});

test('StrictMode admits one authenticated summary POST and delivers it after effect replay', async () => {
  const pending = deferred();
  let summarySignal;
  global.fetch = jest.fn((url, options = {}) => {
    if (String(url).endsWith('/summary')) {
      summarySignal = options.signal;
      return pending.promise;
    }
    return Promise.resolve(ordinary(url) || json({ results: [], recommendation: '' }));
  });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<React.StrictMode><Product /></React.StrictMode>)); await settle();
    expect(global.fetch.mock.calls.filter(([url]) => String(url).endsWith('/summary'))).toHaveLength(1);
    expect(summarySignal.aborted).toBe(false);
    mockSummaryText.set(7,'One genuine summary');
    await act(async () => { pending.resolve(json({ summary: 'One genuine summary' })); await pending.promise; });
    await settle();
    expect(container.textContent).toContain('One genuine summary');
    expect(container.textContent).not.toContain('summarizer thinking');
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
  expect(summarySignal.aborted).toBe(true);
});

test('product change aborts old summary and cannot publish stale model output', async () => {
  const old = deferred(); const current = deferred();
  const signals = new Map();
  global.fetch = jest.fn((url, options = {}) => {
    if (String(url).endsWith('/summary')) {
      signals.set(String(url), options.signal);
      return String(url).includes('/products/7/') ? old.promise : current.promise;
    }
    return Promise.resolve(ordinary(url) || json({ results: [], recommendation: '' }));
  });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    mockProductId = '8';
    await act(async () => root.render(<Product />)); await settle();
    expect(signals.get('/api/secureshop/products/7/summary').aborted).toBe(true);
    expect(signals.get('/api/secureshop/products/8/summary').aborted).toBe(false);
    await act(async () => { old.resolve(json({ summary: 'Stale summary' })); await old.promise; });
    await settle();
    expect(container.textContent).not.toContain('Stale summary');
    mockSummaryText.set(8,'Current product summary');
    await act(async () => { current.resolve(json({ summary: 'Current product summary' })); await current.promise; });
    await settle();
    expect(container.textContent).toContain('Current product summary');
    expect(global.fetch.mock.calls.filter(([url]) => String(url).endsWith('/summary'))).toHaveLength(2);
  } finally { await act(async () => root.unmount()); container.remove(); }
});

test('account switch starts its own summary while credential and transport changes recover without new model work', async () => {
  const old = deferred();
  mockAuthState = { user: { id: 41, role: 'customer' }, token: 'session-one', isAuthed: true };
  let firstSummaryCalls = 0;
  const firstTransport = jest.fn((url, options = {}) => {
    if (String(url).endsWith('/summary')) {
      firstSummaryCalls += 1;
      return firstSummaryCalls === 1 ? old.promise : Promise.resolve(json({
        summary: firstSummaryCalls === 2 ? 'Second account summary' : 'Renewed session summary',
      }));
    }
    return Promise.resolve(ordinary(url) || json({ results: [], recommendation: '' }));
  });
  global.fetch = firstTransport;
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    const oldSignal = firstTransport.mock.calls.find(([url]) => String(url).endsWith('/summary'))[1].signal;
    mockSummaryText.set(7,'Second account summary');
    mockAuthState = { user: { id: 42, role: 'customer' }, token: 'session-two', isAuthed: true };
    await act(async () => root.render(<Product />)); await settle();
    expect(oldSignal.aborted).toBe(true);
    expect(firstSummaryCalls).toBe(2);
    expect(container.textContent).toContain('Second account summary');
    await act(async () => { old.resolve(json({ summary: 'Old account summary' })); await old.promise; });
    await settle();
    expect(container.textContent).not.toContain('Old account summary');
    mockSummaryReadDenied = true;
    mockAuthState = { ...mockAuthState, token: 'session-three' };
    await act(async () => root.render(<Product />)); await settle();
    expect(firstSummaryCalls).toBe(2);
    expect(container.textContent).toContain('AI summary unavailable');
    expect(container.textContent).not.toContain('Second account summary');
    mockSummaryReadDenied = false; mockSummaryText.set(7,'Recovered account summary');
    const secondTransport = jest.fn(url => Promise.resolve(String(url).endsWith('/summary')
      ? json({ summary: 'Replacement transport summary' })
      : ordinary(url) || json({ results: [], recommendation: '' })));
    global.fetch = secondTransport;
    await act(async () => root.render(<Product />)); await settle();
    expect(secondTransport.mock.calls.filter(([url]) => String(url).endsWith('/summary'))).toHaveLength(0);
    expect(container.textContent).toContain('Recovered account summary');
    expect(container.textContent).not.toContain('Renewed session summary');
    expect(container.textContent).not.toContain('Old account summary');
  } finally { await act(async () => root.unmount()); container.remove(); }
});

test('related products reports a truthful HTTP failure instead of presenting an empty success', async () => {
  mockAuthState = { user: null, isAuthed: false };
  global.fetch = jest.fn(async url => ordinary(url)
    || json({ error: 'Bound product model unavailable' }, 503));
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />));
    await settle();
    expect(mockToast.error).toHaveBeenCalledWith(
      'Related products failed: Bound product model unavailable');
    expect(container.textContent).not.toContain('Related products');
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});

test('product changes abort the old graph request and stale completion cannot replace current related data', async () => {
  mockAuthState = { user: null, isAuthed: false };
  const old = deferred();
  let oldSignal;
  let currentSignal;
  global.fetch = jest.fn(async (url, options = {}) => {
    const normal = ordinary(url);
    if (normal) return normal;
    if (String(url).endsWith('/products/7/similar')) {
      oldSignal = options.signal;
      return old.promise;
    }
    if (String(url).endsWith('/products/8/similar')) {
      currentSignal = options.signal;
      return json({ results: [{ id: 81, name: 'Current related product' }], recommendation: 'Current model narrative' });
    }
    throw new Error(`unexpected ${url}`);
  });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    expect(oldSignal).toBeDefined(); expect(oldSignal.aborted).toBe(false);
    mockProductId = '8';
    await act(async () => root.render(<Product />)); await settle();
    expect(oldSignal.aborted).toBe(true);
    expect(currentSignal.aborted).toBe(false);
    expect(container.textContent).toContain('Current related product');
    old.resolve(json({ results: [{ id: 71, name: 'Stale related product' }], recommendation: 'Stale model narrative' }));
    await old.promise; await settle();
    expect(container.textContent).toContain('Current related product');
    expect(container.textContent).not.toContain('Stale related product');
    expect(container.textContent).toContain('Current model narrative');
    expect(container.textContent).not.toContain('Stale model narrative');
    expect(mockToast.error).not.toHaveBeenCalled();
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
  expect(currentSignal.aborted).toBe(true);
});

test('unmount aborts an in-flight related graph without showing a stale error', async () => {
  mockAuthState = { user: null, isAuthed: false };
  const pending = deferred();
  let relatedSignal;
  global.fetch = jest.fn(async (url, options = {}) => {
    const normal = ordinary(url);
    if (normal) return normal;
    relatedSignal = options.signal;
    return pending.promise;
  });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => root.render(<Product />)); await settle();
  expect(relatedSignal).toBeDefined(); expect(relatedSignal.aborted).toBe(false);
  await act(async () => root.unmount()); container.remove();
  expect(relatedSignal.aborted).toBe(true);
  pending.resolve(json({ results: [{ id: 70, name: 'Unmounted stale product' }] }));
  await pending.promise; await settle();
  expect(mockToast.error).not.toHaveBeenCalled();
});


test('renders the exact model recommendation as text even with no related cards', async () => {
  const recommendation = 'I cannot recommend that. <img src=x onerror=alert(1)>\nActual model response.';
  useProductSimilar.mockReturnValue({ reference: { productId: 7 },
    outcome: { status: 'completed', result: { results: [], recommendation } },
    busy: false, error: null, accessLost: false, validProduct: true,
    start: jest.fn(), check: jest.fn(), retryNotFound: jest.fn(), clearCompleted: jest.fn() });
  global.fetch = jest.fn(async url => ordinary(url) || json({ reviews: [] }));
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    const paragraph = container.querySelector('[aria-label="AI product recommendation"]');
    expect(paragraph.textContent).toBe(recommendation);
    expect(paragraph.querySelector('img')).toBeNull();
    expect(container.textContent).toContain('Related products');
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});

test('authenticated related products run only after the explicit action', async () => {
  const start = jest.fn();
  useProductSimilar.mockReturnValue({ reference: null, outcome: null,
    busy: false, error: null, accessLost: false, validProduct: true,
    start, check: jest.fn(), retryNotFound: jest.fn(), clearCompleted: jest.fn() });
  global.fetch = jest.fn(async url => ordinary(url) || json({ reviews: [] }));
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    expect(global.fetch.mock.calls.some(([url]) => String(url).includes('/similar'))).toBe(false);
    const button = [...container.querySelectorAll('button')]
      .find(item => item.textContent === 'Find similar products');
    expect(button).toBeDefined();
    await act(async () => button.click());
    expect(start).toHaveBeenCalledTimes(1);
    expect(useProductSimilar).toHaveBeenCalledWith(expect.objectContaining({
      productId: '7', shopUserId: 41,
    }));
  } finally { await act(async () => root.unmount()); container.remove(); }
});

test('saved recommendation controls use storefront wording and a deliberate same-source retry', async () => {
  const retryNotFound = jest.fn(), check = jest.fn();
  useProductSimilar.mockReturnValue({ reference: { productId: 7 },
    outcome: { status: 'not_found' }, busy: false, error: null, accessLost: false,
    validProduct: true, start: jest.fn(), check, retryNotFound,
    clearCompleted: jest.fn() });
  global.fetch = jest.fn(async url => ordinary(url) || json({ reviews: [] }));
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Product />)); await settle();
    expect(container.textContent).toContain('Ready to try again');
    const button = label => [...container.querySelectorAll('button')]
      .find(item => item.textContent === label);
    await act(async () => button('Check recommendations').click());
    await act(async () => button('Try again').click());
    expect(check).toHaveBeenCalledTimes(1);
    expect(retryNotFound).toHaveBeenCalledTimes(1);
    expect(container.textContent).not.toContain('same similar-products request');
  } finally { await act(async () => root.unmount()); container.remove(); }
});

test('summary renders canonical status separately, escapes answer text and removes completion when saved source becomes unavailable',async()=>{
  mockSummaryText.set(7,'<img src=x onerror=controlled()> Saved answer');
  mockSummaryAssessment = {completed:true,judgment:{evaluationId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',verdict:'pass',canRetry:false},replayed:true};
  global.fetch = jest.fn(async url => ordinary(url) || json({results:[],reviews:[]}));
  const container=document.createElement('div');document.body.appendChild(container);const root=createRoot(container);
  try {
    await act(async()=>root.render(<Product/>));await settle();
    expect(container.textContent).toContain('Objective completed');
    expect(container.querySelector('blockquote').textContent).toContain('<img src=x');expect(container.querySelector('blockquote img')).toBeNull();
    mockSummaryReadDenied=true;
    mockAuthState={...mockAuthState,token:'changed-credential'};
    await act(async()=>root.render(<Product/>));await settle();
    expect(container.textContent).not.toContain('Objective completed');expect(container.textContent).not.toContain('Saved answer');
    expect(container.textContent).toContain('AI summary unavailable');
    expect(global.fetch.mock.calls.filter(([url,options])=>String(url).endsWith('/summary')&&options.method==='POST')).toHaveLength(1);
  } finally {await act(async()=>root.unmount());container.remove();}
});
