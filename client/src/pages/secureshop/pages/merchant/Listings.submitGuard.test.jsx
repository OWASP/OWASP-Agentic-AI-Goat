import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import MerchantListings from './Listings';

const toast = { success: jest.fn(), error: jest.fn(), warn: jest.fn(), info: jest.fn() };
let mockAuth;
jest.mock('./useBoundListings', () => ({ useBoundListings: () => ({ attached: false, busy: false, references: {} }) }));
jest.mock('../../context/AuthContext.jsx', () => ({ useAuth: () => mockAuth }));
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('framer-motion', () => {
  const ReactModule = require('react');
  const element = tag => ReactModule.forwardRef(function MotionElement(
    { initial, animate, exit, transition, whileHover, whileTap, ...props }, ref,
  ) { return ReactModule.createElement(tag, { ...props, ref }); });
  return { motion: { div: element('div'), tr: element('tr') },
    AnimatePresence: ({ children }) => <>{children}</>, useReducedMotion: () => true };
});

const product = { id: 7, name: 'Existing listing', description: 'Original', price: 12,
  category: 'Books', image_url: null, stock_quantity: 1, status: 'active' };
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status,
  json: () => Promise.resolve(body) });
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
const ordinaryFetch = jest.fn(url => Promise.resolve(url === '/api/secureshop/categories'
  ? response({ categories: [{ name: 'Books' }] })
  : response({ products: [product], total: 1, pages: 1, categories: ['Books'] })));
let root;
let container;
const view = () => <MemoryRouter><MerchantListings /></MemoryRouter>;
const submit = () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
const writeCalls = fetcher => fetcher.mock.calls.filter(([url, options]) =>
  String(url).startsWith('/api/secureshop/merchant/products') && ['POST', 'PUT'].includes(options?.method));

beforeEach(async () => {
  jest.clearAllMocks();
  mockAuth = { user: { id: 12, role: 'merchant' }, token: 'first-session' };
  global.IS_REACT_ACT_ENVIRONMENT = true;
  global.fetch = jest.fn((...args) => ordinaryFetch(...args));
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => root.render(view()));
});
afterEach(async () => {
  if (root) await act(async () => root.unmount());
  root = null;
  container.remove();
});

async function open(mode) {
  await act(async () => mode === 'edit'
    ? container.querySelector('button[aria-label="Edit"]').click()
    : container.querySelector('[data-testid="listings-create-cta"]').click());
  if (mode === 'create') {
    const input = container.querySelector('form input');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'New listing');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }
}

test.each(['create', 'edit'])('%s locks synchronously against rapid repeated submits', async mode => {
  await open(mode);
  const held = deferred();
  global.fetch.mockImplementation((url, options) => options?.method === (mode === 'edit' ? 'PUT' : 'POST')
    ? held.promise : ordinaryFetch(url, options));
  await act(async () => { submit(); submit(); });
  expect(writeCalls(global.fetch)).toHaveLength(1);
  expect(container.querySelector('form button[type="submit"]').disabled).toBe(true);
  await act(async () => held.resolve(response({ ok: true, product_id: mode === 'edit' ? 7 : 19 })));
  expect(container.querySelector('form')).toBeNull();
  expect(toast.success).toHaveBeenCalledTimes(1);
});

test('late create success cannot toast or reload a replacement authority', async () => {
  await open('create');
  const held = deferred();
  global.fetch.mockImplementation((url, options) => options?.method === 'POST'
    ? held.promise : ordinaryFetch(url, options));
  await act(async () => submit());
  mockAuth = { user: { id: 99, role: 'merchant' }, token: 'second-session' };
  await act(async () => root.render(view()));
  const reads = global.fetch.mock.calls.length;
  await act(async () => held.resolve(response({ ok: true, product_id: 19 })));
  expect(global.fetch.mock.calls).toHaveLength(reads);
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).not.toHaveBeenCalled();
  expect(container.querySelector('form')).toBeNull();
});

test('late edit failure cannot notify or close a replacement transport editor', async () => {
  await open('edit');
  const old = global.fetch;
  const held = deferred();
  old.mockImplementation((url, options) => options?.method === 'PUT'
    ? held.promise : ordinaryFetch(url, options));
  await act(async () => submit());
  global.fetch = jest.fn((...args) => ordinaryFetch(...args));
  await act(async () => root.render(view()));
  await act(async () => held.resolve(response({ error: 'Old transport rejected' }, 503)));
  expect(toast.error).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
  expect(container.querySelector('form')).not.toBeNull();
  expect(writeCalls(global.fetch)).toHaveLength(0);
});

test('a changed-and-restored listing scope does not revive an old save response', async () => {
  await open('create');
  const held = deferred();
  global.fetch.mockImplementation((url, options) => options?.method === 'POST'
    ? held.promise : ordinaryFetch(url, options));
  await act(async () => submit());
  const search = container.querySelector('[data-testid="listings-search"]');
  for (const value of ['other view', '']) {
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(search, value);
      search.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }
  await act(async () => held.resolve(response({ ok: true, product_id: 19 })));
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).not.toHaveBeenCalled();
  expect(container.querySelector('form')).not.toBeNull();
});

test('late create rejection after unmount has no response-side UI action', async () => {
  await open('create');
  const held = deferred();
  global.fetch.mockImplementation((url, options) => options?.method === 'POST'
    ? held.promise : ordinaryFetch(url, options));
  await act(async () => submit());
  await act(async () => root.unmount());
  root = null;
  await act(async () => held.resolve(Promise.reject(Error('transport dropped'))));
  expect(toast.error).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
});
