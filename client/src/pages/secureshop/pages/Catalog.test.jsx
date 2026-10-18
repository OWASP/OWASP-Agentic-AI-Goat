import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Catalog from './Catalog';

jest.mock('react-router-dom', () => {
  const React = require('react');
  return {
    useSearchParams: () => {
      const [value, setValue] = React.useState(() => new URLSearchParams(window.location.search));
      const update = (next) => setValue(typeof next === 'function' ? next(value) : next);
      return [value, update];
    },
  };
});

jest.mock('framer-motion', () => {
  const React = require('react');
  const MotionDiv = React.forwardRef(function MotionDiv({ initial, animate, transition, ...props }, ref) {
    return <div {...props} ref={ref} />;
  });
  return { motion: { div: MotionDiv }, AnimatePresence: ({ children }) => <>{children}</>, useReducedMotion: () => true };
});

jest.mock('../context/CartContext.jsx', () => ({ useCart: () => ({ addItem: jest.fn() }) }));
jest.mock('../components/ProductCard.jsx', () => ({ product }) => (
  <div data-testid={`product-${product.id}`}>{product.name}</div>
));
jest.mock('../components/Button.jsx', () => ({ children, ...props }) => <button {...props}>{children}</button>);

let container;
let root;

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: jest.fn().mockResolvedValue(body),
  };
}

async function settle() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  window.history.replaceState({}, '', '/secureshop/catalog');
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

test.each([
  ['an HTTP error', () => Promise.resolve(response({ error: 'product service unavailable' }, 503)), 'product service unavailable'],
  ['a network error', () => Promise.reject(new Error('network offline')), 'network offline'],
  ['a malformed successful payload', () => Promise.resolve(response({ total: 1 })), 'Catalog returned an unreadable response.'],
  ['a malformed total', () => Promise.resolve(response({ products: [], total: -1 })), 'Catalog returned an unreadable response.'],
  ['a malformed product entry', () => Promise.resolve(response({ products: [null], total: 1 })), 'Catalog returned an unreadable response.'],
])('shows a truthful error for %s instead of an empty catalog', async (_kind, fetchResult, message) => {
  global.fetch = jest.fn(fetchResult);

  await act(async () => root.render(<Catalog />));
  await settle();

  expect(container.querySelector('[role="alert"]')).not.toBeNull();
  expect(container.textContent).toContain(`Failed to load: ${message}`);
  expect(container.textContent).not.toContain('Nothing to show');
});

test('keeps the normal empty state for a valid empty 200 response', async () => {
  global.fetch = jest.fn(() => Promise.resolve(response({ products: [], total: 0 })));

  await act(async () => root.render(<Catalog />));
  await settle();

  expect(container.querySelector('[role="alert"]')).toBeNull();
  expect(container.textContent).toContain('Nothing to show');
  expect(container.textContent).toContain('0 products');
});

test('a failed later filter hides prior products, count, and pagination', async () => {
  global.fetch = jest.fn(url => Promise.resolve(url === '/api/secureshop/categories'
    ? response({ categories: [] })
    : String(url).includes('search=missing')
      ? response({ error: 'catalog offline' }, 503)
      : response({ products: [{ id: 7, name: 'Earlier product', price: 10 }], total: 25 })));
  await act(async () => root.render(<Catalog />));
  await settle();
  expect(container.querySelector('[data-testid="product-7"]')).not.toBeNull();
  expect(container.querySelector('[aria-label="Pagination"]')).not.toBeNull();

  const input = container.querySelector('input[aria-label="Search catalog"]');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'missing');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => container.querySelector('button[aria-label="Search products"]').click());
  await settle();
  expect(container.textContent).toContain('Failed to load: catalog offline');
  expect(container.textContent).toContain('Catalog unavailable');
  expect(container.textContent).not.toContain('25 products');
  expect(container.querySelector('[data-testid="product-7"]')).toBeNull();
  expect(container.querySelector('[aria-label="Pagination"]')).toBeNull();
});

test('preserves query filters and pagination while validating the product DTO', async () => {
  window.history.replaceState({}, '', '/secureshop/catalog?q=lamp&category=Home&sort=price_asc&rating=4&maxPrice=100&page=2');
  global.fetch = jest.fn(url => Promise.resolve(url === '/api/secureshop/categories'
    ? response({ categories: [{ id: 1, name: 'Home', description: '' }, { id: 2, name: 'Grocery', description: '' }] })
    : response({ total: 25, products: [{ id: 1, name: 'Filtered lamp', price: 80, avg_rating: 4.5 }] })));

  await act(async () => root.render(<Catalog />));
  await settle();

  const requested = global.fetch.mock.calls.find(([url]) => String(url).startsWith('/api/secureshop/products?'))[0];
  expect(requested).toContain('limit=24');
  expect(requested).toContain('offset=24');
  expect(requested).toContain('search=lamp');
  expect(requested).toContain('category=Home');
  expect(requested).toContain('sort=price_asc');
  expect(requested).toContain('minRating=4');
  expect(requested).toContain('maxPrice=100');
  expect(container.textContent).toContain('25 products');
  expect(container.textContent).toContain('Grocery');
  expect(container.querySelector('[data-testid="product-1"]')).not.toBeNull();
  expect(container.querySelector('[aria-label="Pagination"]')).not.toBeNull();
});

test('default price control says any price when products above the slider range are visible', async () => {
  global.fetch = jest.fn(url => Promise.resolve(url === '/api/secureshop/categories'
    ? response({ categories: [] })
    : response({ products: [{ id: 2, name: 'Premium item', price: 2353.96 }], total: 1 })));
  await act(async () => root.render(<Catalog />));
  await settle();
  expect(container.textContent).toContain('Any price');
  expect(container.textContent).toContain('Premium item');
  const requested = global.fetch.mock.calls.find(([url]) => String(url).startsWith('/api/secureshop/products?'))[0];
  expect(requested).not.toContain('maxPrice=');
});

test('submitting the visible catalog search requests the filtered public-readable list', async () => {
  global.fetch = jest.fn(url => Promise.resolve(url === '/api/secureshop/categories'
    ? response({ categories: [] })
    : response({ products: [{ id: 4, name: 'Found notebook', price: 9 }], total: 1 })));
  await act(async () => root.render(<Catalog />));
  await settle();
  const input = container.querySelector('input[aria-label="Search catalog"]');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'Disposable QA notebook');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  expect(global.fetch.mock.calls.filter(([url]) => String(url).includes('search='))).toHaveLength(0);
  await act(async () => container.querySelector('button[aria-label="Search products"]').click());
  await settle();
  const searched = global.fetch.mock.calls.find(([url]) => String(url).includes('search='));
  expect(searched[0]).toContain('search=Disposable+QA+notebook');
  expect(container.textContent).toContain('1 product matching "Disposable QA notebook"');
});
