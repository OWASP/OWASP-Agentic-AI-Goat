import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Home from './Home';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';

jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: jest.fn() }));

jest.mock('react-router-dom', () => ({
  Link: ({ children, to, ...props }) => <a href={to} {...props}>{children}</a>,
}));

jest.mock('framer-motion', () => {
  const React = require('react');
  const MotionSection = React.forwardRef(function MotionSection(
    { initial, animate, transition, ...props }, ref,
  ) { return <section {...props} ref={ref} />; });
  return { motion: { section: MotionSection }, useReducedMotion: () => true };
});

jest.mock('../context/AuthContext', () => ({
  useAuth: () => ({ user: { id: 77, username: 'learner' } }),
}));
jest.mock('../context/CartContext.jsx', () => ({ useCart: () => ({ addItem: jest.fn() }) }));
jest.mock('../components/ProductCard.jsx', () => ({ product }) => (
  <div data-testid={`product-${product.id}`}>{product.name}</div>
));
jest.mock('../components/Card.jsx', () => ({ children }) => <div>{children}</div>);
jest.mock('../components/Button.jsx', () => ({ children }) => <button>{children}</button>);
jest.mock('../components/OrderStatusChip.jsx', () => ({ status }) => <span>{status}</span>);
jest.mock('../components/ControlledSsrfLab.jsx', () => () => null);

let container;
let root;

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: jest.fn().mockResolvedValue(body),
  };
}

function deferred() {
  let resolve;
  const promise = new Promise(res => { resolve = res; });
  return { promise, resolve };
}

async function settle() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

beforeEach(() => {
  getBridgeFetchMetadata.mockReset();
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

test('keeps successful sections while distinguishing 503, network, bad JSON, and malformed payload failures', async () => {
  global.fetch = jest.fn((url) => {
    const value = String(url);
    if (value.includes('/recommended')) {
      return Promise.resolve(response({ error: 'recommendation provider unavailable' }, 503));
    }
    if (value.includes('sort=deals')) {
      return Promise.resolve(response({ products: [{ id: 2, name: 'Retained deal', price: 12 }] }));
    }
    if (value.includes('category=Beauty')) return Promise.reject(new Error('network offline'));
    if (value.includes('category=Books')) {
      return Promise.resolve({ ok: true, status: 200, json: jest.fn().mockRejectedValue(new SyntaxError('bad JSON')) });
    }
    if (value.includes('/trace/latest')) return Promise.resolve(response({ rows: [] }));
    if (value.includes('/orders')) return Promise.resolve(response({}));
    throw new Error(`unexpected URL ${value}`);
  });

  await act(async () => root.render(<Home />));
  await settle();

  expect(container.textContent).toContain('Retained deal');
  expect(container.textContent).toContain('Recommendations unavailable.');
  expect(container.textContent).toContain('recommendation provider unavailable');
  expect(container.textContent).toContain('Beauty unavailable.');
  expect(container.textContent).toContain('network offline');
  expect(container.textContent).toContain('Books unavailable.');
  expect(container.textContent).toContain('unreadable response');
  expect(container.textContent).toContain('Recent orders unavailable.');
  expect(container.textContent).not.toContain('No recommendations yet');
  expect(container.textContent).not.toContain('No orders yet');
  expect(container.querySelectorAll('[role="alert"]')).toHaveLength(4);
});

test('preserves normal empty states for valid 200 responses with empty arrays', async () => {
  global.fetch = jest.fn((url) => {
    const value = String(url);
    if (value.includes('/recommended')) return Promise.resolve(response({ feed: [] }));
    if (value.includes('/trace/latest')) return Promise.resolve(response({ rows: [] }));
    if (value.includes('/orders')) return Promise.resolve(response({ orders: [] }));
    return Promise.resolve(response({ products: [] }));
  });

  await act(async () => root.render(<Home />));
  await settle();

  expect(container.querySelector('[role="alert"]')).toBeNull();
  expect(container.textContent).toContain('No recommendations yet');
  expect(container.textContent).toContain('No orders yet');
  expect(container.textContent).toContain('No deals today');
  expect(container.textContent).toContain('No Beauty products available');
  expect(container.textContent).toContain('No Books available');
});

test('bound Home delegates identity to the authenticated session while legacy Home retains its query', async () => {
  getBridgeFetchMetadata.mockReturnValue({ boundReviews: true });
  global.fetch = jest.fn(() => Promise.resolve(response({ feed: [], products: [], orders: [], rows: [] })));
  await act(async () => root.render(<Home />));
  await settle();
  expect(global.fetch.mock.calls.map(([url]) => url)).toEqual(expect.arrayContaining([
    '/api/secureshop/orders', '/api/secureshop/recommended',
    '/api/secureshop/agents/customer/trace/latest?limit=5',
  ]));
  expect(global.fetch.mock.calls.some(([url]) => url.includes('user_id'))).toBe(false);
  getBridgeFetchMetadata.mockReturnValue(undefined);
  await act(async () => root.render(<Home />));
  await settle();
  expect(global.fetch.mock.calls.map(([url]) => url)).toEqual(expect.arrayContaining([
    '/api/secureshop/orders?user_id=77', '/api/secureshop/recommended?user_id=77',
  ]));
});

test('renders only persisted customer trace rows with loading, empty, and unavailable states', async () => {
  const pending = deferred();
  global.fetch = jest.fn(url => String(url).includes('/trace/latest')
    ? pending.promise
    : Promise.resolve(response({ feed: [], products: [], orders: [] })));

  await act(async () => root.render(<Home />));
  expect(container.textContent).toContain('Loading recent activity');

  await act(async () => {
    pending.resolve(response({ rows: [{
      id: 9,
      session_id: 'owned-session',
      actor: 'customer supervisor',
      kind: 'tool',
      tool_name: 'product-search.lookup',
      ts: '2026-10-09T12:00:00.000Z',
    }] }));
    await pending.promise;
  });
  await settle();
  expect(container.textContent).toContain('customer supervisor · product-search.lookup');
  expect(container.textContent).not.toContain('No agent activity yet');

  await act(async () => root.unmount());
  root = createRoot(container);
  global.fetch = jest.fn(url => String(url).includes('/trace/latest')
    ? Promise.resolve(response({ rows: [] }))
    : Promise.resolve(response({ feed: [], products: [], orders: [] })));
  await act(async () => root.render(<Home />));
  await settle();
  expect(container.textContent).toContain('No agent activity yet. Start a task in the agent lane');

  await act(async () => root.unmount());
  root = createRoot(container);
  global.fetch = jest.fn(url => String(url).includes('/trace/latest')
    ? Promise.resolve(response({ error: 'trace unavailable' }, 503))
    : Promise.resolve(response({ feed: [], products: [], orders: [] })));
  await act(async () => root.render(<Home />));
  await settle();
  expect(container.textContent).toContain('Recent activity unavailable.');
  expect(container.textContent).toContain('trace unavailable');
});

test('does not present prior or empty order data while a new Home load is pending', async () => {
  const pending = deferred();
  global.fetch = jest.fn(() => pending.promise);

  await act(async () => root.render(<Home />));
  await settle();

  expect(container.textContent).toContain('Loading recent orders');
  expect(container.textContent).not.toContain('No orders yet');

  await act(async () => {
    pending.resolve(response({ feed: [], products: [], orders: [] }));
    await pending.promise;
  });
  await settle();
  expect(container.textContent).toContain('No orders yet');
});
