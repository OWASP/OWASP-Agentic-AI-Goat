import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Overview from './Overview';
let mockAuth = { user: { id: 12, username: 'merchant' }, token: 'first-session' };
jest.mock('../../context/AuthContext.jsx', () => ({ useAuth: () => mockAuth }));
jest.mock('react-router-dom', () => ({ Link: ({ to, children, ...props }) => <a href={to} {...props}>{children}</a> }));
jest.mock('framer-motion', () => {
  const React = require('react');
  const wrap = tag => React.forwardRef(({ initial, animate, exit, transition, whileHover, whileTap, layout, ...props }, ref) => React.createElement(tag, { ...props, ref }));
  return { motion: { div: wrap('div'), li: wrap('li') }, AnimatePresence: ({ children }) => children, useReducedMotion: () => true };
});
jest.mock('recharts', () => {
  const Part = ({ children }) => <div>{children}</div>;
  return Object.fromEntries(['LineChart','Line','XAxis','YAxis','ResponsiveContainer','Tooltip','AreaChart','Area','CartesianGrid'].map(key => [key, Part]));
});
const response = (body, status = 200) => ({ ok: status === 200, status, json: async () => body });
function healthy(url) {
  if (url.includes('/kpis')) return response({ revenue: { value: 21 }, orders: { value: 3 }, aov: { value: 7 }, top_product: null });
  if (url.includes('sales-chart')) return response({ series: [] });
  if (url.includes('/products')) return response({ products: [], total: 25 });
  if (url.includes('/reviews')) return response({ reviews: [], total: 4 });
  return response({ rows: [] });
}
let root, container;
const settle = async () => { await act(async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); }); };
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockAuth = { user: { id: 12, username: 'merchant' }, token: 'first-session' };
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); jest.useRealTimers(); });
test('shows the real total rather than the six-product page length', async () => {
  global.fetch = jest.fn(async url => healthy(url));
  await act(async () => root.render(<Overview />)); await settle();
  expect(container.textContent).toContain('25 active');
  expect(container.textContent).toContain('4 pending');
  expect(container.textContent).toContain('$21.00');
  expect(global.fetch.mock.calls.find(([url]) => url.includes('/products'))[0]).toContain('status=active');
});
test('HTTP errors are unavailable states, never zero revenue or an empty trace success', async () => {
  global.fetch = jest.fn(async () => response({ error: 'unavailable' }, 503));
  await act(async () => root.render(<Overview />)); await settle();
  expect(container.querySelector('[role="alert"]').textContent).toContain('Metrics');
  expect(container.textContent).toContain('Sales chart unavailable.');
  expect(container.textContent).toContain('Request failed (503)');
  expect(container.textContent).not.toContain('$0.00');
  expect(container.textContent).not.toContain('no pending');
  expect(container.textContent).toContain('Listings unavailable.');
  expect(container.textContent).not.toContain('No listings yet');
});
test('listings remain loading until resolved and a failed dashboard can recover', async () => {
  let finish;
  global.fetch = jest.fn(url => url.includes('/products')
    ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(healthy(url)));
  await act(async () => root.render(<Overview />)); await settle();
  expect(container.textContent).toContain('Loading listings');
  expect(container.textContent).not.toContain('No listings yet');
  await act(async () => finish(response({ error: 'unavailable' }, 503))); await settle();
  expect(container.textContent).toContain('Listings unavailable.');
  global.fetch.mockImplementation(async url => healthy(url));
  const retry = [...container.querySelectorAll('button')].find(button => button.textContent === 'Retry dashboard');
  await act(async () => retry.click()); await settle();
  expect(container.textContent).not.toContain('Listings unavailable.');
  expect(container.querySelector('[role="alert"]')).toBeNull();
  expect(container.textContent).toContain('25 active');
});
test('trace polling waits for its current request instead of overlapping calls', async () => {
  jest.useFakeTimers(); let finish;
  global.fetch = jest.fn(url => url.includes('/trace/') ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(healthy(url)));
  await act(async () => root.render(<Overview />)); await settle();
  await act(async () => jest.advanceTimersByTime(15000));
  expect(global.fetch.mock.calls.filter(([url]) => url.includes('/trace/'))).toHaveLength(1);
  await act(async () => finish(response({ rows: [] }))); await settle();
  await act(async () => jest.advanceTimersByTime(5000));
  expect(global.fetch.mock.calls.filter(([url]) => url.includes('/trace/'))).toHaveLength(2);
});
test('same-user session replacement aborts prior requests and ignores their late data', async () => {
  const pending = [];
  global.fetch = jest.fn((url, options) => new Promise(resolve => pending.push({ url, options, resolve })));
  await act(async () => root.render(<Overview />));
  const first = [...pending]; mockAuth = { ...mockAuth, token: 'replacement-session' };
  await act(async () => root.render(<Overview />));
  expect(first.every(row => row.options.signal.aborted)).toBe(true);
  await act(async () => { for (const row of first) row.resolve(healthy(row.url)); }); await settle();
  expect(container.textContent).not.toContain('$21.00');
  await act(async () => { for (const row of pending.slice(first.length)) row.resolve(healthy(row.url)); }); await settle();
  expect(container.textContent).toContain('$21.00');
});
