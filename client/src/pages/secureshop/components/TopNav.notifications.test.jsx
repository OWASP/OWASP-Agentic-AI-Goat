import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, useLocation } from 'react-router-dom';
import TopNav from './TopNav.jsx';
import { useAuth } from '../context/AuthContext';

jest.mock('../context/AuthContext', () => ({ useAuth: jest.fn() }));
jest.mock('../context/CartContext.jsx', () => ({ useCart: () => ({ count: 0 }) }));
jest.mock('../context/ToastContext.jsx', () => ({ useToast: () => ({ info: jest.fn(), error: jest.fn() }) }));
jest.mock('./RoleSwitcher.jsx', () => () => null);
jest.mock('framer-motion', () => {
  const React = require('react');
  return { AnimatePresence: ({ children }) => children,
    motion: new Proxy({}, { get: (_, tag) => ({ children, initial, animate, exit, transition, ...props }) =>
      React.createElement(tag, props, children) }) };
});

const response = (body, status = 200) => ({ ok: status >= 200 && status < 300,
  status, json: async () => body });
let root, container;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  jest.clearAllMocks();
});
const mount = (role, token = `${role}-session`) => {
  useAuth.mockReturnValue({ user: { id: 1, username: role }, token, isAuthed: true,
    logout: jest.fn(), switchRole: jest.fn() });
  return act(async () => root.render(<MemoryRouter><TopNav role={role} /></MemoryRouter>));
};
const toggle = () => act(async () => container.querySelector('[aria-label="Notifications"]').click());

test.each(['customer', 'merchant', 'admin'])('%s notifications read only that role trace', async role => {
  global.fetch = jest.fn(async () => response({ ok: true, rows: [{ id: 1, kind: 'tool',
    agent_ns: role, tool_name: 'inspect' }] }));
  await mount(role);
  await toggle();
  expect(global.fetch).toHaveBeenCalledTimes(1);
  expect(global.fetch.mock.calls[0][0]).toBe(`/api/secureshop/agents/${role}/trace/latest?limit=5`);
  expect(container.textContent).toContain(`${role}.inspect`);
  expect(container.textContent).not.toContain('No activity yet');
});

test('failed or malformed trace reads show unavailable rather than a false empty state', async () => {
  global.fetch = jest.fn().mockResolvedValueOnce(response({ error: 'denied' }, 503))
    .mockResolvedValueOnce(response({ ok: true }));
  await mount('merchant');
  await toggle();
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('Recent activity unavailable (HTTP 503)');
  expect(container.textContent).not.toContain('No activity yet');
  await toggle();
  await toggle();
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('Recent activity unavailable (Read failed)');
  expect(container.textContent).not.toContain('No activity yet');
});

test('an empty successful trace alone shows the empty message', async () => {
  global.fetch = jest.fn(async () => response({ ok: true, rows: [] }));
  await mount('admin');
  await toggle();
  expect(container.textContent).toContain('No activity yet. Ask the agents something.');
  expect(container.querySelector('[role="alert"]')).toBeNull();
});

test('role and token rotation abort an old read and hide its late rows', async () => {
  let finishMerchant;
  global.fetch = jest.fn((url) => url.includes('/merchant/')
    ? new Promise(resolve => { finishMerchant = resolve; })
    : Promise.resolve(response({ ok: true, rows: [{ id: 2, kind: 'tool', agent_ns: 'admin', tool_name: 'inspect' }] })));
  await mount('merchant', 'merchant-token');
  await toggle();
  const oldSignal = global.fetch.mock.calls[0][1].signal;
  await mount('admin', 'admin-token');
  expect(oldSignal.aborted).toBe(true);
  await act(async () => finishMerchant(response({ ok: true, rows: [{ id: 1, kind: 'tool',
    agent_ns: 'merchant', tool_name: 'stale' }] })));
  expect(container.textContent).toContain('admin.inspect');
  expect(container.textContent).not.toContain('merchant.stale');
});

test.each(['success', 'failure'])('late %s from an older search cannot replace current suggestions', async outcome => {
  jest.useFakeTimers();
  try {
    let finishOld;
    global.fetch = jest.fn(url => String(url).includes('search=old')
      ? new Promise((resolve, reject) => { finishOld = outcome === 'success' ? resolve : reject; })
      : Promise.resolve(response({ products: [{ id: 2, name: 'Current product', price: 20 }] })));
    await mount('customer');
    const input = container.querySelector('input[aria-label="Search products"]');
    const type = async value => act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await type('old');
    await act(async () => jest.advanceTimersByTime(250));
    expect(finishOld).toBeDefined();
    await type('current');
    await act(async () => jest.advanceTimersByTime(250));
    expect(container.textContent).toContain('Current product');
    await act(async () => finishOld(outcome === 'success'
      ? response({ products: [{ id: 1, name: 'Stale product', price: 10 }] })
      : new Error('old request failed')));
    expect(container.textContent).toContain('Current product');
    expect(container.textContent).not.toContain('Stale product');
  } finally {
    jest.useRealTimers();
  }
});

test('mobile search closes the drawer and navigates to encoded catalog results', async () => {
  const Location = () => {
    const location = useLocation();
    return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
  };
  useAuth.mockReturnValue({ user: { id: 1, username: 'customer' }, token: 'customer-session',
    isAuthed: true, logout: jest.fn(), switchRole: jest.fn() });
  global.fetch = jest.fn(async () => response({ products: [] }));
  await act(async () => root.render(<MemoryRouter><TopNav role="customer" /><Location /></MemoryRouter>));
  await act(async () => container.querySelector('button[aria-label="Menu"]').click());
  const input = container.querySelector('input[placeholder="Search..."]');
  expect(input).not.toBeNull();
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'red & blue');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  expect(container.querySelector('input[aria-label="Search products"]').value).toBe('red & blue');
  const currentInput = container.querySelector('input[placeholder="Search..."]');
  await act(async () => currentInput.closest('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })));
  expect(container.querySelector('button[aria-label="Close menu"]')).toBeNull();
  expect(container.querySelector('[data-testid="location"]').textContent)
    .toBe('/secureshop/catalog?q=red%20%26%20blue');
});
