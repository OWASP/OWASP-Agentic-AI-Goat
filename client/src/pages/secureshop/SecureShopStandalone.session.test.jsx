import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import SecureShopStandalone from './SecureShopStandalone.jsx';

let mockBoundMounts = 0;
jest.mock('./SecureShopStandaloneBound.jsx', () => {
  const React = require('react');
  const { useNavigate } = require('react-router-dom');
  return function Bound({ user, onSessionIntent, onRenewNeeded }) {
    const navigate = useNavigate();
    React.useEffect(() => { mockBoundMounts += 1; }, []);
    return <div data-testid="bound" data-role={user.role}>
      <button onClick={() => onSessionIntent({ type: 'auth-required' })}>Require authentication</button>
      <button onClick={() => onSessionIntent({ type: 'logout', nonce: 'nonce', requestId: 'request',
        frame: { contentWindow: { postMessage: () => {} } } })}>Sign out</button>
      <button onClick={() => onSessionIntent({ type: 'switch-role', role: 'merchant', nonce: 'nonce',
        requestId: 'request', frame: { contentWindow: { postMessage: () => {} } } })}>Switch role</button>
      <button onClick={() => navigate('/secureshop/admin/audit')}>Stale frame route</button>
      <button onClick={onRenewNeeded}>Renew session</button>
    </div>;
  };
});
jest.mock('./SecureShopAccess.jsx', () => {
  const { useLocation } = require('react-router-dom');
  return function Access({ user, login }) {
    const location = useLocation();
    return <div data-testid="login" data-role={user?.role || ''}>{location.search}
      <button onClick={() => login('shop_customer', 'test-password')}>Sign in customer</button>
    </div>;
  };
});
jest.mock('./SecureShopGuestLanding.jsx', () => () => <div data-testid="guest" />);
jest.mock('./SecureShopPassword.jsx', () => () => <div />);
jest.mock('./pages/Register.jsx', () => ({ SecureShopRegisterForm: () => <div /> }));

const admin = { id: 7, principalId: 'principal-7', username: 'shop_admin', role: 'admin' };
const customer = { ...admin, username: 'shop_customer', role: 'customer' };
let root;
let container;
function CurrentRoute() {
  const location = useLocation();
  return <output data-testid="route">{`${location.pathname}${location.search}`}</output>;
}
function NavigationControls() {
  const navigate = useNavigate();
  return <>
    <button onClick={() => navigate('/secureshop/catalog')}>Open catalog</button>
    <button onClick={() => navigate('/secureshop/login')}>Open shop login</button>
  </>;
}
beforeEach(() => {
  mockBoundMounts = 0;
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

async function mount(client, path = '/secureshop/admin/users') {
  await act(async () => root.render(<MemoryRouter initialEntries={[path]}>
    <CurrentRoute />
    <NavigationControls />
    <Routes><Route path="/secureshop/*" element={<SecureShopStandalone client={client} />} /></Routes>
  </MemoryRouter>));
}
const click = label => [...container.querySelectorAll('button')].find(button => button.textContent === label).click();
const deferred = () => {
  let resolve;
  return { promise: new Promise(done => { resolve = done; }), resolve: value => resolve(value) };
};

test('shop session loading uses the original spinner and status', async () => {
  const pending = deferred();
  const client = { session: jest.fn(() => pending.promise) };
  await mount(client);
  const spinner = container.querySelector('.ss-spinner');
  expect(spinner).not.toBeNull();
  expect(spinner.getAttribute('aria-hidden')).toBe('true');
  expect(container.querySelector('p[role="status"]').textContent).toContain('Opening SecureShop');
  await act(async () => pending.resolve(null));
  expect(container.querySelector('.ss-spinner')).toBeNull();
});

test('auth-required adopts the current shop principal and remounts without stale admin role', async () => {
  const client = { session: jest.fn()
    .mockResolvedValueOnce({ user: admin, expiresAt: '2026-10-11T00:00:00Z' })
    .mockResolvedValueOnce({ user: customer, expiresAt: '2026-10-11T01:00:00Z' }) };
  await mount(client);
  expect(container.querySelector('[data-testid="bound"]').dataset.role).toBe('admin');
  await act(async () => click('Require authentication'));
  expect(client.session).toHaveBeenCalledTimes(2);
  expect(container.querySelector('[data-testid="bound"]').dataset.role).toBe('customer');
  expect(mockBoundMounts).toBe(2);
});

test('auth-required with no shop session clears the prior role and preserves the sign-in destination', async () => {
  const client = { session: jest.fn()
    .mockResolvedValueOnce({ user: admin, expiresAt: null })
    .mockResolvedValueOnce(null) };
  await mount(client);
  await act(async () => click('Require authentication'));
  expect(container.querySelector('[data-testid="bound"]')).toBeNull();
  expect(container.querySelector('[data-testid="login"]').dataset.role).toBe('');
  expect(container.querySelector('[data-testid="login"]').textContent)
    .toContain('next=%2Fsecureshop%2Fadmin%2Fusers');
});

test('a transient session failure keeps the protected route and retries without a workshop login', async () => {
  const client = { session: jest.fn().mockRejectedValueOnce(Object.assign(new Error('unavailable'), { status: 503 }))
    .mockResolvedValueOnce({ user: admin, expiresAt: null }) };
  await mount(client);
  expect(container.querySelector('[role="alert"]').textContent).toContain('Unable to verify');
  expect(container.querySelector('[data-testid="login"]')).toBeNull();
  await act(async () => click('Retry'));
  expect(client.session).toHaveBeenCalledTimes(2);
  expect(container.querySelector('[data-testid="bound"]')).not.toBeNull();
});

test('an explicit session 401 opens the canonical shop login', async () => {
  const client = { session: jest.fn().mockRejectedValueOnce(Object.assign(new Error('expired'), { status: 401 })) };
  await mount(client);
  expect(container.querySelector('[data-testid="login"]')).not.toBeNull();
  expect(container.querySelector('[data-testid="login"]').textContent)
    .toContain('next=%2Fsecureshop%2Fadmin%2Fusers');
});

test('an anonymous public catalog keeps the guest storefront', async () => {
  const client = { session: jest.fn().mockResolvedValue(null) };
  await mount(client, '/secureshop/catalog');
  expect(container.querySelector('[data-testid="guest"]')).not.toBeNull();
  expect(container.querySelector('[data-testid="login"]')).toBeNull();
});

test('auth-required verification failure does not remount or redirect until explicit retry', async () => {
  const client = { session: jest.fn().mockResolvedValueOnce({ user: admin, expiresAt: null })
    .mockRejectedValueOnce(Object.assign(new Error('unavailable'), { status: 503 }))
    .mockResolvedValueOnce({ user: admin, expiresAt: null }) };
  await mount(client);
  await act(async () => click('Require authentication'));
  expect(mockBoundMounts).toBe(1);
  expect(container.querySelector('[role="alert"]')).not.toBeNull();
  expect(container.querySelector('[data-testid="login"]')).toBeNull();
  await act(async () => click('Retry'));
  expect(container.querySelector('[data-testid="bound"]')).not.toBeNull();
});

test('renewal failure offers retry without remounting and a successful retry remounts once', async () => {
  const client = { session: jest.fn().mockResolvedValue({ user: admin, expiresAt: null }),
    renew: jest.fn().mockRejectedValueOnce(Object.assign(new Error('unavailable'), { status: 503 }))
      .mockResolvedValueOnce({ user: admin, expiresAt: '2026-10-11T01:00:00Z' }) };
  await mount(client);
  await act(async () => click('Renew session'));
  expect(mockBoundMounts).toBe(1);
  expect(container.querySelector('[role="alert"]')).not.toBeNull();
  await act(async () => click('Retry'));
  expect(client.renew).toHaveBeenCalledTimes(2);
  expect(client.session).toHaveBeenCalledTimes(1);
  expect(mockBoundMounts).toBe(2);
});

test('renewal 401 opens the shop login without retrying or retaining a bound frame', async () => {
  const client = { session: jest.fn().mockResolvedValue({ user: admin, expiresAt: null }),
    renew: jest.fn().mockRejectedValue(Object.assign(new Error('expired'), { status: 401 })) };
  await mount(client);
  await act(async () => click('Renew session'));
  expect(container.querySelector('[data-testid="bound"]')).toBeNull();
  expect(container.querySelector('[data-testid="login"]').textContent)
    .toContain('next=%2Fsecureshop%2Fadmin%2Fusers');
  expect(client.renew).toHaveBeenCalledTimes(1);
});

test('an older session read cannot restore admin after a newer read and customer sign-in', async () => {
  const oldRead = deferred();
  const client = { session: jest.fn()
    .mockResolvedValueOnce({ user: admin, expiresAt: null })
    .mockImplementationOnce(() => oldRead.promise)
    .mockResolvedValueOnce(null),
  login: jest.fn(async () => ({ user: customer, expiresAt: '2026-10-11T01:00:00Z' })) };
  await mount(client);
  act(() => click('Require authentication'));
  await act(async () => click('Require authentication'));
  expect(container.querySelector('[data-testid="login"]').dataset.role).toBe('');
  await act(async () => click('Sign in customer'));
  expect(container.querySelector('[data-testid="login"]').dataset.role).toBe('customer');
  await act(async () => oldRead.resolve({ user: admin, expiresAt: null }));
  expect(container.querySelector('[data-testid="login"]').dataset.role).toBe('customer');
  expect(client.session).toHaveBeenCalledTimes(3);
});

test('logout lands on the public guest shop despite an older session read and late frame intents', async () => {
  const oldRead = deferred();
  const client = { session: jest.fn()
    .mockResolvedValueOnce({ user: admin, expiresAt: null })
    .mockImplementationOnce(() => oldRead.promise),
  logout: jest.fn(async () => {}), renew: jest.fn() };
  await mount(client);
  act(() => click('Require authentication'));
  await act(async () => click('Sign out'));
  await act(async () => click('Require authentication'));
  await act(async () => click('Stale frame route'));
  await act(async () => click('Renew session'));
  expect(client.renew).not.toHaveBeenCalled();
  expect(client.session).toHaveBeenCalledTimes(2);
  await act(async () => oldRead.resolve({ user: admin, expiresAt: null }));
  await act(async () => new Promise(resolve => setTimeout(resolve, 60)));
  expect(container.querySelector('[data-testid="bound"]')).toBeNull();
  expect(container.querySelector('[data-testid="route"]').textContent).toBe('/secureshop');
  expect(container.querySelector('[data-testid="guest"]')).not.toBeNull();
  expect(container.querySelector('[data-testid="login"]')).toBeNull();
  await act(async () => click('Open catalog'));
  expect(container.querySelector('[data-testid="route"]').textContent).toBe('/secureshop/catalog');
  expect(container.querySelector('[data-testid="guest"]')).not.toBeNull();
  await act(async () => click('Open shop login'));
  expect(container.querySelector('[data-testid="route"]').textContent).toBe('/secureshop/login');
  expect(container.querySelector('[data-testid="login"]')).not.toBeNull();
});

test('switch-role preserves its exact login prefill after the prior principal is cleared', async () => {
  const client = { session: jest.fn().mockResolvedValue({ user: admin, expiresAt: null }),
    logout: jest.fn(async () => {}) };
  await mount(client);
  await act(async () => click('Switch role'));
  await act(async () => new Promise(resolve => setTimeout(resolve, 60)));
  expect(client.logout).toHaveBeenCalledTimes(1);
  expect(container.querySelector('[data-testid="route"]').textContent)
    .toBe('/secureshop/login?prefill=student_merchant');
  expect(container.querySelector('[data-testid="bound"]')).toBeNull();
  expect(container.querySelector('[data-testid="login"]').dataset.role).toBe('');
});

test('failed logout preserves the bound session and its route', async () => {
  const client = { session: jest.fn().mockResolvedValue({ user: admin, expiresAt: null }),
    logout: jest.fn().mockRejectedValue(new Error('sign out unavailable')) };
  await mount(client);
  await act(async () => click('Sign out'));
  expect(container.querySelector('[data-testid="route"]').textContent).toBe('/secureshop/admin/users');
  expect(container.querySelector('[data-testid="bound"]').dataset.role).toBe('admin');
  expect(container.querySelector('[data-testid="login"]')).toBeNull();
});

test('a session read settling after unmount cannot publish or navigate', async () => {
  const oldRead = deferred();
  const client = { session: jest.fn()
    .mockResolvedValueOnce({ user: admin, expiresAt: null })
    .mockImplementationOnce(() => oldRead.promise) };
  await mount(client);
  act(() => click('Require authentication'));
  await act(async () => root.unmount());
  root = createRoot(container);
  await act(async () => oldRead.resolve(null));
  expect(container.textContent).toBe('');
});
