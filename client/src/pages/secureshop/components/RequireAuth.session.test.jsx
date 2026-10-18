import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import RequireAuth from './RequireAuth.jsx';

let state;
jest.mock('../context/AuthContext', () => ({ useAuth: () => state }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn() } }));

let host;
let root;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  host = document.createElement('div');
  document.body.append(host);
  root = createRoot(host);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
});

async function renderRoute(initialEntry = '/secureshop/admin/users?tab=all') {
  await act(async () => root.render(<MemoryRouter initialEntries={[initialEntry]}>
    <Routes>
      <Route path="/secureshop/admin/users" element={<RequireAuth requireRole="admin"><div data-testid="protected" /></RequireAuth>} />
      <Route path="/secureshop/merchant/listings" element={<RequireAuth requireRole="merchant"><div data-testid="protected" /></RequireAuth>} />
      <Route path="/secureshop/login" element={<LoginLocation />} />
    </Routes>
  </MemoryRouter>));
}

function LoginLocation() {
  const location = useLocation();
  return <div data-testid="login" data-next={location.search} />;
}

test('retained token and transient verification failure show retry without protected content or login redirect', async () => {
  const retrySession = jest.fn();
  state = { isAuthed: false, loading: false, user: null, token: 'retained-token',
    error: 'Unable to verify the shop session right now.', retrySession };
  await renderRoute();
  expect(host.querySelector('[data-testid="protected"]')).toBeNull();
  expect(host.querySelector('[data-testid="login"]')).toBeNull();
  expect(host.querySelector('[role="alert"]')).not.toBeNull();
  expect(host.querySelector('button').className).toBe('ss-btn ss-btn--ghost ss-btn--sm');
  await act(async () => host.querySelector('button').click());
  expect(retrySession).toHaveBeenCalledTimes(1);
  state = { ...state, isAuthed: true, user: { role: 'admin' }, error: null };
  await renderRoute();
  expect(host.querySelector('[data-testid="protected"]')).not.toBeNull();
});

test('a confirmed absent token redirects to the shop login', async () => {
  state = { isAuthed: false, loading: false, user: null, token: null, error: null,
    retrySession: jest.fn() };
  await renderRoute();
  expect(host.querySelector('[data-testid="login"]')).not.toBeNull();
});

test('unauthenticated route continuation retains an admitted fragment', async () => {
  state = { isAuthed: false, loading: false, user: null, token: null, error: null,
    retrySession: jest.fn() };
  await renderRoute('/secureshop/merchant/listings#new');
  expect(host.querySelector('[data-testid="login"]')?.dataset.next)
    .toBe('?next=%2Fsecureshop%2Fmerchant%2Flistings%23new');
});
