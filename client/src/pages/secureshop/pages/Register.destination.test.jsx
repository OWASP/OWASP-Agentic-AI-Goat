import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import Register from './Register.jsx';
import { useAuth } from '../context/AuthContext';

jest.mock('../context/AuthContext', () => ({ useAuth: jest.fn() }));

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname}{location.search}</output>;
}

let node;
let root;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div');
  root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); jest.clearAllMocks(); });

async function renderRegistration(next) {
  await act(async () => root.render(<MemoryRouter initialEntries={[`/secureshop/register?next=${encodeURIComponent(next)}`]}>
    <Routes>
      <Route path="/secureshop/register" element={<Register />} />
      <Route path="*" element={<LocationProbe />} />
    </Routes>
  </MemoryRouter>));
}

async function fill(input, value) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
}

test.each(['https://evil.invalid/path', '//evil.invalid/path', '/%2Fevil.invalid/path'])
  ('registration refuses foreign or protocol-relative next %s', async next => {
    useAuth.mockReturnValue({ register: jest.fn(), isAuthed: true, user: { role: 'customer' } });
    await renderRegistration(next);
    expect(node.querySelector('[data-testid="location"]').textContent).toBe('/secureshop/home');
  });

test('new merchant registration cannot be redirected into an admin destination', async () => {
  const register = jest.fn().mockResolvedValue({ role: 'merchant' });
  useAuth.mockReturnValue({ register, isAuthed: false, user: null });
  await renderRegistration('/secureshop/admin/audit?tab=events');
  await fill(node.querySelector('#reg-user'), 'newmerchant');
  await fill(node.querySelector('#reg-email'), 'newmerchant@example.test');
  await fill(node.querySelector('#reg-pw'), 'GoodPassword123!');
  await fill(node.querySelector('#reg-pw2'), 'GoodPassword123!');
  await act(async () => node.querySelector('button[aria-pressed="false"]').click());
  expect(node.querySelector('button[type="submit"]').disabled).toBe(false);
  await act(async () => node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  expect(register).toHaveBeenCalledWith(expect.objectContaining({ username: 'newmerchant', role: 'merchant' }));
  expect(node.querySelector('[data-testid="location"]').textContent).toBe('/secureshop/merchant');
});
