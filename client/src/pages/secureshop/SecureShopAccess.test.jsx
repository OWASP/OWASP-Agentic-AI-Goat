import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import SecureShopAccess from './SecureShopAccess';

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname}</output>;
}

function RolePrefillNavigation() {
  const navigate = useNavigate();
  return <button type="button" onClick={() => navigate('/secureshop/login?prefill=student_merchant')}>
    Switch to merchant
  </button>;
}

describe('standalone SecureShop sign in', () => {
  let container;
  let root;

  beforeEach(() => {
    global.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
  });

  async function renderAccess(login, next = '/secureshop/checkout') {
    await act(async () => root.render(
      <MemoryRouter initialEntries={[`/secureshop/login?next=${encodeURIComponent(next)}`]}>
        <Routes>
          <Route path="/secureshop/login" element={<SecureShopAccess login={login} />} />
          <Route path="*" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>,
    ));
  }

  async function submit(username = 'student_customer', password = 'student123') {
    const inputs = container.querySelectorAll('input');
    await act(async () => {
      for (const [input, value] of [[inputs[0], username], [inputs[1], password]]) {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
      container.querySelector('button[type="submit"]').click();
    });
  }

  test('uses shop credentials and preserves a checkout deep link', async () => {
    const login = jest.fn().mockResolvedValue({ username: 'student_customer', role: 'customer' });
    await renderAccess(login);
    expect(container.textContent).toContain('Demo accounts');
    expect(container.textContent).not.toContain('DVAIA platform account');
    await submit();
    expect(login).toHaveBeenCalledWith('student_customer', 'student123');
    expect(container.querySelector('[data-testid="location"]')?.textContent).toBe('/secureshop/checkout');
  });

  test('shows an auth failure without leaving shop sign in', async () => {
    const login = jest.fn().mockRejectedValue(new Error('Invalid credentials'));
    await renderAccess(login);
    await submit();
    expect(container.querySelector('[role="alert"]')?.textContent).toBe('Invalid credentials');
    expect(container.querySelector('[data-testid="location"]')).toBeNull();
  });

  test('role-switch query fills an already-mounted standalone sign-in form', async () => {
    const login = jest.fn();
    await act(async () => root.render(
      <MemoryRouter initialEntries={['/secureshop/login']}>
        <RolePrefillNavigation />
        <Routes><Route path="/secureshop/login" element={<SecureShopAccess login={login} />} /></Routes>
      </MemoryRouter>,
    ));
    expect(container.querySelector('#ss-login-user').value).toBe('');
    await act(async () => container.querySelector('button').click());
    expect(container.querySelector('#ss-login-user').value).toBe('student_merchant');
    expect(container.querySelector('#ss-login-pw').value).toBe('student123');
    expect(login).not.toHaveBeenCalled();
  });
});
