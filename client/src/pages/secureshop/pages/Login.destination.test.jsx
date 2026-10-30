import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import Login from './Login.jsx';
import { useAuth } from '../context/AuthContext';

jest.mock('../context/AuthContext', () => ({ useAuth: jest.fn() }));

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname}{location.search}</output>;
}

describe('OWASP AI SecureShop login destination', () => {
  let container;
  let root;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    jest.clearAllMocks();
  });

  async function submit(user, next) {
    const login = jest.fn().mockResolvedValue(user);
    useAuth.mockReturnValue({ login, isAuthed: false, user: null });
    await act(async () => root.render(
      <MemoryRouter initialEntries={[`/secureshop/login?next=${encodeURIComponent(next)}`]}>
        <Routes>
          <Route path="/secureshop/login" element={<Login />} />
          <Route path="*" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>,
    ));
    const inputs = container.querySelectorAll('input');
    await act(async () => {
      const set = (input, value) => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      };
      set(inputs[0], 'student');
      set(inputs[1], 'student123');
      container.querySelector('button[type="submit"]').click();
    });
    return { login, location: container.querySelector('[data-testid="location"]')?.textContent };
  }

  test('uses the authenticated merchant role for same-role next', async () => {
    const result = await submit({ role: 'merchant' }, '/secureshop/merchant/listings');
    expect(result.login).toHaveBeenCalledWith('student', 'student123');
    expect(result.location).toBe('/secureshop/merchant/listings');
  });

  test('falls back home when customer logs into a merchant next', async () => {
    const result = await submit({ role: 'customer' }, '/secureshop/merchant/listings');
    expect(result.location).toBe('/secureshop/home');
  });

  test('merchant login defaults to merchant overview when next targets customer home', async () => {
    const result = await submit({ role: 'merchant' }, '/secureshop/home');
    expect(result.location).toBe('/secureshop/merchant');
  });

  test('admin login keeps a shared product deep link', async () => {
    const result = await submit({ role: 'admin' }, '/secureshop/product/7');
    expect(result.location).toBe('/secureshop/product/7');
  });
});
