import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import Landing from './Landing';
import { useAuth } from '../context/AuthContext';

jest.mock('../context/AuthContext', () => ({ useAuth: jest.fn() }));
jest.mock('framer-motion', () => {
  const React = require('react');
  return {
    motion: new Proxy({}, {
      get: (_, tag) => ({ children, initial, animate, whileInView, viewport, transition, ...props }) =>
        React.createElement(tag, props, children),
    }),
    useReducedMotion: () => true,
  };
});

global.IS_REACT_ACT_ENVIRONMENT = true;

function response(products, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => ({ products }) };
}

describe('SecureShop landing shelves', () => {
  let container;
  let root;
  const originalFetch = global.fetch;

  beforeEach(() => {
    useAuth.mockReturnValue({ isAuthed: false });
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    global.fetch = originalFetch;
    jest.clearAllMocks();
  });

  async function renderLanding() {
    await act(async () => root.render(<MemoryRouter><Landing /></MemoryRouter>));
  }

  test.each([401, 403])('public category denial %s offers retry instead of requiring sign-in', async status => {
    global.fetch = jest.fn().mockResolvedValue(response(undefined, status));
    await renderLanding();
    expect(container.textContent).toContain('Products are unavailable right now.');
    expect([...container.querySelectorAll('button')].some(button => button.textContent === 'Retry')).toBe(true);
    expect(container.textContent).not.toContain('Sign in to view electronics products.');
    expect(container.textContent).not.toContain('No products in Electronics yet.');
  });

  test('a successful empty category reports a genuinely empty shelf', async () => {
    global.fetch = jest.fn().mockResolvedValue(response([]));
    await renderLanding();
    expect(container.textContent).toContain('No products in Electronics yet.');
    expect(container.textContent).not.toContain('Sign in to view electronics products.');
  });

  test('network failure offers retry and recovers when the fetch succeeds', async () => {
    global.fetch = jest.fn().mockRejectedValueOnce(new Error('connection refused'))
      .mockResolvedValue(response([]));
    await renderLanding();
    expect(container.textContent).toContain('Products are unavailable right now.');
    expect(container.textContent).not.toContain('connection refused');
    const retry = [...container.querySelectorAll('button')].find((button) => button.textContent === 'Retry');
    await act(async () => retry.click());
    expect(global.fetch).toHaveBeenCalledTimes(6);
    expect(container.textContent).toContain('No products in Electronics yet.');
  });
});
