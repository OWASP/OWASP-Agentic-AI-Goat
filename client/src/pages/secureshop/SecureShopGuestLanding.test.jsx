import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import SecureShopGuestLanding from './SecureShopGuestLanding';
import { mountShopFrame } from './bridge/handshake.mjs';
import { GUEST_CART_CHANNEL, GUEST_CART_STORAGE_KEY } from './bridge/guestCartProtocol.mjs';

jest.mock('./bridge/handshake.mjs', () => ({ mountShopFrame: jest.fn() }));

test('a disconnected ready storefront offers Retry and mounts a fresh frame', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mountShopFrame.mockReset().mockImplementation(({ frame }) => {
    frame.src = 'http://localhost/secureshop-frame.html?guest=1#' + 'a'.repeat(64);
    return { ready: Promise.resolve(), close: jest.fn() };
  });
  const host = document.createElement('div'), root = createRoot(host);
  document.body.appendChild(host);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/secureshop/catalog']}>
      <Routes><Route path="/secureshop/*" element={<SecureShopGuestLanding />} /></Routes>
    </MemoryRouter>));
    const firstFrame = host.querySelector('iframe');
    await act(async () => mountShopFrame.mock.calls[0][0].onDisconnect());
    expect(host.textContent).toContain('OWASP AI SecureShop is currently unavailable.');
    await act(async () => host.querySelector('button').click());
    expect(mountShopFrame).toHaveBeenCalledTimes(2);
    expect(host.querySelector('iframe')).not.toBe(firstFrame);
  } finally { await act(async () => root.unmount()); host.remove(); }
});

test('guest storefront mounts an opaque read-only frame without workshop feature flags', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mountShopFrame.mockReset().mockImplementation(({ frame }) => {
    frame.src = 'http://localhost/secureshop-frame.html?guest=1#' + 'a'.repeat(64);
    frame.setAttribute('sandbox', 'allow-scripts allow-forms');
    return { ready: Promise.resolve(), close: jest.fn() };
  });
  const host = document.createElement('div'), root = createRoot(host);
  document.body.appendChild(host);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/secureshop/product/1']}>
      <Routes><Route path="/secureshop/*" element={<SecureShopGuestLanding />} /></Routes>
    </MemoryRouter>));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(mountShopFrame).toHaveBeenCalledTimes(1);
    const options = mountShopFrame.mock.calls[0][0];
    expect(options.transportOptions).toEqual({ publicOnly: true });
    expect(options.getLaunchBearer).toBeUndefined();
    expect(options.url).toContain('guest=1');
    expect(options.url).toContain('product%2F1');
    expect(host.querySelector('iframe')?.getAttribute('sandbox')).toBe('allow-scripts allow-forms');
  } finally { await act(async () => root.unmount()); host.remove(); }
});

test('guest connection error keeps its home link inside OWASP AI SecureShop', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mountShopFrame.mockReset().mockImplementation(({ frame }) => {
    frame.src = 'http://localhost/secureshop-frame.html?guest=1#' + 'a'.repeat(64);
    return { ready: Promise.reject(new Error('frame unavailable')), close: jest.fn() };
  });
  const host = document.createElement('div'), root = createRoot(host);
  document.body.appendChild(host);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/secureshop/catalog']}>
      <Routes><Route path="/secureshop/*" element={<SecureShopGuestLanding />} /></Routes>
    </MemoryRouter>));
    expect(host.textContent).toContain('OWASP AI SecureShop is currently unavailable.');
    expect(host.querySelector('a[href="/secureshop"]')?.textContent).toBe('Back to home');
    expect(host.querySelector('a[href="/"]')).toBeNull();
  } finally { await act(async () => root.unmount()); host.remove(); }
});

test('catalog to cart parent URL sync retains the same guest frame and its local cart lease', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mountShopFrame.mockReset().mockImplementation(({ frame }) => {
    frame.src = 'http://localhost/secureshop-frame.html?guest=1#' + 'a'.repeat(64);
    frame.setAttribute('sandbox', 'allow-scripts allow-forms');
    return { ready: Promise.resolve(), close: jest.fn() };
  });
  let changeRoute;
  function RouteControl() { changeRoute = useNavigate(); return null; }
  const host = document.createElement('div'), root = createRoot(host);
  document.body.appendChild(host);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/secureshop/product/1']}>
      <RouteControl />
      <Routes><Route path="/secureshop/*" element={<SecureShopGuestLanding />} /></Routes>
    </MemoryRouter>));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    const frame = host.querySelector('iframe');
    expect(frame).not.toBeNull();
    await act(async () => changeRoute('/secureshop/cart'));
    expect(host.querySelector('iframe')).toBe(frame);
    expect(mountShopFrame).toHaveBeenCalledTimes(1);
    expect(mountShopFrame.mock.results[0].value.close).not.toHaveBeenCalled();
  } finally { await act(async () => root.unmount()); host.remove(); }
});

test('an unknown guest path shows storefront not-found without opening sign-in or a frame', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mountShopFrame.mockReset();
  function RoutePath() { const location = useLocation(); return <div data-testid="path">{location.pathname}</div>; }
  const host = document.createElement('div'), root = createRoot(host);
  document.body.appendChild(host);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/secureshop/account-typo']}>
      <RoutePath />
      <Routes><Route path="/secureshop/*" element={<SecureShopGuestLanding />} /></Routes>
    </MemoryRouter>));
    expect(host.querySelector('[data-testid="path"]').textContent).toBe('/secureshop/account-typo');
    expect(host.textContent).toContain("This aisle doesn't exist.");
    expect(host.querySelector('iframe')).toBeNull();
    expect(mountShopFrame).not.toHaveBeenCalled();
  } finally { await act(async () => root.unmount()); host.remove(); }
});

test('known protected checkout still opens standalone sign-in with its exact return route', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mountShopFrame.mockReset();
  function LoginDestination() { const location = useLocation(); return <div data-testid="login">{location.search}</div>; }
  const host = document.createElement('div'), root = createRoot(host);
  document.body.appendChild(host);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/secureshop/checkout']}>
      <Routes>
        <Route path="/secureshop/login" element={<LoginDestination />} />
        <Route path="/secureshop/*" element={<SecureShopGuestLanding />} />
      </Routes>
    </MemoryRouter>));
    expect(host.querySelector('[data-testid="login"]').textContent).toBe('?next=%2Fsecureshop%2Fcheckout');
    expect(mountShopFrame).not.toHaveBeenCalled();
  } finally { await act(async () => root.unmount()); host.remove(); }
});

test('navigating from public catalog to an unknown path closes the guest frame', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mountShopFrame.mockReset().mockImplementation(({ frame }) => {
    frame.src = 'http://localhost/secureshop-frame.html?guest=1#' + 'a'.repeat(64);
    return { ready: Promise.resolve(), close: jest.fn() };
  });
  let changeRoute;
  function RouteControl() { changeRoute = useNavigate(); return null; }
  const host = document.createElement('div'), root = createRoot(host);
  document.body.appendChild(host);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/secureshop/catalog']}>
      <RouteControl />
      <Routes><Route path="/secureshop/*" element={<SecureShopGuestLanding />} /></Routes>
    </MemoryRouter>));
    expect(host.querySelector('iframe')).not.toBeNull();
    await act(async () => changeRoute('/secureshop/catalog-typo'));
    expect(mountShopFrame.mock.results[0].value.close).toHaveBeenCalledTimes(1);
    expect(host.querySelector('iframe')).toBeNull();
    expect(host.textContent).toContain("This aisle doesn't exist.");
  } finally { await act(async () => root.unmount()); host.remove(); }
});

test('parent persists only nonce-verified guest cart IDs and quantities', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  sessionStorage.clear();
  mountShopFrame.mockReset().mockImplementation(({ frame }) => {
    frame.src = 'http://localhost/secureshop-frame.html?guest=1#' + 'a'.repeat(64);
    frame.setAttribute('sandbox', 'allow-scripts allow-forms');
    return { ready: Promise.resolve(), close: jest.fn() };
  });
  const host = document.createElement('div'), root = createRoot(host);
  document.body.appendChild(host);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/secureshop/cart']}>
      <Routes><Route path="/secureshop/*" element={<SecureShopGuestLanding />} /></Routes>
    </MemoryRouter>));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    const frame = host.querySelector('iframe');
    const send = (data, source = frame.contentWindow) => window.dispatchEvent(new MessageEvent('message', {
      source, origin: 'null', data,
    }));
    const base = { channel: GUEST_CART_CHANNEL, type: 'snapshot', nonce: 'a'.repeat(64), baseRevision: 0 };
    await act(async () => send({ ...base, items: [{ productId: 125, quantity: 2, price: 0 }] }));
    expect(sessionStorage.getItem(GUEST_CART_STORAGE_KEY)).toBeNull();
    await act(async () => send({ ...base, items: [{ productId: 125, quantity: 2 }] }, window));
    expect(sessionStorage.getItem(GUEST_CART_STORAGE_KEY)).toBeNull();
    await act(async () => send({ ...base, items: [{ productId: 125, quantity: 2 }] }));
    expect(JSON.parse(sessionStorage.getItem(GUEST_CART_STORAGE_KEY))).toEqual({ version: 1,
      revision: 1, items: [{ productId: 125, quantity: 2 }] });
  } finally { await act(async () => root.unmount()); host.remove(); sessionStorage.clear(); }
});

test('guest registration intent opens the independent register form with a safe return route', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mountShopFrame.mockReset().mockImplementation(({ frame }) => {
    frame.src = 'http://localhost/secureshop-frame.html?guest=1#' + 'a'.repeat(64);
    frame.setAttribute('sandbox', 'allow-scripts allow-forms');
    return { ready: Promise.resolve(), close: jest.fn() };
  });
  function RegisterDestination() {
    const location = useLocation();
    return <div data-testid="register-destination">{`${location.pathname}${location.search}`}</div>;
  }
  const host = document.createElement('div'), root = createRoot(host);
  document.body.appendChild(host);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/secureshop/product/7']}>
      <Routes>
        <Route path="/secureshop/register" element={<RegisterDestination />} />
        <Route path="/secureshop/*" element={<SecureShopGuestLanding />} />
      </Routes>
    </MemoryRouter>));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    const frame = host.querySelector('iframe');
    const intent = { channel: 'owasp-ai-goat-secureshop-guest-route-v1', type: 'register',
      nonce: 'a'.repeat(64), route: '/secureshop/product/7' };
    const send = (data, origin = 'null') => window.dispatchEvent(new MessageEvent('message', {
      source: frame.contentWindow, origin, data,
    }));
    await act(async () => send(intent, 'http://evil.example'));
    expect(host.querySelector('[data-testid="register-destination"]')).toBeNull();
    await act(async () => send({ ...intent, route: 'https://evil.example' }));
    expect(host.querySelector('[data-testid="register-destination"]')).toBeNull();
    await act(async () => send(intent));
    expect(host.querySelector('[data-testid="register-destination"]')?.textContent)
      .toBe('/secureshop/register?next=%2Fsecureshop%2Fproduct%2F7');
  } finally { await act(async () => root.unmount()); host.remove(); }
});
