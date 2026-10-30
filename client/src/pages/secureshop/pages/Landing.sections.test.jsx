import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import Landing from './Landing';
import Footer from '../components/Footer.jsx';
import { useAuth } from '../context/AuthContext';
import { safeShopRoute } from '../bridge/guestRouting.mjs';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

jest.mock('../context/AuthContext', () => ({ useAuth: jest.fn() }));
jest.mock('framer-motion', () => {
  const React = require('react');
  return {
    motion: new Proxy({}, { get: (_, tag) => ({ children, initial, animate, whileInView,
      viewport, transition, ...props }) => React.createElement(tag, props, children) }),
    useReducedMotion: () => true,
  };
});

function CurrentRoute() {
  const location = useLocation();
  return <output data-testid="shop-route">{`${location.pathname}${location.hash}`}</output>;
}

const originalFetch = global.fetch;
const originalScroll = Element.prototype.scrollIntoView;
let container;
let root;
let scroll;

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  useAuth.mockReturnValue({ isAuthed: false });
  global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200,
    json: async () => ({ products: [] }) });
  scroll = jest.fn();
  Element.prototype.scrollIntoView = scroll;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  global.fetch = originalFetch;
  Element.prototype.scrollIntoView = originalScroll;
  jest.clearAllMocks();
});

async function renderAt(route) {
  await act(async () => root.render(<MemoryRouter initialEntries={[route]}>
    <Routes>
      <Route path="/secureshop" element={<Landing />} />
      <Route path="/secureshop/catalog" element={<Footer />} />
    </Routes>
    <CurrentRoute />
  </MemoryRouter>));
}

test.each([
  ['How OWASP AI SecureShop thinks', 'about'],
  ['Agent lane', 'agent-lane'],
  ['Lab notes', 'lab-notes'],
])('footer %s navigates within MemoryRouter and scrolls its landing section', async (label, section) => {
  await renderAt('/secureshop/catalog');
  const physicalHash = window.location.hash;
  const link = [...container.querySelectorAll('a')].find(node => node.textContent === label);
  expect(link?.getAttribute('href')).toBe(`/secureshop#${section}`);
  await act(async () => link.click());
  expect(container.querySelector('[data-testid="shop-route"]').textContent).toBe(`/secureshop#${section}`);
  expect(scroll).toHaveBeenCalledTimes(1);
  expect(scroll.mock.instances[0].id).toBe(section);
  expect(window.location.hash).toBe(physicalHash);
  expect(safeShopRoute(`/secureshop#${section}`)).toBe(`/secureshop#${section}`);
});

test('same section can be clicked again and How it works uses the same local route', async () => {
  await renderAt('/secureshop');
  const about = [...container.querySelectorAll('a')]
    .find(node => node.textContent === 'How OWASP AI SecureShop thinks');
  await act(async () => about.click());
  await act(async () => about.click());
  expect(scroll).toHaveBeenCalledTimes(2);
  expect(scroll.mock.instances.every(node => node.id === 'about')).toBe(true);
  const how = [...container.querySelectorAll('a')]
    .find(node => node.textContent === 'How it works');
  await act(async () => how.click());
  expect(scroll.mock.instances.at(-1).id).toBe('how');
});

test('editorial uses a scoped grid that stacks at the existing narrow breakpoint', async () => {
  await renderAt('/secureshop');
  const editorial = container.querySelector('.ss-landing-editorial');
  expect(editorial).toBeTruthy();
  expect(editorial.querySelector('h2')?.textContent).toBe('How OWASP AI SecureShop thinks.');
  expect(editorial.style.gridTemplateColumns).toBe('');
  const css = readFileSync(join(__dirname, '../theme.css'), 'utf8');
  expect(css).toMatch(/\.ss-landing-editorial\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s+minmax\(0,\s*1\.4fr\)/);
  const narrow = css.slice(css.indexOf('@media (max-width: 900px)'), css.indexOf('@media (max-width: 600px)'));
  expect(narrow).toMatch(/\.ss-landing-editorial\s*\{\s*grid-template-columns:\s*minmax\(0,\s*1fr\)/);
});

test.each(['/secureshop#other', '/secureshop#%61bout', '/secureshop#about/..'])
('unknown or malformed section %s cannot scroll or enter a parent route', async route => {
  await renderAt(route);
  expect(scroll).not.toHaveBeenCalled();
  expect(safeShopRoute(route)).toBeNull();
});

test.each([
  ['merchant', '/secureshop/merchant'],
  ['admin', '/secureshop/admin'],
])('authenticated %s users continue to their role home', async (role, destination) => {
  useAuth.mockReturnValue({ isAuthed: true, user: { role } });
  await renderAt('/secureshop');
  const continueLinks = [...container.querySelectorAll('a')]
    .filter(node => ['Continue shopping', 'Continue'].includes(node.textContent.trim()));
  expect(continueLinks).toHaveLength(2);
  expect(continueLinks.map(node => node.getAttribute('href'))).toEqual([destination, destination]);
});
