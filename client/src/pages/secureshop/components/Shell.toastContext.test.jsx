import React, { act, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import Shell from './Shell';
import { useToast } from '../context/ToastContext.jsx';

jest.mock('./TopNav.jsx', () => () => null);
let laneMounts = 0;
jest.mock('./AgentLane.jsx', () => props => {
  const React = require('react'); const [count, setCount] = React.useState(0);
  React.useEffect(() => { laneMounts += 1; }, []);
  return <button type="button" data-testid="lane-state" data-instance={props.instance} data-role={props.role}
    onClick={() => setCount(value => value + 1)}>lane {count}</button>;
});
jest.mock('./Footer.jsx', () => () => null);
let mockAuth = { isAuthed: false, user: null };
const originalMatchMedia = globalThis.matchMedia;
function installViewport(initiallyMobile) {
  const listeners = new Set();
  const query = { matches: initiallyMobile, addEventListener: (_, listener) => listeners.add(listener),
    removeEventListener: (_, listener) => listeners.delete(listener) };
  globalThis.matchMedia = () => query;
  return mobile => {
    query.matches = mobile;
    listeners.forEach(listener => listener({ matches: mobile }));
  };
}
afterEach(() => { globalThis.matchMedia = originalMatchMedia; });
jest.mock('../context/AuthContext', () => ({ useAuth: () => mockAuth }));
jest.mock('../context/CartContext.jsx', () => ({ CartProvider: ({ children }) => children }));
jest.mock('framer-motion', () => {
  const React = require('react');
  const element = tag => React.forwardRef(function Motion({ initial, animate, exit,
    transition, ...props }, ref) { return React.createElement(tag, { ...props, ref }); });
  return { motion: { div: element('div') }, AnimatePresence: ({ children }) => <>{children}</>,
    useReducedMotion: () => true };
});

test('Shell provides one stable toast API to routed pages across state updates', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const observed = [];
  function Probe() {
    const toast = useToast();
    const [count, setCount] = useState(0);
    observed.push(toast);
    return <button type="button" onClick={() => setCount(value => value + 1)}>{count}</button>;
  }
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/']}>
      <Routes><Route element={<Shell />}><Route index element={<Probe />} /></Route></Routes>
    </MemoryRouter>));
    await act(async () => node.querySelector('button').click());
    expect(observed.length).toBeGreaterThanOrEqual(2);
    expect(new Set(observed).size).toBe(1);
  } finally {
    await act(async () => root.unmount()); node.remove();
  }
});

test('the no-provider toast API is also referentially stable', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const observed = [];
  function Probe() {
    const toast = useToast(); const [count, setCount] = useState(0);
    observed.push(toast);
    return <button type="button" onClick={() => setCount(value => value + 1)}>{count}</button>;
  }
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<Probe />));
    await act(async () => node.querySelector('button').click());
    expect(new Set(observed).size).toBe(1);
  } finally {
    await act(async () => root.unmount()); node.remove();
  }
});


test('one AgentLane preserves its chat state through breakpoint, drawer, and recovery handoff', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true; mockAuth = { isAuthed: true, user: { role: 'customer' } }; laneMounts = 0;
  const setMobile = installViewport(false);
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<MemoryRouter><Routes><Route element={<Shell />}><Route index element={<div />} /></Route></Routes></MemoryRouter>));
    const lane = node.querySelector('[data-testid="lane-state"]');
    expect(lane.dataset.instance).toBe('desktop');
    expect(laneMounts).toBe(1);
    await act(async () => lane.click());
    expect(lane.textContent).toBe('lane 1');
    await act(async () => setMobile(true));
    expect(node.querySelector('[data-testid="lane-state"]')).toBe(lane);
    expect(lane.dataset.instance).toBe('mobile');
    expect(lane.closest('[aria-hidden="true"]')).not.toBeNull();
    expect(lane.closest('[inert]')).not.toBeNull();
    await act(async () => [...node.querySelectorAll('button')].find(button => button.getAttribute('aria-label') === 'Open agent lane').click());
    expect(node.querySelectorAll('[data-testid="lane-state"]')).toHaveLength(1);
    expect(lane.textContent).toBe('lane 1');
    expect(lane.closest('[aria-hidden="true"]')).toBeNull();
    await act(async () => [...node.querySelectorAll('button')].find(button => button.getAttribute('aria-label') === 'Close').click());
    expect(lane.textContent).toBe('lane 1');
    expect(lane.closest('[aria-hidden="true"]')).not.toBeNull();
    await act(async () => [...node.querySelectorAll('button')].find(button => button.getAttribute('aria-label') === 'Open agent lane').click());
    expect(node.querySelector('[data-testid="lane-state"]')).toBe(lane);
    expect(lane.textContent).toBe('lane 1');
    expect(laneMounts).toBe(1);
  } finally { mockAuth = { isAuthed: false, user: null }; await act(async () => root.unmount()); node.remove(); }
});

test.each(['merchant', 'admin'])('mobile drawer mounts the %s agent controls on open', async role => {
  global.IS_REACT_ACT_ENVIRONMENT = true; mockAuth = { isAuthed: true, user: { role } }; laneMounts = 0;
  installViewport(true);
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<MemoryRouter><Routes><Route element={<Shell />}>
      <Route index element={<div />} /></Route></Routes></MemoryRouter>));
    expect(node.querySelector('[data-testid="lane-state"]')).not.toBeNull();
    expect(node.querySelector('[data-testid="lane-state"]').closest('[inert]')).not.toBeNull();
    await act(async () => node.querySelector('button[aria-label="Open agent lane"]').click());
    const lane = node.querySelector('.ss-lane-mobile-content [data-testid="lane-state"]');
    expect(lane?.getAttribute('data-role')).toBe(role);
    expect(lane.closest('[aria-hidden="true"]')).toBeNull();
    await act(async () => node.querySelector('button[aria-label="Close"]').click());
    expect(lane.closest('[aria-hidden="true"]')).not.toBeNull();
    expect(laneMounts).toBe(1);
  } finally { mockAuth = { isAuthed: false, user: null }; await act(async () => root.unmount()); node.remove(); }
});
