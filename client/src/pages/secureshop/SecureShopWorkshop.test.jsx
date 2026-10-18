import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';
import SecureShopWorkshop from './SecureShopWorkshop';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));

const mockLogout = jest.fn();
jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 17 }, logout: mockLogout }) }));
jest.mock('../../components/workshop/WorkshopExperience', () => ({
  ResetConfirmation: ({ open, status, title, description, error, onCancel, onConfirm }) => open &&
    <div role="alertdialog" aria-label={title} data-status={status}>
      <p>{description}</p>{error && <p role="alert">{error}</p>}
      <button type="button" onClick={onCancel} disabled={status === 'resetting'}>Cancel</button>
      <button type="button" onClick={onConfirm} disabled={status === 'resetting'}>Confirm reset</button>
    </div>,
}));
let node; let root;
function RouteProbe() {
  const location = useLocation();
  const navigate = useNavigate();
  return <><output data-testid="parent-route">{location.pathname}{location.search}</output>
    <button type="button" data-testid="parent-navigation" onClick={() => navigate('/secureshop/catalog?q=phone')}>Navigate parent</button></>;
}
function renderWorkshop(createController, route = '/secureshop') {
  root.render(<MemoryRouter initialEntries={[route]}>
    <RouteProbe />
    <SecureShopWorkshop createController={createController} />
  </MemoryRouter>);
}
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.setItem('token', 'platform-token');
  axios.get.mockResolvedValue({ data: { success: true, version: 1, mode: 'vuln', effectiveMode: 'vuln',
    defaultMode: 'vuln', selectableModes: ['vuln', 'fixed'], allowedModes: ['vuln', 'fixed'],
    scope: { kind: 'owner', id: 'secureshop_agent_security' }, features: [
      { featureId: 'analytics', policyVersion: 1, scope: { kind: 'launch_feature', id: 'analytics' } },
    ] } });
  node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
});
afterEach(async () => {
  await act(async () => root.unmount()); node.remove(); localStorage.clear(); jest.clearAllMocks();
});

test('starts one controller, confirms the scoped reset, and closes without revoking on unmount', async () => {
  const controller = { start: jest.fn().mockResolvedValue({}), reset: jest.fn().mockResolvedValue({}),
    close: jest.fn() };
  const createController = jest.fn(options => {
    queueMicrotask(() => options.onState({ status: 'ready' })); return controller;
  });
  await act(async () => { renderWorkshop(createController); });
  expect(controller.start).toHaveBeenCalledWith(node.querySelector('[data-testid="secureshop-frame-host"]'));
  expect(node.querySelector('main[aria-label="SecureShop"]').style.position).toBe('fixed');
  expect(node.textContent).not.toMatch(/workshop|objectives|exercises/i);
  await act(async () => node.querySelector('button[aria-controls="secureshop-settings"]').click());
  const reset = [...node.querySelectorAll('button')].find(button => button.textContent === 'Reset shop');
  await act(async () => { reset.click(); });
  expect(controller.reset).not.toHaveBeenCalled();
  expect(node.querySelector('[role="alertdialog"]').textContent).toContain("Other shoppers' data is preserved");
  await act(async () => { node.querySelector('[role="alertdialog"] button:last-child').click(); });
  expect(controller.reset).toHaveBeenCalledTimes(1);
  await act(async () => root.unmount());
  expect(controller.close).toHaveBeenCalledTimes(1);
  expect(controller).not.toHaveProperty('revoke');
  root = createRoot(node);
});

test('passes an owned admin deep link to the bound frame controller', async () => {
  const controller = { start: jest.fn().mockResolvedValue({}), reset: jest.fn(), close: jest.fn() };
  const createController = jest.fn(() => controller);
  await act(async () => renderWorkshop(createController, '/secureshop/admin/audit?tab=events'));
  expect(createController.mock.calls[0][0].initialRoute).toBe('/secureshop/admin/audit?tab=events');
});

test('syncs current bound-frame routes to the parent URL and parent navigation back into the same frame', async () => {
  const nonce = 'a'.repeat(64);
  const frame = document.createElement('iframe');
  frame.src = `http://localhost/secureshop-frame.html#${nonce}`;
  const controller = { start: jest.fn(host => { host.replaceChildren(frame); return Promise.resolve({}); }),
    reset: jest.fn(), close: jest.fn() };
  const createController = jest.fn(options => {
    queueMicrotask(() => options.onState({ status: 'ready', launch: { launchId: 'owned', generation: 1 } }));
    return controller;
  });
  await act(async () => renderWorkshop(createController));
  const postMessage = jest.spyOn(frame.contentWindow, 'postMessage').mockImplementation(() => {});
  const send = (source, route, messageNonce = nonce) => window.dispatchEvent(new MessageEvent('message', {
    origin: 'null', source, data: { channel: 'dvaia-secureshop-bound-route-v1', type: 'route',
      nonce: messageNonce, route },
  }));
  await act(async () => send(frame.contentWindow, '/secureshop/home'));
  expect(node.querySelector('[data-testid="parent-route"]').textContent).toBe('/secureshop/home');
  expect(controller.start).toHaveBeenCalledTimes(1);
  await act(async () => send(frame.contentWindow, '/secureshop/admin/audit?tab=events', 'b'.repeat(64)));
  expect(node.querySelector('[data-testid="parent-route"]').textContent).toBe('/secureshop/home');
  await act(async () => node.querySelector('[data-testid="parent-navigation"]').click());
  expect(node.querySelector('[data-testid="parent-route"]').textContent).toBe('/secureshop/catalog?q=phone');
  expect(postMessage).toHaveBeenCalledWith({ channel: 'dvaia-secureshop-bound-route-v1', type: 'set-route',
    nonce, route: '/secureshop/catalog?q=phone' }, '*');
  expect(controller.start).toHaveBeenCalledTimes(1);
});

test('renders bounded launch errors and reconnect creates a fresh controller', async () => {
  const instances = [];
  const createController = jest.fn(options => {
    const controller = { start: jest.fn(() => {
      options.onState({ status: 'error', message: 'Launch store unavailable' });
      return Promise.reject(new Error('Launch store unavailable'));
    }), reset: jest.fn(), close: jest.fn() };
    instances.push(controller); return controller;
  });
  await act(async () => { renderWorkshop(createController); });
  expect(node.querySelector('[role="alert"]').textContent).toContain('Launch store unavailable');
  await act(async () => { node.querySelector('[role="alert"] button').click(); });
  expect(createController).toHaveBeenCalledTimes(2);
  expect(instances[0].close).toHaveBeenCalledTimes(1);
  expect(instances[1].start).toHaveBeenCalledTimes(1);
});

test('terminal launch offers sign out without reconnecting or resetting', async () => {
  const controller = { start: jest.fn().mockResolvedValue({}), reset: jest.fn(), close: jest.fn() };
  const createController = jest.fn(options => {
    queueMicrotask(() => options.onState({ status: 'error', terminalLaunch: true,
      message: 'This platform session’s SecureShop launch has ended. Sign out and sign in again to start a new session.' }));
    return controller;
  });
  await act(async () => renderWorkshop(createController));
  const alert = node.querySelector('[role="alert"]');
  expect(alert.textContent).toContain('launch has ended');
  expect([...alert.querySelectorAll('button')].map(button => button.textContent)).toEqual(['Sign out']);
  await act(async () => alert.querySelector('button').click());
  expect(mockLogout).toHaveBeenCalledTimes(1);
  expect(createController).toHaveBeenCalledTimes(1);
  expect(controller.reset).not.toHaveBeenCalled();
});

test('cancelled confirmation does not reset the launch', async () => {
  const controller = { start: jest.fn().mockResolvedValue({}), reset: jest.fn(), close: jest.fn() };
  const createController = jest.fn(options => {
    queueMicrotask(() => options.onState({ status: 'ready', launch: { launchId: 'owned', generation: 1 } }));
    return controller;
  });
  await act(async () => renderWorkshop(createController));
  await act(async () => node.querySelector('button[aria-controls="secureshop-settings"]').click());
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent === 'Reset shop').click());
  expect(node.querySelector('[role="alertdialog"]')).not.toBeNull();
  await act(async () => node.querySelector('[role="alertdialog"] button').click());
  expect(node.querySelector('[role="alertdialog"]')).toBeNull();
  expect(controller.reset).not.toHaveBeenCalled();
});

test('failed confirmed reset stays scoped and retries through the same controller', async () => {
  let failFirst;
  const controller = { start: jest.fn().mockResolvedValue({}), close: jest.fn(), reset: jest.fn()
    .mockImplementationOnce(() => new Promise((_, reject) => { failFirst = reject; }))
    .mockResolvedValueOnce({}) };
  const createController = jest.fn(options => {
    queueMicrotask(() => options.onState({ status: 'ready', launch: { launchId: 'owned', generation: 1 } }));
    return controller;
  });
  await act(async () => renderWorkshop(createController));
  await act(async () => node.querySelector('button[aria-controls="secureshop-settings"]').click());
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent === 'Reset shop').click());
  await act(async () => node.querySelector('[role="alertdialog"] button:last-child').click());
  expect(node.querySelector('[role="alertdialog"]').getAttribute('data-status')).toBe('resetting');
  expect(node.querySelector('[role="alertdialog"] button:last-child').disabled).toBe(true);
  expect(controller.reset).toHaveBeenCalledTimes(1);
  await act(async () => failFirst(new Error('Reset response unavailable')));
  expect(node.querySelector('[role="alertdialog"]').textContent).toContain('Reset response unavailable');
  expect(node.querySelector('[role="alertdialog"]').textContent).toContain('Reset response unavailable');
  await act(async () => node.querySelector('[role="alertdialog"] button:last-child').click());
  expect(controller.reset).toHaveBeenCalledTimes(2);
  expect(createController).toHaveBeenCalledTimes(1);
  expect(node.querySelector('[role="alertdialog"]')).toBeNull();
});

test('an uncertain reset retries its existing controller instead of discarding the operation', async () => {
  const instance = { start: jest.fn().mockResolvedValue({}), reset: jest.fn().mockResolvedValue({}), close: jest.fn() };
  const createController = jest.fn(options => {
    queueMicrotask(() => options.onState({ status: 'error', retryReset: true, message: 'Reset response unavailable' }));
    return instance;
  });
  await act(async () => renderWorkshop(createController));
  const button = node.querySelector('[role="alert"] button');
  expect(button.textContent).toBe('Retry reset');
  await act(async () => button.click());
  expect(instance.reset).toHaveBeenCalledTimes(1);
  expect(createController).toHaveBeenCalledTimes(1);
  expect(instance.close).not.toHaveBeenCalled();
});

test('mode control shows scoped server capability and accepts an authoritative fixed response', async () => {
  const launch = { launchId: 'owned-launch', generation: 1 };
  const controller = { start: jest.fn().mockResolvedValue({}), reset: jest.fn(), close: jest.fn() };
  const createController = jest.fn(options => {
    queueMicrotask(() => options.onState({ status: 'ready', launch })); return controller;
  });
  let release;
  axios.post.mockImplementation(() => new Promise(resolve => { release = resolve; }));
  await act(async () => renderWorkshop(createController));
  await act(async () => node.querySelector('button[aria-controls="secureshop-settings"]').click());
  const control = node.querySelector('[role="group"][aria-label="Shop feature mode"]');
  expect(control.textContent).toContain('Covered: Analytics');
  expect(control.textContent).toContain('Applies to the listed features only');
    const fixed = [...control.querySelectorAll('button')].find(button => button.textContent === 'Fixed');
  expect(fixed.getAttribute('aria-pressed')).toBe('false');
  await act(async () => fixed.click());
  expect(axios.post).toHaveBeenCalledWith('/api/auth/secureshop-launch/mode', { mode: 'fixed' },
    expect.objectContaining({ headers: { Authorization: 'Bearer platform-token' }, signal: expect.any(AbortSignal) }));
  expect(fixed.getAttribute('aria-pressed')).toBe('false');
  expect(fixed.disabled).toBe(true);
  const baseline = (await axios.get.mock.results[0].value).data;
  await act(async () => release({ data: { ...baseline, mode: 'fixed', effectiveMode: 'fixed' } }));
  expect(fixed.getAttribute('aria-pressed')).toBe('true');
});

test('shared mode presentation keeps scoped feature readback and retry after a failed change', async () => {
  const controller = { start: jest.fn().mockResolvedValue({}), reset: jest.fn(), close: jest.fn() };
  const createController = jest.fn(options => {
    queueMicrotask(() => options.onState({ status: 'ready', launch: { launchId: 'owned-launch', generation: 1 } }));
    return controller;
  });
  axios.post.mockRejectedValueOnce(new Error('Mode network unavailable'));
  await act(async () => renderWorkshop(createController));
  await act(async () => node.querySelector('button[aria-controls="secureshop-settings"]').click());
  const control = node.querySelector('[role="group"][aria-label="Shop feature mode"]');
  await act(async () => [...control.querySelectorAll('button')].find(button => button.textContent === 'Fixed').click());
  expect(control.textContent).toContain('Covered: Analytics');
  expect(control.textContent).toContain('Mode network unavailable');
  expect([...control.querySelectorAll('button')].find(button => button.textContent === 'Fixed').disabled).toBe(true);
  const original = (await axios.get.mock.results[0].value).data;
  axios.get.mockResolvedValueOnce({ data: { ...original, mode: 'fixed', effectiveMode: 'fixed' } });
  await act(async () => [...control.querySelectorAll('button')].find(button => button.textContent === 'Retry mode').click());
  expect([...control.querySelectorAll('button')].find(button => button.textContent === 'Fixed').getAttribute('aria-pressed')).toBe('true');
  expect(control.textContent).toContain('Covered: Analytics');
});
