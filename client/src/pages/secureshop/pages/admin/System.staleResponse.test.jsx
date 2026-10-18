import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import System from './System.jsx';
import { AuthCtx } from '../../context/AuthContext.jsx';

const toast = { success: jest.fn(), error: jest.fn(), warn: jest.fn(), info: jest.fn() };
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../../components/PageTransition.jsx', () => ({ children }) => <div>{children}</div>);
jest.mock('framer-motion', () => ({
  AnimatePresence: ({ children }) => children,
  motion: new Proxy({}, { get: (_, tag) => ({ children, ...props }) => React.createElement(tag, props, children) }),
}));

const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
const healthy = (url) => response(url.includes('agent-host')
  ? { status: 'SERVICE_READY', model_execution: 'not_tested' }
  : { hostname: 'owned', platform: 'darwin', node: 'v26', uptime_s: 1, loadavg: [0], freemem_mb: 1 });

let root;
let container;
const originalFetch = global.fetch;

beforeEach(() => {
  jest.clearAllMocks();
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(async () => {
  if (root) await act(async () => root.unmount());
  container.remove();
  global.fetch = originalFetch;
});

const mount = token => act(async () => root.render(
  <AuthCtx.Provider value={{ token }}><System /></AuthCtx.Provider>
));
const mountStrict = token => act(async () => root.render(
  <React.StrictMode><AuthCtx.Provider value={{ token }}><System /></AuthCtx.Provider></React.StrictMode>
));
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
const button = label => [...container.querySelectorAll('button')].find(node => node.textContent === label);

test('auth epoch aborts a stale config response and clears scoped result/toast writes', async () => {
  let staleResolve;
  let staleSignal;
  global.fetch = jest.fn((url, options = {}) => {
    if (url.endsWith('/read-config')) {
      staleSignal = options.signal;
      return new Promise(resolve => { staleResolve = resolve; });
    }
    return Promise.resolve(healthy(url));
  });

  await mount('old-session');
  await settle();
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await mount('new-session');
  expect(staleSignal.aborted).toBe(true);

  await act(async () => staleResolve(response({ ok: true, content: 'stale secret', size: 12 })));
  expect(container.textContent).not.toContain('stale secret');
  expect(toast.success).not.toHaveBeenCalledWith('read 12 bytes');
});

test('StrictMode effect replay re-arms lifecycle and accepts current health/read results', async () => {
  global.fetch = jest.fn(async (url, options = {}) => options.method === 'POST'
    ? response({ ok: true, content: 'owned config', size: 12 })
    : healthy(url));

  await mountStrict('admin-session');
  await settle();
  expect(container.textContent).toContain('owned');
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  expect(toast.success).toHaveBeenCalledWith('read 12 bytes');
});

test.each([
  ['diagnostic', 'run', 1, '/diagnostic', { ok: true, executed: false, cmd: 'owned command' }],
  ['restart', 'restart', 2, '/restart-service', { ok: true, executed: false, cmd: 'owned restart' }],
  ['rebuild', 'rebuild products', null, 'rebuild-index', { ok: true, job_id: 'job-1', status: 'enqueued', current_vector_count: 1 }],
])('auth epoch suppresses late %s success', async (_operation, label, formIndex, path, body) => {
  let resolvePending;
  let pendingSignal;
  global.fetch = jest.fn((url, options = {}) => {
    if (options.method === 'POST' && url.includes(path)) {
      pendingSignal = options.signal;
      return new Promise(resolve => { resolvePending = resolve; });
    }
    return Promise.resolve(healthy(url));
  });

  await mount('old-session');
  await settle();
  await act(async () => {
    if (formIndex === null) button(label).click();
    else container.querySelectorAll('form')[formIndex].dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });
  await mount('new-session');
  expect(pendingSignal.aborted).toBe(true);
  await act(async () => resolvePending(response(body)));
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.info).not.toHaveBeenCalled();
});

test('rebuild submission admits only one pending operation', async () => {
  let resolveRebuild;
  global.fetch = jest.fn((url, options = {}) => {
    if (options.method === 'POST' && url.includes('rebuild-index')) {
      return new Promise(resolve => { resolveRebuild = resolve; });
    }
    return Promise.resolve(healthy(url));
  });

  await mount('admin-session');
  await settle();
  const products = button('rebuild products');
  await act(async () => products.click());
  await act(async () => products.click());
  expect(global.fetch.mock.calls.filter(([url, options]) => options?.method === 'POST' && url.includes('rebuild-index'))).toHaveLength(1);
  expect(button('rebuild reviews').disabled).toBe(true);

  await act(async () => resolveRebuild(response({ ok: true, job_id: 'job-1', status: 'enqueued', current_vector_count: 1 })));
  expect(toast.success).toHaveBeenCalledWith('enqueued rebuild for products (1 vectors)');
});


test.each(['auth', 'transport', 'unmount'])('%s change suppresses a late rejected request', async change => {
  let rejectPending;
  let pendingSignal;
  global.fetch = jest.fn((url, options = {}) => {
    if (options.method === 'POST') {
      pendingSignal = options.signal;
      return new Promise((_resolve, reject) => { rejectPending = reject; });
    }
    return Promise.resolve(healthy(url));
  });
  await mount('old-session');
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  if (change === 'unmount') {
    await act(async () => root.unmount());
    root = null;
  } else {
    if (change === 'transport') global.fetch = jest.fn(async url => healthy(url));
    await mount(change === 'auth' ? 'new-session' : 'old-session');
  }
  expect(pendingSignal.aborted).toBe(true);
  await act(async () => rejectPending(new Error('stale transport error')));
  expect(container.textContent).not.toContain('stale transport error');
  expect(toast.error).not.toHaveBeenCalled();
  if (change !== 'unmount') expect(button('read').disabled).toBe(false);
});
