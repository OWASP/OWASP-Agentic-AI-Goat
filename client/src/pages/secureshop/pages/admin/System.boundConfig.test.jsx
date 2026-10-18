import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import System from './System.jsx';
import { AuthCtx } from '../../context/AuthContext.jsx';
import { SHOP_SYSTEM_CONFIG_KEY } from '../../utils/shopStorage.mjs';
import { saveSystemConfigReference, forgetSystemConfigReference } from './systemConfigRecovery.js';

jest.mock('./systemConfigRecovery.js', () => {
  const actual = jest.requireActual('./systemConfigRecovery.js');
  return { ...actual, saveSystemConfigReference: jest.fn(actual.saveSystemConfigReference),
    forgetSystemConfigReference: jest.fn(actual.forgetSystemConfigReference) };
});

let bound = true;
jest.mock('../../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => bound ? {} : null }));
const toast = { success: jest.fn(), error: jest.fn(), warn: jest.fn(), info: jest.fn() };
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../../components/PageTransition.jsx', () => ({ children, className, style }) => <div className={className} style={style}>{children}</div>);
jest.mock('framer-motion', () => ({ AnimatePresence: ({ children }) => children,
  motion: new Proxy({}, { get: (_, tag) => ({ children, ...props }) => React.createElement(tag, props, children) }) }));

const scopeKey = 'a'.repeat(64);
const operationId = '44444444-4444-4444-8444-444444444444';
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
const health = url => response(url.includes('agent-host') ? { status: 'SERVICE_READY', model_execution: 'not_tested' } : { hostname: 'owned', platform: 'darwin', node: 'v26', uptime_s: 1, loadavg: [0], freemem_mb: 1 });
const receipt = (id, input = 'application.json', content = '{}') => ({ ok: true, state: 'completed', operationId: id,
  input, sanitized: input === '....//.env' ? '../.env' : input,
  abs: input === '....//.env' ? '/app/.env' : '/app/config/application.json',
  size: Buffer.byteLength(content), content, contentSha256: require('node:crypto').createHash('sha256').update(content).digest('hex') });
let root, container;

beforeEach(() => { bound = true; jest.clearAllMocks(); localStorage.clear(); global.IS_REACT_ACT_ENVIRONMENT = true; container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container); });
afterEach(async () => { if (root) await act(async () => root.unmount()); container.remove(); });
const mount = token => act(async () => root.render(<AuthCtx.Provider value={{ token }}><System /></AuthCtx.Provider>));
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
const submit = () => act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
const boundAdmin = () => response({ ok: true, administration: { scopeKey, configReadCapability: 'secureshop-owned-system-config-read.v1' } });

test('bound config read persists exact operation and renders verified receipt', async () => {
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/config-read') && !options.method) return boundAdmin();
    if (options.method === 'POST') return response(receipt(JSON.parse(options.body).operationId));
    return health(url);
  });
  await mount('admin'); await settle(); await submit();
  const write = global.fetch.mock.calls.find(([, options]) => options?.method === 'POST');
  expect(write[0]).toContain('/config-read');
  expect(Object.keys(JSON.parse(write[1].body)).sort()).toEqual(['operationId', 'path']);
  expect(JSON.parse(write[1].body).path).toBe('application.json');
  expect(container.textContent).toContain('application.json');
  expect(toast.success).toHaveBeenCalledWith('read 2 bytes');
  const saved = JSON.parse(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).references[0];
  expect(saved).toMatchObject({ scopeKey, state: 'completed' });
  expect(Object.keys(saved).sort()).toEqual(['operationId', 'scopeKey', 'state']);
  expect(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).not.toContain('{}');
});

test('completed traversal config receipt is read back after remount without another POST', async () => {
  const content = 'synthetic training config fixture';
  let storedReceipt;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/config-read') && !options.method) return boundAdmin();
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      storedReceipt = receipt(body.operationId, body.path, content);
      return response(storedReceipt);
    }
    if (url.includes('/config-operations/')) return response(storedReceipt);
    return health(url);
  });
  await mount('admin'); await settle();
  const input = container.querySelector('[aria-label="Config path"]');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, '....//.env');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await submit();
  const operationId = JSON.parse(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).references[0].operationId;
  expect(global.fetch.mock.calls.find(([, options]) => options?.method === 'POST')[1].body).toContain('....//.env');
  expect(container.textContent).toContain(content);
  const reference = JSON.parse(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).references[0];
  expect(reference).toMatchObject({ scopeKey, state: 'completed' });
  expect(Object.keys(reference).sort()).toEqual(['operationId', 'scopeKey', 'state']);
  expect(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).not.toContain(content);

  await act(async () => root.unmount()); root = createRoot(container);
  global.fetch.mockClear();
  await mount('admin'); await settle();
  expect(container.textContent).toContain(`Config read ${operationId} · outcome completed`);
  await act(async () => {
    [...container.querySelectorAll('button')].find(button => button.textContent === 'Refresh operation status').click();
    await new Promise(resolve => setTimeout(resolve, 200));
  });
  expect(global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  expect(global.fetch.mock.calls.filter(([url]) => url.includes(`/config-operations/${operationId}`))).toHaveLength(1);
  expect(container.textContent).toContain(content);
  expect(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).toBeNull();
});

test('uncertain bound response is retained for explicit recovery without resend', async () => {
  let recovery = false; let activeId;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/config-read') && !options.method) return boundAdmin();
    if (url.includes('/config-operations/')) return recovery ? response(receipt(activeId)) : response({ ok: false, state: 'unknown', operationId: activeId, error: 'Read outcome unknown' });
    if (options.method === 'POST') { activeId = JSON.parse(options.body).operationId; return response({ ok: false, code: 'SYSTEM_CONFIG_OUTCOME_UNCERTAIN' }, 503); }
    return health(url);
  });
  await mount('admin'); await settle(); await submit();
  const saved = JSON.parse(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY));
  expect(saved.references[0]).toMatchObject({ scopeKey, state: 'unknown' });
  expect(global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  recovery = true;
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent === 'Refresh operation status').click());
  expect(global.fetch.mock.calls.filter(([url]) => url.includes('/config-operations/'))).toHaveLength(1);
  expect(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).toBeNull();
});

test('auth change aborts bound read and suppresses its late success', async () => {
  let resolveRead;
  let signal;
  global.fetch = jest.fn((url, options = {}) => {
    if (url.endsWith('/config-read') && !options.method) return Promise.resolve(boundAdmin());
    if (options.method === 'POST') { signal = options.signal; return new Promise(resolve => { resolveRead = resolve; }); }
    return Promise.resolve(health(url));
  });
  await mount('old'); await settle(); await submit(); await mount('new');
  expect(signal.aborted).toBe(true);
  await act(async () => resolveRead(response(receipt(operationId))));
  expect(container.textContent).not.toContain('read 2 bytes');
  expect(toast.success).not.toHaveBeenCalled();
});

test('standalone mode keeps the legacy read-config request', async () => {
  bound = false;
  global.fetch = jest.fn(async (url, options = {}) => options.method === 'POST' ? response({ ok: true, input: '.env', sanitized: '.env', content: 'owned', size: 5 }) : health(url));
  await mount('admin'); await settle(); await submit();
  expect(container.querySelector('[aria-label="Config path"]').value).toBe('.env');
  expect(container.querySelector('[aria-label="Config path"]').placeholder).toContain('....//server/platform_secrets.json');
  const write = global.fetch.mock.calls.find(([, options]) => options?.method === 'POST');
  expect(write[0]).toContain('/read-config');
  expect(JSON.parse(write[1].body)).toEqual({ path: '.env' });
});

test('bound config initially selects an existing config path and shows its isolated traversal example', async () => {
  global.fetch = jest.fn(async url => url.endsWith('/config-read') ? boundAdmin() : health(url));
  await mount('admin'); await settle();
  const input = container.querySelector('[aria-label="Config path"]');
  expect(input.value).toBe('application.json');
  expect(input.placeholder).toContain('application.json');
  expect(input.placeholder).toContain('....//.env');
});

test('attached bridge with missing capability DTO fails closed without legacy fallback', async () => {
  global.fetch = jest.fn(async (url, options = {}) => options.method === 'POST'
    ? response({ ok: true, content: 'legacy', size: 6 })
    : url.endsWith('/config-read') ? response({ ok: false, error: 'unavailable' }, 503) : health(url));
  await mount('admin'); await settle(); await submit();
  expect(global.fetch.mock.calls.some(([url]) => url.endsWith('/read-config'))).toBe(false);
  expect(container.textContent).toContain('Bound config read capability unavailable');
});

test('attached bridge rejects an invalid capability DTO', async () => {
  global.fetch = jest.fn(async url => url.endsWith('/config-read') ? response({ ok: true, administration: { scopeKey, configReadCapability: 'wrong.v1' } }) : health(url));
  await mount('admin'); await settle();
  expect(container.textContent).toContain('Invalid config-read capability');
  expect([...container.querySelectorAll('button')].find(button => button.textContent === 'read').disabled).toBe(true);
});

test('completed bound error is terminal and clears its pending reference', async () => {
  let activeId;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/config-read') && !options.method) return boundAdmin();
    if (options.method === 'POST') { activeId = JSON.parse(options.body).operationId; return response({ ok: false, state: 'completed', operationId: activeId, error: 'Config read failed' }); }
    return health(url);
  });
  await mount('admin'); await settle(); await submit();
  expect(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).toBeNull();
  expect(container.textContent).toContain('Config read failed');
});

test('mismatched pending response cannot be treated as a valid recovery state', async () => {
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/config-read') && !options.method) return boundAdmin();
    if (options.method === 'POST') return response({ ok: false, state: 'pending', operationId: '55555555-5555-4555-8555-555555555555' }, 202);
    return health(url);
  });
  await mount('admin'); await settle(); await submit();
  expect(container.textContent).toContain('Invalid config-read operation');
  expect(JSON.parse(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).references[0].state).toBe('pending');
});

test('operation UUID failure does not strand the read button busy', async () => {
  const original = global.crypto.randomUUID;
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => { throw new Error('UUID unavailable'); } });
  global.fetch = jest.fn(async url => url.endsWith('/config-read') ? boundAdmin() : health(url));
  await mount('admin'); await settle(); await submit();
  expect([...container.querySelectorAll('button')].find(button => button.textContent === 'read').disabled).toBe(false);
  expect(container.textContent).toContain('UUID unavailable');
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: original });
});

test('auth change during persistence acknowledgement prevents remote dispatch', async () => {
  let acknowledge;
  saveSystemConfigReference.mockImplementationOnce(reference => new Promise(resolve => {
    acknowledge = () => resolve([reference]);
  }));
  global.fetch = jest.fn(async url => url.endsWith('/config-read') ? boundAdmin() : health(url));
  await mount('old'); await settle(); await submit();
  expect(acknowledge).toBeDefined();
  await mount('new');
  await act(async () => acknowledge());
  expect(global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  expect(toast.success).not.toHaveBeenCalled();
});

test('auth change during completed reference save suppresses late success toast', async () => {
  let acknowledge;
  const actualSave = jest.requireActual('./systemConfigRecovery.js').saveSystemConfigReference;
  let calls = 0;
  saveSystemConfigReference.mockImplementation(reference => {
    calls++;
    if (calls === 2) return new Promise(resolve => {
      acknowledge = async () => resolve(await actualSave(reference));
    });
    return actualSave(reference);
  });
  global.fetch = jest.fn(async (url, options = {}) => {
    if (options.method === 'POST') return response(receipt(JSON.parse(options.body).operationId));
    return url.endsWith('/config-read') ? boundAdmin() : health(url);
  });
  await mount('old'); await settle(); await submit();
  expect(acknowledge).toBeDefined();
  await mount('new');
  await act(async () => acknowledge());
  expect(toast.success).not.toHaveBeenCalled();
});

test('measured zero uptime and available memory are displayed as valid measurements', async () => {
  global.fetch = jest.fn(async url => {
    if (url.endsWith('/config-read')) return boundAdmin();
    if (url.endsWith('/system/health')) return response({ hostname: 'owned', uptime_s: 0, freemem_mb: 0, loadavg: null });
    return health(url);
  });
  await mount('admin'); await settle();
  expect(container.textContent).toContain('0h 0m');
  expect(container.textContent).toContain('0 MB');
});

test('responsive System structure keeps sink controls in shrinkable page-owned layouts', async () => {
  global.fetch = jest.fn(async url => url.endsWith('/config-read') ? boundAdmin() : health(url));
  await mount('admin'); await settle();
  expect(container.querySelector('.ss-admin-system')).toBeTruthy();
  expect(container.querySelector('.ss-admin-system__health-grid')).toBeTruthy();
  const actionForms = container.querySelectorAll('.ss-admin-system__action-form');
  expect(actionForms).toHaveLength(2);
  expect(container.querySelector('.ss-admin-system__diagnostic-form')).toBeTruthy();
  expect(container.querySelector('.ss-admin-system__corpora-grid')).toBeTruthy();
  expect(container.querySelector('[aria-label="Config path"]')).toBeTruthy();
  expect([...container.querySelectorAll('button')].some(button => button.textContent === 'read')).toBe(true);
  expect(container.textContent).toContain('path traversal sink');
  expect(container.textContent).toContain('RCE sink');
  expect(container.textContent).toContain('command injection sink');
});
