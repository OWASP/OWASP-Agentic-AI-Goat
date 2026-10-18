import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import System from './System.jsx';
import { AuthCtx } from '../../context/AuthContext.jsx';
import { SHOP_SYSTEM_DIAGNOSTIC_KEY } from '../../utils/shopStorage.mjs';
const { webcrypto } = require('node:crypto');

let bound = true;
jest.mock('../../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => bound ? {} : null }));
const toast = { success: jest.fn(), error: jest.fn(), warn: jest.fn(), info: jest.fn() };
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../../components/PageTransition.jsx', () => ({ children, className }) => <div className={className}>{children}</div>);
jest.mock('framer-motion', () => ({ AnimatePresence: ({ children }) => children, motion: new Proxy({}, { get: (_, tag) => ({ children, ...props }) => React.createElement(tag, props, children) }) }));
const scopeKey = 'b'.repeat(64);
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
const health = url => response(url.includes('agent-host') ? { status: 'SERVICE_READY', model_execution: 'not_tested' } : { hostname: 'owned', platform: 'darwin', node: 'v26', uptime_s: 1, loadavg: [0], freemem_mb: 1 });
const sha = async text => Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), b => b.toString(16).padStart(2, '0')).join('');
const admin = () => response({ ok: true, administration: { scopeKey, diagnosticCapability: 'secureshop-owned-system-diagnostic.v1' } });
let root, container;
beforeEach(() => { Object.defineProperty(global.crypto, 'subtle', { configurable: true, value: webcrypto.subtle }); Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: webcrypto.randomUUID.bind(webcrypto) }); bound = true; jest.clearAllMocks(); localStorage.clear(); global.IS_REACT_ACT_ENVIRONMENT = true; container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container); });
afterEach(async () => { if (root) await act(async () => root.unmount()); container.remove(); });
const mount = (token = 'admin') => act(async () => root.render(<AuthCtx.Provider value={{ token }}><System /></AuthCtx.Provider>));
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 200)); });
const submit = () => act(async () => { container.querySelector('.ss-admin-system__diagnostic-form button').click(); await new Promise(resolve => setTimeout(resolve, 200)); });
function receipt(id, requestSha256, bindingSha256, exitCode = 0) { const emptySha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; const result = { operationId: id, requestSha256, command: 'ping -c 2 127.0.0.1', executed: true, exitCode, signal: null, timedOut: false, truncated: false, drained: true, stdout: '', stderr: '', encoding: 'base64', stdoutBytes: 0, stderrBytes: 0, stdoutSha256: emptySha, stderrSha256: emptySha }; return { ok: true, state: 'completed', operationId: id, requestSha256, targetId: id, hostname: `system-diag-${id.replaceAll('-', '')}`, bindingSha256, cmd: 'ping -c 2 127.0.0.1', executed: true, exitCode, signal: null, timedOut: false, truncated: false, drained: true, stdout: '', stderr: '', receipt: { version: 'secureshop-owned-system-diagnostic-http.v1', targetId: id, hostname: `system-diag-${id.replaceAll('-', '')}`, bindingSha256, result } }; }

test('bound diagnostic persists before dispatch and renders target-bound receipt', async () => {
  let persistedBeforePost = false;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/diagnostic') && !options.method) return admin();
    if (options.method === 'POST') { persistedBeforePost = localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY) !== null; const body = JSON.parse(options.body); const digest = await sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic.v1', request: body })); const binding = await sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic-http.v1', targetId: body.operationId, requestSha256: digest })); return response(receipt(body.operationId, digest, binding)); }
    return health(url);
  });
  await mount(); await settle(); await submit();
  const write = global.fetch.mock.calls.find(([, options]) => options?.method === 'POST');
  expect(Object.keys(JSON.parse(write[1].body)).sort()).toEqual(['args', 'cmd_template', 'operationId']);
  expect(persistedBeforePost).toBe(true);
  expect(container.textContent).toContain('EXECUTED');
  expect(container.textContent).toContain('Practice actions run only when their section is available');
  expect(container.textContent).toContain('A verified result below shows whether it ran');
  expect(container.textContent).toContain('Diagnostic ran in the isolated SecureShop practice; inspect its verified receipt.');
  expect(container.textContent).not.toContain('SS_SYSTEM_ALLOW_EXEC=true');
  expect(toast.success).toHaveBeenCalledWith('diagnostic executed');
  const reference = JSON.parse(localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY)).references[0];
  expect(reference).toMatchObject({ scopeKey, state: 'completed' });
  expect(Object.keys(reference).sort()).toEqual(['operationId', 'scopeKey', 'state']);
});

test('completed diagnostic receipt is read back after remount without another POST', async () => {
  let savedReceipt;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/diagnostic') && !options.method) return admin();
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      const digest = await sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic.v1', request: body }));
      const binding = await sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic-http.v1', targetId: body.operationId, requestSha256: digest }));
      savedReceipt = receipt(body.operationId, digest, binding);
      savedReceipt.stdout = 'previously persisted diagnostic output';
      savedReceipt.receipt.result.stdout = Buffer.from(savedReceipt.stdout).toString('base64');
      savedReceipt.receipt.result.stdoutBytes = Buffer.byteLength(savedReceipt.stdout);
      savedReceipt.receipt.result.stdoutSha256 = require('node:crypto').createHash('sha256').update(savedReceipt.stdout).digest('hex');
      return response(savedReceipt);
    }
    if (url.includes('/diagnostic-operations/')) return response(savedReceipt);
    return health(url);
  });
  await mount(); await settle(); await submit();
  const operationId = JSON.parse(localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY)).references[0].operationId;
  const stored = JSON.parse(localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY)).references[0];
  expect(Object.keys(stored).sort()).toEqual(['operationId', 'scopeKey', 'state']);
  expect(localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY)).not.toContain('previously persisted diagnostic output');
  expect(container.textContent).toContain('previously persisted diagnostic output');

  await act(async () => root.unmount()); root = createRoot(container);
  global.fetch.mockClear();
  await mount(); await settle();
  expect(container.textContent).toContain(`Diagnostic ${operationId} · outcome completed`);
  await act(async () => {
    [...container.querySelectorAll('button')].find(button => button.textContent === 'Refresh operation status').click();
    await new Promise(resolve => setTimeout(resolve, 200));
  });
  expect(global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  expect(global.fetch.mock.calls.filter(([url]) => url.includes(`/diagnostic-operations/${operationId}`))).toHaveLength(1);
  expect(container.textContent).toContain('previously persisted diagnostic output');
  expect(localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY)).toBeNull();
});

test('lost bound response is recovered by readback without repost', async () => {
  let operationId; let readback = false;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/diagnostic') && !options.method) return admin();
    if (options.method === 'POST') { operationId = JSON.parse(options.body).operationId; return response({ ok: false, code: 'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN' }, 503); }
    if (url.includes('/diagnostic-operations/')) {
      if (!readback) return response({ ok: false, state: 'unknown', operationId });
      const digest = await sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic.v1', request: { operationId, cmd_template: 'ping -c 2', args: '127.0.0.1' } }));
      const binding = await sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic-http.v1', targetId: operationId, requestSha256: digest })); return response(receipt(operationId, digest, binding));
    }
    return health(url);
  });
  await mount(); await settle(); await submit();
  expect(JSON.parse(localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY)).references[0].state).toBe('unknown');
  readback = true;
  await act(async () => { [...container.querySelectorAll('button')].find(button => button.textContent === 'Refresh operation status').click(); await new Promise(resolve => setTimeout(resolve, 200)); });
  expect(global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  expect(container.textContent).toContain('EXECUTED');
  expect(localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY)).toBeNull();
});

test('attached bridge with missing diagnostic capability fails closed', async () => {
  global.fetch = jest.fn(async (url, options = {}) => url.endsWith('/diagnostic') && !options.method ? response({ ok: false }, 503) : health(url));
  await mount(); await settle(); await submit();
  expect(global.fetch.mock.calls.some(([url, options]) => url.endsWith('/diagnostic') && options?.method === 'POST')).toBe(false);
  expect(container.textContent).toContain('bound diagnostic unavailable: HTTP 503');
  expect(container.textContent).not.toContain('configuration required');
});

test('legacy diagnostic retains the original execution guidance', async () => {
  bound = false;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/diagnostic') && options.method === 'POST') {
      return response({ ok: true, executed: true, cmd: 'ping -c 2 127.0.0.1', stdout: '', stderr: '' });
    }
    return health(url);
  });
  await mount(); await settle(); await submit();
  expect(container.textContent).toContain('Exec is guarded by SS_SYSTEM_ALLOW_EXEC=true');
  expect(container.textContent).toContain('cmd_template + args are concatenated and exec\'d. Guarded by SS_SYSTEM_ALLOW_EXEC=true');
  expect(container.textContent).toContain('exec surface is LIVE (SS_SYSTEM_ALLOW_EXEC=true)');
  expect(container.textContent).not.toContain('isolated SecureShop practice');
});

test('forged binding or non-executed receipt is rejected', async () => {
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/diagnostic') && !options.method) return admin();
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      const digest = await sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic.v1', request: body }));
      const forged = receipt(body.operationId, digest, 'a'.repeat(64)); forged.executed = false;
      return response(forged);
    }
    return health(url);
  });
  await mount(); await settle(); await submit();
  expect(container.textContent).toContain('Invalid diagnostic');
  expect(JSON.parse(localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY)).references[0].state).toBe('unknown');
});

test('forged binding with otherwise valid execution is rejected', async () => {
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/diagnostic') && !options.method) return admin();
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      const digest = await sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic.v1', request: body }));
      return response(receipt(body.operationId, digest, 'a'.repeat(64)));
    }
    return health(url);
  });
  await mount(); await settle(); await submit();
  expect(container.textContent).toContain('Invalid diagnostic target binding');
});

test('valid binding with executed false is rejected independently', async () => {
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/diagnostic') && !options.method) return admin();
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      const digest = await sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic.v1', request: body }));
      const binding = await sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic-http.v1', targetId: body.operationId, requestSha256: digest }));
      const value = receipt(body.operationId, digest, binding);
      value.executed = false;
      return response(value);
    }
    return health(url);
  });
  await mount(); await settle(); await submit();
  expect(container.textContent).toContain('Invalid diagnostic receipt');
});

test('token change aborts pending diagnostic and suppresses late success', async () => {
  let resolvePost; let signal;
  global.fetch = jest.fn((url, options = {}) => {
    if (url.endsWith('/diagnostic') && !options.method) return Promise.resolve(admin());
    if (options.method === 'POST') { signal = options.signal; return new Promise(resolve => { resolvePost = resolve; }); }
    return Promise.resolve(health(url));
  });
  await mount('old'); await settle(); await submit();
  await mount('new');
  expect(signal.aborted).toBe(true);
  await act(async () => resolvePost(response({ ok: true, state: 'completed', operationId: '44444444-4444-4444-8444-444444444444' })));
  expect(toast.success).not.toHaveBeenCalledWith('diagnostic executed');
});

test('failed durable reference write prevents diagnostic dispatch', async () => {
  global.fetch = jest.fn(async (url, options = {}) => url.endsWith('/diagnostic') && !options.method ? admin() : health(url));
  await mount(); await settle();
  const original = Storage.prototype.setItem;
  const write = jest.spyOn(Storage.prototype, 'setItem').mockImplementation(function(key, value) {
    if (key === SHOP_SYSTEM_DIAGNOSTIC_KEY) throw new Error('Recovery storage full');
    return original.call(this, key, value);
  });
  try {
    await submit();
    expect(global.fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
    expect(container.textContent).toContain('Recovery storage full');
  } finally { write.mockRestore(); }
});

test('unmount aborts a pending diagnostic without publishing late success', async () => {
  let resolvePost, signal;
  global.fetch = jest.fn((url, options = {}) => {
    if (url.endsWith('/diagnostic') && !options.method) return Promise.resolve(admin());
    if (options.method === 'POST') { signal = options.signal; return new Promise(resolve => { resolvePost = resolve; }); }
    return Promise.resolve(health(url));
  });
  await mount(); await settle(); await submit();
  await act(async () => root.unmount()); root = null;
  expect(signal.aborted).toBe(true);
  await act(async () => resolvePost(response({ok: true})));
  expect(toast.success).not.toHaveBeenCalled();
  expect(localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY)).not.toBeNull();
});

test('signal termination renders actual execution and reports the signal', async () => {
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/diagnostic') && !options.method) return admin();
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      const digest = await sha(JSON.stringify({version:'secureshop-owned-system-diagnostic.v1',request:body}));
      const binding = await sha(JSON.stringify({version:'secureshop-owned-system-diagnostic-http.v1',targetId:body.operationId,requestSha256:digest}));
      const value = receipt(body.operationId, digest, binding, null);
      value.signal = 15; value.receipt.result.signal = 15;
      return response(value);
    }
    return health(url);
  });
  await mount(); await settle(); await submit();
  expect(toast.warn).toHaveBeenCalledWith('diagnostic stopped by signal 15');
  expect(JSON.parse(localStorage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY)).references[0]).toMatchObject({ scopeKey, state: 'completed' });
});
