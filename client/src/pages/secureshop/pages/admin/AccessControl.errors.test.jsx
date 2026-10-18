import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AccessControl from './AccessControl.jsx';
import { AuthCtx } from '../../context/AuthContext.jsx';
import { flushShopStorage, SHOP_ACL_KEY } from '../../utils/shopStorage.mjs';
jest.mock('../../utils/shopStorage.mjs', () => {
  const actual = jest.requireActual('../../utils/shopStorage.mjs');
  return { ...actual, flushShopStorage: jest.fn(() => Promise.resolve()) };
});

let mockBound = false;
jest.mock('../../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => mockBound ? { boundReviews: true } : undefined }));
const toast = { success: jest.fn(), error: jest.fn() };
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../../components/PageTransition.jsx', () => ({ children }) => <div>{children}</div>);
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const valid = { ok: true, enforcement_enabled: true,
  tools: [{ tool_name: 'owned.read', customer: 1, merchant: 0, admin: 1 }] };
let root, container;
beforeEach(() => {
  mockBound = false; jest.clearAllMocks(); global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div'); document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); });
const mount = () => act(async () => root.render(<AccessControl />));
const toggle = () => container.querySelector('[role="switch"]');
async function activate() {
  await act(async () => {
    toggle().click();
    toggle().dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true }));
  });
}
test.each([403, 503])('HTTP %s does not imply enforcement off or allow mutation', async status => {
  global.fetch = jest.fn(async () => response({ error: 'private details' }, status));
  await mount(); await activate();
  expect(toggle().textContent).toContain('UNAVAILABLE');
  expect(toggle().getAttribute('aria-disabled')).toBe('true');
  expect(toggle().hasAttribute('aria-checked')).toBe(false);
  expect(container.querySelector('[role="alert"]').textContent).toContain(`HTTP ${status}`);
  expect(container.textContent).not.toContain('LLM03:2026 excessive agency');
  expect(container.textContent).not.toContain('No tools match');
  expect(container.textContent).not.toContain('private details');
  expect(global.fetch).toHaveBeenCalledTimes(1);
});
test.each([null, {}, { ok: true, tools: [], enforcement_enabled: 'false' },
  { ...valid, tools: [{ tool_name: 'bad' }] }])('malformed response remains unavailable: %p', async body => {
  global.fetch = jest.fn(async () => response(body)); await mount();
  expect(toggle().textContent).toContain('UNAVAILABLE');
  expect(container.querySelector('[role="alert"]').textContent).toContain('Invalid ACL response');
});
test('retry recovers actual state; duplicate keyboard activation cannot duplicate pending write', async () => {
  let finish;
  global.fetch = jest.fn().mockResolvedValueOnce(response({}, 503))
    .mockResolvedValueOnce(response(valid))
    .mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  await mount();
  await act(async () => container.querySelector('button').click());
  expect(toggle().getAttribute('aria-checked')).toBe('true');
  await activate();
  expect(global.fetch).toHaveBeenCalledTimes(3);
  await act(async () => finish(response({ ok: true, enforce_tool_acl: false })));
  expect(toggle().getAttribute('aria-checked')).toBe('false');
  expect(toast.success).toHaveBeenCalledTimes(1);
});
test.each([{ ok: false }, { ok: true }, { ok: true, enforce_tool_acl: true }])(
  'unconfirmed enforcement acknowledgement %p requires reload, never an automatic retry', async body => {
    global.fetch = jest.fn().mockResolvedValueOnce(response(valid)).mockResolvedValue(response(body));
    await mount(); await activate(); await activate();
    expect(toggle().textContent).toContain('UNAVAILABLE');
    expect(toggle().hasAttribute('aria-checked')).toBe(false);
    expect(global.fetch).toHaveBeenCalledTimes(2);
    expect(toast.success).not.toHaveBeenCalled();
  });
test.each([{ ok: false }, { ok: true }, { ok: true, tool_name: 'other', role: 'customer', allowed: false },
  { ok: true, tool_name: 'owned.read', role: 'customer', allowed: true }])(
  'unconfirmed permission acknowledgement %p cannot publish a permission value', async body => {
    global.fetch = jest.fn().mockResolvedValueOnce(response(valid)).mockResolvedValue(response(body));
    await mount();
    await act(async () => container.querySelector('[data-testid="acl-cell-owned.read-customer"]').click());
    expect(toggle().textContent).toContain('UNAVAILABLE');
    expect(container.querySelector('[data-testid="acl-cell-owned.read-customer"]')).toBeNull();
    expect(toast.success).not.toHaveBeenCalled();
  });
test('lost acknowledgement reconciles committed state by GET without replaying mutation', async () => {
  global.fetch = jest.fn().mockResolvedValueOnce(response(valid))
    .mockRejectedValueOnce(new Error('Connection lost after commit'))
    .mockResolvedValueOnce(response({ ...valid, enforcement_enabled: false }));
  await mount(); await activate();
  expect(toggle().textContent).toContain('UNAVAILABLE');
  await act(async () => container.querySelector('button').click());
  expect(toggle().getAttribute('aria-checked')).toBe('false');
  expect(global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  expect(toast.success).not.toHaveBeenCalled();
});
test('exact permission acknowledgement updates the corresponding cell', async () => {
  global.fetch = jest.fn().mockResolvedValueOnce(response(valid))
    .mockResolvedValueOnce(response({ ok: true, tool_name: 'owned.read', role: 'customer', allowed: false }));
  await mount();
  const cell = container.querySelector('[data-testid="acl-cell-owned.read-customer"]');
  const before = cell.textContent;
  await act(async () => cell.click());
  expect(cell.textContent).not.toBe(before);
  expect(toggle().getAttribute('aria-checked')).toBe('true');
  expect(toast.error).not.toHaveBeenCalled();
});

const versioned = { ...valid, version: '1', registrySha256: 'a'.repeat(64),
  administration: { versionedPolicy: true, scopeKey: 'owned-scope' },
  tools: [{ ...valid.tools[0], supported: true, readOnly: false,
    applicable_roles: { customer: true, merchant: false, admin: true } }] };
const receiptFor = body => ({ operationId: body.operationId, expectedVersion: body.expectedVersion,
  version: '2', registrySha256: versioned.registrySha256, enforcement: body.enabled,
  change: { kind: 'enforcement', enabled: body.enabled } });
beforeEach(() => { localStorage.clear(); });
test('versioned toggle sends one operation and refreshes after exact receipt', async () => {
  global.fetch = jest.fn(async (url, options) => {
    if (!options) return response(versioned);
    return response({ ok: true, receipt: receiptFor(JSON.parse(options.body)) });
  });
  await mount(); await activate();
  const writes = fetch.mock.calls.filter(([, options]) => options?.method === 'POST');
  expect(writes).toHaveLength(1);
  expect(JSON.parse(writes[0][1].body)).toMatchObject({ enabled: false, expectedVersion: '1' });
  expect(JSON.parse(writes[0][1].body).operationId).toMatch(/^[0-9a-f-]{36}$/);
  expect(fetch.mock.calls).toHaveLength(3);
});
test('version conflict refreshes policy without replaying mutation', async () => {
  global.fetch = jest.fn(async (url, options) => options
    ? response({ code: 'ACL_VERSION_CONFLICT' }, 409) : response(versioned));
  await mount(); await activate();
  expect(fetch.mock.calls.filter(([, options]) => options)).toHaveLength(1);
  expect(container.textContent).toContain('Policy changed');
});
test('unknown write retains operation and 401 recovery never reposts', async () => {
  global.fetch = jest.fn(async (url, options) => {
    if (options) throw new Error('lost acknowledgement');
    if (url.includes('/operations/')) return response({}, 401);
    return response(versioned);
  });
  await mount(); await activate();
  expect(toggle().getAttribute('aria-disabled')).toBe('true');
  await act(async () => [...container.querySelectorAll('button')].find(b => b.textContent === 'Read change receipt').click());
  expect(container.textContent).toContain('Sign in again');
  expect(fetch.mock.calls.filter(([, options]) => options)).toHaveLength(1);
});
test('foreign-scope saved ACL operation blocks writes without losing its recovery reference', async () => {
  const foreign = { kind: 'enforcement', scopeKey: 'other-scope', registrySha256: 'a'.repeat(64),
    body: { operationId: '11111111-1111-4111-8111-111111111111', expectedVersion: '1', enabled: false } };
  localStorage.setItem(SHOP_ACL_KEY, JSON.stringify(foreign));
  global.fetch = jest.fn(async () => response(versioned));
  await mount(); await activate();
  expect(toggle().getAttribute('aria-disabled')).toBe('true');
  expect(container.querySelector('[role="alert"]').textContent).toContain('another scope');
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  expect(JSON.parse(localStorage.getItem(SHOP_ACL_KEY))).toEqual(foreign);
});
test('a reference appearing after load blocks the write and survives cleanup', async () => {
  const foreign = { kind: 'enforcement', scopeKey: 'other-scope', registrySha256: 'a'.repeat(64),
    body: { operationId: '11111111-1111-4111-8111-111111111111', expectedVersion: '1', enabled: false } };
  global.fetch = jest.fn(async () => response(versioned));
  await mount();
  localStorage.setItem(SHOP_ACL_KEY, JSON.stringify(foreign));
  await activate();
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  expect(JSON.parse(localStorage.getItem(SHOP_ACL_KEY))).toEqual(foreign);
  expect(toggle().getAttribute('aria-disabled')).toBe('true');
});
test('unsupported and nonapplicable permissions stay disabled', async () => {
  global.fetch = jest.fn(async () => response({ ...versioned, tools: [...versioned.tools,
    { ...versioned.tools[0], tool_name: 'legacy.unavailable', supported: false, readOnly: true }] }));
  await mount();
  expect(container.querySelector('[data-testid="acl-cell-owned.read-merchant"]').disabled).toBe(true);
  expect(container.querySelector('[data-testid="acl-cell-legacy.unavailable-admin"]').disabled).toBe(true);
  expect(container.querySelector('[data-testid="acl-cell-owned.read-admin"]').disabled).toBe(false);
});
test('lost acknowledgement survives remount and exact receipt clears pending without replay', async () => {
  let saved;
  global.fetch = jest.fn(async (url, options) => {
    if (options) { saved = JSON.parse(options.body); throw new Error('lost acknowledgement'); }
    if (url.includes('/operations/')) return response({ ok: true, receipt: receiptFor(saved) });
    return response(versioned);
  });
  await mount(); await activate();
  await act(async () => root.unmount()); root = createRoot(container);
  await mount();
  expect(toggle().getAttribute('aria-disabled')).toBe('true');
  await act(async () => [...container.querySelectorAll('button')].find(b => b.textContent === 'Read change receipt').click());
  expect(fetch.mock.calls.filter(([, options]) => options)).toHaveLength(1);
  expect(toggle().getAttribute('aria-disabled')).toBe('false');
});

test('bound bridge without versioned capability cannot use legacy writes', async () => {
  mockBound = true;
  global.fetch = jest.fn(async () => response(valid));
  await mount(); await activate();
  expect(toggle().getAttribute('aria-disabled')).toBe('true');
  expect(container.querySelector('[data-testid="acl-cell-owned.read-admin"]').disabled).toBe(true);
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('failed storage acknowledgement sends no POST and offers no receipt recovery', async () => {
  flushShopStorage.mockRejectedValueOnce(new Error('ack lost'));
  global.fetch = jest.fn(async () => response(versioned));
  await mount(); await activate();
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(container.textContent).toContain('no ACL change was sent');
  expect(container.textContent).not.toContain('outcome unknown');
  expect(container.textContent).not.toContain('Read change receipt');
  expect(toggle().getAttribute('aria-disabled')).toBe('true');
});
test('fresh same-persona credential retains original operation for GET-only recovery', async () => {
  let saved;
  global.fetch = jest.fn(async (url, options) => {
    if (options) { saved = JSON.parse(options.body); throw new Error('ack lost'); }
    if (url.includes('/operations/')) return response({ ok: true, receipt: receiptFor(saved) });
    return response(versioned);
  });
  await act(async () => root.render(<AuthCtx.Provider value={{ token: 'original' }}><AccessControl /></AuthCtx.Provider>));
  await activate();
  await act(async () => root.render(<AuthCtx.Provider value={{ token: 'fresh' }}><AccessControl /></AuthCtx.Provider>));
  await act(async () => [...container.querySelectorAll('button')].find(b => b.textContent === 'Read change receipt').click());
  expect(fetch.mock.calls.filter(([, options]) => options)).toHaveLength(1);
  expect(fetch.mock.calls.some(([url]) => url.endsWith('/operations/' + saved.operationId))).toBe(true);
  expect(toggle().getAttribute('aria-disabled')).toBe('false');
});
