import { compileBridgeOperation } from './compiler.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';
import { createHostTransport } from './transport.mjs';
import { validateShopSnapshot } from './stateStore.mjs';
import { createScopedShopStateStore } from './stateStore.mjs';
import { createHostShopStateChannel, connectFrameShopState } from './stateChannel.mjs';
import { SHOP_ACCOUNT_AVATAR_PENDING_KEY, SHOP_CART_KEY, SHOP_TOKEN_KEY } from '../utils/shopStorage.mjs';

Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Request = web.Request; global.Response = web.Response; global.Headers = web.Headers;
const requestId = '123e4567-e89b-42d3-a456-426614174000';
const reference = JSON.stringify({ version: 1, ownerId: '7', sessionFingerprint: 'a'.repeat(64),
  requestId, filename: 'avatar.svg', mime: 'image/svg+xml', sizeBytes: 4, public: true });

test('direct Account avatar POST and GET use separate closed bridge operations', async () => {
  const calls = [];
  const fetch = createBridgeFetch({ origin: 'https://shop.test', bridge: { request: async (...args) => {
    calls.push(args); return { ok: true };
  } } });
  const form = new FormData();
  form.append('file', new Blob(['body'], { type: 'image/svg+xml' }), 'avatar.svg');
  for (const [key, value] of Object.entries({ kind: 'avatar', scope_id: '7', mime: 'image/svg+xml',
    public: 'true', requestId })) form.append(key, value);
  await fetch('/api/secureshop/uploads/avatar', { method: 'POST', body: form,
    headers: { Authorization: 'Bearer customer-token' } });
  expect(calls[0][0]).toBe('uploads.avatar.create');
  expect(calls[0][2].shopBearer).toBe('customer-token');
  expect(compileBridgeOperation(calls[0][0], calls[0][1]).path).toBe('/api/secureshop/uploads/avatar');
  expect(() => compileBridgeOperation('uploads.create', calls[0][1])).toThrow();
  await fetch(`/api/secureshop/uploads/avatar/operations/${requestId}`, {
    method: 'GET', headers: { Authorization: 'Bearer customer-token' } });
  expect(calls[1][0]).toBe('uploads.avatar.operation');
  expect(compileBridgeOperation(calls[1][0], calls[1][1]).path)
    .toBe(`/api/secureshop/uploads/avatar/operations/${requestId}`);
  await expect(fetch(`/api/secureshop/uploads/avatar/operations/${requestId.toUpperCase()}`))
    .rejects.toThrow();
  await expect(fetch(`/api/secureshop/uploads/avatar/operations/${requestId}?other=1`))
    .rejects.toThrow();
});

test('direct Account form rejects foreign scope and extra fields before bridge dispatch', async () => {
  const calls = [];
  const fetch = createBridgeFetch({ origin: 'https://shop.test', bridge: { request: async (...args) => {
    calls.push(args); return { ok: true };
  } } });
  const form = new FormData();
  form.append('file', new Blob(['body']), 'avatar.svg');
  for (const [key, value] of Object.entries({ kind: 'avatar', scope_id: '0', mime: 'image/svg+xml',
    public: 'true', requestId })) form.append(key, value);
  await expect(fetch('/api/secureshop/uploads/avatar', { method: 'POST', body: form })).rejects.toThrow();
  form.set('scope_id', '7'); form.append('unexpected', 'x');
  await expect(fetch('/api/secureshop/uploads/avatar', { method: 'POST', body: form })).rejects.toThrow();
  expect(calls).toHaveLength(0);
});

test('acknowledged frame state admits only strict Account pending reference', () => {
  const base = { [SHOP_TOKEN_KEY]: 'customer-token', [SHOP_CART_KEY]: null };
  expect(validateShopSnapshot({ ...base, [SHOP_ACCOUNT_AVATAR_PENDING_KEY]: reference })
    [SHOP_ACCOUNT_AVATAR_PENDING_KEY]).toBe(reference);
  const versionTwo = JSON.stringify({ ...JSON.parse(reference), version: 2 });
  expect(validateShopSnapshot({ ...base, [SHOP_ACCOUNT_AVATAR_PENDING_KEY]: versionTwo })
    [SHOP_ACCOUNT_AVATAR_PENDING_KEY]).toBe(versionTwo);
  expect(() => validateShopSnapshot({ ...base, [SHOP_ACCOUNT_AVATAR_PENDING_KEY]: JSON.stringify({
    ...JSON.parse(reference), bearer: 'forbidden',
  }) })).toThrow();
});

function localPorts() {
  const listeners = [new Set(), new Set()];
  return { port1: { addEventListener: (_type, listener) => listeners[0].add(listener),
    removeEventListener: (_type, listener) => listeners[0].delete(listener), start() {}, close() {},
    postMessage: data => queueMicrotask(() => listeners[1].forEach(listener => listener({ data }))) },
  port2: { addEventListener: (_type, listener) => listeners[1].add(listener),
    removeEventListener: (_type, listener) => listeners[1].delete(listener), start() {}, close() {},
    postMessage: data => queueMicrotask(() => listeners[0].forEach(listener => listener({ data }))) } };
}

test('actual host/frame state channel acknowledges Account pending before any POST', async () => {
  const values = new Map(); const ports = localPorts();
  const store = createScopedShopStateStore({ storage: { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value) },
  scenarioId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', generation: 1, isCurrent: () => true });
  const host = createHostShopStateChannel({ port: ports.port1, store });
  try {
    const frame = await connectFrameShopState({ port: ports.port2, timeoutMs: 1000 });
    expect(frame.getItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY)).toBeNull();
    frame.setItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY, reference);
    await frame.flush();
    expect(store.read()[SHOP_ACCOUNT_AVATAR_PENDING_KEY]).toBe(reference);
    frame.removeItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY);
    await frame.flush();
    expect(store.read()).not.toHaveProperty(SHOP_ACCOUNT_AVATAR_PENDING_KEY);
    frame.close();
  } finally { host.close(); }
});

function requestPort() {
  const listeners = new Set(); const messages = [];
  return { messages, addEventListener: (_type, listener) => listeners.add(listener),
    removeEventListener: (_type, listener) => listeners.delete(listener), start() {}, close() {},
    postMessage(message) { messages.push(message);
      if (message.type === 'start' || message.type === 'chunk') queueMicrotask(() =>
        listeners.forEach(listener => listener({ data: { type: 'pull', id: message.id } })));
    },
    dispatch: message => listeners.forEach(listener => listener({ data: message })) };
}
const waitFor = predicate => new Promise((resolve, reject) => {
  const began = Date.now();
  const check = () => predicate() ? resolve() : Date.now() - began > 1000
    ? reject(Error('host bridge timeout')) : setTimeout(check, 0);
  check();
});

test('actual host transport reconstructs direct Account multipart without legacy fallback', async () => {
  const port = requestPort(); const fetchImpl = jest.fn(async () => new Response('{}', {
    status: 200, headers: { 'content-type': 'application/json' },
  }));
  const host = createHostTransport({ port, origin: 'https://shop.test',
    compileOperation: compileBridgeOperation, fetchImpl, getLaunchBearer: () => 'a'.repeat(43) });
  try {
    port.dispatch({ type: 'request', id: 1, operation: 'uploads.avatar.create', shopBearer: 'owner-token',
      input: { file: new Blob(['body'], { type: 'image/svg+xml' }), filename: 'avatar.svg',
        fields: { kind: 'avatar', scope_id: '7', mime: 'image/svg+xml', public: 'true', requestId } } });
    await waitFor(() => port.messages.some(message => message.type === 'end' || message.type === 'error'));
    expect(port.messages.filter(message => message.type === 'error')).toEqual([]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, options] = fetchImpl.mock.calls[0];
    expect(url).toBe('https://shop.test/api/secureshop/uploads/avatar');
    expect(options.method).toBe('POST');
    expect([...options.body.keys()]).toEqual(['file', 'kind', 'scope_id', 'mime', 'public', 'requestId']);
    expect(options.body.get('requestId')).toBe(requestId);
    expect(options.headers.get('Authorization')).toBe('Bearer owner-token');
    expect(options.headers.has('Content-Type')).toBe(false);
  } finally { host.close(); }
});
