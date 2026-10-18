import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { useProductSimilar, decodeSavedProductSimilar } from './useProductSimilar.js';
import { createProductSimilarReferenceStore } from '../utils/productSimilarReference.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ref = { version: 1, shopUserId: 7, productId: 12, sessionId, requestId, startedAt: 12345 };
const result = { results: [{ id: 14, name: 'Similar notebook' }], count: 1,
  mode: 'mixed', recommendation: 'A plain-text recommendation.',
  seed: { id: 12, name: 'Selected notebook' }, retrieved_context: [],
  provider: 'ollama', model: 'llama3.1:8b', sessionId, requestId };
const response = (value, status = 200) => ({ ok: status >= 200 && status < 300, status,
  headers: { get: key => key === 'content-type' ? 'application/json' : null },
  json: async () => value });

function memoryStore() {
  const rows = new Map();
  return createProductSimilarReferenceStore({ storage: {
    getItem: key => rows.get(key) ?? null,
    setItem: (key, value) => rows.set(key, value),
    removeItem: key => rows.delete(key),
  }, flush: async () => {} });
}

let root, node, current, originalCrypto;
function Harness(props) { current = useProductSimilar(props); return null; }
function mount(props) {
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  act(() => root.render(<Harness {...props} />));
  return { rerender(next) { act(() => root.render(<Harness {...next} />)); } };
}
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  originalCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { ...webcrypto, randomUUID: () => requestId } });
});
afterEach(async () => {
  if (root) await act(async () => root.unmount());
  node?.remove(); root = null; node = null;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: originalCrypto });
});

test('completed saved result is closed and bound to the selected product and original IDs', () => {
  expect(decodeSavedProductSimilar({ status: 'completed', result }, ref).result.results)
    .toEqual(result.results);
  for (const changed of [{ ...result, requestId: sessionId },
    { ...result, seed: { ...result.seed, id: 13 } },
    { ...result, extraAuthority: true },
    { ...result, recommendation: '' }])
    expect(() => decodeSavedProductSimilar({ status: 'completed', result: changed }, ref)).toThrow();
  expect(decodeSavedProductSimilar({ status: 'pending', sessionId, requestId }, ref).status)
    .toBe('pending');
  expect(() => decodeSavedProductSimilar({ status: 'not_found', sessionId,
    requestId: sessionId }, ref)).toThrow();
});

test('explicit similar action persists server session and request before one model POST; remount reads only', async () => {
  const referenceStore = memoryStore(), calls = [];
  const transport = jest.fn(async (path, options) => {
    calls.push({ path, method: options.method, body: options.body });
    if (path.endsWith('/session')) return response({ sessionId });
    if (options.method === 'POST') {
      expect(referenceStore.read(7)).toMatchObject({ productId: 12, sessionId, requestId });
      expect(JSON.parse(options.body)).toEqual({ sessionId, requestId });
      return response({ sessionId, requestId });
    }
    if (path.endsWith(`/sessions/${sessionId}/requests/${requestId}`))
      return response({ status: 'completed', result });
    throw Error(`unexpected ${path}`);
  });
  const props = { productId: '12', shopUserId: 7, authorityKey: 'shop-token',
    transport, referenceStore };
  mount(props);
  expect(calls).toHaveLength(0);
  await act(async () => { expect(await current.start()).toBe(true); });
  expect(current.outcome.result.recommendation).toBe(result.recommendation);
  expect(calls.map(call => call.method)).toEqual(['POST', 'POST', 'GET']);
  await act(async () => root.unmount()); root = null; node.remove(); node = null;
  mount(props);
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(calls.map(call => call.method)).toEqual(['POST', 'POST', 'GET', 'GET']);
  expect(current.outcome.result.results).toEqual(result.results);
});

test('lost POST acknowledgement and not-found recovery never auto-repeat; explicit retry keeps IDs', async () => {
  const referenceStore = memoryStore(), calls = [];
  let savedStatus = 'not_found';
  const transport = jest.fn(async (path, options) => {
    calls.push({ path, method: options.method, body: options.body });
    if (path.endsWith('/session')) return response({ sessionId });
    if (options.method === 'POST') {
      expect(referenceStore.read(7)).toMatchObject({ productId: 12, sessionId, requestId });
      if (calls.filter(call => call.method === 'POST').length === 2)
        throw Error('original response lost');
      savedStatus = 'completed'; return response({ sessionId, requestId });
    }
    return savedStatus === 'completed' ? response({ status: 'completed', result })
      : response({ status: savedStatus, sessionId, requestId }, 404);
  });
  const props = { productId: '12', shopUserId: 7, authorityKey: 'shop-token',
    transport, referenceStore };
  mount(props);
  await act(async () => { expect(await current.start()).toBe(true); });
  expect(current.outcome.status).toBe('not_found');
  expect(calls.filter(call => call.method === 'POST')).toHaveLength(2);
  await act(async () => root.unmount()); root = null; node.remove(); node = null;
  mount(props);
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(calls.filter(call => call.method === 'POST')).toHaveLength(2);
  await act(async () => { expect(await current.retryNotFound()).toBe(true); });
  expect(current.outcome.status).toBe('completed');
  expect(calls.filter(call => call.method === 'POST')).toHaveLength(3);
  expect(calls.filter(call => call.method === 'POST').at(-1).body)
    .toBe(JSON.stringify({ sessionId, requestId }));
});

test('an unrelated HTTP 404 is not an eligible retry state', async () => {
  const referenceStore = memoryStore();
  await referenceStore.save({ shopUserId: 7, productId: 12, sessionId, requestId,
    startedAt: 12345 });
  const transport = jest.fn(async () => response({ error: 'Not found' }, 404));
  mount({ productId: '12', shopUserId: 7, authorityKey: 'shop-token', transport,
    referenceStore });
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(current.outcome).toBeNull();
  expect(await current.retryNotFound()).toBe(false);
  expect(transport.mock.calls.map(([, options]) => options.method)).toEqual(['GET']);
});
