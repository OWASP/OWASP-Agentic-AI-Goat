import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useAgentStream } from './useAgentStream';
import { attachShopStorage, SHOP_CUSTOMER_CHAT_KEY } from '../utils/shopStorage.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const customerMode = { version: 1, featureId: 'customer_chat',
  policyVersion: 'owned-catalog-and-cart-read-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'customer_chat' } };

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function response({ json, reader, type = 'application/json' }) {
  return { ok: true, status: 200,
    headers: { get: name => name.toLowerCase() === 'content-type' ? type : null },
    json: jest.fn(async () => json),
    body: reader ? { getReader: () => reader } : null };
}

let current;
function Harness() {
  current = useAgentStream({ role: 'customer', defaultUserId: 5,
    boundCustomerChat: true, authorityKey: 'current-customer' });
  return null;
}

function mount() {
  const root = createRoot(document.createElement('div'));
  act(() => root.render(<Harness />));
  return () => act(() => root.unmount());
}

async function flush() {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
}

let detachStorage;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  global.fetch = jest.fn();
  detachStorage = attachShopStorage({ getItem: key => localStorage.getItem(key),
    setItem: (key, value) => localStorage.setItem(key, value),
    removeItem: key => localStorage.removeItem(key), flush: async () => {} });
  current = null;
});

afterEach(() => {
  detachStorage?.();
  delete global.fetch;
});

test('stopping a saved customer response keeps its UUID and requires explicit GET, never another POST', async () => {
  const waitingRead = deferred();
  const reader = { read: jest.fn(() => waitingRead.promise), cancel: jest.fn(async () => {}) };
  const reads = [];
  let chatSignal;
  fetch.mockImplementation((url, options = {}) => {
    if (url.endsWith('/session')) return Promise.resolve(response({ json: { sessionId } }));
    if (url.endsWith('/chat')) {
      chatSignal = options.signal;
      return Promise.resolve(response({ type: 'text/event-stream', reader }));
    }
    if (url.includes('/operations/')) {
      reads.push(url);
      const requestId = url.split('/').at(-1);
      return Promise.resolve(response({ json: reads.length === 1
        ? { sessionId, requestId, status: 'unconfirmed' }
        : { sessionId, requestId, status: 'completed', replayed: true,
          text: 'Saved answer', stopReason: 'end_turn', modeCapability: customerMode,
          hops: [], cards: [], operations: [] } }));
    }
    throw new Error(`Unexpected request: ${url}`);
  });

  const unmount = mount();
  let sent;
  act(() => { sent = current.send('Find a laptop'); });
  await flush();
  expect(reader.read).toHaveBeenCalledTimes(1);
  expect(current.canStopWatching).toBe(true);
  const saved = current.pending;
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toContain(saved.requestId);

  act(() => { expect(current.stopWatching()).toBe(true); });
  expect(chatSignal.aborted).toBe(true);
  expect(reader.cancel).toHaveBeenCalledTimes(1);
  expect(current.status).toBe('unresolved');
  expect(current.pending).toEqual(saved);
  expect(reads).toHaveLength(0); // Stopping observation does not silently recover or infer the effect.
  await act(async () => { expect(await current.send('Try again')).toBe(false); });
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/chat'))).toHaveLength(1);

  waitingRead.resolve({ value: new TextEncoder().encode(`event: done\ndata: ${JSON.stringify({
    sessionId, requestId: saved.requestId, stopReason: 'end_turn', modeCapability: customerMode,
  })}\n\n`), done: false });
  await act(async () => { await expect(sent).resolves.toBe(false); });
  expect(current.pending).toEqual(saved); // Late stream frames cannot become a confirmed answer.

  await act(async () => { await expect(current.recover()).resolves.toBe(false); });
  expect(reads).toEqual([`/api/secureshop/agents/customer/operations/${sessionId}/${saved.requestId}`]);
  expect(current.pending).toEqual(saved);
  await act(async () => { await expect(current.recover()).resolves.toBe(true); });
  expect(reads).toHaveLength(2);
  expect(current.turns[0]).toMatchObject({ requestId: saved.requestId,
    reply: 'Saved answer', status: 'done' });
  expect(current.pending).toBeNull();
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/chat'))).toHaveLength(1);
  unmount();
});

test('Stop watching stays unavailable until the saved-reference parent ACK', async () => {
  const saveAck = deferred();
  detachStorage();
  detachStorage = attachShopStorage({ getItem: key => localStorage.getItem(key),
    setItem: (key, value) => localStorage.setItem(key, value),
    removeItem: key => localStorage.removeItem(key), flush: () => saveAck.promise });
  const waitingRead = deferred();
  const reader = { read: jest.fn(() => waitingRead.promise), cancel: jest.fn(async () => {}) };
  fetch.mockImplementation((url) => {
    if (url.endsWith('/session')) return Promise.resolve(response({ json: { sessionId } }));
    if (url.endsWith('/chat')) return Promise.resolve(response({ type: 'text/event-stream', reader }));
    throw new Error(`Unexpected request: ${url}`);
  });

  const unmount = mount();
  let sent;
  act(() => { sent = current.send('Show my cart'); });
  await flush();
  expect(current.pending?.requestId).toMatch(/^[0-9a-f-]{36}$/);
  expect(current.canStopWatching).toBe(false);
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/chat'))).toHaveLength(0);

  saveAck.resolve();
  await flush();
  expect(current.canStopWatching).toBe(true);
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/chat'))).toHaveLength(1);
  act(() => { current.stopWatching(); });
  waitingRead.resolve({ value: undefined, done: true });
  await act(async () => { await expect(sent).resolves.toBe(false); });
  unmount();
});
