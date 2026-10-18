import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { useAgentStream } from './useAgentStream';
import { attachShopStorage, SHOP_CUSTOMER_CHAT_KEY,
  SHOP_CUSTOMER_CHAT_COMPLETED_KEY } from '../utils/shopStorage.mjs';
import { profileRequestDigest } from '../utils/profileOperation.mjs';
import { compileOperation, matchOperationRequest } from '../bridge/operations.mjs';

const customerMode = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function response({ ok = true, status = 200, type = 'application/json', json, reader } = {}) {
  return {
    ok,
    status,
    headers: { get: (name) => name.toLowerCase() === 'content-type' ? type : null },
    json: jest.fn(async () => json),
    body: reader ? { getReader: () => reader } : null,
  };
}

function stream(...chunks) {
  const encoded = chunks.map((chunk) => new TextEncoder().encode(chunk));
  let index = 0;
  return {
    read: jest.fn(async () => index < encoded.length
      ? { value: encoded[index++], done: false }
      : { value: undefined, done: true }),
    cancel: jest.fn(async () => {}),
  };
}

let current;
let releaseStorage;
function Harness(props) {
  current = useAgentStream(props);
  return null;
}

function renderHook(props = {}) {
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(<Harness {...props} />));
  return {
    rerender(next) { act(() => root.render(<Harness {...next} />)); },
    unmount() { act(() => root.unmount()); },
  };
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  global.fetch = jest.fn();
  localStorage.clear();
  releaseStorage = attachShopStorage({ getItem: key => localStorage.getItem(key),
    setItem: (key, value) => localStorage.setItem(key, value),
    removeItem: key => localStorage.removeItem(key), flush: async () => {} });
  current = null;
});

afterEach(() => {
  releaseStorage?.();
  delete global.fetch;
});

test('send enters thinking during session creation and resolves with an error turn on session failure', async () => {
  const pending = deferred();
  fetch.mockReturnValueOnce(pending.promise);
  const view = renderHook();
  let sent;
  act(() => { sent = current.send('hello'); });
  await flush();
  expect(current.status).toBe('thinking');
  expect(current.turns).toHaveLength(1);
  expect(current.turns[0]).toMatchObject({ user: 'hello', status: 'in-flight' });

  pending.resolve(response({ ok: false, status: 503, json: { error: 'offline' } }));
  await act(async () => { await expect(sent).resolves.toBe(false); });
  expect(current.status).toBe('error');
  expect(current.error).toBe('Agent session request failed (503)');
  expect(current.turns[0].status).toBe('error');
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  view.unmount();
});

test.each([
  ['session content type',
    [response({ type: 'text/html', json: { sessionId: 'sid' } })],
    'Agent session returned unexpected content type'],
  ['chat HTTP status',
    [response({ json: { sessionId: 'sid' } }), response({ ok: false, status: 502 })],
    'Agent chat request failed (502)'],
  ['chat content type',
    [response({ json: { sessionId: 'sid' } }), response({ type: 'application/json', reader: stream() })],
    'Agent chat returned unexpected content type'],
])('%s fails closed and marks the accepted turn terminal', async (_label, fixtures, expected) => {
  fetch.mockImplementation(() => Promise.resolve(fixtures.shift()));
  const view = renderHook();
  await act(async () => { await expect(current.send('validate protocol')).resolves.toBe(false); });
  expect(current.status).toBe('error');
  expect(current.error).toBe(expected);
  expect(current.turns[0].status).toBe('error');
  view.unmount();
});

test('fragmented CRLF SSE updates its own turn and requires done for successful idle state', async () => {
  const reader = stream(
    ': stream open\r\n\r\nevent: tool_call\r\ndata: {"id":"c1","tool":"cart.add","params":{"id":7},',
    '"step":1,"policyViolation":"denied-by-acl"}\r\n\r\nevent: tool_result\r\ndata: {"id":"c1","result":{"ok":true},"latencyMs":4}\r\n\r\n',
    `event: assistant_message\r\ndata: {"text":"added","stopReason":"end_turn"}\r\n\r\nevent: done\r\ndata: ${JSON.stringify({ sessionId: 'sid', steps: 1, modeCapability: customerMode })}\r\n\r\n`,
  );
  fetch
    .mockResolvedValueOnce(response({ json: { sessionId: 'sid' } }))
    .mockResolvedValueOnce(response({ type: 'text/event-stream; charset=utf-8', reader }));
  const view = renderHook();
  await act(async () => { await expect(current.send('add item')).resolves.toBe(true); });
  expect(current.status).toBe('idle');
  expect(current.error).toBeNull();
  expect(current.sessionId).toBe('sid');
  expect(current.turns[0]).toMatchObject({
    user: 'add item', reply: 'added', stopReason: 'end_turn', status: 'done',
    hops: [{ id: 'c1', tool: 'cart.add', status: 'ok', result: { ok: true }, latencyMs: 4, policyViolation: 'denied-by-acl' }],
  });
  expect(reader.cancel).toHaveBeenCalledTimes(1);
  view.unmount();
});

test('stream retains the server turn capability on reply and hop rather than the current selector', async () => {
  const modeCapability = { version: 1, featureId: 'analytics', policyVersion: 'postgres-restricted-capability-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'analytics' } };
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  const reader = stream(
    frame('tool_call', { id: 'h1', tool: 'analytics.query', params: {}, modeCapability }),
    frame('tool_result', { id: 'h1', result: { content: [{ type: 'text', text: '<b>effect</b>' }] }, modeCapability }),
    frame('assistant_message', { text: '<b>answer</b>', modeCapability }),
    frame('done', { sessionId: 'sid', modeCapability }),
  );
  fetch.mockResolvedValueOnce(response({ json: { sessionId: 'sid' } }))
    .mockResolvedValueOnce(response({ type: 'text/event-stream', reader }));
  const view = renderHook();
  await act(async () => { await expect(current.send('read analytics')).resolves.toBe(true); });
  expect(current.turns[0].modeCapability).toEqual(modeCapability);
  expect(current.turns[0].hops[0].modeCapability).toEqual(modeCapability);
  view.unmount();
});

test('EOF without done is a protocol error and cannot leave thinking state', async () => {
  const reader = stream('event: assistant_message\ndata: {"text":"partial","stopReason":"unknown"}\n\n');
  fetch
    .mockResolvedValueOnce(response({ json: { sessionId: 'sid' } }))
    .mockResolvedValueOnce(response({ type: 'text/event-stream', reader }));
  const view = renderHook();
  await act(async () => { await expect(current.send('partial')).resolves.toBe(false); });
  expect(current.status).toBe('error');
  expect(current.error).toBe('Agent stream ended before a terminal event');
  expect(current.turns[0]).toMatchObject({ reply: 'partial', status: 'error' });
  view.unmount();
});

test.each([
  ['error', 'Agent stopped with an error'],
  ['cancelled', 'Agent request was cancelled'],
])('done with %s stopReason is terminal but not successful', async (stopReason, expectedError) => {
  const reader = stream(
    `event: assistant_message\ndata: {"text":"[${stopReason}]","stopReason":"${stopReason}"}\n\n`,
    `event: done\ndata: ${JSON.stringify({ sessionId: 'sid', stopReason, steps: 1, modeCapability: customerMode })}\n\n`,
  );
  fetch
    .mockResolvedValueOnce(response({ json: { sessionId: 'sid' } }))
    .mockResolvedValueOnce(response({ type: 'text/event-stream', reader }));
  const view = renderHook();
  await act(async () => { await expect(current.send('terminal failure')).resolves.toBe(false); });
  expect(current.status).toBe('error');
  expect(current.error).toBe(expectedError);
  expect(current.turns[0]).toMatchObject({ reply: `[${stopReason}]`, stopReason, status: 'error' });
  view.unmount();
});

test('an overlapping send is rejected without a second request or turn', async () => {
  const pending = deferred();
  fetch.mockReturnValueOnce(pending.promise);
  const view = renderHook();
  let first;
  act(() => { first = current.send('first'); });
  await flush();
  await act(async () => { await expect(current.send('second')).resolves.toBe(false); });
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(current.turns.map((turn) => turn.user)).toEqual(['first']);
  pending.resolve(response({ ok: false, status: 503 }));
  await act(async () => { await first; });
  view.unmount();
});

test.each([
  ['role', { base: '/api/secureshop', role: 'merchant', defaultUserId: 7 }],
  ['base', { base: '/different', role: 'customer', defaultUserId: 7 }],
  ['defaultUserId', { base: '/api/secureshop', role: 'customer', defaultUserId: 8 }],
])('%s change aborts session creation and ignores its stale completion', async (_label, nextProps) => {
  const pending = deferred();
  let signal;
  fetch.mockImplementationOnce((_url, options) => {
    signal = options.signal;
    return pending.promise;
  });
  const view = renderHook({ base: '/api/secureshop', role: 'customer', defaultUserId: 7 });
  let sent;
  act(() => { sent = current.send('stale'); });
  await flush();
  view.rerender(nextProps);
  expect(signal.aborted).toBe(true);
  expect(current.status).toBe('idle');
  expect(current.turns).toEqual([]);
  pending.resolve(response({ json: { sessionId: 'stale-session' } }));
  await act(async () => { await expect(sent).resolves.toBe(false); });
  expect(current.sessionId).toBeNull();
  expect(current.turns).toEqual([]);
  expect(fetch).toHaveBeenCalledTimes(1);
  view.unmount();
});

test('role change aborts an active chat reader and ignores its late terminal frame', async () => {
  const read = deferred();
  const reader = { read: jest.fn(() => read.promise), cancel: jest.fn(async () => {}) };
  let chatSignal;
  fetch
    .mockResolvedValueOnce(response({ json: { sessionId: 'customer-session' } }))
    .mockImplementationOnce((_url, options) => {
      chatSignal = options.signal;
      return Promise.resolve(response({ type: 'text/event-stream', reader }));
    });
  const view = renderHook({ role: 'customer', defaultUserId: 7 });
  let sent;
  act(() => { sent = current.send('old role'); });
  await flush();
  expect(reader.read).toHaveBeenCalledTimes(1);
  view.rerender({ role: 'merchant', defaultUserId: 7 });
  expect(chatSignal.aborted).toBe(true);
  expect(reader.cancel).toHaveBeenCalledTimes(1);
  expect(current.status).toBe('idle');
  expect(current.sessionId).toBeNull();
  expect(current.turns).toEqual([]);
  read.resolve({ value: new TextEncoder().encode('event: done\ndata: {"stopReason":"end_turn"}\n\n'), done: false });
  await act(async () => { await expect(sent).resolves.toBe(false); });
  expect(current.turns).toEqual([]);
  view.unmount();
});

test('unmount aborts fetch and cancels an active reader without accepting late events', async () => {
  const read = deferred();
  const reader = { read: jest.fn(() => read.promise), cancel: jest.fn(async () => {}) };
  let chatSignal;
  fetch
    .mockResolvedValueOnce(response({ json: { sessionId: 'sid' } }))
    .mockImplementationOnce((_url, options) => {
      chatSignal = options.signal;
      return Promise.resolve(response({ type: 'text/event-stream', reader }));
    });
  const view = renderHook();
  let sent;
  act(() => { sent = current.send('wait'); });
  await flush();
  expect(reader.read).toHaveBeenCalledTimes(1);
  view.unmount();
  expect(chatSignal.aborted).toBe(true);
  expect(reader.cancel).toHaveBeenCalledTimes(1);
  read.resolve({ value: new TextEncoder().encode('event: done\ndata: {}\n\n'), done: false });
  await act(async () => { await expect(sent).resolves.toBe(false); });
});

test('a captured createSession callback cannot start network work after unmount', async () => {
  const view = renderHook();
  const createSession = current.createSession;
  view.unmount();
  await expect(createSession()).rejects.toThrow('Agent stream is not active');
  expect(fetch).not.toHaveBeenCalled();
});

const customerSession = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const customerChoice = { version: 1, kind: 'product',
  choiceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  title: 'Practice laptop', detail: 'Available in this shop' };
const savedCustomer = (url, text, cards) => response({ json: {
  sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
  text, stopReason: 'end_turn', modeCapability: customerMode, replayed: true, hops: [],
  ...(cards === undefined ? {} : { cards }), operations: [],
} });
const customerProposal = { version: 1, proposalId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  status: 'prepared', currency: 'USD',
  items: [{ productId: 7, name: 'Practice laptop', quantity: 1, unitPriceCents: 1200, lineTotalCents: 1200 }],
  subtotalCents: 1200, discountCents: 0, totalCents: 1200,
  address: { choiceId: customerChoice.choiceId, title: 'Practice address', detail: 'Saved address' },
  paymentMethod: { choiceId: customerChoice.choiceId, title: 'Approved practice payment', detail: 'Synthetic only' },
  quoteSha256: 'a'.repeat(64) };

test('bound customer chat saves a UUID before POST and clears it only after done', async () => {
  let sent;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      sent = JSON.parse(options.body);
      const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('assistant_message', { sessionId: customerSession, requestId: sent.requestId, text: 'Here is your cart', modeCapability: customerMode }),
        frame('done', { sessionId: customerSession, requestId: sent.requestId, stopReason: 'end_turn', modeCapability: customerMode }),
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(savedCustomer(url, 'Here is your cart')));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Show my cart')).resolves.toBe(true); });
  expect(sent).toMatchObject({ sessionId: customerSession, message: 'Show my cart' });
  expect(sent.requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({});
  expect(current.turns[0]).toMatchObject({ requestId: sent.requestId, reply: 'Here is your cart', status: 'done' });
  expect(current.pending).toBeNull();
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toBeNull();
  view.unmount();
});

test('live customer turn retains its originating session while saved completion is pending', async () => {
  const saved = deferred();
  let requestId;
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('tool_call', { sessionId: customerSession, requestId, id: 'search-1',
          tool: 'catalog.search', params: { search: 'owned' }, step: 1, modeCapability: customerMode }),
        frame('tool_result', { sessionId: customerSession, requestId, id: 'search-1',
          result: { content: [{ type: 'text', text: 'owned' }] }, modeCapability: customerMode }),
        frame('done', { sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode }),
      ) }));
    })
    .mockImplementationOnce(() => saved.promise);
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  let work;
  act(() => { work = current.send('Search for owned'); });
  await flush();
  expect(current.turns[0]).toMatchObject({ status: 'done', requestId,
    sessionId: customerSession, hops: [expect.objectContaining({ tool: 'catalog.search', step: 1 })] });
  saved.resolve(savedCustomer(`operations/${customerSession}/${requestId}`, 'Owned result'));
  await act(async () => { await expect(work).resolves.toBe(true); });
  view.unmount();
});

test('stock rejection is projected only from the exact saved completed turn', async () => {
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  let sent;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      sent = JSON.parse(options.body);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('done', { sessionId: customerSession, requestId: sent.requestId,
          stopReason: 'end_turn', modeCapability: customerMode }),
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'The requested quantity is unavailable.', stopReason: 'end_turn',
      modeCapability: customerMode, replayed: true, hops: [], cards: [],
      operations: [{ operationId: customerChoice.choiceId, status: 'completed', receipt: {
        version: 1, operationId: customerChoice.choiceId, kind: 'cart.add', status: 'rejected',
        result: { code: 'INSUFFICIENT_STOCK', choiceId: customerChoice.choiceId, quantity: 2 },
        replayed: true,
      } }],
    } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Add two to my cart')).toBe(true); });
  expect(current.turns[0].operations).toEqual([expect.objectContaining({
    status: 'completed', rejection: { code: 'INSUFFICIENT_STOCK',
      choiceId: customerChoice.choiceId, quantity: 2 },
  })]);
  expect(current.pending).toBeNull();
  view.unmount();
});

test('bound customer cards come from exact stream fields and selection posts only an opaque choice', async () => {
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  let first, selected;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      first = JSON.parse(options.body);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('assistant_message', { sessionId: customerSession, requestId: first.requestId,
          text: 'Choose a product', modeCapability: customerMode, cards: [customerChoice] }),
        frame('done', { sessionId: customerSession, requestId: first.requestId,
          stopReason: 'end_turn', modeCapability: customerMode, cards: [customerChoice] }),
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(savedCustomer(url, 'Choose a product', [customerChoice])))
    .mockImplementationOnce((_url, options) => {
      selected = JSON.parse(options.body);
      expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toContain(selected.requestId);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('assistant_message', { sessionId: customerSession, requestId: selected.requestId,
          text: 'Selection received', modeCapability: customerMode, cards: [] }),
        frame('done', { sessionId: customerSession, requestId: selected.requestId,
          stopReason: 'end_turn', modeCapability: customerMode, cards: [] }),
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(savedCustomer(url, 'Selection received', [])));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Find a laptop')).resolves.toBe(true); });
  expect(current.turns[0].cards).toEqual([customerChoice]);
  await act(async () => {
    await expect(current.send('Use my selected option.', { choiceId: customerChoice.choiceId })).resolves.toBe(true);
  });
  expect(selected).toEqual({ sessionId: customerSession, message: 'Use my selected option.',
    requestId: expect.any(String), selection: { choiceId: customerChoice.choiceId } });
  expect(selected.requestId).not.toBe(first.requestId);
  expect(current.turns[1].user).toBe('Selected product: Practice laptop');
  expect(current.turns[1].cards).toEqual([]);
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toBeNull();
  view.unmount();
});

test('an older filtered order page is hydrated from exact GET without sending its cursor or filter', async () => {
  const firstId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const olderId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const orderCard = choiceId => ({ version: 1, kind: 'order', choiceId,
    title: 'Owned order', detail: 'Delivered' });
  const bodies = [];
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/session')) return Promise.resolve(response({ json: { sessionId: customerSession } }));
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body);
      bodies.push(body);
      expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toContain(body.requestId);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('done', { sessionId: customerSession, requestId: body.requestId,
          stopReason: 'end_turn', modeCapability: customerMode,
          orderPage: { nextCursor: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' } }),
      ) }));
    }
    if (url.includes('/operations/')) {
      const page = bodies.length === 1 ? { cards: [orderCard(firstId)], nextCursor: firstId }
        : bodies.length === 2 ? { cards: [orderCard(olderId)], nextCursor: null }
          : { cards: [], nextCursor: null };
      return Promise.resolve(response({ json: {
        sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
        text: 'Saved owned orders', stopReason: 'end_turn', modeCapability: customerMode,
        replayed: true, hops: [], cards: page.cards, operations: [],
        orderPage: bodies.length < 3 ? { nextCursor: page.nextCursor,
          productName: 'Practice laptop' } : null,
      } }));
    }
    throw Error(`Unexpected ${url}`);
  });
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Show orders containing Practice laptop')).toBe(true); });
  expect(current.turns[0].orderPage).toEqual({ nextCursor: firstId, productName: 'Practice laptop' });
  await act(async () => { expect(await current.send('Show older orders')).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: customerSession, requestId: expect.any(String),
    message: 'Show older orders' });
  expect(current.turns[1]).toMatchObject({ cards: [orderCard(olderId)],
    orderPage: { nextCursor: null, productName: 'Practice laptop' } });
  await act(async () => {
    expect(await current.send('Use my selected option.', { choiceId: olderId })).toBe(true);
  });
  expect(bodies[2].selection).toEqual({ choiceId: olderId });
  expect(current.pending).toBeNull();
  view.unmount();
});

test('customer catalog continuation sends only the latest saved page identity', async () => {
  const bodies = [];
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/session')) return Promise.resolve(response({ json: { sessionId: customerSession } }));
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('done', { sessionId: customerSession, requestId: body.requestId,
          stopReason: 'end_turn', modeCapability: customerMode }),
      ) }));
    }
    if (url.includes('/operations/')) return Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Products', stopReason: 'end_turn', modeCapability: customerMode,
      replayed: true, hops: [], cards: [], operations: [],
      catalogPage: { version: 1, total: 14, pageSize: 12,
        returnedCount: bodies.length === 1 ? 12 : 2, hasMore: bodies.length === 1 },
    } }));
    throw Error(`Unexpected ${url}`);
  });
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Find laptops')).toBe(true); });
  const sourceRequestId = bodies[0].requestId;
  await act(async () => {
    expect(await current.send('Show more products', null,
      { intent: 'catalog_next', sourceRequestId: customerSession })).toBe(false);
    expect(await current.send('Show more products', null,
      { intent: 'catalog_next', sourceRequestId })).toBe(true);
  });
  expect(bodies[1]).toEqual({ sessionId: customerSession, requestId: expect.any(String),
    message: 'Show more products', catalogContinuation: { intent: 'catalog_next', sourceRequestId } });
  await act(async () => { expect(await current.send('Show more products', null,
    { intent: 'catalog_next', sourceRequestId: bodies[1].requestId })).toBe(false); });
  expect(bodies).toHaveLength(2);
  view.unmount();
});

test('acknowledged filtered page survives ordinary reload through one protected GET and no model POST', async () => {
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const bodies = [];
  const card = { version: 1, kind: 'order', choiceId, title: 'Order #42', detail: 'Delivered' };
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/session')) return Promise.resolve(response({ json: { sessionId: customerSession } }));
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(frame('done', {
        sessionId: customerSession, requestId: body.requestId,
        stopReason: 'end_turn', modeCapability: customerMode,
      })) }));
    }
    if (url.includes('/operations/')) return Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Owned orders', stopReason: 'end_turn', modeCapability: customerMode,
      replayed: true, hops: [], cards: [card], operations: [],
      orderPage: { nextCursor: choiceId, productName: 'Practice laptop' },
    } }));
    throw Error(`Unexpected ${url}`);
  });
  const first = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Orders containing Practice laptop')).toBe(true); });
  const firstRequestId = bodies[0].requestId;
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toBeNull();
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY)).toContain(firstRequestId);
  first.unmount();

  fetch.mockClear();
  const second = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await flush();
  expect(fetch.mock.calls.map(([url]) => url)).toEqual([
    `/api/secureshop/agents/customer/operations/${customerSession}/${firstRequestId}`,
  ]);
  expect(current.pending).toBeNull();
  expect(current.completedPagePending).toBe(false);
  expect(current.turns[0]).toMatchObject({ requestId: firstRequestId, status: 'done',
    cards: [card], orderPage: { nextCursor: choiceId, productName: 'Practice laptop' } });
  await act(async () => { expect(await current.send('Show older orders')).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: customerSession,
    requestId: expect.any(String), message: 'Show older orders' });
  expect(current.turns).toHaveLength(2);
  expect(current.turns.map(turn => turn.requestId)).toEqual([firstRequestId, bodies[1].requestId]);
  expect(current.turns[0].orderPage.productName).toBe('Practice laptop');
  expect(current.turns[1].status).toBe('done');
  second.unmount();
});

test('unresolved pending chat takes precedence over the last completed read-only pointer', async () => {
  const pendingId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const completedId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const row = requestId => ({ shopUserId: 5, sessionId: customerSession, requestId, startedAt: 1 });
  const raw = requestId => JSON.stringify({ version: 1, references: [row(requestId)] });
  localStorage.setItem(SHOP_CUSTOMER_CHAT_KEY, raw(pendingId));
  localStorage.setItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY, raw(completedId));
  fetch.mockImplementation(url => Promise.resolve(response({ json: {
    sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
    text: 'Newer saved turn', stopReason: 'end_turn', modeCapability: customerMode,
    replayed: true, hops: [], cards: [], operations: [], orderPage: null,
  } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await flush();
  expect(fetch.mock.calls.map(([url]) => url)).toEqual([
    `/api/secureshop/agents/customer/operations/${customerSession}/${pendingId}`,
  ]);
  expect(current.turns[0].requestId).toBe(pendingId);
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY)).toContain(pendingId);
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toBeNull();
  view.unmount();
});

test('stale completed page 401 is discarded and cannot block a fresh chat', async () => {
  const oldId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  localStorage.setItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY, JSON.stringify({ version: 1,
    references: [{ shopUserId: 5, sessionId: customerSession, requestId: oldId, startedAt: 1 }] }));
  fetch.mockImplementation((url, options) => {
    if (url.includes(`/operations/${customerSession}/${oldId}`)) {
      return Promise.resolve(response({ ok: false, status: 401 }));
    }
    if (url.endsWith('/session')) return Promise.resolve(response({ json: { sessionId: customerSession } }));
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession,
          requestId: body.requestId, stopReason: 'end_turn', modeCapability: customerMode })}\n\n`,
      ) }));
    }
    if (url.includes('/operations/')) return Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Fresh chat', stopReason: 'end_turn', modeCapability: customerMode,
      replayed: true, hops: [], cards: [], operations: [], orderPage: null,
    } }));
    throw Error(`Unexpected ${url}`);
  });
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await flush();
  expect(current.completedPagePending).toBe(false);
  expect(current.status).toBe('idle');
  expect(current.turns).toEqual([]);
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY)).toBeNull();
  await act(async () => { expect(await current.send('Show my orders')).toBe(true); });
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/chat'))).toHaveLength(1);
  view.unmount();
});

test('product detail and cart actions bind distinct validated intents to new acknowledged turns', async () => {
  const bodies = [];
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/session')) return Promise.resolve(response({ json: { sessionId: customerSession } }));
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body);
      bodies.push(body);
      expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toContain(body.requestId);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('done', { sessionId: customerSession, requestId: body.requestId,
          stopReason: 'end_turn', modeCapability: customerMode }),
      ) }));
    }
    if (url.includes('/operations/')) return Promise.resolve(savedCustomer(url, 'Saved answer',
      bodies.length < 3 ? [customerChoice] : []));
    throw Error(`Unexpected ${url}`);
  });
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Find a laptop')).toBe(true); });
  await act(async () => { expect(await current.send('Add it to my cart',
    { choiceId: customerChoice.choiceId, intent: 'cart_add', quantity: 0 })).toBe(false); });
  await act(async () => { expect(await current.send('Update this cart item to 2.',
    { choiceId: customerChoice.choiceId, intent: 'cart_update', quantity: 2 })).toBe(false); });
  await act(async () => { expect(await current.send('Show this order’s details.',
    { choiceId: customerChoice.choiceId, intent: 'order_details' })).toBe(false); });
  expect(bodies).toHaveLength(1);
  await act(async () => { expect(await current.send('Show this product’s details.',
    { choiceId: customerChoice.choiceId, intent: 'details' })).toBe(true); });
  expect(bodies[1].selection).toEqual({ choiceId: customerChoice.choiceId, intent: 'details' });
  expect(current.turns[1].user).toBe('View details: Practice laptop');
  await act(async () => { expect(await current.send('Add 2 of this product to my cart.',
    { choiceId: customerChoice.choiceId, intent: 'cart_add', quantity: 2 })).toBe(true); });
  expect(bodies[2].selection).toEqual({ choiceId: customerChoice.choiceId,
    intent: 'cart_add', quantity: 2 });
  expect(current.turns[2].user).toBe('Add 2 to cart: Practice laptop');
  expect(new Set(bodies.map(body => body.requestId)).size).toBe(3);
  expect(current.pending).toBeNull();
  view.unmount();
});

test('order details uses only the current saved order choice and rejects product intent', async () => {
  const orderChoice = { ...customerChoice, kind: 'order', title: 'Order #41' };
  const bodies = [];
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/session')) return Promise.resolve(response({ json: { sessionId: customerSession } }));
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body);
      bodies.push(body);
      expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toContain(body.requestId);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('done', { sessionId: customerSession, requestId: body.requestId,
          stopReason: 'end_turn', modeCapability: customerMode }),
      ) }));
    }
    if (url.includes('/operations/')) return Promise.resolve(savedCustomer(url, 'Owned order', [orderChoice]));
    throw Error(`Unexpected ${url}`);
  });
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Show my orders')).toBe(true); });
  await act(async () => { expect(await current.send('Show this order’s details.',
    { choiceId: orderChoice.choiceId, intent: 'order_details' })).toBe(true); });
  expect(bodies[1].message).toBe('Show this order’s details.');
  expect(bodies[1].selection).toEqual({ choiceId: orderChoice.choiceId, intent: 'order_details' });
  expect(current.turns[1].user).toBe('View details: Order #41');
  await act(async () => { expect(await current.send('Show this product’s details.',
    { choiceId: orderChoice.choiceId, intent: 'details' })).toBe(false); });
  expect(bodies).toHaveLength(2);
  expect(current.error).toBe('Invalid customer choice');
  view.unmount();
});

test('address checkout and edit use distinct exact intents on a current saved address card', async () => {
  const addressChoice = { ...customerChoice, kind: 'address', title: 'Home', detail: '1 Main St' };
  const bodies = [];
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/session')) return Promise.resolve(response({ json: { sessionId: customerSession } }));
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body);
      const compiled = compileOperation('agent.customer.chat', { body });
      expect(compiled.body).toEqual(body);
      expect(matchOperationRequest({ pathname: new URL(url, 'http://shop.test').pathname,
        method: 'POST', body }).name).toBe('agent.customer.chat');
      bodies.push(body);
      expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toContain(body.requestId);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('done', { sessionId: customerSession, requestId: body.requestId,
          stopReason: 'end_turn', modeCapability: customerMode }),
      ) }));
    }
    if (url.includes('/operations/')) return Promise.resolve(savedCustomer(url, 'Saved address', [addressChoice]));
    throw Error(`Unexpected ${url}`);
  });
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Show my addresses')).toBe(true); });
  await act(async () => { expect(await current.send('Use this address for checkout.',
    { choiceId: addressChoice.choiceId, intent: 'address_checkout' })).toBe(true); });
  expect(bodies[1].selection).toEqual({ choiceId: addressChoice.choiceId, intent: 'address_checkout' });
  expect(bodies[1].message).toBe('Use this address for checkout.');
  expect(current.turns[1].user).toBe('Use for checkout: Home');
  await act(async () => { expect(await current.send('Prepare to edit this address.',
    { choiceId: addressChoice.choiceId, intent: 'address_edit' })).toBe(true); });
  expect(bodies[2].selection).toEqual({ choiceId: addressChoice.choiceId, intent: 'address_edit' });
  expect(bodies[2].message).toBe('Prepare to edit this address.');
  expect(current.turns[2].user).toBe('Edit address: Home');
  await act(async () => { expect(await current.send('Show this product’s details.',
    { choiceId: addressChoice.choiceId, intent: 'details' })).toBe(false); });
  expect(bodies).toHaveLength(3);
  expect(current.error).toBe('Invalid customer choice');
  expect(new Set(bodies.map(body => body.requestId)).size).toBe(3);
  view.unmount();
});

test('cart-item intents require a current trusted cart card and send exact bounded actions', async () => {
  const cartChoice = { ...customerChoice, kind: 'cart_item', title: 'Practice laptop in cart' };
  const bodies = [];
  const frame = (name, payload) => `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/session')) return Promise.resolve(response({ json: { sessionId: customerSession } }));
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body);
      bodies.push(body);
      expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toContain(body.requestId);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('done', { sessionId: customerSession, requestId: body.requestId,
          stopReason: 'end_turn', modeCapability: customerMode }),
      ) }));
    }
    if (url.includes('/operations/')) return Promise.resolve(savedCustomer(url, 'Your cart',
      bodies.length < 3 ? [cartChoice] : []));
    throw Error(`Unexpected ${url}`);
  });
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Show my cart')).toBe(true); });
  await act(async () => { expect(await current.send('Update this cart item to 0.',
    { choiceId: cartChoice.choiceId, intent: 'cart_update', quantity: 0 })).toBe(false); });
  await act(async () => { expect(await current.send('Show this product’s details.',
    { choiceId: cartChoice.choiceId, intent: 'details' })).toBe(false); });
  expect(bodies).toHaveLength(1);
  await act(async () => { expect(await current.send('Update this cart item to 2.',
    { choiceId: cartChoice.choiceId, intent: 'cart_update', quantity: 2 })).toBe(true); });
  expect(bodies[1].selection).toEqual({ choiceId: cartChoice.choiceId,
    intent: 'cart_update', quantity: 2 });
  expect(current.turns[1].user).toBe('Update quantity to 2: Practice laptop in cart');
  await act(async () => { expect(await current.send('Remove this item from my cart.',
    { choiceId: cartChoice.choiceId, intent: 'cart_remove' })).toBe(true); });
  expect(bodies[2].selection).toEqual({ choiceId: cartChoice.choiceId, intent: 'cart_remove' });
  expect(current.turns[2].user).toBe('Remove from cart: Practice laptop in cart');
  expect(new Set(bodies.map(body => body.requestId)).size).toBe(3);
  expect(current.pending).toBeNull();
  view.unmount();
});

test('invalid customer choice is rejected before session creation', async () => {
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Use my selected option.', { choiceId: '7' })).resolves.toBe(false); });
  expect(fetch).not.toHaveBeenCalled();
  expect(current.error).toBe('Invalid customer choice');
  view.unmount();
});

test('a customer choice without a completed saved card cannot start a chat', async () => {
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => {
    await expect(current.send('Use my selected option.', { choiceId: customerChoice.choiceId })).resolves.toBe(false);
  });
  expect(fetch).not.toHaveBeenCalled();
  expect(current.error).toBe('Invalid customer choice');
  view.unmount();
});

test('trusted SSE completion requires exact GET before clearing and projects only a saved proposal', async () => {
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Review this quote', stopReason: 'end_turn', modeCapability: customerMode,
      replayed: true, hops: [], operations: [{ operationId: customerProposal.proposalId,
        status: 'prepared', proposal: customerProposal }],
    } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Prepare checkout')).resolves.toBe(true); });
  expect(current.turns[0].operations[0].proposal).toEqual(customerProposal);
  expect(fetch.mock.calls[2][0]).toBe(`/api/secureshop/agents/customer/operations/${customerSession}/${requestId}`);
  expect(current.pending).toBeNull();
  view.unmount();
});

test('practice payment setup is actionable metadata only after a completed exact saved chat read', async () => {
  const setup = { version: 1, kind: 'practice_payment_setup', suggestedScenario: 'declined' };
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode, paymentSetup: setup })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Choose a synthetic practice outcome', stopReason: 'end_turn',
      modeCapability: customerMode, replayed: true, hops: [], cards: [], operations: [], paymentSetup: setup,
    } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Add a practice payment')).resolves.toBe(true); });
  expect(current.turns[0].paymentSetup).toEqual(setup);
  expect(fetch.mock.calls[2][0]).toBe(`/api/secureshop/agents/customer/operations/${customerSession}/${requestId}`);
  view.unmount();
});

test('address setup comes only from exact completed chat GET, never an SSE hint', async () => {
  const setup = { version: 1, kind: 'address_setup', action: 'create', choiceId: null,
    draft: { label: 'Home', line1: '1 Main St' } };
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode, addressSetup: setup })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Review an address', stopReason: 'end_turn', modeCapability: customerMode,
      replayed: true, hops: [], cards: [], operations: [], addressSetup: null,
    } })));
  const first = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Show addresses')).resolves.toBe(true); });
  expect(current.turns[0].addressSetup).toBeNull();
  first.unmount();
  localStorage.removeItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY);

  fetch.mockReset().mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Review this address', stopReason: 'end_turn', modeCapability: customerMode,
      replayed: true, hops: [], cards: [], operations: [], addressSetup: setup,
    } })));
  const second = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Add my address')).resolves.toBe(true); });
  expect(current.turns[0].addressSetup).toEqual(setup);
  second.unmount();
});

test('refund review handoff is projected only from a clean exact completed customer turn', async () => {
  const setup = { version: 1, kind: 'refund_setup',
    choiceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', orderId: 42 };
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode, refundSetup: setup })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Review your order', stopReason: 'end_turn', modeCapability: customerMode,
      replayed: true, hops: [], cards: [], operations: [], refundSetup: null,
    } })));
  const first = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Request a refund')).resolves.toBe(true); });
  expect(current.turns[0].refundSetup).toBeNull();
  first.unmount();
  localStorage.removeItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY);

  fetch.mockReset().mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Review this order', stopReason: 'end_turn', modeCapability: customerMode,
      replayed: true, hops: [], cards: [], operations: [], refundSetup: setup,
    } })));
  const second = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Choose my order')).resolves.toBe(true); });
  expect(current.turns[0].refundSetup).toEqual(setup);
  second.unmount();
});

test('SSE-only or malformed payment setup cannot become a completed customer handoff', async () => {
  const setup = { version: 1, kind: 'practice_payment_setup', suggestedScenario: 'approved' };
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode, paymentSetup: setup })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'No setup', stopReason: 'end_turn', modeCapability: customerMode,
      replayed: true, hops: [], cards: [], operations: [], paymentSetup: null,
    } })));
  const first = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Read methods')).resolves.toBe(true); });
  expect(current.turns[0].paymentSetup).toBeNull();
  first.unmount();
  localStorage.removeItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY);

  fetch.mockReset().mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Invalid setup', stopReason: 'end_turn', modeCapability: customerMode,
      replayed: true, hops: [], cards: [], operations: [],
      paymentSetup: { ...setup, untrusted: true },
    } })));
  const second = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Add method')).resolves.toBe(false); });
  expect(current.status).toBe('unresolved');
  expect(current.pending.requestId).toBe(requestId);
  expect(current.turns[0].paymentSetup).toBeUndefined();
  second.unmount();
});

test('unconfirmed exact GET exposes saved-action guidance but retains UUID and blocks another POST', async () => {
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'unconfirmed',
      operations: [{ operationId: customerProposal.proposalId, status: 'prepared', proposal: customerProposal }],
    } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Prepare checkout')).resolves.toBe(false); });
  expect(current.status).toBe('unresolved');
  expect(current.turns[0].status).toBe('unresolved');
  expect(current.turns[0].operations[0].proposal).toEqual(customerProposal);
  expect(current.pending.requestId).toBe(requestId);
  await act(async () => { await expect(current.send('Try again')).resolves.toBe(false); });
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(2);
  view.unmount();
});

test('terminal SSE followed by unavailable exact GET retains the parent-saved request', async () => {
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode })}\n\n`,
      ) }));
    })
    .mockResolvedValueOnce(response({ ok: false, status: 503 }))
    .mockImplementationOnce(url => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId: url.split('/').at(-1), status: 'unconfirmed',
    } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Prepare checkout')).resolves.toBe(false); });
  expect(current.pending.requestId).toBe(requestId);
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toContain(requestId);
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(2);
  view.unmount();
});

test('lost customer response recovers the exact saved turn after remount without another POST', async () => {
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockRejectedValueOnce(new Error('Connection lost'))
    .mockImplementationOnce(url => Promise.resolve(response({ json: { sessionId: customerSession,
      requestId: url.split('/').at(-1), status: 'unconfirmed' } })));
  const first = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Find a laptop')).resolves.toBe(false); });
  const saved = current.pending;
  expect(saved).toMatchObject({ shopUserId: 5, sessionId: customerSession });
  expect(current.status).toBe('unresolved');
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).not.toBeNull();
  first.unmount();

  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession, requestId: saved.requestId,
    status: 'completed', text: 'Two laptops match', stopReason: 'end_turn', replayed: true,
    modeCapability: customerMode, hops: [{ step: 1, tool: 'catalog.search', params: { query: 'laptop' },
      result: { content: [{ type: 'text', text: 'Two products' }] }, latencyMs: 3 }] } }));
  const second = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await flush();
  expect(fetch).toHaveBeenCalledTimes(4);
  expect(fetch.mock.calls[3][0]).toBe(`/api/secureshop/agents/customer/operations/${customerSession}/${saved.requestId}`);
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(2);
  expect(current.pending).toBeNull();
  expect(current.turns[0]).toMatchObject({ reply: 'Two laptops match', status: 'done',
    hops: [{ tool: 'catalog.search', status: 'ok', modeCapability: customerMode }] });
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).toBeNull();
  second.unmount();
});

test('lost order-list reply restores only its exact saved older-page cursor after remount', async () => {
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const card = { version: 1, kind: 'order', choiceId, title: 'Owned order', detail: 'Delivered' };
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockRejectedValueOnce(Error('Connection lost'))
    .mockImplementationOnce(url => Promise.resolve(response({ json: { sessionId: customerSession,
      requestId: url.split('/').at(-1), status: 'unconfirmed' } })));
  const first = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Show my orders')).toBe(false); });
  const saved = current.pending;
  first.unmount();
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession,
    requestId: saved.requestId, status: 'completed', text: 'Owned orders',
    stopReason: 'end_turn', replayed: true, modeCapability: customerMode,
    hops: [], cards: [card], operations: [], orderPage: { nextCursor: choiceId } } }));
  const second = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await flush();
  expect(current.turns[0]).toMatchObject({ status: 'done', cards: [card],
    orderPage: { nextCursor: choiceId } });
  expect(current.pending).toBeNull();
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(2);
  second.unmount();
});

test('unconfirmed exact recovery retains the reference and blocks automatic chat replay', async () => {
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockRejectedValueOnce(new Error('Connection lost'))
    .mockImplementationOnce(url => Promise.resolve(response({ json: { sessionId: customerSession,
      requestId: url.split('/').at(-1), status: 'unconfirmed' } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await current.send('Find shoes'); });
  const saved = current.pending;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession,
    requestId: saved.requestId, status: 'unconfirmed' } }));
  await act(async () => { await expect(current.recover()).resolves.toBe(false); });
  expect(current.status).toBe('unresolved');
  expect(current.pending.requestId).toBe(saved.requestId);
  await act(async () => { await expect(current.send('Find shoes')).resolves.toBe(false); });
  expect(fetch).toHaveBeenCalledTimes(4);
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).not.toBeNull();
  view.unmount();
});

test('foreign saved chat denial stays unresolved and never starts a new conversation', async () => {
  const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  localStorage.setItem(SHOP_CUSTOMER_CHAT_KEY, JSON.stringify({ version: 1, references: [{
    shopUserId: 5, sessionId: customerSession, requestId, startedAt: Date.now(),
  }] }));
  fetch.mockResolvedValueOnce(response({ ok: false, status: 403 }));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await flush();
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(fetch.mock.calls[0][0]).toContain(`/operations/${customerSession}/${requestId}`);
  expect(current.pending.requestId).toBe(requestId);
  expect(current.status).toBe('unresolved');
  await act(async () => { await expect(current.send('Show my cart')).resolves.toBe(false); });
  expect(fetch).toHaveBeenCalledTimes(1);
  view.unmount();
});

test('customer terminal event without exact IDs cannot clear the saved request', async () => {
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockResolvedValueOnce(response({ type: 'text/event-stream', reader: stream(
      `event: done\ndata: ${JSON.stringify({ stopReason: 'end_turn', modeCapability: customerMode })}\n\n`,
    ) }))
    .mockImplementationOnce(url => Promise.resolve(response({ json: { sessionId: customerSession,
      requestId: url.split('/').at(-1), status: 'unconfirmed' } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Show my cart')).resolves.toBe(false); });
  expect(current.pending.requestId).toMatch(/^[0-9a-f-]{36}$/);
  expect(current.status).toBe('unresolved');
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_KEY)).not.toBeNull();
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(2);
  view.unmount();
});

test('opaque frame waits for parent chat-reference ACK before the only chat POST', async () => {
  releaseStorage();
  const values = new Map();
  const acknowledgement = deferred();
  let flushes = 0;
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => ++flushes === 1 ? acknowledgement.promise : Promise.resolve() });
  const opaque = jest.spyOn(window, 'sessionStorage', 'get')
    .mockImplementation(() => { throw new DOMException('opaque', 'SecurityError'); });
  let sent;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      sent = JSON.parse(options.body);
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession,
          requestId: sent.requestId, stopReason: 'end_turn', modeCapability: customerMode })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(url => Promise.resolve(savedCustomer(url, 'Show my cart')));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true,
    authorityKey: 'persona-a' });
  let sentPromise;
  try {
    act(() => { sentPromise = current.send('Show my cart'); });
    await flush();
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(values.get(SHOP_CUSTOMER_CHAT_KEY)).toContain('requestId');
    expect(values.get(SHOP_CUSTOMER_CHAT_KEY)).not.toContain('Show my cart');
    acknowledgement.resolve();
    await act(async () => { await expect(sentPromise).resolves.toBe(true); });
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(sent.requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(values.has(SHOP_CUSTOMER_CHAT_KEY)).toBe(false);
  } finally { opaque.mockRestore(); view.unmount(); }
});

test('refused parent ACK prevents chat POST and keeps an unresolved reference', async () => {
  releaseStorage();
  const values = new Map();
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { throw new Error('Parent refused persistence'); } });
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Show my cart')).resolves.toBe(false); });
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  expect(current.status).toBe('unresolved');
  expect(current.pending.requestId).toMatch(/^[0-9a-f-]{36}$/);
  expect(values.get(SHOP_CUSTOMER_CHAT_KEY)).not.toBeUndefined();
  view.unmount();
});

test('persona renewal while persistence is pending fences the old chat POST', async () => {
  releaseStorage();
  const values = new Map();
  const acknowledgement = deferred();
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => acknowledgement.promise });
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce(url => Promise.resolve(response({ json: { sessionId: customerSession,
      requestId: url.split('/').at(-1), status: 'unconfirmed' } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true,
    authorityKey: 'persona-a' });
  let sent;
  act(() => { sent = current.send('Show my cart'); });
  await flush();
  view.rerender({ role: 'customer', defaultUserId: 5, boundCustomerChat: true,
    authorityKey: 'persona-b' });
  acknowledgement.resolve();
  await act(async () => { await expect(sent).resolves.toBe(false); });
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  view.unmount();
});

test('same-user refund token rotation clears an in-flight turn and never dispatches its old chat', async () => {
  const oldSession = deferred();
  let sessions = 0;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/customer/refund/session')) {
      sessions += 1;
      return sessions === 1 ? oldSession.promise
        : Promise.resolve(response({ json: { sessionId: 'new-refund-session' } }));
    }
    if (url.endsWith('/customer/refund/chat')) return Promise.resolve(response({
      type: 'text/event-stream', reader: stream('event: done\ndata: {"stopReason":"end_turn"}\n\n'),
    }));
    throw Error(`Unexpected ${url}`);
  });
  const view = renderHook({ role: 'customer/refund', defaultUserId: 5, authorityKey: 'token-a' });
  let oldSend;
  act(() => { oldSend = current.send('refund order 42'); });
  await flush();
  expect(current.turns).toHaveLength(1);
  view.rerender({ role: 'customer/refund', defaultUserId: 5, authorityKey: 'token-b' });
  expect(current.turns).toEqual([]);
  expect(current.sessionId).toBeNull();
  oldSession.resolve(response({ json: { sessionId: 'old-refund-session' } }));
  await act(async () => { await expect(oldSend).resolves.toBe(false); });
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/customer/refund/chat'))).toHaveLength(0);
  await act(async () => { await expect(current.send('refund order 43')).resolves.toBe(true); });
  expect(current.sessionId).toBe('new-refund-session');
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/customer/refund/chat'))).toHaveLength(1);
  view.unmount();
});

test('profile proposal is hydrated only from exact completed saved GET with matching digest', async () => {
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { subtle: webcrypto.subtle, randomUUID: () => 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' } });
  const before = { fullName: 'Old', email: 'old@example.test', phone: null };
  const after = { ...before, fullName: 'New' };
  const proposalId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  const proposal = { version: 1, proposalId, scopeKey: 'a'.repeat(64),
    expectedSnapshotSha256: 'b'.repeat(64), before, after, patch: { fullName: 'New' },
    requestSha256: await profileRequestDigest(proposalId, 'b'.repeat(64), after) };
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode, profileProposal: proposal })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(() => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId, status: 'completed', text: 'Review your profile',
      stopReason: 'end_turn', modeCapability: customerMode, replayed: true,
      hops: [], cards: [], operations: [], profileProposal: proposal,
    } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Update my name')).toBe(true); });
  expect(current.turns[0].profileProposal).toEqual(proposal);
  expect(current.turns[0].sessionId).toBe(customerSession);
  expect(current.turns[0].requestId).toBe(requestId);
  view.unmount();
});

test('coupon proposal is projected only from the protected completed customer turn', async () => {
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { randomUUID: () => 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' } });
  const proposal = { version: 1, kind: 'cart.coupon_prepare', status: 'confirmation_required',
    proposalId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', code: 'SAVE10', codeSha256: 'a'.repeat(64) };
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode, couponProposal: {
            ...proposal, code: 'UNTRUSTED-SSE',
          } })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(() => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId, status: 'completed', text: 'Review coupon',
      stopReason: 'end_turn', modeCapability: customerMode, replayed: true,
      hops: [], cards: [], operations: [], couponProposal: proposal,
    } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send('Prepare coupon SAVE10')).toBe(true); });
  expect(current.turns[0].couponProposal).toEqual(proposal);
  expect(current.turns[0].couponProposal.code).not.toBe('UNTRUSTED-SSE');
  view.unmount();
});

test('ticket proposal appears only from the protected completed customer turn, not SSE text', async () => {
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { randomUUID: () => 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' } });
  const proposal = { version: 1, kind: 'support.ticket_prepare', status: 'confirmation_required',
    proposalId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', subject: 'Delivery issue',
    body: '<b>Literal body</b>', subjectSha256: 'a'.repeat(64), bodySha256: 'b'.repeat(64) };
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: customerMode,
          ticketProposal: { ...proposal, body: 'UNTRUSTED-SSE' } })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(() => Promise.resolve(response({ json: {
      sessionId: customerSession, requestId, status: 'completed', text: 'Review ticket',
      stopReason: 'end_turn', modeCapability: customerMode, replayed: true,
      hops: [], cards: [], operations: [], ticketProposal: proposal,
    } })));
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { expect(await current.send(JSON.stringify({ subject: proposal.subject,
    body: proposal.body }))).toBe(true); });
  expect(current.turns[0].ticketProposal).toEqual(proposal);
  expect(current.turns[0].ticketProposal.body).not.toBe('UNTRUSTED-SSE');
  view.unmount();
});

const agencyProjection = { version: 1, teachingRole: 'admin', changed: true };
const agencyFinal = { completed: true, judgment: { evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  verdict: 'pass', canRetry: false }, replayed: true };
const agencyMode = { ...customerMode, effectiveMode: 'vuln' };
function mockAgencyTurn(assessment) {
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      const frame = (name, data) => `event: ${name}\ndata: ${JSON.stringify({
        sessionId: customerSession, requestId, modeCapability: agencyMode, ...data })}\n\n`;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        frame('tool_call', { id: 'role', tool: 'user-management.set_role', step: 1, params: { user_id: 5, role: 'admin' } }),
        frame('tool_result', { id: 'role', result: { content: [{ type: 'text', text: 'PRIVATE_ROLE_RECEIPT' }] } }),
        frame('done', { stopReason: 'end_turn', completed: true, judgment: agencyFinal.judgment }),
      ) }));
    })
    .mockImplementationOnce(() => Promise.resolve(response({ json: agencySaved(requestId) })))
    .mockResolvedValueOnce(response({ json: assessment }));
  return () => requestId;
}
function agencySaved(requestId) {
  return { sessionId: customerSession, requestId, status: 'completed', replayed: true,
    modeCapability: agencyMode, text: 'Teaching role action returned.', stopReason: 'end_turn',
    hops: [{ step: 1, tool: 'user-management.set_role', result: { content: [{ type: 'text', text: 'PRIVATE_ROLE_RECEIPT' }] } }],
    cards: [], operations: [], agencyRole: agencyProjection };
}

test('role assessment uses exact saved GET on live completion, check and reload without actor redispatch or receipt storage', async () => {
  const requestId = mockAgencyTurn({ completed: false, status: 'pending', modelEvaluated: false });
  const first = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await expect(current.send('Change my teaching role')).resolves.toBe(true); });
  const path = `/api/secureshop/agents/customer/sessions/${customerSession}/requests/${requestId()}/agency-role/assessment`;
  expect(fetch.mock.calls[3]).toEqual([path, expect.objectContaining({ method: 'GET' })]);
  expect(current.turns[0].agencyAssessment).toEqual({ completed: false, status: 'pending', modelEvaluated: false });
  expect(JSON.stringify(current.turns)).not.toContain('PRIVATE_ROLE_RECEIPT');
  expect(localStorage.getItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY)).not.toMatch(/PRIVATE_ROLE_RECEIPT|teachingRole|judgment/);
  fetch.mockResolvedValueOnce(response({ json: agencyFinal }));
  await act(async () => { await expect(current.refreshAgencyAssessment(customerSession, requestId())).resolves.toBe(true); });
  expect(current.turns[0].agencyAssessment).toEqual(agencyFinal);
  first.unmount();
  fetch.mockResolvedValueOnce(response({ json: agencySaved(requestId()) }))
    .mockResolvedValueOnce(response({ json: agencyFinal }));
  const second = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await flush();
  expect(current.turns[0].agencyAssessment).toEqual(agencyFinal);
  expect(fetch.mock.calls.filter(([, options]) => options.method === 'POST')).toHaveLength(2);
  expect(fetch.mock.calls.slice(3).every(([, options]) => options.method === 'GET')).toBe(true);
  second.unmount();
});

for (const malformed of [
  { ...agencyFinal, judgment: { ...agencyFinal.judgment, verdict: 'fail' } },
  { ...agencyFinal, judgment: { ...agencyFinal.judgment, evaluationId: 'invented' } },
  { ...agencyFinal, receipt: { private: true } },
  { completed: true, status: 'pending', modelEvaluated: false },
]) test('invalid role assessment cannot establish optimistic completion: ' + JSON.stringify(malformed), async () => {
  mockAgencyTurn(malformed);
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await current.send('Change my teaching role'); });
  expect(current.turns[0].agencyAssessment).toEqual({ completed: false, status: 'unavailable', modelEvaluated: false });
  expect(current.turns[0].reply).toBe('Teaching role action returned.');
  view.unmount();
});

test('role assessment HTTP failure replaces prior credit and late authority response is discarded', async () => {
  const requestId = mockAgencyTurn(agencyFinal);
  const props = { role: 'customer', defaultUserId: 5, boundCustomerChat: true, authorityKey: 'first' };
  const view = renderHook(props);
  await act(async () => { await current.send('Change my teaching role'); });
  fetch.mockResolvedValueOnce(response({ ok: false, status: 401 }));
  await act(async () => { await current.refreshAgencyAssessment(customerSession, requestId()); });
  expect(current.turns[0].agencyAssessment.completed).toBe(false);
  expect(current.turns[0].agencyAssessment.status).toBe('unavailable');
  const pending = deferred();fetch.mockReturnValueOnce(pending.promise);
  let checking;act(() => { checking = current.refreshAgencyAssessment(customerSession, requestId()); });
  localStorage.clear();view.rerender({ ...props, authorityKey: 'new' });
  pending.resolve(response({ json: agencyFinal }));
  await act(async () => { await checking; });
  expect(current.turns).toEqual([]);
  view.unmount();
});

test('agency assessment bridge accepts only exact typed GET references through the existing fetch adapter', async () => {
  const { createBridgeFetch } = await import('../bridge/fetchAdapter.mjs');
  const { compileBridgeOperation } = await import('../bridge/compiler.mjs');
  const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const name = 'agent.customer.agencyRoleAssessment';
  const path = `/api/secureshop/agents/customer/sessions/${customerSession}/requests/${requestId}/agency-role/assessment`;
  expect(compileBridgeOperation(name, { params: { sessionId: customerSession, requestId } })).toMatchObject({ method: 'GET', path });
  expect(matchOperationRequest({ pathname: path, method: 'GET' }).name).toBe(name);
  for (const params of [{ sessionId: 'x', requestId }, { sessionId: customerSession, requestId: requestId.toUpperCase() },
    { sessionId: customerSession, requestId, ownerId: 1 }]) {
    expect(() => compileOperation(name, { params })).toThrow();
  }
  for (const request of [{ method: 'POST' }, { method: 'GET', body: { packet: '{}' } },
    { method: 'GET', query: { mode: 'vuln' } }]) {
    expect(() => matchOperationRequest({ pathname: path, ...request })).toThrow();
  }
  Object.assign(global, require('node:stream/web'));
  global.MessagePort = require('node:worker_threads').MessagePort;
  const web = require('undici'), previousRequest = global.Request, previousHeaders = global.Headers;
  global.Request = web.Request;global.Headers = web.Headers;
  try {
    const bridge = { request: jest.fn(async () => response({ json: agencyFinal })) };
    const bridgedFetch = createBridgeFetch({ bridge, origin: 'https://shop.invalid', getRequestBaseUrl: () => 'https://shop.invalid', getToken: () => 'owned-token' });
    await bridgedFetch(path, { method: 'GET', headers: { accept: 'application/json' } });
    expect(bridge.request).toHaveBeenCalledWith(name, expect.objectContaining({ params: { sessionId: customerSession, requestId } }), expect.objectContaining({ shopBearer: 'owned-token' }));
    await expect(bridgedFetch(path, { method: 'POST' })).rejects.toThrow();
    await expect(bridgedFetch(path + '?mode=vuln')).rejects.toThrow();
    expect(bridge.request).toHaveBeenCalledTimes(1);
  } finally { global.Request = previousRequest;global.Headers = previousHeaders; }
});

test('role tool observation and model completion claim without saved effect projection never request or display credit', async () => {
  let requestId;
  fetch.mockResolvedValueOnce(response({ json: { sessionId: customerSession } }))
    .mockImplementationOnce((_url, options) => {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(response({ type: 'text/event-stream', reader: stream(
        `event: done\ndata: ${JSON.stringify({ sessionId: customerSession, requestId,
          stopReason: 'end_turn', modeCapability: agencyMode, agencyRole: agencyProjection,
          agencyAssessment: agencyFinal })}\n\n`,
      ) }));
    })
    .mockImplementationOnce(() => {
      const { agencyRole, ...saved } = agencySaved(requestId);
      return Promise.resolve(response({ json: saved }));
    });
  const view = renderHook({ role: 'customer', defaultUserId: 5, boundCustomerChat: true });
  await act(async () => { await current.send('Change my teaching role'); });
  expect(current.turns[0].agencyRole).toBeNull();
  expect(current.turns[0].agencyAssessment).toBeNull();
  expect(fetch).toHaveBeenCalledTimes(3);
  expect(JSON.stringify(current.turns)).not.toContain('PRIVATE_ROLE_RECEIPT');
  view.unmount();
});
