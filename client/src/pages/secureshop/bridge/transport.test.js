import { createHostTransport } from './transport.mjs';
import { compileBridgeOperation } from './compiler.mjs';

Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Response = web.Response;
global.Headers = web.Headers;

function fakePort({ failChunk = false } = {}) {
  const listeners = new Set();
  const messages = [];
  return {
    messages,
    addEventListener(_type, listener) { listeners.add(listener); },
    removeEventListener(_type, listener) { listeners.delete(listener); },
    start() {},
    close() {},
    postMessage(message) {
      messages.push(message);
      if (failChunk && message.type === 'chunk') throw new Error('port closed');
      if (message.type === 'start' || message.type === 'chunk') {
        queueMicrotask(() => listeners.forEach(listener => listener({ data: { type: 'pull', id: message.id } })));
      }
      return true;
    },
    dispatch(message) { listeners.forEach(listener => listener({ data: message })); },
  };
}

function setup({ fetchImpl, timeoutMs = 1000, failChunk = false } = {}) {
  const port = fakePort({ failChunk });
  const transport = createHostTransport({ port, origin: 'https://shop.invalid', timeoutMs,
    compileOperation: () => ({ path: '/api/secureshop/products', method: 'GET', responseKind: 'json' }),
    fetchImpl: fetchImpl || jest.fn(), getLaunchBearer: () => 'a'.repeat(43) });
  return { port, transport };
}

function waitFor(predicate, timeout = 500) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const check = () => predicate() ? resolve() : Date.now() - started >= timeout
      ? reject(new Error('timed out waiting for transport')) : setTimeout(check, 0);
    check();
  });
}

test('successful JSON stream sends end and releases the reader without aborting fetch', async () => {
  let capturedSignal;
  let stream;
  const fetchImpl = jest.fn((_url, options) => {
    capturedSignal = options.signal;
    stream = new ReadableStream({
      start(controller) { controller.enqueue(new TextEncoder().encode('{"ok":true}')); controller.close(); },
    });
    return Promise.resolve(new Response(stream, { status: 200, headers: { 'content-type': 'application/json' } }));
  });
  const { port, transport } = setup({ fetchImpl });
  port.dispatch({ type: 'request', id: 1, operation: 'catalog.list', input: {}, shopBearer: undefined });
  await waitFor(() => port.messages.some(message => message.type === 'end'));
  expect(capturedSignal.aborted).toBe(false);
  expect(stream.locked).toBe(false);
  expect(new TextDecoder().decode(new Uint8Array(port.messages.find(message => message.type === 'chunk').chunk)))
    .toBe('{"ok":true}');
  expect(port.messages.filter(message => message.type === 'error')).toHaveLength(0);
  transport.close();
  expect(capturedSignal.aborted).toBe(false); // Completed requests are no longer pending at close.
});

test('bound customer session sends empty JSON body and content type through the host transport', async () => {
  const port = fakePort();
  const fetchImpl = jest.fn(() => Promise.resolve(new Response('{"sessionId":"ready"}', {
    status: 200, headers: { 'content-type': 'application/json' },
  })));
  const transport = createHostTransport({ port, origin: 'https://shop.invalid',
    compileOperation: compileBridgeOperation, fetchImpl,
    getLaunchBearer: () => 'a'.repeat(43) });
  port.dispatch({ type: 'request', id: 1, operation: 'agent.customer.session',
    input: { body: {} }, shopBearer: 'persona-token' });
  await waitFor(() => port.messages.some(message => ['end', 'error'].includes(message.type) && message.id === 1));
  expect(port.messages.filter(message => message.type === 'error')).toEqual([]);
  expect(fetchImpl).toHaveBeenCalledTimes(1);
  const [url, options] = fetchImpl.mock.calls[0];
  expect(url).toBe('https://shop.invalid/api/secureshop/agents/customer/session');
  expect(options.method).toBe('POST');
  expect(options.body).toBe('{}');
  expect(options.headers.get('Content-Type')).toBe('application/json');
  transport.close();
});

test('stale saved customer reference 401 stays readable without detaching the current launch', async () => {
  const port = fakePort();
  const onLaunchUnavailable = jest.fn();
  const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const fetchImpl = jest.fn(url => Promise.resolve(new Response(
    url.endsWith('/v2/auth/whoami') ? '{"ok":true,"user":{"id":5}}' : '{"error":"Shop session unavailable"}',
    { status: url.endsWith('/v2/auth/whoami') ? 200 : 401,
      headers: { 'content-type': 'application/json' } },
  )));
  const transport = createHostTransport({ port, origin: 'https://shop.invalid',
    compileOperation: compileBridgeOperation, fetchImpl,
    getLaunchBearer: () => 'a'.repeat(43), onLaunchUnavailable });
  port.dispatch({ type: 'request', id: 1, operation: 'agent.customer.operation',
    input: { params: { sessionId, requestId } }, shopBearer: 'fresh-persona-token' });
  await waitFor(() => port.messages.some(message => message.type === 'end' && message.id === 1));
  expect(port.messages.find(message => message.type === 'start' && message.id === 1).status).toBe(401);
  expect(onLaunchUnavailable).not.toHaveBeenCalled();
  port.dispatch({ type: 'request', id: 2, operation: 'auth.whoami',
    input: {}, shopBearer: 'fresh-persona-token' });
  await waitFor(() => port.messages.some(message => message.type === 'end' && message.id === 2));
  expect(port.messages.find(message => message.type === 'start' && message.id === 2).status).toBe(200);
  expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([
    `https://shop.invalid/api/secureshop/agents/customer/operations/${sessionId}/${requestId}`,
    'https://shop.invalid/api/secureshop/v2/auth/whoami',
  ]);
  expect(fetchImpl.mock.calls.every(([, options]) => options.method === 'GET')).toBe(true);
  transport.close();
});

test('response protocol failure still aborts and cancels the reader', async () => {
  let capturedSignal;
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array([1])); },
    cancel() { cancelled = true; },
  });
  const fetchImpl = jest.fn((_url, options) => {
    capturedSignal = options.signal;
    return Promise.resolve(new Response(body, { status: 200, headers: { 'content-type': 'application/json' } }));
  });
  const { port, transport } = setup({ fetchImpl, failChunk: true });
  port.dispatch({ type: 'request', id: 1, operation: 'catalog.list', input: {}, shopBearer: undefined });
  await waitFor(() => port.messages.some(message => message.type === 'error'));
  expect(capturedSignal.aborted).toBe(true);
  expect(cancelled).toBe(true);
  transport.close();
});

test('caller cancellation aborts an in-flight request', async () => {
  let capturedSignal;
  const fetchImpl = jest.fn((_url, options) => {
    capturedSignal = options.signal;
    return new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
    });
  });
  const { port, transport } = setup({ fetchImpl });
  port.dispatch({ type: 'request', id: 1, operation: 'catalog.list', input: {}, shopBearer: undefined });
  await waitFor(() => fetchImpl.mock.calls.length === 1);
  port.dispatch({ type: 'cancel', id: 1 });
  await waitFor(() => port.messages.some(message => message.type === 'error'));
  expect(capturedSignal.aborted).toBe(true);
  expect(port.messages.find(message => message.type === 'error').code).toBe('CANCELLED');
  transport.close();
});

test('timeout aborts an in-flight request and reports TIMEOUT', async () => {
  let capturedSignal;
  const fetchImpl = jest.fn((_url, options) => {
    capturedSignal = options.signal;
    return new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
    });
  });
  const { port, transport } = setup({ fetchImpl, timeoutMs: 10 });
  port.dispatch({ type: 'request', id: 1, operation: 'catalog.list', input: {}, shopBearer: undefined });
  await waitFor(() => port.messages.some(message => message.type === 'error'));
  expect(capturedSignal.aborted).toBe(true);
  expect(port.messages.find(message => message.type === 'error').code).toBe('TIMEOUT');
  transport.close();
});

test('persona-anonymous catalog reads use public GET without launch authority', async () => {
  const port = fakePort();
  const fetchImpl = jest.fn(() => Promise.resolve(new Response('{"products":[]}', {
    status: 200, headers: { 'content-type': 'application/json' },
  })));
  const transport = createHostTransport({
    port, origin: 'https://shop.invalid', compileOperation: compileBridgeOperation,
    fetchImpl, getLaunchBearer: () => 'a'.repeat(43), publicReadFallback: true,
  });
  port.dispatch({ type: 'request', id: 1, operation: 'catalog.list', input: { query: { search: 'desk' } } });
  await waitFor(() => port.messages.some(message => ['end', 'error'].includes(message.type) && message.id === 1));
  expect(port.messages.filter(message => message.type === 'error')).toEqual([]);
  expect(fetchImpl).toHaveBeenCalledTimes(1);
  const [url, options] = fetchImpl.mock.calls[0];
  expect(url).toBe('https://shop.invalid/api/secureshop/public/products?search=desk');
  expect(options.method).toBe('GET');
  expect(options.credentials).toBe('omit');
  expect(options.headers.has('Authorization')).toBe(false);
  expect(options.headers.has('X-OWASP-AI-GOAT-SecureShop-Launch')).toBe(false);
  transport.close();
});

test('a present shop bearer and auth operations never fall back to public reads', async () => {
  const port = fakePort();
  const fetchImpl = jest.fn(() => Promise.resolve(new Response('{}', {
    status: 200, headers: { 'content-type': 'application/json' },
  })));
  const transport = createHostTransport({
    port, origin: 'https://shop.invalid', compileOperation: compileBridgeOperation,
    fetchImpl, getLaunchBearer: () => 'a'.repeat(43), publicReadFallback: true,
  });
  port.dispatch({ type: 'request', id: 1, operation: 'catalog.list', input: {}, shopBearer: 'expired-shop-token' });
  await waitFor(() => port.messages.some(message => ['end', 'error'].includes(message.type) && message.id === 1));
  expect(port.messages.filter(message => message.type === 'error')).toEqual([]);
  port.dispatch({ type: 'request', id: 2, operation: 'auth.login', input: { body: { username: 'customer', password: 'secret' } } });
  await waitFor(() => port.messages.some(message => ['end', 'error'].includes(message.type) && message.id === 2));
  expect(port.messages.filter(message => message.type === 'error')).toEqual([]);
  expect(fetchImpl.mock.calls[0][0]).toBe('https://shop.invalid/api/secureshop/products');
  expect(fetchImpl.mock.calls[0][1].headers.get('Authorization')).toBe('Bearer expired-shop-token');
  expect(fetchImpl.mock.calls[0][1].headers.get('X-OWASP-AI-GOAT-SecureShop-Launch')).toBe('a'.repeat(43));
  expect(fetchImpl.mock.calls[1][0]).toBe('https://shop.invalid/api/secureshop/v2/auth/login');
  expect(fetchImpl.mock.calls[1][1].method).toBe('POST');
  expect(fetchImpl.mock.calls[1][1].headers.has('Authorization')).toBe(false);
  expect(fetchImpl.mock.calls[1][1].headers.get('X-OWASP-AI-GOAT-SecureShop-Launch')).toBe('a'.repeat(43));
  transport.close();
});
