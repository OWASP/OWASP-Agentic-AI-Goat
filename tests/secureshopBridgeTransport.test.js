'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { MessageChannel } = require('node:worker_threads');
const text = new TextEncoder();
const compileOperation = (name, input = {}) => {
  if (name === 'catalog.list') return { path: '/api/secureshop/products', method: 'GET', responseKind: 'json' };
  if (name === 'agent.chat') return { path: '/api/secureshop/agents/customer/chat', method: 'POST', responseKind: 'sse', body: input };
  throw new Error('unknown operation');
};
async function pair(t, options = {}) {
  const { createHostTransport, createFrameTransport } = await import('../client/src/pages/secureshop/bridge/transport.mjs');
  const { port1, port2 } = new MessageChannel();
  const host = createHostTransport({ port: port1, origin: 'https://app.invalid', compileOperation,
    getLaunchBearer: () => 'a'.repeat(43), ...options });
  const frame = createFrameTransport({ port: port2, timeoutMs: 2000 });
  t.after(() => { frame.close();host.close(); });
  return { host, frame, port1, port2 };
}
function fakePort(fails = () => false) {
  const listeners = new Set();
  return {
    messages: [],
    addEventListener(type, listener) { if (type === 'message') listeners.add(listener); },
    removeEventListener(type, listener) { if (type === 'message') listeners.delete(listener); },
    start() {}, close() {},
    postMessage(message) {
      if (fails(message)) throw new Error('synthetic post failure');
      this.messages.push(message);
    },
    emit(message) { for (const listener of [...listeners]) listener({ data: message }); },
  };
}

test('named request carries shop token and private launch separately; response strips sensitive headers', async t => {
  let request;
  const { frame } = await pair(t, { fetchImpl: async (url, options) => {
    request = new Request(url, options);
    return new Response('{"products":[]}', { headers: { 'content-type': 'application/json', 'set-cookie': 'private', 'x-private-token': 'secret' } });
  } });
  const response = await frame.request('catalog.list', {}, { shopBearer: 'learner-crafted-jwt' });
  assert.deepEqual(await response.json(), { products: [] });
  assert.equal(request.url, 'https://app.invalid/api/secureshop/products');
  assert.equal(request.headers.get('authorization'), 'Bearer learner-crafted-jwt');
  assert.equal(request.headers.get('x-dvaia-secureshop-launch'), 'a'.repeat(43));
  assert.equal(request.credentials, 'omit');assert.equal(request.redirect, 'error');
  assert.deepEqual([...response.headers.keys()], ['content-type']);
});

test('raw fragmented SSE is preserved exactly through the bridge', async t => {
  const chunks = ['event: tool_call\r\n', 'data: {"id":1}\r\n\r\nevent: done\n', 'data: {"stopReason":"completed"}\n\n'];
  const { frame } = await pair(t, { fetchImpl: async () => new Response(new ReadableStream({ start(c) { for (const chunk of chunks) c.enqueue(text.encode(chunk));c.close(); } }), { headers: { 'content-type': 'text/event-stream' } }) });
  const response = await frame.request('agent.chat', { message: 'synthetic' });
  assert.equal(await response.text(), chunks.join(''));
});

test('HTTP errors retain status/body; unavailable and unknown operations do not leak errors', async t => {
  let calls = 0;
  const { frame } = await pair(t, { fetchImpl: async () => { calls++;return new Response('{"error":"denied"}', { status: 403, headers: { 'content-type': 'application/json' } }); } });
  const response = await frame.request('catalog.list');
  assert.equal(response.status, 403);assert.deepEqual(await response.json(), { error: 'denied' });
  await assert.rejects(frame.request('/api/auth/status'), /Shop request failed/);
  assert.equal(calls, 1);
});

test('only a trusted marked launch rejection reports the captured launch to the host controller', async t => {
  const observed = [];
  const unmarked = await pair(t, {
    onLaunchUnavailable: launch => observed.push(launch),
    fetchImpl: async () => new Response('{"error":"Invalid shop credentials"}', { status: 401,
      headers: { 'content-type': 'application/json' } }),
  });
  const denied = await unmarked.frame.request('catalog.list');
  assert.equal(denied.status, 401);
  assert.deepEqual(await denied.json(), { error: 'Invalid shop credentials' });
  assert.deepEqual(observed, []);

  const marked = await pair(t, {
    onLaunchUnavailable: launch => observed.push(launch),
    fetchImpl: async () => new Response('{"error":"SecureShop launch unavailable"}', { status: 401,
      headers: { 'content-type': 'application/json',
        'x-dvaia-secureshop-launch-state': 'unavailable' } }),
  });
  const stale = await marked.frame.request('catalog.list');
  assert.equal(stale.status, 401);
  assert.deepEqual(await stale.json(), { error: 'SecureShop launch unavailable' });
  assert.deepEqual(observed, ['a'.repeat(43)]);
  assert.deepEqual([...stale.headers.keys()], ['content-type'],
    'private launch state marker is never forwarded into the frame');
});

test('frame messages cannot directly invoke the trusted launch-unavailable callback', async () => {
  const { createHostTransport } = await import('../client/src/pages/secureshop/bridge/transport.mjs');
  const port = fakePort(); let callbacks = 0; let fetches = 0;
  const host = createHostTransport({ port, origin: 'https://app.invalid', compileOperation,
    getLaunchBearer: () => 'a'.repeat(43), onLaunchUnavailable: () => { callbacks++; },
    fetchImpl: async () => { fetches++; return new Response('{}', {
      headers: { 'content-type': 'application/json' } }); } });
  port.emit({ type: 'launchUnavailable', id: 1, launch: 'a'.repeat(43) });
  port.emit({ type: 'request', id: 1, operation: 'catalog.list', input: {}, launchUnavailable: true });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(callbacks, 0);
  assert.equal(fetches, 0);
  host.close();
});

test('compiler cannot turn host into a platform or external fetch proxy', async t => {
  let calls = 0;
  const { frame } = await pair(t, { compileOperation: (_, input) => ({ path: input.path, method: 'GET', responseKind: 'json' }), fetchImpl: async () => { calls++;throw new Error('should not fetch'); } });
  for (const path of ['https://attacker.invalid/api/secureshop/x', '/api/auth/status', '/api/secureshop/../../api/auth/status', '//attacker.invalid/api/secureshop/x']) {
    await assert.rejects(frame.request('bad.compiler', { path }), /Shop request failed/);
  }
  assert.equal(calls, 0);
});

test('abort cancels an in-flight HTTP request and closes pending frame response', async t => {
  let notify;const started = new Promise(resolve => { notify = resolve; });
  let cancelled = false;
  const { frame } = await pair(t, { fetchImpl: async (_, { signal }) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => { cancelled = true;reject(new Error('private credential in error')); }, { once: true });notify();
  }) });
  const controller = new AbortController();
  const request = frame.request('catalog.list', {}, { signal: controller.signal });
  const rejected = assert.rejects(request, { name: 'AbortError' });
  await started;controller.abort();await rejected;
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(cancelled, true);
});

test('bounded response failure errors the readable body without pretending EOF success', async t => {
  const { frame } = await pair(t, { maxResponseBytes: 3, fetchImpl: async () => new Response('oversized', { headers: { 'content-type': 'application/json' } }) });
  const response = await frame.request('catalog.list');
  await assert.rejects(response.text(), /Shop request failed/);
});

test('out-of-sequence and malformed response starts reject without hanging', async t => {
  const { createFrameTransport } = await import('../client/src/pages/secureshop/bridge/transport.mjs');
  const { port1, port2 } = new MessageChannel();
  const frame = createFrameTransport({ port: port2, timeoutMs: 2000 });
  t.after(() => { frame.close();port1.close(); });
  port1.addEventListener('message', event => {
    if (event.data.type !== 'request') return;
    const id = event.data.id;
    if (id === 1) { port1.postMessage({ type: 'start', id, status: 200, contentType: 'bad\r\nheader' });return; }
    port1.postMessage({ type: 'start', id, status: 200, contentType: 'application/json' });
    port1.postMessage({ type: 'chunk', id, seq: 1, chunk: new ArrayBuffer(1) });
  });port1.start();
  await assert.rejects(frame.request('catalog.list'));
  const response = await frame.request('catalog.list');await assert.rejects(response.text(), /Invalid shop bridge response/);
});

test('empty HTTP response completes and duplicate IDs cannot dispatch twice', async t => {
  let calls = 0;
  const { frame, port2 } = await pair(t, { fetchImpl: async () => { calls++;return new Response(null, { status: 204 }); } });
  const response = await frame.request('catalog.list');assert.equal(await response.text(), '');
  port2.postMessage({ type: 'request', id: 1, operation: 'catalog.list', input: {} });
  const next = await frame.request('catalog.list');await next.text();
  assert.equal(calls, 2);
});

test('host-only shutdown settles peer requests immediately', async t => {
  let started;const ready = new Promise(resolve => { started = resolve; });
  const { host, frame } = await pair(t, { fetchImpl: async (_, { signal }) => new Promise((resolve, reject) => { signal.addEventListener('abort', () => reject(new Error('aborted')));started(); }) });
  const result = assert.rejects(frame.request('catalog.list'), { name: 'AbortError' });
  await ready;host.close();await result;
  await assert.rejects(frame.request('catalog.list'), { name: 'AbortError' });
});

test('unconsumed responses pause host reads until frame demand resumes', async t => {
  let reads = 0;
  const { frame } = await pair(t, { fetchImpl: async () => ({ ok: true, status: 200,
    headers: new Headers({ 'content-type': 'application/json' }), body: { getReader: () => ({
      read: async () => { reads++;return reads <= 3 ? { value: text.encode(String(reads)), done: false } : { done: true }; }, cancel: async () => {},
    }) } }) });
  const response = await frame.request('catalog.list');
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(reads, 1, 'One buffered frame chunk must not drain the remaining network stream');
  assert.equal(await response.text(), '123');assert.equal(reads, 4);
});

test('deadline is distinct from caller cancellation and HTML error pages are not relayed', async t => {
  const { frame } = await pair(t, { timeoutMs: 20, fetchImpl: async (_, { signal }) => new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new Error('timeout')))) });
  await assert.rejects(frame.request('catalog.list'), { name: 'TimeoutError' });
  const other = await pair(t, { fetchImpl: async () => new Response('<html>internal error</html>', { status: 500, headers: { 'content-type': 'text/html' } }) });
  await assert.rejects(other.frame.request('catalog.list'), /Shop request failed/);
});

test('real operation catalog composes with transport and bounds input before HTTP dispatch', async t => {
  const { compileOperation: actualCompile } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  let calls = 0;
  const { frame } = await pair(t, { compileOperation: actualCompile, fetchImpl: async (url, request) => {
    calls++;assert.equal(url, 'https://app.invalid/api/secureshop/agents/customer/chat');
    assert.deepEqual(JSON.parse(request.body), { sessionId: 'synthetic-session', message: 'tool observation' });
    return new Response('event: done\ndata: {}\n\n', { headers: { 'content-type': 'text/event-stream' } });
  } });
  assert.equal(await (await frame.request('agent.customer.chat', { body: { sessionId: 'synthetic-session', message: 'tool observation' } })).text(), 'event: done\ndata: {}\n\n');
  await assert.rejects(frame.request('agent.customer.chat', { body: { message: 'x'.repeat(200000) } }));
  assert.equal(calls, 1);
});

test('frame cancellation settles immediately when posting cancel fails', async () => {
  const { createFrameTransport } = await import('../client/src/pages/secureshop/bridge/transport.mjs');
  const port = fakePort(message => message.type === 'cancel');
  const frame = createFrameTransport({ port, timeoutMs: 10000 });
  const controller = new AbortController();
  const pending = frame.request('catalog.list', {}, { signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, { name: 'AbortError' });
  assert.doesNotThrow(() => frame.close());
});

test('frame stream errors and releases state when posting pull fails', async () => {
  const { createFrameTransport } = await import('../client/src/pages/secureshop/bridge/transport.mjs');
  const port = fakePort(message => message.type === 'pull');
  const frame = createFrameTransport({ port, timeoutMs: 10000 });
  const pending = frame.request('catalog.list');
  const id = port.messages[0].id;
  port.emit({ type: 'start', id, status: 200, contentType: 'application/json' });
  const response = await pending;
  await assert.rejects(response.text(), /Invalid shop bridge response/);
  assert.doesNotThrow(() => frame.close());
});

test('host stops and cancels its reader when posting a response chunk fails', async () => {
  const { createHostTransport } = await import('../client/src/pages/secureshop/bridge/transport.mjs');
  const port = fakePort(message => message.type === 'chunk');
  let cancelled;
  const cancelledPromise = new Promise(resolve => { cancelled = resolve; });
  let reads = 0;
  const host = createHostTransport({ port, origin: 'https://app.invalid', compileOperation,
    getLaunchBearer: () => 'a'.repeat(43), timeoutMs: 10000,
    fetchImpl: async () => ({ ok: true, status: 200, headers: new Headers({ 'content-type': 'application/json' }),
      body: { getReader: () => ({ read: async () => (++reads === 1 ? { value: text.encode('{}'), done: false } : { done: true }),
        cancel: async () => { cancelled(); } }) } }) });
  port.emit({ type: 'request', id: 1, operation: 'catalog.list', input: {} });
  while (!port.messages.some(message => message.type === 'start')) await new Promise(resolve => setImmediate(resolve));
  port.emit({ type: 'pull', id: 1 });
  await cancelledPromise;
  assert.equal(reads, 1);
  assert.equal(port.messages.some(message => message.type === 'end'), false);
  host.close();
});

test('Listings readiness, durable mutation and recovery traverse actual compiler and port transport', async t => {
  const { compileOperation: registry } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  const requests=[];
  const {frame}=await pair(t,{compileOperation:registry,fetchImpl:async(url,options)=>{
    requests.push(new Request(url,options));
    return new Response('{"ok":true}',{headers:{'content-type':'application/json'}});
  }});
  const operationId='11111111-1111-4111-8111-111111111111';
  const calls=[['readiness',{}],['assistWrite',{body:{operationId,title:'Example',description:'Source'}}],
    ['operation',{params:{operationId}}],['resume',{params:{operationId},body:{}}],
    ['rewriteSave',{body:{rewriteOperationId:operationId,saveOperationId:'22222222-2222-4222-8222-222222222222',productId:null,
      item:{name:'Example',description:'Source',price:1,category:null,images:[],templateSource:null}}}]];
  for(const [name,input] of calls){
    const response=await frame.request('merchant.listings.'+name,input,{shopBearer:'synthetic-shop-token'});
    assert.deepEqual(await response.json(),{ok:true});
  }
  assert.equal(requests.length,5);
  for(let index=0;index<calls.length;index++){
    const [name,input]=calls[index],expected=registry('merchant.listings.'+name,input),request=requests[index];
    assert.equal(request.url,'https://app.invalid'+expected.path);assert.equal(request.method,expected.method);
    assert.equal(request.headers.get('x-dvaia-secureshop-launch'),'a'.repeat(43));
    assert.equal(request.headers.get('authorization'),'Bearer synthetic-shop-token');
    assert.equal(await request.text(),expected.body===undefined?'':JSON.stringify(expected.body));
  }
  await assert.rejects(frame.request('merchant.listings.rewriteSave',{body:{ownerId:7}}),/Shop request failed/);
  assert.equal(requests.length,5,'rejected authority never reaches HTTP transport');
});
