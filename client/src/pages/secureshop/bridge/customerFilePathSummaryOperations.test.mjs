import { compileBridgeOperation } from './compiler.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';
import { createHostTransport } from './transport.mjs';
Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Request = web.Request; global.Response = web.Response; global.Headers = web.Headers;
const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ids = { sessionId, requestId };
const body = { ...ids, message: 'Summarize this exact virtual path. 🧪', path: '../etc/passwd' };
const base = '/api/secureshop/agents/customer/file-path-summary';
const cases = [
  ['capability', '/capability', 'GET', {}, undefined],
  ['session', '/session', 'POST', { body: {} }, {}],
  ['run', '/run', 'POST', { body }, body],
  ['request', `/requests/${sessionId}/${requestId}`, 'GET', { params: ids }, undefined],
  ['assess', '/assess', 'POST', { body: ids }, ids],
  ['assessment', `/assess/${sessionId}/${requestId}`, 'GET', { params: ids }, undefined],
];

test.each(cases)('V44 %s preserves exact JSON through compiler, frame fetch and host transport', async (suffix, path, method, input, expectedBody) => {
  const operation = `agent.customer.filePathSummary.${suffix}`;
  const compiled = compileBridgeOperation(operation, input);
  expect(compiled).toEqual({ path: base + path, method, responseKind: 'json', ...(expectedBody === undefined ? {} : { body: expectedBody }) });
  const bridgeCalls = [];
  const fetch = createBridgeFetch({ origin: 'https://shop.test', bridge: { request: async (...args) => {
    bridgeCalls.push(args); return new Response('{}', { headers: { 'content-type': 'application/json' } });
  } } });
  await fetch(base + path, { method, headers: { accept: 'application/json', ...(expectedBody === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(expectedBody === undefined ? {} : { body: JSON.stringify(expectedBody) }) });
  expect(bridgeCalls).toHaveLength(1);
  expect(bridgeCalls[0][0]).toBe(operation);
  expect(compileBridgeOperation(operation, bridgeCalls[0][1])).toEqual(compiled);
  const listeners = new Set(), messages = [];
  const port = { addEventListener: (_type, callback) => listeners.add(callback), removeEventListener: (_type, callback) => listeners.delete(callback),
    start() {}, close() {}, postMessage(message) { messages.push(message); if (['start', 'chunk'].includes(message.type)) queueMicrotask(() => listeners.forEach(callback => callback({ data: { type: 'pull', id: message.id } }))); } };
  const fetchImpl = jest.fn(async () => new Response('{}', { headers: { 'content-type': 'application/json' } }));
  const host = createHostTransport({ port, origin: 'https://shop.test', compileOperation: compileBridgeOperation, fetchImpl,
    getLaunchBearer: () => 'a'.repeat(43) });
  try {
    listeners.forEach(callback => callback({ data: { type: 'request', id: 1, operation, input: bridgeCalls[0][1], shopBearer: 'persona' } }));
    for (let i = 0; i < 40 && !messages.some(message => message.type === 'end'); i++) await new Promise(resolve => setTimeout(resolve, 0));
    expect(messages.some(message => message.type === 'end')).toBe(true);
    expect(messages.some(message => message.type === 'error')).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, options] = fetchImpl.mock.calls[0];
    expect(url).toBe('https://shop.test' + base + path); expect(options.method).toBe(method);
    expect(options.body).toBe(expectedBody === undefined ? undefined : JSON.stringify(expectedBody));
    expect(options.headers.get('content-type')).toBe(expectedBody === undefined ? null : 'application/json');
    expect(options.headers.get('authorization')).toBe('Bearer persona');
    expect(options.headers.get('x-dvaia-secureshop-launch')).toBe('a'.repeat(43));
  } finally { host.close(); }
});

test('V44 compiler rejects malformed IDs, paths, message bounds and extra fields', () => {
  for (const patch of [{ sessionId: sessionId.toUpperCase() }, { requestId: 'not-a-uuid' }, { requestId: requestId.replace('-4bbb-', '-0bbb-') },
    { path: '' }, { path: '/etc/passwd' }, { path: 'C:/private' }, { path: '..\\etc\\passwd' }, { path: 'x\0y' }, { path: 'x\ny' }, { path: 'x\ry' },
    { path: '🧪'.repeat(1025) }, { path: '\ud800' }, { message: '' }, { message: ' ' }, { message: '🧪'.repeat(2049) }, { message: '\ud800' }, { message: 'x\0y' },
    { nativePath: '/private/path' }, { authorityKey: 'secret' }]) {
    expect(() => compileBridgeOperation('agent.customer.filePathSummary.run', { body: { ...body, ...patch } })).toThrow();
  }
  for (const key of Object.keys(body)) { const incomplete = { ...body }; delete incomplete[key]; expect(() => compileBridgeOperation('agent.customer.filePathSummary.run', { body: incomplete })).toThrow(); }
  for (const suffix of ['run', 'assess']) expect(() => compileBridgeOperation(`agent.customer.filePathSummary.${suffix}`, { body: { ...(suffix === 'run' ? body : ids), requestId: requestId.toUpperCase() } })).toThrow();
  expect(() => compileBridgeOperation('agent.customer.filePathSummary.session', { body: { path: '../etc/passwd' } })).toThrow();
  expect(() => compileBridgeOperation('agent.customer.filePathSummary.run', { body: { ...body, path: 'x'.repeat(4096), message: 'x'.repeat(8192) } })).not.toThrow();
});

test('V44 rejects query, GET bodies and foreign params on every closed operation', () => {
  for (const [suffix, , method, input] of cases) {
    const operation = `agent.customer.filePathSummary.${suffix}`;
    expect(() => compileBridgeOperation(operation, { ...input, query: { path: '../etc/passwd' } })).toThrow();
    expect(() => compileBridgeOperation(operation, { ...input, params: { ...(input.params || {}), ownerId: 'foreign' } })).toThrow();
    if (method === 'GET') expect(() => compileBridgeOperation(operation, { ...input, body: {} })).toThrow();
  }
  for (const suffix of ['request', 'assessment']) expect(() => compileBridgeOperation(`agent.customer.filePathSummary.${suffix}`, { params: { ...ids, sessionId: sessionId.toUpperCase() } })).toThrow();
});

test('frame fetch rejects malformed requests before bridge dispatch', async () => {
  const request = jest.fn(), fetch = createBridgeFetch({ origin: 'https://shop.test', bridge: { request } });
  for (const [url, options] of [
    [base + '/run?path=other', { method: 'POST', body: JSON.stringify(body) }],
    [base + '/run', { method: 'POST', body: JSON.stringify({ ...body, path: '/etc/passwd' }) }],
    [base + '/run', { method: 'POST', body: JSON.stringify({ ...body, extra: true }) }],
    [base + '/capability', { method: 'GET', body: '{}' }],
    [base + `/requests/${sessionId.toUpperCase()}/${requestId}`, { method: 'GET' }],
  ]) await expect(fetch(url, options)).rejects.toThrow();
  expect(request).not.toHaveBeenCalled();
});


const policyBase = '/api/secureshop/v2/controlled-ssrf/html';
const policyBody = { request_id: requestId, policy_html: '<b>Return policy</b>' };
test.each([
  ['readiness', '/readiness', 'GET', {}, undefined],
  ['run', '/run', 'POST', { body: policyBody }, policyBody],
  ['request', `/run/${requestId}`, 'GET', { params: { requestId } }, undefined],
  ['assess', '/assess', 'POST', { body: { session_id: sessionId, request_id: requestId } }, { session_id: sessionId, request_id: requestId }],
  ['assessment', `/assessment/${sessionId}/${requestId}`, 'GET', { params: ids }, undefined],
])('V27 %s preserves its exact request through the real frame compiler', async (suffix, path, method, input, expectedBody) => {
  const operation = `lab.policyHtml.${suffix}`;
  const compiled = compileBridgeOperation(operation, input);
  expect(compiled).toEqual({ path: policyBase + path, method, responseKind: 'json',
    ...(expectedBody === undefined ? {} : { body: expectedBody }) });
  const calls = [];
  const fetch = createBridgeFetch({ origin: 'https://shop.test', bridge: { request: async (...args) => {
    calls.push(args); return new Response('{}', { headers: { 'content-type': 'application/json' } });
  } } });
  await fetch(policyBase + path, { method, ...(expectedBody === undefined ? {} : {
    headers: { 'content-type': 'application/json' }, body: JSON.stringify(expectedBody) }) });
  expect(calls).toHaveLength(1); expect(calls[0][0]).toBe(operation);
  expect(compileBridgeOperation(operation, calls[0][1])).toEqual(compiled);
  expect(() => compileBridgeOperation(operation, { ...input, query: { owner: 'foreign' } })).toThrow();
});
test('V27 bridge rejects forged ownership, malformed IDs and unbounded policy source', () => {
  for (const patch of [{ request_id: requestId.toUpperCase() }, { request_id: 'bad' },
    { policy_html: '' }, { policy_html: '\ud800' }, { policy_html: 'x\0y' },
    { policy_html: 'x'.repeat(8193) }, { ownerId: 2 }, { policy_url: 'file:///private' }])
    expect(() => compileBridgeOperation('lab.policyHtml.run', { body: { ...policyBody, ...patch } })).toThrow();
  expect(() => compileBridgeOperation('lab.policyHtml.assess', { body: { session_id: 'bad', request_id: requestId } })).toThrow();
  expect(() => compileBridgeOperation('lab.policyHtml.request', { params: { requestId: 'bad' } })).toThrow();
});
