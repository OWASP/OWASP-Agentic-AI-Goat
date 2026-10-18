import { compileOperation, matchOperationRequest } from './operations.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const base = '/api/secureshop/products/7/similar';
const saved = `${base}/sessions/${sessionId}/requests/${requestId}`;

test('similar-products bridge admits one explicit session, ID-only run, and saved read', () => {
  const cases = [
    ['catalog.product.similarSession', 'POST', `${base}/session`, {}],
    ['catalog.product.similarRun', 'POST', base, { sessionId, requestId }],
    ['catalog.product.similarSaved', 'GET', saved, undefined],
  ];
  for (const [name, method, pathname, body] of cases) {
    const matched = matchOperationRequest({ pathname, method,
      ...(body === undefined ? {} : { body }) });
    expect(matched.name).toBe(name);
    expect(compileOperation(name, matched.input)).toMatchObject({ path: pathname, method });
  }
  expect(matchOperationRequest({ pathname: base, method: 'GET' }).name)
    .toBe('catalog.product.similar');
  for (const extra of [{ productId: 7 }, { mode: 'vuln' }, { source: {} }, { echo: '<img>' }])
    expect(() => matchOperationRequest({ pathname: base, method: 'POST',
      body: { sessionId, requestId, ...extra } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${base}/session`, method: 'POST',
    body: { requestId } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${saved}?owner=7`, method: 'GET' })).toThrow();
  expect(() => matchOperationRequest({ pathname: saved, method: 'GET', body: { ownerId: 7 } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${base}/sessions/invalid/requests/${requestId}`,
    method: 'GET' })).toThrow();
  expect(() => matchOperationRequest({ pathname: base, method: 'POST',
    body: { sessionId: 'invalid', requestId } })).toThrow();
});

test('physical fetch adapter forwards only the closed similar request identities', async () => {
  Object.assign(global, require('node:stream/web'));
  global.MessagePort = require('node:worker_threads').MessagePort;
  const web = require('undici'), oldRequest = global.Request, oldHeaders = global.Headers;
  global.Request = web.Request; global.Headers = web.Headers;
  try {
    const bridge = { request: jest.fn(async () => ({ ok: true })) };
    const fetch = createBridgeFetch({ bridge, origin: 'https://shop.invalid',
      getRequestBaseUrl: () => 'https://shop.invalid', getToken: () => 'owned-token' });
    await fetch(`${base}/session`, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: '{}' });
    await fetch(base, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionId, requestId }) });
    await fetch(saved, { method: 'GET', headers: { accept: 'application/json' } });
    expect(bridge.request.mock.calls.map(([name]) => name)).toEqual([
      'catalog.product.similarSession', 'catalog.product.similarRun', 'catalog.product.similarSaved',
    ]);
    await expect(fetch(base, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionId, requestId, ownerId: 7 }) })).rejects.toThrow();
    expect(bridge.request).toHaveBeenCalledTimes(3);
  } finally { global.Request = oldRequest; global.Headers = oldHeaders; }
});
