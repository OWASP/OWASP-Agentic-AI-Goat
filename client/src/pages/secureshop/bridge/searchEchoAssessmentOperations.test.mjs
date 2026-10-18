import { compileOperation, matchOperationRequest } from './operations.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const source = { sessionId, requestId, step: 2 };
const post = '/api/secureshop/agents/customer/search-echo/assess';
const get = `/api/secureshop/agents/customer/sessions/${sessionId}`
  + `/requests/${requestId}/search-echo/2/assessment`;

test('search assessment bridge admits only source IDs and one bounded step', () => {
  expect(matchOperationRequest({ pathname: post, method: 'POST', body: source }).name)
    .toBe('agent.customer.searchEchoAssess');
  expect(compileOperation('agent.customer.searchEchoAssessment', { params: {
    sessionId, requestId, step: '2',
  } }).path).toBe(get);
  expect(matchOperationRequest({ pathname: get, method: 'GET' }).name)
    .toBe('agent.customer.searchEchoAssessment');
  for (const extra of [{ echoHtml: '<img>' }, { mode: 'vuln' }, { ownerId: 1 },
    { traceEventIds: [] }, { packet: '{}' }, { effect: {} }])
    expect(() => matchOperationRequest({ pathname: post, method: 'POST',
      body: { ...source, ...extra } })).toThrow();
  for (const bad of [0, 5, '2', 2.5])
    expect(() => matchOperationRequest({ pathname: post, method: 'POST',
      body: { ...source, step: bad } })).toThrow();
  for (const bad of ['0', '5', '02', 'x'])
    expect(() => compileOperation('agent.customer.searchEchoAssessment', { params: {
      sessionId, requestId, step: bad,
    } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${get}?owner=1`, method: 'GET' })).toThrow();
  expect(() => matchOperationRequest({ pathname: get, method: 'GET', body: source })).toThrow();
});

test('physical fetch adapter reaches only the two closed source operations', async () => {
  Object.assign(global, require('node:stream/web'));
  global.MessagePort = require('node:worker_threads').MessagePort;
  const web = require('undici'), oldRequest = global.Request, oldHeaders = global.Headers;
  global.Request = web.Request; global.Headers = web.Headers;
  try {
    const bridge = { request: jest.fn(async () => ({ completed: false,
      status: 'unconfirmed', modelEvaluated: false })) };
    const fetch = createBridgeFetch({ bridge, origin: 'https://shop.invalid',
      getRequestBaseUrl: () => 'https://shop.invalid', getToken: () => 'owned-token' });
    await fetch(post, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(source) });
    expect(bridge.request).toHaveBeenLastCalledWith('agent.customer.searchEchoAssess',
      expect.objectContaining({ body: source }), expect.objectContaining({ shopBearer: 'owned-token' }));
    await fetch(get, { method: 'GET', headers: { accept: 'application/json' } });
    expect(bridge.request).toHaveBeenLastCalledWith('agent.customer.searchEchoAssessment',
      expect.objectContaining({ params: { sessionId, requestId, step: '2' } }),
      expect.objectContaining({ shopBearer: 'owned-token' }));
    await expect(fetch(post, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...source, html: '<img>' }) })).rejects.toThrow();
    await expect(fetch(`${get}?mode=vuln`, { method: 'GET' })).rejects.toThrow();
    expect(bridge.request).toHaveBeenCalledTimes(2);
  } finally { global.Request = oldRequest; global.Headers = oldHeaders; }
});
