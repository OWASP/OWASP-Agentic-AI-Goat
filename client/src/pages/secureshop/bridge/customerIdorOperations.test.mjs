import { compileOperation, matchOperationRequest } from './operations.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const base = '/api/secureshop/agents/customer/idor';

test('customer IDOR lesson bridge admits only the seven closed routes', () => {
  const cases = [
    ['prepare', 'POST', `${base}/prepare`, {}, 'json'],
    ['cards', 'GET', `${base}/cards`, undefined, 'json'],
    ['session', 'POST', `${base}/session`, {}, 'json'],
    ['chat', 'POST', `${base}/chat`, { sessionId, requestId,
      message: 'Read reserved lesson order #7 status in this access-control lesson.',
      selection: { action: 'order_status', numericId: 7 } }, 'sse'],
    ['operation', 'GET', `${base}/operations/${sessionId}/${requestId}`, undefined, 'json'],
    ['assessment', 'GET', `${base}/assessments/${sessionId}/${requestId}`, undefined, 'json'],
    ['assessmentRetry', 'POST', `${base}/assessment-retry`, { sessionId, requestId }, 'json'],
  ];
  for (const [suffix, method, path, body, responseKind] of cases) {
    const name = `agent.customer.idor.${suffix}`;
    const matched = matchOperationRequest({ pathname: path, method, ...(body === undefined ? {} : { body }) });
    expect(matched.name).toBe(name);
    expect(compileOperation(name, matched.input)).toMatchObject({ path, method, responseKind });
  }
  expect(() => compileOperation('agent.customer.idor.chat', { body: {
    sessionId, requestId, message: 'Try item', selection: { action: 'cart_remove', numericId: 7, ownerId: 3 },
  } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${base}/prepare`, method: 'POST', body: { victimId: 7 } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${base}/assessment-retry`, method: 'POST', body: {
    sessionId, requestId, evaluationId: requestId,
  } })).toThrow();
});

test('the hook-emitted selected request crosses the real closed bridge adapter', async () => {
  Object.assign(global, require('node:stream/web'));
  global.MessagePort = require('node:worker_threads').MessagePort;
  const web = require('undici');
  const oldRequest = global.Request, oldHeaders = global.Headers;
  global.Request = web.Request; global.Headers = web.Headers;
  try {
    const bridge = { request: jest.fn(async () => ({ ok: true })) };
    const transport = createBridgeFetch({ bridge, origin: 'https://shop.invalid',
      getRequestBaseUrl: () => 'https://shop.invalid', getToken: () => 'owned-token' });
    const body = { sessionId, requestId,
      message: 'Read reserved lesson order #7 status in this access-control lesson.',
      selection: { action: 'order_status', numericId: 7 } };
    await transport(`${base}/chat`, { method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'text/event-stream' },
      body: JSON.stringify(body) });
    expect(bridge.request).toHaveBeenCalledWith('agent.customer.idor.chat', expect.objectContaining({ body }),
      expect.objectContaining({ shopBearer: 'owned-token' }));
    await expect(transport(`${base}/chat`, { method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...body, selection: { ...body.selection, victimId: 9 } }) }))
      .rejects.toThrow();
    expect(bridge.request).toHaveBeenCalledTimes(1);
  } finally { global.Request = oldRequest; global.Headers = oldHeaders; }
});
