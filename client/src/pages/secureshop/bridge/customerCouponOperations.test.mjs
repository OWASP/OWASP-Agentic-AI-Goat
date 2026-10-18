import { compileOperation, matchOperationRequest } from './operations.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const base = '/api/secureshop/agents/customer/coupons/confirm';

test('coupon confirmation bridge accepts only exact IDs and saved GET', () => {
  const body = { sessionId, requestId, proposalId };
  for (const [name, path, method, requestBody] of [
    ['agent.customer.coupon.confirm', base, 'POST', body],
    ['agent.customer.coupon.saved', `${base}/${sessionId}/${requestId}/${proposalId}`, 'GET', undefined],
    ['agent.customer.coupon.assessment', `/api/secureshop/agents/customer/coupons/assessment/${sessionId}/${requestId}/${proposalId}`, 'GET', undefined],
    ['agent.customer.coupon.assessmentRetry', '/api/secureshop/agents/customer/coupons/assessment-retry', 'POST', body],
  ]) {
    const matched = matchOperationRequest({ pathname: path, method,
      ...(requestBody ? { body: requestBody } : {}) });
    expect(matched.name).toBe(name);
    expect(compileOperation(name, matched.input)).toMatchObject({ path, method });
  }
  expect(() => matchOperationRequest({ pathname: base, method: 'POST', body: {
    ...body, code: 'BROWSER-SUPPLIED',
  } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${base}/${sessionId}/${requestId}/${proposalId}`,
    method: 'GET', query: { code: 'BROWSER-SUPPLIED' } })).toThrow();
  expect(() => matchOperationRequest({ pathname: '/api/secureshop/agents/customer/coupons/assessment-retry',
    method: 'POST', body: { ...body, code: 'BROWSER-SUPPLIED' } })).toThrow();
});

test('IDs-only physical confirmation crosses the real bridge transport', async () => {
  Object.assign(global, require('node:stream/web'));
  global.MessagePort = require('node:worker_threads').MessagePort;
  const web = require('undici');
  const oldRequest = global.Request, oldHeaders = global.Headers;
  global.Request = web.Request; global.Headers = web.Headers;
  try {
    const bridge = { request: jest.fn(async () => ({ ok: true })) };
    const transport = createBridgeFetch({ bridge, origin: 'https://shop.invalid',
      getRequestBaseUrl: () => 'https://shop.invalid', getToken: () => 'owned-token' });
    const body = { sessionId, requestId, proposalId };
    await transport(base, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body) });
    expect(bridge.request).toHaveBeenCalledWith('agent.customer.coupon.confirm',
      expect.objectContaining({ body }), expect.objectContaining({ shopBearer: 'owned-token' }));
    await expect(transport(base, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...body, code: 'BROWSER-SUPPLIED' }) })).rejects.toThrow();
    expect(bridge.request).toHaveBeenCalledTimes(1);
  } finally { global.Request = oldRequest; global.Headers = oldHeaders; }
});
