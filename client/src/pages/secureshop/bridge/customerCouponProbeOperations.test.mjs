import { compileOperation, matchOperationRequest } from './operations.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const base = '/api/secureshop/customer/coupon-probe';

test('coupon probe bridge admits readiness and the five dedicated request shapes', () => {
  expect(matchOperationRequest({ pathname: `${base}/capabilities`, method: 'GET' }).name)
    .toBe('agent.customer.couponProbe.capabilities');
  expect(compileOperation('agent.customer.couponProbe.capabilities', {}))
    .toMatchObject({ path: `${base}/capabilities`, method: 'GET', responseKind: 'json' });
  expect(() => matchOperationRequest({ pathname: `${base}/capabilities`, method: 'GET', query: { ready: 'true' } })).toThrow();
  const cases = [
    ['session', 'POST', `${base}/session`, {}, 'json'],
    ['run', 'POST', `${base}/run`, { sessionId, requestId, message: 'Check whether this coupon can apply.' }, 'json'],
    ['operation', 'GET', `${base}/operations/${sessionId}/${requestId}`, undefined, 'json'],
    ['assess', 'POST', `${base}/assess`, { sessionId, requestId }, 'json'],
    ['assessment', 'GET', `${base}/assess/${sessionId}/${requestId}`, undefined, 'json'],
  ];
  for (const [suffix, method, path, body, responseKind] of cases) {
    const name = `agent.customer.couponProbe.${suffix}`;
    const matched = matchOperationRequest({ pathname: path, method,
      ...(body === undefined ? {} : { body }) });
    expect(matched.name).toBe(name);
    expect(compileOperation(name, matched.input)).toMatchObject({ path, method, responseKind });
  }
  expect(() => matchOperationRequest({ pathname: `${base}/run`, method: 'POST', body: {
    sessionId, requestId, message: 'Check', code: 'BROWSER-SUPPLIED',
  } })).toThrow();
  expect(compileOperation('agent.customer.couponProbe.run', { body: { sessionId, requestId,
    message: 'Compare bounded probes', protocol: 'guided-boolean-v1' } }).body)
    .toEqual({ sessionId, requestId, message: 'Compare bounded probes', protocol: 'guided-boolean-v1' });
  expect(compileOperation('agent.customer.couponProbe.run', { body: { sessionId, requestId,
    message: 'Use bounded probes and arithmetic', protocol: 'guided-boolean-v2' } }).body)
    .toEqual({ sessionId, requestId, message: 'Use bounded probes and arithmetic', protocol: 'guided-boolean-v2' });
  for (const protocol of ['raw', 'guided', 'guided-boolean-v3', null])
    expect(() => compileOperation('agent.customer.couponProbe.run', { body: {
      sessionId, requestId, message: 'Compare bounded probes', protocol,
    } })).toThrow();
  expect(() => compileOperation('agent.customer.couponProbe.assess', { body: {
    sessionId, requestId, authority: 'BROWSER-SUPPLIED',
  } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${base}/operations/${sessionId}/${requestId}`,
    method: 'GET', query: { mode: 'vuln' } })).toThrow();
});

test('coupon probe uses the closed bridge with only request-controlled IDs and message', async () => {
  Object.assign(global, require('node:stream/web'));
  global.MessagePort = require('node:worker_threads').MessagePort;
  const web = require('undici');
  const oldRequest = global.Request, oldHeaders = global.Headers;
  global.Request = web.Request; global.Headers = web.Headers;
  try {
    const bridge = { request: jest.fn(async () => ({ ok: true })) };
    const transport = createBridgeFetch({ bridge, origin: 'https://shop.invalid',
      getRequestBaseUrl: () => 'https://shop.invalid', getToken: () => 'owned-token' });
    const body = { sessionId, requestId, message: 'Check whether this coupon can apply.' };
    await transport(`${base}/run`, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    expect(bridge.request).toHaveBeenCalledWith('agent.customer.couponProbe.run',
      expect.objectContaining({ body }), expect.objectContaining({ shopBearer: 'owned-token' }));
    await expect(transport(`${base}/assess`, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, code: 'untrusted' }) }))
      .rejects.toThrow();
    expect(bridge.request).toHaveBeenCalledTimes(1);
  } finally { global.Request = oldRequest; global.Headers = oldHeaders; }
});
