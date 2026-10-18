import { compileOperation, matchOperationRequest } from './operations.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const checkoutOperationId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const base = '/api/secureshop/agents/customer/checkout-audit';
const chat = { sessionId, requestId, checkoutOperationId,
  teachingToken: 'synthetic.practice.token', message: 'Read the protected audit for my checkout.' };

test('checkout audit bridge maps only the six bound lesson routes', () => {
  for (const [suffix, method, path, requestBody, responseKind] of [
    ['session', 'POST', `${base}/session`, {}, 'json'],
    ['practiceToken', 'POST', `${base}/practice-token`, { checkoutOperationId }, 'json'],
    ['chat', 'POST', `${base}/chat`, chat, 'sse'],
    ['operation', 'GET', `${base}/operations/${sessionId}/${requestId}`, undefined, 'json'],
    ['assess', 'POST', `${base}/assess`, { sessionId, requestId }, 'json'],
    ['assessment', 'GET', `${base}/assess/${sessionId}/${requestId}`, undefined, 'json'],
  ]) {
    const name = `agent.customer.checkoutAudit.${suffix}`;
    const matched = matchOperationRequest({ pathname: path, method,
      ...(requestBody === undefined ? {} : { body: requestBody }) });
    expect(matched.name).toBe(name);
    expect(compileOperation(name, matched.input)).toMatchObject({ path, method, responseKind });
  }
});

test('checkout audit bridge rejects malformed source, authority, and message fields', () => {
  for (const [path, method, body, query] of [
    [`${base}/session`, 'POST', undefined, undefined],
    [`${base}/session`, 'POST', { mode: 'vuln' }, undefined],
    [`${base}/practice-token`, 'POST', { checkoutOperationId: 'not-an-operation' }, undefined],
    [`${base}/practice-token`, 'POST', { checkoutOperationId, platformOwnerId: 1 }, undefined],
    [`${base}/chat`, 'POST', { ...chat, role: 'admin' }, undefined],
    [`${base}/chat`, 'POST', { ...chat, teachingToken: '' }, undefined],
    [`${base}/chat`, 'POST', { ...chat, teachingToken: '😀'.repeat(1025) }, undefined],
    [`${base}/chat`, 'POST', { ...chat, message: '  ' }, undefined],
    [`${base}/chat`, 'POST', { ...chat, message: 'x'.repeat(8193) }, undefined],
    [`${base}/assess`, 'POST', { sessionId, requestId, verdict: 'pass' }, undefined],
    [`${base}/assess`, 'POST', { sessionId, requestId: 'wrong' }, undefined],
    [`${base}/assess/${sessionId}/${requestId}`, 'GET', undefined, { mode: 'vuln' }],
    [`${base}/operations/${sessionId}/wrong`, 'GET', undefined, undefined],
  ]) expect(() => matchOperationRequest({ pathname: path, method,
    ...(body === undefined ? {} : { body }), ...(query === undefined ? {} : { query }) })).toThrow();
});

test('all checkout audit requests pass the real closed fetch bridge with no URL fallback', async () => {
  Object.assign(global, require('node:stream/web'));
  global.MessagePort = require('node:worker_threads').MessagePort;
  const web = require('undici');
  const oldRequest = global.Request, oldHeaders = global.Headers;
  global.Request = web.Request; global.Headers = web.Headers;
  try {
    const bridge = { request: jest.fn(async () => ({ ok: true })) };
    const transport = createBridgeFetch({ bridge, origin: 'https://shop.invalid',
      getRequestBaseUrl: () => 'https://shop.invalid', getToken: () => 'owned-token' });
    for (const [name, method, path, body] of [
      ['session', 'POST', `${base}/session`, {}],
      ['practiceToken', 'POST', `${base}/practice-token`, { checkoutOperationId }],
      ['chat', 'POST', `${base}/chat`, chat],
      ['operation', 'GET', `${base}/operations/${sessionId}/${requestId}`, undefined],
      ['assess', 'POST', `${base}/assess`, { sessionId, requestId }],
      ['assessment', 'GET', `${base}/assess/${sessionId}/${requestId}`, undefined],
    ]) {
      await transport(path, body === undefined ? { method } : { method,
        headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      expect(bridge.request).toHaveBeenLastCalledWith(`agent.customer.checkoutAudit.${name}`,
        expect.objectContaining(body === undefined ? { params: { sessionId, requestId } } : { body }),
        expect.objectContaining({ shopBearer: 'owned-token' }));
    }
    await expect(transport(`${base}/practice-token`, { method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ checkoutOperationId, platformSessionId: 1 }) })).rejects.toThrow();
    expect(bridge.request).toHaveBeenCalledTimes(6);
  } finally { global.Request = oldRequest; global.Headers = oldHeaders; }
});
