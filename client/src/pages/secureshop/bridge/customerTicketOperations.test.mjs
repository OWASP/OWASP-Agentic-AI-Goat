import { compileOperation, matchOperationRequest } from './operations.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const base = '/api/secureshop/agents/customer/tickets/confirm';

test('closed ticket and admin reads admit only declared paths and IDs-only confirmation', () => {
  const body = { sessionId, requestId, proposalId };
  for (const [name, path, method, requestBody] of [
    ['agent.customer.ticket.confirm', base, 'POST', body],
    ['agent.customer.ticket.saved', `${base}/${sessionId}/${requestId}/${proposalId}`, 'GET'],
    ['admin.tickets.list', '/api/secureshop/admin/tickets', 'GET'],
    ['admin.tickets.detail', '/api/secureshop/admin/tickets/42', 'GET'],
  ]) {
    const matched = matchOperationRequest({ pathname: path, method,
      ...(requestBody ? { body: requestBody } : {}) });
    expect(matched.name).toBe(name);
    expect(compileOperation(name, matched.input)).toMatchObject({ path, method });
  }
  expect(() => matchOperationRequest({ pathname: base, method: 'POST', body: {
    ...body, subject: 'BROWSER-SUPPLIED',
  } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${base}/${sessionId}/${requestId}/${proposalId}`,
    method: 'GET', query: { body: 'BROWSER-SUPPLIED' } })).toThrow();
  expect(() => matchOperationRequest({ pathname: '/api/secureshop/admin/tickets/42',
    method: 'GET', query: { customerId: '9' } })).toThrow();
});

test('ticket confirmation crosses the real bridge with original three IDs only', async () => {
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
    expect(bridge.request).toHaveBeenCalledWith('agent.customer.ticket.confirm',
      expect.objectContaining({ body }), expect.objectContaining({ shopBearer: 'owned-token' }));
    await expect(transport(base, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...body, body: 'BROWSER-SUPPLIED' }) })).rejects.toThrow();
    expect(bridge.request).toHaveBeenCalledTimes(1);
  } finally { global.Request = oldRequest; global.Headers = oldHeaders; }
});
