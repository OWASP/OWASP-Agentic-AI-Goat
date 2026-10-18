import { createBridgeFetch } from '../bridge/fetchAdapter.mjs';
import { requestRefundTicket } from './refundRequest.mjs';

Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Request = web.Request;
global.Response = web.Response;
global.Headers = web.Headers;

test.each([true, false])('refund uses the acknowledged bridge route family (bound=%s)', async boundReviews => {
  const sessionId = '11111111-1111-4111-8111-111111111111';
  const requestId = '22222222-2222-4222-8222-222222222222';
  const result = { ok: true, ticket_id: '9007199254740993', order_id: '9' };
  const stream = [
    ['tool_result', { tool: 'support.refund_request', result: {
      content: [{ type: 'text', text: JSON.stringify(result) }],
    } }],
    ['done', { stopReason: 'end_turn' }],
  ].map(([event, payload]) => `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`).join('');
  const bridge = { request: jest.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({ sessionId }), {
      headers: { 'content-type': 'application/json' },
    }))
    .mockResolvedValueOnce(new Response(stream, { headers: { 'content-type': 'text/event-stream' } })) };
  const fetchImpl = createBridgeFetch({ bridge, origin: 'https://shop.invalid',
    boundReviews, getToken: () => 'owned-persona-token' });
  const beforeChat = jest.fn();
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9,
    reason: 'Damaged item', requestId, beforeChat }))
    .resolves.toEqual({ ticketId: result.ticket_id, orderId: '9' });
  if (boundReviews) expect(beforeChat).toHaveBeenCalledWith(sessionId);
  else expect(beforeChat).not.toHaveBeenCalled();
  const prefix = boundReviews ? 'agent.customer.refund' : 'agent.customer';
  expect(bridge.request).toHaveBeenNthCalledWith(1, `${prefix}.session`, {
    params: {}, query: {}, body: { userId: 4 },
  }, expect.objectContaining({ shopBearer: 'owned-persona-token' }));
  expect(bridge.request).toHaveBeenNthCalledWith(2, `${prefix}.chat`, {
    params: {}, query: {}, body: { sessionId,
      message: 'Please refund order 9. Reason: Damaged item',
      ...(boundReviews ? { requestId } : {}) },
  }, expect.objectContaining({ shopBearer: 'owned-persona-token' }));
});
