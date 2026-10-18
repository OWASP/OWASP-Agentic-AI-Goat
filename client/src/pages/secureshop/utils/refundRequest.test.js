import { requestRefundTicket } from './refundRequest.mjs';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';

jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: jest.fn() }));
beforeEach(() => getBridgeFetchMetadata.mockReturnValue(null));

function headers(type) {
  return { get: (name) => name.toLowerCase() === 'content-type' ? type : null };
}

function jsonResponse(body, { ok = true, status = 200, type = 'application/json' } = {}) {
  return { ok, status, headers: headers(type), json: jest.fn(async () => body) };
}

function frame(name, payload) {
  return `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
}

function streamResponse(chunks, { ok = true, status = 200, type = 'text/event-stream', readError } = {}) {
  const encoded = chunks.map((chunk) => new TextEncoder().encode(chunk));
  let index = 0;
  const reader = {
    read: jest.fn(async () => {
      if (readError && index === readError.at) throw new Error('transport failed');
      return index < encoded.length
        ? { value: encoded[index++], done: false }
        : { value: undefined, done: true };
    }),
    cancel: jest.fn(async () => {}),
  };
  return { ok, status, headers: headers(type), body: { getReader: () => reader }, reader };
}

function refundResult(orderId, overrides = {}) {
  return frame('tool_result', {
    id: 'call-refund', tool: 'support.refund_request',
    result: {
      content: [{ type: 'text', text: JSON.stringify({
        ok: true, ticket_id: 71, order_id: orderId, reason: null, ...overrides,
      }) }],
    },
  });
}

function fetchSequence(...responses) {
  return jest.fn(async () => responses.shift());
}

test.each(['', '  ', 'x'.repeat(501)])('blank or oversized reason is rejected before any agent request', async (reason) => {
  const fetchImpl = jest.fn();
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason }))
    .rejects.toMatchObject({ code: 'failed' });
  expect(fetchImpl).not.toHaveBeenCalled();
});

test.each([
  ['session HTTP error', jsonResponse({ error: 'offline' }, { ok: false, status: 503 })],
  ['session content type', jsonResponse({ sessionId: 'sid' }, { type: 'text/html' })],
  ['session missing id', jsonResponse({})],
])('%s fails before chat', async (_label, session) => {
  const fetchImpl = fetchSequence(session);
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .rejects.toMatchObject({ code: 'failed' });
  expect(fetchImpl).toHaveBeenCalledTimes(1);
});

test('session transport failure is definite because chat was never dispatched', async () => {
  const fetchImpl = jest.fn(async () => { throw new Error('offline'); });
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .rejects.toMatchObject({ code: 'failed' });
  expect(fetchImpl).toHaveBeenCalledTimes(1);
});

test.each([
  ['chat HTTP error', streamResponse([], { ok: false, status: 502 })],
])('%s after dispatch cannot prove whether the server committed an effect', async (_label, chat) => {
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: 'sid' }), chat);
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .rejects.toMatchObject({ code: 'uncertain' });
  expect(fetchImpl).toHaveBeenCalledTimes(2);
});

test('chat transport failure is uncertain because dispatch may have committed an unseen effect', async () => {
  const fetchImpl = jest.fn()
    .mockResolvedValueOnce(jsonResponse({ sessionId: 'sid' }))
    .mockRejectedValueOnce(new Error('connection reset'));
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .rejects.toMatchObject({ code: 'uncertain' });
  expect(fetchImpl).toHaveBeenCalledTimes(2);
});

test.each([
  ['chat content type', streamResponse([], { type: 'application/json' })],
  ['explicit SSE error', streamResponse([frame('error', { message: 'provider unavailable' })])],
  ['cancelled terminal', streamResponse([frame('done', { stopReason: 'cancelled' })])],
  ['premature EOF', streamResponse([frame('assistant_message', { text: 'working' })])],
])('%s cannot prove whether the accepted request produced an effect', async (_label, chat) => {
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: 'sid' }), chat);
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .rejects.toMatchObject({ code: 'uncertain' });
});

test('an unreadable response stream after dispatch is uncertain', async () => {
  const chat = {
    ok: true,
    headers: headers('text/event-stream'),
    body: { getReader: () => { throw new Error('stream is locked'); } },
  };
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: 'sid' }), chat);
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .rejects.toMatchObject({ code: 'uncertain' });
});

test.each([
  ['clean completion without a tool effect', [frame('done', { stopReason: 'end_turn' })]],
  ['tool effect for a different order', [refundResult(10), frame('done', { stopReason: 'end_turn' })]],
  ['malformed matching tool result', [frame('tool_result', {
    id: 'call-refund', tool: 'support.refund_request', result: { content: [{ type: 'text', text: '{' }] },
  }), frame('done', { stopReason: 'end_turn' })]],
])('%s is a clean but unconfirmed outcome', async (_label, chunks) => {
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: 'sid' }), streamResponse(chunks));
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .rejects.toMatchObject({ code: 'not_confirmed' });
});

test.each(['max_steps', 'unknown', undefined])('done stopReason %s is not a clean terminal', async (stopReason) => {
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: 'sid' }), streamResponse([
    refundResult(9), frame('done', { ...(stopReason === undefined ? {} : { stopReason }) }),
  ]));
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .rejects.toMatchObject({ code: 'uncertain' });
});

test('matching MCP tool result plus clean terminal is the only filed-success contract', async () => {
  const chat = streamResponse([
    ': stream open\n\n',
    refundResult(9),
    frame('assistant_message', { text: 'Ticket opened.', stopReason: 'end_turn' }),
    frame('done', { sessionId: 'sid', stopReason: 'end_turn', steps: 2 }),
  ]);
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: 'sid' }), chat);
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .resolves.toEqual({ ticketId: 71, orderId: 9 });
  expect(JSON.parse(fetchImpl.mock.calls[1][1].body)).toEqual({
    sessionId: 'sid', message: 'Please refund order 9. Reason: Damaged on arrival',
  });
  expect(chat.reader.cancel).toHaveBeenCalledTimes(1);
});

test('a terminal failure after observing the effect is reported as uncertain', async () => {
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: 'sid' }), streamResponse([
    refundResult(9), frame('error', { message: 'trace flush failed' }),
  ]));
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .rejects.toMatchObject({ code: 'uncertain' });
});

test('canonical positive decimal string ticket IDs are retained', async () => {
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: 'sid' }), streamResponse([
    refundResult(9, { ticket_id: '9007199254740993' }),
    frame('done', { stopReason: 'end_turn' }),
  ]));
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .resolves.toEqual({ ticketId: '9007199254740993', orderId: 9 });
});

test('ticket IDs outside PostgreSQL BIGINT are not accepted as a confirmed effect', async () => {
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: 'sid' }), streamResponse([
    refundResult(9, { ticket_id: '9223372036854775808' }),
    frame('done', { stopReason: 'end_turn' }),
  ]));
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival' }))
    .rejects.toMatchObject({ code: 'not_confirmed' });
});

test('bound refund waits for saved reference acknowledgement before chat dispatch', async () => {
  getBridgeFetchMetadata.mockReturnValue({ boundReviews: true });
  const sessionId = '11111111-1111-4111-8111-111111111111';
  const requestId = '22222222-2222-4222-8222-222222222222';
  let acknowledge;
  const beforeChat = jest.fn(() => new Promise(resolve => { acknowledge = resolve; }));
  const fetchImpl = fetchSequence(jsonResponse({ sessionId }), streamResponse([
    refundResult(9), frame('done', { stopReason: 'end_turn' }),
  ]));
  const request = requestRefundTicket({ fetchImpl, userId: 4, orderId: 9,
    reason: ' Damaged on arrival ', requestId, beforeChat });
  await Promise.resolve();
  await Promise.resolve();
  expect(beforeChat).toHaveBeenCalledWith(sessionId);
  expect(fetchImpl).toHaveBeenCalledTimes(1);
  acknowledge();
  await expect(request).resolves.toEqual({ ticketId: 71, orderId: 9 });
  expect(JSON.parse(fetchImpl.mock.calls[1][1].body)).toEqual({
    sessionId, requestId,
    message: 'Please refund order 9. Reason: Damaged on arrival',
  });
});

test('a failed reference acknowledgement prevents the bound chat POST', async () => {
  getBridgeFetchMetadata.mockReturnValue({ boundReviews: true });
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: '11111111-1111-4111-8111-111111111111' }));
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9,
    reason: 'Damaged', requestId: '22222222-2222-4222-8222-222222222222',
    beforeChat: async () => { throw Error('Storage unavailable'); },
  })).rejects.toMatchObject({ code: 'failed' });
  expect(fetchImpl).toHaveBeenCalledTimes(1);
});

test('exact saved-reference verification after ACK can stop a replaced refund before the sole chat POST', async () => {
  getBridgeFetchMetadata.mockReturnValue({ boundReviews: true });
  const sessionId = '11111111-1111-4111-8111-111111111111';
  const requestId = '22222222-2222-4222-8222-222222222222';
  const fetchImpl = fetchSequence(jsonResponse({ sessionId }));
  const beforeChat = jest.fn(async () => {});
  const verifyBeforeChat = jest.fn(() => { throw Error('reference replaced'); });
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9,
    reason: 'Damaged', requestId, beforeChat, verifyBeforeChat }))
    .rejects.toMatchObject({ code: 'failed' });
  expect(beforeChat).toHaveBeenCalledWith(sessionId);
  expect(verifyBeforeChat).toHaveBeenCalledWith(sessionId);
  expect(fetchImpl).toHaveBeenCalledTimes(1);
});

test('bounded stream overflow fails closed before a later success frame', async () => {
  const fetchImpl = fetchSequence(jsonResponse({ sessionId: 'sid' }), streamResponse([
    'x'.repeat(65), refundResult(9), frame('done', { stopReason: 'end_turn' }),
  ]));
  await expect(requestRefundTicket({ fetchImpl, userId: 4, orderId: 9, reason: 'Damaged on arrival', maxStreamBytes: 64 }))
    .rejects.toMatchObject({ code: 'uncertain' });
});
