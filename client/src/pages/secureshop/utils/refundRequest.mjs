import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';

import {
  parseAgentFrame,
  requireAgentContentType,
  takeAgentFrame,
} from './agentStreamProtocol.mjs';

const MAX_STREAM_BYTES = 256 * 1024;
const MAX_POSTGRES_BIGINT = 9223372036854775807n;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class RefundRequestError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'RefundRequestError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new RefundRequestError(code, message);
}

function parseSuccessfulRefund(payload, orderId) {
  if (payload?.tool !== 'support.refund_request' || payload.result?.isError === true) return null;
  const content = payload.result?.content;
  if (!Array.isArray(content) || content.length !== 1
      || content[0]?.type !== 'text' || typeof content[0].text !== 'string') return null;
  let result;
  try { result = JSON.parse(content[0].text); } catch { return null; }
  const ticketIdValid = (Number.isSafeInteger(result?.ticket_id) && result.ticket_id > 0)
    || (typeof result?.ticket_id === 'string' && /^[1-9][0-9]{0,18}$/.test(result.ticket_id)
      && BigInt(result.ticket_id) <= MAX_POSTGRES_BIGINT);
  if (!result || typeof result !== 'object' || Array.isArray(result)
      || result.ok !== true || String(result.order_id) !== String(orderId)
      || !ticketIdValid) return null;
  return Object.freeze({ ticketId: result.ticket_id, orderId: result.order_id });
}

function uncertain(message) {
  fail('uncertain', message);
}

export async function requestRefundTicket({ fetchImpl = globalThis.fetch, userId, orderId, reason,
  requestId, beforeChat, verifyBeforeChat,
  maxStreamBytes = MAX_STREAM_BYTES } = {}) {
  const refundReason = typeof reason === 'string' ? reason.trim() : '';
  const bound = Boolean(getBridgeFetchMetadata(fetchImpl)?.boundReviews);
  if (typeof fetchImpl !== 'function' || !Number.isSafeInteger(Number(userId))
      || Number(userId) <= 0 || !Number.isSafeInteger(Number(orderId)) || Number(orderId) <= 0
      || !refundReason || refundReason.length > 500
      || (bound && (!UUID.test(requestId || '') || typeof beforeChat !== 'function'
        || (verifyBeforeChat !== undefined && typeof verifyBeforeChat !== 'function')))
      || !Number.isSafeInteger(maxStreamBytes) || maxStreamBytes < 1
      || maxStreamBytes > MAX_STREAM_BYTES) {
    fail('failed', 'Refund request input is invalid');
  }

  const sessionPath = bound ? '/api/secureshop/agents/customer/refund/session' : '/api/secureshop/agents/customer/session';
  const chatPath = bound ? '/api/secureshop/agents/customer/refund/chat' : '/api/secureshop/agents/customer/chat';
  let sessionResponse;
  try {
    sessionResponse = await fetchImpl(sessionPath, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId }),
    });
  } catch { fail('failed', 'Refund service is unavailable'); }
  if (!sessionResponse?.ok) fail('failed', 'Refund session could not be created');
  try { requireAgentContentType(sessionResponse, 'application/json', 'Refund session'); }
  catch { fail('failed', 'Refund session returned an invalid response'); }
  let session;
  try { session = await sessionResponse.json(); } catch { fail('failed', 'Refund session returned invalid JSON'); }
  if (typeof session?.sessionId !== 'string' || !session.sessionId.trim()) {
    fail('failed', 'Refund session is missing its identifier');
  }
  if (bound) {
    if (!UUID.test(session.sessionId)) fail('failed', 'Refund session identifier is invalid');
    try { await beforeChat(session.sessionId); }
    catch { fail('failed', 'Refund reference could not be saved'); }
  }

  if (bound && verifyBeforeChat) {
    try { verifyBeforeChat(session.sessionId); }
    catch { fail('failed', 'Saved refund reference changed before the request was sent'); }
  }

  let chatResponse;
  try {
    chatResponse = await fetchImpl(chatPath, {
      method: 'POST', headers: { 'content-type': 'application/json', accept: 'text/event-stream' },
      body: JSON.stringify({ sessionId: session.sessionId,
        message: `Please refund order ${orderId}. Reason: ${refundReason}`,
        ...(bound ? { requestId } : {}) }),
    });
  } catch { fail('uncertain', 'Refund agent response could not be confirmed'); }
  if (!chatResponse?.ok) fail('uncertain', 'Refund agent response could not be confirmed');
  try { requireAgentContentType(chatResponse, 'text/event-stream', 'Refund agent'); }
  catch { fail('uncertain', 'Refund agent response could not be confirmed'); }
  if (!chatResponse.body || typeof chatResponse.body.getReader !== 'function') {
    fail('uncertain', 'Refund agent returned no event stream');
  }

  let reader;
  try { reader = chatResponse.body.getReader(); }
  catch { uncertain('Refund agent event stream could not be read'); }
  const decoder = new TextDecoder();
  let buffer = '';
  let bytes = 0;
  let observed = null;
  let done = false;
  try {
    readLoop: while (true) {
      let part;
      try { part = await reader.read(); }
      catch { uncertain('Refund event stream failed'); }
      if (part.done) {
        buffer += decoder.decode();
        break;
      }
      if (!ArrayBuffer.isView(part.value) || part.value.BYTES_PER_ELEMENT !== 1) {
        uncertain('Refund event stream was invalid');
      }
      bytes += part.value.byteLength;
      if (bytes > maxStreamBytes) uncertain('Refund event stream exceeded its limit');
      buffer += decoder.decode(part.value, { stream: true });
      if (new TextEncoder().encode(buffer).byteLength > maxStreamBytes) {
        uncertain('Refund event frame exceeded its limit');
      }
      while (true) {
        const extracted = takeAgentFrame(buffer);
        if (!extracted) break;
        buffer = extracted.rest;
        let event;
        try { event = parseAgentFrame(extracted.frame); }
        catch { uncertain('Refund event stream was invalid'); }
        if (!event) continue;
        if (event.name === 'tool_result') {
          observed = parseSuccessfulRefund(event.payload, orderId) || observed;
        } else if (event.name === 'error') {
          uncertain('Refund agent reported an error');
        } else if (event.name === 'done') {
          if (event.payload.stopReason !== 'end_turn') {
            uncertain('Refund agent did not finish cleanly');
          }
          done = true;
          break readLoop;
        }
      }
    }
  } finally {
    try { await reader.cancel(); } catch {}
  }
  if (!done) uncertain('Refund event stream ended before completion');
  if (!observed) fail('not_confirmed', 'The agent completed without a confirmed refund request');
  return observed;
}
