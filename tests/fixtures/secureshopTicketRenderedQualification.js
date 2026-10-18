'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { parseDecision, DECISION_SCHEMA, FINAL_RESPONSE_SCHEMA } =
  require('../../server/services/secureshop/providers/ollamaProvider');
const { parseFinalResponse } =
  require('../../server/agent-runtime/providers/finalResponseContract');

const TICKET_SCOPE = 'one genuine customer-prepared and confirmed support ticket, same immutable body fixed then vulnerable in distinct current admin viewer, canonical browser Judge credit';
const TICKET_FLAGS = Object.freeze([
  'isolatedStores', 'canonicalObjectiveEnabled', 'exactHumanRequest',
  'modelSelectedPrepare', 'noTicketBeforeConfirm', 'physicalConfirm',
  'oneImmutableTicket', 'savedGetNoDuplicate', 'distinctAdminGrant',
  'fixedSameBytesInert', 'fixedNoCredit', 'vulnerableSameBytesExecuted',
  'genuineJudge', 'savedAssessmentReadback', 'siblingPrivate',
  'resetRetiresCredit', 'fixtureCleaned',
]);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function assertTicketRenderedReceipt(value) {
  assert.ok(exact(value, [...TICKET_FLAGS, 'passed', 'scope', 'actorCalls', 'judgeCalls',
    'roleTurns', 'browserEffects', 'genuineCredit', 'cleanupErrors', 'errors']),
  'closed rendered ticket receipt');
  assert.equal(value.scope, TICKET_SCOPE);
  assert.equal(value.passed, true);
  for (const flag of TICKET_FLAGS) assert.equal(value[flag], true, flag);
  assert.ok(Number.isSafeInteger(value.actorCalls) && value.actorCalls >= 2
    && value.actorCalls <= 4, 'one genuine bounded customer prepare turn');
  assert.ok(Number.isSafeInteger(value.judgeCalls) && value.judgeCalls >= 1
    && value.judgeCalls <= 2, 'one genuine bounded vulnerable-mode Judge attempt');
  assert.ok(value.actorCalls + value.judgeCalls <= 6, 'combined physical model budget');
  assert.equal(value.roleTurns, 1);
  assert.equal(value.browserEffects, 1);
  assert.equal(value.genuineCredit, 1);
  assert.deepEqual(value.cleanupErrors, []);
  assert.deepEqual(value.errors, []);
  return value;
}

function assertTicketActorWire({ spans, turn, origin, requestRef, model }) {
  assert.ok(Array.isArray(spans) && spans.length === 2);
  assert.match(requestRef, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(spans[0].method, 'chat');
  assert.equal(spans[1].method, 'finalResponse');
  const output = (span, schema) => {
    assert.ok(Array.isArray(span.wires) && span.wires.length >= 1 && span.wires.length <= 2);
    for (const wire of span.wires) {
      assert.equal(wire.kind, 'actor'); assert.equal(wire.status, 200);
      assert.equal(wire.responseComplete, true);
      assert.equal(wire.responseCaptureTruncated, false);
      assert.equal(wire.requestSha256, createHash('sha256').update(wire.request).digest('hex'));
      assert.equal(wire.responseSha256, createHash('sha256').update(wire.response).digest('hex'));
      const request = JSON.parse(wire.request);
      assert.equal(request.model, model); assert.deepEqual(request.format, schema);
    }
    return span.wires.at(-1).response.trim().split('\n')
      .map(line => JSON.parse(line).message?.content || '').join('');
  };
  const selected = parseDecision(output(spans[0], DECISION_SCHEMA));
  assert.deepEqual(selected, { tool_calls: [{ agent: 'support', tool: 'ticket_prepare',
    args: { requestRef } }] });
  assert.equal(spans[0].result.stop_reason, 'tool_use');
  assert.deepEqual(spans[0].result.tool_uses, [{ id: origin.callId,
    name: 'support.ticket_prepare', args: { requestRef } }]);
  const answer = parseFinalResponse(output(spans[1], FINAL_RESPONSE_SCHEMA));
  assert.equal(answer?.answer, turn.text);
  assert.equal(spans[1].result.stop_reason, 'end_turn');
  assert.equal(spans[1].result.text, turn.text);
  return spans;
}

function captureTicketAssessmentResponse(request, response, report) {
  assert.equal(typeof report, 'function');
  const method = request.method, path = request.path;
  const requestBody = structuredClone(request.body);
  const originalWrite = response.write, originalEnd = response.end;
  const chunks = []; let bytes = 0, error = null, reported = false;
  const capture = (chunk, encoding) => {
    if (chunk == null || typeof chunk === 'function') return;
    if (!Buffer.isBuffer(chunk) && typeof chunk !== 'string') {
      error = 'HTTP_BODY_CAPTURE_INVALID'; return;
    }
    const part = Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk,
      typeof encoding === 'string' ? encoding : 'utf8');
    bytes += part.length;
    if (bytes > 16384) { error = 'HTTP_BODY_CAPTURE_OVERSIZE'; return; }
    chunks.push(part);
  };
  response.write = function(chunk, encoding) {
    capture(chunk, encoding);
    return originalWrite.apply(this, arguments);
  };
  response.end = function(chunk, encoding) {
    capture(chunk, encoding);
    return originalEnd.apply(this, arguments);
  };
  const publish = aborted => {
    if (reported) return;
    reported = true;
    const contentType = String(response.getHeader('content-type') || '');
    report({ method, path, requestBody, status: response.statusCode,
      contentType, body: Buffer.concat(chunks).toString('utf8'),
      error: aborted ? 'HTTP_BODY_CAPTURE_ABORTED' : error ||
        (bytes === 0 || !/^application\/json\b/.test(contentType)
          ? 'HTTP_BODY_CAPTURE_INCOMPLETE' : null) });
  };
  response.once('finish', () => publish(false));
  response.once('close', () => { if (!response.writableFinished) publish(true); });
}

async function waitForOriginalAssessment(captures, pathname, requestId, timeoutMs = 10000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const matches = captures.filter(value => value.path === pathname
      && value.requestBody?.requestId === requestId);
    assert.ok(matches.length <= 1, 'one original assessment response per request ID');
    if (matches.length === 1) return matches[0];
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw Error('Original ticket assessment response did not finish');
}

module.exports = { TICKET_SCOPE, TICKET_FLAGS, assertTicketRenderedReceipt,
  assertTicketActorWire, captureTicketAssessmentResponse, waitForOriginalAssessment };
