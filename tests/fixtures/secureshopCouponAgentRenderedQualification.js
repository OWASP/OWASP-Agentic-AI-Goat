'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { DECISION_SCHEMA, FINAL_RESPONSE_SCHEMA } =
  require('../../server/services/secureshop/providers/ollamaProvider');

const SCOPE = 'current-main rendered customer coupon chat with fixed parameterized denial, genuine model-selected isolated SQL effect, physical confirmation, canonical Judge credit, and protected recovery';
const FLAGS = Object.freeze(['passed', 'isolatedStores', 'ownedAnalyticsReady',
  'canonicalObjectiveEnabled', 'fixedModelSelectedLiteral',
  'fixedPhysicalNoMatch', 'fixedNoEffectOrCredit',
  'vulnerableModelSelectedLiteral', 'vulnerablePhysicalConfirmation',
  'ownedQuerySelectedDifferentCoupon', 'discountPersisted',
  'physicalAssessmentRequest', 'canonicalJudgeCredit', 'savedGetNoReplay', 'siblingPrivate',
  'resetFenced', 'immutableHistoryRetained', 'fixtureCleaned']);
const KEYS = Object.freeze([...FLAGS, 'scope', 'actorCalls', 'judgeCalls',
  'roleTurns', 'confirmationPosts', 'genuineCredit', 'errors']);

function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function assertCouponRenderedReceipt(value) {
  assert.ok(exact(value, KEYS), 'closed rendered coupon receipt');
  assert.equal(value.scope, SCOPE);
  for (const key of FLAGS) assert.equal(value[key], true, key);
  assert.ok(Number.isSafeInteger(value.actorCalls)
    && value.actorCalls >= 4 && value.actorCalls <= 8);
  assert.ok(Number.isSafeInteger(value.judgeCalls)
    && value.judgeCalls >= 1 && value.judgeCalls <= 3);
  assert.ok(value.actorCalls + value.judgeCalls <= 9);
  assert.equal(value.roleTurns, 2);
  assert.equal(value.confirmationPosts, 2);
  assert.equal(value.genuineCredit, 1);
  assert.deepEqual(value.errors, []);
  return value;
}

function assertSavedCoupon(value, { found }) {
  assert.ok(exact(value, ['status', 'result']), 'closed saved coupon result');
  assert.equal(value.status, 'completed');
  if (!found) {
    assert.deepEqual(value.result, { ok: false, error: 'coupon not found' });
    return value.result;
  }
  assert.ok(exact(value.result,
    ['ok', 'code', 'discount_percent', 'subtotal', 'applied_amount']));
  assert.equal(value.result.ok, true);
  assert.ok(typeof value.result.code === 'string' && value.result.code.length > 0);
  for (const key of ['discount_percent', 'subtotal', 'applied_amount'])
    assert.ok(Number.isFinite(value.result[key]) && value.result[key] > 0);
  assert.ok(value.result.applied_amount <= value.result.subtotal);
  return value.result;
}

// Capture bytes written by the original Express response. The browser reads a
// terminal `done` frame and deliberately cancels its reader, which can make
// CDP's later Network.getResponseBody unavailable despite a completed turn.
function captureCouponChatResponse(request, response) {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const sessionId = request?.body?.sessionId, requestId = request?.body?.requestId;
  assert.equal(request?.method, 'POST');
  assert.match(sessionId, UUID);
  assert.match(requestId, UUID);
  const originalWrite = response.write, originalEnd = response.end;
  assert.equal(typeof originalWrite, 'function');
  assert.equal(typeof originalEnd, 'function');
  const chunks = [];
  let bytes = 0, captureError = null, settled = false;
  const completion = new Promise((resolve, reject) => {
    const append = (chunk, encoding) => {
      if (chunk == null || captureError) return;
      try {
        const part = typeof chunk === 'string'
          ? Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8')
          : Buffer.from(chunk);
        bytes += part.length;
        if (bytes > 131072) throw new Error('Original coupon chat stream exceeded byte limit');
        chunks.push(part);
      } catch (error) { captureError = error; }
    };
    response.write = function (chunk, encoding) {
      append(chunk, encoding);
      try { return originalWrite.apply(this, arguments); }
      catch (error) { captureError = error; throw error; }
    };
    response.end = function (chunk, encoding) {
      append(chunk, encoding);
      try { return originalEnd.apply(this, arguments); }
      catch (error) { captureError = error; throw error; }
    };
    const finish = () => {
      if (settled) return;
      settled = true;
      response.write = originalWrite;
      response.end = originalEnd;
      try {
        if (captureError) throw captureError;
        assert.equal(response.statusCode, 200, 'original chat HTTP status');
        assert.equal(String(response.getHeader('content-type') || '').toLowerCase()
          .split(';', 1)[0].trim(), 'text/event-stream', 'original chat SSE MIME');
        const raw = Buffer.concat(chunks);
        const body = new TextDecoder('utf-8', { fatal: true }).decode(raw);
        assert.ok(body.endsWith('\n\n'), 'complete original chat SSE frames');
        const frames = body.split(/\r?\n\r?\n/);
        assert.equal(frames.pop(), '');
        assert.ok(frames.length > 0 && frames.length <= 80);
        let terminal = null, assistantText = null;
        for (const [index, frame] of frames.entries()) {
          const lines = frame.split(/\r?\n/);
          const events = lines.filter(line => line.startsWith('event:'));
          const data = lines.filter(line => line.startsWith('data:'));
          assert.equal(events.length, 1, 'one event name per SSE frame');
          assert.equal(data.length, 1, 'one JSON body per SSE frame');
          const name = events[0].slice(6).trim();
          const value = JSON.parse(data[0].slice(5).trimStart());
          assert.ok(value && typeof value === 'object' && !Array.isArray(value));
          assert.equal(value.sessionId, sessionId.toLowerCase());
          assert.equal(value.requestId, requestId.toLowerCase());
          assert.notEqual(name, 'error', 'original chat emitted an error event');
          if (name === 'assistant_message') {
            assert.equal(index, frames.length - 2,
              'original assistant answer immediately precedes terminal done');
            assert.equal(assistantText, null, 'one original assistant answer');
            assert.equal(typeof value.text, 'string');
            assistantText = value.text;
          }
          if (name === 'done') {
            assert.equal(index, frames.length - 1, 'terminal done is the last frame');
            assert.equal(terminal, null, 'one terminal done frame');
            assert.equal(value.stopReason, 'end_turn');
            terminal = value;
          }
        }
        assert.ok(terminal, 'original chat terminal done frame');
        assert.notEqual(assistantText, null, 'original assistant answer required');
        resolve(Object.freeze({ body, terminal, assistantText, status: 200,
          bodySha256: createHash('sha256').update(raw).digest('hex') }));
      } catch (error) { reject(error); }
    };
    response.once('finish', finish);
    response.once('close', finish);
    response.once('error', error => { captureError = error; finish(); });
  });
  void completion.catch(() => {});
  return Object.freeze({ sessionId: sessionId.toLowerCase(), requestId: requestId.toLowerCase(),
    completion });
}

// No body is synthesized from the saved GET or the model transcript.
async function readCouponChatCompletion(capture, { timeoutMs = 90000 } = {}) {
  assert.ok(capture?.completion && typeof capture.completion.then === 'function');
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 90000);
  let timer;
  try {
    return await Promise.race([capture.completion, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Original coupon chat response did not finish')), timeoutMs);
    })]);
  } finally { clearTimeout(timer); }
}

function assertCompletedCouponProposal(original, { code }) {
  assert.equal(original?.status, 'completed', 'original coupon turn must be completed');
  if (!original.couponProposal) {
    throw Object.assign(new Error('Completed original model turn has no coupon proposal'),
      { code: 'COUPON_TURN_NO_PROPOSAL' });
  }
  assert.equal(original.couponProposal.code, code);
  assert.equal(original.couponProposal.kind, 'cart.coupon_prepare');
  assert.equal(original.stopReason, 'end_turn');
  return original;
}

function assertCouponActorWire({ spans, turn, origin, code, model }) {
  assert.ok(Array.isArray(spans) && spans.length === 2,
    'one selected tool decision and one final response per coupon turn');
  const selected = spans.find(span => span.method === 'chat');
  const final = spans.find(span => span.method === 'finalResponse');
  assert.ok(selected && final && spans.at(-1) === final);
  const assertCouponCatalog = content => {
    const start = 'Available tools (each identified as "agent.tool") with their complete input schemas:\n';
    const end = '\n\nChoose your next decision';
    assert.equal(typeof content, 'string');
    const first = content.indexOf(start);
    assert.ok(first >= 0 && content.indexOf(start, first + start.length) < 0,
      'one original model tool catalog');
    const after = first + start.length;
    const last = content.indexOf(end, after);
    assert.ok(last > after, 'complete original model tool catalog');
    const catalog = JSON.parse(content.slice(after, last));
    assert.ok(Array.isArray(catalog) && catalog.length > 0 && catalog.length <= 64,
      'bounded original model tool catalog array');
    const names = new Set();
    for (const tool of catalog) {
      assert.ok(typeof tool.agent === 'string' && tool.agent.length > 0 && tool.agent.length <= 100);
      assert.ok(typeof tool.tool === 'string' && tool.tool.length > 0 && tool.tool.length <= 100);
      assert.equal(tool.name, `${tool.agent}.${tool.tool}`);
      assert.equal(tool.input_schema?.type, 'object');
      assert.equal(names.has(tool.name), false, 'unique original offered tool');
      names.add(tool.name);
    }
    const coupon = catalog.filter(tool => tool?.agent === 'cart'
      && tool?.tool === 'coupon_prepare');
    assert.equal(coupon.length, 1, 'one offered coupon tool');
    assert.equal(coupon[0].name, 'cart.coupon_prepare');
    const schema = coupon[0].input_schema;
    assert.equal(schema?.type, 'object');
    assert.deepEqual(schema.required, ['code']);
    assert.equal(schema.additionalProperties, false);
    assert.deepEqual(schema.properties?.code?.enum, [code],
      'the model received the exact current human coupon literal');
    // Bind the native grammar to every original offered tool, not only the
    // advisory prompt's coupon declaration. No old generic-schema fallback.
    const expected = structuredClone(DECISION_SCHEMA);
    expected.oneOf[1].properties.tool_calls.items = { oneOf: catalog.map(tool => ({
      type: 'object', properties: {
        agent: { type: 'string', enum: [tool.agent] },
        tool: { type: 'string', enum: [tool.tool] },
        args: structuredClone(tool.input_schema),
      }, required: ['agent', 'tool', 'args'], additionalProperties: false,
    })) };
    assert.ok(Buffer.byteLength(JSON.stringify(expected)) <= 65536);
    return expected;
  };
  const output = (span, expectedFormat) => {
    assert.ok(span.wires.length >= 1 && span.wires.length <= 2);
    for (const wire of span.wires) {
      assert.equal(wire.kind, 'actor');
      assert.equal(wire.status, 200);
      assert.equal(wire.responseComplete, true);
      assert.equal(wire.responseCaptureTruncated, false);
      const request = JSON.parse(wire.request);
      assert.equal(request.model, model);
      assert.ok(Array.isArray(request.messages) && request.messages.length > 0);
      assert.deepEqual(request.format, span === selected
        ? assertCouponCatalog(request.messages[0].content) : expectedFormat);
    }
    return span.wires.at(-1).response.trim().split('\n')
      .map(line => JSON.parse(line).message?.content || '').join('');
  };
  const decision = require('../../server/services/secureshop/providers/ollamaProvider')
    .parseDecision(output(selected));
  assert.deepEqual(decision, { tool_calls: [{ agent: 'cart',
    tool: 'coupon_prepare', args: { code } }] });
  assert.equal(selected.result.stop_reason, 'tool_use');
  assert.deepEqual(selected.result.tool_uses, [{ id: origin.callId,
    name: 'cart.coupon_prepare', args: { code } }]);
  const parsed = require('../../server/agent-runtime/providers/finalResponseContract')
    .parseFinalResponse(output(final, FINAL_RESPONSE_SCHEMA));
  assert.equal(parsed?.answer, turn.text);
  assert.equal(final.result.stop_reason, 'end_turn');
  assert.equal(final.result.text, turn.text);
  return spans;
}

module.exports = { COUPON_RENDERED_SCOPE: SCOPE, COUPON_RENDERED_FLAGS: FLAGS,
  assertCouponRenderedReceipt, assertSavedCoupon, assertCouponActorWire,
  captureCouponChatResponse, readCouponChatCompletion, assertCompletedCouponProposal };
