'use strict';

const assert = require('node:assert/strict');
const { isQualifiedSecureShopModelTrace } = require('../../server/services/secureshopRealModelTrace');
const { IDOR_LESSON_TOOLS } = require('../../server/services/secureshopIdorLessonContract');
const { projectIdorLessonObservation } = require('../../server/services/secureshopIdorLessonTools');
const { IDOR_LESSON_MANIFEST } = require('../../server/services/secureshopIdorLessonContract');
const { DECISION_SCHEMA, FINAL_RESPONSE_SCHEMA,
  serializeTools } = require('../../server/services/secureshop/providers/ollamaProvider');

const SCOPE = 'current-main rendered customer access-control lesson with fixed denials, two genuine model-selected reserved-ID effects, canonical Judge credit, and protected recovery';
const FLAGS = Object.freeze(['passed', 'isolatedStores', 'canonicalObjectivesEnabled',
  'renderedFixedCartDenied', 'renderedFixedOrderDenied', 'fixedNoEffectOrCredit',
  'modelSelectedCartId', 'renderedCartDeletion', 'cartJudgeCredit',
  'modelSelectedOrderId', 'renderedOrderDisclosure', 'orderJudgeCredit',
  'savedReloadGetOnly', 'exactReplayNoRerun', 'siblingPrivate', 'resetFenced',
  'immutableHistoryRetained', 'fixtureCleaned']);
const LABELS = Object.freeze({ cart_remove: 'Reserved lesson cart item',
  order_status: 'Reserved lesson order' });

function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function assertCardsMatchBirth(cards, birth) {
  assert.ok(Array.isArray(cards) && cards.length === 2);
  assert.ok(Number.isSafeInteger(birth?.cartItemId) && birth.cartItemId > 0);
  assert.ok(Number.isSafeInteger(birth?.orderId) && birth.orderId > 0);
  assert.deepEqual(cards, [
    { action: 'cart_remove', numericId: birth.cartItemId, label: LABELS.cart_remove },
    { action: 'order_status', numericId: birth.orderId, label: LABELS.order_status },
  ]);
  return cards;
}

function assertSavedLesson(value, { sessionId, requestId, action, numericId, mode, birth }) {
  assert.ok(exact(value, ['sessionId', 'requestId', 'status', 'text', 'result', 'modeCapability']));
  assert.equal(value.sessionId, sessionId);
  assert.equal(value.requestId, requestId);
  assert.equal(value.status, 'completed');
  assert.ok(typeof value.text === 'string' && value.text.trim());
  assert.ok(exact(value.modeCapability,
    ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope']));
  assert.equal(value.modeCapability.featureId, 'customer_idor');
  assert.equal(value.modeCapability.effectiveMode, mode);
  const expected = { action, numericId,
    status: mode === 'fixed' ? 'denied'
      : action === 'cart_remove' ? 'deleted' : 'disclosed' };
  if (mode === 'vuln' && action === 'order_status') {
    assert.ok(exact(value.result, ['action', 'numericId', 'status', 'order']));
    assert.deepEqual({ action: value.result.action, numericId: value.result.numericId,
      status: value.result.status }, expected);
    const order = value.result.order;
    assert.ok(exact(order, ['orderId', 'totalAmount', 'status', 'paymentMethod',
      'paymentStatus', 'shippingAddress']));
    assert.equal(order.orderId, birth.orderId);
    assert.equal(order.totalAmount, birth.orderPreimage.totalAmount);
    for (const key of ['status', 'paymentMethod', 'paymentStatus', 'shippingAddress']) {
      assert.equal(order[key], birth.orderPreimage[key]);
    }
    for (const key of ['shippingAddress', 'paymentMethod', 'paymentStatus']) {
      assert.ok(value.text.includes(birth.orderPreimage[key]), `visible model answer includes ${key}`);
    }
  } else {
    assert.deepEqual(value.result, expected);
  }
  return value;
}

function assertOriginalLessonTurn({ row, traces, receipt, sessionId, requestId,
  action, numericId, mode, qualifyModel }) {
  assert.equal(row?.status, 'completed');
  const turn = row.result_json, meta = turn?.taskMetadata?.idorLesson;
  assert.equal(turn?.stopReason, 'end_turn');
  assert.equal(meta?.version, 1);
  assert.equal(meta?.action, action);
  assert.equal(meta?.numericId, numericId);
  assert.equal(meta?.operationId, receipt.operationId);
  assert.equal(meta?.birthId, receipt.birthId);
  assert.deepEqual(meta?.mode, receipt.mode);
  assert.equal(meta?.mode?.mode, mode);
  assert.equal(meta?.origin?.sessionId, sessionId);
  assert.equal(meta?.origin?.requestId, requestId);
  assert.equal(meta?.origin?.toolKey, IDOR_LESSON_TOOLS[action]);
  assert.deepEqual(meta?.origin, receipt.turnOrigin);
  assert.deepEqual(meta?.traceEventIds, traces?.map(trace => trace.event_id.toLowerCase()));
  const envelope = JSON.parse(meta.originalEnvelope);
  assert.deepEqual(envelope.selection, { action, numericId });
  assert.equal(meta.originalEnvelope, JSON.stringify(envelope));
  assert.ok(Array.isArray(turn.hops) && turn.hops.length === 1);
  const hop = turn.hops[0];
  assert.equal(hop.step, meta.origin.step);
  assert.equal(hop.tool, meta.origin.toolKey);
  assert.deepEqual(hop.params, { numericId });
  assert.equal(hop.error, null);
  assert.equal(hop.policyViolation, null);
  assert.deepEqual(hop.result,
    projectIdorLessonObservation(receipt, action, numericId, meta.origin));
  assert.ok(Array.isArray(traces) && traces.length >= 4);
  const parse = text => JSON.parse(text);
  const selected = traces.findIndex(trace => {
    if (trace.kind !== 'model_decision' || trace.actor !== 'supervisor'
        || trace.step !== meta.origin.step
        || !isQualifiedSecureShopModelTrace(trace, qualifyModel)) return false;
    const params = parse(trace.params_json);
    return params.decision === 'tool_use' && params.toolCalls?.length === 1
      && params.toolCalls[0].id === meta.origin.callId
      && params.toolCalls[0].name === meta.origin.toolKey
      && require('node:util').isDeepStrictEqual(params.toolCalls[0].args,
        { numericId });
  });
  assert.ok(selected >= 0, 'qualified model selected exact reserved ID');
  const [agent, tool] = meta.origin.toolKey.split('.');
  const call = traces.findIndex((trace, index) => index > selected
    && trace.kind === 'local_tool_call' && trace.actor === 'supervisor→task'
    && trace.step === meta.origin.step && trace.agent_ns === agent
    && trace.tool_name === tool && require('node:util').isDeepStrictEqual(
      parse(trace.params_json), { numericId }));
  assert.ok(call > selected);
  const result = traces.findIndex((trace, index) => index > call
    && trace.kind === 'local_tool_result' && trace.actor === 'task→supervisor'
    && trace.step === meta.origin.step && trace.agent_ns === agent
    && trace.tool_name === tool && require('node:util').isDeepStrictEqual(
      parse(trace.result_json), hop.result));
  assert.ok(result > call);
  const terminal = traces.at(-1), final = parse(terminal?.result_json);
  assert.equal(terminal?.kind, 'terminal');
  assert.equal(terminal.actor, 'supervisor');
  assert.ok(isQualifiedSecureShopModelTrace(terminal, qualifyModel));
  assert.equal(terminal.provider, traces[selected].provider);
  assert.equal(final.model, parse(traces[selected].result_json).model);
  assert.equal(final.stopReason, 'end_turn');
  assert.equal(final.steps, turn.steps);
  assert.equal(final.hops, turn.hops.length);
  return { turn, meta };
}

function assertOriginalActorWire({ spans, turn, origin, action, numericId, model }) {
  assert.ok(Array.isArray(spans) && spans.length >= 2 && spans.length <= 4);
  const output = (wire, expectedFormat) => {
    assert.equal(wire.kind, 'actor');
    assert.equal(wire.status, 200);
    assert.equal(wire.responseComplete, true);
    assert.equal(wire.responseCaptureTruncated, false);
    const request = JSON.parse(wire.request);
    assert.equal(request.model, model);
    assert.ok(Array.isArray(request.messages) && request.messages.length > 0);
    assert.deepEqual(request.format, expectedFormat);
    if (expectedFormat === DECISION_SCHEMA) {
      const selected = IDOR_LESSON_MANIFEST.filter(tool =>
        `${tool.agent}.${tool.tool}` === IDOR_LESSON_TOOLS[action]);
      assert.equal(selected.length, 1);
      assert.ok(request.messages[0].content.includes(
        `Available tools (each identified as "agent.tool") with their complete input schemas:\n${serializeTools(selected)}\n\n`));
    }
    return wire.response.trim().split('\n')
      .map(line => JSON.parse(line).message?.content || '').join('');
  };
  const selections = spans.filter(span => span.method === 'chat');
  const finals = spans.filter(span => span.method === 'finalResponse');
  assert.equal(selections.length, 1);
  assert.equal(finals.length, 1);
  assert.equal(spans.at(-1), finals[0]);
  const selected = selections[0], final = finals[0];
  assert.ok(selected.wires.length >= 1 && selected.wires.length <= 2);
  assert.ok(final.wires.length >= 1 && final.wires.length <= 2);
  const decision = JSON.parse(output(selected.wires.at(-1), DECISION_SCHEMA));
  assert.deepEqual(decision, { tool_calls: [{ agent: 'lesson',
    tool: action, args: { numericId } }] });
  assert.equal(selected.result.stop_reason, 'tool_use');
  assert.deepEqual(selected.result.tool_uses, [{ id: origin.callId,
    name: IDOR_LESSON_TOOLS[action], args: { numericId } }]);
  const parsed = require('../../server/agent-runtime/providers/finalResponseContract')
    .parseFinalResponse(output(final.wires.at(-1), FINAL_RESPONSE_SCHEMA));
  assert.equal(parsed?.answer, turn.text);
  assert.equal(final.result.stop_reason, 'end_turn');
  assert.equal(final.result.text, turn.text);
  return spans;
}

function assertIdorBrowserReceipt(value) {
  assert.ok(exact(value, [...FLAGS, 'scope', 'actorCalls', 'judgeCalls',
    'roleTurns', 'genuineCredit', 'errors']));
  assert.equal(value.scope, SCOPE);
  for (const key of FLAGS) assert.equal(value[key], true, key);
  assert.ok(Number.isSafeInteger(value.actorCalls) && value.actorCalls >= 8
    && value.actorCalls <= 10);
  assert.ok(Number.isSafeInteger(value.judgeCalls) && value.judgeCalls >= 2
    && value.judgeCalls <= 4);
  assert.equal(value.roleTurns, 4);
  assert.equal(value.genuineCredit, 2);
  assert.deepEqual(value.errors, []);
  return value;
}

module.exports = { IDOR_BROWSER_SCOPE: SCOPE, IDOR_BROWSER_FLAGS: FLAGS,
  assertCardsMatchBirth, assertSavedLesson, assertOriginalLessonTurn,
  assertOriginalActorWire,
  assertIdorBrowserReceipt };
