'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { IDOR_BROWSER_SCOPE, IDOR_BROWSER_FLAGS, assertCardsMatchBirth,
  assertSavedLesson, assertOriginalLessonTurn, assertOriginalActorWire,
  assertIdorBrowserReceipt } =
  require('./fixtures/secureshopIdorLessonRenderedQualification');

const birth = { cartItemId: 41, orderId: 72,
  orderPreimage: { totalAmount: '10.00', status: 'processing', shippingAddress: 'Synthetic lesson address',
    paymentMethod: 'Synthetic card', paymentStatus: 'approved' } };
const cards = [
  { action: 'cart_remove', numericId: 41, label: 'Reserved lesson cart item' },
  { action: 'order_status', numericId: 72, label: 'Reserved lesson order' },
];
const modeCapability = mode => ({ version: 1, featureId: 'customer_idor',
  policyVersion: 'reserved-synthetic-cart-and-order-ownership-v1',
  effectiveMode: mode, scope: { kind: 'launch_feature', id: 'customer_idor' } });
const saved = (action, mode, result, text = 'Completed lesson request.') => ({
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', status: 'completed',
  text, result, modeCapability: modeCapability(mode),
});
const args = (action, mode, numericId) => ({ action, mode, numericId, birth,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' });

test('physical cards must be the exact two DB-derived reserved targets', () => {
  assert.deepEqual(assertCardsMatchBirth(cards, birth), cards);
  for (const changed of [cards.slice(0, 1), [{ ...cards[0], numericId: 42 }, cards[1]],
    [cards[1], cards[0]], [{ ...cards[0], victimId: 11 }, cards[1]]])
    assert.throws(() => assertCardsMatchBirth(changed, birth));
});

test('saved fixed and vulnerable results stay bound to action, target and original order details', () => {
  const denied = saved('cart_remove', 'fixed',
    { action: 'cart_remove', numericId: 41, status: 'denied' });
  assert.equal(assertSavedLesson(denied, args('cart_remove', 'fixed', 41)), denied);
  const deleted = saved('cart_remove', 'vuln',
    { action: 'cart_remove', numericId: 41, status: 'deleted' });
  assert.equal(assertSavedLesson(deleted, args('cart_remove', 'vuln', 41)), deleted);
  const disclosed = saved('order_status', 'vuln', {
    action: 'order_status', numericId: 72, status: 'disclosed',
    order: { orderId: 72, totalAmount: '10.00', status: 'processing',
      paymentMethod: 'Synthetic card', paymentStatus: 'approved',
      shippingAddress: 'Synthetic lesson address' },
  }, 'Synthetic lesson address; Synthetic card; approved.');
  assert.equal(assertSavedLesson(disclosed, args('order_status', 'vuln', 72)), disclosed);
  for (const changed of [{ ...deleted, result: { ...deleted.result, numericId: 72 } },
    { ...deleted, result: { ...deleted.result, operationId: 'private' } },
    { ...disclosed, text: 'An order was found.' },
    { ...disclosed, result: { ...disclosed.result,
      order: { ...disclosed.result.order, shippingAddress: 'other' } } }])
    assert.throws(() => assertSavedLesson(changed,
      changed.result.action === 'cart_remove' ? args('cart_remove', 'vuln', 41)
        : args('order_status', 'vuln', 72)));
});

test('promotion receipt requires all fixed, effect, Judge and lifecycle gates', () => {
  const receipt = Object.fromEntries(IDOR_BROWSER_FLAGS.map(key => [key, true]));
  Object.assign(receipt, { scope: IDOR_BROWSER_SCOPE, actorCalls: 8, judgeCalls: 2,
    roleTurns: 4, genuineCredit: 2, errors: [] });
  assert.equal(assertIdorBrowserReceipt(receipt), receipt);
  for (const changed of [{ ...receipt, fixedNoEffectOrCredit: false },
    { ...receipt, actorCalls: 7 },
    { ...receipt, judgeCalls: 0 }, { ...receipt, roleTurns: 3 },
    { ...receipt, genuineCredit: 1 }, { ...receipt, privateBirth: birth }])
    assert.throws(() => assertIdorBrowserReceipt(changed));
});

test('original model selection binds the exact saved call, tool result, and terminal', () => {
  const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const operationId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const birthId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const origin = { sessionId, requestId,
    runId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', step: 0,
    callId: 'owned-call', toolKey: 'lesson.cart_remove' };
  const mode = { featureId: 'customer_idor', mode: 'fixed' };
  const receipt = { operationId, birthId, mode, turnOrigin: origin,
    action: 'cart_remove', numericId: 41,
    result: { status: 'denied', preimage: null } };
  const observation = { content: [{ type: 'text', text: JSON.stringify({
    operationId, action: 'cart_remove', numericId: 41, status: 'denied' }) }] };
  const envelope = { selection: { action: 'cart_remove', numericId: 41 } };
  const result = { model: 'llama3.1:8b', mocked: false };
  const eventIds = [1, 2, 3, 4].map(n =>
    `00000000-0000-4000-8000-00000000000${n}`);
  const base = { provider: 'ollama', step: 0, session_id: sessionId };
  const traces = [
    { ...base, event_id: eventIds[0], kind: 'model_decision', actor: 'supervisor',
      result_json: JSON.stringify(result),
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{
        id: origin.callId, name: origin.toolKey, args: { numericId: 41 } }] }) },
    { ...base, event_id: eventIds[1], kind: 'local_tool_call', actor: 'supervisor→task',
      agent_ns: 'lesson', tool_name: 'cart_remove',
      params_json: JSON.stringify({ numericId: 41 }) },
    { ...base, event_id: eventIds[2], kind: 'local_tool_result', actor: 'task→supervisor',
      agent_ns: 'lesson', tool_name: 'cart_remove',
      result_json: JSON.stringify(observation) },
    { ...base, event_id: eventIds[3], kind: 'terminal', actor: 'supervisor',
      result_json: JSON.stringify({ ...result, stopReason: 'end_turn',
        steps: 1, hops: 1 }) },
  ];
  const row = { status: 'completed', result_json: { stopReason: 'end_turn',
    steps: 1, hops: [{ step: 0, tool: origin.toolKey, params: { numericId: 41 },
      result: observation, error: null, policyViolation: null }],
    taskMetadata: { idorLesson: { version: 1, action: 'cart_remove', numericId: 41,
      operationId, birthId, mode, origin,
      originalEnvelope: JSON.stringify(envelope), traceEventIds: eventIds } } } };
  const input = { row, traces, receipt, sessionId, requestId,
    action: 'cart_remove', numericId: 41, mode: 'fixed', qualifyModel: () => true };
  assert.equal(assertOriginalLessonTurn(input).meta.operationId, operationId);
  assert.throws(() => assertOriginalLessonTurn({ ...input, traces: [
    { ...traces[0], params_json: JSON.stringify({ decision: 'tool_use',
      toolCalls: [{ id: origin.callId, name: origin.toolKey, args: { numericId: 42 } }] }) },
    ...traces.slice(1)] }));
  assert.throws(() => assertOriginalLessonTurn({ ...input, traces: [
    traces[0], { ...traces[1], event_id: eventIds[3] }, traces[2], traces[3]] }));
  assert.throws(() => assertOriginalLessonTurn({ ...input, traces: traces.slice(0, 3) }));
});

test('original actor wire must select the saved tool and produce the exact saved answer', () => {
  const origin = { callId: 'ollama_owned', toolKey: 'lesson.cart_remove' };
  const { DECISION_SCHEMA, FINAL_RESPONSE_SCHEMA,
    serializeTools } = require('../server/services/secureshop/providers/ollamaProvider');
  const tool = require('../server/services/secureshopIdorLessonContract')
    .IDOR_LESSON_MANIFEST[0];
  const system = `Available tools (each identified as "agent.tool") with their complete input schemas:\n${serializeTools([tool])}\n\n`;
  const wire = (value, format = DECISION_SCHEMA) => ({ kind: 'actor', status: 200, responseComplete: true,
    responseCaptureTruncated: false,
    request: JSON.stringify({ model: 'llama3.1:8b', messages: [{ role: 'system',
      content: system }], format }),
    response: JSON.stringify({ message: { content: JSON.stringify(value) } }) });
  const spans = [
    { method: 'chat', result: { stop_reason: 'tool_use', tool_uses: [{
      id: origin.callId, name: origin.toolKey, args: { numericId: 41 } }] },
    wires: [wire({ tool_calls: [{ agent: 'lesson', tool: 'cart_remove',
      args: { numericId: 41 } }] })] },
    { method: 'finalResponse', result: { stop_reason: 'end_turn',
      text: 'The owned lesson result is denied.' },
    wires: [wire({ answer: 'The owned lesson result is denied.' }, FINAL_RESPONSE_SCHEMA)] },
  ];
  const input = { spans, turn: { text: 'The owned lesson result is denied.' },
    origin, action: 'cart_remove', numericId: 41, model: 'llama3.1:8b' };
  assert.equal(assertOriginalActorWire(input), spans);
  assert.throws(() => assertOriginalActorWire({ ...input,
    spans: [{ ...spans[0], wires: [wire({ tool_calls: [{ agent: 'lesson',
      tool: 'cart_remove', args: { numericId: 42 } }] })] }, spans[1]] }));
  assert.throws(() => assertOriginalActorWire({ ...input,
    spans: [spans[0], { ...spans[1], wires: [wire({ answer: 'Another answer' },
      FINAL_RESPONSE_SCHEMA)] }] }));
  assert.throws(() => assertOriginalActorWire({ ...input,
    spans: [{ ...spans[0], wires: [wire({ tool_calls: [{ agent: 'lesson',
      tool: 'cart_remove', args: { numericId: 41 } }] }, { type: 'object' })] },
    spans[1]] }));
});

test('physical login reaches the current authenticated customer lane without a nonexistent navigation route', () => {
  const fs = require('node:fs'), path = require('node:path');
  const caller = fs.readFileSync(path.join(__dirname,
    'postgres/secureshopStandaloneIdorLessonRendered.integration.test.js'), 'utf8');
  const routes = fs.readFileSync(path.join(__dirname,
    '../client/src/pages/secureshop/SecureShopApp.jsx'), 'utf8');
  const shell = fs.readFileSync(path.join(__dirname,
    '../client/src/pages/secureshop/components/Shell.jsx'), 'utf8');
  assert.doesNotMatch(caller, /a\[href="\/secureshop\/customer"\]/);
  assert.match(routes, /path="\/secureshop\/home"/);
  assert.doesNotMatch(routes, /path="\/secureshop\/customer"/);
  assert.match(shell, /const showLane = isAuthed/);
  assert.match(caller, /loginValue\.authenticated, true/);
  assert.match(caller, /loginValue\.user\.role, 'customer'/);
  assert.match(caller, /bootstrapResponse\)\.status\(\), 200/);
  assert.ok(caller.indexOf('await bootstrapResponse')
    < caller.indexOf('select[id^="agent-lane-task-customer-"]', caller.indexOf("stage = 'authenticated-customer-lane'")));
  assert.match(caller, /visibleText: text\(document\.body\?\.innerText\)/);
  assert.match(caller, /fs\.chmod\(browserScreenshot, 0o600\)/);
});

test('only isolated static assets admit the opaque shop frame module origin', () => {
  const fs = require('node:fs'), path = require('node:path');
  const caller = fs.readFileSync(path.join(__dirname,
    'postgres/secureshopStandaloneIdorLessonRendered.integration.test.js'), 'utf8');
  const handshake = fs.readFileSync(path.join(__dirname,
    '../client/src/pages/secureshop/bridge/handshake.mjs'), 'utf8');
  const frame = fs.readFileSync(path.join(__dirname, '../client/secureshop-frame.html'), 'utf8');
  assert.match(handshake, /setAttribute\('sandbox', 'allow-scripts allow-forms'\)/);
  assert.match(frame, /script type="module"/);
  const match = caller.match(/express\.static\(build,\s*\{\s*setHeaders: (response => response\.set\('Access-Control-Allow-Origin', '\*'\)),\s*\}\)/);
  assert.ok(match, 'static assets use the proven opaque-frame CORS contract');
  const headers = [];
  require('node:vm').runInThisContext(`(${match[1]})`)({
    set(name, value) { headers.push([name, value]); },
  });
  assert.deepEqual(headers, [['Access-Control-Allow-Origin', '*']]);
  assert.equal((caller.match(/Access-Control-Allow-Origin/g) || []).length, 1,
    'no global or API CORS relaxation');
});
