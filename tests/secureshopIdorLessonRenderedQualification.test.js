'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { IDOR_BROWSER_SCOPE, IDOR_BROWSER_FLAGS, assertCardsMatchBirth,
  assertSavedLesson, assertOriginalLessonTurn, assertOriginalActorWire,
  assertIdorBrowserReceipt, assertPrivateIdorEvidencePath,
  admitDisposableIdorCandidate } =
  require('./fixtures/secureshopIdorLessonRenderedQualification');

test('V12 candidate is a disposable, exact-source CAS; public defaults stay pending', async t => {
  const prior = process.env.PG_TEST_DISPOSABLE;
  t.after(() => { if (prior === undefined) delete process.env.PG_TEST_DISPOSABLE;
    else process.env.PG_TEST_DISPOSABLE = prior; });
  const curriculum = require('../server/config/secureshopCurriculum');
  const orderId = 'ss_idor_order_status_disclosure';
  const cart = { objectiveId: 'ss_idor_cart_delete', qualification: 'native-model',
    enabled: false, revision: '1' };
  const order = { objectiveId: orderId, qualification: 'pending',
    enabled: false, revision: '1' };
  const queries = [], sets = [];
  const migration = { async query(sql, params) {
    queries.push({ sql, params });
    if (order.qualification !== 'pending') return { rowCount: 0, rows: [] };
    order.qualification = 'native-model';
    return { rowCount: 1, rows: [{ objective_id: orderId,
      qualification: 'native-model', is_enabled: false }] };
  } };
  const catalog = {
    async list() { return { objectives: [cart, order].map(row => ({ ...row })) }; },
    async set(_context, input) {
      sets.push(input);
      const row = [cart, order].find(candidate => candidate.objectiveId === input.objectiveId);
      if (row.qualification !== 'native-model') throw Object.assign(Error('unqualified'),
        { code: 'SHOP_OBJECTIVE_UNQUALIFIED' });
      row.enabled = input.enabled;
      return { ...row };
    },
  };
  const argumentsFor = () => ({ migration, catalog, administratorContext: {}, curriculum,
    activeObjectiveIds: [cart.objectiveId, orderId] });
  delete process.env.PG_TEST_DISPOSABLE;
  await assert.rejects(admitDisposableIdorCandidate(argumentsFor()));
  assert.equal(queries.length, 0);
  process.env.PG_TEST_DISPOSABLE = 'yes';
  const result = await admitDisposableIdorCandidate(argumentsFor());
  assert.deepEqual(result, { fixtureLocalCandidateAdmission: true,
    publicOrderQualification: 'pending', publicOrderDefaultEnabled: false });
  assert.equal(curriculum.isAssessmentReleaseAllowed(orderId), false);
  assert.equal(curriculum.OBJECTIVES.find(row => row.id === orderId).qualification, 'pending');
  assert.equal(queries.length, 1);
  assert.match(queries[0].sql, /qualification='pending'[\s\S]*is_enabled=false[\s\S]*configuration_source='checked_in_default'/);
  assert.equal(queries[0].params[0], orderId);
  const expectedSource = JSON.stringify({ version: 1, id: orderId,
    label: curriculum.OBJECTIVES.find(row => row.id === orderId).text,
    defaultEnabled: false, qualification: 'pending' });
  assert.equal(queries[0].params[2], expectedSource);
  assert.equal(queries[0].params[1], require('node:crypto').createHash('sha256')
    .update(expectedSource).digest('hex'));
  assert.deepEqual(sets.map(set => set.objectiveId), [orderId, cart.objectiveId, orderId]);
  assert.equal(sets[0].enabled, true); // Initial public denial, before the CAS.
  assert.equal(sets[2].enabled, true);
});

test('V12 candidate refuses a stale or foreign seed without enabling order', async t => {
  const prior = process.env.PG_TEST_DISPOSABLE;
  t.after(() => { if (prior === undefined) delete process.env.PG_TEST_DISPOSABLE;
    else process.env.PG_TEST_DISPOSABLE = prior; });
  process.env.PG_TEST_DISPOSABLE = 'yes';
  const orderId = 'ss_idor_order_status_disclosure';
  const rows = [
    { objectiveId: 'ss_idor_cart_delete', qualification: 'native-model', enabled: false,
      revision: '1' },
    { objectiveId: orderId, qualification: 'pending', enabled: false, revision: '1' },
  ];
  let enabledOrder = false, updates = 0, enabledCart = false;
  const catalog = {
    async list() { return { objectives: rows.map(row => ({ ...row })) }; },
    async set(_context, input) {
      if (input.objectiveId === orderId) {
        if (rows[1].qualification === 'pending') throw Object.assign(Error('unqualified'),
          { code: 'SHOP_OBJECTIVE_UNQUALIFIED' });
        enabledOrder = true;
      } else enabledCart = true;
      return { enabled: true };
    },
  };
  await assert.rejects(admitDisposableIdorCandidate({
    migration: { async query() { updates++; return { rowCount: 0, rows: [] }; } },
    catalog, administratorContext: {},
    curriculum: require('../server/config/secureshopCurriculum'),
    activeObjectiveIds: rows.map(row => row.objectiveId),
  }));
  assert.equal(updates, 1);
  assert.equal(enabledOrder, false);
  assert.equal(enabledCart, false);
});

test('current-host IDOR receipt must be new, private, and inside this checkout; legacy stays external', async t => {
  const checkout = path.resolve(__dirname, '..');
  const tempCandidate = process.env.DVAIA_REPO_LOCAL_UNIT_RUNTIME || process.env.TMPDIR;
  const tempParent = tempCandidate && path.resolve(tempCandidate).startsWith(
    `${checkout}${path.sep}tasks${path.sep}tmp${path.sep}`)
    ? path.resolve(tempCandidate) : path.join(checkout, 'tasks', 'tmp');
  const root = fs.mkdtempSync(path.join(tempParent, 'idor-path-'));
  fs.mkdirSync(path.join(root, 'tasks'));
  const qualification = path.join(root, 'tasks', 'qualification');
  const profileRoot = path.join(root, '.qualification');
  fs.mkdirSync(qualification, { mode: 0o700 });
  fs.mkdirSync(profileRoot, { mode: 0o700 });
  const run = fs.mkdtempSync(path.join(qualification, 'run-'));
  const profile = path.join(profileRoot, `goat-i-${randomUUID().slice(0, 6)}`);
  fs.mkdirSync(profile, { mode: 0o700 });
  const socket = path.join(profile, 'docker.sock');
  const realLstat = fs.lstatSync;
  t.mock.method(fs, 'lstatSync', (target, ...options) => target === socket
    ? { isSocket: () => true, isSymbolicLink: () => false, uid: process.getuid() }
    : realLstat(target, ...options));
  t.after(() => {
    fs.rmdirSync(profile);
    fs.rmdirSync(run);
    fs.rmdirSync(profileRoot);
    fs.rmdirSync(qualification);
    fs.rmdirSync(path.join(root, 'tasks'));
    fs.rmdirSync(root);
  });
  const dockerHost = `unix://${socket}`;
  const evidencePath = path.join(run, 'customer-idor-lesson-browser.json');
  assert.equal(assertPrivateIdorEvidencePath(evidencePath, { root, dockerHost }), evidencePath);
  const cartPath = path.join(run, 'customer-idor-cart-v10-browser.json');
  assert.equal(assertPrivateIdorEvidencePath(cartPath, { root, dockerHost, cartOnly: true }), cartPath);
  assert.throws(() => assertPrivateIdorEvidencePath('/tmp/legacy-id-or/receipt.json', { root, dockerHost }));
  assert.throws(() => assertPrivateIdorEvidencePath(evidencePath, { root, dockerHost,
    cartOnly: true }));
  assert.throws(() => assertPrivateIdorEvidencePath(path.join(run, '..', 'elsewhere.json'),
    { root, dockerHost }));
  fs.chmodSync(run, 0o755);
  assert.throws(() => assertPrivateIdorEvidencePath(evidencePath, { root, dockerHost }));
  fs.chmodSync(run, 0o700);
  fs.writeFileSync(evidencePath, 'old receipt');
  assert.throws(() => assertPrivateIdorEvidencePath(evidencePath, { root, dockerHost }));
  fs.unlinkSync(evidencePath);
  fs.symlinkSync(path.join(run, 'missing-receipt.json'), evidencePath);
  assert.throws(() => assertPrivateIdorEvidencePath(evidencePath, { root, dockerHost }));
  fs.unlinkSync(evidencePath);
  assert.equal(assertPrivateIdorEvidencePath('/tmp/legacy-id-or/receipt.json',
    { root, dockerHost: 'unix:///legacy/docker.sock' }), '/tmp/legacy-id-or/receipt.json');
  assert.throws(() => assertPrivateIdorEvidencePath(evidencePath,
    { root, dockerHost: 'unix:///legacy/docker.sock' }));
});

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
