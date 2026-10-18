'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { COUPON_RENDERED_SCOPE, COUPON_RENDERED_FLAGS,
  assertCouponRenderedReceipt, assertSavedCoupon, assertCouponActorWire,
  captureCouponChatResponse, readCouponChatCompletion, assertCompletedCouponProposal } =
  require('./fixtures/secureshopCouponAgentRenderedQualification');

const CHAT_SESSION = '3220c0c2-476e-4dd5-97e4-734987060afb';
const CHAT_REQUEST = 'a3b8c144-66ac-4446-bc3c-f86127f8d687';
function originalResponse({ status = 200, contentType = 'text/event-stream; charset=utf-8',
  failMethod = null } = {}) {
  const response = new EventEmitter(), forwarded = [];
  response.statusCode = status;
  response.getHeader = name => name.toLowerCase() === 'content-type' ? contentType : undefined;
  response.write = function (chunk) {
    if (failMethod === 'write') throw new Error('original write failed');
    forwarded.push(chunk); return true;
  };
  response.end = function (chunk) {
    if (failMethod === 'end') throw new Error('original end failed');
    if (chunk != null) forwarded.push(chunk);
    this.emit('finish');
    return this;
  };
  const capture = captureCouponChatResponse({ method: 'POST', body: {
    sessionId: CHAT_SESSION, requestId: CHAT_REQUEST } }, response);
  return { response, capture, forwarded };
}
const assistantFrame = (changes = {}) => `event: assistant_message\ndata: ${JSON.stringify({
  sessionId: CHAT_SESSION, requestId: CHAT_REQUEST,
  text: 'There are no older orders to list.', ...changes })}\n\n`;
const doneFrame = (changes = {}) => `event: done\ndata: ${JSON.stringify({
  sessionId: CHAT_SESSION, requestId: CHAT_REQUEST, stopReason: 'end_turn',
  ...changes })}\n\n`;
const completeStream = (changes = {}) => assistantFrame() + doneFrame(changes);

const receipt = () => ({ ...Object.fromEntries(COUPON_RENDERED_FLAGS.map(key => [key, true])),
  scope: COUPON_RENDERED_SCOPE, actorCalls: 4, judgeCalls: 1,
  roleTurns: 2, confirmationPosts: 2, genuineCredit: 1, errors: [] });

test('valid sibling coupon lookup denies only the foreign proposal without reading or applying it', async () => {
  const { createCouponAgentConfirmation } = require('../server/services/secureshopCouponAgentConfirmation');
  const { publicError } = require('../server/routes/secureshop/boundCouponAgentConfirm');
  const scope = { launchId: CHAT_SESSION, scenarioId: CHAT_REQUEST, generation: 1,
    platformOwnerId: 14, platformSessionId: 15 };
  const persona = { id: 16, role: 'customer' };
  let bindings = 0, forbiddenReads = 0, effects = 0, modelCalls = 0;
  const forbidden = async () => { forbiddenReads++; throw Error('foreign data read'); };
  const state = { scope, persona, personaSession: { sessionId: CHAT_SESSION, authorityVersion: 1 },
    check: async () => {}, target: { scene: { grantId: CHAT_REQUEST } },
    mode: { snapshot: { featureId: 'customer_chat', mode: 'vuln' }, assertCurrent: async () => {} },
    couponMode: { snapshot: { featureId: 'coupons', mode: 'vuln' }, assertCurrent: async () => {} } };
  const confirmation = createCouponAgentConfirmation({ captureCurrent: async () => state,
    bindingRepository: { read: async input => {
      bindings++;
      assert.equal(input.scope.platformOwnerId, scope.platformOwnerId);
      assert.equal(input.scope.platformSessionId, scope.platformSessionId);
      assert.deepEqual(input.persona, persona);
      assert.equal(input.sessionId, CHAT_SESSION);
      assert.equal(input.requestId, CHAT_REQUEST);
      return null; // Exact current-owner query cannot see the other owner's turn.
    } }, journal: { readBoundRequest: forbidden },
    conversations: { getMessages: forbidden, getTraceEvents: forbidden },
    readConfirmedCoupon: forbidden, applyConfirmedCoupon: async () => { effects++; },
    qualifyModel: () => { modelCalls++; throw Error('unexpected model qualification'); } });
  let error;
  try { await confirmation.readSaved({}, { sessionId: CHAT_SESSION,
    requestId: CHAT_REQUEST, proposalId: CHAT_SESSION }); } catch (caught) { error = caught; }
  assert.equal(error?.code, 'COUPON_AGENT_SOURCE_INVALID');
  const reply = publicError(error);
  assert.deepEqual(reply, { status: 409, unavailable: false, message: 'Coupon proposal unavailable' });
  assert.deepEqual({ bindings, forbiddenReads, effects, modelCalls },
    { bindings: 1, forbiddenReads: 0, effects: 0, modelCalls: 0 });
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopCustomerCouponRendered.integration.test.js'), 'utf8');
  const helper = source.slice(source.indexOf('function assertCouponSiblingDenial('),
    source.indexOf('function storeUrls('));
  const check = new Function('assert', `${helper}; return assertCouponSiblingDenial;`)(assert);
  const denied = { status: reply.status, body: { error: reply.message }, launchState: null };
  check(denied);
  for (const changes of [{ status: 401 }, { status: 200 }, { status: 503 },
    { body: { error: reply.message, result: { code: 'foreign' } } },
    { body: { error: 'Shop session unavailable' } }, { launchState: 'unavailable' }])
    assert.throws(() => check({ ...denied, ...changes }));
});

test('rendered coupon enters the authenticated customer lane without the retired customer link', () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopCustomerCouponRendered.integration.test.js'), 'utf8');
  assert.ok(!source.includes('a[href="/secureshop/customer"]'));
  assert.ok(source.includes("waitResponse(page, 'POST', '/api/secureshop/auth/login', 20000)"));
  assert.ok(source.includes("waitResponse(page, 'POST', '/api/secureshop/auth/bootstrap', 20000)"));
  assert.ok(source.includes('select[id^="agent-lane-task-customer-"]'));
  assert.ok(source.includes('a[href="/secureshop/cart"]'));
  assert.ok(source.includes("waitResponse(page, 'GET', '/api/secureshop/cart', 20000)"));
  assert.ok(source.indexOf('const completedCart = await cartResponse;')
    < source.indexOf('await frame.click(\'a[href="/secureshop/cart"]\')'));
  assert.ok(source.includes('const ownerHeaders = headersFrom(completedCart.request());'));
  assert.ok(!source.includes('authorityRequests.at(-1)'));
  assert.ok(source.includes("request.path === '/agents/customer/chat'"));
  assert.ok(!source.includes("request.path.startsWith('/agents/customer/chat/')"));
  assert.ok(source.includes("request.path.startsWith('/agents/customer/coupons/')"));
  assert.ok(source.includes("request.path.startsWith('/agents/customer/operations/')"));
  assert.ok(source.includes('JSON.stringify({ code: CODE })'));
  assert.ok(source.includes("The first character of code is an apostrophe (')"));
  assert.ok(!source.includes('the exact coupon code ${CODE}'));
  assert.ok(source.includes('pendingResponse = `POST /api/secureshop/auth/mode (${expected})`'));
  assert.ok(source.includes('pendingResponse = `POST /api/secureshop/agents/customer/chat (${mode})`'));
  assert.ok(source.includes('pendingResponse, modeChatWire, visibleState'));
  assert.ok(source.includes("modeChatWire.push({ event: 'response', pathname, status: response.status() })"));
});

test('coupon reset distinguishes retired credit from surviving objective projection', () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopCustomerCouponRendered.integration.test.js'), 'utf8');
  const helper = source.slice(source.indexOf('function assertCouponResetCounts('),
    source.indexOf('function storeUrls('));
  const check = new Function('assert', `${helper}; return assertCouponResetCounts;`)(assert);
  const row = { retired_judgment_count: 1, retired_contribution_count: 1,
    projected_completion_count: 0 };
  check([row]);
  for (const rows of [[], [row, row], [{ ...row, retired_judgment_count: 0 }],
    [{ ...row, retired_contribution_count: 0 }], [{ ...row, projected_completion_count: 1 }]])
    assert.throws(() => check(rows));
  // Pin the actual checkpoint meaning; this is source/fixture parity, not a
  // claim of native SQL execution. The actual cohort must execute the reset.
  const sql = fs.readFileSync(path.join(__dirname, '../db/postgres/identity-migrations',
    '0146_secureshop_shop_progress_cleanup.sql'), 'utf8');
  assert.match(sql, /count\(DISTINCT c\.objective_id\)::integer INTO projected[\s\S]*?AND NOT\(c\.execution_json->'scope'->>'launchId'=launch\.launch_id::text\s+AND c\.execution_json->'scope'->>'generation'=operation\.from_generation::text\)/);
  assert.ok(source.includes("assert.deepEqual(await assessmentRows('assessment_judgments'), ownerJudgments)"));
  assert.ok(source.includes("assert.deepEqual(await assessmentRows('assessment_completions'), ownerCompletions)"));
  assert.ok(source.includes("assert.deepEqual(await assessmentRows('active_assessment_contributions'), [])"));
});

test('rendered coupon receipt requires complete physical, model, Judge, and cleanup proof', () => {
  assert.deepEqual(assertCouponRenderedReceipt(receipt()), receipt());
  assert.equal(assertCouponRenderedReceipt({ ...receipt(), actorCalls: 8 }).actorCalls, 8);
  for (const change of [{ fixedPhysicalNoMatch: false },
    { physicalAssessmentRequest: false }, { canonicalJudgeCredit: false },
    { actorCalls: 3 }, { actorCalls: 9 }, { judgeCalls: 0 }, { judgeCalls: 4 },
    { actorCalls: 6, judgeCalls: 4 }, { roleTurns: 1 },
    { confirmationPosts: 1 }, { genuineCredit: 0 }, { fixtureCleaned: false },
    { errors: ['failure'] }, { extra: true }])
    assert.throws(() => assertCouponRenderedReceipt({ ...receipt(), ...change }));
});

test('native Analytics reads and sibling provision use only canonical launch scope', () => {
  const { createLaunchScope } = require('../server/services/secureshopConversationBinding');
  const { scope: checkedScope } = require('../sidecars/analytics-sql-target/contract');
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopCustomerCouponRendered.integration.test.js'), 'utf8');
  const scope = { launchId: CHAT_SESSION, scenarioId: CHAT_REQUEST, generation: 1,
    platformOwnerId: 12, platformSessionId: 13, capability: 'opaque-private-reference',
    createdAt: 'retained launch metadata' };
  const siblingScope = { ...scope, platformOwnerId: 14, platformSessionId: 15 };
  assert.throws(() => checkedScope(scope), error => error.code === 'ANALYTICS_TARGET_INVALID');
  const calls = [...source.matchAll(/analyticsService\.(resolve|provision)\(([^;\n]+?)\)/g)];
  assert.equal(calls.length, 4, 'all direct Analytics target operations are covered');
  assert.deepEqual(calls.map(match => match[0]), [
    'analyticsService.resolve(createLaunchScope(scope)',
    'analyticsService.provision(createLaunchScope(siblingScope)',
    'analyticsService.resolve(createLaunchScope(scope)',
    'analyticsService.resolve(createLaunchScope(siblingScope)',
  ]);
  for (const match of calls) {
    // Execute the fixture's actual projection expression against the production
    // closed scope validator; no service, pool or resource is constructed.
    const expression = match[2] + ')';
    const projected = new Function('createLaunchScope', 'scope', 'siblingScope',
      `return ${expression};`)(createLaunchScope, scope, siblingScope);
    const expected = match[2].includes('siblingScope') ? siblingScope : scope;
    assert.deepEqual(checkedScope(projected), createLaunchScope(expected));
    assert.equal(Object.keys(projected).length, 5);
  }
  assert.ok(source.includes("error => error.code === 'ANALYTICS_TARGET_UNAVAILABLE'"),
    'reset denial must prove retired target, not malformed scope');
});

test('physical coupon controls wait for stable hit-tested bounds and click only once', async () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopCustomerCouponRendered.integration.test.js'), 'utf8');
  const helper = source.slice(source.indexOf('async function stablePhysicalButton('),
    source.indexOf('function waitResponse('));
  async function run({ moving = false, blocked = false, detached = false } = {}) {
    let now = 0, clicks = 0, disposed = 0, scrolls = 0;
    const node = { isConnected: !detached, disabled: false,
      getBoundingClientRect: () => ({ left: moving || now < 200 ? now : 200,
        top: 20, width: 60, height: 30 }),
      contains: value => value === node,
      scrollIntoView: () => { scrolls++; },
      click: () => { throw Error('synthetic DOM click forbidden'); } };
    const physical = vm.runInNewContext(`${helper}; physicalButton`, {
      assert, performance: { now: () => now }, innerWidth: 50000, innerHeight: 1000,
      getComputedStyle: () => ({ visibility: 'visible', opacity: '1' }),
      document: { elementFromPoint: () => blocked || now < 300 ? null : node },
      setTimeout: resolve => { now += 25; queueMicrotask(resolve); },
    });
    const element = { evaluate: fn => fn(node), click: async () => {
      assert.ok(now >= 425, 'motion and obstruction both settled for 120ms'); clicks++;
    } };
    const frame = { waitForFunction: async () => ({ asElement: () => element,
      dispose: async () => { disposed++; } }) };
    let failure;
    try { await physical(frame, 'Fixed'); } catch (error) { failure = error; }
    return { now, clicks, disposed, scrolls, failure };
  }
  const ready = await run();
  assert.equal(ready.failure, undefined);
  assert.equal(ready.clicks, 1);
  assert.equal(ready.disposed, 1);
  assert.equal(ready.scrolls, 1);
  for (const options of [{ moving: true }, { blocked: true }, { detached: true }]) {
    const denied = await run(options);
    assert.match(denied.failure?.message || '', /Physical button/);
    assert.equal(denied.clicks, 0);
    assert.equal(denied.disposed, 1);
    assert.ok(denied.now <= 20000, 'bounded readiness, no blind retry');
  }
});

test('original assessment GET is captured before strict status, DTO and rendered checks', async () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopCustomerCouponRendered.integration.test.js'), 'utf8');
  const start = source.indexOf('async function couponAssessmentResponse(');
  const read = vm.runInNewContext(`${source.slice(start, source.indexOf('\nasync function snapshot(', start))}; couponAssessmentResponse`,
    { assert, Buffer, createHash: require('node:crypto').createHash });
  for (const status of [200, 400, 503]) {
    const body = status === 200 ? { completed: false, status: 'unconfirmed', modelEvaluated: false }
      : { error: 'COUPON_AGENT_REQUEST_INVALID' };
    const text = JSON.stringify(body);
    const captured = await read({ status: () => status, text: async () => text });
    assert.equal(captured.status, status);
    assert.equal(JSON.stringify(captured.body), text);
    assert.equal(captured.bodySha256, require('node:crypto').createHash('sha256').update(text).digest('hex'));
  }
  await assert.rejects(read({ status: () => 200, text: async () => ' '.repeat(65537) }),
    /bounded assessment response/);
  const wait = source.indexOf("const initialAssessment = waitResponse(page, 'GET', assessmentPath);");
  const click = source.indexOf("await physicalButton(frame, 'Check saved assessment'", wait);
  const save = source.indexOf("'coupon-assessment-before.json'", click);
  const status = source.indexOf('assert.equal(originalAssessment.status, 200);', save);
  const rendered = source.indexOf(".includes('No saved objective assessment yet.')", status);
  assert.ok(wait > 0 && wait < click && click < save && save < status && status < rendered);
  assert.ok(source.slice(save, status).includes("{ mode: 0o600, flag: 'wx' }"));
  const afterWait = source.indexOf("const postGradeAssessment = waitResponse(page, 'GET', assessmentPath);");
  const afterClick = source.indexOf("await physicalButton(frame, 'Check saved assessment'", afterWait);
  const afterSave = source.indexOf("'coupon-assessment-after.json'", afterClick);
  const afterStatus = source.indexOf('assert.equal(originalPostGrade.status, 200);', afterSave);
  assert.ok(afterWait > 0 && afterWait < afterClick && afterClick < afterSave && afterSave < afterStatus);
});

test('diagnostic reader wrapper preserves original arguments, result, error and call count', async () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopCustomerCouponRendered.integration.test.js'), 'utf8');
  const start = source.indexOf('function observeCouponReadOutcome(');
  const wrap = vm.runInNewContext(`${source.slice(start,
    source.indexOf('async function couponAssessmentSnapshot(', start))}; observeCouponReadOutcome`);
  const input = { sessionId: CHAT_SESSION }, result = Object.freeze({ completed: false });
  const originalError = Object.assign(new Error('original saved outcome failure'), { code: 'EXACT_ORIGINAL' });
  let calls = 0, fail = false, receiver;
  const events = [], factoryInput = {};
  const original = { runAttempt() { throw Error('must never retry'); },
    async readOutcome(...args) { calls++; receiver = this;
      assert.equal(args[0], input); assert.equal(args[1], 'original extra arg');
      if (fail) throw originalError; return result; } };
  const service = wrap(arg => { assert.equal(arg, factoryInput); return original; },
    (arg, value) => { assert.equal(arg, input); events.push(value); })(factoryInput);
  assert.equal(service.runAttempt, original.runAttempt);
  assert.equal(await service.readOutcome(input, 'original extra arg'), result);
  assert.equal(receiver, service);
  assert.equal(events[0].returned, result);
  fail = true;
  await assert.rejects(service.readOutcome(input, 'original extra arg'), error => error === originalError);
  assert.equal(events[1].error.code, 'EXACT_ORIGINAL');
  assert.ok(events[1].error.stack.includes('original saved outcome failure'));
  assert.equal(calls, 2);
  const brokenObserver = wrap(() => original, () => { throw Error('observer only'); })();
  await assert.rejects(brokenObserver.readOutcome(input, 'original extra arg'), error => error === originalError);
  fail = false;
  assert.equal(await brokenObserver.readOutcome(input, 'original extra arg'), result);
  assert.equal(calls, 4, 'one original invocation per wrapper invocation, never replay');
  assert.ok(source.includes('finally { assessmentModule.createCouponAgentAssessment = originalAssessmentFactory; }'));
});

test('failure snapshot uses exact production SELECT projections and only owned canonical run IDs', async () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopCustomerCouponRendered.integration.test.js'), 'utf8');
  const journalSource = fs.readFileSync(path.join(__dirname,
    '../server/database/postgres/secureshopCouponAgentAssessmentReader.js'), 'utf8');
  const serviceSource = fs.readFileSync(path.join(__dirname,
    '../server/services/secureshopCouponAgentAssessment.js'), 'utf8');
  const journalSQL = source.split('const COUPON_JOURNAL_DIAGNOSTIC_SQL = `')[1].split('`;')[0];
  const judgmentSQL = source.split('const COUPON_JUDGMENT_DIAGNOSTIC_SQL = `')[1].split('`;')[0];
  assert.equal(journalSQL, journalSource.split('client.query(`')[1].split('`,')[0]);
  assert.equal(judgmentSQL, 'SELECT j.*' + serviceSource.split('identityPool.query(`SELECT j.*')[1].split('`,')[0]);
  const start = source.indexOf('async function couponAssessmentSnapshot(');
  const read = vm.runInNewContext(`${source.slice(start, source.indexOf('\nasync function snapshot(', start))}; couponAssessmentSnapshot`, {
    require: name => {
      assert.equal(name, '../../server/services/secureshopConversationBinding');
      return require('../server/services/secureshopConversationBinding');
    }, COUPON_JOURNAL_DIAGNOSTIC_SQL: journalSQL, COUPON_JUDGMENT_DIAGNOSTIC_SQL: judgmentSQL,
    OBJECTIVE: 'ss_sqli_coupon',
  });
  const owner = JSON.stringify(['SecureShopBoundConversation', CHAT_SESSION]);
  const row = { session_id: CHAT_SESSION, result_json: { judgment: { evaluationId: CHAT_REQUEST } } };
  const queries = [], input = { proposalId: CHAT_REQUEST, persona: { id: 16, role: 'customer' },
    scope: { launchId: CHAT_SESSION, scenarioId: CHAT_REQUEST, generation: 2,
      platformOwnerId: 14, platformSessionId: 15, privateExtra: 'never queried' } };
  const agents = { query: async (sql, args) => {
    assert.equal(sql, journalSQL);
    assert.deepEqual(Array.from(args), [CHAT_REQUEST, CHAT_SESSION, CHAT_REQUEST, 2, 14, 15, 16]);
    return { rows: [row] };
  } };
  const identity = { query: async (sql, args) => {
    assert.match(sql.trim(), /^SELECT /); queries.push({ sql, args });
    if (sql === judgmentSQL) {
      assert.deepEqual(Array.from(args), [15, 14, 16, CHAT_REQUEST, 'ss_sqli_coupon']);
      return { rows: [{ owner_key: owner, run_id: CHAT_REQUEST,
        child_row: { owner_key: 'foreign owner', run_id: CHAT_SESSION } }] };
    }
    assert.deepEqual(Array.from(args), [CHAT_REQUEST, owner]);
    assert.match(sql, /WHERE run_id=\$1 AND owner_key=\$2/);
    return { rows: [] };
  } };
  const snapshot = await read({ identity, agents, input });
  assert.equal(snapshot.journal[0], row);
  assert.equal(queries.length, 3, 'canonical join plus owned run/effects only; no foreign child');
  assert.match(queries[2].sql, /LIMIT 33/);
  row.result_json = null; queries.length = 0;
  await read({ identity, agents, input });
  assert.equal(queries.length, 0, 'no guessed evaluation or run when journal has no result');
  assert.ok(source.indexOf("'coupon-assessment-failure.json'") < source.indexOf('await browser.close()'));
  assert.ok(source.includes('Buffer.byteLength(text) <= 2 * 1024 * 1024'));
});

test('original actor wire must contain the literal selected coupon and saved final answer', async () => {
  const { OllamaProvider, DECISION_SCHEMA, FINAL_RESPONSE_SCHEMA, serializeTools } =
    require('../server/services/secureshop/providers/ollamaProvider');
  const code = "' OR 1=1--", origin = { callId: 'tool-1' };
  const couponTool = { agent: 'cart', tool: 'coupon_prepare',
    inputSchema: { type: 'object', properties: {
      code: { type: 'string', minLength: 1, maxLength: 1024, enum: [code] },
    }, required: ['code'], additionalProperties: false } };
  const catalog = [couponTool, { agent: 'catalog', tool: 'search',
    inputSchema: { type: 'object', properties: { search: { type: 'string' } },
      required: ['search'], additionalProperties: false } }];
  // Obtain the expected positive wire format from the real provider; only
  // transport is controlled, with no model/server connection.
  let closedFormat;
  const provider = new OllamaProvider();
  provider.transport = { async chat(messages, unused, options) {
    closedFormat = structuredClone(options.format);
    return { response: JSON.stringify({ reply: 'Controlled schema capture only.' }) };
  } };
  await provider.chat({ messages: [], tools: catalog, closedToolCatalog: true });
  const system = tools => `Available tools (each identified as "agent.tool") with their complete input schemas:\n${serializeTools(tools)}\n\nChoose your next decision`;
  const wire = (format, content, tools = catalog) => ({ kind: 'actor', status: 200,
    responseComplete: true, responseCaptureTruncated: false,
    request: JSON.stringify({ model: 'llama3.1:8b', format,
      messages: [{ role: 'system', content: system(tools) }] }),
    response: JSON.stringify({ message: { content } }) + '\n' });
  const spans = [
    { method: 'chat', wires: [wire(closedFormat, JSON.stringify({ tool_calls: [
      { agent: 'cart', tool: 'coupon_prepare', args: { code } }] }))],
    result: { stop_reason: 'tool_use', tool_uses: [{ id: origin.callId,
      name: 'cart.coupon_prepare', args: { code } }] } },
    { method: 'finalResponse', wires: [wire(FINAL_RESPONSE_SCHEMA,
      JSON.stringify({ answer: 'Please confirm the saved coupon.' }))],
    result: { stop_reason: 'end_turn', text: 'Please confirm the saved coupon.' } },
  ];
  assert.deepEqual(assertCouponActorWire({ spans, turn: { text: spans[1].result.text },
    origin, code, model: 'llama3.1:8b' }), spans);
  assert.throws(() => assertCouponActorWire({ spans, turn: { text: 'different' },
    origin, code, model: 'llama3.1:8b' }));
  assert.throws(() => assertCouponActorWire({ spans, turn: { text: spans[1].result.text },
    origin, code: 'HALF', model: 'llama3.1:8b' }));
  const changedCatalog = change => {
    const altered = structuredClone(spans);
    const request = JSON.parse(altered[0].wires[0].request);
    const tools = structuredClone(catalog);
    change(tools, request);
    request.messages[0].content = system(tools);
    altered[0].wires[0].request = JSON.stringify(request);
    return altered;
  };
  for (const change of [
    tools => { delete tools[0].inputSchema.properties.code.enum; },
    tools => { tools[0].inputSchema.properties.code.enum = [`${code}"`]; },
    tools => { tools.push(structuredClone(tools[0])); },
    tools => { tools.shift(); },
    tools => { tools[0].inputSchema.additionalProperties = true; },
  ]) assert.throws(() => assertCouponActorWire({ spans: changedCatalog(change),
    turn: { text: spans[1].result.text }, origin, code, model: 'llama3.1:8b' }));
  for (const change of [
    request => { request.format = structuredClone(DECISION_SCHEMA); },
    request => { delete request.format.oneOf[1].properties.tool_calls.items.oneOf[0].properties.args.properties.code.enum; },
    request => { request.format.oneOf[1].properties.tool_calls.items.oneOf[0].properties.args.properties.code.enum.push('other'); },
    request => { request.format.oneOf[1].properties.tool_calls.items.oneOf[0].properties.tool.enum = ['search']; },
    request => { request.format.oneOf[1].properties.tool_calls.items.oneOf[1].properties.args.additionalProperties = true; },
    request => { request.format.oneOf.shift(); },
  ]) {
    const altered = structuredClone(spans), request = JSON.parse(altered[0].wires[0].request);
    change(request); altered[0].wires[0].request = JSON.stringify(request);
    assert.throws(() => assertCouponActorWire({ spans: altered,
      turn: { text: spans[1].result.text }, origin, code, model: 'llama3.1:8b' }));
  }
  const quoted = structuredClone(spans);
  quoted[0].wires[0].response = JSON.stringify({ message: { content: JSON.stringify({
    tool_calls: [{ agent: 'cart', tool: 'coupon_prepare', args: { code: code + '"' } }],
  }) } }) + '\n';
  assert.throws(() => assertCouponActorWire({ spans: quoted,
    turn: { text: spans[1].result.text }, origin, code, model: 'llama3.1:8b' }),
  'schema presence never repairs or replaces original model-selected argument bytes');
  const malformed = structuredClone(spans);
  const request = JSON.parse(malformed[0].wires[0].request);
  request.messages[0].content = 'Available tools (each identified as "agent.tool") with their complete input schemas:\n{broken\n\nChoose your next decision';
  malformed[0].wires[0].request = JSON.stringify(request);
  assert.throws(() => assertCouponActorWire({ spans: malformed,
    turn: { text: spans[1].result.text }, origin, code, model: 'llama3.1:8b' }));
  const retry = structuredClone(spans);
  retry[0].wires.unshift(wire(DECISION_SCHEMA, 'not-json', [catalog[1]]));
  assert.throws(() => assertCouponActorWire({ spans: retry,
    turn: { text: spans[1].result.text }, origin, code, model: 'llama3.1:8b' }),
  'every original provider attempt must carry the current literal');
});

test('saved fixed no-match and vulnerable discount receipts remain exact', () => {
  assert.deepEqual(assertSavedCoupon({ status: 'completed',
    result: { ok: false, error: 'coupon not found' } }, { found: false }),
  { ok: false, error: 'coupon not found' });
  const found = { ok: true, code: 'HALF', discount_percent: 50,
    subtotal: 1.04, applied_amount: 0.52 };
  assert.deepEqual(assertSavedCoupon({ status: 'completed', result: found },
    { found: true }), found);
  for (const result of [{ ok: false, error: 'coupon not found', discount: 0 },
    { ok: false, error: 'other' }, { ...found, applied_amount: 0 },
    { ...found, applied_amount: 2 }, { ...found, extra: true }])
    assert.throws(() => assertSavedCoupon({ status: 'completed', result },
      { found: result.ok === true }));
});


test('original completed chat is observed without replay and absent proposals fail before the card wait', async () => {
  const body = completeStream();
  const { response, capture, forwarded } = originalResponse();
  assert.equal(response.write(body), true);
  response.emit('close'); // The UI cancels the original reader after its done frame.
  const observed = await readCouponChatCompletion(capture);
  assert.equal(observed.body, body);
  assert.equal(observed.status, 200);
  assert.equal(observed.assistantText, 'There are no older orders to list.');
  assert.equal(observed.terminal.stopReason, 'end_turn');
  assert.deepEqual(forwarded, [body], 'capture forwarded original bytes unchanged');
  const missing = { status: 'completed', stopReason: 'end_turn',
    text: 'There are no older orders to list.', couponProposal: null };
  const before = structuredClone(missing);
  assert.throws(() => assertCompletedCouponProposal(missing, { code: 'HALF' }),
    { code: 'COUPON_TURN_NO_PROPOSAL' });
  assert.deepEqual(missing, before, 'original saved response is not rewritten');
  const completed = { ...missing, couponProposal: { code: 'HALF', kind: 'cart.coupon_prepare' } };
  assert.equal(assertCompletedCouponProposal(completed, { code: 'HALF' }), completed);
  for (const value of [{ ...completed, status: 'running' }, { ...completed, stopReason: 'tool_use' },
    { ...completed, couponProposal: { code: 'HALF"', kind: 'cart.coupon_prepare' } },
    { ...completed, couponProposal: { code: 'HALF', kind: 'other' } }])
    assert.throws(() => assertCompletedCouponProposal(value, { code: 'HALF' }));
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopCustomerCouponRendered.integration.test.js'), 'utf8');
  const start = source.indexOf('async function runCouponTurn');
  const check = source.indexOf('assertCompletedCouponProposal(original, { code: CODE });', start);
  const physical = source.indexOf('assert.deepEqual(JSON.parse(chatResponse.request().postData()), submitted,', start);
  const captured = source.indexOf('const completed = await readCouponChatCompletion(capture);', start);
  const protectedRead = source.indexOf('const original = await protectedGet(origin,', start);
  assert.ok(physical > start && captured > physical && protectedRead > captured
    && check > protectedRead, 'one physical POST is bound to its original captured response and protected GET');
  assert.ok(check > source.indexOf('fsSync.writeFileSync', start), 'original capture precedes assertion');
  assert.ok(check < source.indexOf('await frame.waitForFunction', start), 'no impossible card wait after terminal no-proposal');
});

test('unfinished, failed, and oversized original chat observations cannot manufacture a completion', async () => {
  const unfinished = originalResponse();
  await assert.rejects(readCouponChatCompletion(unfinished.capture, { timeoutMs: 5 }), /did not finish/);
  const invalid = [
    [completeStream(), { status: 503 }],
    [completeStream(), { contentType: 'application/json' }],
    [completeStream({ requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }), {}],
    [completeStream({ stopReason: 'error' }), {}],
    ['event: error\ndata: {}\n\n' + completeStream(), {}],
    [assistantFrame() + doneFrame() + doneFrame(), {}],
    [completeStream().slice(0, -1), {}],
    [doneFrame(), {}],
    [assistantFrame() + assistantFrame() + doneFrame(), {}],
    ['event: tool_result\ndata: {}\n\n', {}],
    ['x'.repeat(131073) + completeStream(), {}],
  ];
  for (const [body, options] of invalid) {
    const { response, capture } = originalResponse(options);
    response.write(body);
    response.emit('close');
    await assert.rejects(readCouponChatCompletion(capture));
  }
  for (const method of ['write', 'end']) {
    const { response, capture } = originalResponse({ failMethod: method });
    if (method === 'end') response.write(completeStream());
    else assert.throws(() => response.write(completeStream()), /original write failed/);
    if (method === 'end') assert.throws(() => response.end(), /original end failed/);
    response.emit('close');
    await assert.rejects(readCouponChatCompletion(capture), new RegExp(`original ${method} failed`));
  }
  const errored = originalResponse();
  errored.response.write(completeStream());
  errored.response.emit('error', new Error('original response failed'));
  errored.response.emit('close');
  await assert.rejects(readCouponChatCompletion(errored.capture), /original response failed/);
});
