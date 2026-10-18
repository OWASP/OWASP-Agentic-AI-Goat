'use strict';

// Controlled orchestration checks. No browser, PostgreSQL or model is started.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { EventEmitter } = require('node:events');
const { assertMailHeaderReceipt, MAIL_HEADER_FLAGS, MAIL_HEADER_SCOPE } =
  require('./postgres/secureshopStandaloneRoleChoicesRendered.integration.test');
const { captureMailHeaderRequestBody, observeOriginalMailHeaderSse,
  validateOriginalMailHeaderSse, readOriginalMailHeaderSse,
  observeOriginalMailHeaderJson, validateOriginalMailHeaderJson, readOriginalMailHeaderJson,
  observeMailHeaderRepository, observeMailHeaderAssessment, findOriginalMailPreparationWire,
  buildV05ChatPrompt, createMailHeaderBrowserActions, clickHitTestedButton,
  runMailHeaderRenderedScenario } = require('./fixtures/secureshopMailHeaderRenderedScenario');

const subject = 'Lesson header\r\nX-Training: owned';
const body = 'Please acknowledge.';
function setup({ altered = false } = {}) {
  const order = [], choiceId = randomUUID(), proposalId = randomUUID(), replyOperationId = randomUUID();
  const merchant = { username: 'merchant', email: 'merchant@shop.example',
    persona: { id: 5, role: 'merchant' }, personaSession: { sessionId: randomUUID(), authorityVersion: '1' },
    scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
      platformOwnerId: 11, platformSessionId: 12 }, targetId: randomUUID(), mode: 'vuln' };
  const physical = {
    async sendChat(message) {
      order.push(message.startsWith('Find the mail recipient') ? 'discover' : 'prepare');
      if (order.at(-1) === 'discover') return { receipt: { status: 'completed',
        hops: [{ tool: 'merchant.mail_recipients' }], cards: [{ kind: 'merchant_mail_recipient',
          title: 'merchant', choiceId }] } };
      return { body: { selection: { choiceId, intent: 'mail_send' } },
        receipt: { status: 'completed', hops: [{ tool: 'merchant.mail_send_prepare',
          params: { subject: altered ? 'benign' : subject, body_markdown: body } }],
          mailProposal: { subject, recipient: { email: merchant.email }, proposalId } } };
    },
    async selectChoice(label) { order.push('choice'); assert.equal(label, 'Compose message to merchant'); },
    async confirmSend({ control }) { order.push('confirm'); assert.equal(control, 'Send message');
      return { response: { value: { status: 'saved', sendOperationId: proposalId,
        savedSend: { subject }, emailId: 13 } } }; },
    async openOwnedInbox({ control, recipientId, sourceEmailId }) {
      order.push('inbox'); assert.equal(control, 'Reload'); assert.equal(recipientId, 5);
      assert.equal(sourceEmailId, 13);
      return { selectedMessage: { id: 13, subject, thread_id: 14 } };
    },
    async autoReply({ control, sourceEmailId, sourceThreadId }) {
      order.push('reply'); assert.equal(control, 'Auto-reply');
      return { sourceMessageId: sourceEmailId, sourceThreadId,
        response: { value: { status: 'saved', sendOperationId: replyOperationId } } };
    },
    async checkSavedHeaders({ control, replyOperationId: operation }) {
      order.push('assessment'); assert.equal(control, 'Check saved headers');
      assert.equal(operation, replyOperationId);
      return { response: { value: { completed: true } } };
    },
  };
  const observe = {
    async readSavedHeaders() { order.push('saved'); return { source: { receipt: { email_id: 13 } },
      reply: { binding: { operationId: replyOperationId } } }; },
    async readJudge() { order.push('judge'); return {}; },
  };
  const guards = Object.fromEntries(['replay', 'sibling', 'fixed', 'reset'].map(name =>
    [name, async () => { order.push(name); return {}; }]));
  return { order, merchant, physical, observe, guards };
}

test('prompt physically separates exact JSON fields while demanding model-selected literal CRLF', () => {
  const prompt = buildV05ChatPrompt(subject, body);
  assert(prompt.includes('U+000D') && prompt.includes('U+000A'));
  const json = prompt.slice(prompt.indexOf('\n') + 1);
  assert.deepEqual(JSON.parse(json), { subject, body_markdown: body });
  assert(json.includes('\n  "subject": ') && json.includes('\n  "body_markdown": '));
  assert(json.includes('Lesson header\\r\\nX-Training: owned'));
  assert(!prompt.includes(subject));
  assert(prompt.includes('without appending the subject'));
  assert.throws(() => buildV05ChatPrompt('benign', body));
});

test('scenario sequences the existing physical and production seams before strict evidence assertion', async () => {
  const value = setup();
  await assert.rejects(runMailHeaderRenderedScenario({ origin: 'http://127.0.0.1:8081',
    requestFrame: {}, merchant: value.merchant, subject, body,
    physical: value.physical, observe: value.observe, guards: value.guards }));
  assert.deepEqual(value.order, ['discover', 'choice', 'prepare', 'confirm', 'inbox', 'reply',
    'saved', 'assessment', 'judge', 'replay', 'sibling', 'fixed', 'reset']);
});

test('a model-selected benign subject stops before any send confirmation', async () => {
  const value = setup({ altered: true });
  await assert.rejects(runMailHeaderRenderedScenario({ origin: 'http://127.0.0.1:8081',
    requestFrame: {}, merchant: value.merchant, subject, body,
    physical: value.physical, observe: value.observe, guards: value.guards }),
  /actual model must select literal CRLF/);
  assert.deepEqual(value.order, ['discover', 'choice', 'prepare']);
});

test('missing physical or production callbacks fail before discovery', async () => {
  const value = setup(); delete value.physical.confirmSend;
  await assert.rejects(runMailHeaderRenderedScenario({ origin: 'http://127.0.0.1:8081',
    requestFrame: {}, merchant: value.merchant, subject, body,
    physical: value.physical, observe: value.observe, guards: value.guards }),
  /Physical confirmSend callback required/);
  assert.deepEqual(value.order, []);
});

test('physical browser adapter captures original UI requests and enters multiline chat with Shift+Enter', async () => {
  const origin = 'http://127.0.0.1:8081';
  const requestFrame = {}, clicked = [], keys = [], submitted = [];
  const source = { id: 13, thread_id: 14, subject, body_markdown: body,
    from_addr: 'merchant@shop.example', created_at: '2026-10-15T18:23:00.000Z' };
  const page = new EventEmitter();
  const jsonResponses = new WeakMap();
  let pendingResponse;
  page.waitForResponse = async () => new Promise(resolve => { pendingResponse = resolve; });
  page.keyboard = { async type(value) { keys.push(['type', value]); },
    async press(value) { keys.push(['press', value]); },
    async down(value) { keys.push(['down', value]); },
    async up(value) { keys.push(['up', value]); } };
  const rawSse = Buffer.from('event: done\ndata: {"status":"completed"}\n\n');
  let originalChatResponse;
  const makeRequest = (path, method, data, value) => {
    const request = { frame: () => requestFrame, method: () => method,
      url: () => `${origin}${path}`, postData: () => JSON.stringify(data) };
    submitted.push(request); page.emit('request', request);
    const response = { request: () => request, status: () => 200,
      headers: () => ({ 'content-type': 'text/event-stream; charset=utf-8' }),
      buffer: async () => { throw Error('CDP body unavailable; must use original server capture'); },
      json: async () => { throw Error('CDP JSON body unavailable'); } };
    if (path.endsWith('/assistant/chat')) originalChatResponse = response;
    else jsonResponses.set(response, value);
    pendingResponse(response);
  };
  const frame = { waitForFunction: async () => {}, waitForSelector: async () => {},
    $eval: async () => 5,
    locator: selector => ({ fill: async value => clicked.push(['fill', selector, value]),
      click: async () => {
        clicked.push(['locator', selector]);
        if (selector.includes('button[type="submit"]')) makeRequest(
          '/api/secureshop/agents/merchant/assistant/chat', 'POST',
          { message: `first\nsecond`, sessionId: randomUUID(), requestId: randomUUID() }, {});
      } }),
    evaluateHandle: async (_fn, _selector, label) => ({ asElement: () => ({ click: async () => {
      clicked.push(['button', label]);
      if (label === 'Send message') makeRequest(
        '/api/secureshop/agents/merchant/assistant/mail/confirm', 'POST',
        { sessionId: chat.body.sessionId, requestId: chat.body.requestId,
          proposalId }, { status: 'saved' });
      if (label === 'Check saved headers') makeRequest(
        '/api/secureshop/email/header-assessment', 'POST',
        { requestId: assessmentId, sendOperationId: replyOperationId }, { completed: true });
      if (label === 'Reload') makeRequest(
        `/api/secureshop/email/inbox/5?requestId=${randomUUID()}`, 'GET', null,
        { ok: true, emails: [source] });
      if (label === 'Auto-reply') makeRequest(
        '/api/secureshop/email/auto-reply/14', 'POST', { requestId: replyRequestId },
        { status: 'saved', sendOperationId: replyOperationId });
    } }) }) };
  const merchant = { persona: { id: 5 } }, proposalId = randomUUID();
  const replyOperationId = randomUUID(), assessmentId = randomUUID(), replyRequestId = randomUUID();
  let chat;
  const actions = createMailHeaderBrowserActions({ page, frame, requestFrame, origin,
    merchant, counts: async () => ({ sends: 0, reads: 0, judgeCalls: 0 }),
    readOriginalSse: async (_request, wire) => {
      assert.equal(wire, originalChatResponse); return rawSse;
    },
    readOriginalJson: async (request, wire) => {
      assert.equal(wire.request(), request);
      return jsonResponses.get(wire);
    },
    readSavedChat: async ({ body, request, response }) => {
      assert.equal(request, submitted[0]);
      assert.equal(response.original, originalChatResponse);
      assert.equal(response.kind, 'sse'); assert.equal(response.status, 200);
      assert.deepEqual(response.bytes, rawSse);
      assert.equal(response.sha256, createHash('sha256').update(rawSse).digest('hex'));
      assert.equal(response.value, undefined);
      return { receipt: { status: 'completed', requestId: body.requestId } };
    }, readReplyEvidence: async () => ({ trusted: { proven: true } }) });
  chat = await actions.sendChat('first\nsecond');
  assert.deepEqual(keys, [['type', 'first'], ['down', 'Shift'], ['press', 'Enter'],
    ['up', 'Shift'], ['type', 'second']]);
  assert.equal(chat.request, submitted[0]);
  const confirmation = await actions.confirmSend({ control: 'Send message', chat, proposalId });
  assert.equal(confirmation.request, submitted[1]);
  assert.equal(confirmation.requestMutation, false);
  const inbox = await actions.openOwnedInbox({ control: 'Reload', recipientId: 5,
    sourceEmailId: source.id });
  assert.equal(inbox.request, submitted[2]);
  assert.equal(inbox.selectedMessage, source);
  const reply = await actions.autoReply({ control: 'Auto-reply',
    sourceEmailId: source.id, sourceThreadId: source.thread_id });
  assert.equal(reply.request, submitted[3]);
  assert.equal(reply.requestId, replyRequestId);
  assert.deepEqual(reply.trusted, { proven: true });
  const assessment = await actions.checkSavedHeaders({ control: 'Check saved headers',
    replyOperationId });
  assert.equal(assessment.originalRequest, submitted[4]);
  assert.deepEqual(assessment.request, { requestId: assessmentId, sendOperationId: replyOperationId });
  assert(clicked.some(row => row[0] === 'button' && row[1] === 'Send message'));
});


test('physical button waits for smooth scroll to settle on the same hit-tested element', async () => {
  const calls = [], blocker = {}, previous = global.document;
  let hit = blocker;
  const element = { isConnected: true, disabled: false, textContent: 'Reload',
    getClientRects: () => [{}], getBoundingClientRect: () => ({ left: 10, top: 20, width: 40, height: 20 }),
    contains: value => value === element, scrollIntoView: options => calls.push(['scroll', options]),
    click: async () => calls.push(['click']) };
  global.document = { querySelectorAll: selector => {
    assert.equal(selector, 'button[aria-label="Refresh"]'); return [element];
  }, elementFromPoint: (x, y) => { assert.deepEqual([x, y], [30, 30]); return hit; } };
  let waits = 0;
  const handle = { asElement: () => element, dispose: async () => calls.push(['dispose']) };
  const current = {
    async waitForFunction(predicate, options, ...args) {
      waits++; assert.deepEqual(options, { timeout: 30000 });
      if (waits === 1) assert.equal(predicate(...args), true);
      else { assert.equal(args[0], element); assert.equal(predicate(...args), false);
        hit = element; assert.equal(predicate(...args), true); calls.push(['settled']); }
    },
    async evaluateHandle(predicate, ...args) { assert.equal(predicate(...args), element); return handle; },
  };
  try {
    await clickHitTestedButton(current, 'button[aria-label="Refresh"]', 'Reload');
    assert.equal(waits, 2);
    assert.deepEqual(calls, [['scroll', { block: 'center' }], ['settled'], ['click'], ['dispose']]);
    element.isConnected = false; assert.equal(require('./fixtures/secureshopMailHeaderRenderedScenario').isHitTestedElement(element), false);
  } finally { if (previous === undefined) delete global.document; else global.document = previous; }
});

test('chat adapter rejects non-SSE and incomplete original responses before saved reader handoff', async () => {
  const origin = 'http://127.0.0.1:8081', requestFrame = {};
  const originalFailure = new Error('Original response body incomplete');
  for (const fault of ['json', 'incomplete', 'oversized']) {
    const page = new EventEmitter(); let resolveResponse, reads = 0;
    page.waitForResponse = () => new Promise(resolve => { resolveResponse = resolve; });
    page.keyboard = { type: async () => {}, press: async () => {},
      down: async () => {}, up: async () => {} };
    const frame = { waitForFunction: async () => {}, evaluateHandle: async () => {},
      locator: selector => ({ fill: async () => {}, click: async () => {
        if (!selector.includes('button[type="submit"]')) return;
        const request = { frame: () => requestFrame, method: () => 'POST',
          url: () => origin + '/api/secureshop/agents/merchant/assistant/chat',
          postData: () => JSON.stringify({ message: 'Original prompt' }) };
        page.emit('request', request);
        resolveResponse({ request: () => request, status: () => 200,
          headers: () => ({ 'content-type': fault === 'json' ? 'application/json' : 'text/event-stream' }),
          buffer: async () => {
            if (fault === 'incomplete') throw originalFailure;
            return Buffer.alloc(131073);
          },
          json: async () => { throw Error('SSE must not be decoded as JSON'); },
        });
      } }),
    };
    const actions = createMailHeaderBrowserActions({ page, frame, requestFrame, origin,
      merchant: { persona: { id: 5 } }, counts: async () => ({}),
      readOriginalSse: async () => {
        if (fault === 'incomplete') throw originalFailure;
        return Buffer.alloc(131073);
      },
      readOriginalJson: async () => ({}),
      readSavedChat: async () => { reads++; }, readReplyEvidence: async () => ({}) });
    await assert.rejects(actions.sendChat('Original prompt'), error => fault === 'incomplete'
      ? error === originalFailure : error.code === 'ERR_ASSERTION');
    assert.equal(reads, 0);
    assert.equal(page.listenerCount('request'), 0);
  }
});

test('physical multiline entry releases Shift and preserves the original Enter failure before submission', async () => {
  const page = new EventEmitter(), keys = [], failure = new Error('Original Enter failed');
  let submits = 0;
  page.waitForResponse = async () => { throw Error('No request must start'); };
  page.keyboard = {
    type: async value => keys.push(['type', value]),
    down: async value => keys.push(['down', value]),
    press: async value => { keys.push(['press', value]); throw failure; },
    up: async value => keys.push(['up', value]),
  };
  const frame = { waitForFunction: async () => {}, evaluateHandle: async () => {},
    locator: selector => ({ fill: async () => {}, click: async () => {
      if (selector.includes('button[type="submit"]')) submits++;
    } }) };
  const actions = createMailHeaderBrowserActions({ page, frame, requestFrame: {},
    origin: 'http://127.0.0.1:8081', merchant: { persona: { id: 5 } },
    counts: async () => ({}), readSavedChat: async () => ({}),
    readReplyEvidence: async () => ({}), readOriginalSse: async () => Buffer.from('unused'),
    readOriginalJson: async () => ({}) });
  await assert.rejects(actions.sendChat('first\nsecond'), error => error === failure);
  assert.deepEqual(keys, [['type', 'first'], ['down', 'Shift'], ['press', 'Enter'], ['up', 'Shift']]);
  assert.equal(submits, 0); assert.equal(page.listenerCount('request'), 0);
});


test('mail observers preserve branded arguments, original return objects and original errors', async () => {
  const branded = {}, input = {}, options = {}, result = { receipt: { id: 1 } };
  const brands = new WeakSet([branded]);
  const failure = Object.assign(new Error('Invalid fixed mail header'), { code: 'P0001' });
  const observed = { sends: [], recovers: [], assessments: [] };
  const original = { browse() {}, async send(...args) {
    assert.equal(brands.has(args[0]), true);
    assert.equal(args[1], input); assert.equal(args[2], options); return result;
  }, async recover(binding) { assert.equal(binding, branded); throw failure; } };
  const repository = observeMailHeaderRepository(original, observed);
  assert.equal(repository.browse, original.browse);
  assert.equal(await repository.send(branded, input, options), result);
  await assert.rejects(repository.recover(branded), error => error === failure);
  assert.deepEqual(observed.recovers[0].error, { name: failure.name, code: failure.code,
    message: failure.message, stack: failure.stack });
  const attempt = { binding: branded, requestId: randomUUID(), signal: options };
  const service = observeMailHeaderAssessment({ async runAttempt(value) {
    assert.equal(value, attempt); assert.equal(value.binding, branded); throw failure;
  } }, observed);
  await assert.rejects(service.runAttempt(attempt), error => error === failure);
  assert.equal(observed.assessments[0].input.requestId, attempt.requestId);
});

test('mail wire reader requires the original closed choice schema and refuses final or generic calls', () => {
  const { DECISION_SCHEMA } = require('../server/services/secureshop/providers/ollamaProvider');
  const { FINAL_RESPONSE_SCHEMA } = require('../server/agent-runtime/providers/finalResponseContract');
  const selected = { choiceId: randomUUID(), subject, body_markdown: body };
  const packet = { tool_calls: [{ agent: 'merchant', tool: 'mail_send_prepare', args: selected }] };
  const closed = structuredClone(DECISION_SCHEMA);
  closed.oneOf[1].properties.tool_calls.items = { oneOf: [{ type: 'object', properties: {
    agent: { type: 'string', enum: ['merchant'] },
    tool: { type: 'string', enum: ['mail_send_prepare'] },
    args: { type: 'object', properties: {
      choiceId: { type: 'string', enum: [selected.choiceId] },
      subject: { type: 'string', maxLength: 512 },
      body_markdown: { type: 'string', maxLength: 8192 },
    }, required: ['choiceId', 'subject', 'body_markdown'], additionalProperties: false },
  }, required: ['agent', 'tool', 'args'], additionalProperties: false }] };
  const make = (value, format) => {
    const request = JSON.stringify({ model: 'controlled-model', format });
    const response = JSON.stringify({ model: 'controlled-model', message: { content: JSON.stringify(value) }, done: true }) + '\n';
    return { kind: 'actor', request, response, requestSha256: createHash('sha256').update(request).digest('hex'),
      responseSha256: createHash('sha256').update(response).digest('hex'), status: 200,
      responseComplete: true, responseCaptureTruncated: false };
  };
  const wire = make(packet, closed);
  assert.equal(findOriginalMailPreparationWire([wire, make({ answer: 'Completed' }, FINAL_RESPONSE_SCHEMA)], selected), wire);
  assert.throws(() => findOriginalMailPreparationWire([make(packet, DECISION_SCHEMA)], selected));
  const otherChoice = structuredClone(closed);
  otherChoice.oneOf[1].properties.tool_calls.items.oneOf[0].properties.args.properties.choiceId.enum = [randomUUID()];
  assert.throws(() => findOriginalMailPreparationWire([make(packet, otherChoice)], selected));
  for (const change of [{ status: 503 }, { responseComplete: false }, { responseCaptureTruncated: true },
    { requestSha256: 'a'.repeat(64) }, { responseSha256: 'b'.repeat(64) }])
    assert.throws(() => findOriginalMailPreparationWire([{ ...wire, ...change }], selected));
  assert.throws(() => findOriginalMailPreparationWire([wire, wire], selected));
  assert.throws(() => findOriginalMailPreparationWire([make({ answer: 'No tool' }, FINAL_RESPONSE_SCHEMA)], selected));
});

test('V05 receipt is closed and matches the existing physical call cap without admitting constructed proof', () => {
  const value = { ...Object.fromEntries(MAIL_HEADER_FLAGS.map(flag => [flag, true])),
    scope: MAIL_HEADER_SCOPE, actorCalls: 11, judgeCalls: 1, roleTurns: 4,
    readEffects: 1, sendEffects: 2, genuineCredit: 1, errors: [] };
  assert.doesNotThrow(() => assertMailHeaderReceipt(value));
  for (const flag of MAIL_HEADER_FLAGS) assert.throws(() => assertMailHeaderReceipt({ ...value, [flag]: false }));
  for (const change of [{ actorCalls: 6 }, { actorCalls: 14 }, { actorCalls: 13, judgeCalls: 2 },
    { judgeCalls: 0 }, { roleTurns: 3 }, { readEffects: 0 }, { sendEffects: 3 }, { genuineCredit: 0 },
    { unexpected: true }, { errors: ['failed'] }]) assert.throws(() => assertMailHeaderReceipt({ ...value, ...change }));
  const fs = require('node:fs');
  const fixture = fs.readFileSync(require.resolve('./postgres/secureshopStandaloneRoleChoicesRendered.integration.test'), 'utf8');
  assert.ok(fixture.includes('(MAIL_HEADER_BROWSER || MAIL_HTML_BROWSER || V11_MAIL_READ_BROWSER) ? { publicationModes: modeRepository }'));
  assert.ok(fixture.includes('createSecureShopModeRepository(identity)'));
  const scenario = fs.readFileSync(require.resolve('./fixtures/secureshopMailHeaderRenderedScenario'), 'utf8');
  assert.ok(scenario.includes('captureAssessmentPublicationScope(publicationModes, scope.platformOwnerId, undefined, scope)'));
});

test('V05 installs real mail and captures its original merchant bootstrap through all three setup gates', () => {
  const fixture = require('node:fs').readFileSync(require.resolve(
    './postgres/secureshopStandaloneRoleChoicesRendered.integration.test'), 'utf8');
  const gates = [
    '...((MERCHANT_MAIL_ACTIONS_BROWSER || MAIL_HEADER_BROWSER || MAIL_HTML_BROWSER || V11_MAIL_READ_BROWSER) ? { mail: mailProduction } : {})',
    "if (USER_LOOKUP_BROWSER || ADMIN_POLICY_BROWSER || ADMIN_AUDIT_BROWSER || SYSTEM_READ_BROWSER || MERCHANT_MAIL_ACTIONS_BROWSER || MAIL_HEADER_BROWSER || MAIL_HTML_BROWSER || V11_MAIL_READ_BROWSER || REVIEW_INJECTION_BROWSER || LISTING_RAW_BROWSER || V03_BROWSER) app.use('/api/secureshop/auth'",
    'if ((MERCHANT_MAIL_ACTIONS_BROWSER || MAIL_HEADER_BROWSER || MAIL_HTML_BROWSER || V11_MAIL_READ_BROWSER || REVIEW_INJECTION_BROWSER || LISTING_RAW_BROWSER) && response.statusCode === 200',
  ];
  const check = source => gates.forEach(gate => assert.ok(source.includes(gate),
    'Mail-header opt-in must reach the actual mounted mail and bootstrap observers'));
  check(fixture);
  for (const gate of gates) {
    const priorGuard = gate.replace(' || MAIL_HEADER_BROWSER', '');
    assert.throws(() => check(fixture.replace(gate, priorGuard)));
  }
});

test('V05 retains scoped immutable contributions while separately checking reset retires active credit', () => {
  const fs = require('node:fs');
  const scenario = fs.readFileSync(require.resolve('./fixtures/secureshopMailHeaderRenderedScenario'), 'utf8');
  assert.equal(scenario.includes("rows('assessment_contributions')"), false,
    'The immutable base table has no objective_id for the generic filtered reader');
  assert.ok(scenario.includes('SELECT c.* FROM secureshop_auth.assessment_contributions c'));
  assert.ok(scenario.includes('JOIN secureshop_auth.assessment_judgments j USING (tenant_id,principal_id,evaluation_id)'));
  assert.ok(scenario.includes('c.tenant_id=$1 AND c.principal_id=$2 AND j.objective_id=$3'));
  assert.ok(scenario.includes('SELECT * FROM secureshop_auth.active_assessment_contributions'));
  assert.ok(scenario.includes('assert.deepEqual(active.rows, [])'));
  const base = fs.readFileSync(require.resolve('../db/postgres/identity-migrations/0142_secureshop_assessments.sql'), 'utf8')
    .split('CREATE TABLE secureshop_auth.assessment_contributions (')[1].split(');')[0];
  assert.equal(base.includes('objective_id'), false);
  const projection = fs.readFileSync(require.resolve('../db/postgres/identity-migrations/0146_secureshop_shop_progress_cleanup.sql'), 'utf8')
    .split('CREATE VIEW secureshop_auth.active_assessment_contributions AS')[1].split(';')[0];
  assert.ok(projection.includes('j.objective_id,j.generation,j.evaluation_id'));
  assert.ok(projection.includes('JOIN secureshop_auth.assessment_judgments'));
  assert.ok(projection.includes('assessment_cleanup_history'));
});

function originalServerSse() {
  const body = { sessionId: randomUUID(), requestId: randomUUID(), message: 'first\nsecond' };
  const raw = Buffer.from(JSON.stringify(body)), captures = [], calls = [];
  const request = { method: 'POST', originalUrl: '/api/secureshop/agents/merchant/assistant/chat',
    path: '/agents/merchant/assistant/chat', body };
  captureMailHeaderRequestBody(request, null, raw);
  const response = new EventEmitter();
  response.statusCode = 200;
  response.writableFinished = false;
  response.getHeader = () => 'text/event-stream; charset=utf-8';
  response.write = function (...args) {
    assert.equal(this, response); calls.push(['write', args]); return false;
  };
  response.end = function (...args) {
    assert.equal(this, response); calls.push(['end', args]);
    response.writableFinished = true; response.emit('finish'); return response;
  };
  const event = observeOriginalMailHeaderSse(request, response, captures);
  const browserRequest = { method: () => 'POST',
    url: () => 'http://127.0.0.1:8081/api/secureshop/agents/merchant/assistant/chat',
    postData: () => raw.toString('utf8') };
  const wire = { request: () => browserRequest, status: () => 200,
    headers: () => ({ 'content-type': 'text/event-stream; charset=utf-8' }),
    buffer: () => { throw Error('CDP body unavailable'); } };
  return { request, response, event, captures, calls, browserRequest, wire };
}

test('original server SSE bytes retain write/end arguments, return values and exact browser request joins', async () => {
  const value = originalServerSse(), callback = () => {}, chunk = Buffer.from('event: done\ndata: {"text":"π"}');
  assert.equal(value.response.write(chunk, callback), false);
  assert.equal(value.response.end('\n\n', 'utf8', callback), value.response);
  assert.equal(value.calls[0][1][0], chunk);
  assert.equal(value.calls[0][1][1], callback);
  assert.deepEqual(value.calls[1][1], ['\n\n', 'utf8', callback]);
  const expected = Buffer.concat([chunk, Buffer.from('\n\n')]);
  assert.deepEqual(validateOriginalMailHeaderSse(value.event, value.browserRequest, value.wire), expected);
  assert.deepEqual(await readOriginalMailHeaderSse(value.captures, value.browserRequest, value.wire), expected);
  assert.equal(value.event.responseSha256, createHash('sha256').update(expected).digest('hex'));
  const fs = require('node:fs');
  const caller = fs.readFileSync(require.resolve('./postgres/secureshopStandaloneRoleChoicesRendered.integration.test'), 'utf8');
  assert.ok(caller.includes('app.use((MAIL_HEADER_BROWSER || MAIL_HTML_BROWSER) ? express.json({'));
  assert.ok(caller.includes("require('../fixtures/secureshopMailHeaderRenderedScenario').captureMailHeaderRequestBody(request,response,bytes)"));
  assert.ok(caller.includes("require('../fixtures/secureshopMailHtmlRenderedQualification').captureV09RequestBody(request,response,bytes)"));
  assert.ok(caller.includes(": require('../fixtures/secureshopMailHeaderRenderedScenario').captureMailHeaderRequestBody,"));
  assert.ok(caller.includes('.observeOriginalMailHeaderSse(request, response, mailHeaderSseCaptures)'));
});

function originalServerJson(path = '/api/secureshop/agents/merchant/assistant/mail/confirm', method = 'POST') {
  const body = { sessionId: randomUUID(), requestId: randomUUID(), proposalId: randomUUID() };
  const raw = Buffer.from(JSON.stringify(body)), captures = [], calls = [];
  const request = { method, originalUrl: path, body: method === 'POST' ? body : undefined };
  if (method === 'POST') captureMailHeaderRequestBody(request, null, raw);
  const response = new EventEmitter();
  response.statusCode = 200;
  response.writableFinished = false;
  response.getHeader = () => 'application/json; charset=utf-8';
  response.write = function (...args) { calls.push(['write', args]); return false; };
  response.end = function (...args) { calls.push(['end', args]);
    response.writableFinished = true; response.emit('finish'); return response; };
  const event = observeOriginalMailHeaderJson(request, response, captures);
  const browserRequest = { method: () => method, url: () => `http://127.0.0.1:8081${path}`,
    postData: () => method === 'POST' ? raw.toString('utf8') : undefined };
  const wire = { request: () => browserRequest, status: () => 200,
    headers: () => ({ 'content-type': 'application/json; charset=utf-8' }),
    json: async () => { throw Error('CDP body unavailable'); } };
  return { request, response, event, captures, calls, browserRequest, wire, body };
}

test('original physical JSON response is captured without CDP decoding or request replay', async () => {
  const value = originalServerJson(), callback = () => {}, payload = { status: 'saved', operationId: randomUUID() };
  const first = Buffer.from(JSON.stringify(payload).slice(0, 12));
  assert.equal(value.response.write(first, callback), false);
  assert.equal(value.response.end(JSON.stringify(payload).slice(12), 'utf8', callback), value.response);
  assert.deepEqual(value.calls[0][1], [first, callback]);
  assert.deepEqual(value.calls[1][1], [JSON.stringify(payload).slice(12), 'utf8', callback]);
  assert.deepEqual(validateOriginalMailHeaderJson(value.event, value.browserRequest, value.wire), payload);
  assert.deepEqual(await readOriginalMailHeaderJson(value.captures, value.browserRequest, value.wire), payload);
  assert.equal(value.event.responseSha256, createHash('sha256').update(JSON.stringify(payload)).digest('hex'));
  const inbox = originalServerJson(`/api/secureshop/email/inbox/5?requestId=${randomUUID()}`, 'GET');
  inbox.response.end(JSON.stringify({ ok: true, emails: [] }));
  assert.deepEqual(await readOriginalMailHeaderJson(inbox.captures, inbox.browserRequest, inbox.wire),
    { ok: true, emails: [] });
  const caller = require('node:fs').readFileSync(require.resolve(
    './postgres/secureshopStandaloneRoleChoicesRendered.integration.test'), 'utf8');
  assert.ok(caller.includes('.observeOriginalMailHeaderJson(request, response, mailHeaderJsonCaptures)'));
});

test('original physical JSON rejects mutation, duplicate, truncation and incomplete delivery', async () => {
  const value = originalServerJson(); value.response.end('{"status":"saved"}');
  for (const change of [
    { method: 'GET' }, { url: '/api/secureshop/email/inbox/5' },
    { requestBytes: Buffer.from('{}') }, { requestSha256: '0'.repeat(64) },
    { body: { ...value.body, proposalId: randomUUID() } },
    { status: 503 }, { contentType: 'text/event-stream' }, { complete: false },
    { finished: false }, { captureTruncated: true }, { captureError: 'ORIGINAL_JSON_WRITE_FAILED' },
    { responseSha256: '0'.repeat(64) }, { bytes: Buffer.from('changed') },
  ]) assert.throws(() => validateOriginalMailHeaderJson({ ...value.event, ...change },
    value.browserRequest, value.wire));
  assert.throws(() => validateOriginalMailHeaderJson(value.event, value.browserRequest,
    { ...value.wire, request: () => ({}) }));
  await assert.rejects(readOriginalMailHeaderJson([value.event, value.event], value.browserRequest, value.wire), /Duplicate/);
  await assert.rejects(readOriginalMailHeaderJson([], value.browserRequest, value.wire, 1), /did not finish/);
  const incomplete = originalServerJson(); incomplete.response.write('{"partial":'); incomplete.response.emit('close');
  await assert.rejects(readOriginalMailHeaderJson(incomplete.captures, incomplete.browserRequest, incomplete.wire));
  const oversized = originalServerJson(); oversized.response.end(Buffer.alloc(131073));
  await assert.rejects(readOriginalMailHeaderJson(oversized.captures, oversized.browserRequest, oversized.wire));
});

test('original SSE rejects request/body/status/MIME/hash mutations, duplicates and incomplete streams', async () => {
  const value = originalServerSse();
  value.response.end('event: done\ndata: {}\n\n');
  for (const change of [
    { requestId: randomUUID() }, { sessionId: randomUUID() }, { method: 'GET' }, { path: '/different' },
    { body: { ...value.event.body, message: 'changed' } },
    { requestBytes: Buffer.from('{}') }, { requestSha256: '0'.repeat(64) }, { status: 503 },
    { contentType: 'application/json' }, { complete: false }, { finished: false },
    { captureTruncated: true }, { captureError: 'ORIGINAL_WRITE_FAILED' },
    { responseSha256: '0'.repeat(64) }, { bytes: Buffer.from('changed') },
  ]) assert.throws(() => validateOriginalMailHeaderSse({ ...value.event, ...change }, value.browserRequest, value.wire));
  assert.throws(() => validateOriginalMailHeaderSse(value.event, value.browserRequest,
    { ...value.wire, request: () => ({}) }));
  await assert.rejects(readOriginalMailHeaderSse([value.event, value.event], value.browserRequest, value.wire), /Duplicate/);
  await assert.rejects(readOriginalMailHeaderSse([], value.browserRequest, value.wire, 1), /did not finish/);
  const incomplete = originalServerSse();
  incomplete.response.write('event: assistant_message\ndata: {"text":"partial"}');
  incomplete.response.emit('close');
  await assert.rejects(readOriginalMailHeaderSse(incomplete.captures, incomplete.browserRequest, incomplete.wire));
  assert.equal(incomplete.event.complete, false);
  const oversized = originalServerSse();
  oversized.response.end(Buffer.alloc(131073));
  assert.equal(oversized.event.captureTruncated, true);
  await assert.rejects(readOriginalMailHeaderSse(oversized.captures, oversized.browserRequest, oversized.wire));
});

test('original SSE write failure is rethrown unchanged and unrelated routes are never captured', () => {
  const value = originalServerSse(), failure = new Error('Original write failed');
  const response = new EventEmitter();
  response.write = function () { throw failure; };
  response.end = function () { return this; };
  observeOriginalMailHeaderSse(value.request, response, []);
  assert.throws(() => response.write('original'), error => error === failure);
  const unrelated = { ...value.request, path: '/email/header-assessment' };
  const before = value.captures.length;
  assert.equal(observeOriginalMailHeaderSse(unrelated, value.response, value.captures), undefined);
  assert.equal(value.captures.length, before);
});
