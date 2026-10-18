'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const path = require('node:path');
const root = process.cwd();
const { createSceneBinding } = require(path.join(root, 'server/services/secureshopSceneBinding'));
const { createV01TeachingTokenAuthority } = require(path.join(root, 'server/services/secureshopV01TeachingToken'));
const { createV01CheckoutAuditLesson } = require(path.join(root, 'server/services/secureshopV01CheckoutAuditLesson'));
const { createBoundAuditStore } = require(path.join(root, 'server/database/postgres/secureshopBoundAuditRepository'));
const { createBoundAgentRunner } = require(path.join(root, 'server/services/secureshopBoundAgentRunner'));

function fixture() {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 3,
    platformOwnerId: 19, platformSessionId: 23 };
  const storage = { ...scope, generation: 1, platformSessionId: 17 };
  const targetId = randomUUID(), sceneId = randomUUID();
  const target = createSceneBinding({ ...storage, targetId }, { sceneId, sceneGeneration: 2,
    grantId: randomUUID(), execution: scope, withLease: work => work() });
  const persona = { id: 41, role: 'customer' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '2' };
  const checkoutOperationId = randomUUID(), eventId = randomUUID(), requestId = randomUUID();
  const checkout = { operationId: checkoutOperationId, status: 'completed',
    order: { id: 83, total: 17.25 } };
  const paramsJson = JSON.stringify({ total: 17.25, shippingAddress: 'Synthetic private address',
    paymentMethod: 'synthetic_card', storageTargetId: targetId,
    sceneId, sceneGeneration: 2 });
  const row = { event_id: eventId, ts: '2026-10-15T02:02:02.000000Z', actor: 'customer',
    action: 'checkout', outcome: 'completed', target: '83', source_kind: 'order',
    source_id: '83', params_json: paramsJson, order_total: '17.25',
    payment_method: 'synthetic_card', shipping_address: 'Synthetic private address' };
  let mode = 'vuln', stale = false, rowMode = 'one', rowReads = 0,
    receiptReads = 0, grants = 0;
  const client = { async query(sql, values) {
    if (sql.includes('assert_scene_execution_grant')) { grants++; return { rows: [{ allowed: !stale }] }; }
    if (sql.includes('FROM secureshop_review.bound_audit_events e')) {
      rowReads++;
      assert.match(sql, /e\.original_platform_owner_id=\$4/);
      assert.match(sql, /e\.source_kind='order'/);
      assert.deepEqual(values.slice(0, 8), [scope.launchId, scope.scenarioId, scope.generation,
        scope.platformOwnerId, scope.platformSessionId, targetId, persona.id, checkout.order.id]);
      assert.equal(values[9], sceneId);
      assert.equal(values[10], 2);
      assert.deepEqual(values.slice(11), [storage.launchId, storage.scenarioId,
        storage.generation, storage.platformOwnerId, storage.platformSessionId]);
      return { rows: values[8] && values[8] !== eventId ? []
        : rowMode === 'missing' ? [] : rowMode === 'duplicate' ? [row, row] : [row] };
    }
    return { rows: [] };
  }, release() {} };
  const auditStore = createBoundAuditStore({ store: 'review',
    pool: { query() {}, async connect() { return client; } },
    async checkCurrent(s) { assert.equal(s.launchId, scope.launchId); if (stale) throw Error('reset'); } });
  const checkoutHistory = { async read(t, id, operationId) {
    receiptReads++;
    assert.equal(t, target); assert.equal(id, persona.id); assert.equal(operationId, checkoutOperationId);
    return checkout;
  } };
  const modeAuthority = { async capture() {
    const captured = mode;
    return { snapshot: { featureId: 'checkout_audit_jwt', mode: captured, scope },
      async assertCurrent() { if (stale || mode !== captured) throw Error('mode stale'); },
      async assertCurrentAtEffect() { if (stale || mode !== captured) throw Error('mode stale'); } };
  }, assertToken(token) { return token; } };
  const personaAuthority = { async capture(x) { return { binding: { ...x.scope,
    personaId: x.personaId, role: x.role, sessionId: x.sessionId,
    authorityVersion: x.authorityVersion },
    async assertRemoteAdmission() { if (stale) throw Error('persona stale'); } }; } };
  const secretMaterial = Buffer.alloc(32, 17);
  const lesson = createV01CheckoutAuditLesson({ secretMaterial, checkoutHistory,
    auditStore, launches: { async assertCurrent() { if (stale) throw Error('reset'); } },
    personaAuthority, modeAuthority, async resolveExistingTarget() { return target; } });
  const execution = { runId: randomUUID(), ownerKey: '["SecureShop",19]',
    durableGeneration: '3', async check() { if (stale) throw Error('reset'); } };
  const input = { scope, persona, personaSession, checkoutOperationId, requestId, execution };
  function observed(result, teachingToken) {
    const step = 1, callId = 'v01-model-call-1', tool = 'auth.audit_probe';
    return { index: 0, step, callId, tool,
      args: { checkoutOperationId, teachingToken },
      result: structuredClone(result),
      effectReceipt: { version: 1, status: 'completed', runId: execution.runId,
        ownerKey: execution.ownerKey, generation: execution.durableGeneration,
        effectKey: `${requestId}:${JSON.stringify([step, callId, tool])}` } };
  }
  return { scope, target, persona, checkout, eventId, row, lesson, input, observed,
    tokens: createV01TeachingTokenAuthority({ secretMaterial }),
    mode(value) { mode = value; }, stale(value = true) { stale = value; },
    rowMode(value) { rowMode = value; },
    counts() { return { rowReads, receiptReads, grants }; } };
}

function forgeNone(signed) {
  const [header, payload] = signed.split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  claims.role = 'admin';
  return `${Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'none' })).toString('base64url')}.`
    + `${Buffer.from(JSON.stringify(claims)).toString('base64url')}.`;
}

function report(result) { return JSON.parse(result.content[0].text); }

test('owned checkout event is the exact immutable protected source', async () => {
  const f = fixture();
  const token = await f.lesson.presentCustomerToken(f.input);
  const publicClaims = JSON.parse(Buffer.from(token.token.split('.')[1], 'base64url').toString('utf8'));
  for (const name of ['launchId','scenarioId','generation','platformOwnerId',
    'platformSessionId','targetId','shopUserId']) assert.equal(publicClaims[name], undefined);
  assert.match(publicClaims.bindingTag, /^[A-Za-z0-9_-]{43}$/);
  const forged = forgeNone(token.token);
  const result = await f.lesson.readAudit({ ...f.input, teachingToken: forged });
  assert.equal(report(result).eventId, f.eventId);
  assert.equal(report(result).report.orderId, f.checkout.order.id);
  assert.equal(report(result).report.shippingAddress, undefined);
  assert.equal(report(result).report.paymentMethod, undefined);
  assert.equal(JSON.stringify(result).includes('platformSessionId'), false);
  const observed = f.observed(result, forged);
  assert.throws(() => f.lesson.evidenceFor(observed), { code: 'V01_EVIDENCE_UNAVAILABLE' });
  const evidence = await f.lesson.bindObservedEffect({ ...f.input, teachingToken: forged }, observed);
  assert.equal(f.lesson.evidenceFor(observed), evidence);
  assert.equal(evidence.teachingAlgorithm, 'none');
  assert.equal(evidence.scope.platformSessionId, f.scope.platformSessionId);
  assert.match(evidence.sourceSha256, /^[a-f0-9]{64}$/);
  assert.equal(f.counts().rowReads, 2);
});

test('completed graph effect replays by its saved event ID and source digest', async () => {
  const f = fixture();
  const token = forgeNone((await f.lesson.presentCustomerToken(f.input)).token);
  const original = await f.lesson.readAudit({ ...f.input, teachingToken: token });
  const saved = f.observed(original, token);
  const first = await f.lesson.bindObservedEffect({ ...f.input, teachingToken: token }, saved);
  // Simulate replay of the graph's durable public effect without rerunning
  // the local tool callback or retaining its object identity.
  const replay = structuredClone(saved);
  const second = await f.lesson.bindObservedEffect({ ...f.input, teachingToken: token }, replay);
  assert.deepEqual(second, first);
  assert.equal(f.counts().rowReads, 3);
});

test('a graph receipt with another request prefix is unavailable', async () => {
  const f = fixture();
  const token = forgeNone((await f.lesson.presentCustomerToken(f.input)).token);
  const result = await f.lesson.readAudit({ ...f.input, teachingToken: token });
  const observed = f.observed(result, token);
  observed.effectReceipt.effectKey = `${randomUUID()}:${JSON.stringify([
    observed.step, observed.callId, observed.tool])}`;
  await assert.rejects(f.lesson.bindObservedEffect({ ...f.input, teachingToken: token }, observed),
    { code: 'V01_EFFECT_UNAVAILABLE' });
  assert.equal(f.counts().rowReads, 1);
});

test('fixed mode rejects unsigned admin claim before protected audit read', async () => {
  const f = fixture();
  const token = await f.lesson.presentCustomerToken(f.input);
  f.mode('fixed');
  await assert.rejects(f.lesson.readAudit({ ...f.input, teachingToken: forgeNone(token.token) }),
    { code: 'V01_TEACHING_TOKEN_DENIED' });
  assert.equal(f.counts().rowReads, 0);
});

test('sibling launch, order and target claims cannot authorize a checkout audit', async () => {
  const f = fixture();
  const token = forgeNone((await f.lesson.presentCustomerToken(f.input)).token);
  for (const [name, value] of [['bindingTag', 'other-scope'], ['orderId', 84],
    ['sub', 'shop-user:99']]) {
    const parts = token.split('.');
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    claims[name] = value;
    const changed = `${parts[0]}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.`;
    await assert.rejects(f.lesson.readAudit({ ...f.input, teachingToken: changed }),
      { code: 'V01_TEACHING_TOKEN_DENIED' });
  }
  assert.throws(() => f.tokens.verifyAdmin(token, 'vuln',
    { ...f.scope, platformSessionId: f.scope.platformSessionId + 1 },
    f.target.targetId, f.persona.id, f.checkout.order.id),
  { code: 'V01_TEACHING_TOKEN_DENIED' });
  assert.equal(f.counts().rowReads, 0);
});

test('reset and mode drift fence the effect, with no audit read', async () => {
  const f = fixture();
  const token = forgeNone((await f.lesson.presentCustomerToken(f.input)).token);
  f.stale();
  await assert.rejects(f.lesson.readAudit({ ...f.input, teachingToken: token }));
  assert.equal(f.counts().rowReads, 0);
  const g = fixture();
  const token2 = forgeNone((await g.lesson.presentCustomerToken(g.input)).token);
  g.mode('fixed');
  await assert.rejects(g.lesson.readAudit({ ...g.input, teachingToken: token2 }));
  assert.equal(g.counts().rowReads, 0);
});

test('audit lookup rejects substituted original row', async () => {
  const f = fixture();
  const forged = forgeNone((await f.lesson.presentCustomerToken(f.input)).token);
  f.row.order_total = '99.00';
  await assert.rejects(f.lesson.readAudit({ ...f.input, teachingToken: forged }),
    { code: 'INVALID_ARGUMENT' });
});

test('audit lookup denies missing and duplicate event rows', async () => {
  for (const rowMode of ['missing','duplicate']) {
    const f = fixture();
    const token = forgeNone((await f.lesson.presentCustomerToken(f.input)).token);
    f.rowMode(rowMode);
    await assert.rejects(f.lesson.readAudit({ ...f.input, teachingToken: token }),
      { code: 'INVALID_ARGUMENT' });
    assert.equal(f.counts().rowReads, 1);
  }
});

test('substituted durable digest and report never gain an evidence packet', async () => {
  const f = fixture();
  const token = forgeNone((await f.lesson.presentCustomerToken(f.input)).token);
  const result = await f.lesson.readAudit({ ...f.input, teachingToken: token });
  for (const change of [v => { v.sourceSha256 = '0'.repeat(64); },
    v => { v.report.total = 1; }]) {
    const changed = structuredClone(result);
    const value = report(changed); change(value);
    changed.content[0].text = JSON.stringify(value);
    const observed = f.observed(changed, token);
    await assert.rejects(f.lesson.bindObservedEffect({ ...f.input, teachingToken: token }, observed),
      { code: 'V01_SOURCE_CHANGED' });
  }
});

test('actual BoundAgentRunner graph binds the selected tool and its durable effect receipt', async () => {
  const f = fixture();
  const teachingToken = forgeNone((await f.lesson.presentCustomerToken(f.input)).token);
  const args = { checkoutOperationId: f.input.checkoutOperationId, teachingToken };
  const sessionId = randomUUID(), messages = [], effects = [], packets = [], claims = new Map();
  let execution, modelCalls = 0;
  const identity = f.input.execution;
  const turns = { async run(_id, _binding, _persona, options, operation) {
    assert.equal(options.idempotencyKey, f.input.requestId);
    return operation({ identity, async check() {}, async trace() {},
      async effectWithReceipt(node, work) {
        effects.push(node);
        const value = await work();
        return { value, receipt: { version: 1, status: 'completed',
          runId: identity.runId, ownerKey: identity.ownerKey,
          generation: identity.durableGeneration,
          effectKey: `${options.idempotencyKey}:${node}` } };
      } });
  } };
  const runner = createBoundAgentRunner({ turns,
    conversations: { async assertOwned() {}, async getMessages() { return structuredClone(messages); } },
    repository: {
      async appendMessage(_id, _binding, message) { messages.push(structuredClone(message)); },
      async getTokens() { return 0; }, async addTokens() {}, async appendTraces() {},
    },
    journal: { async claim({ requestId }) { claims.set(requestId, 'claimed');
      return { status: 'claimed', claimId: requestId }; },
      async complete({ requestId }) { claims.set(requestId, 'completed'); },
      async markUncertain() {} },
    provider: { async chat() { return modelCalls++ === 0
      ? { stop_reason: 'tool_use',
        tool_uses: [{ id: 'selected-v01-call', name: 'auth.audit_probe', args }] }
      : { stop_reason: 'end_turn', text: 'Observed the owned audit report.' }; },
      async finalResponse() { return { stop_reason: 'end_turn', text: 'Observed the owned audit report.',
        responseMode: 'structured_final' }; } },
    pool: { async callTool() { throw Error('Remote tool is unavailable'); } },
    manifest: { getForRole: () => [{ agent: 'auth', tool: 'audit_probe',
      description: 'Read the selected owned checkout audit through the practice verifier.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: true } }] },
    buildBasePrompt: () => 'Select the declared audit practice tool.',
    buildPolicyBlock: async () => '',
    checkToolAcl: async () => ({ allowed: true, action: 'dispatch',
      policyViolation: null, enforcement: true }),
    createLocalTools(_binding, _context, _authority, actual) {
      execution = actual;
      return { 'auth.audit_probe': value => f.lesson.readAudit({ ...f.input,
        checkoutOperationId: value.checkoutOperationId,
        teachingToken: value.teachingToken, execution: actual }) };
    },
    observeLocalTool: async ({ observation, requestId }) => {
      assert.equal(requestId, f.input.requestId);
      const privatePacket = await f.lesson.bindObservedEffect({ ...f.input,
        checkoutOperationId: args.checkoutOperationId, teachingToken,
        execution }, observation);
      packets.push(structuredClone(privatePacket));
    },
    limits: { maxSteps: 3, maxParallelTools: 1 },
  });
  const result = await runner.run({ sessionId, requestId: f.input.requestId,
    scope: f.scope, persona: f.persona, personaSession: f.input.personaSession,
    message: 'Read the audit report for my confirmed checkout.' });
  assert.equal(result.stopReason, 'end_turn');
  assert.equal(result.hops.length, 1);
  assert.equal(effects.length, 1);
  assert.equal(effects[0], JSON.stringify([1, 'selected-v01-call', 'auth.audit_probe']));
  assert.equal(packets.length, 1);
  assert.equal(packets[0].eventId, f.eventId);
  assert.equal(packets[0].effectReceipt.effectKey,
    `${f.input.requestId}:${effects[0]}`);
  assert.equal(claims.get(f.input.requestId), 'completed');
});
