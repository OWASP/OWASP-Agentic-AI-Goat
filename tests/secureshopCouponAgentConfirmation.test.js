'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCouponAgentConfirmation } = require('../server/services/secureshopCouponAgentConfirmation');
const { createBoundCouponAgentConfirmRouter, closedConfirmation, couponResult, publicError } = require('../server/routes/secureshop/boundCouponAgentConfirm');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { capture } = require('../server/database/postgres/secureshopCustomerChatBindingRepository');
const { projectFeatureMode } = require('../server/services/secureshopFeatureModeAuthority');
const Coupon = require('../server/services/secureshopCouponAgentContract');
const S = '00000000-0000-4000-8000-000000000001';
const R = '00000000-0000-4000-8000-000000000002';
const E = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const scope = { launchId: E(10), scenarioId: E(11), generation: 2,
  platformOwnerId: 8, platformSessionId: 9 };
const persona = { id: 10, role: 'customer' };
const personaSession = { sessionId: E(12), authorityVersion: '3' };
const target = createSceneBinding({ ...scope, targetId: E(13) },
  { sceneId: E(14), sceneGeneration: 1, grantId: E(15), execution: scope,
    withLease: async work => work() });
const code = "' OR 1=1--", human = `Apply coupon ${code}`;
const envelope = JSON.stringify({ version: 1, sceneId: target.scene.sceneId,
  sceneGeneration: 1, targetId: target.targetId, requestId: R, message: human });
const captured = capture({ sessionId: S, requestId: R, scope, persona,
  personaSession, target, message: envelope });
const sourceOrigin = { turnSessionId: S, turnRequestId: R, toolKey: Coupon.TOOL,
  invocationStep: 1, callId: 'coupon-call' };
const couponProposal = Coupon.prepare({ code, message: human, sourceOrigin });
const result = { content: [{ type: 'text', text: JSON.stringify({ status: 'confirmation_required',
  couponProposal, couponOrigin: sourceOrigin }) }] };
const columnPairs = [['session_id', 'sessionId'], ['request_id', 'requestId'],
  ['launch_id', 'launchId'], ['scenario_id', 'scenarioId'], ['generation', 'generation'],
  ['owner_id', 'ownerId'], ['execution_session_id', 'executionSessionId'],
  ['persona_id', 'personaId'], ['persona_session_id', 'personaSessionId'],
  ['authority_version', 'authorityVersion'], ['scene_id', 'sceneId'],
  ['scene_generation', 'sceneGeneration'], ['grant_id', 'grantId'],
  ['target_id', 'targetId'], ['envelope_sha256', 'envelopeSha256'],
  ['request_hash', 'requestHash']];
function fixture() {
  const state = { stale: false, checkCount: 0, effects: [], reads: [], saved: null };
  const mode = feature('customer_chat', state), couponMode = feature('coupons', state);
  const binding = Object.fromEntries(columnPairs.map(([db, js]) => [db, captured[js]]));
  const traces = [
    { id: 1, event_id: E(1), session_id: S, step: 1, actor: 'supervisor',
      kind: 'model_decision', provider: 'ollama',
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: sourceOrigin.callId,
        name: Coupon.TOOL, args: { code } }] }),
      result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
    { id: 2, event_id: E(2), session_id: S, step: 1, actor: 'supervisor→task',
      kind: 'local_tool_call', agent_ns: 'cart', tool_name: 'coupon_prepare',
      params_json: JSON.stringify({ code }) },
    { id: 3, event_id: E(3), session_id: S, step: 1, actor: 'task→supervisor',
      kind: 'local_tool_result', agent_ns: 'cart', tool_name: 'coupon_prepare',
      result_json: JSON.stringify(result) },
    { id: 4, event_id: E(4), session_id: S, step: 2, actor: 'supervisor',
      kind: 'terminal', provider: 'ollama', result_json: JSON.stringify({
        stopReason: 'end_turn', steps: 2, hops: 1, model: 'llama3.1:8b', mocked: false }) },
  ];
  const customerChat = { version: 1, sceneId: captured.sceneId,
    sceneGeneration: captured.sceneGeneration, targetId: captured.targetId,
    envelopeSha256: captured.envelopeSha256, cards: [], orderPage: null,
    paymentSetup: null, addressSetup: null, refundSetup: null,
    profileProposal: null, profileOrigin: null, couponOrigin: sourceOrigin,
    couponProposal, traceEventIds: traces.map(row => row.event_id) };
  const turn = { session_id: S, status: 'completed', request_version: 1,
    request_hash: captured.requestHash, result_json: { stopReason: 'end_turn',
      steps: 2, hops: [{ step: 1, tool: Coupon.TOOL, params: { code }, result }],
      taskMetadata: { customerChat }, modeCapability: projectFeatureMode(mode) } };
  const service = createCouponAgentConfirmation({
    captureCurrent: async () => ({ scope, persona, personaSession, target, mode, couponMode,
      check: async () => { state.checkCount++; if (state.stale) throw Object.assign(new Error('stale'),
        { code: 'SHOP_SCENE_STALE' }); } }),
    bindingRepository: { read: async () => binding },
    journal: { readBoundRequest: async () => turn },
    conversations: {
      getMessages: async () => [{ role: 'user', content: envelope,
        modeCapability: projectFeatureMode(mode) }],
      getTraceEvents: async () => traces,
    },
    qualifyModel: identity => identity.provider === 'ollama' && identity.mocked === false,
    applyConfirmedCoupon: async input => { state.effects.push(input); return { ok: true,
      code: 'OWNED', discount_percent: 25, subtotal: 4, applied_amount: 1 }; },
    readConfirmedCoupon: async input => { state.reads.push(input); return state.saved; },
  });
  return { service, state, turn, traces };
}
function feature(featureId, state) {
  return { snapshot: { featureId, policyVersion: 'v1', mode: 'vuln' },
    assertCurrent: async () => { if (state.stale) throw Object.assign(new Error('stale'),
      { code: 'SHOP_AUTH_INVALID' }); } };
}

test('closed route IDs drive exact saved proposal into target-bound effect dependency', async () => {
  const selected = fixture(), request = { sessionId: S, requestId: R,
    proposalId: couponProposal.proposalId };
  assert.deepEqual(closedConfirmation(request), request);
  assert.equal(closedConfirmation({ ...request, code }), null);
  assert.equal(closedConfirmation({ ...request, operationId: couponProposal.proposalId }), null);
  const value = await selected.service.confirm({}, request);
  assert.equal(value.result.ok, true);
  assert.equal(selected.state.effects.length, 1);
  const effect = selected.state.effects[0];
  assert.equal(effect.code, code);
  assert.equal(effect.operationId, couponProposal.proposalId);
  assert.deepEqual(effect.expectedTarget, { targetId: target.targetId,
    sceneId: target.scene.sceneId, sceneGeneration: target.scene.sceneGeneration,
    grantId: target.scene.grantId });
  assert.equal(effect.customerMode.snapshot.featureId, 'customer_chat');
  assert.equal(effect.couponMode.snapshot.featureId, 'coupons');
  assert.equal(typeof effect.checkCurrent, 'function');
  assert.equal(value.source.callEventId, E(2));
  assert.equal(publicError({ code: 'COUPON_AGENT_SOURCE_INVALID' }).status, 409);
});

test('changed saved call and stale current authority never reach coupon effect', async () => {
  const request = { sessionId: S, requestId: R, proposalId: couponProposal.proposalId };
  const forged = fixture();
  forged.traces[1].params_json = JSON.stringify({ code: 'OTHER' });
  await assert.rejects(forged.service.confirm({}, request),
    error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  assert.equal(forged.state.effects.length, 0);
  const stale = fixture(); stale.state.stale = true;
  await assert.rejects(stale.service.confirm({}, request),
    error => error.code === 'SHOP_SCENE_STALE');
  assert.equal(stale.state.effects.length, 0);
});

test('protected saved confirmation GET is read-only and binds exact original code and receipt', async () => {
  const selected = fixture(), request = { sessionId: S, requestId: R,
    proposalId: couponProposal.proposalId };
  assert.deepEqual(await selected.service.readSaved({}, request),
    { status: 'unconfirmed' });
  assert.equal(selected.state.reads.length, 1);
  assert.equal(selected.state.effects.length, 0);
  const savedResult = { ok: true, code, discount_percent: 25,
    subtotal: 4, applied_amount: 1 };
  selected.state.saved = { state: 'completed', request: {
    operationId: couponProposal.proposalId, code, mode: 'vuln', scope,
    persona, personaSession }, result: savedResult };
  assert.deepEqual(await selected.service.readSaved({}, request),
    { status: 'completed', result: savedResult });
  assert.equal(selected.state.reads[1].code, code);
  assert.equal(selected.state.reads[1].operationId, couponProposal.proposalId);
  assert.equal(selected.state.reads[1].expectedTarget.grantId, target.scene.grantId);
  assert.equal(selected.state.effects.length, 0);
  selected.state.saved = { ...selected.state.saved,
    request: { ...selected.state.saved.request, code: 'WRONG' } };
  await assert.rejects(selected.service.readSaved({}, request),
    { code: 'COUPON_AGENT_SOURCE_INVALID' });
  selected.state.saved = null; selected.state.stale = true;
  await assert.rejects(selected.service.readSaved({}, request),
    { code: 'SHOP_SCENE_STALE' });
  assert.equal(selected.state.effects.length, 0);
});

test('unmounted route projects only coupon result from closed identity request', async () => {
  const captured = [];
  const router = createBoundCouponAgentConfirmRouter({
    launches: { resolveCapability: async () => scope },
    authenticatePersona: (_req, _res, next) => next(),
    confirmation: { confirm: async (...args) => { captured.push(args);
      return { result: { ok: false, error: 'coupon not found' },
        source: { code: 'PRIVATE', traceEventIds: [E(1)] } }; },
      readSaved: async (...args) => { captured.push(args);
        return { status: 'completed', result: { ok: false,
          error: 'coupon not found' } }; } },
  });
  const route = router.stack.find(layer => layer.route?.path === '/agents/customer/coupons/confirm')?.route;
  assert.equal(route?.methods.post, true);
  const handle = route.stack.at(-1).handle;
  const request = { sessionId: S, requestId: R, proposalId: couponProposal.proposalId };
  const req = { body: request, query: {}, is: () => true, ssLaunch: scope,
    boundPersona: persona, ssPersonaSession: personaSession };
  const res = { statusCode: null, body: null, headers: {},
    status(value) { this.statusCode = value; return this; },
    set(key, value) { this.headers[key] = value; return this; },
    json(value) { this.body = value; return this; } };
  await handle(req, res);
  assert.equal(res.statusCode, 404);
  assert.deepEqual(res.body, { ok: false, error: 'coupon not found' });
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.deepEqual(captured[0][1], request);
  assert.equal(captured[0][0].persona, persona);
  req.body = { ...request, code };
  await handle(req, res);
  assert.equal(res.statusCode, 400);
  assert.equal(captured.length, 1);
  assert.deepEqual(couponResult({ ok: true, code: 'SAVE25', discount_percent: 25,
    subtotal: 4, applied_amount: 1 }),
  { ok: true, code: 'SAVE25', discount_percent: 25, subtotal: 4, applied_amount: 1 });
  assert.throws(() => couponResult({ ok: true, code: 'SAVE25', discount_percent: 25,
    subtotal: 4, applied_amount: 1, traceEventIds: [E(1)] }));
  assert.throws(() => couponResult({ ok: false, error: 'coupon not found', source: 'PRIVATE' }));
  const getRoute = router.stack.find(layer => layer.route?.path ===
    '/agents/customer/coupons/confirm/:sessionId/:requestId/:proposalId')?.route;
  assert.equal(getRoute?.methods.get, true);
  const get = getRoute.stack.at(-1).handle;
  req.params = request; req.query = {};
  await get(req, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, { status: 'completed', result: {
    ok: false, error: 'coupon not found' } });
  assert.deepEqual(captured.at(-1)[1], request);
  req.params = { ...request, proposalId: E(99) }; req.query = { code };
  await get(req, res);
  assert.equal(res.statusCode, 400);
});
