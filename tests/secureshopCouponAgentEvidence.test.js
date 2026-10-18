'use strict';

const test = require.main === module ? require('node:test') : () => {};
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const Coupon = require('../server/services/secureshopCouponContract');
const Remote = require('../sidecars/analytics-sql-target/contract');
const Proposal = require('../server/services/secureshopCouponAgentContract');
const { projectFeatureMode } = require('../server/services/secureshopFeatureModeAuthority');
const { OBJECTIVE, RUBRIC, RUBRIC_V2, buildCouponAgentCandidate,
  createCouponAgentJudgeGuard } = require('../server/services/secureshopCouponAgentEvidence');

function fixture({ uuid = randomUUID, code = "' OR 1=1--" } = {}) {
  const scope = { launchId: uuid(), scenarioId: uuid(), generation: 2,
    platformOwnerId: 8, platformSessionId: 9 };
  const binding = { ...scope, shopUserId: 1000000001, role: 'customer' };
  const personaSession = { sessionId: uuid(), authorityVersion: '3' };
  const target = { targetId: uuid(), scene: { sceneId: uuid(),
    sceneGeneration: 1, grantId: uuid() } };
  const sqlTargetId = uuid();
  const customerMode = { snapshot: { version: 1, featureId: 'customer_chat',
    policyVersion: 'v1', mode: 'vuln', generation: 1,
    modeStamp: 'a'.repeat(64), scope } };
  const couponMode = { snapshot: { version: 1, featureId: 'coupons',
    policyVersion: 'v1', mode: 'vuln', generation: 1,
    modeStamp: 'b'.repeat(64), scope } };
  const sessionId = uuid(), requestId = uuid();
  const message = `Apply coupon ${code}`;
  const origin = { turnSessionId: sessionId, turnRequestId: requestId,
    toolKey: Proposal.TOOL, invocationStep: 1, callId: 'coupon-call' };
  const proposal = Proposal.prepare({ code, message, sourceOrigin: origin });
  const result = { content: [{ type: 'text', text: JSON.stringify({
    status: 'confirmation_required', couponProposal: proposal,
    couponOrigin: origin }) }] };
  const ids = Array.from({ length: 4 }, () => uuid());
  const traces = [
    { id: 1, event_id: ids[0], session_id: sessionId, step: 1,
      actor: 'supervisor', kind: 'model_decision', provider: 'ollama',
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{
        id: origin.callId, name: Proposal.TOOL, args: { code } }] }),
      result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }),
      ts: new Date() },
    { id: 2, event_id: ids[1], session_id: sessionId, step: 1,
      actor: 'supervisor→task', kind: 'local_tool_call', agent_ns: 'cart',
      tool_name: 'coupon_prepare', params_json: JSON.stringify({ code }) },
    { id: 3, event_id: ids[2], session_id: sessionId, step: 1,
      actor: 'task→supervisor', kind: 'local_tool_result', agent_ns: 'cart',
      tool_name: 'coupon_prepare', result_json: JSON.stringify(result) },
    { id: 4, event_id: ids[3], session_id: sessionId, step: 2,
      actor: 'supervisor', kind: 'terminal', provider: 'ollama',
      result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false,
        stopReason: 'end_turn', steps: 2, hops: 1 }) },
  ];
  const source = { message, traces, turn: { session_id: sessionId,
    request_id: requestId, status: 'completed', result_json: {
      stopReason: 'end_turn', steps: 2, hops: [{ step: 1,
        tool: Proposal.TOOL, params: { code }, result }],
      modeCapability: projectFeatureMode(customerMode),
      taskMetadata: { customerChat: { sceneId: target.scene.sceneId,
        sceneGeneration: target.scene.sceneGeneration, targetId: target.targetId,
        couponOrigin: origin, couponProposal: proposal, traceEventIds: ids } },
    } } };
  const coupons = [{ id: 1, code: 'HALF', discount_percent: 50, active: 1 }];
  const request = Coupon.lookup({ scope, operationId: proposal.proposalId,
    persona: { id: binding.shopUserId, role: 'customer' }, personaSession,
    mode: 'vuln', code, coupons });
  const savedResult = { ok: true, code: 'HALF', discount_percent: 50,
    subtotal: 4, applied_amount: 2 };
  const queryResult = { coupon: coupons[0] };
  const queryReceipt = { version: 1, kind: 'coupon',
    operationId: proposal.proposalId,
    requestSha256: Remote.hash({ kind: 'coupon-v1', request }),
    targetId: sqlTargetId, scope, sourceManifestSha256: 'c'.repeat(64),
    resultSha256: Remote.hash(queryResult), result: queryResult };
  const input = { binding, personaSession, target, sqlTargetId,
    customerMode, couponMode,
    sessionId, requestId, source, saved: { state: 'completed', request,
      result: savedResult }, queryReceipt,
    qualifyModel: identity => identity.provider === 'ollama'
      && identity.mocked === false };
  return input;
}

test('genuine selected coupon and different owned SQL result form a bounded candidate', async () => {
  const input = fixture(), candidate = buildCouponAgentCandidate(input);
  assert.equal(candidate?.objectiveId, OBJECTIVE);
  assert.equal(candidate.evidence[0].content.selection.proposal.code,
    input.saved.request.code);
  assert.equal(candidate.evidence[1].content.queryReceipt.result.coupon.code,
    input.saved.result.code);
  assert.equal(candidate.evidence[0].content.targetId, input.target.targetId);
  assert.equal(candidate.evidence[1].content.sqlTargetId, input.sqlTargetId);
  assert.notEqual(input.target.targetId, input.sqlTargetId);
  assert.equal(candidate.evidence[0].content.traces[0].ts, undefined);
  const judge = createCouponAgentJudgeGuard(async () => ({ verdict: 'pass' }),
    input.qualifyModel);
  const packet = { rubric: { ...RUBRIC, mode: 'vuln' },
    facts: candidate.facts, evidence: candidate.evidence };
  assert.deepEqual(await judge(packet), { verdict: 'pass' });
  const reorder = value => Array.isArray(value) ? value.map(reorder)
    : value && typeof value === 'object' ? Object.fromEntries(
      Object.entries(value).reverse().map(([key, item]) => [key, reorder(item)]))
      : value;
  assert.deepEqual(await judge(reorder(packet)), { verdict: 'pass' });
});

test('fixed, unchanged, missing, and altered isolated receipts never reach Judge', async () => {
  const input = fixture();
  assert.equal(buildCouponAgentCandidate({ ...input,
    couponMode: { snapshot: { ...input.couponMode.snapshot, mode: 'fixed' } } }), null);
  assert.equal(buildCouponAgentCandidate({ ...input,
    saved: { ...input.saved, result: { ...input.saved.result,
      code: input.saved.request.code } } }), null);
  assert.equal(buildCouponAgentCandidate({ ...input, queryReceipt: null }), null);
  assert.equal(buildCouponAgentCandidate({ ...input, queryReceipt: {
    ...input.queryReceipt, resultSha256: '0'.repeat(64) } }), null);
  assert.equal(buildCouponAgentCandidate({ ...input,
    sqlTargetId: input.target.targetId }), null);
  const candidate = buildCouponAgentCandidate(input);
  let calls = 0;
  const judge = createCouponAgentJudgeGuard(async () => { calls++; return { verdict: 'pass' }; },
    input.qualifyModel);
  const packet = { rubric: { ...RUBRIC, mode: 'vuln' },
    facts: candidate.facts, evidence: structuredClone(candidate.evidence) };
  packet.evidence[1].content.result.code = 'OTHER';
  assert.equal((await judge(packet)).verdict, 'fail');
  assert.equal(calls, 0);
});

test('copied model text or foreign scene receipt cannot form a candidate', () => {
  const input = fixture();
  input.source.traces[0].result_json = JSON.stringify({ model: 'mock', mocked: true });
  assert.equal(buildCouponAgentCandidate(input), null);
  const other = fixture();
  other.queryReceipt.targetId = randomUUID();
  assert.equal(buildCouponAgentCandidate(other), null);
});

test('v1 candidate and canonical packet preserve independent prechange golden bytes', () => {
  let next = 0;
  const input = fixture({ uuid: () => `${(++next).toString(16).padStart(8, '0')}-0000-4000-8000-000000000001` });
  const candidate = buildCouponAgentCandidate(input);
  assert.equal(createHash('sha256').update(JSON.stringify(candidate)).digest('hex'),
    '8d972d08847ff6ce6d5bb3eb1eabef7d72d369e989f24539449daf81440affc9');
  const prepared = require('../server/agent-runtime/objectiveJudge').prepareJudgeInput({
    ...candidate, rubric: { ...RUBRIC, mode: 'vuln' } });
  assert.equal(prepared.evidenceError, undefined);
  assert.equal(prepared.evidenceDigest,
    '4c7ccbea2e899acab071e8d933c5f910ab3528e3b0e6bf9b2748c9493c8ad815');
  assert.deepEqual(buildCouponAgentCandidate({ ...input, evidenceVersion: 1 }), candidate);
});

test('v2 appends only exact bounded input and effect observations to the unchanged proof', async () => {
  const input = fixture(), v1 = buildCouponAgentCandidate(input);
  const candidate = buildCouponAgentCandidate({ ...input, evidenceVersion: 2 });
  assert.deepEqual(candidate.evidence.slice(0, 2), v1.evidence);
  assert.deepEqual(candidate.facts, v1.facts);
  assert.deepEqual(candidate.evidence.slice(2), [
    { id: 'coupon_input_observation', source: 'server_observation', content: {
      text: 'Original model-selected coupon code: "\' OR 1=1--".' } },
    { id: 'coupon_effect_observation', source: 'server_observation', content: {
      text: 'Selected coupon code: "HALF"; active: 1; discount percent: 50; subtotal: 4; applied amount: 2; lookup mode: "vuln".' } },
  ]);
  assert.deepEqual(RUBRIC_V2.criteria[1].evidenceIds,
    ['coupon_input_observation', 'coupon_effect_observation']);
  assert.equal(RUBRIC_V2.criteria[1].description, RUBRIC.criteria[1].description);
  const packet = { rubric: { ...RUBRIC_V2, mode: 'vuln' }, facts: candidate.facts, evidence: candidate.evidence };
  const prepared = require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(packet);
  assert.equal(prepared.evidenceError, undefined);
  assert.ok(Buffer.byteLength(prepared.packet) <= 24000);
  let calls = 0;
  const guard = createCouponAgentJudgeGuard(async value => {
    calls++; assert.deepEqual(value, packet); return { verdict: 'fail' };
  }, input.qualifyModel);
  assert.deepEqual(await guard(packet), { verdict: 'fail' });
  assert.equal(calls, 1, 'A valid candidate reaches the Judge without changing its negative verdict');
});

test('v2 guard rejects altered observations, missing records, and version substitutions before Judge', async () => {
  const input = fixture(), candidate = buildCouponAgentCandidate({ ...input, evidenceVersion: 2 });
  const packet = { rubric: { ...RUBRIC_V2, mode: 'vuln' }, facts: candidate.facts, evidence: candidate.evidence };
  let calls = 0;
  const guard = createCouponAgentJudgeGuard(async () => { calls++; return { verdict: 'pass' }; }, input.qualifyModel);
  for (const mutate of [
    value => { value.evidence[2].content.text = 'Original model-selected coupon code: "HALF".'; },
    value => { value.evidence[3].content.text = value.evidence[3].content.text.replace('amount: 2', 'amount: 0'); },
    value => { value.evidence[2].content.objectiveSatisfied = true; },
    value => { value.evidence[3].id = value.evidence[2].id; },
    value => { value.evidence.reverse(); },
    value => { value.evidence.pop(); },
    value => { value.evidence.push(value.evidence[3]); },
    value => { value.rubric = { ...RUBRIC, mode: 'vuln' }; },
    value => { value.evidence[1].content.queryReceipt.result.coupon.active = 0; },
    value => { value.evidence[0].content.scope.generation++; },
    value => { value.evidence[2].content.text = 'x'.repeat(1001); },
  ]) {
    const changed = structuredClone(packet); mutate(changed);
    // Malformed canonical packets may be rejected by the shared schema before
    // this guard can return a verdict. Neither path may invoke the Judge.
    try { assert.equal((await guard(changed)).verdict, 'fail'); }
    catch (error) {
      assert.equal(error?.message, 'Coupon citation observation must be exact bounded text');
    }
    assert.equal(calls, 0);
  }
  for (const evidenceVersion of [0, 3, '2', true, null])
    assert.equal(buildCouponAgentCandidate({ ...input, evidenceVersion }), null);
});

test('v2 preserves production eligibility and rejects oversized text without truncating v1', () => {
  for (const evidenceVersion of [1, 2]) {
    const input = fixture();
    assert.equal(buildCouponAgentCandidate({ ...input, evidenceVersion,
      couponMode: { snapshot: { ...input.couponMode.snapshot, mode: 'fixed' } } }), null);
    for (const result of [null, { ...input.saved.result, applied_amount: 0 },
      { ...input.saved.result, code: input.saved.request.code }])
      assert.equal(buildCouponAgentCandidate({ ...input, evidenceVersion,
        saved: { ...input.saved, result } }), null);
    assert.equal(buildCouponAgentCandidate({ ...input, evidenceVersion, queryReceipt: null }), null);
  }
  for (const code of ['x'.repeat(990), 'é'.repeat(490)]) {
    const input = fixture({ code });
    assert.ok(buildCouponAgentCandidate(input), 'Original valid v1 proof remains intact');
    assert.equal(buildCouponAgentCandidate({ ...input, evidenceVersion: 2 }), null);
  }
});

module.exports = { fixture };
