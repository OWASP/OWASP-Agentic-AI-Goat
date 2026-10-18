'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createCouponAgentAssessment } =
  require('../server/services/secureshopCouponAgentAssessment');
const { OBJECTIVE, RUBRIC, RUBRIC_V2 } =
  require('../server/services/secureshopCouponAgentEvidence');

function fixture(mode = 'fixed') {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(),
    generation: 1, platformOwnerId: 8, platformSessionId: 9 };
  const persona = { id: 1000000001, role: 'customer' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '2' };
  const target = { targetId: randomUUID(), scene: { sceneId: randomUUID(),
    sceneGeneration: 1, grantId: randomUUID() } };
  const state = { reads: 0, claims: 0, judges: 0, checked: 0 };
  const check = async () => { state.checked++; };
  const token = featureId => ({ snapshot: { version: 1, featureId,
    policyVersion: 'v1', mode: featureId === 'coupons' ? mode : 'vuln',
    generation: 1, modeStamp: 'a'.repeat(64), scope },
  assertCurrent: check });
  const dependencies = {
    identityPool: { query: async sql => ({ rows: sql.includes('SELECT realm')
      ? [{ realm: 'platform', shop_tenant_id: null }]
      : [{ objective_id: OBJECTIVE }] }) },
    launches: { assertCurrent: check },
    conversationRepository: { getMessages: async () => [],
      getTraceEvents: async () => [], getBoundSession: async () => null,
      acquireBoundSession: async () => null,
      activateBoundSession: async () => false },
    coordinator: { run: async () => { throw Error('Unexpected grading run'); } },
    journal: { readBoundRequest: async () => null,
      readCouponAgentAssessment: async () => null,
      claim: async () => { state.claims++; throw Error('Unexpected claim'); },
      complete: async () => {}, markUncertain: async () => {} },
    personaAuthority: { capture: () => ({ binding: {},
      assertRemoteAdmission: check }) },
    personaBindings: { capture: async () => ({}) },
    receipts: { beginEvaluation: async () => {}, recordVerdict: async () => {} },
    progress: { getGeneration: async () => 1 },
    judge: async () => { state.judges++; return {}; },
    qualifyModel: () => true,
    captureCurrent: async () => ({ scope, persona, personaSession, target,
      mode: token('customer_chat'), couponMode: token('coupons'), check }),
    bindingRepository: { read: async () => { state.reads++; return null; } },
    readConfirmedCoupon: async () => { throw Error('Unexpected coupon receipt'); },
    readCouponReceipt: async () => { throw Error('Unexpected SQL receipt'); },
  };
  return { dependencies, input: { scope, persona, personaSession,
    sessionId: randomUUID(), requestId: randomUUID(),
    proposalId: randomUUID() }, state };
}

test('fixed coupon mode exits before protected source, SQL receipt, admission and Judge', async () => {
  const { dependencies, input, state } = fixture('fixed');
  const service = createCouponAgentAssessment(dependencies);
  assert.deepEqual(await service.runAttempt(input),
    { completed: false, status: 'ineligible', modelEvaluated: false });
  assert.deepEqual(await service.readOutcome(input),
    { completed: false, status: 'ineligible', modelEvaluated: false });
  assert.equal(state.reads, 0);
  assert.equal(state.claims, 0);
  assert.equal(state.judges, 0);
});

test('retained packet guard rejects invented packet before any protected source read', async () => {
  const { dependencies, input, state } = fixture('vuln');
  const service = createCouponAgentAssessment(dependencies);
  await assert.rejects(service.assertRetainedPacket({ packet: {
    rubric: { objectiveId: OBJECTIVE, mode: 'vuln' }, facts: {}, evidence: [] },
    scope: input.scope, persona: input.persona,
    personaSession: input.personaSession }),
  { code: 'COUPON_AGENT_ASSESSMENT_UNAVAILABLE' });
  assert.equal(state.reads, 0);
  assert.equal(state.claims, 0);
  assert.equal(state.judges, 0);
});

test('retained coupon packets reject unknown versions and mismatched proof shapes before source access', async () => {
  const { dependencies, input, state } = fixture('vuln');
  const service = createCouponAgentAssessment(dependencies);
  for (const [version, count] of [
    ['secureshop-agent-coupon-sqli-unknown', 2],
    [RUBRIC.version, 4],
    [RUBRIC_V2.version, 2],
  ]) {
    const packet = { rubric: { objectiveId: OBJECTIVE, mode: 'vuln', version },
      facts: {}, evidence: Array.from({ length: count }, () => ({})) };
    await assert.rejects(service.assertRetainedPacket({ packet,
      scope: input.scope, persona: input.persona,
      personaSession: input.personaSession }),
    { code: 'COUPON_AGENT_ASSESSMENT_UNAVAILABLE' });
  }
  assert.equal(state.reads, 0);
  assert.equal(state.claims, 0);
  assert.equal(state.judges, 0);
});

test('missing original protected turn fails before any assessment claim or SQL read', async () => {
  const { dependencies, input, state } = fixture('vuln');
  const service = createCouponAgentAssessment(dependencies);
  await assert.rejects(service.runAttempt(input),
    { code: 'COUPON_AGENT_SOURCE_INVALID' });
  assert.equal(state.reads, 1);
  assert.equal(state.claims, 0);
  assert.equal(state.judges, 0);
});

test('assessment refuses to construct without the SELECT-only SQL receipt reader', () => {
  const { dependencies } = fixture('vuln');
  delete dependencies.readCouponReceipt;
  assert.throws(() => createCouponAgentAssessment(dependencies),
    { code: 'COUPON_AGENT_ASSESSMENT_UNAVAILABLE' });
});
