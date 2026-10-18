'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Agent = require('../server/services/secureshopCouponAgentContract');
const Coupon = require('../server/services/secureshopCouponContract');
const Remote = require('../sidecars/analytics-sql-target/contract');

const S = '00000000-0000-4000-8000-000000000001';
const R = '00000000-0000-4000-8000-000000000002';
const T = '00000000-0000-4000-8000-000000000003';
const origin = { turnSessionId: S, turnRequestId: R, toolKey: Agent.TOOL,
  invocationStep: 1, callId: 'original-provider-call' };
const code = "' OR 1=1--";

test('a no-effect coupon proposal preserves exact selected code and origin identity', () => {
  const message = `Apply coupon ${code} to this cart`;
  const proposal = Agent.prepare({ code, message, sourceOrigin: origin });
  assert.deepEqual(proposal, { version: 1, kind: Agent.TOOL,
    status: 'confirmation_required', proposalId: Agent.operationId(origin),
    code, codeSha256: Coupon.hash(code) });
  assert.deepEqual(Agent.confirmation({ sessionId: S, requestId: R,
    proposalId: proposal.proposalId }, { sourceOrigin: origin }),
  { sessionId: S, requestId: R, proposalId: proposal.proposalId });
  assert.throws(() => Agent.proposal({ ...proposal, code: `${code} ` }, { message, sourceOrigin: origin }));
  assert.throws(() => Agent.proposal(proposal, { message: 'Apply WELCOME10', sourceOrigin: origin }));
  assert.throws(() => Agent.prepare({ message, sourceOrigin: origin }),
    error => error.code === 'COUPON_AGENT_PROPOSAL_INVALID');
  assert.throws(() => Agent.confirmation({ sessionId: S, requestId: R,
    proposalId: proposal.proposalId, code }, { sourceOrigin: origin }));
  assert.throws(() => Agent.confirmation({ sessionId: S, requestId: T,
    proposalId: proposal.proposalId }, { sourceOrigin: origin }));
  assert.notEqual(Agent.operationId({ ...origin, callId: 'other-provider-call' }), proposal.proposalId);
});

test('new explicit human JSON code admits only the decoded literal selected by the model', () => {
  const json = `Use the exact JSON field ${JSON.stringify({ code })} for my cart.`;
  assert.equal(Agent.currentExplicitCode(json), code);
  assert.equal(Agent.currentExplicitCode('Apply coupon HALF'), undefined);
  const prepared = Agent.prepare({ code, message: json, sourceOrigin: origin });
  assert.equal(prepared.code, code);
  // Historical v1 proposal reads retain their original containment contract.
  assert.deepEqual(Agent.proposal(prepared, { message: json, sourceOrigin: origin }), prepared);
  const historicalMessage = `Use ${JSON.stringify({ code })} and "code":"OTHER"`;
  assert.throws(() => Agent.currentExplicitCode(historicalMessage),
    error => error.code === 'COUPON_AGENT_PROPOSAL_INVALID');
  assert.deepEqual(Agent.proposal(prepared, { message: historicalMessage, sourceOrigin: origin }),
    prepared, 'existing v1 saved proposal validation is unchanged');
  for (const selected of [`${code}\"`, code.slice(1), `${code} `]) {
    assert.throws(() => Agent.prepare({ code: selected, message: json, sourceOrigin: origin }),
      error => error.code === 'COUPON_AGENT_PROPOSAL_INVALID');
  }
  for (const message of [`Use ${JSON.stringify({ code: '' })}`,
    `Use ${JSON.stringify({ code: 'x'.repeat(1025) })}`,
    'Use {"code":']) {
    assert.throws(() => Agent.currentExplicitCode(message),
      error => error.code === 'COUPON_AGENT_PROPOSAL_INVALID');
  }
  const spaced = `Use { "code" : ${JSON.stringify(code)} } in this cart.`;
  assert.equal(Agent.prepare({ code, message: spaced, sourceOrigin: origin }).code, code);
  assert.equal(Agent.prepare({ code: 'HALF', message: 'Apply coupon HALF', sourceOrigin: origin }).code,
    'HALF', 'ordinary natural coupon requests remain supported');
});

test('new explicit human JSON code rejects malformed, duplicate and ambiguous fields', () => {
  for (const message of [
    `Use {"code":${JSON.stringify(code)},"code":${JSON.stringify(code)}}`,
    `Use {"code":${JSON.stringify(code)},"other":1}`,
    `Use {"code":${JSON.stringify(code)}} and {"code":${JSON.stringify(code)}}`,
    `Use {"code":${JSON.stringify(code)}} and {'code':'OTHER'}`,
    `Use {"code":${JSON.stringify(code)}} and "code":"OTHER"`,
    `Use {"code":${JSON.stringify(code)}} and {"co\\u0064e":"OTHER", }`,
    'Use {"code":',
    `Use {'code':${JSON.stringify(code)}}`,
    'Use the exact JSON field {"code":}',
    `Use {"code":12} and ${code}`,
  ]) {
    assert.throws(() => Agent.prepare({ code, message, sourceOrigin: origin }),
      error => error.code === 'COUPON_AGENT_PROPOSAL_INVALID', message);
  }
});

test('v1 isolated query receipt validates only its actual fields, not imagined actor or SQL fields', () => {
  const scope = { launchId: '00000000-0000-4000-8000-000000000004',
    scenarioId: '00000000-0000-4000-8000-000000000005', generation: 1,
    platformOwnerId: 7, platformSessionId: 8 };
  const request = Coupon.lookup({ scope, operationId: Agent.operationId(origin),
    persona: { id: 9, role: 'customer' }, personaSession: { sessionId: T, authorityVersion: '1' },
    mode: 'vuln', code, coupons: [{ id: 1, code: 'HALF', discount_percent: 50, active: 1 }] });
  const remoteResult = { coupon: request.coupons[0] };
  const receipt = { version: 1, kind: 'coupon', operationId: request.operationId,
    requestSha256: Remote.hash({ kind: 'coupon-v1', request }), targetId: T,
    scope: request.scope, sourceManifestSha256: 'a'.repeat(64),
    resultSha256: Remote.hash(remoteResult), result: remoteResult };
  const completed = { ok: true, code: 'HALF', discount_percent: 50,
    subtotal: 1.04, applied_amount: 0.52 };
  assert.deepEqual(Agent.queryReceiptV1(receipt, request, completed), {
    operationId: request.operationId, targetId: T,
    requestSha256: receipt.requestSha256, resultSha256: receipt.resultSha256,
    sourceManifestSha256: receipt.sourceManifestSha256 });
  assert.throws(() => Agent.queryReceiptV1({ ...receipt, sqlSha256: 'b'.repeat(64) }, request, completed));
  assert.throws(() => Agent.queryReceiptV1({ ...receipt, requestSha256: 'b'.repeat(64) }, request, completed));
  assert.throws(() => Agent.queryReceiptV1({ ...receipt, result: { coupon: null } }, request, completed));
  for (const wrongCoupon of [false, 0, '']) {
    const wrongResult = { coupon: wrongCoupon };
    assert.throws(() => Agent.queryReceiptV1({ ...receipt, result: wrongResult,
      resultSha256: Remote.hash(wrongResult) }, request,
    { ok: false, error: 'coupon not found' }));
  }
  assert.throws(() => Agent.queryReceiptV1(receipt, request, { ...completed, code: 'FULL' }));
  assert.throws(() => Agent.queryReceiptV1(receipt, request, { ...completed, applied_amount: 0.51 }));
});
