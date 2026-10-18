'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createCouponProbeComposition } =
  require('../server/services/secureshopCouponProbeComposition');

const fn = async () => ({ rows: [] });
function dependencies() {
  const identityPool = { query: fn, connect: async () => ({ query: fn, release() {} }) };
  const agentsPool = { query: fn };
  const launches = { resolveCapability: fn, assertCurrent: fn };
  const conversations = Object.fromEntries([
    'getTraceEvents', 'getBoundSession', 'acquireBoundSession', 'activateBoundSession',
    'appendTraces', 'getMessages', 'getTrace', 'runExclusive',
  ].map(name => [name, fn]));
  const journal = { claim: fn, complete: fn, markUncertain: fn };
  const coordinator = { run: fn };
  const provider = { chat: fn, finalResponse: fn };
  const personaAuthority = { capture: fn };
  const personaBindings = { capture: fn, initial: fn, inherit: fn, commit: fn,
    check: fn, projectRecoverable: fn };
  const receipts = { beginEvaluation: fn, recordVerdict: fn };
  const progress = { getGeneration: fn };
  const modeAuthority = { assertToken: fn };
  const customerChat = { captureCouponProbe: fn };
  const toolPolicyRepository = { admitTool: fn };
  const promptPolicyRepository = { admitRunSnapshot: fn };
  const probeDependencies = { service: { provision: fn, lookupCouponProbe: fn,
    readCouponProbeReceipt: fn, readCouponProbeReference: fn }, readCoupons: fn };
  return { identityPool, agentsPool, launches, conversations, journal, coordinator,
    provider, personaAuthority, personaBindings, receipts, progress, modeAuthority,
    customerChat, toolPolicyRepository, promptPolicyRepository,
    authenticatePersona: (_req, _res, next) => next(), probeDependencies,
    judge: fn };
}

test('composition constructs only the distinct customer probe application, assessment and router', () => {
  const bundle = createCouponProbeComposition(dependencies());
  assert.equal(bundle.ready, true);
  assert.deepEqual(Object.keys(bundle), ['ready', 'application', 'assessment', 'router']);
  assert.equal(typeof bundle.application.run, 'function');
  assert.equal(typeof bundle.application.readSavedSource, 'function');
  assert.equal(typeof bundle.assessment.runAttempt, 'function');
  assert.equal(typeof bundle.assessment.readOutcome, 'function');
  assert.deepEqual(bundle.router.stack.filter(layer => layer.route).map(layer => layer.route.path), [
    '/customer/coupon-probe/capabilities',
    '/customer/coupon-probe/session', '/customer/coupon-probe/run',
    '/customer/coupon-probe/operations/:sessionId/:requestId',
    '/customer/coupon-probe/assess',
    '/customer/coupon-probe/assess/:sessionId/:requestId',
  ]);
  assert.equal(Object.isFrozen(bundle), true);
});

test('composition rejects absent target, private evidence and grading dependencies', () => {
  const base = dependencies();
  for (const input of [
    { ...base, customerChat: {} },
    { ...base, probeDependencies: { ...base.probeDependencies,
      service: { ...base.probeDependencies.service, readCouponProbeReference: undefined } } },
    { ...base, probeDependencies: { ...base.probeDependencies, readCoupons: undefined } },
    { ...base, personaBindings: undefined },
    { ...base, receipts: undefined },
    { ...base, provider: { chat: fn } },
    { ...base, toolPolicyRepository: undefined },
    { ...base, promptPolicyRepository: undefined },
  ]) assert.throws(() => createCouponProbeComposition(input), TypeError);
});
