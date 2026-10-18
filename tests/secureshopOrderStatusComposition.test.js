'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createOrderStatusComposition } =
  require('../server/services/secureshopOrderStatusComposition');

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
  const customerChat = { captureOrderStatus: fn };
  const toolPolicyRepository = { admitTool: fn };
  const promptPolicyRepository = { admitRunSnapshot: fn };
  const orderStatusDependencies = { service: { provision: fn, lookupOrderStatus: fn,
    readOrderStatusReceipt: fn, readOrderStatusReference: fn } };
  return { identityPool, agentsPool, launches, conversations, journal, coordinator,
    provider, personaAuthority, personaBindings, receipts, progress, modeAuthority,
    customerChat, toolPolicyRepository, promptPolicyRepository,
    authenticatePersona: (_req, _res, next) => next(), orderStatusDependencies,
    judge: fn };
}

test('composition constructs only the distinct customer order status application, assessment and router', () => {
  const bundle = createOrderStatusComposition(dependencies());
  assert.equal(bundle.ready, true);
  assert.deepEqual(Object.keys(bundle), ['ready', 'application', 'assessment', 'router']);
  assert.equal(typeof bundle.application.run, 'function');
  assert.equal(typeof bundle.application.readSavedSource, 'function');
  assert.equal(typeof bundle.assessment.runAttempt, 'function');
  assert.equal(typeof bundle.assessment.readOutcome, 'function');
  assert.deepEqual(bundle.router.stack.filter(layer => layer.route).map(layer => layer.route.path), [
    '/customer/order-status/capabilities',
    '/customer/order-status/session', '/customer/order-status/run',
    '/customer/order-status/operations/:sessionId/:requestId',
    '/customer/order-status/assess',
    '/customer/order-status/assess/:sessionId/:requestId',
  ]);
  assert.equal(Object.isFrozen(bundle), true);
});

test('composition rejects absent target, private evidence and grading dependencies', () => {
  const base = dependencies();
  for (const input of [
    { ...base, customerChat: {} },
    { ...base, orderStatusDependencies: { ...base.orderStatusDependencies,
      service: { ...base.orderStatusDependencies.service, readOrderStatusReference: undefined } } },
    { ...base, personaBindings: undefined },
    { ...base, receipts: undefined },
    { ...base, provider: { chat: fn } },
    { ...base, toolPolicyRepository: undefined },
    { ...base, promptPolicyRepository: undefined },
  ]) assert.throws(() => createOrderStatusComposition(input), TypeError);
});
