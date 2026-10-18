'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { assertPrivateReceipt, FLAGS, SCOPE, systemRestartDependencies } =
  require('./secureshopAdminRestartChatRendered.integration.test');

function receipt(overrides = {}) {
  return { ...Object.fromEntries(FLAGS.map(flag => [flag, true])), scope: SCOPE,
    actorCalls: 2, roleTurns: 1, judgeCalls: 0, errors: [], ...overrides };
}

test('administrator restart receipt accepts only the exact bounded cohort', () => {
  assert.doesNotThrow(() => assertPrivateReceipt(receipt()));
  for (const invalid of [
    receipt({ scope: 'wrong cohort' }),
    { ...receipt(), unexpected: true },
    receipt({ passed: false }),
    receipt({ actorCalls: 1 }),
    receipt({ actorCalls: 6 }),
    receipt({ actorCalls: 2.5 }),
    receipt({ roleTurns: 2 }),
    receipt({ judgeCalls: 1 }),
    receipt({ errors: [{ name: 'Error' }] }),
  ]) assert.throws(() => assertPrivateReceipt(invalid));
});

test('administrator restart setup uses the existing product repository and review audit authority', () => {
  const restartClient = {}, grading = {}, reviewPool = {}, launches = {}, products = {}, scenes = {},
    reviewAudit = {}, authenticatePersona = () => {}, composition = { launches, scenes,
      repositories: { products }, personaAuth: { authenticatePersona } },
    reset = { audit: { review: reviewAudit, agents: {} } };
  assert.deepEqual(systemRestartDependencies({ restartClient, grading, reviewPool, composition, reset }),
    { systemRestartClient: restartClient, preparedGrading: grading, reviewPool, launches, products,
      scenes, audit: reviewAudit, authenticatePersona });
});
