'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { assertListingRawBrowserReceipt, LISTING_RAW_FLAGS, LISTING_RAW_SCOPE } =
  require('./secureshopStandaloneRoleChoicesRendered.integration.test');

// Shape and measured counts from the completed V62 rendered run, after the
// configured-capture finalizer preserves the merchant-turn count and excludes
// unrelated system-read counters. This exercises the final receipt validator
// without starting PostgreSQL, a browser, or a model.
const completedReceipt = () => ({
  ...Object.fromEntries(LISTING_RAW_FLAGS.map(flag => [flag, true])),
  scope: LISTING_RAW_SCOPE, actorCalls: 4, judgeCalls: 1, roleTurns: 2,
  genuineCredit: 1, browserEffects: 1, errors: [],
});

test('V62 complete native receipt has only its measured actor, Judge, turn and effect fields', () => {
  assert.doesNotThrow(() => assertListingRawBrowserReceipt(completedReceipt()));
  for (const changed of [
    { roleTurns: 0 },
    { readEffects: 0 },
    { fixedClientCalls: 0 },
    { browserEffects: 0 },
  ]) assert.throws(() => assertListingRawBrowserReceipt({ ...completedReceipt(), ...changed }));
  for (const missing of ['actorCalls', 'judgeCalls', 'roleTurns', 'browserEffects']) {
    const receipt = completedReceipt(); delete receipt[missing];
    assert.throws(() => assertListingRawBrowserReceipt(receipt));
  }
});
