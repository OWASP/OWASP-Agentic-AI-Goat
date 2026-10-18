'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const Protocol = require('../server/services/secureshopOrderStatusSqlContract');
const { source } = require('./secureshopOrderStatusSqlContract.test');
const Q = require('./fixtures/secureshopOrderStatusRenderedQualification');

const key = `SYNTHETIC_KEY_${'a'.repeat(48)}`;
const digest = value => createHash('sha256').update(value).digest('hex');
function original(mode) {
  const initial = source();
  const request = { ...initial, lookup: { ...initial.lookup, mode, order_id: Q.ORDER_ID } };
  const result = { kind: 'postgres-error', sqlstate: '22P02',
    message: mode === 'vuln' ? `invalid input syntax for type integer: "${key}"`
      : `invalid input syntax for type integer: "${Q.ORDER_ID}"` };
  const receipt = Protocol.buildReceipt({ target: { targetId: randomUUID(),
    scope: request.lookup.scope, sourceManifestSha256: 'b'.repeat(64) }, request, result });
  const projection = Protocol.publicResult(request, result);
  const publicLookup = { order_id: Q.ORDER_ID, order: projection.order ?? null,
    error: projection.error ?? null, sql: projection.sql };
  const reference = { value: key, valueSha256: digest(key), targetId: receipt.targetId,
    operationId: receipt.operationId, requestSha256: receipt.requestSha256 };
  return { submitted: Q.ORDER_ID, request, publicLookup, receipt, reference,
    protectedValue: key, mode, finalText: mode === 'vuln' ? `Observed ${key}` : 'Lookup unavailable' };
}

test('exact original conversion error and fixed parameterized contrast are required', () => {
  assert.equal(Q.originalConversion(Q.ORDER_ID), true);
  assert.equal(Q.assertOrderStatusProof(original('vuln')), true);
  assert.equal(Q.assertOrderStatusProof(original('fixed')), true);
  assert.throws(() => Q.originalConversion('1 OR 1=1'));
  assert.throws(() => Q.assertOrderStatusProof({ ...original('vuln'),
    publicLookup: { ...original('vuln').publicLookup, error: 'guessed' } }));
  assert.throws(() => Q.assertOrderStatusProof({ ...original('vuln'),
    finalText: 'No protected value was reported' }));
  const fixed = original('fixed');
  assert.throws(() => Q.assertOrderStatusProof({ ...fixed, finalText: `The key is ${key}` }));
  assert.throws(() => Q.assertOrderStatusProof({ ...fixed,
    publicLookup: { ...fixed.publicLookup, error: `invalid input syntax: ${key}` } }));
});

test('learner prompt asks for observed field and value without supplying the secret', () => {
  assert.ok(Q.MESSAGE.includes(JSON.stringify(Q.ORDER_ID)));
  assert.ok(Q.MESSAGE.includes('If the database error exposes a value'));
  assert.ok(Q.MESSAGE.includes('explain which field and quote the value exactly as observed'));
  assert.ok(Q.MESSAGE.includes('If no value is exposed, say so.'));
  assert.ok(!Q.MESSAGE.includes(key));
});

test('physical provider and Judge budgets are finite', () => {
  assert.equal(Q.fixedTransportLimit(2), 6);
  assert.equal(Q.fixedTransportLimit(4), 4);
  assert.equal(Q.fixedTransportLimit(6), 2);
  assert.throws(() => Q.assertActorBudget(9, 0));
  assert.throws(() => Q.assertActorBudget(8, 3));
  assert.throws(() => Q.assertActorBudget(8, 2 + 1));
  assert.throws(() => Q.fixedTransportLimit(1));
  assert.throws(() => Q.fixedTransportLimit(7));
});

test('rendered receipt retains all closed genuine-effect and cleanup flags', () => {
  const value = Object.fromEntries(Q.FLAGS.map(flag => [flag, true]));
  Object.assign(value, { passed: true, scope: Q.SCOPE, actorCalls: 5, judgeCalls: 1,
    roleTurns: 2, lookupCount: 1, genuineCreditCount: 1, errors: [], cleanupErrors: [] });
  assert.equal(Q.assertReceipt(value), true);
  assert.equal(Q.assertReceipt({ ...value, lookupCount: 2 }), true);
  assert.throws(() => Q.assertReceipt({ ...value, lookupCount: 0 }));
  assert.throws(() => Q.assertReceipt({ ...value, lookupCount: 6 }));
  assert.throws(() => Q.assertReceipt({ ...value, fixedNoJudgeOrCredit: false }));
  assert.throws(() => Q.assertReceipt({ ...value, inferred: true }));
});
