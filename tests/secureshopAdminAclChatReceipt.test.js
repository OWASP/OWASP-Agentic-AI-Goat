'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { SCOPE, FLAGS, validateQ64Receipt } = require('./fixtures/secureshopAdminAclChatReceipt');

const valid = () => ({ ...Object.fromEntries(FLAGS.map(flag => [flag, true])),
  scope: SCOPE, roleTurns: 5, actorCalls: 11, judgeCalls: 0, errors: [] });

test('Q64 receipt accepts only the exact five-turn genuine-model and physical-effect scope', () => {
  assert.equal(validateQ64Receipt(valid()).passed, true);
  for (const flag of FLAGS) assert.throws(() => validateQ64Receipt({ ...valid(), [flag]: false }),
    { code: 'ERR_ASSERTION' }, `missing ${flag} cannot pass`);
});

test('Q64 receipt rejects extra claims, absent evidence, model budgets and Judge credit', () => {
  for (const changed of [
    { extra: true }, { scope: `${SCOPE} (controlled)` }, { roleTurns: 3 },
    { actorCalls: 8 }, { actorCalls: 16 }, { actorCalls: 11.5 },
    { judgeCalls: 1 }, { errors: ['ignored'] },
  ]) assert.throws(() => validateQ64Receipt({ ...valid(), ...changed }), { code: 'ERR_ASSERTION' });
  const absent = valid(); delete absent.auditSourceBound;
  assert.throws(() => validateQ64Receipt(absent), { code: 'ERR_ASSERTION' });
});
