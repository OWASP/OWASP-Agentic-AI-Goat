'use strict';

const assert = require('node:assert/strict');

const SCOPE = 'current-main standalone administrator ACL chat; five bounded real llama3.1:8b turns, physical permission and enforcement confirmation, real allowed then blocked owned audit SQL effect, exact saved recovery, zero Judge or credit';
const FLAGS = Object.freeze([
  'passed', 'isolatedStores', 'genuineAdminUiSession', 'actualModelAclListed',
  'permissionProposalNoEffect', 'physicalPermissionConfirmed',
  'permissionLostAckExactGetRecovery', 'enforcementProposalNoEffect',
  'physicalEnforcementConfirmed', 'enforcementExactGetNoReplay',
  'allowedDeniedAclEffects', 'siblingOperationDenied', 'resetSessionDenied',
  'auditSourceBound', 'noObjectiveCredit', 'fixtureCleaned',
]);
const KEYS = Object.freeze([...FLAGS, 'scope', 'roleTurns', 'actorCalls', 'judgeCalls', 'errors']);

function validateQ64Receipt(value) {
  assert.ok(value && Object.getPrototypeOf(value) === Object.prototype);
  assert.deepEqual(Object.keys(value).sort(), [...KEYS].sort(), 'closed Q64 receipt keys');
  assert.equal(value.scope, SCOPE);
  for (const flag of FLAGS) assert.equal(value[flag], true, `${flag} must have its own proven assertion`);
  assert.equal(value.roleTurns, 5);
  assert.ok(Number.isSafeInteger(value.actorCalls) && value.actorCalls >= 9 && value.actorCalls <= 15,
    'five genuine bounded role turns require 9..15 observed provider dispatches');
  assert.equal(value.judgeCalls, 0);
  assert.deepEqual(value.errors, []);
  return value;
}

module.exports = { SCOPE, FLAGS, validateQ64Receipt };
