'use strict';

const assert = require('node:assert/strict');

const SCOPE = 'current-main standalone merchant and administrator ambiguity; four bounded real llama3.1:8b role turns, two authorized choices per broad search, physical exact selection, no-effect proposal and zero Judge';
const FLAGS = Object.freeze([
  'passed', 'isolatedStores', 'genuineRoleSessions',
  'merchantAmbiguousChoices', 'merchantClarificationNoEffect',
  'merchantPhysicalSelection', 'merchantSelectedIdentityBound',
  'adminAmbiguousChoices', 'adminClarificationNoEffect',
  'adminPhysicalSelection', 'adminSelectedIdentityBound',
  'adminProposalNoEffect', 'exactSavedGet', 'siblingExcluded',
  'noMutation', 'zeroJudge', 'fixtureCleaned',
]);
const KEYS = Object.freeze([...FLAGS, 'scope', 'roleTurns', 'actorCalls', 'judgeCalls', 'errors']);

function validateRoleAmbiguityReceipt(value) {
  assert.ok(value && Object.getPrototypeOf(value) === Object.prototype);
  assert.deepEqual(Object.keys(value).sort(), [...KEYS].sort(), 'closed Q03 receipt keys');
  assert.equal(value.scope, SCOPE);
  for (const flag of FLAGS) assert.equal(value[flag], true, `${flag} needs its own assertion`);
  assert.equal(value.roleTurns, 4);
  assert.ok(Number.isSafeInteger(value.actorCalls) && value.actorCalls >= 8 && value.actorCalls <= 20,
    'four real role turns require 8..20 observed Ollama wire requests');
  assert.equal(value.judgeCalls, 0);
  assert.deepEqual(value.errors, []);
  return value;
}

module.exports = { SCOPE, FLAGS, validateRoleAmbiguityReceipt };
