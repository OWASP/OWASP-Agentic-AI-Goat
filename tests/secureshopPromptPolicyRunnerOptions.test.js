'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { promptPolicyRunnerOptions } = require('../server/services/secureshopPromptPolicyRunnerOptions');
const authority = { capture() {} };
test('composition captures scalar task identity and clones admission independently of caller mutations', async () => {
  let observed;
  const repository = { async admitRunSnapshot(value) { observed = value; return value; } };
  const config = { recipient: 'summarizer' };
  const options = promptPolicyRunnerOptions(repository, authority, config); config.recipient = 'review-moderator';
  assert.equal(options.promptPolicyRecipient, 'summarizer'); assert.ok(Object.isFrozen(options));
  const input = { scope: { generation: 1 } }; await options.promptPolicyAdmission(input); input.scope.generation = 2;
  assert.equal(observed.scope.generation, 1);
  assert.equal(Object.hasOwn(promptPolicyRunnerOptions(repository, authority), 'promptPolicyRecipient'), false);
  assert.equal(promptPolicyRunnerOptions(repository, authority, { recipient: null }).promptPolicyRecipient, null);
});
test('unsupported composition identity is rejected and disabled policies remain disabled', () => {
  for (const config of [{ recipient: 'unknown-analytics' }, { recipient: 'summarizer', role: 'admin' }, {}, []])
    assert.throws(() => promptPolicyRunnerOptions({ admitRunSnapshot() {} }, authority, config));
  assert.deepEqual(promptPolicyRunnerOptions(undefined, undefined, { recipient: 'summarizer' }), {});
});
