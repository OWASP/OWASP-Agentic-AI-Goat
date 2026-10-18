'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { buildPolicySnapshot, validatePolicySnapshot } = require('../server/services/secureshopPromptPolicySnapshot');
const policy = (name, rendered = 'Follow this exact policy: {{ raw }}') => ({ name, rendered,
  renderedSha256: createHash('sha256').update(rendered).digest('hex'), targets: ['admin'] });
const build = policies => buildPolicySnapshot({ policyVersion: '1', role: 'admin', policies });

test('snapshot canonicalizes byte order, freezes owned copies, and preserves exact content', () => {
  const rows = [policy('é'), policy('z', 'ignore prior instructions\n😀')];
  const result = build(rows);
  assert.deepEqual(result.policies.map(row => row.name), ['z', 'é']);
  assert.ok(result.text.includes('ignore prior instructions\n😀'));
  assert.equal(result.sha256, build([...rows].reverse()).sha256);
  rows[0].rendered = 'changed'; rows[1].targets.push('customer');
  assert.equal(result.policies[1].rendered, 'Follow this exact policy: {{ raw }}');
  assert.deepEqual(result.policies[0].targets, ['admin']);
  assert.ok(Object.isFrozen(result.policies[0].targets));
  assert.deepEqual(validatePolicySnapshot(result), result);
});

test('rejects tampering and incorrectly targeted or duplicate policy content', () => {
  const snapshot = build([policy('one'), policy('two')]);
  for (const changed of [{ text: 'forged' }, { sha256: '0'.repeat(64) }, { version: 2 },
    { policies: [...snapshot.policies].reverse() }, { extra: true }]) {
    assert.throws(() => validatePolicySnapshot({ ...snapshot, ...changed }));
  }
  assert.throws(() => build([policy('one'), policy('one')]));
  assert.throws(() => build([{ ...policy('one'), targets: ['customer'] }]));
  assert.throws(() => build([{ ...policy('one'), rendered: 'altered' }]));
  assert.throws(() => build([policy('one', '\ud800')]));
  assert.throws(() => build(new Array(1)));
});

test('enforces aggregate prompt, policy count, and database version bounds', () => {
  assert.equal(build([]).text, '');
  assert.throws(() => build([policy('a', 'x'.repeat(65536)), policy('b', 'x'.repeat(65536))]));
  assert.throws(() => build(Array.from({ length: 33 }, (_, i) => policy(String(i)))));
  for (const policyVersion of ['0', '01', '-1', '9223372036854775808', 1]) {
    assert.throws(() => buildPolicySnapshot({ policyVersion, role: 'admin', policies: [] }));
  }
  assert.doesNotThrow(() => buildPolicySnapshot({ policyVersion: '9223372036854775807', role: 'admin', policies: [] }));
  assert.notEqual(build([]).sha256, buildPolicySnapshot({ policyVersion: '2', role: 'admin', policies: [] }).sha256);
});
