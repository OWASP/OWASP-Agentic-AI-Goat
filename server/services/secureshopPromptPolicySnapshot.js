'use strict';

const { createHash } = require('node:crypto');
const { SUPPORTED_TARGETS, normalizePolicyName, normalizePolicyTargets } = require('./secureshopPromptPolicyContract');
const MAX_POLICIES = 32;
const MAX_PROMPT_BYTES = 128 * 1024;
const hash = value => createHash('sha256').update(value, 'utf8').digest('hex');

function invalid() { throw new TypeError('Invalid prompt policy snapshot'); }
function closed(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) invalid();
}

// Pure content construction: authority and genuine run admission are enforced by
// the repository. A caller-created snapshot is never execution or Judge proof.
function buildPolicySnapshot(input) {
  closed(input, ['policyVersion', 'role', 'policies']);
  const { policyVersion, role, policies } = input;
  if (typeof policyVersion !== 'string' || !/^[1-9][0-9]{0,18}$/.test(policyVersion)
    || BigInt(policyVersion) > 9223372036854775807n || !SUPPORTED_TARGETS.includes(role)
    || !Array.isArray(policies) || policies.length > MAX_POLICIES) invalid();
  const rows = [];
  const names = new Set();
  for (const policy of policies) {
    closed(policy, ['name', 'rendered', 'renderedSha256', 'targets']);
    const name = normalizePolicyName(policy.name);
    const targets = normalizePolicyTargets(policy.targets);
    if (names.has(name) || !targets.includes(role) || typeof policy.rendered !== 'string'
      || !policy.rendered.isWellFormed() || policy.rendered.includes('\0')
      || Buffer.byteLength(policy.rendered, 'utf8') > 65536
      || typeof policy.renderedSha256 !== 'string' || hash(policy.rendered) !== policy.renderedSha256) invalid();
    names.add(name);
    rows.push(Object.freeze({ name, rendered: policy.rendered, renderedSha256: policy.renderedSha256, targets }));
  }
  rows.sort((a, b) => Buffer.compare(Buffer.from(a.name, 'utf8'), Buffer.from(b.name, 'utf8')));
  // Verbatim rendered text is the intentional policy-poisoning teaching sink.
  // Delimiters describe content; they are not asserted as a security boundary.
  const text = rows.map(row => `[Policy ${JSON.stringify(row.name)}]\n${row.rendered}\n[/Policy]`).join('\n\n');
  if (Buffer.byteLength(text, 'utf8') > MAX_PROMPT_BYTES) invalid();
  const content = { version: 1, policyVersion, role, policies: Object.freeze(rows), text };
  return Object.freeze({ ...content, sha256: hash(JSON.stringify(content)) });
}

function validatePolicySnapshot(snapshot) {
  closed(snapshot, ['version', 'policyVersion', 'role', 'policies', 'text', 'sha256']);
  const rebuilt = buildPolicySnapshot({ policyVersion: snapshot.policyVersion, role: snapshot.role, policies: snapshot.policies });
  if (snapshot.version !== 1 || snapshot.text !== rebuilt.text || snapshot.sha256 !== rebuilt.sha256
    || snapshot.policies.some((row, i) => row.name !== rebuilt.policies[i].name)) invalid();
  return rebuilt;
}

module.exports = { MAX_POLICIES, MAX_PROMPT_BYTES, buildPolicySnapshot, validatePolicySnapshot };
