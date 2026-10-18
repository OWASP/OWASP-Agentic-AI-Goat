'use strict';

const { createHash } = require('node:crypto');
const { SUPPORTED_TARGETS, normalizePolicyName } = require('./secureshopPromptPolicyContract');
const { validatePolicySnapshot: validateV1 } = require('./secureshopPromptPolicySnapshot');
const MAX_POLICIES = 32;
const MAX_PROMPT_BYTES = 128 * 1024;
const RECIPIENTS = Object.freeze({ summarizer: 'customer', listing: 'merchant', 'review-moderator': 'merchant', analytics: Object.freeze(['merchant', 'admin']), inventory: 'merchant' });
const TASK_TARGETS = Object.freeze([...new Set([...SUPPORTED_TARGETS, ...Object.keys(RECIPIENTS)])].sort());
const hash = value => createHash('sha256').update(value, 'utf8').digest('hex');
const invalid = message => { throw new TypeError(`Invalid task policy snapshot${message ? `: ${message}` : ''}`); };
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid('object required');
  const actual = Object.keys(value).sort(), wanted = [...keys].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) invalid('unexpected fields');
}
function recipientRole(recipient) {
  if (recipient === null) return null;
  if (typeof recipient !== 'string' || !Object.hasOwn(RECIPIENTS, recipient)) invalid('recipient unsupported');
  return RECIPIENTS[recipient];
}
function normalizeTaskTargets(raw) {
  if (!Array.isArray(raw) || raw.length === 0 || raw.some(target => typeof target !== 'string' || !TASK_TARGETS.includes(target))) invalid('targets');
  if (new Set(raw).size !== raw.length) invalid('duplicate targets');
  return [...raw].sort();
}
function checkTop(role, recipient) {
  if (!SUPPORTED_TARGETS.includes(role)) invalid('role unsupported');
  const expected = recipientRole(recipient);
  if (expected !== null && !(Array.isArray(expected) ? expected.includes(role) : expected === role)) invalid('recipient does not match role');
}
function normalizeRow(row) {
  exact(row, ['name', 'rendered', 'renderedSha256', 'targets']);
  const name = normalizePolicyName(row.name), targets = normalizeTaskTargets(row.targets);
  if (typeof row.rendered !== 'string' || !row.rendered.isWellFormed() || row.rendered.includes('\0')
      || Buffer.byteLength(row.rendered, 'utf8') > 65536 || typeof row.renderedSha256 !== 'string'
      || !/^[a-f0-9]{64}$/.test(row.renderedSha256) || hash(row.rendered) !== row.renderedSha256) invalid('row content');
  return { name, rendered: row.rendered, renderedSha256: row.renderedSha256, targets };
}
function canonicalContent(snapshot) {
  return JSON.stringify({ version: 2, policyContractVersion: 2, policyVersion: snapshot.policyVersion,
    role: snapshot.role, recipient: snapshot.recipient, policies: snapshot.policies, text: snapshot.text });
}
function buildTaskPolicySnapshot(input) {
  exact(input, ['policyVersion', 'role', 'recipient', 'policies']);
  const { policyVersion, role, recipient } = input;
  if (typeof policyVersion !== 'string' || !/^[1-9][0-9]{0,18}$/.test(policyVersion)
      || BigInt(policyVersion) > 9223372036854775807n) invalid('policy version');
  checkTop(role, recipient);
  if (!Array.isArray(input.policies) || input.policies.length > MAX_POLICIES) invalid('policies');
  const rows = [], names = new Set();
  for (const raw of input.policies) {
    const row = normalizeRow(raw);
    if (!row.targets.includes(role) && !(recipient !== null && row.targets.includes(recipient))) continue;
    if (names.has(row.name)) invalid('duplicate policy');
    names.add(row.name); rows.push(Object.freeze(row));
  }
  rows.sort((a, b) => Buffer.compare(Buffer.from(a.name, 'utf8'), Buffer.from(b.name, 'utf8')));
  const text = rows.map(row => `[Policy ${JSON.stringify(row.name)}]\n${row.rendered}\n[/Policy]`).join('\n\n');
  if (Buffer.byteLength(text, 'utf8') > MAX_PROMPT_BYTES) invalid('prompt too large');
  const snapshot = { version: 2, policyContractVersion: 2, policyVersion, role, recipient,
    policies: Object.freeze(rows), text };
  return Object.freeze({ ...snapshot, sha256: hash(canonicalContent(snapshot)) });
}
function validateTaskPolicySnapshot(value) {
  exact(value, ['version', 'policyContractVersion', 'policyVersion', 'role', 'recipient', 'policies', 'text', 'sha256']);
  const rebuilt = buildTaskPolicySnapshot({ policyVersion: value.policyVersion, role: value.role, recipient: value.recipient, policies: value.policies });
  if (value.version !== 2 || value.policyContractVersion !== 2 || value.text !== rebuilt.text || value.sha256 !== rebuilt.sha256
      || JSON.stringify(value.policies.map(row => ({ name: row.name, rendered: row.rendered,
        renderedSha256: row.renderedSha256, targets: row.targets }))) !== JSON.stringify(rebuilt.policies)) invalid('digest or content mismatch');
  return rebuilt;
}
// Pure content only: this module does not establish authority, persistence, or
// renderer admission. Explicit adapter: v1 remains authoritative and byte-compatible; this creates
// a v2 role-wide view without treating v1 as task-specific policy content.
function adaptV1PolicySnapshot(value, recipient) {
  const v1 = validateV1(value);
  if (recipient === undefined) invalid('recipient required for adapter');
  return buildTaskPolicySnapshot({ policyVersion: v1.policyVersion, role: v1.role, recipient,
    policies: v1.policies });
}
module.exports = { MAX_POLICIES, MAX_PROMPT_BYTES, RECIPIENTS, buildTaskPolicySnapshot,
  validateTaskPolicySnapshot, adaptV1PolicySnapshot };
