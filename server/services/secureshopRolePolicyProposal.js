'use strict';

const { createHash } = require('node:crypto');
const render = require('./secureshopPromptPolicyContract');
const tasks = require('./secureshopPromptPolicyTaskMutation');
const { RECIPIENTS } = require('./secureshopPromptPolicyTaskSnapshot');
const HISTORICAL_TARGETS = Object.freeze([...new Set([...render.SUPPORTED_TARGETS, ...Object.keys(RECIPIENTS)])].sort());
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const MAX_VERSION = 9007199254740991n;
const PLACEHOLDER_ID = '00000000-0000-4000-8000-000000000001';
const TASK_TARGETS = Object.freeze(['summarizer', 'review-moderator', 'listing']);
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype
  && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fail = () => Object.assign(new Error('Policy proposal unavailable'), { code: 'ROLE_POLICY_PROPOSAL_INVALID' });
const version = v => typeof v === 'string' && /^[1-9]\d{0,15}$/.test(v) && BigInt(v) < MAX_VERSION;
const readableVersion = v => typeof v === 'string' && /^[1-9]\d{0,15}$/.test(v) && BigInt(v) <= MAX_VERSION;

function supportedTargets(taskTargets = []) {
  if (!Array.isArray(taskTargets) || new Set(taskTargets).size !== taskTargets.length
      || taskTargets.some(t => !TASK_TARGETS.includes(t))) throw fail();
  return [...render.SUPPORTED_TARGETS, ...taskTargets].sort();
}
function candidate(value, allowed) {
  if (!exact(value, ['name', 'markdown', 'targets']) || !Array.isArray(allowed)
      || !Array.isArray(value.targets) || value.targets.some(t => !allowed.includes(t))) throw fail();
  try {
    const normalized = tasks.normalizeTaskMutationRequest({ contractVersion: 2,
      operationId: PLACEHOLDER_ID, ...value });
    return { name: normalized.name, markdown: normalized.markdown, targets: [...normalized.targets] };
  } catch { throw fail(); }
}
function mode(value) {
  if (!exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
      || value.version !== 1 || value.featureId !== 'admin_assistant'
      || value.policyVersion !== 'owned-admin-read-and-confirmation-v1'
      || !['vuln', 'fixed'].includes(value.effectiveMode)
      || !exact(value.scope, ['kind', 'id']) || value.scope.kind !== 'launch_feature'
      || value.scope.id !== 'admin_assistant') throw fail();
  return { version: 1, featureId: value.featureId, policyVersion: value.policyVersion,
    effectiveMode: value.effectiveMode, scope: { kind: value.scope.kind, id: value.scope.id } };
}
function proposalId(source, origin) {
  if (!UUID.test(source?.sessionId || '') || !UUID.test(source?.requestId || '')
      || !exact(origin, ['step', 'callId']) || !Number.isInteger(origin.step)
      || origin.step < 1 || origin.step > 4 || typeof origin.callId !== 'string'
      || !origin.callId || Buffer.byteLength(origin.callId) > 128) throw fail();
  const h = digest(['admin-policy-proposal-v1', source.sessionId, source.requestId, origin.step, origin.callId]);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
function policySnapshotDigest({ scopeKey, headVersion, policy }) {
  if (!SHA.test(scopeKey || '') || !readableVersion(headVersion) || !readableVersion(policy?.version)) throw fail();
  const p = candidate({ name: policy.name, markdown: policy.markdown, targets: policy.targets }, HISTORICAL_TARGETS);
  return digest({ version: 1, scopeKey, headVersion,
    policy: { name: p.name, version: policy.version, markdown: p.markdown, targets: p.targets } });
}
function publicValue(p, allowed) {
  const fields = (value, targets) => {
    if (value === null) return null;
    if (!exact(value, ['markdown', 'targets'])) throw fail();
    const c = candidate({ name: p.name, ...value }, targets);
    return { markdown: c.markdown, targets: c.targets };
  };
  return { version: 1, proposalId: p.proposalId, choiceId: p.choiceId, action: p.action,
    name: render.normalizePolicyName(p.name), before: fields(p.before, HISTORICAL_TARGETS), after: fields(p.after, allowed),
    expectedVersion: p.expectedVersion, scopeKey: p.scopeKey, modeCapability: mode(p.modeCapability),
    sourceSnapshotSha256: p.sourceSnapshotSha256 };
}
function validate(p, source, allowed = supportedTargets(TASK_TARGETS)) {
  if (!exact(p, ['version', 'proposalId', 'choiceId', 'action', 'name', 'before', 'after',
    'expectedVersion', 'scopeKey', 'modeCapability', 'sourceSnapshotSha256', 'requestSha256', 'origin'])
      || p.version !== 1 || p.proposalId !== proposalId(source, p.origin)
      || !['create', 'edit', 'preview', 'delete'].includes(p.action)
      || !version(p.expectedVersion) || !SHA.test(p.scopeKey || '')
      || !SHA.test(p.requestSha256 || '')) throw fail();
  const value = publicValue(p, allowed);
  if (p.action === 'create') {
    if (p.choiceId !== null || p.sourceSnapshotSha256 !== null || p.before !== null || p.after === null) throw fail();
  } else if (!UUID.test(p.choiceId || '') || !SHA.test(p.sourceSnapshotSha256 || '')
      || p.before === null || (p.action === 'delete' ? p.after !== null : p.after === null)) throw fail();
  if (p.action === 'edit' && digest(value.before) === digest(value.after)) throw fail();
  if (digest(value) !== p.requestSha256) throw fail();
  return { ...value, requestSha256: p.requestSha256, origin: { step: p.origin.step, callId: p.origin.callId } };
}
function create({ source, origin, action, selected, before, after, name, expectedVersion,
  scopeKey, modeCapability }, allowed) {
  const p = { version: 1, proposalId: proposalId(source, origin), choiceId: selected?.choiceId ?? null,
    action, name, before, after, expectedVersion, scopeKey, modeCapability,
    sourceSnapshotSha256: selected?.snapshotSha256 ?? null, origin };
  p.requestSha256 = digest(publicValue(p, allowed));
  return validate(p, source, allowed);
}
function project(value, source, allowed) {
  const p = validate(value, source, allowed);
  const { origin, ...result } = p;
  return result;
}
function mutationRequest(p) {
  const raw = { operationId: p.proposalId, name: p.name, ...p.after };
  return p.after.targets.some(t => !render.SUPPORTED_TARGETS.includes(t))
    ? tasks.normalizeTaskMutationRequest({ contractVersion: 2, ...raw })
    : render.normalizeRenderRequest(raw);
}
module.exports = { createRolePolicyProposal: create, validateRolePolicyProposal: validate,
  projectRolePolicyProposal: project, policySnapshotDigest, normalizePolicyCandidate: candidate,
  policySupportedTargets: supportedTargets, policyMutationRequest: mutationRequest, HISTORICAL_TARGETS };
