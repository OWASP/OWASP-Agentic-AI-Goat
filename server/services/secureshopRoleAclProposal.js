'use strict';

const { createHash } = require('node:crypto');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const MAX_VERSION = 9223372036854775807n;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fail = () => Object.assign(new Error('ACL proposal unavailable'), { code: 'ROLE_ACL_PROPOSAL_INVALID' });
const version = value => typeof value === 'string' && /^[1-9]\d{0,18}$/.test(value)
  && BigInt(value) <= MAX_VERSION;
const scope = value => typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 1024;

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
  if (!exact(source, ['sessionId', 'requestId']) || !UUID.test(source.sessionId || '')
      || !UUID.test(source.requestId || '') || !exact(origin, ['step', 'callId'])
      || !Number.isInteger(origin.step) || origin.step < 1 || origin.step > 5
      || typeof origin.callId !== 'string' || !origin.callId
      || Buffer.byteLength(origin.callId) > 128) throw fail();
  const hash = digest(['admin-acl-proposal-v1', source.sessionId, source.requestId,
    origin.step, origin.callId]);
  // The existing shared ACL pending-reference codec accepts UUIDv4-shaped
  // operation IDs. Keep deterministic replay identity within that format.
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-8${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
}

function choiceSnapshot({ scopeKey, expectedVersion, registrySha256, toolKey, role, allowed, enforcement }) {
  if (!scope(scopeKey) || !version(expectedVersion) || !SHA.test(registrySha256 || '')
      || typeof toolKey !== 'string' || !toolKey || Buffer.byteLength(toolKey) > 256
      || !['customer', 'merchant', 'admin'].includes(role)
      || typeof allowed !== 'boolean' || typeof enforcement !== 'boolean') throw fail();
  return digest({ version: 1, scopeKey, expectedVersion, registrySha256,
    toolKey, role, allowed, enforcement });
}

function enforcementSnapshot({ scopeKey, expectedVersion, registrySha256, enforcement }) {
  if (!scope(scopeKey) || !version(expectedVersion) || !SHA.test(registrySha256 || '')
      || typeof enforcement !== 'boolean') throw fail();
  return digest({ version: 1, scopeKey, expectedVersion, registrySha256, enforcement });
}

function publicValue(proposal) {
  const p = proposal;
  const permission = p.action === 'permission';
  if (!['permission', 'enforcement'].includes(p.action)) throw fail();
  const before = permission
    ? { allowed: p.before?.allowed, enforcement: p.before?.enforcement }
    : { enforcement: p.before?.enforcement };
  const after = permission
    ? { allowed: p.after?.allowed, enforcement: p.after?.enforcement }
    : { enforcement: p.after?.enforcement };
  return { version: 1, proposalId: p.proposalId, choiceId: p.choiceId,
    action: p.action, tool: permission ? { toolKey: p.tool?.toolKey, role: p.tool?.role } : null,
    before, after, expectedVersion: p.expectedVersion, registrySha256: p.registrySha256,
    scopeKey: p.scopeKey, modeCapability: mode(p.modeCapability),
    sourceSnapshotSha256: p.sourceSnapshotSha256 };
}

function validate(proposal, source) {
  const p = proposal;
  if (!exact(p, ['version', 'proposalId', 'choiceId', 'action', 'tool', 'before', 'after',
    'expectedVersion', 'registrySha256', 'scopeKey', 'modeCapability',
    'sourceSnapshotSha256', 'requestSha256', 'origin'])
      || p.version !== 1 || p.proposalId !== proposalId(source, p.origin)
      || !version(p.expectedVersion) || BigInt(p.expectedVersion) === MAX_VERSION
      || !SHA.test(p.registrySha256 || '') || !scope(p.scopeKey)
      || !SHA.test(p.sourceSnapshotSha256 || '') || !SHA.test(p.requestSha256 || '')) throw fail();
  const permission = p.action === 'permission';
  if (permission) {
    if (!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(p.choiceId || '')
        || !exact(p.tool, ['toolKey', 'role'])
        || !exact(p.before, ['allowed', 'enforcement'])
        || !exact(p.after, ['allowed', 'enforcement'])
        || typeof p.before.allowed !== 'boolean' || typeof p.after.allowed !== 'boolean'
        || typeof p.before.enforcement !== 'boolean'
        || p.after.enforcement !== p.before.enforcement
        || p.after.allowed === p.before.allowed
        || p.sourceSnapshotSha256 !== choiceSnapshot({ scopeKey: p.scopeKey,
          expectedVersion: p.expectedVersion, registrySha256: p.registrySha256,
          toolKey: p.tool.toolKey, role: p.tool.role, allowed: p.before.allowed,
          enforcement: p.before.enforcement })) throw fail();
  } else if (p.action === 'enforcement') {
    if (p.choiceId !== null || p.tool !== null || !exact(p.before, ['enforcement'])
        || !exact(p.after, ['enforcement']) || typeof p.before.enforcement !== 'boolean'
        || typeof p.after.enforcement !== 'boolean'
        || p.before.enforcement === p.after.enforcement
        || p.sourceSnapshotSha256 !== enforcementSnapshot({ scopeKey: p.scopeKey,
          expectedVersion: p.expectedVersion, registrySha256: p.registrySha256,
          enforcement: p.before.enforcement })) throw fail();
  } else throw fail();
  const value = publicValue(p);
  if (digest(value) !== p.requestSha256) throw fail();
  return { ...value, requestSha256: p.requestSha256,
    origin: { step: p.origin.step, callId: p.origin.callId } };
}

function create({ source, origin, action, selected, before, after, expectedVersion,
  registrySha256, scopeKey, modeCapability }) {
  const p = { version: 1, proposalId: proposalId(source, origin),
    choiceId: selected?.choiceId ?? null, action,
    tool: action === 'permission' ? { toolKey: selected?.toolKey, role: selected?.role } : null,
    before, after, expectedVersion, registrySha256, scopeKey, modeCapability,
    sourceSnapshotSha256: selected?.snapshotSha256 ?? enforcementSnapshot({ scopeKey,
      expectedVersion, registrySha256, enforcement: before?.enforcement }), origin };
  p.requestSha256 = digest(publicValue(p));
  return validate(p, source);
}

function project(proposal, source) {
  const { origin, ...value } = validate(proposal, source);
  return value;
}

module.exports = { createRoleAclProposal: create, validateRoleAclProposal: validate,
  projectRoleAclProposal: project, aclChoiceSnapshot: choiceSnapshot,
  aclEnforcementSnapshot: enforcementSnapshot };
