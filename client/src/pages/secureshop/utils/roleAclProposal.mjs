import { sameRolePolicyMode } from './rolePolicyProposal.mjs';
import { assertAclReceipt } from '../pages/admin/aclOperation.js';

const V4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const MAX = 9223372036854775807n;
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype
  && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const bytes = v => new TextEncoder().encode(v).byteLength;
const text = (v, max) => typeof v === 'string' && v.length > 0 && bytes(v) <= max;
const version = v => typeof v === 'string' && /^[1-9]\d{0,18}$/.test(v) && BigInt(v) <= MAX;
const invalid = () => { throw Error('Saved ACL review is invalid'); };
async function hash(v) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(v)));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function decodeRoleAclProposal(value) {
  if (value == null) return null;
  if (!exact(value, ['version', 'proposalId', 'choiceId', 'action', 'tool', 'before', 'after',
    'expectedVersion', 'registrySha256', 'scopeKey', 'modeCapability', 'sourceSnapshotSha256', 'requestSha256'])
    || value.version !== 1 || !V4.test(value.proposalId || '')
    || !['permission', 'enforcement'].includes(value.action)
    || !version(value.expectedVersion) || BigInt(value.expectedVersion) === MAX
    || !text(value.scopeKey, 1024) || !SHA.test(value.registrySha256 || '')
    || !SHA.test(value.sourceSnapshotSha256 || '') || !SHA.test(value.requestSha256 || '')) invalid();
  const modeCapability = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: value.modeCapability?.effectiveMode,
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  if (!['vuln', 'fixed'].includes(modeCapability.effectiveMode)
    || !sameRolePolicyMode(value.modeCapability, modeCapability)) invalid();
  const common = { version: 1, scopeKey: value.scopeKey, expectedVersion: value.expectedVersion,
    registrySha256: value.registrySha256 };
  let tool = null, before, after, snapshot;
  if (value.action === 'permission') {
    if (!V4.test(value.choiceId || '') || !exact(value.tool, ['toolKey', 'role'])
      || !text(value.tool.toolKey, 256) || !['customer', 'merchant', 'admin'].includes(value.tool.role)
      || !exact(value.before, ['allowed', 'enforcement']) || !exact(value.after, ['allowed', 'enforcement'])
      || typeof value.before.allowed !== 'boolean' || typeof value.after.allowed !== 'boolean'
      || typeof value.before.enforcement !== 'boolean' || value.before.enforcement !== value.after.enforcement
      || value.before.allowed === value.after.allowed) invalid();
    tool = { toolKey: value.tool.toolKey, role: value.tool.role };
    before = { allowed: value.before.allowed, enforcement: value.before.enforcement };
    after = { allowed: value.after.allowed, enforcement: value.after.enforcement };
    snapshot = await hash({ ...common, toolKey: tool.toolKey, role: tool.role,
      allowed: before.allowed, enforcement: before.enforcement });
  } else {
    if (value.choiceId !== null || value.tool !== null || !exact(value.before, ['enforcement'])
      || !exact(value.after, ['enforcement']) || typeof value.before.enforcement !== 'boolean'
      || typeof value.after.enforcement !== 'boolean' || value.before.enforcement === value.after.enforcement) invalid();
    before = { enforcement: value.before.enforcement }; after = { enforcement: value.after.enforcement };
    snapshot = await hash({ ...common, enforcement: before.enforcement });
  }
  if (snapshot !== value.sourceSnapshotSha256) invalid();
  const canonical = { version: 1, proposalId: value.proposalId, choiceId: value.choiceId,
    action: value.action, tool, before, after, expectedVersion: value.expectedVersion,
    registrySha256: value.registrySha256, scopeKey: value.scopeKey, modeCapability,
    sourceSnapshotSha256: snapshot };
  if (await hash(canonical) !== value.requestSha256) invalid();
  return Object.freeze({ ...canonical, requestSha256: value.requestSha256 });
}

export function aclProposalPending(p) {
  return { kind: p.action, scopeKey: p.scopeKey, registrySha256: p.registrySha256,
    body: { operationId: p.proposalId, expectedVersion: p.expectedVersion,
      ...(p.action === 'permission' ? { tool_name: p.tool.toolKey, role: p.tool.role, allowed: p.after.allowed }
        : { enabled: p.after.enforcement }) } };
}
export function decodeAclAdministration(value) {
  if (value?.ok !== true || value.administration?.versionedPolicy !== true
    || !text(value.administration.scopeKey, 1024) || !version(value.version)
    || !SHA.test(value.registrySha256 || '') || typeof value.enforcement_enabled !== 'boolean') invalid();
  return { scopeKey: value.administration.scopeKey, version: value.version,
    registrySha256: value.registrySha256, enforcement: value.enforcement_enabled };
}
export function verifyAclOperation(value, pending) {
  if (!exact(value, ['ok', 'receipt']) || value.ok !== true
    || !exact(value.receipt, ['operationId', 'expectedVersion', 'version', 'registrySha256', 'enforcement', 'change'])) invalid();
  return assertAclReceipt(value.receipt, pending);
}
