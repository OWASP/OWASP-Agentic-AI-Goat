import { isPolicyName, isPolicyVersion, policyDigest } from '../pages/admin/policyOperation.js';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const TARGETS = Object.freeze(['admin', 'customer', 'listing', 'merchant', 'review-moderator', 'summarizer']);
const HISTORICAL_TARGETS = Object.freeze(['admin', 'analytics', 'customer', 'inventory',
  'listing', 'merchant', 'review-moderator', 'summarizer']);
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const wellFormed = value => typeof value === 'string' && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value);
const fail = () => { throw new Error('Saved policy proposal invalid'); };

export function sameRolePolicyMode(left, right) {
  if (!exact(left, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    || !exact(right, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    || !exact(left.scope, ['kind', 'id']) || !exact(right.scope, ['kind', 'id'])) return false;
  return left.version === right.version && left.featureId === right.featureId
    && left.policyVersion === right.policyVersion && left.effectiveMode === right.effectiveMode
    && left.scope.kind === right.scope.kind && left.scope.id === right.scope.id;
}

function source(value, historical = false) {
  if (value === null) return null;
  if (!exact(value, ['markdown', 'targets']) || !wellFormed(value.markdown)
    || value.markdown.includes('\0') || new TextEncoder().encode(value.markdown).byteLength > 16384
    || !Array.isArray(value.targets) || !value.targets.length
    || value.targets.some((target, index) => !(historical ? HISTORICAL_TARGETS : TARGETS).includes(target)
      || (index && value.targets[index - 1] >= target))) fail();
  return { markdown: value.markdown, targets: [...value.targets] };
}

export async function decodeRolePolicyProposal(value) {
  if (value == null) return null;
  if (!exact(value, ['version', 'proposalId', 'choiceId', 'action', 'name', 'before', 'after',
    'expectedVersion', 'scopeKey', 'modeCapability', 'sourceSnapshotSha256', 'requestSha256'])
    || value.version !== 1 || !UUID.test(value.proposalId)
    || !['create', 'edit', 'preview', 'delete'].includes(value.action)
    || !isPolicyName(value.name) || !isPolicyVersion(value.expectedVersion)
    || BigInt(value.expectedVersion) >= 9007199254740991n
    || !SHA.test(value.scopeKey) || !SHA.test(value.requestSha256)) fail();
  const before = source(value.before, true), after = source(value.after);
  const selected = value.action !== 'create';
  if (selected !== (value.choiceId !== null) || (selected && !UUID.test(value.choiceId))
    || selected !== (value.sourceSnapshotSha256 !== null)
    || (selected && !SHA.test(value.sourceSnapshotSha256))
    || (selected && !before) || (!selected && before)
    || (value.action === 'delete' ? !!after : !after)
    || (value.action === 'edit' && JSON.stringify(before) === JSON.stringify(after))) fail();
  const mode = value.modeCapability;
  if (!exact(mode, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    || mode.version !== 1 || mode.featureId !== 'admin_assistant'
    || mode.policyVersion !== 'owned-admin-read-and-confirmation-v1'
    || !['vuln', 'fixed'].includes(mode.effectiveMode)
    || !exact(mode.scope, ['kind', 'id']) || mode.scope.kind !== 'launch_feature'
    || mode.scope.id !== 'admin_assistant') fail();
  const canonical = { version: 1, proposalId: value.proposalId, choiceId: value.choiceId,
    action: value.action, name: value.name, before, after,
    expectedVersion: value.expectedVersion, scopeKey: value.scopeKey,
    modeCapability: { version: 1, featureId: mode.featureId, policyVersion: mode.policyVersion,
      effectiveMode: mode.effectiveMode, scope: { kind: mode.scope.kind, id: mode.scope.id } },
    sourceSnapshotSha256: value.sourceSnapshotSha256 };
  if (await policyDigest(JSON.stringify(canonical)) !== value.requestSha256) fail();
  return Object.freeze({ ...canonical, requestSha256: value.requestSha256 });
}

export function decodeRolePolicyDetail(value) {
  if (value == null) return null;
  if (!exact(value, ['version', 'choiceId', 'name', 'policyVersion', 'markdown', 'targets',
    'snapshotSha256', 'scopeKey', 'headVersion', 'oversized'])
    || value.version !== 1 || !UUID.test(value.choiceId) || !isPolicyName(value.name)
    || !isPolicyVersion(value.policyVersion) || !isPolicyVersion(value.headVersion)
    || BigInt(value.policyVersion) > 9007199254740991n
    || BigInt(value.headVersion) > 9007199254740991n
    || !SHA.test(value.snapshotSha256) || !SHA.test(value.scopeKey)
    || typeof value.oversized !== 'boolean') fail();
  const readable = source({ markdown: value.markdown, targets: value.targets }, true);
  return Object.freeze({ version: 1, choiceId: value.choiceId, name: value.name,
    policyVersion: value.policyVersion, markdown: readable.markdown, targets: readable.targets,
    snapshotSha256: value.snapshotSha256, scopeKey: value.scopeKey,
    headVersion: value.headVersion, oversized: value.oversized });
}
