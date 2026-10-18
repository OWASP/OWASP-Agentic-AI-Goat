const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const ROLES = ['customer', 'merchant', 'admin'];
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const text = (value, limit) => typeof value === 'string' && value.length > 0
  && value.isWellFormed() && encoder.encode(value).byteLength <= limit;
const invalid = () => { throw new Error('Saved user administration proposal invalid'); };

function canonical(value) {
  const target = value.target, mode = value.modeCapability;
  return { version: 1, proposalId: value.proposalId,
    target: { choiceId: target.choiceId, userId: target.userId, username: target.username,
      identityKind: target.identityKind, currentRole: target.currentRole, bannedAt: target.bannedAt },
    action: value.action, role: value.role, reason: value.reason,
    expectedVersion: value.expectedVersion, scopeKey: value.scopeKey,
    modeCapability: { version: mode.version, featureId: mode.featureId,
      policyVersion: mode.policyVersion, effectiveMode: mode.effectiveMode,
      scope: { kind: mode.scope.kind, id: mode.scope.id } } };
}

export async function decodeUserAdministrationProposal(value) {
  if (value === null) return null;
  if (!exact(value, ['version', 'proposalId', 'target', 'action', 'role', 'reason',
    'expectedVersion', 'scopeKey', 'modeCapability', 'requestSha256'])
    || value.version !== 1 || !UUID.test(value.proposalId)
    || !exact(value.target, ['choiceId', 'userId', 'username', 'identityKind', 'currentRole', 'bannedAt'])
    || !UUID.test(value.target.choiceId) || !Number.isSafeInteger(value.target.userId)
    || value.target.userId < 1 || value.target.userId > 2147483647
    || !text(value.target.username, 100)
    || !['teaching_persona', 'registered_account'].includes(value.target.identityKind)
    || !ROLES.includes(value.target.currentRole)
    || !(value.target.bannedAt === null || (text(value.target.bannedAt, 64)
      && Number.isFinite(Date.parse(value.target.bannedAt))))
    || !['set_role', 'ban'].includes(value.action)
    || (value.action === 'set_role' && (!ROLES.includes(value.role) || value.reason !== null))
    || (value.action === 'ban' && (value.role !== null || !text(value.reason, 1024)
      || !value.reason.trim()))
    || typeof value.expectedVersion !== 'string' || !/^[1-9]\d*$/.test(value.expectedVersion)
    || value.expectedVersion.length > 16 || BigInt(value.expectedVersion) >= 9007199254740991n
    || !text(value.scopeKey, 1024)
    || !exact(value.modeCapability, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    || value.modeCapability.version !== 1 || value.modeCapability.featureId !== 'admin_assistant'
    || value.modeCapability.policyVersion !== 'owned-admin-read-and-confirmation-v1'
    || !['vuln', 'fixed'].includes(value.modeCapability.effectiveMode)
    || !exact(value.modeCapability.scope, ['kind', 'id'])
    || value.modeCapability.scope.kind !== 'launch_feature'
    || value.modeCapability.scope.id !== 'admin_assistant'
    || !SHA.test(value.requestSha256)) invalid();
  const projection = canonical(value);
  const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256',
    encoder.encode(JSON.stringify(projection))))].map(byte => byte.toString(16).padStart(2, '0')).join('');
  if (hash !== value.requestSha256) invalid();
  return Object.freeze({ ...projection, target: Object.freeze(projection.target),
    modeCapability: Object.freeze({ ...projection.modeCapability,
      scope: Object.freeze(projection.modeCapability.scope) }), requestSha256: hash });
}

export function sameUserAdministrationProposal(left, right) {
  return !!left && !!right && left.proposalId === right.proposalId
    && left.requestSha256 === right.requestSha256 && left.scopeKey === right.scopeKey;
}
