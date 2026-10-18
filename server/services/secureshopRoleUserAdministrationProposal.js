'use strict';
const { createHash } = require('node:crypto');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const uuid = value => typeof value === 'string' && UUID.test(value);
const sha = value => typeof value === 'string' && SHA.test(value);
const ROLES = ['customer', 'merchant', 'admin'];
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const text = (value, max) => typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= max;
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const invalid = () => Object.assign(Error('User administration proposal unavailable'), { code: 'ROLE_USER_ADMINISTRATION_PROPOSAL_INVALID' });
function proposalId(source, origin) {
  if (!uuid(source?.sessionId) || !uuid(source?.requestId)
      || !exact(origin, ['step', 'callId']) || !Number.isInteger(origin.step)
      || origin.step < 1 || origin.step > 4 || !text(origin.callId, 128)) throw invalid();
  const h = digest(['admin-user-proposal-v1', source.sessionId, source.requestId, origin.step, origin.callId]);
  return `${h.slice(0,8)}-${h.slice(8,12)}-5${h.slice(13,16)}-8${h.slice(17,20)}-${h.slice(20,32)}`;
}
function modeValid(m) {
  return exact(m, ['version','featureId','policyVersion','effectiveMode','scope'])
    && m.version === 1 && m.featureId === 'admin_assistant'
    && m.policyVersion === 'owned-admin-read-and-confirmation-v1'
    && ['vuln','fixed'].includes(m.effectiveMode)
    && exact(m.scope, ['kind','id']) && m.scope.kind === 'launch_feature' && m.scope.id === 'admin_assistant';
}
function publicValue(p) {
  const t = p.target, m = p.modeCapability;
  // Fixed nested order preserves the creation digest through PostgreSQL JSONB.
  return { version: 1, proposalId: p.proposalId,
    target: { choiceId:t.choiceId, userId:t.userId, username:t.username, identityKind:t.identityKind,
      currentRole:t.currentRole, bannedAt:t.bannedAt },
    action:p.action, role:p.role, reason:p.reason, expectedVersion:p.expectedVersion, scopeKey:p.scopeKey,
    modeCapability: { version:m.version, featureId:m.featureId, policyVersion:m.policyVersion,
      effectiveMode:m.effectiveMode, scope:{kind:m.scope.kind,id:m.scope.id} } };
}
function validate(p, source) {
  if (!exact(p, ['version','proposalId','target','action','role','reason','expectedVersion','scopeKey','modeCapability','requestSha256','origin','sourceSnapshotSha256'])
      || p.version !== 1 || p.proposalId !== proposalId(source, p.origin)
      || !exact(p.target, ['choiceId','userId','username','identityKind','currentRole','bannedAt'])
      || !uuid(p.target.choiceId) || !Number.isSafeInteger(p.target.userId)
      || p.target.userId < 1 || p.target.userId > 2147483647 || !text(p.target.username, 100)
      || !['teaching_persona','registered_account'].includes(p.target.identityKind)
      || !ROLES.includes(p.target.currentRole)
      || !(p.target.bannedAt === null || (text(p.target.bannedAt, 64) && Number.isFinite(Date.parse(p.target.bannedAt))))
      || !['set_role','ban'].includes(p.action)
      || (p.action === 'set_role' && (!ROLES.includes(p.role) || p.reason !== null))
      || (p.action === 'ban' && (p.role !== null || !text(p.reason, 1024) || !p.reason.trim()))
      || typeof p.expectedVersion !== 'string' || !/^[1-9]\d*$/.test(p.expectedVersion)
      || p.expectedVersion.length > 16 || BigInt(p.expectedVersion) >= 9007199254740991n
      || !text(p.scopeKey, 1024) || !modeValid(p.modeCapability)
      || !sha(p.sourceSnapshotSha256) || !sha(p.requestSha256)
      || p.requestSha256 !== digest(publicValue(p))) throw invalid();
  return { ...publicValue(p), requestSha256:p.requestSha256,
    origin:{step:p.origin.step,callId:p.origin.callId}, sourceSnapshotSha256:p.sourceSnapshotSha256 };
}
function create({sessionId,requestId,step,callId,selected,user,administration,action,role,reason,modeCapability}) {
  if (selected?.kind !== 'tenant_user' || selected.sourceId !== user?.id
      || !sha(selected.snapshotSha256) || administration?.roleBan !== true) throw invalid();
  const p = { version:1, proposalId:proposalId({sessionId,requestId},{step,callId}),
    target:{choiceId:selected.choiceId,userId:user.id,username:user.username,identityKind:user.identity_kind,
      currentRole:user.role,bannedAt:user.banned_at},
    action,role,reason,expectedVersion:user.authority_version,scopeKey:administration.scopeKey,
    modeCapability,origin:{step,callId},sourceSnapshotSha256:selected.snapshotSha256 };
  // Validate structure before accessing a possibly malformed nested mode.
  if (!modeValid(modeCapability)) throw invalid();
  p.requestSha256 = digest(publicValue(p));
  return validate(p,{sessionId,requestId});
}
function project(value, source) {
  const p = validate(value, source);
  return { ...publicValue(p), requestSha256:p.requestSha256 };
}
module.exports = { createRoleUserAdministrationProposal:create,
  validateRoleUserAdministrationProposal:validate, projectRoleUserAdministrationProposal:project };
