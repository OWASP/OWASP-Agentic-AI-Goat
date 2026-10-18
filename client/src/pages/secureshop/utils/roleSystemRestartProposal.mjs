import { restartHash, restartRequest } from '../pages/admin/systemRestartOperation.mjs';
import { sameRolePolicyMode } from './rolePolicyProposal.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && Object.getPrototypeOf(value) === Object.prototype
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const fail = () => { throw new Error('Saved System restart proposal invalid'); };

export async function decodeRoleSystemRestartProposal(value) {
  if (value == null) return null;
  if (!exact(value, ['version', 'proposalId', 'action', 'name', 'targetId', 'scopeKey',
    'sourceSnapshotSha256', 'modeCapability', 'requestSha256', 'proposalSha256'])
    || value.version !== 1 || value.action !== 'restart' || !UUID.test(value.proposalId)
    || !UUID.test(value.targetId) || !SHA.test(value.scopeKey)
    || !SHA.test(value.sourceSnapshotSha256) || !SHA.test(value.requestSha256)
    || !SHA.test(value.proposalSha256)) fail();
  const mode = value.modeCapability;
  const expectedMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: mode?.effectiveMode,
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  if (!sameRolePolicyMode(mode, expectedMode)) fail();
  let request;
  try { request = restartRequest(value.proposalId, value.name); } catch { fail(); }
  const scopeKey = await restartHash({ restartTargetId: value.targetId });
  const requestSha256 = await restartHash(request);
  if (scopeKey !== value.scopeKey || requestSha256 !== value.requestSha256) fail();
  const body = { version: 1, proposalId: value.proposalId, action: 'restart',
    name: value.name, targetId: value.targetId, scopeKey: value.scopeKey,
    sourceSnapshotSha256: value.sourceSnapshotSha256,
    modeCapability: expectedMode, requestSha256: value.requestSha256 };
  if (await restartHash(canonical(body)) !== value.proposalSha256) fail();
  return Object.freeze({ ...body, proposalSha256: value.proposalSha256 });
}
