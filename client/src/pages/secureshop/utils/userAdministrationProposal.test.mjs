import { webcrypto } from 'node:crypto';
import { decodeUserAdministrationProposal, sameUserAdministrationProposal } from './userAdministrationProposal.mjs';

const { createRoleUserAdministrationProposal, projectRoleUserAdministrationProposal } =
  require('../../../../../server/services/secureshopRoleUserAdministrationProposal.js');
const sessionId = '11111111-1111-4111-8111-111111111111';
const requestId = '22222222-2222-4222-8222-222222222222';
const selected = { kind: 'tenant_user', choiceId: '33333333-3333-4333-8333-333333333333',
  sourceId: 7, snapshotSha256: 'a'.repeat(64) };
const user = { id: 7, username: 'owned_customer', identity_kind: 'registered_account',
  role: 'customer', banned_at: null, authority_version: '4' };
const administration = { roleBan: true, scopeKey: 'owned administrator scope' };
const modeCapability = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const create = changes => projectRoleUserAdministrationProposal(createRoleUserAdministrationProposal({
  sessionId, requestId, step: 1, callId: 'tool-1', selected, user, administration,
  action: 'set_role', role: 'merchant', reason: null, modeCapability, ...changes,
}), { sessionId, requestId });

beforeAll(() => { Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto }); });

test('decodes the server canonical role and ban proposals without inventing target authority', async () => {
  const role = create();
  const ban = create({ action: 'ban', role: null, reason: 'Documented account abuse' });
  expect(await decodeUserAdministrationProposal(role)).toEqual(role);
  expect(await decodeUserAdministrationProposal(ban)).toEqual(ban);
  expect(sameUserAdministrationProposal(role, role)).toBe(true);
  expect(sameUserAdministrationProposal(role, ban)).toBe(false);
});

test('rejects changed target, action, scope, mode and extra authority fields', async () => {
  const role = create();
  for (const changed of [
    { ...role, target: { ...role.target, userId: 8 } },
    { ...role, role: 'admin' },
    { ...role, scopeKey: 'another administrator scope' },
    { ...role, modeCapability: { ...role.modeCapability, effectiveMode: 'vuln' } },
    { ...role, target: { ...role.target, email: 'private@example.invalid' } },
  ]) await expect(decodeUserAdministrationProposal(changed)).rejects.toThrow('proposal invalid');
});
