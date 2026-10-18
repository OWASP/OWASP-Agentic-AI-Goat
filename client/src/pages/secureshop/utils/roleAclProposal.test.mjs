import { decodeRoleAclProposal, aclProposalPending, decodeAclAdministration, verifyAclOperation } from './roleAclProposal.mjs';
const { webcrypto, randomUUID } = require('node:crypto');
const C = require('../../../../../server/services/secureshopRoleAclProposal.js');
const source = { sessionId: '11111111-1111-4111-8111-111111111111', requestId: '22222222-2222-4222-8222-222222222222' };
const modeCapability = { version: 1, featureId: 'admin_assistant', policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'admin_assistant' } };
function proposal(action = 'permission') {
  const base = { scopeKey: 'owned-scope', expectedVersion: '4', registrySha256: 'a'.repeat(64), toolKey: 'audit.search_by_user', role: 'admin', allowed: false, enforcement: true };
  const selected = action === 'permission' ? { ...base, choiceId: randomUUID(),
    snapshotSha256: C.aclChoiceSnapshot(base) } : null;
  return C.projectRoleAclProposal(C.createRoleAclProposal({ ...base, source, origin: { step: 1, callId: 'acl-prepare' }, action, selected,
    before: action === 'permission' ? { allowed: false, enforcement: true } : { enforcement: true },
    after: action === 'permission' ? { allowed: true, enforcement: true } : { enforcement: false }, modeCapability }), source);
}
beforeEach(() => Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle }));
test.each(['permission', 'enforcement'])('server %s projection decodes exact JSONB-order-independent public fields', async action => {
  const p = proposal(action);
  if (action === 'permission') expect(p.choiceId).toMatch(/^[a-f0-9]{8}-[a-f0-9]{4}-4/);
  const reverse = v => Array.isArray(v) ? v.map(reverse) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).reverse().map(([k, x]) => [k, reverse(x)])) : v;
  expect(await decodeRoleAclProposal(reverse(p))).toEqual(p);
  const ref = aclProposalPending(p);
  expect(ref.body.operationId).toBe(p.proposalId);
  expect(ref.kind).toBe(action);
});
test('tampered source snapshot, scope, target, before/after, mode and extra keys fail closed', async () => {
  const p = proposal();
  for (const changed of [{ ...p, scopeKey: 'foreign' }, { ...p, sourceSnapshotSha256: 'b'.repeat(64) },
    { ...p, choiceId: randomUUID() },
    { ...p, tool: { ...p.tool, role: 'customer' } }, { ...p, before: p.after },
    { ...p, after: { ...p.after, enforcement: false } }, { ...p, extra: true },
    { ...p, modeCapability: { ...p.modeCapability, extra: true } }, { ...p, expectedVersion: '9223372036854775807' }]) {
    await expect(decodeRoleAclProposal(changed)).rejects.toThrow('invalid');
  }
});
test('terminal head remains readable for exact old receipt recovery and receipt binds all change fields', () => {
  expect(decodeAclAdministration({ ok: true, administration: { versionedPolicy: true, scopeKey: 'owned-scope' },
    version: '9223372036854775807', registrySha256: 'a'.repeat(64), enforcement_enabled: true }).version).toBe('9223372036854775807');
  const p = proposal(), ref = aclProposalPending(p);
  const receipt = { operationId: p.proposalId, expectedVersion: '4', version: '5', registrySha256: p.registrySha256,
    enforcement: true, change: { kind: 'permission', toolKey: p.tool.toolKey, role: 'admin', allowed: true } };
  expect(verifyAclOperation({ ok: true, receipt }, ref)).toEqual(receipt);
  expect(() => verifyAclOperation({ ok: true, receipt: { ...receipt, operationId: source.requestId } }, ref)).toThrow();
  expect(() => verifyAclOperation({ ok: true, receipt: { ...receipt, extra: true } }, ref)).toThrow();
});
