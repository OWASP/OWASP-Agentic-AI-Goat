import { decodeRolePolicyProposal, decodeRolePolicyDetail, sameRolePolicyMode } from './rolePolicyProposal.mjs';

const { webcrypto } = require('node:crypto');
const { createRolePolicyProposal, projectRolePolicyProposal,
  policySupportedTargets } = require('../../../../../server/services/secureshopRolePolicyProposal.js');

const source = { sessionId: '11111111-1111-4111-8111-111111111111',
  requestId: '22222222-2222-4222-8222-222222222222' };
const origin = { step: 1, callId: 'policy-prepare-1' };
const modeCapability = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const context = { source, origin, expectedVersion: '4', scopeKey: 'a'.repeat(64), modeCapability };
beforeEach(() => { Object.defineProperty(globalThis.crypto, 'subtle', {
  configurable: true, value: webcrypto.subtle }); });

test('policy mode comparison accepts JSONB key order but rejects extra and changed fields', () => {
  const jsonbMode = { scope: { id: 'admin_assistant', kind: 'launch_feature' },
    effectiveMode: 'fixed', policyVersion: 'owned-admin-read-and-confirmation-v1',
    featureId: 'admin_assistant', version: 1 };
  expect(sameRolePolicyMode(modeCapability, jsonbMode)).toBe(true);
  expect(sameRolePolicyMode(modeCapability, { ...jsonbMode, extra: true })).toBe(false);
  expect(sameRolePolicyMode(modeCapability, { ...jsonbMode,
    scope: { ...jsonbMode.scope, extra: true } })).toBe(false);
  expect(sameRolePolicyMode(modeCapability, { ...jsonbMode, effectiveMode: 'vuln' })).toBe(false);
});

test('full 16 KiB create candidate matches canonical backend public review digest', async () => {
  const value = createRolePolicyProposal({ ...context, action: 'create', name: 'Store policy',
    selected: null, before: null, after: { markdown: 'x'.repeat(16384), targets: ['customer'] } },
  policySupportedTargets(['summarizer']));
  const publicValue = projectRolePolicyProposal(value, source, policySupportedTargets(['summarizer']));
  expect((await decodeRolePolicyProposal(publicValue)).after.markdown).toHaveLength(16384);
  await expect(decodeRolePolicyProposal({ ...publicValue, requestSha256: 'b'.repeat(64) }))
    .rejects.toThrow('Saved policy proposal invalid');
  await expect(decodeRolePolicyProposal({ ...publicValue,
    after: { ...publicValue.after, markdown: 'x'.repeat(16385) } }))
    .rejects.toThrow('Saved policy proposal invalid');
});

test('historical source targets remain readable but cannot be assigned in after candidate', async () => {
  const selected = { choiceId: '33333333-3333-4333-8333-333333333333',
    snapshotSha256: 'b'.repeat(64) };
  const value = createRolePolicyProposal({ ...context, action: 'edit', name: 'Legacy policy',
    selected, before: { markdown: 'old', targets: ['analytics'] },
    after: { markdown: 'new', targets: ['admin'] } }, policySupportedTargets([]));
  const publicValue = projectRolePolicyProposal(value, source, policySupportedTargets([]));
  expect((await decodeRolePolicyProposal(publicValue)).before.targets).toEqual(['analytics']);
  await expect(decodeRolePolicyProposal({ ...publicValue,
    after: { markdown: 'new', targets: ['analytics'] } }))
    .rejects.toThrow('Saved policy proposal invalid');
  await expect(decodeRolePolicyProposal({ ...publicValue, expectedVersion: '9007199254740991' }))
    .rejects.toThrow('Saved policy proposal invalid');
});

test('selected policy detail displays full current source only from a closed saved projection', () => {
  const value = { version: 1, choiceId: '33333333-3333-4333-8333-333333333333',
    name: 'Legacy policy', policyVersion: '3', markdown: '{{ teaching }}'.repeat(1000),
    targets: ['analytics'], snapshotSha256: 'a'.repeat(64), scopeKey: 'b'.repeat(64),
    headVersion: '4', oversized: true };
  expect(decodeRolePolicyDetail(value).markdown).toBe(value.markdown);
  expect(decodeRolePolicyDetail({ ...value, policyVersion: '9007199254740991',
    headVersion: '9007199254740991' }).markdown).toBe(value.markdown);
  expect(() => decodeRolePolicyDetail({ ...value, policyVersion: '9007199254740992' }))
    .toThrow('Saved policy proposal invalid');
  expect(() => decodeRolePolicyDetail({ ...value, secret: 'invented' })).toThrow('Saved policy proposal invalid');
  expect(() => decodeRolePolicyDetail({ ...value, markdown: 'x'.repeat(16385) }))
    .toThrow('Saved policy proposal invalid');
});
