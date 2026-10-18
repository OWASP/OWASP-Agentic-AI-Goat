import { decodeRoleSystemRestartProposal } from './roleSystemRestartProposal.mjs';

const { randomUUID, webcrypto } = require('node:crypto');
const { createRoleSystemRestartProposal, projectRoleSystemRestartProposal } = require(
  '../../../../../server/services/secureshopRoleSystemRestartProposal.js');
const { CAPABILITY } = require('../../../../../server/services/secureshopSystemRestartClient.js');
const reordered = value => Array.isArray(value) ? value.map(reordered)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).reverse().map(key => [key, reordered(value[key])])) : value;
beforeEach(() => Object.defineProperty(globalThis.crypto, 'subtle',
  { configurable: true, value: webcrypto.subtle }));

function fixture() {
  const source = { sessionId: randomUUID(), requestId: randomUUID() };
  const proposal = createRoleSystemRestartProposal({
    context: { scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
      platformOwnerId: 17, platformSessionId: 19 }, persona: { id: 23, role: 'admin' },
    personaSession: { sessionId: randomUUID(), authorityVersion: '1' } },
    administration: { restartCapability: CAPABILITY, targetId: randomUUID() },
    source, origin: { step: 2, callId: 'restart-prepare-1' },
    name: 'nginx; touch /owned-effect/witness',
    modeCapability: { version: 1, featureId: 'admin_assistant',
      policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
      scope: { kind: 'launch_feature', id: 'admin_assistant' } },
  });
  return projectRoleSystemRestartProposal(proposal, source);
}

describe('saved System restart proposal', () => {
  it('accepts the real server projection even when JSONB reorders nested keys', async () => {
    const projected = fixture();
    expect(await decodeRoleSystemRestartProposal(reordered(projected))).toEqual(projected);
  });

  it('rejects changed request, scope, policy, digest, and extra fields', async () => {
    const projected = fixture();
    for (const changed of [
      { ...projected, name: 'different' },
      { ...projected, scopeKey: 'f'.repeat(64) },
      { ...projected, requestSha256: 'f'.repeat(64) },
      { ...projected, proposalSha256: 'f'.repeat(64) },
      { ...projected, modeCapability: { ...projected.modeCapability, policyVersion: 'wrong' } },
      { ...projected, hidden: 'unexpected' },
    ]) await expect(decodeRoleSystemRestartProposal(changed)).rejects.toThrow('proposal invalid');
  });
});
