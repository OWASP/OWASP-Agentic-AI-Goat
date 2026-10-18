'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { promptPolicyRunnerOptions } = require('../server/services/secureshopPromptPolicyRunnerOptions');
const { createSecureShopBoundRefundRuntime } = require('../server/services/secureshopBoundRefundRuntime');
const { createBoundReviewRuntime } = require('../server/services/secureshopBoundReviewRuntime');
const { createSecureShopBoundProductAssist } = require('../server/services/secureshopBoundProductAssist');
const { createSecureShopBoundManualIngestion } = require('../server/services/secureshopBoundManualIngestion');

const FACTORIES = [
  ['refund', createSecureShopBoundRefundRuntime],
  ['review', createBoundReviewRuntime],
  ['product-assist', createSecureShopBoundProductAssist],
  ['manual-ingestion', createSecureShopBoundManualIngestion],
];

test('all four bound graph factories reject an invalid prompt policy repository before graph setup', () => {
  for (const [name, factory] of FACTORIES) {
    assert.throws(() => factory({ promptPolicyRepository: {}, personaAuthority: { capture() {} } }),
      /Prompt policy repository and persona authority required/, name);
  }
});

test('all four bound graph factories reject a repository without original persona authority', () => {
  const repository = { admitRunSnapshot() {} };
  for (const [name, factory] of FACTORIES) {
    assert.throws(() => factory({ promptPolicyRepository: repository }),
      /Prompt policy repository and persona authority required/, name);
  }
});

test('the trusted factory adapter snapshots the exact graph admission input and preserves role/persona binding', async () => {
  const calls = [];
  const repository = { async admitRunSnapshot(input) { calls.push(input); return { role: input.persona.role, policyVersion: '4', policies: [], text: 'owned policy', sha256: 'a'.repeat(64) }; } };
  const authority = { capture() {} };
  const options = promptPolicyRunnerOptions(repository, authority);
  const input = {
    scope: { launchId: '10000000-0000-4000-8000-000000000001', scenarioId: '20000000-0000-4000-8000-000000000001', generation: 3, platformOwnerId: 9, platformSessionId: 10 },
    persona: { id: 17, role: 'merchant' },
    personaSession: { sessionId: '30000000-0000-4000-8000-000000000001', authorityVersion: '8' },
    runId: '40000000-0000-4000-8000-000000000001',
  };
  const admission = await options.promptPolicyAdmission(input);
  assert.deepEqual(admission, { role: 'merchant', policyVersion: '4', policies: [], text: 'owned policy', sha256: 'a'.repeat(64) });
  assert.deepEqual(calls, [input]);
  input.persona.role = 'admin'; input.scope.platformOwnerId = 99;
  assert.equal(calls[0].persona.role, 'merchant');
  assert.equal(calls[0].scope.platformOwnerId, 9);
});
