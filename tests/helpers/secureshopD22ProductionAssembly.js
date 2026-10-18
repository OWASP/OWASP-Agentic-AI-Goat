'use strict';

// Test-only assembler for the real owned-audit production composition.  It
// accepts the disposable stores and target client supplied by the fixture; it
// never reads an installed audit configuration or creates a target itself.
const assert = require('node:assert/strict');

async function createD22AuditApplication({ identityPool, agentsPool, resetComposition,
  gradingBootstrap, launches, personaAuth, auditReader, client, provider, judge,
  toolPolicyRepository, modeAuthority } = {}) {
  for (const [name, value] of Object.entries({ identityPool, agentsPool, resetComposition,
    gradingBootstrap, launches, personaAuth, auditReader, client, provider, judge,
    toolPolicyRepository, modeAuthority })) assert.ok(value, `D22 ${name} is required`);
  const cleanupAuthority = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository')
    .createSecureShopResetCleanupAuthorityRepository(identityPool);
  const composition = require('../../server/services/secureshopOwnedAuditComposition')
    .createOwnedAuditComposition({ identityPool, agentsPool, resetComposition, gradingBootstrap,
      launches, personaAuth, auditReader, cleanupAuthority,
      turns: resetComposition.turns, journal: resetComposition.journal,
      conversations: resetComposition.conversationService,
      conversationRepository: resetComposition.conversations,
      client, provider, judge, agentEnabled: true, toolPolicyRepository, modeAuthority });
  await composition.checkReadiness();
  assert.equal(typeof composition.application.createAgentSession, 'function');
  assert.equal(typeof composition.application.runAgent, 'function');
  return composition.application;
}

module.exports = { createD22AuditApplication };
