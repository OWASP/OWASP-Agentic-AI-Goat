'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopPersonaInboxComposition, createSecureShopPersonaInboxRepositoryBundle,
  mapPersonaInboxFixtures }
  = require('../server/services/secureshopPersonaInboxComposition');
const { assertPersonaInboxReadiness } = require('../server/services/secureshopBoundReviewComposition');

test('feature is structurally absent by default and invalid readiness never coerces on', () => {
  assert.deepEqual(createSecureShopPersonaInboxComposition(), { ready: false });
  assert.throws(() => createSecureShopPersonaInboxComposition({ enabled: 'false' }), {
    code: 'SECURESHOP_PERSONA_INBOX_UNAVAILABLE',
  });
  assert.throws(() => createSecureShopPersonaInboxComposition({ enabled: true }), {
    code: 'SECURESHOP_PERSONA_INBOX_UNAVAILABLE',
  });
});

test('neutral fixture ownership comes from durable installation personas for all three roles', () => {
  const mapped = mapPersonaInboxFixtures([
    { id: 902, role: 'merchant' }, { id: 701, role: 'customer' }, { id: 803, role: 'admin' },
  ]);
  assert.deepEqual(mapped.map(row => row.owner), [
    { id: 701, role: 'customer' }, { id: 902, role: 'merchant' }, { id: 803, role: 'admin' },
  ]);
  assert.equal(mapped.some(row => /instruction|ignore previous/i.test(row.body)), false);
});

test('structural startup readiness ignores mutable visibility and enablement', async () => {
  const agentsPool = { async query(_sql, args) { return { rows: args[0].map(value => ({ value, ready: true })) }; } };
  const identityPool = { async query(sql, args) {
    if (sql.includes('FROM pg_constraint')) return { rows: args[0].map(conname => ({ conname, ready: true })) };
    if (sql.includes('secureshop_auth.assessment_objectives')) return { rows: args[0].map(objective_id => ({
      objective_id, catalog_active: true, is_enabled: false,
    })) };
    if (sql.includes('workshop_platform.exercises')) return { rows: [{ catalog_active: true, is_visible: false }] };
    throw new Error('unexpected query');
  } };
  assert.equal(await assertPersonaInboxReadiness({ identityPool, agentsPool }), true);
  const unavailableAgents = { async query(_sql, args) { return { rows: args[0].map((value, index) => ({
    value, ready: index !== 0,
  })) }; } };
  await assert.rejects(assertPersonaInboxReadiness({ identityPool, agentsPool: unavailableAgents }), {
    code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE',
  });
});

test('repository bundle gives ACL advancement an exact short-lived server authority', async () => {
  const queries = [];
  const agentsPool = { query: async (...args) => { queries.push(args); return { rows: [] }; }, connect: async () => ({ query: async (...args) => { queries.push(args); return { rows: [] }; }, release() {} }) };
  const launches = { assertCurrent: async () => ({}) };
  const cleanupAuthority = { checkTarget: async () => ({}) };
  const bundle = createSecureShopPersonaInboxRepositoryBundle({ agentsPool, launches, cleanupAuthority });
  const value = Object.freeze({ targetId: '10000000-0000-4000-8000-000000000006',
    launchId: '20000000-0000-4000-8000-000000000006',
    scenarioId: '30000000-0000-4000-8000-000000000006', generation: 1,
    platformOwnerId: 7, platformSessionId: 8, expectedVersion: 1, mode: 'enforced' });
  await assert.rejects(bundle.repository.advanceAcl(value, { expectedVersion: 1, mode: 'enforced' }), {
    code: 'ACL_TRANSITION_UNAVAILABLE',
  });
  const revoke = await bundle.authorizeAclTransition(value);
  // The database call is now reached; the empty fake result fails integrity,
  // proving the private authorization gate opened without granting caller authority.
  await assert.rejects(bundle.repository.advanceAcl(value, { expectedVersion: 1, mode: 'enforced' }), {
    code: 'PERSONA_INBOX_ACL_MISMATCH',
  });
  revoke();
  await assert.rejects(bundle.repository.advanceAcl(value, { expectedVersion: 1, mode: 'enforced' }), {
    code: 'ACL_TRANSITION_UNAVAILABLE',
  });
  assert.equal(queries.filter(([sql]) => sql.includes('advance_persona_inbox_acl')).length, 1);
});
