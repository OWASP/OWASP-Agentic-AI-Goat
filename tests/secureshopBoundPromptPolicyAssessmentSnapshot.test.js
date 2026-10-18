'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { createBoundPromptPolicyRepository } = require('../server/database/postgres/secureshopBoundPromptPolicyRepository');
const { buildPolicySnapshot } = require('../server/services/secureshopPromptPolicySnapshot');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');

function fixture() {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 7, platformSessionId: 9 };
  const persona = { id: 11, role: 'admin' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '3' };
  const runId = randomUUID();
  const rendered = 'Use the exact saved instruction.';
  const snapshot = buildPolicySnapshot({ policyVersion: '2', role: 'admin', policies: [{
    name: 'owned-policy', rendered,
    renderedSha256: createHash('sha256').update(rendered).digest('hex'), targets: ['admin']
  }] });
  let row = { run_id: runId, persona_id: persona.id, persona_session_id: personaSession.sessionId,
    authority_version: personaSession.authorityVersion, persona_role: 'admin', version: '2',
    payload_json: structuredClone(snapshot), digest: canonicalDigest(snapshot) };
  const publicationOperationId = randomUUID();
  let revisions = [{ operation_id: publicationOperationId, name: 'owned-policy', action: 'upsert',
    payload_json: { markdown: rendered, targets: ['admin'], rendered,
      renderedSha256: snapshot.policies[0].renderedSha256 }, digest: null }];
  revisions[0].digest = canonicalDigest(revisions[0].payload_json);
  let revoked = false;
  const queries = [];
  const client = { async query(sql) {
    queries.push(sql);
    if (sql.startsWith('SET LOCAL')) return { rows: [] };
    if (sql.includes('FROM secureshop_agents.bound_prompt_policy_snapshots')) return { rows: row === undefined ? [] : [row] };
    if (sql.includes('FROM secureshop_agents.bound_prompt_policy_revisions')) return { rows: revisions };
    throw Error(`Unexpected SQL: ${sql}`);
  } };
  const authority = { async capture(input) {
    const current = async () => { if (revoked) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); };
    await current();
    return { binding: { ...input.scope, personaId: input.personaId, role: input.role,
      sessionId: input.sessionId, authorityVersion: input.authorityVersion }, assertRemoteAdmission: current,
    withPersonaEffect: async work => { await current(); return work(client); } };
  } };
  const repository = createBoundPromptPolicyRepository({ pool: { async query() { throw Error('unexpected pool query'); } },
    personaAuthority: authority, audit: { async append() {} } });
  const input = () => ({ scope: structuredClone(scope), persona: structuredClone(persona),
    personaSession: structuredClone(personaSession), runId });
  return { repository, input, snapshot, publicationOperationId, queries, setRow: value => { row = value; },
    setRevisions: value => { revisions = value; }, revoke: () => { revoked = true; } };
}

test('V24 assessment snapshot reads only the original run-bound immutable v1 policy snapshot', async () => {
  const f = fixture();
  const result = await f.repository.readAssessmentSnapshot(f.input());
  assert.deepEqual(result.snapshot, f.snapshot);
  assert.equal(result.runId, f.input().runId);
  assert.equal(result.publicationOperationId, f.publicationOperationId);
  assert.deepEqual(result.persona, { id: 11, role: 'admin' });
  assert.ok(f.queries.every(sql => sql.startsWith('SET LOCAL') || sql.startsWith('SELECT ')));
  assert.equal(f.queries.some(sql => sql.includes('_current') || sql.includes('INSERT')), false);
});

test('V24 assessment snapshot returns null only when the original run has no persisted snapshot', async () => {
  const f = fixture();
  f.setRow(undefined);
  assert.equal(await f.repository.readAssessmentSnapshot(f.input()), null);
});

test('V24 assessment snapshot fails closed for foreign or tampered persisted data', async () => {
  for (const alter of [
    row => ({ ...row, persona_session_id: randomUUID() }),
    row => ({ ...row, digest: '0'.repeat(64) }),
    row => ({ ...row, payload_json: { ...row.payload_json, policyVersion: '3' } }),
  ]) {
    const f = fixture();
    const result = await f.repository.readAssessmentSnapshot(f.input());
    f.setRow(alter({ run_id: result.runId, persona_id: result.persona.id,
      persona_session_id: result.personaSession.sessionId, authority_version: result.personaSession.authorityVersion,
      persona_role: 'admin', version: result.snapshot.policyVersion,
      payload_json: result.snapshot, digest: canonicalDigest(result.snapshot) }));
    await assert.rejects(f.repository.readAssessmentSnapshot(f.input()), { code: 'POLICY_INTEGRITY_UNAVAILABLE' });
  }
});

test('V24 assessment snapshot fails closed without one immutable matching publication revision', async () => {
  const f = fixture();
  f.setRevisions([]);
  await assert.rejects(f.repository.readAssessmentSnapshot(f.input()), { code: 'POLICY_INTEGRITY_UNAVAILABLE' });
  f.setRevisions([{ operation_id: randomUUID(), name: 'different', action: 'upsert', payload_json: {}, digest: canonicalDigest({}) }]);
  await assert.rejects(f.repository.readAssessmentSnapshot(f.input()), { code: 'POLICY_INTEGRITY_UNAVAILABLE' });
});

test('V24 assessment snapshot rejects a revoked owner before exposing stored policy text', async () => {
  const f = fixture();
  f.revoke();
  await assert.rejects(f.repository.readAssessmentSnapshot(f.input()), { code: 'SHOP_AUTH_INVALID' });
});
