'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { createCtfAuthorityRepository } = require('../server/database/postgres/ctfAuthorityRepository');
const run = '00000000-0000-0000-0000-000000000001';
function fixture(identityRows = [], ctfRows = []) {
  const queries = [];
  const pool = rows => ({ query: async (sql, args) => { assert.match(sql.trim(), /^SELECT\b/); queries.push({ sql, args }); return { rows }; } });
  return { repo: createCtfAuthorityRepository(pool(identityRows), pool(ctfRows)), queries };
}
test('scope is unavailable when uninitialized or missing; transport counters do not coerce bigint', async () => {
  const row = { scope_key: 'global', lifecycle_state: 'uninitialized', next_sequence: '9007199254740993' };
  const { repo } = fixture([row]); assert.equal((await repo.readScopeSnapshot(['global'])).available, false);
  row.lifecycle_state = 'ready'; assert.equal((await repo.readScopeSnapshot(['global'])).rows[0].next_sequence, '9007199254740993');
  assert.equal((await repo.readScopeSnapshot(['global', 'owner:1'])).available, false);
  await assert.rejects(repo.readScopeSnapshot(['owner:9223372036854775808']), TypeError);
});
test('adaptive overflow is unavailable with no truncated rows or no-match claim', async () => {
  const input = { stageId: 1, stageRevision: '0', clearRevision: '0', limit: 1 };
  assert.deepEqual(await fixture([{}, {}]).repo.readAdaptiveSnapshot(input), { available: false, complete: false, reason: 'adaptive_snapshot_limit', rows: null });
  assert.equal((await fixture([{ normalized_payload: 'abcdef' }]).repo.readAdaptiveSnapshot({ ...input, maxBytes: 1 })).complete, false);
  assert.deepEqual((await fixture().repo.readAdaptiveSnapshot(input)).rows, []);
  await assert.rejects(fixture().repo.readAdaptiveSnapshot({ ...input, stageId: Number.MAX_SAFE_INTEGER + 1 }), TypeError);
});
test('legacy, missing authority, pending and mismatched projections never become authorization', async () => {
  assert.equal((await fixture([], [{ accepted: 1 }]).repo.compareLegacyProjection(run)).classification, 'legacy');
  const linked = { decision_id: run, authority_version: 'identity-ctf-v1', accepted: 1, participant_id: '1', progress_id: '2', stage_id: '3', stage_digest: 'a' };
  assert.equal((await fixture([], [linked]).repo.compareLegacyProjection(run)).classification, 'missing_authority');
  assert.equal((await fixture([linked]).repo.compareLegacyProjection(run)).classification, 'pending_projection');
  assert.equal((await fixture([linked], [linked]).repo.compareLegacyProjection(run)).classification, 'linked_comparison_match');
  assert.equal((await fixture([{ ...linked, progress_id: '9' }], [linked]).repo.compareLegacyProjection(run)).classification, 'mismatch');
});
test('surface contains only reads/comparison and closed projection state', async () => {
  const { repo } = fixture([], [{ initialized: false, applied_sequence: '0' }]);
  assert.deepEqual(Object.keys(repo).sort(), ['compareLegacyProjection','readAdaptiveSnapshot','readAppliedProjectionStatus','readDecisionByRun','readScopeSnapshot'].sort());
  assert.equal((await repo.readAppliedProjectionStatus()).available, false);
  await assert.rejects(repo.readDecisionByRun('bad'), TypeError);
});
