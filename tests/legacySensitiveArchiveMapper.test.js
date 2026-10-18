'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mapLegacySensitiveArchive } = require('../db/postgres/map-legacy-sensitive-archive');
const { fixture } = require('./fixtures/legacySensitiveArchive');

test('maps document/access history with exact IDs, owner mapping, and asset references', () => {
  const result = mapLegacySensitiveArchive(fixture());
  assert.deepEqual(result.snapshot.documents, [{
    id: 101, filename: 'legacy-guide.txt', filePath: '/archive/legacy-guide.txt', category: 'user',
    accessLevel: 'user', description: 'Exact archived document', uploadedBy: 71, createdAt: '2025-01-02T03:04:05.000Z',
  }]);
  assert.deepEqual(result.snapshot.accessLogs, [{
    id: 701, userId: 71, filePath: '/archive/legacy-guide.txt', accessType: 'read', status: 'success',
    ipAddress: '198.51.100.10', userAgent: 'fixture-agent', timestamp: '2025-01-03T04:05:06.000Z',
  }]);
  assert.equal(result.report.canonicalProgressImported, false);
  assert.equal(result.report.assetReferences[0].imported, false);
  assert.deepEqual(result.report.retainedTables.map(row => row.table), ['challenge_progress', 'ssi_templates']);
});

test('retains historical progress outside judgments and requires every archive-bound disposition', () => {
  const raw = fixture();
  const result = mapLegacySensitiveArchive(raw);
  assert.equal(result.snapshot.provenance.filter(row => row.sourceTable === 'challenge_progress').length, 0);
  assert.equal(result.report.semanticDispositions.find(row => row.scope === 'challenge_progress').policy, 'retain_archive_only_no_judge_receipts');
  raw.review.decisions = raw.review.decisions.filter(row => row.scope !== 'historical_sessions');
  assert.throws(() => mapLegacySensitiveArchive(raw), { code: 'INCOMPLETE_OR_STALE_SENSITIVE_SEMANTICS' });
});

test('rejects unmapped owners and stale retained-table decisions', () => {
  const raw = fixture();
  raw.tables.file_access_logs[0].user_id = 99;
  assert.throws(() => mapLegacySensitiveArchive(raw), { code: 'UNMAPPED_SENSITIVE_IDENTITY' });
  const other = fixture();
  other.review.retainedTables[0].rows = 99;
  assert.throws(() => mapLegacySensitiveArchive(other), { code: 'INCOMPLETE_OR_STALE_SENSITIVE_REVIEW' });
});

test('rejects ambiguous timestamps unless UTC policy is explicit', () => {
  const raw = fixture();
  raw.naiveTimestamps = 'reject';
  assert.throws(() => mapLegacySensitiveArchive(raw), { code: 'AMBIGUOUS_SENSITIVE_TIMESTAMP' });
});

test('explicit orphan dispositions preserve source provenance without attaching another account', () => {
  const raw = fixture();
  raw.identityMap = { 7: null };
  const result = mapLegacySensitiveArchive(raw);
  assert.equal(result.snapshot.documents[0].uploadedBy, null);
  assert.equal(result.snapshot.accessLogs[0].userId, null);
  assert.equal(result.snapshot.provenance[0].row.uploaded_by, 7);
});

test('legacy sensitive import requires an exact branded platform owner proof before pool checkout', async () => {
  const { importLegacySensitiveArchive } = require('../db/postgres/import-legacy-sensitive-archive');
  const { fixtureOwnerProof } = require('./fixtures/archiveOwnerBinding');
  const raw = fixture();
  raw.ownerBinding = { archiveDigest: raw.archiveDigest, identityMap: { 7: 71 } };
  let connected = false;
  const pool = { connect: async () => { connected = true; throw new Error('must not connect'); } };
  await assert.rejects(importLegacySensitiveArchive(pool, raw), { code: 'OWNER_PROOF_REQUIRED' });
  const otherBinding = { archiveDigest: raw.archiveDigest, identityMap: { 7: 72 } };
  const otherProof = await fixtureOwnerProof(otherBinding);
  await assert.rejects(importLegacySensitiveArchive(pool, raw, { ownerProof: otherProof }), {
    code: 'VERIFIED_ARCHIVE_OWNER_BINDING_REQUIRED',
  });
  const orphan = fixture();
  orphan.identityMap = { 7: null };
  orphan.ownerBinding = raw.ownerBinding;
  const proof = await fixtureOwnerProof(raw.ownerBinding);
  await assert.rejects(importLegacySensitiveArchive(pool, orphan, { ownerProof: proof }), {
    code: 'SENSITIVE_ORPHAN_HAS_PLATFORM_OWNER',
  });
  assert.equal(connected, false);
});
