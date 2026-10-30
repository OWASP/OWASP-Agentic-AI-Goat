'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');
const generator = require('../scripts/generate-finflow-admin-enum-copy-defaults');

const root = path.resolve(__dirname, '..');
const registered = path.join(root, 'db/postgres/identity-migrations/0068_finflow_admin_enum_copy_defaults.sql');

test('identity0068 preserves its qualified names-only predecessor without registration', () => {
  const predecessor = fs.readFileSync(generator.namesOnlyPredecessorPath, 'utf8');
  const record = JSON.parse(fs.readFileSync(generator.namesOnlyPredecessorRecordPath, 'utf8'));

  assert.equal(createHash('sha256').update(predecessor).digest('hex'),
    generator.namesOnlyPredecessorSha256);
  assert.equal(record.status, 'superseded_unregistered_draft');
  assert.equal(record.originalSha256, generator.namesOnlyPredecessorSha256);
  assert.equal(record.registration.checkedPath,
    'db/postgres/identity-migrations/0068_finflow_admin_enum_copy_defaults.sql');
  assert.equal(record.registration.presentAtPreservation, false);
  assert.equal(record.nativeQualification.reviewRecord,
    'tasks/finflow-0068-r3-native-root-review.json');
  assert.equal(createHash('sha256').update(fs.readFileSync(path.join(root,
    'tests/release-inputs', path.basename(record.nativeQualification.reviewRecord)))).digest('hex'),
  record.nativeQualification.reviewRecordSha256);
  assert.equal(record.nativeQualification.evidence,
    '/Users/averma5/.owasp-ai-goat/native-verification/owasp-ai-goat-finflow_0068_admin_enum_copy_defaults-b031b78466ee');
  assert.equal(record.nativeQualification.status, 'terminal_pass_cleaned');
  assert.equal(fs.existsSync(registered), false);
});

test('identity0068 draft is canonical, unregistered and bound to exact predecessor documents', () => {
  const sql = fs.readFileSync(generator.outputPath, 'utf8');
  const rows = generator.buildRows();

  assert.equal(sql, generator.buildSql());
  assert.equal(fs.existsSync(registered), false);
  assert.match(fs.readFileSync(generator.seedSourcePath, 'utf8'),
    new RegExp(`const CATALOG_VERSION='${generator.sourceVersion}'`));
  assert.equal(generator.sourceVersion, 'workshop-defaults-2026-09-15-v4-secureshop-coherence',
    'the seed may retain its version because document hashes drive reconciliation');
  assert.equal(rows.length, 5);
  assert.deepEqual(rows.map(row => `${row.objectiveId}:${row.fieldName}:${row.oldLineage}`), [
    'admin_enum:hint_content:identity0041',
    'admin_enum:hint_content:reserved-identity0067',
    'admin_enum:solution_content:identity0041',
    'admin_enum:solution_content:reserved-identity0067',
    'tool_version:solution_content:canonical-before-0068',
  ]);
  for (const row of rows) {
    assert.equal(row.oldHash, provenance.hashDocument(row.oldDocument));
    assert.equal(row.newHash, provenance.hashDocument(row.newDocument));
    assert.notEqual(row.oldHash, row.newHash);
    assert.equal(sql.split(row.oldHash).length - 1, 1);
  }
  assert.deepEqual([...new Set(rows.map(row => row.newHash))].sort(), [
    '6c8529601941c45c245437c5563c65b32b745867e0d604f70f3bcc63e1d6ce67',
    '5ad8aa296bc4cdd398f86e24774053cb37dd2dc9377118418f252863a5e9da1a',
    '62a29f5b2d52639ea5942fe970370b9bdb5e5f04a25706bb9f4443c2142addb1',
  ].sort());
});

test('identity0068 SQL admits only exact managed or recognized legacy defaults', () => {
  const sql = generator.buildSql();

  assert.match(sql, /p\.provenance_state='managed' AND p\.applied_default_hash=d\.old_hash/);
  assert.match(sql, /p\.applied_default_document=d\.old_document/);
  assert.match(sql, /p\.provenance_state='legacy_unknown' AND p\.observed_document=d\.old_document/);
  assert.match(sql, /jsonb_build_object\('present',true,'value',o\.(?:hint_content|solution_content)\)/);
  assert.doesNotMatch(sql, /provenance_state='custom'/);
  assert.equal((sql.match(/UPDATE workshop_platform\.config_revision/g) || []).length, 1);
  assert.match(sql, /EXISTS\(SELECT 1 FROM synced\)/);
  assert.doesNotMatch(sql, /is_enabled|ordinal|updated_by|workshop_platform\.(?:completions|user_state)/);
});

test('identity0068 eligibility preserves missing, custom, NULL and drifted fields', () => {
  for (const row of generator.buildRows()) {
    const managed = { provenance_state: 'managed', applied_default_hash: row.oldHash,
      applied_default_document: row.oldDocument, observed_document: row.oldDocument };
    const legacy = { provenance_state: 'legacy_unknown', observed_document: row.oldDocument };
    const driftedDocument = provenance.document({ instructor: 'custom copy' });

    assert.equal(generator.isEligible({ row, provenanceRow: managed,
      currentDocument: row.oldDocument }), true);
    assert.equal(generator.isEligible({ row, provenanceRow: legacy,
      currentDocument: row.oldDocument }), true);
    assert.equal(generator.isEligible({ row, provenanceRow: null,
      currentDocument: row.oldDocument }), false, 'missing provenance is preserved');
    assert.equal(generator.isEligible({ row, provenanceRow: { ...managed, provenance_state: 'custom' },
      currentDocument: row.oldDocument }), false, 'custom provenance is preserved');
    assert.equal(generator.isEligible({ row, provenanceRow: managed,
      currentDocument: provenance.document(null) }), false, 'NULL is preserved');
    assert.equal(generator.isEligible({ row, provenanceRow: managed,
      currentDocument: driftedDocument }), false, 'live drift is preserved');
    assert.equal(generator.isEligible({ row, provenanceRow: { ...managed,
      applied_default_hash: provenance.hashDocument(driftedDocument) },
      currentDocument: row.oldDocument }), false, 'managed applied-hash drift is preserved');
    assert.equal(generator.isEligible({ row, provenanceRow: { ...legacy,
      observed_document: driftedDocument }, currentDocument: row.oldDocument }), false,
    'unrecognized legacy provenance is preserved');
  }
});

test('same seed version still reconciles changed canonical hashes', () => {
  for (const row of generator.buildRows()) {
    const prior = {
      provenance_state: 'managed', source_version: generator.sourceVersion,
      applied_default_hash: row.oldHash, applied_default_document: row.oldDocument,
    };
    assert.equal(provenance.decideReconciliation({
      provenance: prior, currentDocument: row.oldDocument, sourceDocument: row.newDocument,
    }).action, 'upgrade');
    assert.equal(provenance.decideReconciliation({
      provenance: { ...prior, applied_default_hash: row.newHash,
        applied_default_document: row.newDocument },
      currentDocument: row.newDocument, sourceDocument: row.newDocument,
    }).action, 'record');
  }
});
