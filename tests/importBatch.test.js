'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { buildImportBatch } = require('../db/postgres/import-batch');
const { COLUMNS } = require('../db/postgres/map-platform-snapshot');
const { fixture, legacyXssContent, legacyXssVisibility } = require('./fixtures/platformAdditionalSolutions');

function input() {
  const archiveDigest = 'a'.repeat(64);
  return {
    identity: {},
    platform: {
      tables: Object.fromEntries(Object.keys(COLUMNS).map(key => [key, []])),
      identityMap: {}, archiveDigest,
      review: {
        archiveDigest, retainedTables: [],
        missingDefaults: Object.fromEntries(['exercises', 'objectiveVisibility', 'hintVisibility']
          .map(key => [key, 'catalog_visibility_defaults_without_content'])),
      },
    },
  };
}

test('batch digest is stable across object key ordering and binds imported content and policy', () => {
  const source = input();
  const original = buildImportBatch(source);
  const reordered = { platform: { ...source.platform, tables: Object.fromEntries(Object.entries(source.platform.tables).reverse()) }, identity: {} };
  assert.equal(buildImportBatch(reordered).planSha256, original.planSha256);
  source.platform.naiveTimestamps = 'UTC';
  assert.notEqual(buildImportBatch(source).planSha256, original.planSha256);
  assert.equal(buildImportBatch(source).reviewDecisions.timestamp_policy, 'naive_utc');
  source.platform.tables.workshop_hints.push({ id: 1, workshop_key: 'sql_injection_workshop', objective_id: 'sqli_1', title: 'Private instructor text', hints: '["private payload"]' });
  const withHint = buildImportBatch(source);
  assert.notEqual(withHint.planSha256, original.planSha256);
  assert.equal(withHint.counts.platform_hints, 1);
  assert.ok(!JSON.stringify(withHint).includes('private payload'));
  assert.ok(!JSON.stringify(withHint).includes('Private instructor text'));
});

test('retained source names and rows are represented only by digest and counts', () => {
  const source = input();
  source.platform.tables['private-alice@example.test'] = [{ secret: 'private credential' }];
  source.platform.review.retainedTables = ['private-alice@example.test'];
  const batch = buildImportBatch(source);
  assert.ok(!JSON.stringify(batch).includes('alice'));
  assert.ok(!JSON.stringify(batch).includes('credential'));
  const key = Object.keys(batch.coverage).find(key => key.startsWith('retained_table:'));
  assert.equal(batch.coverage[key], 1);
  assert.equal(batch.reviewDecisions[key], 'retained_archive_only');
  source.platform.tables['private-alice@example.test'].push({ secret: 'another value' });
  assert.notEqual(buildImportBatch(source).planSha256, batch.planSha256);
});

test('batch preparation refuses unreviewed or stale archive decisions', () => {
  const source = input();
  source.platform.review.archiveDigest = 'b'.repeat(64);
  assert.throws(() => buildImportBatch(source), { code: 'ARCHIVE_BOUND_REVIEW_REQUIRED' });
  source.platform.review.archiveDigest = source.platform.archiveDigest;
  source.platform.tables.unknown_table = [];
  assert.throws(() => buildImportBatch(source), { code: 'UNMAPPED_TABLE_RESOLUTION_REQUIRED' });
});

test('additional canonical and legacy solutions bind the batch without storing instructor content', () => {
  const source = input();
  source.additionalSolutions = fixture();
  Object.assign(source.additionalSolutions, {
    archiveDigest: source.platform.archiveDigest, naiveTimestamps: 'UTC', identityMap: { 42: 71 },
  });
  const tables = source.additionalSolutions.sources['users_auth.db'].tables;
  tables.xss_workshop_solutions = [legacyXssContent()];
  tables.xss_workshop_solution_visibility = [legacyXssVisibility()];
  const batch = buildImportBatch(source);
  assert.equal(batch.counts.additional_solutions, 48);
  assert.equal(batch.coverage['legacySolutions:xss_workshop:reflected'], 1);
  assert.equal(batch.reviewDecisions['legacySolutionVisibility:xss_workshop:reflected'], 'imported');
  assert.equal(batch.reviewDecisions.additional_timestamp_policy, 'naive_utc');
  for (const privateValue of ['Legacy tab content', 'legacy payload', 'Legacy approach']) {
    assert.equal(JSON.stringify(batch).includes(privateValue), false);
  }
  tables.xss_workshop_solutions[0].hints = 'Instructor-edited raw string';
  assert.notEqual(buildImportBatch(source).planSha256, batch.planSha256);
  source.additionalSolutions.archiveDigest = 'f'.repeat(64);
  assert.throws(() => buildImportBatch(source), /platform archive/);
});

test('auxiliary metadata binds exact identity set and private content without exposing either',()=>{
 const source=input();
 source.identity={users:[{id:71,username:'fixture',email:'fixture@example.test',password:require('bcryptjs').hashSync('synthetic',4),created_at:'2026-01-01T00:00:00Z'}]};
 source.identityAuxiliary=require('./fixtures/identityAuxiliaryImport').fixture(source.platform.archiveDigest);
 const batch=buildImportBatch(source);
 assert.equal(batch.counts.identity_auxiliary_email_verification_tokens,1);
 for(const value of ['private-verification-fixture','private-email@example.test','private subject','private configuration'])assert.equal(JSON.stringify(batch).includes(value),false);
 source.identityAuxiliary.tables.system_config[0].config_value='true';assert.notEqual(buildImportBatch(source).planSha256,batch.planSha256);
 source.identityAuxiliary.identityUserIds=[71,72];assert.throws(()=>buildImportBatch(source),/exactly match/);
 source.identityAuxiliary.identityUserIds=[71];source.identityAuxiliary.archiveDigest='f'.repeat(64);assert.throws(()=>buildImportBatch(source),/match the platform archive/);
});
