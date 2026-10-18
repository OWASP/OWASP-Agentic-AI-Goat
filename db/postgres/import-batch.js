'use strict';

const { reviewIdentityArchive } = require('./review-identity-archive');
const { createHash } = require('node:crypto');
const { validateIdentityImport } = require('../../server/database/postgres/identityImport');
const { preparePlatformImport } = require('./import-platform-snapshot');
const { mapPlatformSolutions } = require('./map-platform-solutions');
const { mapAdditionalPlatformSolutions } = require('./map-platform-additional-solutions');
const { COLUMNS: AUXILIARY_COLUMNS, mapIdentityAuxiliary } = require('./map-identity-auxiliary');
const { COLUMNS } = require('./map-platform-snapshot');

const IMPORTER_VERSION = 'platform-identity-v4';
const digest = value => createHash('sha256').update(value).digest('hex');
function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  throw new Error('Import plan must contain canonical JSON values');
}

/** Store only counts/policy identifiers; content and credentials enter only the digest. */
function buildImportBatch({ identity: identityInput, platform: platformInput, solutions: solutionInput, additionalSolutions: additionalInput, identityAuxiliary: auxiliaryInput, archiveReview }) {
  const identity = validateIdentityImport(identityInput);
  const platform = preparePlatformImport(platformInput);
  let auxiliary = null;
  if (auxiliaryInput) {
    if (auxiliaryInput.archiveDigest !== platform.archiveDigest) throw new Error('Auxiliary identity must match the platform archive');
    if (Object.keys(auxiliaryInput.tables || {}).sort().join(',') !== Object.keys(AUXILIARY_COLUMNS).sort().join(',')) throw new Error('Auxiliary identity requires exactly four source tables');
    auxiliary = mapIdentityAuxiliary(auxiliaryInput);
    if (!auxiliary.report.readyToApply) throw new Error('Auxiliary identity requires explicit resolved review');
    const expectedIds = identity.users.map(row => row.id).sort((a,b)=>a-b);
    if (JSON.stringify([...auxiliaryInput.identityUserIds].sort((a,b)=>a-b)) !== JSON.stringify(expectedIds)) throw new Error('Auxiliary identity references must exactly match imported users');
  }
  const solutions = solutionInput ? mapPlatformSolutions(solutionInput) : null;
  if (solutionInput && (solutionInput.archiveDigest !== platform.archiveDigest || solutions.report.requiresReview)) {
    throw new Error('Solutions require resolved decisions bound to the platform archive');
  }
  const additional = additionalInput ? mapAdditionalPlatformSolutions(additionalInput) : null;
  if (additionalInput && (additionalInput.archiveDigest !== platform.archiveDigest || additional.report.requiresReview)) {
    throw new Error('Additional solutions require resolved decisions bound to the platform archive');
  }
  if (archiveReview) {
    if (Object.keys(archiveReview).sort().join(',') !== 'identityReview,identitySource,retainedPlatformTables,reviewSha256') throw new Error('Invalid archive review envelope');
    const {reviewSha256, ...reviewPayload} = archiveReview;
    if (reviewSha256 !== digest(JSON.stringify(canonical(reviewPayload)))) throw new Error('Archive review digest mismatch');
    if (archiveReview.identitySource.archiveDigest !== platform.archiveDigest) throw new Error('Archive identity review digest mismatch');
    const reviewed = reviewIdentityArchive({...archiveReview.identitySource,review:archiveReview.identityReview});
    if (JSON.stringify(canonical(reviewed.identity)) !== JSON.stringify(canonical(identityInput))) throw new Error('Archive identity review does not match importer input');
    if (!Array.isArray(archiveReview.retainedPlatformTables)) throw new Error('Invalid archive retained review');
    const retained = archiveReview.retainedPlatformTables.map(row=>{
      if (!row || Object.keys(row).sort().join(',') !== 'policy,table' || row.policy !== 'retain_archive_only' || typeof row.table !== 'string') throw new Error('Invalid archive retained decision');
      return row.table;
    }).sort();
    if (JSON.stringify(retained) !== JSON.stringify([...platform.review.retainedTables].sort())) throw new Error('Archive retained decisions do not match platform input');
  }
  const counts = {}, coverage = {}, reviewDecisions = {
    scope: 'explicit_collections_only',
    timestamp_policy: platform.report.naiveTimestamps === 'UTC' ? 'naive_utc' : 'reject_naive',
  };
  for (const key of ['users', 'permissions', 'sessions', 'audit']) {
    counts[`identity_${key}`] = identity[key].length;
    coverage[`identity:${key}`] = identity[key].length;
    reviewDecisions[`identity:${key}`] = 'imported';
  }
  for (const [key, count] of Object.entries(platform.report.counts)) counts[`platform_${key}`] = count;
  for (const table of Object.keys(COLUMNS)) {
    coverage[`platform:${table}`] = platformInput.tables[table].length;
    reviewDecisions[`platform:${table}`] = 'imported';
  }
  for (const [key, decision] of Object.entries(platform.review.missingDefaults)) reviewDecisions[`default:${key}`] = decision;
  for (const table of new Set(platform.report.retainedRows.map(row => row.table))) {
    const key = `retained_rows:${table}`;
    coverage[key] = platform.report.retainedRows.filter(row => row.table === table).length;
    reviewDecisions[key] = 'retained_archive_only';
  }
  for (const table of platform.review.retainedTables) {
    // Unknown table names can themselves contain personal information. The archive
    // and its digest preserve the name; the database stores only its stable hash.
    const key = `retained_table:${digest(table)}`;
    coverage[key] = platformInput.tables[table].length;
    reviewDecisions[key] = 'retained_archive_only';
  }
  if (solutions) {
    for (const [key, count] of Object.entries(solutions.report.counts)) counts[`solutions_${key}`] = count;
    for (const [key, decision] of Object.entries(solutionInput.resolutions || {})) reviewDecisions[`solution:${key}`] = decision.source;
    for (const [key, rows] of Object.entries(solutions.snapshot)) {
      if (!Array.isArray(rows)) continue;
      for (const row of rows) {
        coverage[`${key}:${row.workshopKey}:${row.objectiveId}`] = 1;
        reviewDecisions[`${key}:${row.workshopKey}:${row.objectiveId}`] = 'imported';
      }
    }
  }
  if (additional) {
    for (const [key, count] of Object.entries(additional.report.counts)) counts[`additional_${key}`] = count;
    for (const key of ['solutions', 'solutionVisibility']) {
      for (const row of additional.snapshot[key]) {
        coverage[`${key}:${row.workshopKey}:${row.objectiveId}`] = 1;
        reviewDecisions[`${key}:${row.workshopKey}:${row.objectiveId}`] = 'imported';
      }
    }
    for (const key of ['legacySolutions', 'legacySolutionVisibility']) {
      for (const row of additional.snapshot[key] || []) {
        coverage[`${key}:xss_workshop:${row.challengeId}`] = 1;
        reviewDecisions[`${key}:xss_workshop:${row.challengeId}`] = 'imported';
      }
    }
    reviewDecisions.additional_timestamp_policy = additionalInput.naiveTimestamps === 'UTC' ? 'naive_utc' : 'reject_naive';
  }
  if (auxiliary) {
    for (const [table, count] of Object.entries(auxiliary.report.counts)) {
      counts[`identity_auxiliary_${table}`] = count;
      coverage[`identity_auxiliary:${table}`] = count;
      reviewDecisions[`identity_auxiliary:${table}`] = 'imported';
    }
    for (const record of auxiliary.report.transformations) {
      const key = `auxiliary_transform:${record.table}:${record.field}:${record.policy}`;
      counts[key] = (counts[key] || 0) + 1;
      reviewDecisions[key] = 'imported';
    }
    reviewDecisions.identity_auxiliary_timestamp_policy = auxiliaryInput.naiveTimestamps === 'UTC' ? 'naive_utc' : 'reject_naive';
  }
  if (archiveReview) {
    for (const row of archiveReview.identityReview.normalizations) {
      const key = `identity_normalization:${row.collection}:${row.field}:${row.reason}`;
      counts[key] = (counts[key] || 0) + 1;
      reviewDecisions[key] = 'explicitly_excluded';
    }
  }
  const plan = {
    version: IMPORTER_VERSION, archiveDigest: platform.archiveDigest,
    identity, platform: { snapshot: platform.snapshot, review: platform.review, identityMap: platformInput.identityMap, timestampPolicy: platform.report.naiveTimestamps },
    solutions: solutions ? { snapshot: solutions.snapshot, resolutions: solutionInput.resolutions || {} } : null,
    additionalSolutions: additional ? {
      snapshot: additional.snapshot, identityMap: additionalInput.identityMap || {},
      timestampPolicy: additionalInput.naiveTimestamps || 'reject',
    } : null,
    identityAuxiliary: auxiliary ? { snapshot: auxiliary.auxiliary, source: auxiliaryInput, transformations: auxiliary.report.transformations } : null,
    archiveReview: archiveReview || null,
    metadata: { counts, coverage, reviewDecisions },
  };
  return {
    archiveSha256: platform.archiveDigest, importerVersion: IMPORTER_VERSION,
    planSha256: digest(JSON.stringify(canonical(plan))), counts, coverage, reviewDecisions,
  };
}

async function recordImportBatch(client, batch) {
  await client.query('SAVEPOINT import_batch_guard');
  await client.query(`INSERT INTO identity.import_batches
    (archive_sha256,importer_version,plan_sha256,counts,coverage,review_decisions)
    VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb)`, [
    batch.archiveSha256, batch.importerVersion, batch.planSha256,
    JSON.stringify(batch.counts), JSON.stringify(batch.coverage), JSON.stringify(batch.reviewDecisions),
  ]);
  await client.query('RELEASE SAVEPOINT import_batch_guard');
}

module.exports = { IMPORTER_VERSION, buildImportBatch, recordImportBatch, canonical };
