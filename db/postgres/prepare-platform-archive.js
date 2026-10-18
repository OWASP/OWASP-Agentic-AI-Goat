'use strict';

const { readVerifiedLegacyArchive, projectPlatformArchive } = require('./read-platform-archive');
const { COLUMNS: PLATFORM_TABLES } = require('./map-platform-snapshot');
const { COLUMNS: IDENTITY_TABLES, mapIdentityArchive } = require('./map-identity-archive');
const { COLUMNS: AUXILIARY_TABLES, mapIdentityAuxiliary } = require('./map-identity-auxiliary');
const { mapSolutionArchive } = require('./map-solution-archive');
const { reviewIdentityArchive } = require('./review-identity-archive');

/**
 * Read the archive once, then derive every platform projection from those bytes.
 * `inputs` contains credentials and instructor content and is private importer data.
 * Only `report` is suitable for an operator summary. This function never writes a DB.
 */
async function preparePlatformArchive({ archive, identityMap, naiveTimestamps = 'reject', resolutions = {}, identityReview }) {
  const verified = await readVerifiedLegacyArchive({ archive });
  const platform = projectPlatformArchive({ ...verified, identityMap, naiveTimestamps });
  const identityInput = { tables: verified.sources['users_auth.db'].tables,
    archiveDigest: verified.archiveDigest, naiveTimestamps };
  const identity = identityReview === undefined ? mapIdentityArchive(identityInput)
    : reviewIdentityArchive({ ...identityInput, review: identityReview });
  const solutions = mapSolutionArchive({ ...verified, identityMap, naiveTimestamps, resolutions });
  const owners = new Set(identity.identity.users.map(row => row.id));
  for (const target of Object.values(identityMap)) {
    if (!owners.has(target)) {
      const error = new Error('ARCHIVE_IDENTITY_MAPPING_TARGET_MISSING'); error.code = error.message; throw error;
    }
  }
  const sourceTables = verified.sources['users_auth.db'].tables;
  const auxiliaryNames = Object.keys(AUXILIARY_TABLES);
  const auxiliaryPresent = auxiliaryNames.filter(table => Object.hasOwn(sourceTables, table));
  if (auxiliaryPresent.length > 0 && auxiliaryPresent.length !== auxiliaryNames.length) {
    const error = new Error('INCOMPLETE_AUXILIARY_ARCHIVE_SCOPE'); error.code = error.message; throw error;
  }
  const identityAuxiliary = auxiliaryPresent.length ? {
    tables: Object.fromEntries(auxiliaryNames.map(table => [table, sourceTables[table]])),
    archiveDigest: verified.archiveDigest, identityUserIds: [...owners], naiveTimestamps,
  } : null;
  const auxiliary = identityAuxiliary ? mapIdentityAuxiliary(identityAuxiliary) : null;
  const covered = new Set([
    ...Object.keys(PLATFORM_TABLES).map(table => `users_auth.db:${table}`),
    ...Object.keys(IDENTITY_TABLES).map(table => `users_auth.db:${table}`),
    ...(auxiliary ? auxiliaryNames.map(table => `users_auth.db:${table}`) : []),
    ...solutions.report.coverage.map(row => `${row.source}:${row.table}`),
  ]);
  // Retired CSRF is reported by the solution mapper but never imported.
  for (const table of ['csrf_workshop_solutions', 'csrf_workshop_solution_visibility']) covered.delete(`users_auth.db:${table}`);
  const coverage = [];
  for (const [source, envelope] of Object.entries(verified.sources)) for (const [table, rows] of Object.entries(envelope.tables)) {
    coverage.push({ source, table, rows: rows.length, disposition: covered.has(`${source}:${table}`) ? 'mapped' : 'unmapped' });
  }
  return {
    inputs: {
      identity: identity.identity,
      identitySource: identityInput,
      ...(identityAuxiliary ? { identityAuxiliary } : {}),
      platform: { tables: platform.tables, identityMap, naiveTimestamps, archiveDigest: verified.archiveDigest },
      solutions: solutions.solutions, additionalSolutions: solutions.additionalSolutions,
    },
    report: {
      archiveDigest: verified.archiveDigest, coverage,
      unmappedPopulatedTables: coverage.filter(row => row.disposition === 'unmapped' && row.rows > 0),
      identity: identity.report, identityAuxiliary: auxiliary?.report || { missingSourceTables: auxiliaryNames, readyToApply: false }, platform: platform.report, solutions: solutions.report,
      requiresReview: true, readyToApply: false,
      reason: 'Explicit default, normalization and retained-source decisions are required before constructing an apply input.',
    },
  };
}

module.exports = { preparePlatformArchive };
