'use strict';

const { FAMILIES, mapPlatformSolutions } = require('./map-platform-solutions');
const { FAMILY_CONFIG, mapAdditionalPlatformSolutions } = require('./map-platform-additional-solutions');

function reject(code, location) {
  const error = new Error(code); error.code = code; error.location = location; throw error;
}

// Inputs are the lossless tagged values returned by readVerifiedLegacyArchive.
// Only numeric schema fields are converted; raw JSON text is never decoded here.
function decode(value, column, location) {
  if (value === null || typeof value === 'string') return value;
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'type,value' || value.type !== 'integer'
      || typeof value.value !== 'string' || !/^-?(0|[1-9][0-9]*)$/.test(value.value)) {
    reject('UNSUPPORTED_SOLUTION_ARCHIVE_VALUE', location);
  }
  if (column === 'enabled_by') return value.value;
  if (!['id', 'solutions_enabled'].includes(column)) reject('UNEXPECTED_SOLUTION_INTEGER', location);
  const number = Number(value.value);
  if (!Number.isSafeInteger(number) || BigInt(number) !== BigInt(value.value)) reject('UNSAFE_SOLUTION_INTEGER', location);
  return number;
}

/** Project verified sources into both native solution contracts without opening storage. */
function mapSolutionArchive({ sources, archiveDigest, identityMap = {}, naiveTimestamps = 'reject', resolutions = {} }) {
  if (!sources || typeof sources !== 'object' || Array.isArray(sources)) reject('INVALID_ARCHIVE_SOURCES');
  const coverage = [];
  const project = (source, names) => {
    if (!Object.hasOwn(sources, source)) return null;
    const tables = sources[source]?.tables;
    if (!tables || typeof tables !== 'object' || Array.isArray(tables)) reject('INVALID_ARCHIVE_SOURCE', source);
    const projected = Object.create(null);
    for (const name of names) {
      if (!Object.hasOwn(tables, name)) continue;
      if (!Array.isArray(tables[name])) reject('INVALID_ARCHIVE_TABLE', `${source}.${name}`);
      projected[name] = tables[name].map((row, index) => {
        if (!row || typeof row !== 'object' || Array.isArray(row)) reject('INVALID_ARCHIVE_ROW', `${source}.${name}[${index}]`);
        return Object.fromEntries(Object.entries(row).map(([column, value]) => [column, decode(value, column, `${source}.${name}[${index}].${column}`)]));
      });
      coverage.push({ source, table: name, rows: tables[name].length });
    }
    return { tables: projected };
  };
  const solutionSources = {}, additionalSources = {};
  const common = project('users_auth.db', Object.values(FAMILIES).flatMap(row => [row.contentTable, row.visibilityTable]));
  if (common) solutionSources['users_auth.db'] = common;
  const nova = FAMILIES.nosql_injection_workshop;
  const local = project('nosql_workshop.db', [nova.contentTable, nova.visibilityTable]);
  if (local) solutionSources['nosql_workshop.db'] = local;
  const additional = project('users_auth.db', ['xss_workshop_objective_solutions', 'csrf_workshop_objective_solutions',
    'xss_workshop_solutions', 'xss_workshop_solution_visibility', 'csrf_workshop_solutions', 'csrf_workshop_solution_visibility']);
  if (additional) additionalSources['users_auth.db'] = additional;
  for (const config of Object.values(FAMILY_CONFIG)) {
    const value = project(config.source, [config.contentTable, config.visibilityTable]);
    if (value) additionalSources[config.source] = value;
  }
  const solutions = { sources: solutionSources, archiveDigest, resolutions };
  const additionalSolutions = { sources: additionalSources, archiveDigest, identityMap, naiveTimestamps };
  const mapped = mapPlatformSolutions(solutions), extra = mapAdditionalPlatformSolutions(additionalSolutions);
  return {
    solutions, additionalSolutions,
    report: { archiveDigest, coverage, requiresReview: mapped.report.requiresReview || extra.report.requiresReview,
      canonical: mapped.report, additional: extra.report,
      scope: 'Solution table projection only; other archive tables require separate coverage.' },
  };
}

module.exports = { mapSolutionArchive };
