'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { FAMILIES } = require('../db/postgres/map-platform-solutions');
const { mapSolutionArchive } = require('../db/postgres/map-solution-archive');
const { fixture, legacyXssContent, legacyXssVisibility } = require('./fixtures/platformAdditionalSolutions');

function input() {
  const value = fixture(), tables = value.sources['users_auth.db'].tables;
  for (const family of Object.values(FAMILIES)) {
    tables[family.contentTable] = family.objectiveIds.map((id, i) => ({
      ...(family.contentHasId ? { id: i + 1 } : {}), [family.idColumn]: id,
      title: 'Preserved title', difficulty: 'Easy', hints: '["hint"]', examples: '[{"prompt":"example","explanation":"why"}]', approach: 'approach', tips: '[]',
      ...(family.contentHasTimestamp ? { updated_at: '2026-01-01 00:00:00' } : {}),
    }));
    tables[family.visibilityTable] = family.objectiveIds.map((id, i) => ({
      ...(family.visibilityHasId ? { id: i + 1 } : {}), [family.idColumn]: id, solutions_enabled: 0,
      updated_at: '2026-01-01 00:00:00', ...(family.visibilityTracksActor ? { enabled_by: null, enabled_at: null } : {}),
    }));
  }
  tables.xss_workshop_solutions = [{ ...legacyXssContent(), hints: 'raw instructor hint' }];
  tables.xss_workshop_solution_visibility = [legacyXssVisibility()];
  for (const source of Object.values(value.sources)) for (const rows of Object.values(source.tables)) {
    for (const row of rows) for (const [key, entry] of Object.entries(row)) if (typeof entry === 'number') row[key] = { type: 'integer', value: String(entry) };
  }
  return { ...value, identityMap: { 42: 71 }, naiveTimestamps: 'UTC' };
}

test('projects all100 canonical solutions and independent legacy raw text from verified encoding', () => {
  const source = input(), original = structuredClone(source);
  const mapped = mapSolutionArchive(source);
  assert.equal(mapped.report.requiresReview, false);
  assert.equal(mapped.report.canonical.counts.solutions + mapped.report.additional.counts.solutions, 100);
  assert.equal(mapped.report.additional.counts.legacySolutions, 1);
  assert.equal(mapped.additionalSolutions.sources['users_auth.db'].tables.xss_workshop_solutions[0].hints, 'raw instructor hint');
  assert.equal(mapped.additionalSolutions.sources['users_auth.db'].tables.xss_workshop_solution_visibility[0].enabled_by, '42');
  assert.deepEqual(source, original);
  assert.equal(mapped.report.coverage.reduce((count, row) => count + row.rows, 0), 178);
});

test('NOVA duplicate source conflicts remain explicit after archive projection', () => {
  const source = input(), family = FAMILIES.nosql_injection_workshop;
  source.sources['nosql_workshop.db'] = { tables: Object.fromEntries([family.contentTable, family.visibilityTable].map(table => [table, structuredClone(source.sources['users_auth.db'].tables[table])])) };
  source.sources['nosql_workshop.db'].tables[family.contentTable][0].title = 'Other edited source';
  assert.equal(mapSolutionArchive(source).report.requiresReview, true);
  source.resolutions = { 'nosql_injection_workshop:nosqli_1:content': { archiveDigest: source.archiveDigest, source: 'nosql_workshop.db' } };
  assert.equal(mapSolutionArchive(source).report.requiresReview, false);
});

test('projection refuses lossy numeric/blob conversions and reports missing source content', () => {
  const source = input(), rows = source.sources['users_auth.db'].tables.xss_workshop_solutions;
  rows[0].id = { type: 'integer', value: '9007199254740993' };
  assert.throws(() => mapSolutionArchive(source), { code: 'UNSAFE_SOLUTION_INTEGER' });
  rows[0].id = { type: 'integer', value: '900' };
  rows[0].hints = { type: 'blob', base64: 'AP8=' };
  assert.throws(() => mapSolutionArchive(source), { code: 'UNSUPPORTED_SOLUTION_ARCHIVE_VALUE' });
  rows[0].hints = 'preserved';
  delete source.sources['supply_chain_workshop.db'];
  assert.equal(mapSolutionArchive(source).report.requiresReview, true);
});
