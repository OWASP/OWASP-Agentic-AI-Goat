'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const {
  FAMILY_CONFIG,
  XSS_TABS,
  CSRF_TABS,
  mapAdditionalPlatformSolutions,
  xssResolutionKey,
} = require('../db/postgres/map-platform-additional-solutions');

const { fixture, legacyXssContent, legacyXssVisibility, DIGEST } = require('./fixtures/platformAdditionalSolutions');

test('maps all 48 additional canonical objective DTOs and flags independently', () => {
  const input = fixture();
  input.sources['sensitive_info_workshop.db'].tables.finflow_solutions[0].approach = 'Instructor-edited approach';
  input.sources['sensitive_info_workshop.db'].tables.finflow_solution_visibility[0].solutions_enabled = 0;
  const result = mapAdditionalPlatformSolutions(input);
  assert.deepEqual(result.report.counts, { solutions: 48, solutionVisibility: 48, retainedLegacy: 0, legacySolutions: 0, legacySolutionVisibility: 0 });
  assert.equal(result.report.requiresReview, false);
  const xss = result.snapshot.solutions.find(row => row.workshopKey === 'xss_workshop' && row.objectiveId === 'xss_r1');
  assert.deepEqual(xss.content, { title: 'Title xss_r1', hint: 'Hint xss_r1', example: 'Example xss_r1', explanation: 'Explanation xss_r1' });
  const finflow = result.snapshot.solutions.find(row => row.workshopKey === 'sensitive_info_disclosure' && row.objectiveId === 'tool_enum');
  const flag = result.snapshot.solutionVisibility.find(row => row.workshopKey === 'sensitive_info_disclosure' && row.objectiveId === 'tool_enum');
  assert.equal(finflow.content.approach, 'Instructor-edited approach');
  assert.equal(flag.enabled, false);
  assert.equal(finflow.provenance[0].sourceUpdatedAt, '2026-04-05 06:07:08.654321');
});

test('preserves XSS tab raw content and canonical objective content independently', () => {
  const input = fixture();
  input.naiveTimestamps = 'UTC';
  input.identityMap = { 42: 71 };
  input.sources['users_auth.db'].tables.xss_workshop_solutions = [legacyXssContent()];
  input.sources['users_auth.db'].tables.xss_workshop_solution_visibility = [legacyXssVisibility()];
  input.sources['users_auth.db'].tables.xss_workshop_solutions[0].hints = 'legacy malformed JSON { kept';
  const result = mapAdditionalPlatformSolutions(input);
  assert.equal(result.snapshot.legacySolutions[0].hints, 'legacy malformed JSON { kept');
  assert.equal(result.snapshot.solutions.length, 48);
  assert.equal(result.snapshot.solutionVisibility.length, 48);
  assert.equal(result.snapshot.legacySolutions[0].examples, legacyXssContent().examples);
  assert.equal(result.snapshot.legacySolutionVisibility[0].enabledBy, 71);
  assert.equal(result.snapshot.legacySolutionVisibility[0].updatedAt, '2025-01-02T03:04:06Z');
  assert.equal(result.report.requiresReview, false);
  assert.deepEqual(result.report.conflicts, []);
});

test('requires explicit actor mapping and timestamp policy for legacy XSS', () => {
  const input = fixture();
  input.sources['users_auth.db'].tables.xss_workshop_solution_visibility = [legacyXssVisibility()];
  assert.throws(() => mapAdditionalPlatformSolutions(input), { code: 'UNMAPPED_SOURCE_ACTOR' });
  input.identityMap = {42: 71};
  assert.throws(() => mapAdditionalPlatformSolutions(input), { code: 'AMBIGUOUS_TIMESTAMP' });
  input.naiveTimestamps = 'UTC';
  input.sources['users_auth.db'].tables.xss_workshop_solution_visibility[0].updated_at = '2025-02-30 03:04:06';
  assert.throws(() => mapAdditionalPlatformSolutions(input), { code: 'INVALID_CALENDAR_DATE' });
});

test('rejects obsolete destructive XSS source choices', () => {
  const input = fixture();
  input.resolutions = {[xssResolutionKey('reflected', 'content')]: {archiveDigest: DIGEST, source:'objective'}};
  assert.throws(() => mapAdditionalPlatformSolutions(input), {code:'UNUSED_SOLUTION_RESOLUTION'});
});

test('reports retired CSRF tab rows rather than silently importing them', () => {
  const input = fixture();
  input.sources['users_auth.db'].tables.csrf_workshop_solutions = [{ legacy: 'preserved in archive' }];
  const result = mapAdditionalPlatformSolutions(input);
  assert.deepEqual(result.report.unmappedTables, [{ source: 'users_auth.db', table: 'csrf_workshop_solutions', rows: 1, reason: 'retired_tab_solution_requires_review' }]);
  assert.equal(result.report.requiresReview, true);
});

test('rejects non-renderable generic content and mismatched distinct objective ownership', () => {
  let input = fixture();
  input.sources['supply_chain_workshop.db'].tables.sc_solutions[0].examples = '[{"prompt":{"nested":"React child"},"explanation":"why"}]';
  assert.throws(() => mapAdditionalPlatformSolutions(input), {
    code: 'INVALID_SOLUTION_CONTENT_SHAPE',
    location: 'supply_chain_workshop.db.sc_solutions[0].examples[0].prompt',
  });

  input = fixture();
  input.sources['users_auth.db'].tables.csrf_workshop_objective_solutions[0].exercise_id = 'post';
  assert.throws(() => mapAdditionalPlatformSolutions(input), {
    code: 'SOLUTION_EXERCISE_MISMATCH',
    location: 'users_auth.db.csrf_workshop_objective_solutions[0].exercise_id',
  });
});

test('preserves content when its independent flag row is missing and reports the gap', () => {
  const input = fixture();
  input.sources['supply_chain_workshop.db'].tables.sc_solution_visibility =
    input.sources['supply_chain_workshop.db'].tables.sc_solution_visibility.filter(row => row.objective_id !== 'rce_cmd');
  const result = mapAdditionalPlatformSolutions(input);
  assert.equal(result.snapshot.solutions.some(row => row.workshopKey === 'supply_chain_rce' && row.objectiveId === 'rce_cmd'), true);
  assert.equal(result.snapshot.solutionVisibility.some(row => row.workshopKey === 'supply_chain_rce' && row.objectiveId === 'rce_cmd'), false);
  assert.equal(result.report.missingSourceRows.some(row => row.objectiveId === 'rce_cmd' && row.field === 'visibility'), true);
  assert.equal(result.report.requiresReview, true);
});
