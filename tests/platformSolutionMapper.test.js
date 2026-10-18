'use strict';

const assert = require('node:assert/strict');
const { test: run } = require('node:test');
const {
  FAMILIES,
  mapPlatformSolutions,
  resolutionKey,
} = require('../db/postgres/map-platform-solutions');

const DIGEST = 'a'.repeat(64);

function contentRow(config, objectiveId, index, overrides = {}) {
  return {
    ...(config.contentHasId ? { id: index + 1 } : {}),
    [config.idColumn]: objectiveId,
    title: `Title ${objectiveId}`,
    difficulty: 'Intermediate',
    hints: JSON.stringify([`hint ${objectiveId}`]),
    examples: JSON.stringify([{ prompt: `example ${objectiveId}`, explanation: 'why' }]),
    approach: `Approach ${objectiveId}`,
    tips: JSON.stringify([`tip ${objectiveId}`]),
    ...(config.contentHasTimestamp ? { updated_at: '2026-01-02 03:04:05.123456' } : {}),
    ...overrides,
  };
}

function visibilityRow(config, objectiveId, index, overrides = {}) {
  return {
    ...(config.visibilityHasId ? { id: index + 101 } : {}),
    [config.idColumn]: objectiveId,
    solutions_enabled: index % 2,
    ...(config.visibilityTracksActor ? { enabled_by: index % 2 ? 77 : null, enabled_at: index % 2 ? '2026-02-03 04:05:06' : null } : {}),
    updated_at: '2026-02-03 04:05:06.654321',
    ...overrides,
  };
}

function fixture({ includeNovaLocal = false } = {}) {
  const users = {};
  for (const config of Object.values(FAMILIES)) {
    users[config.contentTable] = config.objectiveIds.map((id, index) => contentRow(config, id, index));
    users[config.visibilityTable] = config.objectiveIds.map((id, index) => visibilityRow(config, id, index));
  }
  const sources = { 'users_auth.db': { tables: users } };
  if (includeNovaLocal) {
    const nova = FAMILIES.nosql_injection_workshop;
    sources['nosql_workshop.db'] = { tables: {
      [nova.contentTable]: nova.objectiveIds.map((id, index) => contentRow(nova, id, index)),
      [nova.visibilityTable]: nova.objectiveIds.map((id, index) => visibilityRow(nova, id, index)),
    } };
  }
  return { sources, archiveDigest: DIGEST };
}

run('maps all archived content and visibility independently with exact provenance', () => {
  const input = fixture();
  input.sources['users_auth.db'].tables.prompt_injection_solutions[0].hints = '["edited hint","kept as authored"]';
  input.sources['users_auth.db'].tables.prompt_injection_solution_visibility[0].solutions_enabled = 0;
  const result = mapPlatformSolutions(input);
  assert.deepEqual(result.report.counts, { solutions: 52, solutionVisibility: 52 });
  assert.equal(result.report.requiresReview, false);
  assert.deepEqual(result.report.legitimateCatalogGaps, [
    { workshopKey: 'direct_prompt_injection', objectiveId: 'interact' },
    { workshopKey: 'indirect_prompt_injection', objectiveId: 'email_create_inbox' },
    { workshopKey: 'indirect_prompt_injection', objectiveId: 'email_send_attack' },
    { workshopKey: 'indirect_prompt_injection', objectiveId: 'email_retrieve' },
    { workshopKey: 'indirect_prompt_injection', objectiveId: 'email_trigger_injection' },
    { workshopKey: 'indirect_prompt_injection', objectiveId: 'email_understand_defense' },
  ]);
  const solution = result.snapshot.solutions.find(row => row.workshopKey === 'direct_prompt_injection' && row.objectiveId === 'system_prompt');
  const visibility = result.snapshot.solutionVisibility.find(row => row.workshopKey === 'direct_prompt_injection' && row.objectiveId === 'system_prompt');
  assert.deepEqual(solution.content.hints, ['edited hint', 'kept as authored']);
  assert.equal(visibility.enabled, false);
  assert.deepEqual(solution.provenance[0], {
    archiveDigest: DIGEST,
    source: 'users_auth.db',
    table: 'prompt_injection_solutions',
    sourceId: 1,
    sourceUpdatedAt: '2026-01-02 03:04:05.123456',
    sourceEnabledBy: null,
    sourceEnabledAt: null,
    rowIndex: 0,
    kind: 'legacy_import',
  });
  assert.equal(input.sources['users_auth.db'].tables.prompt_injection_solutions[0].hints, '["edited hint","kept as authored"]');
});

run('does not zip away visibility when content is absent', () => {
  const input = fixture();
  input.sources['users_auth.db'].tables.ipi_solutions = input.sources['users_auth.db'].tables.ipi_solutions.filter(row => row.objective_id !== 'rag_query');
  const result = mapPlatformSolutions(input);
  assert.equal(result.snapshot.solutions.some(row => row.workshopKey === 'indirect_prompt_injection' && row.objectiveId === 'rag_query'), false);
  assert.equal(result.snapshot.solutionVisibility.some(row => row.workshopKey === 'indirect_prompt_injection' && row.objectiveId === 'rag_query'), true);
  assert.deepEqual(result.report.missingSourceRows.find(row => row.workshopKey === 'indirect_prompt_injection' && row.objectiveId === 'rag_query'), {
    workshopKey: 'indirect_prompt_injection', objectiveId: 'rag_query', field: 'content', expectedSources: ['users_auth.db'],
  });
  assert.equal(result.report.requiresReview, true);
});

run('deduplicates equal NOVA sources and records both origins', () => {
  const result = mapPlatformSolutions(fixture({ includeNovaLocal: true }));
  assert.equal(result.report.conflicts.length, 0);
  const row = result.snapshot.solutions.find(item => item.workshopKey === 'nosql_injection_workshop' && item.objectiveId === 'nosqli_1');
  assert.deepEqual(row.provenance.map(origin => origin.source), ['users_auth.db', 'nosql_workshop.db']);
});

run('leaves a NOVA field unselected on conflict while retaining its independent flag', () => {
  const input = fixture({ includeNovaLocal: true });
  input.sources['nosql_workshop.db'].tables.nosql_injection_solutions[0].approach = 'Local instructor edit';
  const result = mapPlatformSolutions(input);
  const key = resolutionKey('nosql_injection_workshop', 'nosqli_1', 'content');
  assert.equal(result.snapshot.solutions.some(row => row.workshopKey === 'nosql_injection_workshop' && row.objectiveId === 'nosqli_1'), false);
  assert.equal(result.snapshot.solutionVisibility.some(row => row.workshopKey === 'nosql_injection_workshop' && row.objectiveId === 'nosqli_1'), true);
  assert.equal(result.report.conflicts[0].key, key);
  assert.equal(result.report.conflicts[0].sources.length, 2);
  assert.equal(Object.hasOwn(result.report.conflicts[0].sources[0], 'value'), false);
  assert.equal(result.report.requiresReview, true);
});

run('applies only an archive-bound per-field NOVA resolution', () => {
  const input = fixture({ includeNovaLocal: true });
  input.sources['nosql_workshop.db'].tables.nosql_injection_solutions[0].approach = 'Local instructor edit';
  const key = resolutionKey('nosql_injection_workshop', 'nosqli_1', 'content');
  input.resolutions = { [key]: { archiveDigest: DIGEST, source: 'nosql_workshop.db' } };
  const result = mapPlatformSolutions(input);
  const row = result.snapshot.solutions.find(item => item.workshopKey === 'nosql_injection_workshop' && item.objectiveId === 'nosqli_1');
  assert.equal(row.content.approach, 'Local instructor edit');
  assert.deepEqual(row.provenance.map(origin => origin.source), ['nosql_workshop.db']);
  assert.equal(result.report.conflicts.length, 0);
  assert.equal(result.report.resolvedConflicts[0].selectedSource, 'nosql_workshop.db');
  assert.equal(result.report.requiresReview, false);

  input.resolutions[key].archiveDigest = 'b'.repeat(64);
  assert.throws(() => mapPlatformSolutions(input), { code: 'ARCHIVE_BOUND_REVIEW_REQUIRED', location: key });
});

run('does not silently prefer a NOVA source when the other provided source lacks the row', () => {
  const input = fixture({ includeNovaLocal: true });
  input.sources['nosql_workshop.db'].tables.nosql_injection_solutions =
    input.sources['nosql_workshop.db'].tables.nosql_injection_solutions.filter(row => row.objective_id !== 'nosqli_2');
  const key = resolutionKey('nosql_injection_workshop', 'nosqli_2', 'content');
  let result = mapPlatformSolutions(input);
  assert.equal(result.snapshot.solutions.some(row => row.workshopKey === 'nosql_injection_workshop' && row.objectiveId === 'nosqli_2'), false);
  assert.deepEqual(result.report.conflicts.find(row => row.key === key).sources[1], { source: 'nosql_workshop.db', missing: true });

  input.resolutions = { [key]: { archiveDigest: DIGEST, source: 'users_auth.db' } };
  result = mapPlatformSolutions(input);
  assert.equal(result.snapshot.solutions.some(row => row.workshopKey === 'nosql_injection_workshop' && row.objectiveId === 'nosqli_2'), true);
});

run('rejects unknown IDs, duplicate rows, malformed JSON, malformed flags, and unused decisions', () => {
  let input = fixture();
  input.sources['users_auth.db'].tables.ea_solutions[0].objective_id = 'objective_99';
  assert.throws(() => mapPlatformSolutions(input), { code: 'UNKNOWN_SOLUTION_OBJECTIVE' });

  input = fixture();
  input.sources['users_auth.db'].tables.mcp_workshop_solutions.push({ ...input.sources['users_auth.db'].tables.mcp_workshop_solutions[0] });
  assert.throws(() => mapPlatformSolutions(input), { code: 'DUPLICATE_SOLUTION_ROW' });

  input = fixture();
  input.sources['users_auth.db'].tables.sql_injection_solutions[0].examples = '{bad';
  assert.throws(() => mapPlatformSolutions(input), { code: 'INVALID_SOLUTION_JSON' });

  input = fixture();
  input.sources['users_auth.db'].tables.nosql_injection_solution_visibility[0].solutions_enabled = 2;
  assert.throws(() => mapPlatformSolutions(input), { code: 'INVALID_BOOLEAN_FLAG' });

  input = fixture();
  input.resolutions = { unused: { archiveDigest: DIGEST, source: 'users_auth.db' } };
  assert.throws(() => mapPlatformSolutions(input), { code: 'UNUSED_SOLUTION_RESOLUTION', location: 'unused' });
});

run('rejects non-renderable lists and family-incompatible examples without changing the archive', () => {
  let input = fixture();
  const originalHints = '["safe",{"objectChild":"would crash React"}]';
  input.sources['users_auth.db'].tables.prompt_injection_solutions[0].hints = originalHints;
  assert.throws(() => mapPlatformSolutions(input), {
    code: 'INVALID_SOLUTION_CONTENT_SHAPE',
    location: 'users_auth.db.prompt_injection_solutions[0].hints[1]',
  });
  assert.equal(input.sources['users_auth.db'].tables.prompt_injection_solutions[0].hints, originalHints);

  input = fixture();
  input.sources['users_auth.db'].tables.ea_solutions[0].examples = '["plain strings render as empty EA cards"]';
  assert.throws(() => mapPlatformSolutions(input), {
    code: 'INVALID_SOLUTION_CONTENT_SHAPE',
    location: 'users_auth.db.ea_solutions[0].examples[0]',
  });

  input = fixture();
  input.sources['users_auth.db'].tables.mcp_workshop_solutions[0].examples = '[{"prompt":{"nested":"React child"},"explanation":"why"}]';
  assert.throws(() => mapPlatformSolutions(input), {
    code: 'INVALID_SOLUTION_CONTENT_SHAPE',
    location: 'users_auth.db.mcp_workshop_solutions[0].examples[0].prompt',
  });

  input = fixture();
  input.sources['users_auth.db'].tables.sql_injection_solutions[0].examples = '["\' OR 1=1 --",{"payload":"UNION SELECT","explanation":"works"}]';
  assert.doesNotThrow(() => mapPlatformSolutions(input));

  input = fixture();
  input.sources['users_auth.db'].tables.nosql_injection_solutions[0].examples = '[{"payload":"{\\"$gt\\":\\"\\"}","explanation":{"nested":"React child"}}]';
  assert.throws(() => mapPlatformSolutions(input), {
    code: 'INVALID_SOLUTION_CONTENT_SHAPE',
    location: 'users_auth.db.nosql_injection_solutions[0].examples[0].explanation',
  });
});

run('reports a missing source table without inventing rows', () => {
  const input = fixture();
  delete input.sources['users_auth.db'].tables.sql_injection_solutions;
  const result = mapPlatformSolutions(input);
  assert.equal(result.snapshot.solutions.filter(row => row.workshopKey === 'sql_injection_workshop').length, 0);
  assert.deepEqual(result.report.missingSourceTables.find(row => row.workshopKey === 'sql_injection_workshop'), {
    source: 'users_auth.db', table: 'sql_injection_solutions', workshopKey: 'sql_injection_workshop', field: 'content',
  });
  assert.equal(result.report.requiresReview, true);
});
