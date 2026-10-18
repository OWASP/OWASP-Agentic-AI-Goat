'use strict';

const crypto = require('node:crypto');
const { WORKSHOP_OBJECTIVES } = require('../../server/config/workshopCatalog');

const CONTENT_FIELDS = Object.freeze(['title', 'difficulty', 'hints', 'examples', 'approach', 'tips']);
const JSON_FIELDS = new Set(['hints', 'examples', 'tips']);
const USERS_AUTH = 'users_auth.db';
const NOVA_LOCAL = 'nosql_workshop.db';

const FAMILIES = Object.freeze({
  direct_prompt_injection: Object.freeze({
    contentTable: 'prompt_injection_solutions', visibilityTable: 'prompt_injection_solution_visibility',
    idColumn: 'challenge_id', contentHasId: true, contentHasTimestamp: true,
    visibilityHasId: true, visibilityTracksActor: true,
    objectiveIds: Object.freeze(['system_prompt', 'jailbreak', 'multi_language', 'virtualization', 'role_playing', 'side_stepping', 'obfuscation']),
  }),
  indirect_prompt_injection: Object.freeze({
    contentTable: 'ipi_solutions', visibilityTable: 'ipi_solution_visibility', idColumn: 'objective_id',
    objectiveIds: Object.freeze(['rag_upload', 'rag_query', 'rag_clean_doc', 'rag_injected_doc', 'rag_query_injection']),
  }),
  excessive_agency: Object.freeze({
    contentTable: 'ea_solutions', visibilityTable: 'ea_solution_visibility', idColumn: 'objective_id',
    objectiveIds: Object.freeze(Array.from({ length: 9 }, (_, index) => `objective_${index + 1}`)),
  }),
  mcp_workshop: Object.freeze({
    contentTable: 'mcp_workshop_solutions', visibilityTable: 'mcp_workshop_solution_visibility', idColumn: 'objective_id',
    objectiveIds: Object.freeze(['mcp_recon', 'mcp_cmd_injection', 'mcp_ssrf', 'mcp_tool_poisoning', 'mcp_indirect_injection', 'mcp_confused_deputy', 'mcp_broken_authz', 'mcp_secret_exposure', 'mcp_supply_chain', 'mcp_audit_gap', 'mcp_shadow_server']),
  }),
  sql_injection_workshop: Object.freeze({
    contentTable: 'sql_injection_solutions', visibilityTable: 'sql_injection_solution_visibility', idColumn: 'objective_id',
    objectiveIds: Object.freeze(Array.from({ length: 10 }, (_, index) => `sqli_${index + 1}`)),
  }),
  nosql_injection_workshop: Object.freeze({
    contentTable: 'nosql_injection_solutions', visibilityTable: 'nosql_injection_solution_visibility', idColumn: 'objective_id',
    objectiveIds: Object.freeze(Array.from({ length: 10 }, (_, index) => `nosqli_${index + 1}`)),
    sources: Object.freeze([USERS_AUTH, NOVA_LOCAL]),
  }),
});

function invalid(code, location) {
  const error = new Error(code);
  error.code = code;
  if (location !== undefined) error.location = location;
  throw error;
}

function object(value, location) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid('INVALID_MAPPING_INPUT', location);
  return value;
}

function exactColumns(row, columns, location) {
  object(row, location);
  const actual = Object.keys(row).sort();
  const expected = [...columns].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) invalid('UNMAPPED_COLUMNS', location);
}

function nullableText(value, location) {
  if (value === null) return null;
  if (typeof value !== 'string' || value.includes('\0')) invalid('INVALID_TEXT', location);
  return value;
}

function sourceTimestamp(value, location) {
  if (value === null) return null;
  return nullableText(value, location);
}

function flag(value, location) {
  if (value !== 0 && value !== 1) invalid('INVALID_BOOLEAN_FLAG', location);
  return value === 1;
}

function sourceId(value, location) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) invalid('INVALID_SOURCE_ID', location);
  return value;
}

function decodeJsonArray(raw, location) {
  if (raw === null) return null;
  nullableText(raw, location);
  let decoded;
  try { decoded = JSON.parse(raw); } catch (_) { invalid('INVALID_SOLUTION_JSON', location); }
  if (!Array.isArray(decoded)) invalid('INVALID_SOLUTION_JSON_SHAPE', location);
  return decoded;
}

function renderableText(value) {
  return typeof value === 'string' && value.trim().length > 0 && !value.includes('\0');
}

function contentShapeError(location) {
  invalid('INVALID_SOLUTION_CONTENT_SHAPE', location);
}

function validateStringList(value, location) {
  if (value === null) return;
  value.forEach((entry, index) => {
    if (!renderableText(entry)) contentShapeError(`${location}[${index}]`);
  });
}

function validateObjectText(example, field, location, { required = false } = {}) {
  if (!Object.hasOwn(example, field)) {
    if (required) contentShapeError(`${location}.${field}`);
    return;
  }
  if (!renderableText(example[field])) contentShapeError(`${location}.${field}`);
}

function validateExample(example, family, location) {
  if (typeof example === 'string') {
    if (!renderableText(example)) contentShapeError(location);
    if (['indirect_prompt_injection', 'excessive_agency'].includes(family)) contentShapeError(location);
    return;
  }
  if (!example || typeof example !== 'object' || Array.isArray(example)) contentShapeError(location);

  if (['indirect_prompt_injection', 'excessive_agency', 'mcp_workshop'].includes(family)) {
    validateObjectText(example, 'prompt', location, { required: true });
    validateObjectText(example, 'explanation', location, { required: true });
    return;
  }
  if (family === 'direct_prompt_injection') {
    const payloadField = ['prompt', 'input', 'code', 'payload'].find(field => renderableText(example[field]));
    if (!payloadField) contentShapeError(location);
    validateObjectText(example, 'explanation', location);
    validateObjectText(example, 'title', location);
    return;
  }
  if (['sql_injection_workshop', 'nosql_injection_workshop'].includes(family)) {
    const payloadField = ['payload', 'prompt'].find(field => renderableText(example[field]));
    if (!payloadField) contentShapeError(location);
    validateObjectText(example, 'explanation', location);
    validateObjectText(example, 'note', location);
    return;
  }
  contentShapeError(location);
}

function validateContentShape(content, family, location) {
  validateStringList(content.hints, `${location}.hints`);
  validateStringList(content.tips, `${location}.tips`);
  if (content.examples !== null) {
    content.examples.forEach((example, index) => validateExample(example, family, `${location}.examples[${index}]`));
  }
}

function digestValue(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function rowProvenance({ archiveDigest, source, table, row, rowIndex, config, kind }) {
  return {
    archiveDigest,
    source,
    table,
    sourceId: config[`${kind}HasId`] ? row.id : null,
    sourceUpdatedAt: kind === 'content'
      ? (config.contentHasTimestamp ? row.updated_at : null)
      : row.updated_at,
    sourceEnabledBy: kind === 'visibility' && config.visibilityTracksActor ? row.enabled_by : null,
    sourceEnabledAt: kind === 'visibility' && config.visibilityTracksActor ? row.enabled_at : null,
    rowIndex,
    kind: 'legacy_import',
  };
}

function contentColumns(config) {
  return [
    ...(config.contentHasId ? ['id'] : []), config.idColumn, ...CONTENT_FIELDS,
    ...(config.contentHasTimestamp ? ['updated_at'] : []),
  ];
}

function visibilityColumns(config) {
  return [
    ...(config.visibilityHasId ? ['id'] : []), config.idColumn, 'solutions_enabled',
    ...(config.visibilityTracksActor ? ['enabled_by', 'enabled_at'] : []), 'updated_at',
  ];
}

function normalizeContent(row, config, family, location) {
  exactColumns(row, contentColumns(config), location);
  if (config.contentHasId) sourceId(row.id, `${location}.id`);
  const objectiveId = nullableText(row[config.idColumn], `${location}.${config.idColumn}`);
  const content = {};
  for (const field of CONTENT_FIELDS) {
    content[field] = JSON_FIELDS.has(field)
      ? decodeJsonArray(row[field], `${location}.${field}`)
      : nullableText(row[field], `${location}.${field}`);
  }
  if (config.contentHasTimestamp) sourceTimestamp(row.updated_at, `${location}.updated_at`);
  validateContentShape(content, family, location);
  return { objectiveId, content };
}

function normalizeVisibility(row, config, location) {
  exactColumns(row, visibilityColumns(config), location);
  if (config.visibilityHasId) sourceId(row.id, `${location}.id`);
  const objectiveId = nullableText(row[config.idColumn], `${location}.${config.idColumn}`);
  if (config.visibilityTracksActor && row.enabled_by !== null) sourceId(row.enabled_by, `${location}.enabled_by`);
  if (config.visibilityTracksActor) sourceTimestamp(row.enabled_at, `${location}.enabled_at`);
  sourceTimestamp(row.updated_at, `${location}.updated_at`);
  return { objectiveId, enabled: flag(row.solutions_enabled, `${location}.solutions_enabled`) };
}

function candidateRows({ source, tables, family, config, kind, archiveDigest }) {
  const table = config[`${kind}Table`];
  if (!Object.hasOwn(tables, table)) return { missingTable: true, candidates: [] };
  if (!Array.isArray(tables[table])) invalid('INVALID_SOURCE_TABLE', `${source}.${table}`);
  const seen = new Set();
  const candidates = tables[table].map((row, rowIndex) => {
    const location = `${source}.${table}[${rowIndex}]`;
    const normalized = kind === 'content' ? normalizeContent(row, config, family, location) : normalizeVisibility(row, config, location);
    if (!config.objectiveIds.includes(normalized.objectiveId)) invalid('UNKNOWN_SOLUTION_OBJECTIVE', location);
    if (seen.has(normalized.objectiveId)) invalid('DUPLICATE_SOLUTION_ROW', location);
    seen.add(normalized.objectiveId);
    return {
      workshopKey: family,
      objectiveId: normalized.objectiveId,
      value: kind === 'content' ? normalized.content : normalized.enabled,
      provenance: rowProvenance({ archiveDigest, source, table, row, rowIndex, config, kind }),
      comparison: Object.fromEntries((kind === 'content' ? contentColumns(config).filter(column => !['id', 'updated_at'].includes(column)) : visibilityColumns(config).filter(column => !['id', 'updated_at', 'enabled_by', 'enabled_at'].includes(column))).map(column => [column, row[column]])),
    };
  });
  return { missingTable: false, candidates };
}

function resolutionKey(family, objectiveId, kind) {
  return `${family}:${objectiveId}:${kind}`;
}

function chooseCandidate({ candidates, expectedSources, family, objectiveId, kind, archiveDigest, resolutions, usedResolutions, conflicts, resolvedConflicts }) {
  if (!candidates.length) return null;
  if (candidates.length === 1 && expectedSources.length === 1) return { ...candidates[0], provenance: [candidates[0].provenance] };
  const first = candidates[0].comparison;
  const equal = candidates.length === expectedSources.length
    && candidates.every(candidate => JSON.stringify(candidate.comparison) === JSON.stringify(first));
  if (equal) return { ...candidates[0], provenance: candidates.map(candidate => candidate.provenance) };

  const key = resolutionKey(family, objectiveId, kind);
  const choice = resolutions[key];
  const conflict = {
    key, workshopKey: family, objectiveId, field: kind,
    sources: expectedSources.map(source => {
      const candidate = candidates.find(item => item.provenance.source === source);
      return candidate ? {
        source,
        table: candidate.provenance.table,
        sourceId: candidate.provenance.sourceId,
        sourceUpdatedAt: candidate.provenance.sourceUpdatedAt,
        valueDigest: digestValue(candidate.comparison),
      } : { source, missing: true };
    }),
  };
  if (!choice) {
    conflicts.push(conflict);
    return null;
  }
  object(choice, `resolutions.${key}`);
  if (Object.keys(choice).sort().join(',') !== 'archiveDigest,source') invalid('INVALID_SOLUTION_RESOLUTION', key);
  if (choice.archiveDigest !== archiveDigest) invalid('ARCHIVE_BOUND_REVIEW_REQUIRED', key);
  const selected = candidates.find(candidate => candidate.provenance.source === choice.source);
  if (!selected) invalid('INVALID_SOLUTION_RESOLUTION_SOURCE', key);
  usedResolutions.add(key);
  resolvedConflicts.push({ ...conflict, selectedSource: choice.source });
  return { ...selected, provenance: [selected.provenance] };
}

/**
 * Maps already decoded archive rows. It never opens a database or imports static fixtures.
 * `sources` is keyed by archive database filename and each value is `{ tables }`.
 */
function mapPlatformSolutions({ sources, archiveDigest, resolutions = {} }) {
  object(sources, 'sources');
  object(resolutions, 'resolutions');
  if (!/^[a-f0-9]{64}$/.test(archiveDigest || '')) invalid('ARCHIVE_DIGEST_REQUIRED', 'archiveDigest');
  for (const [source, envelope] of Object.entries(sources)) {
    if (![USERS_AUTH, NOVA_LOCAL].includes(source)) invalid('UNKNOWN_SOLUTION_SOURCE', source);
    object(envelope, `sources.${source}`);
    if (Object.keys(envelope).length !== 1 || !Object.hasOwn(envelope, 'tables')) invalid('INVALID_SOURCE_ENVELOPE', source);
    object(envelope.tables, `sources.${source}.tables`);
  }
  if (!Object.hasOwn(sources, USERS_AUTH)) invalid('USERS_AUTH_SOURCE_REQUIRED', 'sources');

  const solutions = [];
  const solutionVisibility = [];
  const conflicts = [];
  const resolvedConflicts = [];
  const missingSourceTables = [];
  const missingSourceRows = [];
  const legitimateCatalogGaps = [];
  const usedResolutions = new Set();

  for (const [family, config] of Object.entries(FAMILIES)) {
    const catalogIds = (WORKSHOP_OBJECTIVES[family] || []).map(objective => objective.id);
    legitimateCatalogGaps.push(...catalogIds.filter(id => !config.objectiveIds.includes(id)).map(objectiveId => ({ workshopKey: family, objectiveId })));
    const allowedSources = config.sources || [USERS_AUTH];
    const byKind = {};
    for (const kind of ['content', 'visibility']) {
      byKind[kind] = new Map(config.objectiveIds.map(id => [id, []]));
      for (const source of allowedSources) {
        if (!Object.hasOwn(sources, source)) continue;
        const result = candidateRows({ source, tables: sources[source].tables, family, config, kind, archiveDigest });
        if (result.missingTable) {
          missingSourceTables.push({ source, table: config[`${kind}Table`], workshopKey: family, field: kind });
          continue;
        }
        for (const candidate of result.candidates) byKind[kind].get(candidate.objectiveId).push(candidate);
      }
    }
    for (const objectiveId of config.objectiveIds) {
      for (const kind of ['content', 'visibility']) {
        const candidates = byKind[kind].get(objectiveId);
        if (!candidates.length) {
          missingSourceRows.push({ workshopKey: family, objectiveId, field: kind, expectedSources: allowedSources.filter(source => Object.hasOwn(sources, source)) });
          continue;
        }
        const expectedSources = allowedSources.filter(source => Object.hasOwn(sources, source));
        const chosen = chooseCandidate({ candidates, expectedSources, family, objectiveId, kind, archiveDigest, resolutions, usedResolutions, conflicts, resolvedConflicts });
        if (!chosen) continue;
        if (kind === 'content') solutions.push({ workshopKey: family, objectiveId, content: chosen.value, provenance: chosen.provenance });
        else solutionVisibility.push({ workshopKey: family, objectiveId, enabled: chosen.value, provenance: chosen.provenance });
      }
    }
  }
  const unusedResolutions = Object.keys(resolutions).filter(key => !usedResolutions.has(key));
  if (unusedResolutions.length) invalid('UNUSED_SOLUTION_RESOLUTION', unusedResolutions[0]);
  const requiresReview = conflicts.length > 0 || missingSourceTables.length > 0 || missingSourceRows.length > 0;
  return {
    snapshot: { version: 1, solutions, solutionVisibility },
    report: {
      conflicts, resolvedConflicts, missingSourceTables, missingSourceRows, legitimateCatalogGaps,
      requiresReview,
      counts: { solutions: solutions.length, solutionVisibility: solutionVisibility.length },
    },
  };
}

module.exports = { CONTENT_FIELDS, FAMILIES, mapPlatformSolutions, resolutionKey };
