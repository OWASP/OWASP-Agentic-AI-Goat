'use strict';

const crypto = require('node:crypto');
const { WORKSHOP_OBJECTIVES } = require('../../server/config/workshopCatalog');

const USERS_AUTH = 'users_auth.db';
const FINFLOW_DB = 'sensitive_info_workshop.db';
const CODEBOT_DB = 'supply_chain_workshop.db';
const GENERIC_FIELDS = Object.freeze(['title', 'difficulty', 'hints', 'examples', 'approach', 'tips']);
const JSON_FIELDS = new Set(['hints', 'examples', 'tips']);

const XSS_TABS = Object.freeze({
  reflected: Object.freeze(['xss_r1', 'xss_r2', 'xss_r3']),
  stored_user: Object.freeze(['xss_s1', 'xss_s2', 'xss_s3']),
  stored_llm: Object.freeze(['xss_g1', 'xss_g2', 'xss_g3']),
  email: Object.freeze(['xss_e1', 'xss_e2', 'xss_e3']),
});
const CSRF_TABS = Object.freeze({
  get: Object.freeze(['csrf_g1', 'csrf_g2', 'csrf_g3']),
  post: Object.freeze(['csrf_p1', 'csrf_p2', 'csrf_p3']),
  xss: Object.freeze(['csrf_x1', 'csrf_x2', 'csrf_x3']),
  indirect: Object.freeze(['csrf_i1', 'csrf_i2', 'csrf_i3']),
});
const FAMILY_CONFIG = Object.freeze({
  sensitive_info_disclosure: Object.freeze({
    source: FINFLOW_DB, contentTable: 'finflow_solutions', visibilityTable: 'finflow_solution_visibility',
    objectiveIds: Object.freeze((WORKSHOP_OBJECTIVES.sensitive_info_disclosure || []).map(row => row.id)),
    visibilityColumns: Object.freeze(['id', 'objective_id', 'solutions_enabled', 'enabled_by', 'enabled_at', 'updated_at']),
  }),
  supply_chain_rce: Object.freeze({
    source: CODEBOT_DB, contentTable: 'sc_solutions', visibilityTable: 'sc_solution_visibility',
    objectiveIds: Object.freeze((WORKSHOP_OBJECTIVES.supply_chain_rce || []).map(row => row.id)),
    visibilityColumns: Object.freeze(['id', 'objective_id', 'solutions_enabled', 'enabled_by', 'enabled_at']),
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
  if (JSON.stringify(Object.keys(row).sort()) !== JSON.stringify([...columns].sort())) invalid('UNMAPPED_COLUMNS', location);
}
function nullableText(value, location) {
  if (value === null) return null;
  if (typeof value !== 'string' || value.includes('\0')) invalid('INVALID_TEXT', location);
  return value;
}
function requiredText(value, location) {
  nullableText(value, location);
  if (value === null || !value.trim()) invalid('INVALID_SOLUTION_CONTENT_SHAPE', location);
  return value;
}
function sourceId(value, location) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) invalid('INVALID_SOURCE_ID', location);
  return value;
}
function flag(value, location) {
  if (value !== 0 && value !== 1) invalid('INVALID_BOOLEAN_FLAG', location);
  return value === 1;
}
function jsonArray(value, location) {
  if (value === null) return null;
  nullableText(value, location);
  let decoded;
  try { decoded = JSON.parse(value); } catch (_) { invalid('INVALID_SOLUTION_JSON', location); }
  if (!Array.isArray(decoded)) invalid('INVALID_SOLUTION_JSON_SHAPE', location);
  return decoded;
}
function stringList(value, location) {
  if (value === null) return;
  value.forEach((entry, index) => {
    if (typeof entry !== 'string' || !entry.trim() || entry.includes('\0')) invalid('INVALID_SOLUTION_CONTENT_SHAPE', `${location}[${index}]`);
  });
}
function promptExamples(value, location) {
  if (value === null) return;
  value.forEach((entry, index) => {
    const at = `${location}[${index}]`;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) invalid('INVALID_SOLUTION_CONTENT_SHAPE', at);
    if (typeof entry.prompt !== 'string' || !entry.prompt.trim() || entry.prompt.includes('\0')) invalid('INVALID_SOLUTION_CONTENT_SHAPE', `${at}.prompt`);
    if (typeof entry.explanation !== 'string' || !entry.explanation.trim() || entry.explanation.includes('\0')) invalid('INVALID_SOLUTION_CONTENT_SHAPE', `${at}.explanation`);
  });
}
function payloadExamples(value, location) {
  if (value === null) return;
  value.forEach((entry, index) => {
    const at = `${location}[${index}]`;
    if (typeof entry === 'string') {
      if (!entry.trim() || entry.includes('\0')) invalid('INVALID_SOLUTION_CONTENT_SHAPE', at);
      return;
    }
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) invalid('INVALID_SOLUTION_CONTENT_SHAPE', at);
    if (typeof entry.payload !== 'string' || !entry.payload.trim() || entry.payload.includes('\0')) invalid('INVALID_SOLUTION_CONTENT_SHAPE', `${at}.payload`);
    if (Object.hasOwn(entry, 'explanation') && (typeof entry.explanation !== 'string' || entry.explanation.includes('\0'))) invalid('INVALID_SOLUTION_CONTENT_SHAPE', `${at}.explanation`);
  });
}
function provenance(archiveDigest, source, table, row, rowIndex, { timestamp = 'updated_at', actor = false } = {}) {
  return {
    archiveDigest, source, table, sourceId: row.id,
    sourceUpdatedAt: timestamp && Object.hasOwn(row, timestamp) ? row[timestamp] : null,
    sourceEnabledBy: actor && Object.hasOwn(row, 'enabled_by') ? row.enabled_by : null,
    sourceEnabledAt: actor && Object.hasOwn(row, 'enabled_at') ? row.enabled_at : null,
    rowIndex, kind: 'legacy_import',
  };
}
function digest(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}
function rows(tables, table, source, report) {
  if (!Object.hasOwn(tables, table)) {
    report.missingSourceTables.push({ source, table });
    return [];
  }
  if (!Array.isArray(tables[table])) invalid('INVALID_SOURCE_TABLE', `${source}.${table}`);
  return tables[table];
}
function indexUnique(entries, idOf, validIds, locationPrefix) {
  const result = new Map();
  entries.forEach((row, index) => {
    const id = idOf(row, index);
    if (!validIds.includes(id)) invalid('UNKNOWN_SOLUTION_OBJECTIVE', `${locationPrefix}[${index}]`);
    if (result.has(id)) invalid('DUPLICATE_SOLUTION_ROW', `${locationPrefix}[${index}]`);
    result.set(id, { row, index });
  });
  return result;
}
function genericContent(row, location, idColumn = 'objective_id', exampleShape = 'prompt') {
  exactColumns(row, ['id', idColumn, ...GENERIC_FIELDS, 'updated_at'], location);
  sourceId(row.id, `${location}.id`);
  requiredText(row[idColumn], `${location}.${idColumn}`);
  const content = {};
  for (const field of GENERIC_FIELDS) content[field] = JSON_FIELDS.has(field) ? jsonArray(row[field], `${location}.${field}`) : nullableText(row[field], `${location}.${field}`);
  if (content.title !== null) requiredText(content.title, `${location}.title`);
  stringList(content.hints, `${location}.hints`);
  stringList(content.tips, `${location}.tips`);
  (exampleShape === 'payload' ? payloadExamples : promptExamples)(content.examples, `${location}.examples`);
  nullableText(row.updated_at, `${location}.updated_at`);
  return content;
}
function genericVisibility(row, columns, location) {
  exactColumns(row, columns, location);
  sourceId(row.id, `${location}.id`);
  requiredText(row.objective_id, `${location}.objective_id`);
  if (row.enabled_by !== null && typeof row.enabled_by !== 'string' && !Number.isSafeInteger(row.enabled_by)) invalid('INVALID_SOURCE_ACTOR', `${location}.enabled_by`);
  nullableText(row.enabled_at, `${location}.enabled_at`);
  if (Object.hasOwn(row, 'updated_at')) nullableText(row.updated_at, `${location}.updated_at`);
  return flag(row.solutions_enabled, `${location}.solutions_enabled`);
}
function distinctContent(row, location, expectedExercise) {
  exactColumns(row, ['id', 'objective_id', 'exercise_id', 'title', 'hint', 'example', 'explanation', 'solutions_enabled', 'updated_at'], location);
  sourceId(row.id, `${location}.id`);
  requiredText(row.objective_id, `${location}.objective_id`);
  if (row.exercise_id !== expectedExercise) invalid('SOLUTION_EXERCISE_MISMATCH', `${location}.exercise_id`);
  const content = {
    title: requiredText(row.title, `${location}.title`),
    hint: nullableText(row.hint, `${location}.hint`),
    example: nullableText(row.example, `${location}.example`),
    explanation: nullableText(row.explanation, `${location}.explanation`),
  };
  nullableText(row.updated_at, `${location}.updated_at`);
  return { content, enabled: flag(row.solutions_enabled, `${location}.solutions_enabled`) };
}
function xssResolutionKey(tab, field) { return `xss_workshop:${tab}:${field}`; }
function legacyTimestamp(value, location, policy) {
  if (value === null) return null;
  nullableText(value, location);
  const shape = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(Z|[+-]\d{2}:\d{2})?$/.exec(value);
  if (!shape || (!shape[1] && policy !== 'UTC') || !Number.isFinite(Date.parse(shape[1] ? value : value.replace(' ', 'T') + 'Z'))) invalid('AMBIGUOUS_TIMESTAMP', location);
  const [hour, minute, second] = value.slice(11, 19).split(':').map(Number);
  if (hour > 23 || minute > 59 || second > 59) invalid('INVALID_CLOCK_TIME', location);
  const [year, month, day] = value.slice(0, 10).split('-').map(Number);
  const calendar = new Date(Date.UTC(year, month - 1, day));
  if (calendar.getUTCFullYear() !== year || calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day) invalid('INVALID_CALENDAR_DATE', location);
  return shape[1] ? value : value.replace(' ', 'T') + 'Z';
}

/** Map decoded solution archive rows only; never opens a file or database. */
function mapAdditionalPlatformSolutions({ sources, archiveDigest, resolutions = {}, identityMap = {}, naiveTimestamps = 'reject' }) {
  object(sources, 'sources'); object(resolutions, 'resolutions'); object(identityMap, 'identityMap');
  if (!['reject', 'UTC'].includes(naiveTimestamps)) invalid('INVALID_TIMESTAMP_POLICY');
  const targets = new Set();
  for (const [key, target] of Object.entries(identityMap)) {
    if (!key) invalid('INVALID_IDENTITY_MAP');
    sourceId(target, 'identityMap');
    if (targets.has(target)) invalid('AMBIGUOUS_IDENTITY_MERGE');
    targets.add(target);
  }
  if (!/^[a-f0-9]{64}$/.test(archiveDigest || '')) invalid('ARCHIVE_DIGEST_REQUIRED', 'archiveDigest');
  for (const [source, envelope] of Object.entries(sources)) {
    if (![USERS_AUTH, FINFLOW_DB, CODEBOT_DB].includes(source)) invalid('UNKNOWN_SOLUTION_SOURCE', source);
    object(envelope, `sources.${source}`);
    if (Object.keys(envelope).length !== 1 || !Object.hasOwn(envelope, 'tables')) invalid('INVALID_SOURCE_ENVELOPE', source);
    object(envelope.tables, `sources.${source}.tables`);
  }

  const snapshot = { version: 1, solutions: [], solutionVisibility: [], retainedLegacy: [], legacySolutions: [], legacySolutionVisibility: [] };
  const report = { conflicts: [], resolvedConflicts: [], missingSourceTables: [], missingSourceRows: [], unmappedTables: [], legitimateCatalogGaps: [], requiresReview: false, counts: null };
  const usedResolutions = new Set();
  const usersTables = sources[USERS_AUTH]?.tables;
  if (!usersTables) report.missingSourceTables.push({ source: USERS_AUTH, table: '*' });

  if (usersTables) {
    const xssIds = Object.values(XSS_TABS).flat();
    const xssTable = 'xss_workshop_objective_solutions';
    const objectiveRows = rows(usersTables, xssTable, USERS_AUTH, report);
    const xssIndexed = indexUnique(objectiveRows, (row, index) => {
      exactColumns(row, ['id', 'objective_id', 'exercise_id', 'title', 'hint', 'example', 'explanation', 'solutions_enabled', 'updated_at'], `${USERS_AUTH}.${xssTable}[${index}]`);
      return row.objective_id;
    }, xssIds, `${USERS_AUTH}.${xssTable}`);

    const legacyContentTable = 'xss_workshop_solutions';
    const legacyVisibilityTable = 'xss_workshop_solution_visibility';
    const legacyContent = Object.hasOwn(usersTables, legacyContentTable)
      ? indexUnique(rows(usersTables, legacyContentTable, USERS_AUTH, report), (row, index) => {
        exactColumns(row, ['id', 'challenge_id', ...GENERIC_FIELDS, 'updated_at'], `${USERS_AUTH}.${legacyContentTable}[${index}]`);
        return row.challenge_id;
      }, Object.keys(XSS_TABS), `${USERS_AUTH}.${legacyContentTable}`) : new Map();
    const legacyVisibility = Object.hasOwn(usersTables, legacyVisibilityTable)
      ? indexUnique(rows(usersTables, legacyVisibilityTable, USERS_AUTH, report), (row, index) => {
        exactColumns(row, ['id', 'challenge_id', 'solutions_enabled', 'enabled_by', 'enabled_at', 'updated_at'], `${USERS_AUTH}.${legacyVisibilityTable}[${index}]`);
        return row.challenge_id;
      }, Object.keys(XSS_TABS), `${USERS_AUTH}.${legacyVisibilityTable}`) : new Map();

    for (const [tab, objectiveIds] of Object.entries(XSS_TABS)) {
      for (const field of ['content', 'visibility']) {
        const legacy = field === 'content' ? legacyContent.get(tab) : legacyVisibility.get(tab);
        if (legacy) {
          const table = field === 'content' ? legacyContentTable : legacyVisibilityTable;
          const location = `${USERS_AUTH}.${table}[${legacy.index}]`;
          const row = legacy.row;
          if (row.updated_at === null) invalid('MISSING_LEGACY_UPDATED_TIMESTAMP', location);
          const origin = provenance(archiveDigest, USERS_AUTH, table, row, legacy.index, { actor: field === 'visibility' });
          if (field === 'content') {
            sourceId(row.id, `${location}.id`);
            requiredText(row.title, `${location}.title`);
            // Legacy tab APIs parse these text fields themselves; preserve malformed
            // JSON and formatting exactly instead of imposing canonical DTO rules.
            for (const key of GENERIC_FIELDS) nullableText(row[key], `${location}.${key}`);
            snapshot.legacySolutions.push({ challengeId: tab,
              ...Object.fromEntries(GENERIC_FIELDS.map(key => [key, row[key]])),
              updatedAt: legacyTimestamp(row.updated_at, `${location}.updated_at`, naiveTimestamps), provenance: [origin] });
          } else {
            sourceId(row.id, `${location}.id`);
            const actor = row.enabled_by;
            if (actor !== null && (typeof actor !== 'string' && !Number.isSafeInteger(actor))) invalid('INVALID_SOURCE_ACTOR', location);
            if (actor !== null && !Object.hasOwn(identityMap, String(actor))) invalid('UNMAPPED_SOURCE_ACTOR', location);
            snapshot.legacySolutionVisibility.push({ challengeId: tab,
              enabled: flag(row.solutions_enabled, `${location}.solutions_enabled`),
              enabledBy: actor === null ? null : identityMap[String(actor)],
              enabledAt: legacyTimestamp(row.enabled_at, `${location}.enabled_at`, naiveTimestamps),
              updatedAt: legacyTimestamp(row.updated_at, `${location}.updated_at`, naiveTimestamps), provenance: [origin] });
          }
        }
        for (const objectiveId of objectiveIds) {
          const entry = xssIndexed.get(objectiveId);
          if (!entry) { report.missingSourceRows.push({ source: USERS_AUTH, table: xssTable, workshopKey: 'xss_workshop', objectiveId, field }); continue; }
          const location = `${USERS_AUTH}.${xssTable}[${entry.index}]`;
          const mapped = distinctContent(entry.row, location, tab);
          if (field === 'content') snapshot.solutions.push({ workshopKey: 'xss_workshop', objectiveId, content: mapped.content, provenance: [provenance(archiveDigest, USERS_AUTH, xssTable, entry.row, entry.index)] });
          else snapshot.solutionVisibility.push({ workshopKey: 'xss_workshop', objectiveId, enabled: mapped.enabled, provenance: [provenance(archiveDigest, USERS_AUTH, xssTable, entry.row, entry.index)] });
        }
      }
    }

    const csrfTable = 'csrf_workshop_objective_solutions';
    const csrfIds = Object.values(CSRF_TABS).flat();
    const csrfRows = rows(usersTables, csrfTable, USERS_AUTH, report);
    const csrfIndexed = indexUnique(csrfRows, (row, index) => {
      exactColumns(row, ['id', 'objective_id', 'exercise_id', 'title', 'hint', 'example', 'explanation', 'solutions_enabled', 'updated_at'], `${USERS_AUTH}.${csrfTable}[${index}]`);
      return row.objective_id;
    }, csrfIds, `${USERS_AUTH}.${csrfTable}`);
    for (const [tab, objectiveIds] of Object.entries(CSRF_TABS)) for (const objectiveId of objectiveIds) {
      const entry = csrfIndexed.get(objectiveId);
      if (!entry) {
        report.missingSourceRows.push({ source: USERS_AUTH, table: csrfTable, workshopKey: 'csrf_workshop', objectiveId, field: 'content_and_visibility' });
        continue;
      }
      const mapped = distinctContent(entry.row, `${USERS_AUTH}.${csrfTable}[${entry.index}]`, tab);
      const origin = provenance(archiveDigest, USERS_AUTH, csrfTable, entry.row, entry.index);
      snapshot.solutions.push({ workshopKey: 'csrf_workshop', objectiveId, content: mapped.content, provenance: [origin] });
      snapshot.solutionVisibility.push({ workshopKey: 'csrf_workshop', objectiveId, enabled: mapped.enabled, provenance: [origin] });
    }
    for (const retired of ['csrf_workshop_solutions', 'csrf_workshop_solution_visibility']) {
      if (Object.hasOwn(usersTables, retired) && usersTables[retired].length) report.unmappedTables.push({ source: USERS_AUTH, table: retired, rows: usersTables[retired].length, reason: 'retired_tab_solution_requires_review' });
    }
  }

  for (const [family, config] of Object.entries(FAMILY_CONFIG)) {
    const tables = sources[config.source]?.tables;
    if (!tables) {
      report.missingSourceTables.push({ source: config.source, table: config.contentTable });
      report.missingSourceTables.push({ source: config.source, table: config.visibilityTable });
      continue;
    }
    const contentRows = rows(tables, config.contentTable, config.source, report);
    const visibilityRows = rows(tables, config.visibilityTable, config.source, report);
    const contentIndex = indexUnique(contentRows, (row, index) => {
      const location = `${config.source}.${config.contentTable}[${index}]`;
      exactColumns(row, ['id', 'objective_id', ...GENERIC_FIELDS, 'updated_at'], location);
      return row.objective_id;
    }, config.objectiveIds, `${config.source}.${config.contentTable}`);
    const visibilityIndex = indexUnique(visibilityRows, (row, index) => {
      const location = `${config.source}.${config.visibilityTable}[${index}]`;
      exactColumns(row, config.visibilityColumns, location);
      return row.objective_id;
    }, config.objectiveIds, `${config.source}.${config.visibilityTable}`);
    for (const objectiveId of config.objectiveIds) {
      const contentEntry = contentIndex.get(objectiveId);
      if (contentEntry) {
        const location = `${config.source}.${config.contentTable}[${contentEntry.index}]`;
        snapshot.solutions.push({ workshopKey: family, objectiveId, content: genericContent(contentEntry.row, location), provenance: [provenance(archiveDigest, config.source, config.contentTable, contentEntry.row, contentEntry.index)] });
      } else report.missingSourceRows.push({ source: config.source, table: config.contentTable, workshopKey: family, objectiveId, field: 'content' });
      const visibilityEntry = visibilityIndex.get(objectiveId);
      if (visibilityEntry) {
        const location = `${config.source}.${config.visibilityTable}[${visibilityEntry.index}]`;
        snapshot.solutionVisibility.push({ workshopKey: family, objectiveId, enabled: genericVisibility(visibilityEntry.row, config.visibilityColumns, location), provenance: [provenance(archiveDigest, config.source, config.visibilityTable, visibilityEntry.row, visibilityEntry.index, { timestamp: config.visibilityColumns.includes('updated_at') ? 'updated_at' : 'enabled_at', actor: true })] });
      } else report.missingSourceRows.push({ source: config.source, table: config.visibilityTable, workshopKey: family, objectiveId, field: 'visibility' });
    }
  }

  const unused = Object.keys(resolutions).filter(key => !usedResolutions.has(key));
  if (unused.length) invalid('UNUSED_SOLUTION_RESOLUTION', unused[0]);
  report.requiresReview = report.conflicts.length > 0 || report.missingSourceTables.length > 0 || report.missingSourceRows.length > 0 || report.unmappedTables.length > 0;
  report.counts = { solutions: snapshot.solutions.length, solutionVisibility: snapshot.solutionVisibility.length, retainedLegacy: snapshot.retainedLegacy.length, legacySolutions: snapshot.legacySolutions.length, legacySolutionVisibility: snapshot.legacySolutionVisibility.length };
  return { snapshot, report };
}

module.exports = { FAMILY_CONFIG, XSS_TABS, CSRF_TABS, mapAdditionalPlatformSolutions, xssResolutionKey };
