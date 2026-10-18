'use strict';

const { WORKSHOP_OBJECTIVES, toWorkshopKey, toChallengeKey } = require('../../server/config/workshopCatalog');
// SecureShop grading was introduced with immutable PostgreSQL launch evidence.
// A legacy SQLite row cannot establish that provenance or enable its objectives.
const LEGACY_CATALOG = Object.fromEntries(Object.entries(WORKSHOP_OBJECTIVES)
  .filter(([key]) => key !== 'secureshop_agent_security'));

const { WORKSHOP_MODE_CATALOG } = require('../../server/services/workshopModeService');

const COLUMNS = Object.freeze({
  challenge_visibility: 'id challenge_key challenge_name challenge_description category difficulty is_visible show_solutions show_hints route updated_by updated_at',
  workshop_objective_visibility: 'id workshop_key objective_id is_enabled updated_by updated_at',
  workshop_hint_visibility: 'id workshop_key objective_id is_enabled updated_by updated_at',
  workshop_hints: 'id workshop_key objective_id title hints',
  workshop_objectives_progress: 'id user_id workshop_key objective_id objective_label objective_category completed completed_at created_at updated_at',
  workshop_time_tracking: 'id user_id workshop_key session_start last_heartbeat duration_seconds',
  workshop_user_modes: 'user_id workshop_key mode created_at updated_at',
});

function invalid(code, location) {
  const error = new Error(code);
  error.code = code;
  error.location = location;
  throw error;
}
function flag(value, location) {
  if (value !== 0 && value !== 1) invalid('INVALID_BOOLEAN_FLAG', location);
  return value === 1;
}
function integer(value, location, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum || value > 2147483647) invalid('INVALID_INTEGER', location);
  return value;
}
function text(value, location, nullable = false) {
  if (nullable && value === null) return null;
  if (typeof value !== 'string' || value.includes('\0')) invalid('INVALID_TEXT', location);
  return value;
}
function timestamp(value, location, naiveTimestamps) {
  text(value, location);
  const shape = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(Z|[+-]\d{2}:\d{2})?$/.exec(value);
  if (!shape || (!shape[1] && naiveTimestamps !== 'UTC') || !Number.isFinite(Date.parse(shape[1] ? value : value.replace(' ', 'T') + 'Z'))) invalid('AMBIGUOUS_TIMESTAMP', location);
  const [hour, minute, second] = value.slice(11, 19).split(':').map(Number);
  if (hour > 23 || minute > 59 || second > 59) invalid('INVALID_CLOCK_TIME', location);
  const [year, month, day] = value.slice(0, 10).split('-').map(Number);
  const calendar = new Date(Date.UTC(year, month - 1, day));
  if (calendar.getUTCFullYear() !== year || calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day) invalid('INVALID_CALENDAR_DATE', location);
  return shape[1] ? value : value.replace(' ', 'T') + 'Z';
}

/** Map already decoded archive rows only. Does not open files, connect, seed, or award judgments. */
function mapPlatformSnapshot({ tables, identityMap, archiveDigest, naiveTimestamps = 'reject' }) {
  if (!tables || typeof tables !== 'object' || Array.isArray(tables) || !identityMap || typeof identityMap !== 'object' || Array.isArray(identityMap)) invalid('INVALID_MAPPING_INPUT');
  if (!/^[a-f0-9]{64}$/.test(archiveDigest || '')) invalid('ARCHIVE_DIGEST_REQUIRED');
  if (!['reject', 'UTC'].includes(naiveTimestamps)) invalid('INVALID_TIMESTAMP_POLICY');
  const mappedIds = new Set();
  for (const [source, target] of Object.entries(identityMap)) {
    if (!source) invalid('INVALID_IDENTITY_MAP');
    integer(target, 'identityMap', 1);
    if (mappedIds.has(target)) invalid('AMBIGUOUS_IDENTITY_MERGE');
    mappedIds.add(target);
  }
  const owner = (value, location) => {
    if (typeof value !== 'string' && !Number.isSafeInteger(value)) invalid('INVALID_SOURCE_IDENTITY', location);
    const key = String(value);
    if (!Object.hasOwn(identityMap, key)) invalid('UNMAPPED_IDENTITY', location);
    return identityMap[key];
  };
  const workshop = (value, location) => {
    text(value, location);
    const key = toWorkshopKey(value);
    if (!Object.hasOwn(LEGACY_CATALOG, key)) invalid('UNKNOWN_WORKSHOP', location);
    return key;
  };
  const objective = (row, location) => {
    const workshopKey = workshop(row.workshop_key, location);
    if (!LEGACY_CATALOG[workshopKey].some(item => item.id === row.objective_id)) invalid('UNKNOWN_OBJECTIVE', location);
    return { workshopKey, objectiveId: row.objective_id };
  };
  const provenance = (table, row, index) => ({ archiveDigest, source: 'users_auth.db', table, rowId: row.id ?? null, rowIndex: index, kind: 'legacy_import' });
  const snapshot = { version: 1, exercises: [], objectiveVisibility: [], hintVisibility: [], hints: [], historicalCompletions: [], timeTracking: [], modes: [] };
  const retainedRows = [];
  for (const [table, columnsText] of Object.entries(COLUMNS)) {
    if (!Array.isArray(tables[table])) invalid('REQUIRED_TABLE_MISSING', table);
    const columns = columnsText.split(' '), keys = new Set(), rowIds = new Set();
    for (const [index, row] of tables[table].entries()) {
      const location = `${table}[${index}]`;
      if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).length !== columns.length || columns.some(column => !Object.hasOwn(row, column))) invalid('UNMAPPED_COLUMNS', location);
      if (Object.hasOwn(row, 'id')) {
        integer(row.id, location + '.id', 1);
        if (rowIds.has(row.id)) invalid('DUPLICATE_SOURCE_ID', location);
        rowIds.add(row.id);
      }
      const origin = provenance(table, row, index);
      let key;
      if (table === 'challenge_visibility') {
        const workshopKey = workshop(row.challenge_key, location);
        key = workshopKey;
        snapshot.exercises.push({ workshopKey, challengeKey: toChallengeKey(workshopKey), name: text(row.challenge_name, location), description: text(row.challenge_description, location, true), category: text(row.category, location, true), difficulty: text(row.difficulty, location, true), route: text(row.route, location, true), visible: flag(row.is_visible, location), showHints: flag(row.show_hints, location), showSolutions: flag(row.show_solutions, location), updatedBy: row.updated_by === null ? null : owner(row.updated_by, location), updatedAt: timestamp(row.updated_at, location, naiveTimestamps), provenance: origin });
      } else if (table === 'workshop_user_modes') {
        const workshopKey = workshop(row.workshop_key, location), userId = owner(row.user_id, location);
        if (!WORKSHOP_MODE_CATALOG[workshopKey]?.allowedModes.includes(row.mode)) invalid('INVALID_MODE', location);
        key = JSON.stringify([userId, workshopKey]);
        snapshot.modes.push({ userId, workshopKey, mode: row.mode, createdAt: timestamp(row.created_at, location, naiveTimestamps), updatedAt: timestamp(row.updated_at, location, naiveTimestamps), provenance: origin });
      } else if (table === 'workshop_time_tracking') {
        key = row.id;
        snapshot.timeTracking.push({ id: row.id, userId: owner(row.user_id, location), workshopKey: workshop(row.workshop_key, location), sessionStart: timestamp(row.session_start, location, naiveTimestamps), lastHeartbeat: timestamp(row.last_heartbeat, location, naiveTimestamps), durationSeconds: integer(row.duration_seconds, location), provenance: origin });
      } else {
        const scope = objective(row, location);
        key = JSON.stringify([scope.workshopKey, scope.objectiveId]);
        if (table === 'workshop_objectives_progress') {
          const userId = owner(row.user_id, location);
          key = JSON.stringify([userId, scope.workshopKey, scope.objectiveId]);
          const completed = flag(row.completed, location);
          if (completed) snapshot.historicalCompletions.push({ ...scope, userId, completedAt: timestamp(row.completed_at, location, naiveTimestamps), updatedAt: timestamp(row.updated_at, location, naiveTimestamps), sourceLabel: text(row.objective_label, location, true), sourceCategory: text(row.objective_category, location, true), sourceCreatedAt: timestamp(row.created_at, location, naiveTimestamps), provenance: origin });
          else retainedRows.push({ ...origin, reason: 'incomplete_progress_does_not_award_credit' });
        } else if (table === 'workshop_hints') {
          const raw = text(row.hints, location);
          let hints; try { hints = JSON.parse(raw); } catch { invalid('INVALID_HINT_JSON', location); }
          if (!Array.isArray(hints) || hints.some(item => typeof item !== 'string')) invalid('INVALID_HINT_SHAPE', location);
          snapshot.hints.push({ ...scope, title: text(row.title, location, true), hints, rawHints: raw, provenance: origin });
        } else {
          const target = table === 'workshop_hint_visibility' ? snapshot.hintVisibility : snapshot.objectiveVisibility;
          target.push({ ...scope, enabled: flag(row.is_enabled, location), updatedBy: row.updated_by === null ? null : owner(row.updated_by, location), updatedAt: timestamp(row.updated_at, location, naiveTimestamps), provenance: origin });
        }
      }
      if (keys.has(key)) invalid('CONFLICTING_SOURCE_ROWS', location);
      keys.add(key);
    }
  }
  const unmappedTables = Object.keys(tables).filter(table => !Object.hasOwn(COLUMNS, table)).map(table => {
    if (!Array.isArray(tables[table])) invalid('INVALID_UNMAPPED_TABLE', table);
    return { table, rows: tables[table].length, reason: /solution/.test(table) ? 'solution_precedence_requires_review' : 'outside_adapter_scope' };
  });
  const exerciseKeys = new Set(snapshot.exercises.map(row => row.workshopKey));
  const visibilityKeys = new Set(snapshot.objectiveVisibility.map(row => JSON.stringify([row.workshopKey, row.objectiveId])));
  const hintKeys = new Set(snapshot.hintVisibility.map(row => JSON.stringify([row.workshopKey, row.objectiveId])));
  const missingCatalogRows = { exercises: [], objectiveVisibility: [], hintVisibility: [] };
  for (const [workshopKey, objectives] of Object.entries(LEGACY_CATALOG)) {
    if (!exerciseKeys.has(workshopKey)) missingCatalogRows.exercises.push(workshopKey);
    for (const { id: objectiveId } of objectives) {
      const key = JSON.stringify([workshopKey, objectiveId]);
      if (!visibilityKeys.has(key)) missingCatalogRows.objectiveVisibility.push({ workshopKey, objectiveId });
      if (!hintKeys.has(key)) missingCatalogRows.hintVisibility.push({ workshopKey, objectiveId });
    }
  }
  const missingDefaults = Object.values(missingCatalogRows).some(rows => rows.length > 0);
  return { snapshot, report: { unmappedTables, retainedRows, missingCatalogRows, requiresReview: missingDefaults || unmappedTables.some(table => table.rows > 0), naiveTimestamps, counts: Object.fromEntries(Object.entries(snapshot).filter(([, rows]) => Array.isArray(rows)).map(([key, rows]) => [key, rows.length])) } };
}
module.exports = { COLUMNS, mapPlatformSnapshot };
