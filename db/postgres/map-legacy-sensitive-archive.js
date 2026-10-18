'use strict';

const { timestamp } = require('../../server/database/postgres/identityValidation');

const SOURCE = 'sensitive_info.db';
const COLUMNS = Object.freeze({
  documents: 'id filename file_path category access_level description uploaded_by created_at',
  file_access_logs: 'id user_id file_path access_type status ip_address user_agent timestamp',
  challenge_progress: 'id user_id challenge_type flag_found exploit_used payload success run_id judgment timestamp',
});
const SUPPORTED = new Set(['documents', 'file_access_logs']);
const HISTORICAL_DISPOSITIONS = Object.freeze([
  { scope: 'challenge_progress', policy: 'retain_archive_only_no_judge_receipts' },
  { scope: 'ssi_templates', policy: 'retain_archive_only_no_native_equivalent' },
  { scope: 'historical_reset', policy: 'retain_archive_only_no_reset_replay' },
  { scope: 'historical_sessions', policy: 'retain_archive_only_no_session_replay' },
  { scope: 'asset_references', policy: 'preserve_references_without_importing_assets' },
]);

function reject(code, location) {
  const error = new Error(code);
  error.code = code;
  if (location) error.location = location;
  throw error;
}

function integer(value, location, { positive = false } = {}) {
  if (value && typeof value === 'object' && !Array.isArray(value)
      && Object.keys(value).sort().join(',') === 'type,value'
      && value.type === 'integer' && typeof value.value === 'string'
      && /^-?(0|[1-9][0-9]*)$/.test(value.value)) value = Number(value.value);
  if (!Number.isSafeInteger(value) || value < 0 || (positive && value < 1)) reject('INVALID_SENSITIVE_INTEGER', location);
  return value;
}

function text(value, location, nullable = false) {
  if (nullable && value === null) return null;
  if (typeof value !== 'string' || value.includes('\0')) reject('INVALID_SENSITIVE_TEXT', location);
  return value;
}

function stamp(value, location, naiveTimestamps) {
  if (value === null) return null;
  text(value, location);
  if (!/(Z|[+-]\d{2}:\d{2})$/.test(value) && naiveTimestamps !== 'UTC') reject('AMBIGUOUS_SENSITIVE_TIMESTAMP', location);
  try { return timestamp(value, false); } catch { reject('INVALID_SENSITIVE_TIMESTAMP', location); }
}

function exact(row, columns, location) {
  if (!row || typeof row !== 'object' || Array.isArray(row)
      || Object.keys(row).sort().join(',') !== columns.split(' ').sort().join(',')) reject('UNMAPPED_SENSITIVE_COLUMNS', location);
}

function identityMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject('SENSITIVE_IDENTITY_MAP_REQUIRED', 'identityMap');
  const result = new Map();
  for (const [source, target] of Object.entries(value)) {
    if (!/^[1-9][0-9]*$/.test(source)) reject('INVALID_SENSITIVE_IDENTITY_SOURCE', `identityMap.${source}`);
    result.set(integer(Number(source), `identityMap.${source}`, { positive: true }),
      target === null ? null : integer(target, `identityMap.${source}`, { positive: true }));
  }
  return result;
}

function mappedOwner(value, location, ids, report, nullable = false) {
  if (value === null && nullable) return null;
  const sourceId = integer(value, location, { positive: true });
  if (!ids.has(sourceId)) reject('UNMAPPED_SENSITIVE_IDENTITY', location);
  const targetId = ids.get(sourceId);
  report.identityMappings.push({ sourceId, targetId, location });
  return targetId;
}

function reviewRows(rawTables) {
  const retained = [];
  for (const [table, rows] of Object.entries(rawTables)) {
    if (!SUPPORTED.has(table) && Array.isArray(rows) && rows.length) retained.push({ source: SOURCE, table, rows: rows.length, policy: table === 'challenge_progress' ? 'retain_archive_only_no_judge_receipts' : 'retain_archive_only_no_native_equivalent' });
  }
  return retained;
}

function canonicalReview(review, archiveDigest, retainedTables) {
  if (!review || typeof review !== 'object' || Array.isArray(review)
      || Object.keys(review).sort().join(',') !== 'archiveDigest,decisions,retainedTables'
      || review.archiveDigest !== archiveDigest || !Array.isArray(review.retainedTables) || !Array.isArray(review.decisions)) reject('ARCHIVE_BOUND_SENSITIVE_REVIEW_REQUIRED');
  const expectedRetained = retainedTables.map(({ source, table, rows, policy }) => JSON.stringify([source, table, rows, policy])).sort();
  const actualRetained = review.retainedTables.map(row => {
    if (!row || Object.keys(row).sort().join(',') !== 'policy,rows,source,table' || row.source !== SOURCE || !Number.isSafeInteger(row.rows) || row.rows < 1 || typeof row.table !== 'string' || typeof row.policy !== 'string') reject('INVALID_SENSITIVE_RETAINED_DECISION');
    return JSON.stringify([row.source, row.table, row.rows, row.policy]);
  }).sort();
  if (JSON.stringify(expectedRetained) !== JSON.stringify(actualRetained)) reject('INCOMPLETE_OR_STALE_SENSITIVE_REVIEW');
  const expectedDecisions = HISTORICAL_DISPOSITIONS.map(row => JSON.stringify([row.scope, row.policy])).sort();
  const actualDecisions = review.decisions.map(row => {
    if (!row || Object.keys(row).sort().join(',') !== 'policy,scope' || typeof row.scope !== 'string' || typeof row.policy !== 'string') reject('INVALID_SENSITIVE_SEMANTIC_DECISION');
    return JSON.stringify([row.scope, row.policy]);
  }).sort();
  if (JSON.stringify(expectedDecisions) !== JSON.stringify(actualDecisions)) reject('INCOMPLETE_OR_STALE_SENSITIVE_SEMANTICS');
}

function mapLegacySensitiveArchive(raw = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
      || Object.keys(raw).some(key => !['tables', 'archiveDigest', 'identityMap', 'naiveTimestamps', 'review'].includes(key))) reject('INVALID_SENSITIVE_ARCHIVE_INPUT');
  const { tables, archiveDigest, naiveTimestamps = 'reject' } = raw;
  if (!tables || typeof tables !== 'object' || Array.isArray(tables)) reject('INVALID_SENSITIVE_ARCHIVE_TABLES');
  if (!/^[a-f0-9]{64}$/.test(archiveDigest || '')) reject('ARCHIVE_DIGEST_REQUIRED');
  if (!['reject', 'UTC'].includes(naiveTimestamps)) reject('INVALID_TIMESTAMP_POLICY');
  const ids = identityMap(raw.identityMap);
  for (const [table, rows] of Object.entries(tables)) if (!Array.isArray(rows)) reject('INVALID_ARCHIVE_TABLE', table);
  for (const required of SUPPORTED) if (!Object.hasOwn(tables, required)) reject('MISSING_SENSITIVE_TABLE', required);

  const report = { archiveDigest, counts: {}, identityMappings: [], retainedTables: reviewRows(tables), assetReferences: [], semanticDispositions: [...HISTORICAL_DISPOSITIONS], canonicalProgressImported: false };
  const snapshot = { documents: [], accessLogs: [], provenance: [] };
  const seenDocumentIds = new Set(), seenAccessIds = new Set(), seenFilenames = new Set(), seenAccessKeys = new Set();

  for (const source of tables.documents) {
    const at = `documents[${snapshot.documents.length}]`; exact(source, COLUMNS.documents, at);
    const id = integer(source.id, `${at}.id`, { positive: true });
    if (seenDocumentIds.has(id) || id === 2147483647) reject('DUPLICATE_OR_EXHAUSTED_SENSITIVE_DOCUMENT_ID', at);
    seenDocumentIds.add(id);
    const filename = text(source.filename, `${at}.filename`); if (!filename.length || seenFilenames.has(filename)) reject('DUPLICATE_SENSITIVE_FILENAME', at); seenFilenames.add(filename);
    const row = {
      id, filename, filePath: text(source.file_path, `${at}.file_path`), category: text(source.category, `${at}.category`),
      accessLevel: text(source.access_level, `${at}.access_level`, true), description: text(source.description, `${at}.description`, true),
      uploadedBy: mappedOwner(source.uploaded_by, `${at}.uploaded_by`, ids, report, true), createdAt: stamp(source.created_at, `${at}.created_at`, naiveTimestamps),
    };
    report.assetReferences.push({ sourceTable: 'documents', sourceId: String(id), filePath: row.filePath, imported: false });
    snapshot.documents.push(row); snapshot.provenance.push({ sourceFile: SOURCE, sourceTable: 'documents', sourceId: String(id), row: structuredClone(source) });
  }
  report.counts.documents = snapshot.documents.length;

  for (const source of tables.file_access_logs) {
    const at = `file_access_logs[${snapshot.accessLogs.length}]`; exact(source, COLUMNS.file_access_logs, at);
    const id = integer(source.id, `${at}.id`, { positive: true });
    if (seenAccessIds.has(id) || id === Number.MAX_SAFE_INTEGER) reject('DUPLICATE_OR_EXHAUSTED_SENSITIVE_ACCESS_ID', at);
    seenAccessIds.add(id);
    const row = {
      id, userId: mappedOwner(source.user_id, `${at}.user_id`, ids, report, true), filePath: text(source.file_path, `${at}.file_path`),
      accessType: text(source.access_type, `${at}.access_type`, true), status: text(source.status, `${at}.status`, true),
      ipAddress: text(source.ip_address, `${at}.ip_address`, true), userAgent: text(source.user_agent, `${at}.user_agent`, true), timestamp: stamp(source.timestamp, `${at}.timestamp`, naiveTimestamps),
    };
    const key = JSON.stringify([row.userId, row.id]); if (seenAccessKeys.has(key)) reject('DUPLICATE_SENSITIVE_ACCESS_KEY'); seenAccessKeys.add(key);
    snapshot.accessLogs.push(row); snapshot.provenance.push({ sourceFile: SOURCE, sourceTable: 'file_access_logs', sourceId: String(id), row: structuredClone(source) });
  }
  report.counts.file_access_logs = snapshot.accessLogs.length;
  for (const [table, rows] of Object.entries(tables)) if (!SUPPORTED.has(table)) report.counts[table] = rows.length;
  canonicalReview(raw.review, archiveDigest, report.retainedTables);
  return { snapshot, report };
}

module.exports = { SOURCE, COLUMNS, HISTORICAL_DISPOSITIONS, mapLegacySensitiveArchive };
