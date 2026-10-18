'use strict';
const { normalizeArchiveOwnerBinding, normalizeOpaqueResolutions, mapOwnerKey } = require('./archive-owner-binding');
const { timestamp } = require('../../server/database/postgres/identityValidation');
const { WORKSHOP_OBJECTIVES } = require('../../server/config/workshopCatalog');
const COLUMNS = Object.freeze({
  mcp_workshop_progress: 'user_key objective_id completed completed_at created_at',
  mcp_workshop_tool_log: 'id user_key tool_name args result_summary outcome success created_at',
});
function reject(code) { const error = new Error(code); error.code = code; throw error; }
function integer(value) {
  if (value && typeof value === 'object' && Object.keys(value).sort().join(',') === 'type,value' && value.type === 'integer' && typeof value.value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value.value)) value = Number(value.value);
  if (!Number.isSafeInteger(value)) reject('INVALID_MCP_INTEGER');
  return value;
}
function text(value, nullable = false) {
  if (nullable && value === null) return null;
  if (typeof value !== 'string' || value.includes('\0')) reject('INVALID_MCP_TEXT');
  return value;
}
function mapMcpArchive(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(key => !['tables','archiveDigest','naiveTimestamps','review','ownerBinding','opaqueOwnerResolutions'].includes(key))) reject('INVALID_MCP_ARCHIVE');
  const {tables, archiveDigest, naiveTimestamps = 'reject', review} = raw;
  if (!/^[a-f0-9]{64}$/.test(archiveDigest || '')) reject('ARCHIVE_DIGEST_REQUIRED');
  if (!['UTC','reject'].includes(naiveTimestamps)) reject('INVALID_TIMESTAMP_POLICY');
  if (!tables || typeof tables !== 'object' || Array.isArray(tables)) reject('INVALID_ARCHIVE_TABLES');
  const binding = raw.ownerBinding ? normalizeArchiveOwnerBinding(raw.ownerBinding) : null;
  if (!binding && raw.opaqueOwnerResolutions !== undefined) reject('OWNER_RESOLUTIONS_WITHOUT_BINDING');
  const resolutions = binding ? normalizeOpaqueResolutions(raw.opaqueOwnerResolutions) : new Map();
  const usedResolutions = new Set();
  if (binding && binding.archiveDigest !== archiveDigest) reject('OWNER_ARCHIVE_MISMATCH');
  const stamp = value => {
    if (value === null) return null;
    text(value);
    if (!/(Z|[+-]\d{2}:\d{2})$/.test(value) && naiveTimestamps !== 'UTC') reject('AMBIGUOUS_TIMESTAMP');
    return timestamp(value, false);
  };
  const flag = value => { if (value === null) return null; const n = integer(value); if (![0,1].includes(n)) reject('INVALID_MCP_FLAG'); return n; };
  const snapshot = {progress: [], toolLog: [], provenance: []}, unmappedTables = [];
  for (const [table, rows] of Object.entries(tables)) {
    if (!Array.isArray(rows)) reject('INVALID_ARCHIVE_TABLE');
    if (!Object.hasOwn(COLUMNS,table) && rows.length) unmappedTables.push(table);
  }
  for (const [table, columns] of Object.entries(COLUMNS)) {
    if (!Object.hasOwn(tables,table)) reject('MISSING_MCP_TABLE');
    const seen = new Set();
    for (const row of tables[table]) {
      if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).sort().join(' ') !== columns.split(' ').sort().join(' ')) reject('UNMAPPED_MCP_COLUMNS');
      const sourceUserKey = text(row.user_key);
      if (resolutions.has(sourceUserKey)) usedResolutions.add(sourceUserKey);
      const userKey = binding ? mapOwnerKey(sourceUserKey, binding, { opaqueOwnerResolutions: raw.opaqueOwnerResolutions || [] }) : sourceUserKey;
      if (!userKey.length || userKey.length > 200) reject('INVALID_MCP_OWNER');
      let id;
      if (table === 'mcp_workshop_progress') {
        const objectiveId = text(row.objective_id);
        if (!WORKSHOP_OBJECTIVES.mcp_workshop.some(o => o.id === objectiveId)) reject('UNKNOWN_MCP_OBJECTIVE');
        id = JSON.stringify([userKey, objectiveId]);
        snapshot.progress.push({userKey, objectiveId, completed: flag(row.completed), completedAt: stamp(row.completed_at), createdAt: stamp(row.created_at)});
      } else {
        id = integer(row.id);
        if (id < 1 || id === Number.MAX_SAFE_INTEGER) reject('MCP_LOG_SEQUENCE_EXHAUSTED');
        snapshot.toolLog.push({id, userKey, toolName: text(row.tool_name), args: text(row.args,true), resultSummary: text(row.result_summary,true), outcome: text(row.outcome,true), success: flag(row.success), createdAt: stamp(row.created_at)});
      }
      if (seen.has(String(id))) reject('DUPLICATE_MCP_SOURCE_KEY');
      seen.add(String(id));
      snapshot.provenance.push({table, id: table === 'mcp_workshop_progress' ? JSON.stringify([sourceUserKey, row.objective_id]) : String(id), row: structuredClone(row)});
    }
  }
  if (!review || Object.keys(review).sort().join(',') !== 'archiveDigest,retainedTables' || review.archiveDigest !== archiveDigest || !Array.isArray(review.retainedTables) || review.retainedTables.some(v => typeof v !== 'string') || JSON.stringify([...review.retainedTables].sort()) !== JSON.stringify(unmappedTables.sort())) reject('ARCHIVE_BOUND_MCP_REVIEW_REQUIRED');
  if ([...resolutions.keys()].some(key => !usedResolutions.has(key))) reject('UNUSED_OPAQUE_OWNER_RESOLUTION');
  return {snapshot, report: {archiveDigest, identityMapSha256: binding?.identityMapSha256 || null, counts: {progress: snapshot.progress.length, toolLog: snapshot.toolLog.length}, retainedTables: unmappedTables, canonicalProgressImported: false}};
}
module.exports = {COLUMNS, mapMcpArchive};
