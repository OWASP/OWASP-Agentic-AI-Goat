'use strict';
const { normalizeArchiveOwnerBinding, normalizeOpaqueResolutions, mapOwnerKey } = require('./archive-owner-binding');
const { timestamp } = require('../../server/database/postgres/identityValidation');
const { WORKSHOP_OBJECTIVES } = require('../../server/config/workshopCatalog');
const FAMILIES = Object.freeze({
  finflow: { source: 'sensitive_info_workshop.db', workshop: 'sensitive_info_disclosure', progress: 'finflow_progress',
    columns: { finflow_progress: 'id user_id objective_id completed completed_at', finflow_tool_log: 'id user_id tool_name params result_summary security_flag mode timestamp' },
    external: ['finflow_solutions', 'finflow_solution_visibility'] },
  supply_chain: { source: 'supply_chain_workshop.db', workshop: 'supply_chain_rce', progress: 'sc_progress',
    columns: { sc_progress: 'id user_id objective_id status completed_at' }, external: ['sc_solutions', 'sc_solution_visibility'] },
});
function reject(code, location) { const error = new Error(code); error.code = code; error.location = location; throw error; }
function integer(value, location) {
  if (value && typeof value === 'object' && Object.keys(value).sort().join(',') === 'type,value' && value.type === 'integer' && typeof value.value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value.value)) value = Number(value.value);
  if (!Number.isSafeInteger(value) || value < 0) reject('UNSAFE_WORKSHOP_INTEGER', location);
  return value;
}
function text(value, location, nullable = false) {
  if (nullable && value === null) return null;
  if (typeof value !== 'string' || value.includes('\0') || (!nullable && !value.length)) reject('INVALID_WORKSHOP_TEXT', location);
  return value;
}
function mapAgentWorkshopArchive({ family, tables, archiveDigest, naiveTimestamps = 'reject', ownerBinding, opaqueOwnerResolutions }) {
  if (!Object.hasOwn(FAMILIES, family) || !tables || typeof tables !== 'object' || Array.isArray(tables)) reject('INVALID_AGENT_WORKSHOP_ARCHIVE');
  if (typeof archiveDigest !== 'string' || !/^[a-f0-9]{64}$/.test(archiveDigest)) reject('ARCHIVE_DIGEST_REQUIRED');
  if (!['UTC', 'reject'].includes(naiveTimestamps)) reject('INVALID_TIMESTAMP_POLICY');
  const binding = ownerBinding ? normalizeArchiveOwnerBinding(ownerBinding) : null;
  if (!binding && opaqueOwnerResolutions !== undefined) reject('OWNER_RESOLUTIONS_WITHOUT_BINDING');
  const resolutions = binding ? normalizeOpaqueResolutions(opaqueOwnerResolutions) : new Map();
  const usedResolutions = new Set();
  if (binding && binding.archiveDigest !== archiveDigest) reject('OWNER_ARCHIVE_MISMATCH');
  const config = FAMILIES[family], catalog = WORKSHOP_OBJECTIVES[config.workshop].map(row => row.id);
  const snapshot = { family, progress: [], toolLog: [], sourceRows: [] };
  const report = { archiveDigest, family, identityMapSha256: binding?.identityMapSha256 || null, counts: {}, unmappedTables: [], externalSolutionTables: [], requiresReview: false, canonicalProgressImported: false };
  const stamp = (value, location, nullable = true) => {
    if (value === null && nullable) return null;
    text(value, location);
    if (!/(Z|[+-]\d{2}:\d{2})$/.test(value) && naiveTimestamps !== 'UTC') reject('AMBIGUOUS_TIMESTAMP', location);
    return timestamp(value, false);
  };
  for (const [table, entries] of Object.entries(tables)) {
    if (!Array.isArray(entries)) reject('INVALID_ARCHIVE_TABLE', table);
    if (!Object.hasOwn(config.columns, table)) {
      const target = config.external.includes(table) ? report.externalSolutionTables : report.unmappedTables;
      target.push({ source: config.source, table, rows: entries.length });
    }
  }
  for (const [table, columns] of Object.entries(config.columns)) {
    if (!Object.hasOwn(tables, table)) reject('MISSING_WORKSHOP_TABLE', table);
    const seenIds = new Set(), seenOwners = new Set();
    for (const [index, source] of tables[table].entries()) {
      const at = `${table}[${index}]`;
      if (!source || typeof source !== 'object' || Array.isArray(source) || Object.keys(source).sort().join(' ') !== columns.split(' ').sort().join(' ')) reject('UNMAPPED_WORKSHOP_COLUMNS', at);
      const id = integer(source.id, at + '.id');
      if (!id || id === Number.MAX_SAFE_INTEGER || seenIds.has(id)) reject('INVALID_OR_DUPLICATE_SOURCE_ID', at);
      seenIds.add(id);
      let owner = source.user_id;
      if (owner && typeof owner === 'object' && owner.type === 'integer' && Object.keys(owner).sort().join(',') === 'type,value' && typeof owner.value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(owner.value)) owner = owner.value;
      owner = text(owner, at + '.user_id');
      if (owner.length > 200) reject('OWNER_KEY_TOO_LONG', at);
      if (resolutions.has(owner)) usedResolutions.add(owner);
      if (binding) owner = mapOwnerKey(owner, binding, { opaqueOwnerResolutions: opaqueOwnerResolutions });
      if (table === config.progress) {
        const objectiveId = text(source.objective_id, at + '.objective_id');
        if (!catalog.includes(objectiveId)) reject('UNKNOWN_WORKSHOP_OBJECTIVE', at);
        const key = JSON.stringify([owner, objectiveId]);
        if (seenOwners.has(key)) reject('DUPLICATE_WORKSHOP_PROGRESS', at);
        seenOwners.add(key);
        let completed;
        if (family === 'finflow') { const flag = integer(source.completed, at); if (![0, 1].includes(flag)) reject('INVALID_PROGRESS_FLAG', at); completed = flag === 1; }
        else { if (!['pending', 'completed'].includes(source.status)) reject('INVALID_PROGRESS_STATUS', at); completed = source.status === 'completed'; }
        const completedAt = stamp(source.completed_at, at + '.completed_at');
        if (completed && completedAt === null) reject('HISTORICAL_COMPLETION_TIMESTAMP_REQUIRED', at);
        snapshot.progress.push({ sourceId: id, userId: owner, objectiveId, completed, completedAt });
      } else {
        if (id >= 2147483647) reject('TOOL_LOG_SEQUENCE_EXHAUSTED', at);
        snapshot.toolLog.push({ id, userId: owner, toolName: text(source.tool_name, at), params: text(source.params, at, true),
          resultSummary: text(source.result_summary, at, true), securityFlag: text(source.security_flag, at, true), mode: text(source.mode, at, true), timestamp: stamp(source.timestamp, at, false) });
      }
      snapshot.sourceRows.push({ sourceTable: table, sourceId: String(id), row: structuredClone(source) });
    }
    report.counts[table] = tables[table].length;
  }
  if ([...resolutions.keys()].some(key => !usedResolutions.has(key))) reject('UNUSED_OPAQUE_OWNER_RESOLUTION');
  report.requiresReview = report.unmappedTables.some(row => row.rows) || report.externalSolutionTables.some(row => row.rows);
  return { snapshot, report };
}
module.exports = { FAMILIES, mapAgentWorkshopArchive };
