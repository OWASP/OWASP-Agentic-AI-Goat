'use strict';
const { normalizeArchiveOwnerBinding, assertVerifiedArchiveOwnerBinding } = require('./archive-owner-binding');
const { createHash } = require('node:crypto');
const { withTransaction } = require('../../server/database/postgres');
const { readVerifiedLegacyArchive } = require('./read-platform-archive');
const { WORKSHOP_OBJECTIVES } = require('../../server/config/workshopCatalog');
const { FAMILIES, mapAgentWorkshopArchive } = require('./map-agent-workshop-archive');
function reject(code) { const error = new Error(code); error.code = code; throw error; }
function prepareAgentWorkshopImport(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(key => !['family','tables','archiveDigest','naiveTimestamps','review','ownerBinding','opaqueOwnerResolutions'].includes(key))) reject('INVALID_AGENT_WORKSHOP_IMPORT');
  const mapped = mapAgentWorkshopArchive(raw);
  const decisions = [...mapped.report.unmappedTables.filter(row => row.rows).map(row => ({ table: row.table, disposition: 'retain_archive_no_native_equivalent' })),
    ...mapped.report.externalSolutionTables.filter(row => row.rows).map(row => ({ table: row.table, disposition: 'retain_archive_import_separately_to_platform_solutions' }))];
  const review = raw.review;
  if (!review || Object.keys(review).sort().join(',') !== 'archiveDigest,tables' || review.archiveDigest !== raw.archiveDigest || !Array.isArray(review.tables)) reject('ARCHIVE_BOUND_WORKSHOP_REVIEW_REQUIRED');
  const expected = decisions.map(row => JSON.stringify([row.table,row.disposition])).sort();
  const actual = review.tables.map(row => {
    if (!row || Object.keys(row).sort().join(',') !== 'disposition,table') reject('INVALID_WORKSHOP_REVIEW');
    return JSON.stringify([row.table,row.disposition]);
  }).sort();
  if (JSON.stringify(expected) !== JSON.stringify(actual)) reject('INCOMPLETE_OR_STALE_WORKSHOP_REVIEW');
  return { ...mapped, decisions };
}
async function readAgentWorkshopArchive({ archive, family, naiveTimestamps = 'reject' }) {
  if (!Object.hasOwn(FAMILIES,family)) reject('UNKNOWN_WORKSHOP_FAMILY');
  const verified = await readVerifiedLegacyArchive({archive});
  const source = verified.sources[FAMILIES[family].source];
  if (!source) reject('MISSING_WORKSHOP_ARCHIVE_SOURCE');
  const input = { family, tables: source.tables, archiveDigest: verified.archiveDigest, naiveTimestamps };
  return { input, ...mapAgentWorkshopArchive(input) };
}
async function importAgentWorkshopArchive(pool, raw, { apply = false, ownerProof } = {}) {
  if (typeof apply !== 'boolean') reject('INVALID_APPLY_OPTION');
  // Capture one immutable-by-ownership request before pool checkout can yield.
  // Every decision, row and provenance digest below derives from this private copy.
  const captured = structuredClone(raw);
  const { snapshot, report, decisions } = prepareAgentWorkshopImport(captured);
  const binding = normalizeArchiveOwnerBinding(captured.ownerBinding);
  assertVerifiedArchiveOwnerBinding(ownerProof, binding);
  const family = snapshot.family, config = FAMILIES[family];
  return withTransaction(pool, async client => {
    await client.query('SELECT pg_advisory_xact_lock(1886610804,2)');
    const tables = ['objectives','progress','import_provenance','import_batches', ...(family === 'finflow' ? ['tool_log'] : [])];
    await client.query(`LOCK TABLE ${tables.map(table=>`${family}.${table}`).join(',')} IN ACCESS EXCLUSIVE MODE`);
    for (const table of tables) if ((await client.query(`SELECT EXISTS(SELECT 1 FROM ${family}.${table}) AS populated`)).rows[0].populated) reject('WORKSHOP_IMPORT_REQUIRES_EMPTY_TARGET');
    await client.query('SAVEPOINT agent_workshop_import');
    for (const [ordinal, row] of WORKSHOP_OBJECTIVES[config.workshop].entries()) await client.query(`INSERT INTO ${family}.objectives(objective_id,ordinal) VALUES($1,$2)`,[row.id,ordinal]);
    for (const row of snapshot.progress) {
      if (family === 'finflow') await client.query('INSERT INTO finflow.progress(user_id,objective_id,completed,completed_at) VALUES($1,$2,$3,$4)',[row.userId,row.objectiveId,row.completed,row.completedAt]);
      else await client.query('INSERT INTO supply_chain.progress(user_id,objective_id,status,completed_at) VALUES($1,$2,$3,$4)',[row.userId,row.objectiveId,row.completed?'completed':'pending',row.completedAt]);
    }
    for (const row of snapshot.toolLog) await client.query(`INSERT INTO finflow.tool_log(id,user_id,tool_name,params,result_summary,security_flag,mode,timestamp)
      OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,[row.id,row.userId,row.toolName,row.params,row.resultSummary,row.securityFlag,row.mode,row.timestamp]);
    for (const row of snapshot.sourceRows) await client.query(`INSERT INTO ${family}.import_provenance(archive_sha256,source_table,source_id,source_row) VALUES($1,$2,$3,$4::jsonb)`,[captured.archiveDigest,row.sourceTable,row.sourceId,JSON.stringify(row.row)]);
    const retainedMetadata = decisions.map(decision => ({
      tableSha256: createHash('sha256').update(decision.table).digest('hex'),
      rows: captured.tables[decision.table].length, disposition: decision.disposition,
    }));
    await client.query(`INSERT INTO ${family}.import_batches
      (archive_sha256,importer_version,timestamp_policy,counts,retained_decisions,identity_map_sha256) VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6)`,
    [captured.archiveDigest,'agent-workshop-v1',captured.naiveTimestamps || 'reject',JSON.stringify(report.counts),JSON.stringify(retainedMetadata),binding.identityMapSha256]);
    if (family === 'finflow') {
      const next = snapshot.toolLog.reduce((max,row)=>Math.max(max,row.id),0)+1;
      await client.query(`ALTER TABLE finflow.tool_log ALTER COLUMN id RESTART WITH ${next}`);
    }
    if (!apply) await client.query('ROLLBACK TO SAVEPOINT agent_workshop_import');
    return { applied: apply, status: apply?'imported':'validated', family, archiveDigest: captured.archiveDigest,
      identityMapSha256: binding.identityMapSha256, counts: report.counts, retainedNotImported: decisions, canonicalProgressImported: false, provenanceRows: snapshot.sourceRows.length };
  });
}
module.exports = { prepareAgentWorkshopImport, readAgentWorkshopArchive, importAgentWorkshopArchive };
