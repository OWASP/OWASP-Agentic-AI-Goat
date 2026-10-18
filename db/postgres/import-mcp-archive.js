'use strict';
const {normalizeArchiveOwnerBinding, assertVerifiedArchiveOwnerBinding} = require('./archive-owner-binding');
const {createHash} = require('node:crypto');
const {withTransaction} = require('../../server/database/postgres');
const {readVerifiedLegacyArchive} = require('./read-platform-archive');
const {mapMcpArchive} = require('./map-mcp-archive');
async function readMcpArchive({archive, naiveTimestamps = 'reject'}) {
  const verified = await readVerifiedLegacyArchive({archive});
  if (!verified.sources['mcp_workshop.db']) throw Object.assign(new Error('MISSING_MCP_SOURCE'), {code:'MISSING_MCP_SOURCE'});
  return {tables: verified.sources['mcp_workshop.db'].tables, archiveDigest: verified.archiveDigest, naiveTimestamps};
}
async function importMcpArchive(pool, raw, {apply = false, ownerProof} = {}) {
  if (typeof apply !== 'boolean') throw new TypeError('Invalid apply option');
  const captured = structuredClone(raw), {snapshot,report} = mapMcpArchive(captured);
  const binding = normalizeArchiveOwnerBinding(captured.ownerBinding);
  assertVerifiedArchiveOwnerBinding(ownerProof, binding);
  return withTransaction(pool, async client => {
    await client.query('SELECT pg_advisory_xact_lock(1886610804,2)');
    await client.query('LOCK TABLE mcp.progress,mcp.tool_log,mcp.import_provenance,mcp.import_batches IN ACCESS EXCLUSIVE MODE');
    for (const table of ['progress','tool_log','import_provenance','import_batches']) if ((await client.query(`SELECT EXISTS(SELECT 1 FROM mcp.${table}) AS populated`)).rows[0].populated) throw Object.assign(new Error('MCP_IMPORT_REQUIRES_EMPTY_TARGET'), {code:'MCP_IMPORT_REQUIRES_EMPTY_TARGET'});
    await client.query('SAVEPOINT mcp_archive_import');
    for (const row of snapshot.progress) await client.query('INSERT INTO mcp.progress(user_key,objective_id,completed,completed_at,created_at) VALUES($1,$2,$3,$4,$5)', [row.userKey,row.objectiveId,row.completed,row.completedAt,row.createdAt]);
    for (const row of snapshot.toolLog) await client.query('INSERT INTO mcp.tool_log(id,user_key,tool_name,args,result_summary,outcome,success,created_at) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,$7,$8)', [row.id,row.userKey,row.toolName,row.args,row.resultSummary,row.outcome,row.success,row.createdAt]);
    for (const row of snapshot.provenance) await client.query('INSERT INTO mcp.import_provenance(archive_sha256,source_table,source_id,source_row) VALUES($1,$2,$3,$4::jsonb)', [captured.archiveDigest,row.table,row.id,JSON.stringify(row.row)]);
    await client.query('INSERT INTO mcp.import_batches(archive_sha256,counts,retained_tables,identity_map_sha256) VALUES($1,$2::jsonb,$3::jsonb,$4)', [captured.archiveDigest,JSON.stringify(report.counts),JSON.stringify(report.retainedTables.map(table => ({tableDigest:createHash('sha256').update(table).digest('hex'),disposition:'retained_archive_only'}))),binding.identityMapSha256]);
    const next = snapshot.toolLog.reduce((max,row) => Math.max(max,row.id),0) + 1;
    await client.query(`ALTER TABLE mcp.tool_log ALTER COLUMN id RESTART WITH ${next}`);
    if (!apply) await client.query('ROLLBACK TO SAVEPOINT mcp_archive_import');
    return {...report, applied: apply, provenanceRows: snapshot.provenance.length};
  });
}
module.exports = {readMcpArchive,importMcpArchive};
