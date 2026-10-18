'use strict';

const { HISTORICAL_DISPOSITIONS } = require('../../db/postgres/map-legacy-sensitive-archive');

function review(tables, archiveDigest) {
  const retainedTables = Object.entries(tables)
    .filter(([table, rows]) => !['documents', 'file_access_logs'].includes(table) && rows.length)
    .map(([table, rows]) => ({ source: 'sensitive_info.db', table, rows: rows.length,
      policy: table === 'challenge_progress' ? 'retain_archive_only_no_judge_receipts' : 'retain_archive_only_no_native_equivalent' }));
  return {
    archiveDigest,
    retainedTables,
    decisions: HISTORICAL_DISPOSITIONS.map(({ scope, policy }) => ({ scope, policy })),
  };
}

function fixture() {
  const archiveDigest = 'a'.repeat(64);
  const tables = {
    documents: [{ id: 101, filename: 'legacy-guide.txt', file_path: '/archive/legacy-guide.txt', category: 'user', access_level: 'user', description: 'Exact archived document', uploaded_by: 7, created_at: '2025-01-02 03:04:05' }],
    file_access_logs: [{ id: 701, user_id: 7, file_path: '/archive/legacy-guide.txt', access_type: 'read', status: 'success', ip_address: '198.51.100.10', user_agent: 'fixture-agent', timestamp: '2025-01-03 04:05:06' }],
    challenge_progress: [{ id: 801, user_id: 7, challenge_type: 'path_traversal', flag_found: 'historical-flag', exploit_used: '../', payload: '../secret', success: 1, run_id: 'legacy-run', judgment: '{"verdict":"pass"}', timestamp: '2025-01-04 05:06:07' }],
    ssi_templates: [{ id: 1, template_name: 'legacy-header', template_content: '<!--#echo var="REMOTE_ADDR" -->', created_at: '2025-01-05 06:07:08' }],
  };
  return { tables, archiveDigest, identityMap: { 7: 71 }, naiveTimestamps: 'UTC', review: review(tables, archiveDigest) };
}

module.exports = { fixture, review };
