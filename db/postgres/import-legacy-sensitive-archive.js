'use strict';

const { createHash } = require('node:crypto');
const { withTransaction } = require('../../server/database/postgres');
const { readVerifiedLegacyArchive } = require('./read-platform-archive');
const { SOURCE, mapLegacySensitiveArchive } = require('./map-legacy-sensitive-archive');
const { normalizeArchiveOwnerBinding, assertVerifiedArchiveOwnerBinding } = require('./archive-owner-binding');

const DEFAULT_DOCUMENTS = Object.freeze([
  { id: 1, filename: 'welcome.txt', file_path: '/public/welcome.txt', category: 'public', description: 'Welcome message for all users' },
  { id: 2, filename: 'info.html', file_path: '/public/info.html', category: 'public', description: 'Public information page' },
  { id: 3, filename: 'readme.md', file_path: '/public/readme.md', category: 'public', description: 'Public documentation' },
]);

function reject(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

async function readLegacySensitiveArchive({ archive, identityMap, naiveTimestamps = 'reject', review }) {
  const verified = await readVerifiedLegacyArchive({ archive });
  if (!verified.sources[SOURCE]) reject('SENSITIVE_ARCHIVE_SOURCE_MISSING');
  const input = {
    tables: verified.sources[SOURCE].tables,
    archiveDigest: verified.archiveDigest,
    identityMap: structuredClone(identityMap),
    naiveTimestamps,
    review: structuredClone(review),
  };
  return { input, ...mapLegacySensitiveArchive(input) };
}

function sameDefaultDocuments(rows) {
  if (!Array.isArray(rows) || rows.length !== DEFAULT_DOCUMENTS.length) return false;
  const key = row => JSON.stringify([row.id, row.filename, row.file_path, row.category, row.description]);
  return JSON.stringify(rows.map(key).sort()) === JSON.stringify(DEFAULT_DOCUMENTS.map(key).sort());
}

function verifiedOwnerBinding(raw, ownerProof) {
  if (!raw || raw.ownerBinding === undefined) reject('OWNER_BINDING_REQUIRED');
  if (!ownerProof) reject('OWNER_PROOF_REQUIRED');
  const binding = normalizeArchiveOwnerBinding(raw.ownerBinding);
  if (binding.archiveDigest !== raw.archiveDigest) reject('OWNER_ARCHIVE_MISMATCH');
  assertVerifiedArchiveOwnerBinding(ownerProof, binding);
  if (!raw.identityMap || typeof raw.identityMap !== 'object' || Array.isArray(raw.identityMap)) reject('SENSITIVE_IDENTITY_MAP_REQUIRED');
  for (const [source, target] of Object.entries(raw.identityMap)) {
    const mapped = binding.identityMap[source];
    if (target === null) {
      if (Object.hasOwn(binding.identityMap, source)) reject('SENSITIVE_ORPHAN_HAS_PLATFORM_OWNER');
    } else if (!Object.hasOwn(binding.identityMap, source) || mapped !== target) {
      reject('SENSITIVE_OWNER_BINDING_MISMATCH');
    }
  }
  return binding;
}

async function importLegacySensitiveArchive(pool, raw, { apply = false, ownerProof } = {}) {
  if (typeof apply !== 'boolean') reject('INVALID_APPLY_OPTION');
  const captured = structuredClone(raw);
  const binding = verifiedOwnerBinding(captured, ownerProof);
  const mappingInput = { ...captured };
  delete mappingInput.ownerBinding;
  const { snapshot, report } = mapLegacySensitiveArchive(mappingInput);
  return withTransaction(pool, async client => {
    await client.query('SELECT pg_advisory_xact_lock(1886610804,2)');
    await client.query('LOCK TABLE legacy_sensitive.documents,legacy_sensitive.access_logs,legacy_sensitive.import_provenance,legacy_sensitive.import_batches IN ACCESS EXCLUSIVE MODE');
    for (const table of ['legacy_sensitive.access_logs', 'legacy_sensitive.import_provenance', 'legacy_sensitive.import_batches']) {
      if ((await client.query(`SELECT EXISTS(SELECT 1 FROM ${table}) AS populated`)).rows[0].populated) reject('SENSITIVE_IMPORT_REQUIRES_EMPTY_TARGET');
    }
    const docs = (await client.query('SELECT id,filename,file_path,category,description FROM legacy_sensitive.documents ORDER BY id')).rows;
    if (!sameDefaultDocuments(docs)) reject('SENSITIVE_IMPORT_REQUIRES_NATIVE_DEFAULT_DOCUMENTS');
    await client.query('SAVEPOINT sensitive_archive_import');
    await client.query('DELETE FROM legacy_sensitive.documents');
    for (const row of snapshot.documents) {
      await client.query(`INSERT INTO legacy_sensitive.documents
        (id,filename,file_path,category,access_level,description,uploaded_by,created_at)
        OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [row.id, row.filename, row.filePath, row.category, row.accessLevel, row.description, row.uploadedBy, row.createdAt]);
    }
    for (const row of snapshot.accessLogs) {
      await client.query(`INSERT INTO legacy_sensitive.access_logs
        (id,user_id,file_path,access_type,status,ip_address,user_agent,timestamp)
        OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [row.id, row.userId, row.filePath, row.accessType, row.status, row.ipAddress, row.userAgent, row.timestamp]);
    }
    for (const row of snapshot.provenance) {
      await client.query(`INSERT INTO legacy_sensitive.import_provenance
        (archive_sha256,source_table,source_id,source_row)
        VALUES($1,$2,$3,$4::jsonb)`,
      [captured.archiveDigest, `${row.sourceFile}:${row.sourceTable}`, row.sourceId, JSON.stringify(row.row)]);
    }
    const retained = report.retainedTables.map(row => ({
      source: row.source, table: row.table, rows: row.rows,
      tableSha256: createHash('sha256').update(`${row.source}:${row.table}`).digest('hex'), policy: row.policy,
    }));
    await client.query(`INSERT INTO legacy_sensitive.import_batches
      (archive_sha256,importer_version,timestamp_policy,counts,retained_decisions,identity_map_sha256)
      VALUES($1,'legacy-sensitive-v2',$2,$3::jsonb,$4::jsonb,$5)`,
    [captured.archiveDigest, captured.naiveTimestamps || 'reject', JSON.stringify(report.counts), JSON.stringify([
      ...retained,
      ...report.semanticDispositions.map(row => ({ scope: row.scope, policy: row.policy })),
      { scope: 'asset_references', references: report.assetReferences.length, policy: 'preserve_references_without_importing_assets' },
    ]), binding.identityMapSha256]);
    const nextDoc = snapshot.documents.reduce((max, row) => Math.max(max, row.id), 0) + 1;
    const nextAccess = snapshot.accessLogs.reduce((max, row) => Math.max(max, row.id), 0) + 1;
    await client.query(`ALTER TABLE legacy_sensitive.documents ALTER COLUMN id RESTART WITH ${nextDoc}`);
    await client.query(`ALTER TABLE legacy_sensitive.access_logs ALTER COLUMN id RESTART WITH ${nextAccess}`);
    if (!apply) await client.query('ROLLBACK TO SAVEPOINT sensitive_archive_import');
    await client.query('RELEASE SAVEPOINT sensitive_archive_import');
    return {
      applied: apply, status: apply ? 'imported' : 'validated', archiveDigest: captured.archiveDigest,
      counts: report.counts, provenanceRows: snapshot.provenance.length,
      retainedTables: report.retainedTables, semanticDispositions: report.semanticDispositions,
      assetReferences: report.assetReferences.length, canonicalProgressImported: false, judgmentsImported: 0,
      identityMapSha256: binding.identityMapSha256,
    };
  });
}

module.exports = { DEFAULT_DOCUMENTS, readLegacySensitiveArchive, importLegacySensitiveArchive };
