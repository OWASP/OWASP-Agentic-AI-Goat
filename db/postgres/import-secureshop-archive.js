'use strict';
const {createHash} = require('node:crypto');
const {withTransaction} = require('../../server/database/postgres');
const {readVerifiedLegacyArchive} = require('./read-platform-archive');
const {mapSecureShopArchive, IDENTITY_TABLES} = require('./map-secureshop-archive');
const {isArchiveAssetBindingProof} = require('./archive-asset-binding');

const SCHEMAS = new Set(['secureshop', 'secureshop_agents']);
const CORPORA = ['manuals', 'policies', 'products', 'reviews'];
const hash = value => createHash('sha256').update(value).digest('hex');
function reject(code) { throw Object.assign(new Error(code), {code}); }
function identifier(value) {
  if (!/^[a-z_][a-z0-9_]*$/.test(value)) reject('INVALID_SECURESHOP_IMPORT_IDENTIFIER');
  return value;
}

async function readSecureShopArchive({archive, naiveTimestamps = 'reject'}) {
  const verified = await readVerifiedLegacyArchive({archive});
  return {
    sources: Object.fromEntries(Object.entries(verified.sources).filter(([name]) =>
      ['secureshop.db', 'secureshop_agents.db'].includes(name))),
    archiveDigest: verified.archiveDigest,
    naiveTimestamps,
  };
}

/** One staging database per transaction. This does not claim cross-database atomicity or transfer assets. */
async function importSecureShopArchive(pool, raw, {schema, apply = false, assetReview, assetProof} = {}) {
  if (!SCHEMAS.has(schema) || typeof apply !== 'boolean') reject('INVALID_SECURESHOP_IMPORT_OPTIONS');
  const captured = structuredClone(raw);
  const mapped = mapSecureShopArchive(captured);
  const snapshot = mapped.snapshots[schema];
  const references = mapped.assetReferences;
  const referenceDigest = hash(JSON.stringify(references));
  if (assetProof !== undefined && (!isArchiveAssetBindingProof(assetProof) ||
      assetProof.archiveDigest !== captured.archiveDigest || assetProof.referenceDigest !== referenceDigest || assetReview !== undefined))
    reject('INVALID_SECURESHOP_ASSET_PROOF');
  if (assetReview !== undefined && (!assetReview ||
      Object.keys(assetReview).sort().join(',') !== 'archiveDigest,disposition,referenceDigest' ||
      assetReview.archiveDigest !== captured.archiveDigest || assetReview.referenceDigest !== referenceDigest ||
      assetReview.disposition !== 'retain_references_without_file_transfer')) reject('INVALID_SECURESHOP_ASSET_REVIEW');
  if (apply && references.length && !assetReview && !assetProof) reject('SECURESHOP_ASSET_REVIEW_REQUIRED');
  const tables = Object.keys(snapshot).map(identifier);
  const targetOnly = schema === 'secureshop' ? ['commerce_outbox'] : [];
  const provenance = mapped.provenance.filter(row => row.schema === schema);
  const counts = Object.fromEntries(tables.map(table => [table, snapshot[table].length]));

  return withTransaction(pool, async client => {
    await client.query('SELECT pg_advisory_xact_lock(1886610804, 2)');
    const locked = [...tables, ...targetOnly, 'import_provenance', 'import_batches'];
    await client.query(`LOCK TABLE ${locked.map(table => `${schema}.${table}`).join(',')} IN ACCESS EXCLUSIVE MODE`);
    for (const table of locked.filter(name => name !== 'vector_corpora')) {
      if ((await client.query(`SELECT EXISTS(SELECT 1 FROM ${schema}.${table}) AS populated`)).rows[0].populated)
        reject('SECURESHOP_IMPORT_REQUIRES_EMPTY_TARGET');
    }
    if (schema === 'secureshop_agents') {
      const rows = (await client.query('SELECT corpus,dimension,active_generation,revision,document_count,embedder_model,embedding_identity FROM secureshop_agents.vector_corpora ORDER BY corpus')).rows;
      if (rows.length !== CORPORA.length || rows.some((row, i) => row.corpus !== CORPORA[i] || row.dimension !== 768 ||
          String(row.active_generation) !== '0' || String(row.revision) !== '0' || row.document_count !== 0 ||
          row.embedder_model !== 'nomic-embed-text' || row.embedding_identity !== null)) reject('SECURESHOP_IMPORT_REQUIRES_DEFAULT_VECTOR_CORPORA');
    }
    await client.query('SAVEPOINT secureshop_archive_import');
    if (schema === 'secureshop_agents') await client.query('DELETE FROM secureshop_agents.vector_corpora');
    // Mapper order is FK-safe: commerce parents before children; sessions and corpora before dependent rows.
    for (const table of tables) {
      for (const row of snapshot[table]) {
        const columns = Object.keys(row).map(identifier);
        await client.query(`INSERT INTO ${schema}.${table}(${columns.join(',')}) ${IDENTITY_TABLES[schema].includes(table) ? 'OVERRIDING SYSTEM VALUE ' : ''}VALUES(${columns.map((_, i) => '$' + (i + 1)).join(',')})`, Object.values(row));
      }
      if (IDENTITY_TABLES[schema].includes(table)) {
        const next = snapshot[table].reduce((max, row) => BigInt(row.id) >= max ? BigInt(row.id) + 1n : max, 1n);
        await client.query(`ALTER TABLE ${schema}.${table} ALTER COLUMN id RESTART WITH ${next}`);
      }
    }
    for (const row of provenance) await client.query(
      `INSERT INTO ${schema}.import_provenance(archive_sha256,source_file,source_table,source_key,source_row) VALUES($1,$2,$3,$4,$5::jsonb)`,
      [captured.archiveDigest, row.source, row.table, row.key, JSON.stringify(row.row)]);
    const metadata = {
      naiveTimestamps: captured.naiveTimestamps || 'reject',
      review: captured.review,
      assetReferenceDigest: referenceDigest,
      assetReferenceCount: references.length,
      assetDisposition: assetProof ? 'verified_staging_at_capture_no_activation' : references.length ? assetReview?.disposition || 'unreviewed' : 'no_local_references',
      ...(assetProof ? { assetStaging: { bundleManifestDigest: assetProof.bundleManifestDigest,
        restoreManifestDigest: assetProof.restoreManifestDigest, referenceDigest,
        referenceCount: assetProof.mappings.length, activated: false, databaseReferencesRewritten: false } } : {}),
      targetOnlyColumns: {event_id: 'null_no_outbox_replay'},
      crossDatabaseAtomic: false,
      vectorRebuildRequired: mapped.report.vectorRebuildRequired,
      canonicalProgressImported: false,
    };
    await client.query(`INSERT INTO ${schema}.import_batches(archive_sha256,counts,review_metadata) VALUES($1,$2::jsonb,$3::jsonb)`,
      [captured.archiveDigest, JSON.stringify(counts), JSON.stringify(metadata)]);
    if (!apply) await client.query('ROLLBACK TO SAVEPOINT secureshop_archive_import');
    return {
      archiveDigest: captured.archiveDigest, schema, applied: apply, counts,
      provenanceRows: provenance.length, assetReferenceDigest: referenceDigest,
      assetReferences: references.length, assetContinuity: assetProof ? 'verified_staging_at_capture_no_activation' : references.length ? 'unverified_external_files' : 'no_local_references',
      ...(assetProof ? { assetStaging: metadata.assetStaging } : {}),
      crossDatabaseAtomic: false, vectorRebuildRequired: mapped.report.vectorRebuildRequired, canonicalProgressImported: false,
    };
  });
}
module.exports = {readSecureShopArchive, importSecureShopArchive};
