'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createPool } = require('../../server/database/postgres');
const { migrate } = require('../../db/postgres/migrate');
const { importAgentWorkshopArchive } = require('../../db/postgres/import-agent-workshop-archive');
const { importLegacySensitiveArchive } = require('../../db/postgres/import-legacy-sensitive-archive');
const { input: agentInput } = require('../fixtures/agentWorkshopArchive');
const { fixture: legacyInput } = require('../fixtures/legacySensitiveArchive');
const { createNativeOwnerProof } = require('./helpers/archiveOwnerBinding');

const URL_ENV = 'PG_LEGACY_SENSITIVE_REVERSE_TEST_MIGRATION_URL';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!process.env[URL_ENV];
const migrations = path.join(__dirname, '../../db/postgres/workshop-migrations/finflow');

async function snapshot(pool) {
  const [progress, toolLog, finflowBatch, finflowProvenance, documents, accessLogs, legacyBatch, legacyProvenance] = await Promise.all([
    pool.query('SELECT user_id,objective_id,completed,completed_at FROM finflow.progress ORDER BY user_id,objective_id'),
    pool.query('SELECT id,user_id,tool_name,params,result_summary,security_flag,mode,timestamp FROM finflow.tool_log ORDER BY id'),
    pool.query('SELECT archive_sha256,importer_version,identity_map_sha256,counts,retained_decisions FROM finflow.import_batches'),
    pool.query('SELECT archive_sha256,source_table,source_id,source_row FROM finflow.import_provenance ORDER BY source_table,source_id'),
    pool.query('SELECT id,filename,file_path,category,access_level,description,uploaded_by,created_at FROM legacy_sensitive.documents ORDER BY id'),
    pool.query('SELECT id,user_id,file_path,access_type,status,ip_address,user_agent,timestamp FROM legacy_sensitive.access_logs ORDER BY id'),
    pool.query('SELECT archive_sha256,importer_version,identity_map_sha256,counts,retained_decisions FROM legacy_sensitive.import_batches'),
    pool.query('SELECT archive_sha256,source_table,source_id,source_row FROM legacy_sensitive.import_provenance ORDER BY source_table,source_id'),
  ]);
  return {
    progress: progress.rows,
    toolLog: toolLog.rows,
    finflowBatch: finflowBatch.rows,
    finflowProvenance: finflowProvenance.rows,
    documents: documents.rows,
    accessLogs: accessLogs.rows,
    legacyBatch: legacyBatch.rows,
    legacyProvenance: legacyProvenance.rows,
  };
}

test('FinFlow-first and Legacy Sensitive imports coexist and survive migration restart', { skip: !enabled }, async () => {
  const url = new URL(process.env[URL_ENV]);
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  const pool = createPool(process.env, URL_ENV);
  let ownerFixture;
  try {
    await migrate(pool, migrations);

    const finflow = agentInput('finflow');
    const legacy = legacyInput();
    assert.equal(finflow.archiveDigest, legacy.archiveDigest, 'fixture imports must belong to one archive');
    const ownerBinding = { archiveDigest: finflow.archiveDigest, identityMap: { 7: 71 } };
    finflow.ownerBinding = ownerBinding;
    finflow.opaqueOwnerResolutions = [
      { sourceKey: '0007', disposition: 'map_source_identity', sourceId: '7' },
    ];
    legacy.ownerBinding = ownerBinding;
    ownerFixture = await createNativeOwnerProof(pool, ownerBinding);

    const finflowResult = await importAgentWorkshopArchive(pool, finflow, {
      apply: true,
      ownerProof: ownerFixture.ownerProof,
    });
    assert.equal(finflowResult.status, 'imported');
    assert.equal(finflowResult.identityMapSha256, ownerFixture.ownerProof.identityMapSha256);

    const finflowBeforeLegacy = await snapshot(pool);
    assert.equal(finflowBeforeLegacy.finflowBatch.length, 1);
    assert.equal(finflowBeforeLegacy.finflowBatch[0].archive_sha256, ownerBinding.archiveDigest);
    assert.equal(finflowBeforeLegacy.finflowBatch[0].identity_map_sha256, ownerFixture.ownerProof.identityMapSha256);
    assert.equal(finflowBeforeLegacy.legacyBatch.length, 0);

    const legacyResult = await importLegacySensitiveArchive(pool, legacy, {
      apply: true,
      ownerProof: ownerFixture.ownerProof,
    });
    assert.equal(legacyResult.status, 'imported');
    assert.equal(legacyResult.identityMapSha256, ownerFixture.ownerProof.identityMapSha256);

    const combined = await snapshot(pool);
    assert.deepEqual(combined.progress, finflowBeforeLegacy.progress);
    assert.deepEqual(combined.toolLog, finflowBeforeLegacy.toolLog);
    assert.deepEqual(combined.finflowBatch, finflowBeforeLegacy.finflowBatch);
    assert.deepEqual(combined.finflowProvenance, finflowBeforeLegacy.finflowProvenance);
    assert.equal(combined.legacyBatch.length, 1);
    assert.equal(combined.legacyBatch[0].archive_sha256, ownerBinding.archiveDigest);
    assert.equal(combined.legacyBatch[0].identity_map_sha256, ownerFixture.ownerProof.identityMapSha256);
    assert.equal(combined.legacyBatch[0].importer_version, 'legacy-sensitive-v2');
    assert.equal(combined.documents.length, 1);
    assert.equal(combined.documents[0].uploaded_by, '71');
    assert.equal(combined.accessLogs.length, 1);
    assert.equal(combined.accessLogs[0].user_id, '71');

    // Migration discovery is the restart path. Reapplying it must neither seed
    // over imported rows nor move the now-independent audit namespaces again.
    await migrate(pool, migrations);
    assert.deepEqual(await snapshot(pool), combined);

    await assert.rejects(pool.query('DELETE FROM finflow.import_batches'), { code: '55000' });
    await assert.rejects(pool.query('DELETE FROM legacy_sensitive.import_batches'), { code: '55000' });
  } finally {
    await ownerFixture?.cleanup();
    await pool.end();
  }
});
