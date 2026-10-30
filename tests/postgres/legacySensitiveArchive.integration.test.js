'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createPool } = require('../../server/database/postgres');
const { migrate } = require('../../db/postgres/migrate');
const { createFinflowWorkshopDb } = require('../../server/database/postgres/sensitiveInfoWorkshopDb');
const { importLegacySensitiveArchive } = require('../../db/postgres/import-legacy-sensitive-archive');
const { importAgentWorkshopArchive } = require('../../db/postgres/import-agent-workshop-archive');
const { fixture } = require('../fixtures/legacySensitiveArchive');
const { createNativeOwnerProof } = require('./helpers/archiveOwnerBinding');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && !!process.env.PG_LEGACY_SENSITIVE_IMPORT_TEST_RUNTIME_URL
  && !!process.env.PG_LEGACY_SENSITIVE_IMPORT_TEST_MIGRATION_URL;

test('imports supported sensitive_info archive rows into native FinFlow legacy namespace without receipts', { skip: !enabled }, async () => {
  const runtime = createPool(process.env, 'PG_LEGACY_SENSITIVE_IMPORT_TEST_RUNTIME_URL');
  const migration = createPool(process.env, 'PG_LEGACY_SENSITIVE_IMPORT_TEST_MIGRATION_URL');
  let ownerFixture;
  try {
    for (const key of ['PG_LEGACY_SENSITIVE_IMPORT_TEST_RUNTIME_URL', 'PG_LEGACY_SENSITIVE_IMPORT_TEST_MIGRATION_URL']) {
      assert.match(new URL(process.env[key]).pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
    }
    await migrate(migration,path.join(__dirname,'../../db/postgres/workshop-migrations/finflow'));
    const raw=fixture();raw.ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};
    ownerFixture=await createNativeOwnerProof(migration,raw.ownerBinding);
    const dryRun = await importLegacySensitiveArchive(migration, raw, { apply: false, ownerProof:ownerFixture.ownerProof });
    assert.equal(dryRun.applied, false);
    assert.equal(dryRun.status, 'validated');
    assert.deepEqual((await runtime.query('SELECT id,filename,file_path FROM legacy_sensitive.documents ORDER BY id')).rows,
      [{ id: 1, filename: 'welcome.txt', file_path: '/public/welcome.txt' },
        { id: 2, filename: 'info.html', file_path: '/public/info.html' },
        { id: 3, filename: 'readme.md', file_path: '/public/readme.md' }]);
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM legacy_sensitive.access_logs')).rows[0].n, 0);
    assert.equal((await migration.query('SELECT count(*)::int AS n FROM legacy_sensitive.import_provenance')).rows[0].n, 0);
    assert.equal((await migration.query('SELECT count(*)::int AS n FROM legacy_sensitive.import_batches')).rows[0].n, 0);
    await assert.rejects(runtime.query('SELECT count(*) FROM legacy_sensitive.import_provenance'), { code: '42501' });
    await assert.rejects(runtime.query("INSERT INTO legacy_sensitive.import_provenance(archive_sha256,source_table,source_id,source_row) VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','x','1','{}'::jsonb)"), { code: '42501' });
    const result = await importLegacySensitiveArchive(migration, raw, { apply: true, ownerProof:ownerFixture.ownerProof });
    assert.equal(result.canonicalProgressImported, false);
    assert.equal(result.judgmentsImported, 0);
    assert.equal(result.provenanceRows, 2);
    assert.deepEqual((await runtime.query('SELECT id,filename,file_path,uploaded_by FROM legacy_sensitive.documents')).rows,
      [{ id: 101, filename: 'legacy-guide.txt', file_path: '/archive/legacy-guide.txt', uploaded_by: '71' }]);
    assert.deepEqual((await runtime.query('SELECT id,user_id,file_path FROM legacy_sensitive.access_logs')).rows,
      [{ id: '701', user_id: '71', file_path: '/archive/legacy-guide.txt' }]);
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM legacy_sensitive.judgments')).rows[0].n, 0);
    assert.equal((await migration.query('SELECT count(*)::int AS n FROM legacy_sensitive.import_provenance')).rows[0].n, 2);
    assert.equal((await migration.query('SELECT importer_version FROM legacy_sensitive.import_batches')).rows[0].importer_version, 'legacy-sensitive-v2');
    assert.equal((await migration.query('SELECT identity_map_sha256 FROM legacy_sensitive.import_batches')).rows[0].identity_map_sha256,ownerFixture.ownerProof.identityMapSha256);
    assert.equal((await migration.query('SELECT count(*)::int AS n FROM finflow.import_provenance')).rows[0].n,0);
    assert.equal((await migration.query('SELECT count(*)::int AS n FROM finflow.import_batches')).rows[0].n,0);
    const agentRaw=require('../fixtures/agentWorkshopArchive').input('finflow');
    agentRaw.ownerBinding=raw.ownerBinding;agentRaw.opaqueOwnerResolutions=[{sourceKey:'0007',disposition:'map_source_identity',sourceId:'7'}];
    await importAgentWorkshopArchive(migration,agentRaw,{apply:true,ownerProof:ownerFixture.ownerProof});
    assert.equal((await migration.query('SELECT importer_version FROM finflow.import_batches')).rows[0].importer_version,'agent-workshop-v1');
    await createFinflowWorkshopDb(runtime).initialize(migration);
    const nextDocument = (await migration.query("INSERT INTO legacy_sensitive.documents(filename,file_path,category,description) VALUES('sequence-check.txt','/archive/sequence-check.txt','user','sequence check') RETURNING id")).rows[0].id;
    assert.equal(nextDocument, 102);
    await migration.query('DELETE FROM legacy_sensitive.documents WHERE id=$1', [nextDocument]);
    const nextAccess = (await migration.query("INSERT INTO legacy_sensitive.access_logs(user_id,file_path) VALUES(NULL,'/archive/sequence-check.txt') RETURNING id")).rows[0].id;
    assert.equal(nextAccess, '702');
    await migration.query('DELETE FROM legacy_sensitive.access_logs WHERE id=$1', [nextAccess]);
    await assert.rejects(importLegacySensitiveArchive(migration, raw, { apply: true, ownerProof:ownerFixture.ownerProof }), { code: 'SENSITIVE_IMPORT_REQUIRES_EMPTY_TARGET' });
    await assert.rejects(migration.query('DELETE FROM legacy_sensitive.import_batches'),{code:'55000'});
  } finally {
    await ownerFixture?.cleanup();
    await Promise.all([runtime.end(), migration.end()]);
  }
});
