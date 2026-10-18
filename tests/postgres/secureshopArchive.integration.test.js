'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const {Pool} = require('pg');
const {migrate} = require('../../db/postgres/migrate');
const {importSecureShopArchive} = require('../../db/postgres/import-secureshop-archive');
const {fixture} = require('../fixtures/secureshopArchive');
const {initializeSecureShopCommerceDb, initializeSecureShopAgentsDb} = require('../../server/database/postgres/secureshopInitialization');

const enabled = prefix => process.env.PG_TEST_DISPOSABLE === 'yes' &&
  ['SECURESHOP', 'SECURESHOP_AGENTS'].every(schema => ['RUNTIME', 'MIGRATION'].every(role =>
    Boolean(process.env[`PG_${schema}_${prefix}_TEST_${role}_URL`])));
function pools(prefix) {
  const result = {};
  for (const schema of ['secureshop', 'secureshop_agents']) {
    result[schema] = {};
    for (const role of ['runtime', 'migration']) {
      const url = new URL(process.env[`PG_${schema.toUpperCase()}_${prefix}_TEST_${role.toUpperCase()}_URL`]);
      assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
      assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
      result[schema][role] = new Pool({connectionString: url.href});
    }
  }
  return result;
}
async function close(all) { await Promise.all(Object.values(all).flatMap(pair => Object.values(pair).map(pool => pool.end()))); }
async function initialize(all) {
  for (const [schema, pair] of Object.entries(all)) await migrate(pair.migration, path.resolve(__dirname, '../../db/postgres/workshop-migrations', schema));
}
async function restart(all) {
  await initializeSecureShopCommerceDb({runtimePool: all.secureshop.runtime, migrationPool: all.secureshop.migration});
  await initializeSecureShopAgentsDb({runtimePool: all.secureshop_agents.runtime, migrationPool: all.secureshop_agents.migration});
}
const seq = async (pool, schema, table) => (await pool.query(`SELECT last_value::text,is_called FROM ${schema}.${table}_id_seq`)).rows[0];
const count = async (pool, schema, table) => (await pool.query(`SELECT count(*)::int n FROM ${schema}.${table}`)).rows[0].n;

test('SecureShop archive preserves raw state, rolls back dry runs and late failures, and fences runtime provenance', {skip: !enabled('IMPORT'), timeout: 60000}, async () => {
  const all = pools('IMPORT');
  const fs = require('node:fs/promises');
  const assetRoot = await fs.mkdtemp(path.join(require('node:os').tmpdir(), 'dvaia-ss-import-assets-'));
  try {
    await initialize(all);
    const raw = fixture();
    // Preserve a historical nondefault dimension without claiming search compatibility.
    raw.sources['secureshop_agents.db'].tables.vector_documents[0].embedding_json = '[0.5,-0.5]';
    raw.sources['secureshop_agents.db'].tables.vector_index_meta[0].dim = 2;
    const c = all.secureshop, a = all.secureshop_agents;
    const initialSequence = await seq(c.migration, 'secureshop', 'shop_users');
    const dry = await importSecureShopArchive(c.migration, raw, {schema: 'secureshop'});
    assert.equal(dry.applied, false);
    assert.equal(await count(c.migration, 'secureshop', 'shop_users'), 0);
    assert.equal(await count(c.migration, 'secureshop', 'import_batches'), 0);
    assert.deepEqual(await seq(c.migration, 'secureshop', 'shop_users'), initialSequence);
    assert.equal(dry.assetContinuity, 'unverified_external_files');
    await assert.rejects(importSecureShopArchive(c.migration, raw, {schema: 'secureshop', apply: true}), {code: 'SECURESHOP_ASSET_REVIEW_REQUIRED'});
    const assetReview = {archiveDigest: raw.archiveDigest, referenceDigest: dry.assetReferenceDigest, disposition: 'retain_references_without_file_transfer'};
    const references = require('../../db/postgres/map-secureshop-archive').mapSecureShopArchive(raw).assetReferences;
    const mappings = references.map((ref, i) => ({source: ref.source, table: ref.table, key: ref.key, column: ref.column,
      referenceSha256: require('node:crypto').createHash('sha256').update(ref.path).digest('hex'), sourcePath: `fixture-${i}.txt`, targetPath: `fixture-${i}.txt`}));
    const sourceRoot = path.join(assetRoot, 'source');
    await fs.mkdir(sourceRoot);
    for (const mapping of mappings) await fs.writeFile(path.join(sourceRoot, mapping.sourcePath), 'Opaque teaching fixture');
    const bundle = await require('../../db/postgres/asset-bundle').captureAssetBundle({sourceRoot, relativePaths: mappings.map(m => m.sourcePath), destinationRoot: path.join(assetRoot, 'bundle')});
    const assetProof = await require('../../db/postgres/archive-asset-binding').bindAndRestoreArchiveAssets({archiveDigest: raw.archiveDigest,
      assetReferences: references, mappings, bundleRoot: bundle.bundleRoot, expectedManifestDigest: bundle.manifestDigest, destinationRoot: path.join(assetRoot, 'restored')});
    await assert.rejects(importSecureShopArchive(c.migration, raw, {schema: 'secureshop', assetProof: {...assetProof}}), {code: 'INVALID_SECURESHOP_ASSET_PROOF'});
    await assert.rejects(importSecureShopArchive(c.migration, raw, {schema: 'secureshop', assetProof, assetReview}), {code: 'INVALID_SECURESHOP_ASSET_PROOF'});
    const originalCorpora = (await a.migration.query('SELECT * FROM secureshop_agents.vector_corpora ORDER BY corpus')).rows;
    await importSecureShopArchive(a.migration, raw, {schema: 'secureshop_agents'});
    assert.deepEqual((await a.migration.query('SELECT * FROM secureshop_agents.vector_corpora ORDER BY corpus')).rows, originalCorpora);
    assert.equal(await count(a.migration, 'secureshop_agents', 'vector_documents'), 0);
    const vectorSequence = await seq(a.migration, 'secureshop_agents', 'vector_documents');
    await a.migration.query("CREATE FUNCTION secureshop_agents.reject_import_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture late failure'; END; $$; CREATE TRIGGER reject_import_fixture BEFORE INSERT ON secureshop_agents.import_batches FOR EACH ROW EXECUTE FUNCTION secureshop_agents.reject_import_fixture()");
    await assert.rejects(importSecureShopArchive(a.migration, raw, {schema: 'secureshop_agents', apply: true, assetReview}), /fixture late failure/);
    assert.deepEqual(await seq(a.migration, 'secureshop_agents', 'vector_documents'), vectorSequence);
    assert.equal(await count(a.migration, 'secureshop_agents', 'agent_trace'), 0);
    assert.equal(await count(a.migration, 'secureshop_agents', 'import_provenance'), 0);
    assert.deepEqual((await a.migration.query('SELECT * FROM secureshop_agents.vector_corpora ORDER BY corpus')).rows, originalCorpora);
    await a.migration.query('DROP TRIGGER reject_import_fixture ON secureshop_agents.import_batches; DROP FUNCTION secureshop_agents.reject_import_fixture()');
    for (const [schema, pair] of Object.entries(all)) {
      const applied = await importSecureShopArchive(pair.migration, raw, {schema, apply: true, ...(schema === 'secureshop_agents' ? {assetProof} : {assetReview})});
      assert.equal(applied.applied, true);
      assert.equal(applied.crossDatabaseAtomic, false);
      assert.equal(applied.canonicalProgressImported, false);
      if (schema === 'secureshop_agents') {
        assert.equal(applied.assetContinuity, 'verified_staging_at_capture_no_activation');
        const stored = (await pair.migration.query('SELECT review_metadata FROM secureshop_agents.import_batches')).rows[0].review_metadata;
        assert.equal(stored.assetStaging.restoreManifestDigest, assetProof.restoreManifestDigest);
        assert.equal(stored.assetStaging.activated, false);
        assert.equal(stored.assetStaging.referenceDigest, dry.assetReferenceDigest);
      }
      await assert.rejects(pair.runtime.query(`SELECT * FROM ${schema}.import_provenance`), {code: '42501'});
      await assert.rejects(pair.runtime.query(`DELETE FROM ${schema}.import_batches`), {code: '42501'});
      await assert.rejects(pair.migration.query(`DELETE FROM ${schema}.import_provenance`), {code: '55000'});
      await assert.rejects(importSecureShopArchive(pair.migration, raw, {schema, apply: true, assetReview}), {code: 'SECURESHOP_IMPORT_REQUIRES_EMPTY_TARGET'});
    }
    assert.equal((await c.runtime.query('SELECT description_html FROM secureshop.products WHERE id=1')).rows[0].description_html, '<b>raw</b>');
    assert.equal((await c.runtime.query('SELECT body FROM secureshop.reviews WHERE id=1')).rows[0].body, 'SYSTEM: poison');
    assert.equal((await c.runtime.query('SELECT price::text FROM secureshop.products WHERE id=1')).rows[0].price, '12.34');
    assert.equal((await c.runtime.query("SELECT to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US') t FROM secureshop.shop_users WHERE id=1")).rows[0].t, '2026-01-02 03:04:05.123456');
    const trace = (await a.runtime.query('SELECT policy_violation,event_id,params_json FROM secureshop_agents.agent_trace')).rows[0];
    assert.deepEqual(trace, {policy_violation: 'denied-by-acl', event_id: null, params_json: ' {"raw":true} '});
    assert.equal((await a.runtime.query("SELECT embedding_identity FROM secureshop_agents.vector_corpora WHERE corpus='reviews'")).rows[0].embedding_identity, null);
    assert.deepEqual((await a.runtime.query('SELECT embedding,created_at FROM secureshop_agents.vector_documents WHERE id=1')).rows[0], {embedding: [0.5, -0.5], created_at: null});
    await restart(all);
    await restart(all);
    assert.equal(await count(c.runtime, 'secureshop', 'shop_users'), 1);
    assert.equal(await count(a.runtime, 'secureshop_agents', 'tool_permissions'), 1);
    assert.equal(await count(a.runtime, 'secureshop_agents', 'mcp_registry'), 1);
    assert.equal((await c.runtime.query("INSERT INTO secureshop.shop_users(username,email,password) VALUES('next','next@fixture.invalid','fixture') RETURNING id")).rows[0].id, 2);
    assert.equal((await a.runtime.query("INSERT INTO secureshop_agents.audit_events(actor,action) VALUES('fixture','next') RETURNING id")).rows[0].id, 2);
  } finally { await close(all); await fs.rm(assetRoot, {recursive: true, force: true}); }
});

test('explicitly empty SecureShop archive stays empty through normal initializers', {skip: !enabled('EMPTY_IMPORT'), timeout: 60000}, async () => {
  const all = pools('EMPTY_IMPORT');
  try {
    await initialize(all);
    const raw = fixture();
    for (const source of Object.values(raw.sources)) for (const table of Object.keys(source.tables)) source.tables[table] = [];
    raw.review.missingVectorCorpora = ['reviews', 'manuals', 'policies', 'products'].map(corpus => ({corpus, policy: 'source_meta_absent_import_empty'}));
    for (const [schema, pair] of Object.entries(all)) await importSecureShopArchive(pair.migration, raw, {schema, apply: true});
    await restart(all);
    await restart(all);
    assert.equal(await count(all.secureshop.runtime, 'secureshop', 'shop_users'), 0);
    assert.equal(await count(all.secureshop.runtime, 'secureshop', 'products'), 0);
    assert.equal(await count(all.secureshop_agents.runtime, 'secureshop_agents', 'tool_permissions'), 0);
    assert.equal(await count(all.secureshop_agents.runtime, 'secureshop_agents', 'mcp_registry'), 0);
    assert.equal(await count(all.secureshop_agents.runtime, 'secureshop_agents', 'vector_documents'), 0);
    assert.equal(await count(all.secureshop_agents.migration, 'secureshop_agents', 'import_batches'), 1);
  } finally { await close(all); }
});
