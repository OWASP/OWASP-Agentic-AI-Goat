'use strict';

// Storage qualification only. The owned launcher supplies two disposable review
// databases; this test never invokes a provider, browser, Judge, or app database.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { withTransaction } = require('../../server/database/postgres');
const { createSceneBinding } = require('../../server/services/secureshopSceneBinding');
const { createConversationBinding } = require('../../server/services/secureshopConversationBinding');
const { createSecureShopBoundProductRepository } = require('../../server/database/postgres/secureshopBoundProductRepository');
const { createSecureShopBoundProductRetrievalRepository } = require('../../server/database/postgres/secureshopBoundProductRetrievalRepository');
const { createSecureShopBoundManualIngestRepository } = require('../../server/database/postgres/secureshopBoundManualIngestRepository');
const { createSecureShopEmbeddingRevisionRepository } = require('../../server/database/postgres/secureshopEmbeddingRevisionRepository');
const { createManualRagSourceAdapter } = require('../../server/database/postgres/secureshopManualRagSourceAdapter');

const ROOT = path.resolve(__dirname, '../..');
const DIRECTORY = path.join(ROOT, 'db/postgres/workshop-migrations/secureshop_review');
const CANDIDATE = '0050_product_embedding_revision_preimages.sql';
const PREFIX = 'PG_SECURESHOP_MANUAL_RAG_PREIMAGES_';
const STORES = ['FRESH_REVIEW', 'POPULATED_REVIEW'];
const TITLE = 'native manual RAG preimages preserve original dense vectors across upgrade, replay, rollback and retirement';
const ENABLED = process.env.SECURESHOP_MANUAL_RAG_PREIMAGES_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes';
const FINGERPRINT = 'a'.repeat(64);
const sha = text => createHash('sha256').update(text, 'utf8').digest('hex');
const seed = require('../../db/postgres/seeds/secureshop.json');

function urls() {
  const result = {}, databases = new Set(), ports = new Set();
  for (const store of STORES) {
    const pair = {};
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const url = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
      assert.equal(url.protocol, 'postgresql:');
      assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
      assert.equal(url.username, `dvaia_secureshop_review_${role.toLowerCase()}`);
      assert.equal(url.password, '');
      assert.equal(url.search, ''); assert.equal(url.hash, '');
      pair[role.toLowerCase()] = url;
      ports.add(url.port);
    }
    assert.equal(pair.runtime.pathname, pair.migration.pathname);
    assert.ok(!databases.has(pair.runtime.pathname), 'fresh/populated database identities must differ');
    databases.add(pair.runtime.pathname); result[store] = pair;
  }
  assert.equal(ports.size, 1);
  return result;
}
function pool(url) {
  return new Pool({ connectionString: url.href, max: 3, connectionTimeoutMillis: 5000,
    statement_timeout: 30000, lock_timeout: 10000,
    idle_in_transaction_session_timeout: 30000 });
}
function beforeCandidate() {
  const filename = require.resolve('../../db/postgres/migrate');
  const localRequire = createRequire(filename);
  const originalFs = require('node:fs/promises');
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? {
    async readdir(directory, ...args) {
      assert.equal(path.resolve(directory), DIRECTORY);
      return (await originalFs.readdir(directory, ...args)).filter(item => item < CANDIDATE);
    },
    readFile: (...args) => originalFs.readFile(...args),
  } : localRequire(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports;
}
function binding(owner) {
  return Object.freeze({ targetId: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(),
    generation: 1, platformOwnerId: owner, platformSessionId: owner + 1000 });
}
async function scene(runtime, source) {
  const execution = { ...source, launchId: randomUUID(), scenarioId: randomUUID(),
    generation: 2, platformSessionId: source.platformSessionId + 1 };
  const sceneId = randomUUID(), grantId = randomUUID();
  await runtime.query(`INSERT INTO secureshop_review.scene_execution_grants
    (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
     original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,1,$3,$4,$5,$6,$7,$8)`, [grantId, sceneId, source.targetId,
    execution.launchId, execution.scenarioId, execution.generation,
    execution.platformOwnerId, execution.platformSessionId]);
  return createSceneBinding(source, { sceneId, sceneGeneration: 1, grantId, execution,
    withLease: work => work() });
}
function repos(runtime) {
  const authority = { checkCurrent: async () => {}, checkCleanup: async () => {},
    getRuntimeFingerprint: () => FINGERPRINT };
  return {
    products: createSecureShopBoundProductRepository(runtime, authority),
    retrieval: createSecureShopBoundProductRetrievalRepository(runtime, authority),
    manuals: createSecureShopBoundManualIngestRepository(runtime, authority),
    revisions: createSecureShopEmbeddingRevisionRepository(runtime, authority),
  };
}
function sourceReader(reviewPool, target) {
  // These two source callbacks are review-store reads. Fail if the fixture
  // accidentally starts depending on an unprovisioned agents/identity store;
  // the actual callback SQL and scene grant run on the owned runtime review DB.
  const unused = { query() { throw new Error('Unexpected cross-store source read'); } };
  const persona = { id: 8101, role: 'customer' };
  const state = { target, persona, binding: createConversationBinding(target.scene.execution, persona),
    personaSession: { sessionId: randomUUID(), authorityVersion: 1 }, check: async () => {} };
  return { adapter: createManualRagSourceAdapter({ agentsPool: unused,
    identityPool: unused, reviewPool }), state };
}
function product(row) {
  return { id: row.id, sourceRetailerId: row.retailer_id, retailerId: 12,
    name: row.name, description: row.description, descriptionHtml: row.description_html,
    price: row.price, category: row.category, imageUrl: row.image_url, images: [],
    stockQuantity: row.stock_quantity, status: row.status,
    templateSource: row.template_source, createdAt: row.created_at, updatedAt: row.updated_at };
}
function vector(index) {
  // All 384 coordinates are nonzero decimals; this is a storage probe, never
  // a substitute for a configured embedding provider or semantic retrieval.
  return Array.from({ length: 384 }, (_, i) =>
    Number((Math.sin((index + 1) * (i + 3) / 19) / 7 + Math.cos((i + 1) / 13) / 11).toFixed(12)));
}
const corpus = seed.products.map(product);
assert.equal(corpus.length, 125, 'shipped product corpus changed');
const documents = corpus.map(row => ({ sourceKind: 'product', sourceId: row.id,
  chunkIndex: 0, text: `${row.name}\n${row.description || ''}`, embedding: vector(row.id) }));
function publishInput(snapshot, operationId, mapVector = item => vector(Number(item.sourceId))) {
  return { operationId, sourceSetDigest: snapshot.sourceSetDigest,
    expectedHead: snapshot.expectedHead, expectedRuntimeFingerprint: FINGERPRINT,
    documents: snapshot.documents.map(({ text, ...item }) =>
      ({ ...item, embedding: mapVector(item) })) };
}
async function preimages(runtime, targetId) {
  return {
    revisions: (await runtime.query(`SELECT p.revision_id,p.target_id,p.source_set_json,p.vectors_json,
      encode(r.source_set_digest,'hex') AS source_digest,encode(r.vector_digest,'hex') AS vector_digest
      FROM secureshop_review.product_target_embedding_preimages p
      JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id)
      WHERE p.target_id=$1 ORDER BY p.revision_id`, [targetId])).rows,
    manuals: (await runtime.query(`SELECT operation_id,target_id,documents_json
      FROM secureshop_review.product_target_manual_preimages WHERE target_id=$1
      ORDER BY operation_id`, [targetId])).rows,
  };
}
function assertOriginal(row, count) {
  assert.equal(sha(row.source_set_json), row.source_digest);
  assert.equal(sha(row.vectors_json), row.vector_digest);
  assert.equal(JSON.parse(row.source_set_json).length, count);
  const vectors = JSON.parse(row.vectors_json);
  assert.equal(vectors.length, count);
  assert.ok(vectors.every(item => item.embedding.length === 384
    && item.embedding.filter(value => value !== 0).length > 300));
}
function manualInput(storage, current, operationId) {
  const execution = current.scene.execution;
  return { operationId, productId: corpus[0].id, merchantId: 12,
    fileReceipt: { targetId: randomUUID(), launchId: execution.launchId,
      scenarioId: execution.scenarioId, generation: execution.generation,
      platformOwnerId: execution.platformOwnerId,
      platformSessionId: execution.platformSessionId,
      virtualPath: `/uploads/product_manuals/${corpus[0].id}/${operationId}-manual`,
      bytes: 143, sha256: '1'.repeat(64) },
    filename: 'owned-manual.txt', mime: 'text/plain', isPublic: true,
    extractor: 'raw-utf8', extractionSha256: '2'.repeat(64),
    embeddingModel: 'fixture-embedding-v1', embeddingDimension: 384,
    expectedRuntimeFingerprint: FINGERPRINT,
    chunks: [{ text: 'Owned synthetic manual recommends original product',
      embedding: vector(999) }] };
}

test(TITLE, { skip: !ENABLED, timeout: 240000 }, async t => {
  assert.equal(process.cwd(), ROOT);
  assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/'), ROOT);
  const names = (await readMigrations(DIRECTORY)).map(row => row.name);
  assert.equal(names.at(-1), CANDIDATE, '0050 must be the current review migration tip');
  const pair = urls(), pools = [], state = {};
  t.after(async () => {
    const results = await Promise.allSettled(pools.map(item => item.end()));
    assert.deepEqual(results.filter(item => item.status === 'rejected'), []);
  });
  for (const key of STORES) {
    const runtime = pool(pair[key].runtime), migration = pool(pair[key].migration);
    pools.push(runtime, migration); state[key] = { runtime, migration, repos: repos(runtime) };
    assert.equal((await runtime.query('SELECT current_user AS role')).rows[0].role,
      'dvaia_secureshop_review_runtime');
  }
  const historical = beforeCandidate();
  const populated = state.POPULATED_REVIEW, fresh = state.FRESH_REVIEW;
  assert.deepEqual(await historical.migrate(populated.migration, DIRECTORY),
    names.filter(name => name < CANDIDATE));
  assert.deepEqual(await historical.migrate(populated.migration, DIRECTORY), []);
  const old = binding(3101);
  await populated.repos.products.provision(old, { ownMerchantId: 12, products: corpus });
  await populated.repos.retrieval.provision(old, {
    embeddingModel: 'fixture-embedding-v1', embeddingDimension: 384, documents });
  const oldScene = await scene(populated.runtime, old);
  const oldManual = manualInput(old, oldScene, randomUUID());
  const oldReceipt = await populated.repos.manuals.appendManual(oldScene, oldManual);
  assert.equal(oldReceipt.replayed, false);
  const oldSnapshot = await populated.repos.revisions.snapshot(oldScene);
  const oldRevision = await populated.repos.revisions.publish(oldScene,
    publishInput(oldSnapshot, randomUUID(), item => item.sourceKind === 'manual'
      ? vector(999) : vector(Number(item.sourceId))));
  const oldRows = (await populated.runtime.query(`SELECT to_jsonb(r) AS row FROM
    secureshop_review.product_target_embedding_revisions r WHERE r.revision_id=$1`,
  [oldRevision.revisionId])).rows;
  const oldProducts = (await populated.runtime.query(`SELECT to_jsonb(p) AS row FROM
    secureshop_review.product_target_products p WHERE target_id=$1 ORDER BY product_id`,
  [old.targetId])).rows;
  assert.equal(oldProducts.length, 125);
  assert.deepEqual(await migrate(populated.migration, DIRECTORY), [CANDIDATE]);
  assert.deepEqual(await migrate(populated.migration, DIRECTORY), []);
  assert.deepEqual((await populated.runtime.query(`SELECT to_jsonb(r) AS row FROM
    secureshop_review.product_target_embedding_revisions r WHERE r.revision_id=$1`,
  [oldRevision.revisionId])).rows, oldRows);
  assert.deepEqual((await populated.runtime.query(`SELECT to_jsonb(p) AS row FROM
    secureshop_review.product_target_products p WHERE target_id=$1 ORDER BY product_id`,
  [old.targetId])).rows, oldProducts);
  assert.deepEqual(await preimages(populated.runtime, old.targetId),
    { revisions: [], manuals: [] }, 'migration must not invent historical preimages');
  await assert.rejects(populated.runtime.query(`SELECT * FROM
    secureshop_review.capture_product_manual_preimage($1,$2,$3::jsonb)`,
  [oldManual.operationId, old.targetId, JSON.stringify(oldManual.chunks)]),
  error => error.code === '55000');
  const oldSearch = await populated.repos.revisions.searchWithLineage(oldScene,
    { embedding: vector(999), limit: 1 });
  assert.equal(oldSearch.lineage.eligible, false);
  assert.equal(oldSearch.rows[0].sourceKind, 'manual');

  assert.deepEqual(await migrate(fresh.migration, DIRECTORY), names);
  assert.deepEqual(await migrate(fresh.migration, DIRECTORY), []);
  const owned = binding(4101), sibling = binding(4201);
  await fresh.repos.products.provision(owned, { ownMerchantId: 12, products: corpus });
  await fresh.repos.retrieval.provision(owned, {
    embeddingModel: 'fixture-embedding-v1', embeddingDimension: 384, documents });
  await fresh.repos.products.provision(sibling,
    { ownMerchantId: 12, products: [corpus[0]] });
  await fresh.repos.retrieval.provision(sibling, {
    embeddingModel: 'fixture-embedding-v1', embeddingDimension: 384,
    documents: [documents[0]] });
  const ownerScene = await scene(fresh.runtime, owned), siblingScene = await scene(fresh.runtime, sibling);
  const reader = sourceReader(fresh.runtime, ownerScene);
  const siblingSnapshot = await fresh.repos.revisions.snapshot(siblingScene);
  const siblingRevision = await fresh.repos.revisions.publish(siblingScene,
    publishInput(siblingSnapshot, randomUUID()));
  const siblingBefore = await preimages(fresh.runtime, sibling.targetId);
  const baseSnapshot = await fresh.repos.revisions.snapshot(ownerScene);
  const baseInput = publishInput(baseSnapshot, randomUUID());
  const baseRevision = await fresh.repos.revisions.publish(ownerScene, baseInput);
  assert.equal(baseRevision.replayed, false);
  let stored = await preimages(fresh.runtime, owned.targetId);
  assert.equal(stored.revisions.length, 1);
  assertOriginal(stored.revisions[0], 125);
  assert.deepEqual(await fresh.repos.revisions.publish(ownerScene, baseInput),
    { ...baseRevision, replayed: true });
  assert.deepEqual(await preimages(fresh.runtime, owned.targetId), stored,
    'same operation replay must not rewrite original bytes');

  const input = manualInput(owned, ownerScene, randomUUID());
  const appended = await fresh.repos.manuals.appendManualWithLineage(ownerScene, input);
  assert.equal(appended.lineage.eligible, true);
  assert.equal(appended.lineage.version, 2);
  assert.equal(appended.lineage.preimageRef.documentDigest, appended.receipt.documentDigest);
  const manualStored = await preimages(fresh.runtime, owned.targetId);
  assert.equal(manualStored.manuals.length, 1);
  assert.equal(manualStored.manuals[0].documents_json,
    (await fresh.runtime.query(`SELECT $1::jsonb::text AS canonical`,
      [JSON.stringify(input.chunks)])).rows[0].canonical);
  assert.equal(sha(manualStored.manuals[0].documents_json),
    appended.receipt.documentDigest);
  const originalManual = await reader.adapter.readManualPreimage({
    state: reader.state, operationId: input.operationId });
  assert.equal(originalManual.documentsJson, manualStored.manuals[0].documents_json);
  assert.equal(originalManual.receipt.receiptSha256, appended.receipt.receiptSha256);
  const appendedReplay = await fresh.repos.manuals.appendManualWithLineage(ownerScene, input);
  assert.equal(appendedReplay.receipt.replayed, true);
  assert.deepEqual(appendedReplay.lineage,
    { eligible: false, reason: 'replayed_without_original' });
  assert.deepEqual((await preimages(fresh.runtime, owned.targetId)).manuals,
    manualStored.manuals);

  const snapshot = await fresh.repos.revisions.snapshot(ownerScene);
  const selectedInput = publishInput(snapshot, randomUUID(), item =>
    item.sourceKind === 'manual' ? vector(999) : vector(Number(item.sourceId)));
  const selectedRevision = await fresh.repos.revisions.publish(ownerScene, selectedInput);
  stored = await preimages(fresh.runtime, owned.targetId);
  assert.equal(stored.revisions.length, 2);
  const selectedStored = stored.revisions.find(row => row.revision_id === selectedRevision.revisionId);
  assertOriginal(selectedStored, 126);
  const originalRevision = await reader.adapter.readRevisionPreimage({
    state: reader.state, revisionId: selectedRevision.revisionId });
  assert.equal(originalRevision.sourceSetJson, selectedStored.source_set_json);
  assert.equal(originalRevision.vectorsJson, selectedStored.vectors_json);
  const found = await fresh.repos.revisions.searchWithLineage(ownerScene,
    { embedding: vector(999), limit: 1 });
  assert.equal(found.rows[0].sourceKind, 'manual');
  assert.equal(found.lineage.eligible, true);
  assert.equal(found.lineage.version, 2);
  assert.equal(found.lineage.preimageRef.revisionId, selectedRevision.revisionId);
  assert.equal(found.lineage.preimageRef.sourceSetDigest, selectedStored.source_digest);
  assert.equal(found.lineage.preimageRef.vectorDigest, selectedStored.vector_digest);
  assert.equal(found.lineage.selected[0].sourceKind, 'manual');
  assert.ok(Buffer.byteLength(JSON.stringify(found.lineage), 'utf8') <= 48 * 1024,
    'semantic lineage limit remains 48 KiB with shipped dense corpus');
  assert.ok(Buffer.byteLength(selectedStored.vectors_json, 'utf8') > 48 * 1024,
    'the test must exercise a genuinely large original vector preimage');

  const rollbackId = randomUUID();
  const rollbackInput = publishInput({ ...snapshot, expectedHead: selectedRevision.revisionId },
    rollbackId, item => item.sourceKind === 'manual'
      ? vector(999) : vector(Number(item.sourceId)));
  await assert.rejects(withTransaction(fresh.runtime, async client => {
    await fresh.repos.revisions.publishInTransaction(client, ownerScene, rollbackInput);
    throw new Error('intentional publication rollback');
  }), /intentional publication rollback/);
  assert.equal((await fresh.runtime.query(`SELECT count(*)::int AS count FROM
    secureshop_review.product_target_embedding_revisions WHERE revision_id=$1`,
  [rollbackId])).rows[0].count, 0);
  assert.deepEqual(await preimages(fresh.runtime, owned.targetId), stored);
  const advanced = await fresh.repos.revisions.publish(ownerScene, rollbackInput);
  assert.equal(advanced.replayed, false);
  assert.equal((await fresh.repos.revisions.readHead(ownerScene)).revisionId,
    advanced.revisionId);
  const retainedOriginal = (await preimages(fresh.runtime, owned.targetId)).revisions
    .find(row => row.revision_id === selectedRevision.revisionId);
  assert.deepEqual(retainedOriginal, selectedStored,
    'head advance cannot substitute the original revision preimage');
  assert.deepEqual(await reader.adapter.readRevisionPreimage({
    state: reader.state, revisionId: selectedRevision.revisionId }), originalRevision);
  assert.deepEqual(await reader.adapter.readManualPreimage({
    state: reader.state, operationId: input.operationId }), originalManual);

  const digestRows = (await fresh.runtime.query(`SELECT revision_id,
    encode(source_set_digest,'hex') AS source_digest,encode(vector_digest,'hex') AS vector_digest
    FROM secureshop_review.product_target_embedding_revisions WHERE target_id=$1
    ORDER BY revision_id`, [owned.targetId])).rows;
  const manualDigest = (await fresh.runtime.query(`SELECT operation_id,
    encode(document_digest,'hex') AS document_digest,encode(receipt_sha256,'hex') AS receipt_sha256
    FROM secureshop_review.product_target_manual_ingests WHERE target_id=$1`,
  [owned.targetId])).rows;
  await fresh.repos.products.cleanup(owned, { operationId: randomUUID() });
  assert.deepEqual(await preimages(fresh.runtime, owned.targetId),
    { revisions: [], manuals: [] }, 'canonical retirement removes original payloads');
  await assert.rejects(reader.adapter.readRevisionPreimage({
    state: reader.state, revisionId: selectedRevision.revisionId }),
  { code: 'SHOP_SCENE_STALE' });
  await assert.rejects(reader.adapter.readManualPreimage({
    state: reader.state, operationId: input.operationId }),
  { code: 'SHOP_SCENE_STALE' });
  assert.deepEqual((await fresh.runtime.query(`SELECT revision_id,
    encode(source_set_digest,'hex') AS source_digest,encode(vector_digest,'hex') AS vector_digest
    FROM secureshop_review.product_target_embedding_revisions WHERE target_id=$1
    ORDER BY revision_id`, [owned.targetId])).rows, digestRows);
  assert.deepEqual((await fresh.runtime.query(`SELECT operation_id,
    encode(document_digest,'hex') AS document_digest,encode(receipt_sha256,'hex') AS receipt_sha256
    FROM secureshop_review.product_target_manual_ingests WHERE target_id=$1`,
  [owned.targetId])).rows, manualDigest);
  assert.deepEqual(await preimages(fresh.runtime, sibling.targetId), siblingBefore);
  assert.equal((await fresh.repos.revisions.readHead(siblingScene)).revisionId,
    siblingRevision.revisionId);
});
