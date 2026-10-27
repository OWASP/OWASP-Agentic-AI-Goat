'use strict';
// Import-inert controlled lifecycle support. No provider, browser or objective credit.
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const FINGERPRINT = 'a'.repeat(64);
function validateScope(scope) {
  assert.ok(scope && Number.isSafeInteger(Number(scope.platformOwnerId)) && Number(scope.platformOwnerId) > 0);
  assert.ok(Number.isSafeInteger(scope.generation) && scope.generation >= 0);
  assert.ok(Number.isSafeInteger(scope.platformSessionId) && scope.platformSessionId > 0);
  for (const key of ['launchId', 'scenarioId']) assert.ok(typeof scope[key] === 'string' && scope[key].length > 0);
}
function requirePools(pools) {
  for (const key of ['identity', 'secureshop', 'secureshop_agents', 'secureshop_review']) assert.equal(typeof pools?.[key]?.query, 'function', `Missing runtime pool ${key}`);
}
function retrievalBinding(scope, targetId) {
  validateScope(scope);
  return { targetId, launchId: scope.launchId, scenarioId: scope.scenarioId, generation: scope.generation,
    platformOwnerId: scope.platformOwnerId, platformSessionId: scope.platformSessionId };
}
async function seedSecureShopOwner(pools, { platformOwnerId, platformSessionId }) {
  // Only the admitted process environment can authorize side-effecting factories.
  require('./adminStudentDeletionRenderedSupport').admitStores(process.env);
  requirePools(pools);
  assert.ok(Number.isSafeInteger(platformOwnerId) && platformOwnerId > 0);
  assert.ok(Number.isSafeInteger(platformSessionId) && platformSessionId > 0);
  const launches = require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(pools.identity);
  assert.equal(await launches.readActiveMetadata({ platformOwnerId, platformSessionId }), null, 'Seed requires a fresh owned launch scope');
  const issued = await launches.issueOrRenew({ platformOwnerId, platformSessionId, expiresAt: new Date(Date.now() + 3600000) });
  const scope = issued.binding; validateScope(scope);
  assert.equal(Number(scope.platformOwnerId), platformOwnerId); assert.equal(scope.platformSessionId, platformSessionId);
  const cleanup = await require('../../server/services/secureshopCleanupComposition').getSecureShopCleanupComposition();
  const personas = require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({ commercePool: pools.secureshop, agentsPool: pools.secureshop_agents });
  await personas.ensureTemplates(); const merchant = await personas.readPersona(12);
  assert.equal(merchant.role, 'merchant');
  const authority = { platformOwnerId, platformSessionId, launchId: scope.launchId, expectedGeneration: scope.generation };
  const reviewTarget = await launches.reserveReviewsTarget(authority), productTarget = await launches.reserveProductsTarget(authority);
  await cleanup.reviews.provision({ ...scope, targetId: reviewTarget.targetId }, { reviews: [{ productId: 1, authorId: platformOwnerId, body: 'synthetic lifecycle review', rating: 3 }] });
  const products = [12, 9].map((id, index) => ({ id: index + 1, sourceRetailerId: id, retailerId: id,
    name: 'Synthetic lifecycle product', description: 'controlled deletion fixture', descriptionHtml: '<p>controlled deletion fixture</p>',
    price: 10, category: 'fixture', imageUrl: null, images: [], stockQuantity: 2, status: 'active', templateSource: 'owned deletion fixture', createdAt: null, updatedAt: null }));
  await cleanup.products.provision({ ...scope, targetId: productTarget.targetId }, { ownMerchantId: 12, products });
  const binding = retrievalBinding(scope, productTarget.targetId);
  const embeddingAuthority = { checkCurrent: value => launches.assertCurrent(value), checkCleanup: async () => { throw Error('Seed must not perform cleanup'); } };
  const retrieval = require('../../server/database/postgres/secureshopBoundProductRetrievalRepository').createSecureShopBoundProductRetrievalRepository(pools.secureshop_review, embeddingAuthority);
  await retrieval.provision(binding, { embeddingModel: 'controlled-deletion-fixture', embeddingDimension: 2, documents: [
    { sourceKind: 'product', sourceId: 1, chunkIndex: 0, text: 'synthetic lifecycle product', embedding: [1, 0] },
    { sourceKind: 'manual', sourceId: 91, chunkIndex: 0, text: 'synthetic lifecycle manual', embedding: [0.8, 0.2] }
  ] });
  const revisions = require('../../server/database/postgres/secureshopEmbeddingRevisionRepository').createSecureShopEmbeddingRevisionRepository(pools.secureshop_review, { ...embeddingAuthority, getRuntimeFingerprint: () => FINGERPRINT });
  const source = await revisions.snapshot(binding);
  await revisions.publish(binding, { operationId: randomUUID(), sourceSetDigest: source.sourceSetDigest, expectedHead: source.expectedHead,
    expectedRuntimeFingerprint: FINGERPRINT, documents: source.documents.map(d => ({ sourceKind: d.sourceKind, sourceId: d.sourceId, chunkIndex: d.chunkIndex,
      sourceSha256: d.sourceSha256, embedding: Array.from({ length: 384 }, (_, i) => i === 0 ? 1 : 0) })) });
  const conversation = await cleanup.conversationService.create(scope, { id: merchant.id, role: merchant.role });
  await personas.createSession({ sessionId: randomUUID(), jti: randomUUID(), scope, persona: merchant, expiresAt: new Date(Date.now() + 3600000).toISOString() });
  return { scope, reviewTargetId: reviewTarget.targetId, productTargetId: productTarget.targetId, conversationId: conversation.id,
    seedProvenance: 'controlled-lifecycle-vectors-no-model-credit', nativeVerified: false };
}
const TABLES = Object.freeze({ reviews: ['reviews', 'reviewTargetId'], products: ['product_target_products', 'productTargetId'], documents: ['product_target_retrieval_documents', 'productTargetId'],
  revisions: ['product_target_embedding_revisions', 'productTargetId'], heads: ['product_target_embedding_heads', 'productTargetId'],
  embeddingCleanup: ['product_target_embedding_cleanup_receipts', 'productTargetId'], reviewCleanup: ['review_cleanup_receipts', 'reviewTargetId'],
  productCleanup: ['product_cleanup_receipts', 'productTargetId'], retrievalCleanup: ['product_target_retrieval_cleanup_receipts', 'productTargetId'] });
function byteaHex(value) { assert.match(value, /^\\x[0-9a-f]{64}$/); return value.slice(2); }
function assertCleanupBindings(snapshot) {
  const scope = snapshot.scope;
  for (const key of ['reviewCleanup', 'productCleanup', 'retrievalCleanup', 'embeddingCleanup']) {
    assert.equal(snapshot[key].length, 1); const r = snapshot[key][0].row;
    assert.equal(r.target_id, key === 'reviewCleanup' ? snapshot.reviewTargetId : snapshot.productTargetId);
    for (const [column, field] of [['launch_id', 'launchId'], ['scenario_id', 'scenarioId'], ['generation', 'generation'],
      ['original_platform_owner_id', 'platformOwnerId'], ['original_platform_session_id', 'platformSessionId']]) assert.equal(r[column], scope[field]);
    byteaHex(r.receipt_sha256);
    assert.ok(typeof r.completed_at === 'string' && Number.isFinite(Date.parse(r.completed_at)));
    if (key === 'embeddingCleanup' || key === 'retrievalCleanup') {
      assert.equal(snapshot[key][0].receipt_valid, true, `${key} canonical SQL digest invalid`);
      if (key === 'embeddingCleanup') assert.equal(snapshot[key][0].manifest_valid, true);
      continue;
    }
    assert.match(r.operation_id, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    const common = { version: 1, operationId: r.operation_id, targetId: r.target_id };
    if (key === 'productCleanup') common.kind = 'products';
    Object.assign(common, { launchId: scope.launchId, scenarioId: scope.scenarioId, generation: scope.generation,
      platformOwnerId: scope.platformOwnerId, platformSessionId: scope.platformSessionId });
    if (key === 'productCleanup') Object.assign(common, { deletedProductCount: r.deleted_product_count, sourceSha256: byteaHex(r.source_sha256) });
    else Object.assign(common, { deletedReviewCount: r.deleted_review_count, seedCount: r.seed_count, seedSha256: byteaHex(r.seed_sha256) });
    assert.equal(byteaHex(r.receipt_sha256), createHash('sha256').update(JSON.stringify(common)).digest('hex'));
  }
  assert.equal(snapshot.retrievalCleanup[0].row.operation_id, snapshot.productCleanup[0].row.operation_id);
}
async function readSecureShopOwner(pools, seeded) {
  requirePools(pools); validateScope(seeded.scope);
  for (const key of ['reviewTargetId', 'productTargetId', 'conversationId']) assert.ok(seeded[key]);
  const rows = async (pool, sql, params) => (await pool.query(sql, params)).rows;
  const result = { scope: structuredClone(seeded.scope), reviewTargetId: seeded.reviewTargetId, productTargetId: seeded.productTargetId };
  for (const [key, [table, target]] of Object.entries(TABLES)) result[key] = await rows(pools.secureshop_review,
    `SELECT to_jsonb(r) AS row FROM secureshop_review.${table} r WHERE target_id=$1 ORDER BY to_jsonb(r)::text`, [seeded[target]]);
  // Use PostgreSQL's canonical JSONB encoding, never a lookalike JS JSON encoder.
  result.retrievalCleanup = await rows(pools.secureshop_review, `SELECT to_jsonb(r) AS row,
    r.receipt_sha256=secureshop_review.product_retrieval_cleanup_digest(r.operation_id,r.target_id,r.launch_id,r.scenario_id,r.generation,
      r.original_platform_owner_id,r.original_platform_session_id,r.deleted_document_count) AS receipt_valid
    FROM secureshop_review.product_target_retrieval_cleanup_receipts r WHERE target_id=$1`, [seeded.productTargetId]);
  result.embeddingCleanup = await rows(pools.secureshop_review, `SELECT to_jsonb(r) AS row,
    r.receipt_sha256=sha256(convert_to(jsonb_build_object('version',1,'targetId',r.target_id,'launchId',r.launch_id,
      'scenarioId',r.scenario_id,'generation',r.generation,'platformOwnerId',r.original_platform_owner_id,
      'platformSessionId',r.original_platform_session_id,'revisionCount',r.revision_count,'deletedVectorCount',r.deleted_vector_count,
      'revisionManifestSha256',encode(r.revision_manifest_sha256,'hex'))::text,'UTF8')) AS receipt_valid,
    r.revision_manifest_sha256=(SELECT sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_object('revisionId',v.revision_id,
      'runtimeFingerprint',encode(v.runtime_fingerprint,'hex'),'sourceSetDigest',encode(v.source_set_digest,'hex'),
      'vectorDigest',encode(v.vector_digest,'hex'),'documentCount',v.document_count) ORDER BY v.revision_id),'[]'::jsonb)::text,'UTF8'))
      FROM secureshop_review.product_target_embedding_revisions v WHERE v.target_id=r.target_id) AS manifest_valid
    FROM secureshop_review.product_target_embedding_cleanup_receipts r WHERE target_id=$1`, [seeded.productTargetId]);
  result.vectors = await rows(pools.secureshop_review, 'SELECT to_jsonb(v) AS row FROM secureshop_review.product_target_embedding_vectors v JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id) WHERE r.target_id=$1 ORDER BY to_jsonb(v)::text', [seeded.productTargetId]);
  result.launch = await rows(pools.identity, 'SELECT launch_id,original_platform_owner_id,original_platform_session_id,platform_session_id,generation,status FROM identity.secureshop_launches WHERE launch_id=$1', [seeded.scope.launchId]);
  result.conversation = await rows(pools.secureshop_agents, 'SELECT id,binding_state FROM secureshop_agents.agent_sessions WHERE id=$1', [seeded.conversationId]);
  result.personas = await rows(pools.secureshop_agents, 'SELECT session_id AS id,revoked_at FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1 ORDER BY session_id', [seeded.scope.launchId]);
  return result;
}
function assertSecureShopDeletion(before, after, siblingBefore, siblingAfter) {
  assert.deepEqual(after.scope, before.scope); assert.notEqual(before.scope.platformOwnerId, siblingBefore.scope.platformOwnerId);
  assert.equal(after.reviewTargetId, before.reviewTargetId); assert.equal(after.productTargetId, before.productTargetId);
  assertCleanupBindings(after);
  assert.notEqual(before.scope.launchId, siblingBefore.scope.launchId); assert.deepEqual(siblingAfter, siblingBefore);
  for (const key of ['reviews', 'products', 'documents', 'vectors', 'heads']) { assert.ok(before[key].length > 0, `Missing seed ${key}`); assert.deepEqual(after[key], [], `Retained target ${key}`); }
  assert.ok(before.revisions.length > 0); assert.deepEqual(after.revisions, before.revisions);
  for (const [key, count, expected] of [['embeddingCleanup', 'deleted_vector_count', before.vectors.length], ['reviewCleanup', 'deleted_review_count', before.reviews.length], ['productCleanup', 'deleted_product_count', before.products.length]]) {
    assert.deepEqual(before[key], []); assert.equal(after[key].length, 1); assert.equal(after[key][0].row[count], expected);
  }
  assert.deepEqual(before.retrievalCleanup, []); assert.equal(after.retrievalCleanup.length, 1);
  assert.equal(after.retrievalCleanup[0].row.deleted_document_count, before.documents.length);
  assert.equal(after.embeddingCleanup[0].row.revision_count, before.revisions.length);
  assert.equal(before.launch.length, 1); assert.equal(after.launch.length, 1); assert.equal(before.launch[0].status, 'active'); assert.equal(after.launch[0].status, 'revoked');
  assert.equal(before.launch[0].original_platform_session_id, before.scope.platformSessionId);
  assert.equal(before.launch[0].platform_session_id, before.scope.platformSessionId);
  const fromGeneration = before.launch[0].generation;
  assert.match(fromGeneration, /^[1-9][0-9]*$/, 'Original launch generation must be canonical PostgreSQL bigint text');
  const toGeneration = Number(fromGeneration) + 1;
  assert(Number.isSafeInteger(toGeneration) && toGeneration > 1, 'Deletion fence generation must be bounded');
  assert.equal(Number(fromGeneration), before.scope.generation, 'Seeded launch and bound scope must agree');
  const expectedLaunch = { ...before.launch[0], generation: String(toGeneration),
    status: 'revoked', platform_session_id: null };
  assert.deepEqual(after.launch[0], expectedLaunch);
  assert.equal(before.conversation.length, 1); assert.deepEqual(after.conversation, [{ ...before.conversation[0], binding_state: 'abandoned' }]);
  assert.equal(before.conversation[0].binding_state, 'active'); assert.ok(before.personas.length > 0);
  assert.deepEqual(after.personas.map(p => p.id), before.personas.map(p => p.id));
  for (const p of before.personas) assert.equal(p.revoked_at, null);
  for (const p of after.personas) assert.ok(p.revoked_at && Number.isFinite(Date.parse(p.revoked_at)));
  return { scopedLifecycleRowsDeleted: true, immutableRevisionsRetained: true, siblingUnchanged: true,
    fullStoreCoverage: false, allExternalResourcesAbsent: false, canonicalCredit: false, nativeVerified: false };
}
module.exports = { seedSecureShopOwner, readSecureShopOwner, assertSecureShopDeletion, assertCleanupBindings, retrievalBinding, TABLES };
