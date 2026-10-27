'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const support = require('./adminStudentDeletionSecureShopSupport');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');
function sample(owner = 19) {
  return { reviewTargetId: 'review', productTargetId: 'product', scope: { platformOwnerId: owner, platformSessionId: owner, launchId: `launch-${owner}`, scenarioId: 'scene', generation: 1 },
    reviews: [{ row: { id: 1 } }], products: [{ row: { id: 1 } }], documents: [{ row: { id: 1 } }, { row: { id: 2 } }], vectors: [{ row: { id: 1 } }], heads: [{ row: { id: 1 } }],
    revisions: [{ row: { revision_id: 'immutable', source_sha256: 'retained' } }], embeddingCleanup: [], reviewCleanup: [], productCleanup: [], retrievalCleanup: [],
    launch: [{ launch_id: `launch-${owner}`, original_platform_owner_id: owner, original_platform_session_id: owner, platform_session_id: owner, generation: '1', status: 'active' }],
    conversation: [{ id: `conversation-${owner}`, binding_state: 'active' }], personas: [{ id: `persona-${owner}`, revoked_at: null }] };
}
function removed(before) {
  const after = structuredClone(before);
  for (const key of ['reviews', 'products', 'documents', 'vectors', 'heads']) after[key] = [];
  for (const [key, count] of [['embeddingCleanup', 'deleted_vector_count'], ['reviewCleanup', 'deleted_review_count'], ['productCleanup', 'deleted_product_count']]) after[key] = [{ row: { [count]: 1 } }];
  after.retrievalCleanup = [{ row: { deleted_document_count: 2 } }];
  for (const key of ['reviewCleanup', 'productCleanup', 'retrievalCleanup', 'embeddingCleanup']) {
    const r = after[key][0].row; Object.assign(r, { target_id: key === 'reviewCleanup' ? 'review' : 'product', launch_id: before.scope.launchId,
      scenario_id: 'scene', generation: 1, original_platform_owner_id: before.scope.platformOwnerId, original_platform_session_id: before.scope.platformSessionId,
      operation_id: '00000000-0000-4000-8000-000000000001', completed_at: '2026-01-01T00:00:00Z', receipt_sha256: '\\x' + 'a'.repeat(64) });
    if (key === 'embeddingCleanup' || key === 'retrievalCleanup') { after[key][0].receipt_valid = true; after[key][0].manifest_valid = true; r.revision_count = 1; continue; }
    const payload = { version: 1, operationId: r.operation_id, targetId: r.target_id };
    if (key === 'productCleanup') payload.kind = 'products';
    Object.assign(payload, { launchId: before.scope.launchId, scenarioId: 'scene', generation: 1, platformOwnerId: before.scope.platformOwnerId, platformSessionId: before.scope.platformSessionId });
    if (key === 'productCleanup') { r.source_sha256 = '\\x' + 'b'.repeat(64); Object.assign(payload, { deletedProductCount: 1, sourceSha256: 'b'.repeat(64) }); }
    else { r.seed_count = 1; r.seed_sha256 = '\\x' + 'b'.repeat(64); Object.assign(payload, { deletedReviewCount: 1, seedCount: 1, seedSha256: 'b'.repeat(64) }); }
    r.receipt_sha256 = '\\x' + createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  }
  after.launch[0].generation = '2'; after.launch[0].status = 'revoked'; after.launch[0].platform_session_id = null; after.conversation[0].binding_state = 'abandoned'; after.personas[0].revoked_at = '2026-01-01T00:00:00Z'; return after;
}
test('bounded oracle retains immutable revisions and siblings without qualification/external claims', () => {
  const before = sample(), after = removed(before), sibling = sample(20);
  const result = support.assertSecureShopDeletion(before, after, sibling, structuredClone(sibling));
  assert.equal(result.canonicalCredit, false); assert.equal(result.nativeVerified, false); assert.equal(result.allExternalResourcesAbsent, false);
  for (const key of ['reviews', 'products', 'documents', 'vectors', 'heads']) { const bad = structuredClone(after); bad[key] = before[key]; assert.throws(() => support.assertSecureShopDeletion(before, bad, sibling, sibling)); }
  for (const key of ['embeddingCleanup', 'reviewCleanup', 'productCleanup', 'retrievalCleanup', 'revisions', 'personas', 'conversation', 'launch']) {
    const bad = structuredClone(after); bad[key] = []; assert.throws(() => support.assertSecureShopDeletion(before, bad, sibling, sibling), key);
  }
  const changed = structuredClone(sibling); changed.revisions[0].row.source_sha256 = 'changed'; assert.throws(() => support.assertSecureShopDeletion(before, after, sibling, changed));
  const changedOwner = structuredClone(after); changedOwner.scope.platformSessionId++; assert.throws(() => support.assertSecureShopDeletion(before, changedOwner, sibling, sibling));
  for (const [key, value] of [['original_platform_session_id', 999], ['platform_session_id', 19]]) {
    const bad = structuredClone(after); bad.launch[0][key] = value; assert.throws(() => support.assertSecureShopDeletion(before, bad, sibling, sibling));
  }
  for (const generation of ['1', '3', 2, '02']) {
    const bad = structuredClone(after); bad.launch[0].generation = generation;
    assert.throws(() => support.assertSecureShopDeletion(before, bad, sibling, sibling), `generation ${generation}`);
  }
});
test('active launch deletion fence increments exactly once in the production transaction', () => {
  const production = readFileSync(path.join(__dirname, '../../server/database/postgres/studentDeletionRepository.js'), 'utf8');
  const active = production.slice(production.indexOf("if (launch.status === 'active')"),
    production.indexOf("} else if (launch.status === 'resetting')"));
  assert.match(active, /const resetId = randomUUID\(\), from = Number\(launch\.generation\), to = from \+ 1;/);
  assert.match(active, /UPDATE identity\.secureshop_launches\s+SET generation=\$2,status='resetting'/);
  assert.match(active, /\[launch\.launch_id,to\]/);
});
test('readback uses exact bound IDs and current schema columns, never allocates a pool', async () => {
  const calls = []; const pool = { async query(sql, args) { calls.push({ sql, args }); return { rows: [] }; } };
  const seeded = { scope: sample().scope, reviewTargetId: 'review', productTargetId: 'product', conversationId: 'conversation' };
  await support.readSecureShopOwner(Object.fromEntries(['identity', 'secureshop', 'secureshop_agents', 'secureshop_review'].map(k => [k, pool])), seeded);
  assert.equal(calls.length, Object.keys(support.TABLES).length + 6);
  assert.ok(calls.every(c => c.args.length === 1 && ['review', 'product', 'conversation', 'launch-19'].includes(c.args[0])));
  assert.ok(calls.some(c => c.sql.includes('original_platform_owner_id')));
  assert.ok(calls.some(c => c.sql.includes('session_id AS id')));
});
test('every cleanup receipt rejects foreign scope, corrupt digest and copied operation', () => {
  const after = removed(sample()); support.assertCleanupBindings(after);
  for (const key of ['reviewCleanup', 'productCleanup', 'retrievalCleanup', 'embeddingCleanup']) {
    for (const field of ['target_id', 'launch_id', 'scenario_id', 'generation', 'original_platform_owner_id', 'original_platform_session_id', 'receipt_sha256']) {
      const bad = structuredClone(after); bad[key][0].row[field] = 'wrong'; assert.throws(() => support.assertCleanupBindings(bad), `${key}.${field}`);
    }
  }
  for (const [key, field] of [['embeddingCleanup', 'manifest_valid'], ['embeddingCleanup', 'receipt_valid'], ['retrievalCleanup', 'receipt_valid']]) {
    const bad = structuredClone(after); bad[key][0][field] = false; assert.throws(() => support.assertCleanupBindings(bad));
  }
  const copied = structuredClone(after); copied.retrievalCleanup[0].row.operation_id = 'foreign'; assert.throws(() => support.assertCleanupBindings(copied));
});
test('real embedding repository accepts only projected six-field seed binding before controlled transaction boundary', async () => {
  const id = '00000000-0000-4000-8000-000000000001';
  const scope = { platformOwnerId: 19, platformSessionId: 21, generation: 1, launchId: id, scenarioId: id, status: 'active', credentialVersion: 1, expiresAt: new Date() };
  let connections = 0; const stop = Error('controlled transaction boundary');
  const pool = { query: async () => { throw Error('unexpected query'); }, connect: async () => { connections++; throw stop; } };
  const repository = require('../../server/database/postgres/secureshopEmbeddingRevisionRepository').createSecureShopEmbeddingRevisionRepository(pool,
    { checkCurrent: async () => {}, checkCleanup: async () => {}, getRuntimeFingerprint: () => 'a'.repeat(64) });
  await assert.rejects(repository.snapshot({ ...scope, targetId: id }), { code: 'INVALID_ARGUMENT' }); assert.equal(connections, 0);
  await assert.rejects(repository.snapshot(support.retrievalBinding(scope, id)), error => error === stop); assert.equal(connections, 1);
});
test('complete seed orchestration preserves owner/session and canonical factory ordering with controlled boundaries', async () => {
  const Module = require('node:module'), originalLoad = Module._load;
  const admission = require('./adminStudentDeletionRenderedSupport');
  const environment = { PG_TEST_DISPOSABLE: 'yes', PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres', PG_POOL_BUDGET: '78' };
  for (const row of admission.STORES) for (const [key, role] of [[row.runtimeVariable, row.runtimeRole], [row.migrationVariable, row.migrationRole]]) environment[key] = `postgresql://${role}@127.0.0.1:54321/dvaia_test_student_deletion_123456abcdef_${row.schema}`;
  const old = Object.fromEntries([...Object.keys(environment), 'LEGACY_PLATFORM_LIFECYCLE_ENABLED'].map(k => [k, process.env[k]]));
  Object.assign(process.env, environment); delete process.env.LEGACY_PLATFORM_LIFECYCLE_ENABLED;
  const id = '00000000-0000-4000-8000-000000000001', target = '00000000-0000-4000-8000-000000000002';
  const scope = { platformOwnerId: 19, platformSessionId: 21, generation: 1, launchId: id, scenarioId: id, status: 'active', credentialVersion: 1 };
  const pools = Object.fromEntries(['identity', 'secureshop', 'secureshop_agents', 'secureshop_review'].map(k => [k, { query: async () => { throw Error('unexpected direct SQL'); } }]));
  let events = [], occupied = false;
  const record = name => events.push(name);
  const launches = {
    async readActiveMetadata(input) { assert.deepEqual(input, { platformOwnerId: 19, platformSessionId: 21 }); record('read'); return occupied ? scope : null; },
    async issueOrRenew(input) { assert.equal(input.platformOwnerId, 19); assert.equal(input.platformSessionId, 21); record('issue'); return { binding: scope }; },
    async reserveReviewsTarget(input) { assert.deepEqual(input, { platformOwnerId: 19, platformSessionId: 21, launchId: id, expectedGeneration: 1 }); record('reviewTarget'); return { targetId: id }; },
    async reserveProductsTarget(input) { assert.equal(input.expectedGeneration, 1); record('productTarget'); return { targetId: target }; },
    async assertCurrent(binding) { assert.equal(binding.platformSessionId, 21); }
  };
  const stubs = {
    '../../server/database/postgres/secureshopLaunchRepository': { createSecureShopLaunchRepository(pool) { assert.equal(pool, pools.identity); return launches; } },
    '../../server/services/secureshopCleanupComposition': { async getSecureShopCleanupComposition() { return {
      reviews: { async provision(binding, data) { assert.equal(binding.platformOwnerId, 19); assert.equal(data.reviews[0].authorId, 19); record('reviews'); } },
      products: { async provision(binding, data) { assert.equal(binding.targetId, target); assert.equal(data.products.length, 2); assert.equal(data.ownMerchantId, 12); record('products'); } },
      conversationService: { async create(binding, persona) { assert.equal(binding, scope); assert.deepEqual(persona, { id: 12, role: 'merchant' }); record('conversation'); return { id }; } }
    }; } },
    '../../server/database/postgres/secureshopBoundPersonaRepository': { createSecureShopBoundPersonaRepository(input) { assert.equal(input.commercePool, pools.secureshop); assert.equal(input.agentsPool, pools.secureshop_agents); return {
      async ensureTemplates() { record('templates'); }, async readPersona(personaId) { assert.equal(personaId, 12); return { id: 12, role: 'merchant' }; },
      async createSession(input) { assert.equal(input.scope, scope); assert.notEqual(input.sessionId, input.jti); record('personaSession'); }
    }; } },
    '../../server/database/postgres/secureshopBoundProductRetrievalRepository': { createSecureShopBoundProductRetrievalRepository(pool, authority) { assert.equal(pool, pools.secureshop_review); return {
      async provision(binding, data) { assert.deepEqual(binding, support.retrievalBinding(scope, target)); await authority.checkCurrent(binding); await assert.rejects(authority.checkCleanup(), /must not perform cleanup/); assert.equal(data.embeddingDimension, 2); assert.equal(data.documents.length, 2); record('retrieval'); }
    }; } },
    '../../server/database/postgres/secureshopEmbeddingRevisionRepository': { createSecureShopEmbeddingRevisionRepository(pool, authority) { assert.equal(pool, pools.secureshop_review); return {
      async snapshot(binding) { assert.deepEqual(binding, support.retrievalBinding(scope, target)); record('snapshot'); return { sourceSetDigest: 'b'.repeat(64), expectedHead: null,
        documents: [{ sourceKind: 'product', sourceId: '1', chunkIndex: 0, sourceSha256: 'c'.repeat(64) }] }; },
      async publish(binding, input) { assert.equal(input.expectedRuntimeFingerprint, authority.getRuntimeFingerprint()); assert.equal(input.sourceSetDigest, 'b'.repeat(64)); assert.equal(input.documents[0].embedding.length, 384); assert.equal(input.documents[0].sourceSha256, 'c'.repeat(64)); record('publish'); }
    }; } }
  };
  Module._load = function(name, ...args) { return Object.hasOwn(stubs, name) ? stubs[name] : originalLoad.call(this, name, ...args); };
  try {
    const result = await support.seedSecureShopOwner(pools, { platformOwnerId: 19, platformSessionId: 21 });
    assert.deepEqual(events, ['read', 'issue', 'templates', 'reviewTarget', 'productTarget', 'reviews', 'products', 'retrieval', 'snapshot', 'publish', 'conversation', 'personaSession']);
    assert.equal(result.nativeVerified, false); assert.equal(result.productTargetId, target); assert.equal(result.scope, scope);
    occupied = true; events = []; await assert.rejects(support.seedSecureShopOwner(pools, { platformOwnerId: 19, platformSessionId: 21 }), /fresh owned launch/); assert.deepEqual(events, ['read']);
  } finally {
    Module._load = originalLoad;
    for (const [key, value] of Object.entries(old)) if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
});
