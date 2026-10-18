'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createSecureShopBoundProductRetrievalRepository } = require('../server/database/postgres/secureshopBoundProductRetrievalRepository');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');

const binding = Object.freeze({
  targetId: '30000000-0000-4000-8000-000000000081',
  launchId: '10000000-0000-4000-8000-000000000081',
  scenarioId: '20000000-0000-4000-8000-000000000081',
  generation: 3,
  platformOwnerId: 81,
  platformSessionId: 801,
});
const operationId = '40000000-0000-4000-8000-000000000081';
const document = Object.freeze({ sourceKind: 'product', sourceId: 7, chunkIndex: 0,
  text: 'red product', embedding: [1, 0] });

function createPool(handler, events = []) {
  const client = {
    async query(sql, params = []) {
      const compact = sql.replace(/\s+/g, ' ').trim();
      events.push(['sql', compact, params]);
      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(compact)) return { rows: [], rowCount: 0 };
      return handler(compact, params, { transaction: true });
    },
    release(error) { events.push(['release', Boolean(error)]); },
  };
  return {
    events,
    async connect() { events.push(['connect']); return client; },
    async query(sql, params = []) {
      const compact = sql.replace(/\s+/g, ' ').trim();
      events.push(['sql', compact, params]);
      return handler(compact, params, { transaction: false });
    },
  };
}
function repository(pool, { current, cleanup } = {}) {
  return createSecureShopBoundProductRetrievalRepository(pool, {
    checkCurrent: current || (async value => pool.events.push(['current', value.targetId])),
    checkCleanup: cleanup || (async value => pool.events.push(['cleanup', value.operationId])),
  });
}
function receiptRow(overrides = {}) {
  return {
    operation_id: operationId,
    target_id: binding.targetId,
    launch_id: binding.launchId,
    scenario_id: binding.scenarioId,
    generation: String(binding.generation),
    original_platform_owner_id: binding.platformOwnerId,
    original_platform_session_id: binding.platformSessionId,
    deleted_document_count: 2,
    receipt_sha256: Buffer.alloc(32, 4),
    completed_at: new Date('2026-09-19T12:00:00Z'),
    receipt_valid: true,
    ...overrides,
  };
}

function provisionHandler(sql) {
  if (sql.includes('SELECT t.* FROM secureshop_review.product_targets t')) {
    assert.match(sql, /WHERE t\.target_id=\$1/);
    return { rows: [{ lifecycle: 'active' }] };
  }
  if (sql.includes('FROM secureshop_review.product_target_retrieval_config')) return { rows: [] };
  if (sql.includes('provision_product_retrieval')) return { rows: [{ provision_product_retrieval: 1 }] };
  if (sql.includes('count(*)::integer AS count')) return { rows: [{ count: 1 }] };
  throw new Error(`Unhandled provision SQL: ${sql}`);
}

// Input validation is deliberately tested before any authority or SQL access.
test('rejects malformed bindings and non-finite vectors before DB access', async () => {
  const pool = createPool(() => { throw new Error('SQL must not run'); });
  const value = repository(pool);
  await assert.rejects(value.provision({ ...binding, targetId: 'not-a-uuid' }, {
    embeddingModel: 'embed-v1', embeddingDimension: 2, documents: [document],
  }), { code: 'INVALID_ARGUMENT' });
  await assert.rejects(value.provision(binding, { embeddingModel: 'embed-v1',
    embeddingDimension: 2, documents: [{ ...document, embedding: [NaN, 0] }] }),
  { code: 'INVALID_ARGUMENT' });
  assert.deepEqual(pool.events, []);
});

test('provision uses the aliased canonical target and checks current authority before commit', async () => {
  const pool = createPool(provisionHandler);
  const value = repository(pool);
  const result = await value.provision(binding, { embeddingModel: 'embed-v1',
    embeddingDimension: 2, documents: [document] });
  assert.equal(result.documentCount, 1);
  assert.ok(pool.events.some(event => event[0] === 'sql'
    && event[1].includes('provision_product_retrieval')));
  assert.deepEqual(pool.events.filter(event => event[0] === 'current').length, 2);
  const lastCurrent = pool.events.map(event => event[0]).lastIndexOf('current');
  const commit = pool.events.findIndex(event => event[0] === 'sql' && event[1] === 'COMMIT');
  assert.ok(lastCurrent < commit, 'the second authority check is a pre-commit check');
});

test('failed provision pre-commit authority rolls back all writes', async () => {
  const pool = createPool(provisionHandler);
  let checks = 0;
  const value = repository(pool, { current: async () => {
    checks += 1;
    pool.events.push(['current']);
    if (checks === 2) throw Object.assign(new Error('stale'), { code: 'STALE_LAUNCH' });
  } });
  await assert.rejects(value.provision(binding, { embeddingModel: 'embed-v1',
    embeddingDimension: 2, documents: [document] }), { code: 'STALE_LAUNCH' });
  assert.ok(pool.events.some(event => event[0] === 'sql' && event[1] === 'ROLLBACK'));
  assert.equal(pool.events.some(event => event[0] === 'sql' && event[1] === 'COMMIT'), false);
});

test('replacement checks authority in its transaction after the security-definer write', async () => {
  const pool = createPool(sql => {
    if (sql.includes('JOIN secureshop_review.product_target_retrieval_config')) {
      return { rows: [{ lifecycle: 'active', retrieval_lifecycle: 'active',
        embedding_model: 'embed-v1', embedding_dimension: 2 }] };
    }
    if (sql.includes('replace_product_retrieval')) {
      return { rows: [{ replaced_count: 1, document_count: 1, replayed: false }] };
    }
    throw new Error(`Unhandled replacement SQL: ${sql}`);
  });
  const value = repository(pool);
  const result = await value.replaceDocuments(binding, { operationId,
    embeddingModel: 'embed-v1', embeddingDimension: 2, documents: [document] });
  assert.equal(result.replayed, false);
  assert.equal(pool.events.filter(event => event[0] === 'current').length, 2);
  assert.ok(pool.events.map(event => event[0]).lastIndexOf('current')
    < pool.events.findIndex(event => event[0] === 'sql' && event[1] === 'COMMIT'));
});

test('search uses the exact binding and ranks only target-owned stored vectors', async () => {
  const pool = createPool(sql => {
    if (sql.includes('JOIN secureshop_review.product_target_retrieval_config')) {
      return { rows: [{ embedding_model: 'embed-v1', embedding_dimension: 2 }] };
    }
    if (sql.includes('FROM secureshop_review.product_target_retrieval_documents d')) {
      return { rows: [{ source_kind: 'product', source_id: '7', chunk_index: 0,
        body: 'red product', embedding: [1, 0], source_sha256: Buffer.alloc(32) }] };
    }
    throw new Error(`Unhandled search SQL: ${sql}`);
  });
  const value = repository(pool);
  const rows = await value.search(binding, { embeddingModel: 'embed-v1',
    embedding: [1, 0], limit: 1 });
  assert.equal(rows[0].sourceId, 7);
  assert.equal(rows[0].score, 1);
  const documentQuery = pool.events.find(event => event[0] === 'sql'
    && event[1].includes('FROM secureshop_review.product_target_retrieval_documents d'));
  assert.deepEqual(documentQuery[2], [binding.targetId, binding.generation]);
});

test('retirement requires the canonical product target to already be retired', async () => {
  const pool = createPool(sql => {
    if (sql.includes('SELECT t.lifecycle FROM secureshop_review.product_targets t')) {
      return { rows: [{ lifecycle: 'active' }] };
    }
    throw new Error(`Unexpected retirement SQL: ${sql}`);
  });
  const value = repository(pool);
  await assert.rejects(value.retire(binding, { operationId }),
    { code: 'PRODUCT_TARGET_UNAVAILABLE' });
  assert.equal(pool.events.some(event => event[0] === 'sql'
    && event[1].includes('retire_product_target_retrieval')), false);
});

test('retirement validates the SQL-canonical receipt tuple and digest before commit', async () => {
  const pool = createPool((sql, params) => {
    if (sql.includes('SELECT t.lifecycle FROM secureshop_review.product_targets t')) {
      assert.match(sql, /product_targets t WHERE t\.target_id=\$1/);
      return { rows: [{ lifecycle: 'retired' }] };
    }
    if (sql.includes('SELECT c.lifecycle AS retrieval_lifecycle')) {
      return { rows: [{ retrieval_lifecycle: 'active', document_count: 2 }] };
    }
    if (sql.includes('SELECT operation_id,target_id')) return { rows: [] };
    if (sql.includes('retire_product_target_retrieval')) return { rows: [receiptRow()] };
    if (sql.includes('product_retrieval_cleanup_digest')) {
      assert.deepEqual(params, [operationId, ...Object.values(binding)]);
      return { rows: [receiptRow()] };
    }
    throw new Error(`Unhandled retirement SQL: ${sql}`);
  });
  const value = repository(pool);
  const result = await value.retire(binding, { operationId });
  assert.equal(result.deletedDocumentCount, 2);
  assert.equal(result.receiptSha256, Buffer.alloc(32, 4).toString('hex'));
  assert.equal(pool.events.filter(event => event[0] === 'cleanup').length, 2);
  assert.ok(pool.events.map(event => event[0]).lastIndexOf('cleanup')
    < pool.events.findIndex(event => event[0] === 'sql' && event[1] === 'COMMIT'));
});

test('cleanup receipt read verifies retired empty state, exact tuple and canonical digest', async () => {
  const pool = createPool((sql, params) => {
    if (sql.includes('SELECT t.lifecycle FROM secureshop_review.product_targets t')) {
      return { rows: [{ lifecycle: 'retired' }] };
    }
    if (sql.includes('SELECT c.lifecycle AS retrieval_lifecycle')) {
      return { rows: [{ retrieval_lifecycle: 'retired', document_count: 0 }] };
    }
    if (sql.includes('product_retrieval_cleanup_digest')) {
      assert.deepEqual(params, [operationId, binding.targetId, binding.launchId,
        binding.scenarioId, binding.generation, binding.platformOwnerId,
        binding.platformSessionId]);
      return { rows: [receiptRow()] };
    }
    throw new Error(`Unhandled receipt SQL: ${sql}`);
  });
  const value = repository(pool);
  const result = await value.readCleanupReceipt(binding, { operationId });
  assert.equal(result.operationId, operationId);
  assert.equal(result.targetId, binding.targetId);
  assert.equal(result.completedAt, '2026-09-19T12:00:00.000Z');
  assert.equal(pool.events.filter(event => event[0] === 'cleanup').length, 2);
});

test('invalid digest or immutable receipt tuple is rejected and transaction rolls back', async () => {
  for (const bad of [receiptRow({ receipt_valid: false }),
    receiptRow({ original_platform_owner_id: binding.platformOwnerId + 1 })]) {
    const pool = createPool(sql => {
      if (sql.includes('SELECT t.lifecycle FROM secureshop_review.product_targets t')) {
        return { rows: [{ lifecycle: 'retired' }] };
      }
      if (sql.includes('SELECT c.lifecycle AS retrieval_lifecycle')) {
        return { rows: [{ retrieval_lifecycle: 'retired', document_count: 0 }] };
      }
      if (sql.includes('product_retrieval_cleanup_digest')) return { rows: [bad] };
      throw new Error(`Unhandled invalid receipt SQL: ${sql}`);
    });
    await assert.rejects(repository(pool).readCleanupReceipt(binding, { operationId }),
      { code: 'BOUND_RETRIEVAL_MISMATCH' });
    assert.ok(pool.events.some(event => event[0] === 'sql' && event[1] === 'ROLLBACK'));
  }
});

test('scene retrieval ingest retains birth target, current lease, and immutable grant effect', async () => {
  const current = { launchId: '10000000-0000-4000-8000-000000000082',
    scenarioId: '20000000-0000-4000-8000-000000000082', generation: 4,
    platformOwnerId: binding.platformOwnerId, platformSessionId: 802 };
  let leased = false;
  const scene = createSceneBinding(binding, {
    sceneId: '50000000-0000-4000-8000-000000000081', sceneGeneration: 1,
    grantId: '60000000-0000-4000-8000-000000000081', execution: current,
    async withLease(work) { leased = true; try { return await work(); } finally { leased = false; } },
  });
  let grants = 0, recorded = 0, replayed = false;
  const pool = createPool((sql, args) => {
    assert.equal(leased, true);
    if (sql.includes('assert_scene_execution_grant')) {
      grants++;
      assert.deepEqual(args, [scene.scene.grantId, scene.scene.sceneId, 1, binding.targetId,
        current.launchId, current.scenarioId, current.generation,
        current.platformOwnerId, current.platformSessionId]);
      return { rows: [{ allowed: true }] };
    }
    if (sql.includes('JOIN secureshop_review.product_target_retrieval_config')) {
      assert.deepEqual(args, [binding.targetId, binding.launchId, binding.scenarioId,
        binding.generation, binding.platformOwnerId, binding.platformSessionId]);
      return { rows: [{ lifecycle: 'active', retrieval_lifecycle: 'active',
        embedding_model: 'embed-v1', embedding_dimension: 2 }] };
    }
    if (sql.includes('replace_product_retrieval')) {
      return { rows: [{ replaced_count: 1, document_count: 1, replayed }] };
    }
    if (sql.includes('record_scene_retrieval_embedding_effect')) {
      recorded++;
      assert.deepEqual(args, ['retrieval_ingest', operationId, binding.targetId, scene.scene.grantId]);
      return { rows: [{ record_scene_retrieval_embedding_effect: true }] };
    }
    throw new Error(`Unexpected scene retrieval SQL: ${sql}`);
  });
  const value = repository(pool, { current: async actual => assert.deepEqual(actual, current) });
  await value.replaceDocuments(scene, { operationId, embeddingModel: 'embed-v1',
    embeddingDimension: 2, documents: [document] });
  replayed = true;
  await value.replaceDocuments(scene, { operationId, embeddingModel: 'embed-v1',
    embeddingDimension: 2, documents: [document] });
  assert.equal(grants, 4);
  assert.equal(recorded, 1);
  assert.equal(leased, false);
  await assert.rejects(value.replaceDocuments({ ...scene }, { operationId,
    embeddingModel: 'embed-v1', embeddingDimension: 2, documents: [document] }),
  { code: 'SHOP_SCENE_STALE' });
});
