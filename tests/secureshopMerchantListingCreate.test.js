'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createSecureShopBoundProductRepository } = require('../server/database/postgres/secureshopBoundProductRepository');
const C = require('../server/services/secureshopListingCreateContract');

const birth = { targetId: '40000000-0000-4000-8000-000000000001',
  launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1,
  platformOwnerId: 4, platformSessionId: 5 };
const binding = createSceneBinding(birth, { sceneId: '50000000-0000-4000-8000-000000000001',
  sceneGeneration: 1, grantId: '60000000-0000-4000-8000-000000000001',
  execution: birth, withLease: work => work() });
const personaSession = { sessionId: '70000000-0000-4000-8000-000000000001', authorityVersion: '2' };
const operationId = '80000000-0000-4000-8000-000000000001';

function fixture() {
  const state = { products: [], merchantRows: [], receipts: new Map(), audits: [], queries: [] };
  const client = { async query(sql, args = []) {
    state.queries.push(sql);
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [] };
    if (sql.includes('assert_scene_execution_grant')) return { rows: [{ allowed: true }] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{
      target_id: birth.targetId, launch_id: birth.launchId, scenario_id: birth.scenarioId,
      generation: birth.generation, original_platform_owner_id: birth.platformOwnerId,
      original_platform_session_id: birth.platformSessionId, own_merchant_id: 12,
      lifecycle: 'active', source_sha256: Buffer.alloc(32, 5), source_count: 1 }] };
    if (sql.includes('SELECT COALESCE(max(product_id),0)+1'))
      return { rows: [{ product_id: state.products.length + 1 }] };
    if (sql.includes('INSERT INTO secureshop_review.product_target_products')) {
      state.products.push({ productId: args[1], actor: args[2], sourceSha256: args[3],
        name: args[4], description: args[5], price: args[6], category: args[7],
        imageUrl: args[8], images: args[9], templateSource: args[10], sql });
      return { rows: [], rowCount: 1 };
    }
    if (sql.includes('INSERT INTO secureshop_review.product_target_merchant_listings')) {
      state.merchantRows.push(args);
      return { rows: [], rowCount: 1 };
    }
    if (sql.includes('INSERT INTO secureshop_review.owned_merchant_listing_create_receipts')) {
      const keys = ['operation_id', 'target_id', 'launch_id', 'scenario_id', 'generation',
        'original_platform_owner_id', 'original_platform_session_id', 'scene_id', 'scene_generation',
        'grant_id', 'merchant_id', 'persona_session_id', 'authority_version', 'product_id',
        'scope_key', 'request_sha256', 'source_sha256', 'receipt_sha256'];
      const row = Object.fromEntries(keys.map((key, i) => [key, args[i]]));
      state.receipts.set(row.operation_id, row);
      return { rows: [row], rowCount: 1 };
    }
    if (sql.includes('FROM secureshop_review.owned_merchant_listing_create_receipts')) {
      assert.doesNotMatch(sql, /FOR\s+(?:SHARE|UPDATE|NO KEY UPDATE|KEY SHARE)\b/i,
        'SELECT,INSERT-only receipt table cannot use a locking SELECT');
      const row = state.receipts.get(args[0]);
      if (!row || (args.length > 1 && (args[1] !== row.target_id || args[2] !== row.merchant_id
          || args[3] !== row.persona_session_id || !args[4].equals(row.scope_key)))) return { rows: [] };
      return { rows: [row] };
    }
    throw Error(`Unexpected listing-create query: ${sql}`);
  }, release() {} };
  const pool = { async connect() { return client; }, async query() { throw Error('transaction required'); } };
  const repository = createSecureShopBoundProductRepository(pool, {
    checkCurrent: async () => {}, checkCleanup: async () => {},
    auditStore: { async append(_client, row) { state.audits.push(row); } },
  });
  return { repository, state, scopeKey: C.listingCreateScopeKey(binding, 12, personaSession) };
}

test('create input canonicalizes missing optional fields without inventing content', () => {
  assert.deepEqual(C.normalizeListingCreateInput({ name: 'Lamp', price: 12.25 }),
    { name: 'Lamp', description: null, category: null, price: 12.25 });
  assert.deepEqual(C.LISTING_CREATE_INPUT_SCHEMA.required, ['name', 'price']);
  for (const bad of [{ name: 'Lamp' }, { price: 12 }, { name: ' ', price: 12 },
    { name: 'Lamp', price: 12.001 }, { name: 'Lamp', price: 12, description: 7 },
    { name: 'Lamp', price: 12, stock: 9 }]) {
    assert.throws(() => C.normalizeListingCreateInput(bad), { code: 'LISTING_CREATE_INVALID' });
  }
});

test('create preview has no effect; trusted confirm inserts one owned product, audit and exact receipt', async () => {
  const f = fixture();
  const preview = await f.repository.previewListingCreate(binding, 12,
    { name: 'Practice lamp', price: 12.25 }, f.scopeKey);
  assert.deepEqual(preview.listing, { name: 'Practice lamp', description: null,
    category: null, price: 12.25 });
  assert.equal(preview.currency, 'USD'); assert.equal(preview.initialStock, 0);
  assert.equal(preview.status, 'active');
  assert.deepEqual(C.validateListingCreatePreview(JSON.parse(JSON.stringify(preview))), preview);
  assert.throws(() => C.validateListingCreatePreview({ ...preview, initialStock: 3 }),
    { code: 'LISTING_CREATE_INVALID' });
  assert.throws(() => C.validateListingCreatePreview({ ...preview, currency: 'EUR' }),
    { code: 'LISTING_CREATE_INVALID' });
  assert.equal(f.state.products.length, 0); assert.equal(f.state.audits.length, 0);
  const args = { operationId, preview, personaSession };
  const first = await f.repository.confirmListingCreate(binding, 12, args);
  assert.deepEqual(C.validateListingCreateReceipt(first, operationId), first);
  assert.equal(first.replayed, false); assert.equal(first.productId, 1);
  assert.equal(first.requestSha256, preview.requestSha256);
  assert.equal(f.state.products.length, 1); assert.equal(f.state.merchantRows.length, 1);
  assert.equal(f.state.audits.length, 1);
  assert.equal(f.state.audits[0].action, 'listing_create_confirm');
  const created = f.state.products[0];
  assert.equal(created.name, 'Practice lamp'); assert.equal(created.description, null);
  assert.equal(created.category, null); assert.equal(created.price, 12.25);
  assert.equal(created.images, '[]'); assert.equal(created.templateSource, null);
  assert.match(created.sql, /NULL,\$7,\$8,\$9,\$10,0,'active'/);
  assert.equal(first.sourceSha256, created.sourceSha256.toString('hex'));
  assert.deepEqual(await f.repository.confirmListingCreate(binding, 12, args), { ...first, replayed: true });
  assert.equal(f.state.products.length, 1); assert.equal(f.state.audits.length, 1);
  assert.deepEqual(await f.repository.readListingCreate(binding, 12, { operationId, personaSession }),
    { ...first, replayed: true });
  const absentId = '80000000-0000-4000-8000-000000000002';
  assert.deepEqual(await f.repository.readListingCreate(binding, 12,
    { operationId: absentId, personaSession }),
  { operationId: absentId, status: 'not_found', scopeKey: f.scopeKey });
});

test('changed saved create request cannot replay and foreign scene cannot read a receipt', async () => {
  const f = fixture();
  const preview = await f.repository.previewListingCreate(binding, 12,
    { name: 'Practice lamp', price: 12 }, f.scopeKey);
  await f.repository.confirmListingCreate(binding, 12, { operationId, preview, personaSession });
  const changed = await f.repository.previewListingCreate(binding, 12,
    { name: 'Different lamp', price: 12 }, f.scopeKey);
  await assert.rejects(f.repository.confirmListingCreate(binding, 12,
    { operationId, preview: changed, personaSession }), { code: 'LISTING_CREATE_RECEIPT_INVALID' });
  assert.equal(f.state.products.length, 1);
  const otherSession = { sessionId: '70000000-0000-4000-8000-000000000002', authorityVersion: '2' };
  const otherScopeKey = C.listingCreateScopeKey(binding, 12, otherSession);
  assert.notEqual(otherScopeKey, f.scopeKey);
  assert.deepEqual(await f.repository.readListingCreate(binding, 12,
    { operationId, personaSession: otherSession }),
  { operationId, status: 'not_found', scopeKey: otherScopeKey });
  const saved = f.state.receipts.get(operationId);
  saved.source_sha256 = Buffer.alloc(32, 9);
  await assert.rejects(f.repository.readListingCreate(binding, 12,
    { operationId, personaSession }), { code: 'LISTING_CREATE_RECEIPT_INVALID' });
});

test('legacy direct listing create retains its one insert and listing_create audit', async () => {
  const f = fixture();
  const productId = await f.repository.createListing(binding, 12, { name: 'Direct lamp',
    description: null, price: 9, category: null, templateSource: null, images: [] });
  assert.equal(productId, 1); assert.equal(f.state.products.length, 1);
  assert.equal(f.state.merchantRows.length, 1); assert.equal(f.state.audits.length, 1);
  assert.equal(f.state.audits[0].action, 'listing_create');
  assert.equal(f.state.receipts.size, 0);
});
