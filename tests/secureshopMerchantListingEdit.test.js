'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createSecureShopBoundProductRepository } = require('../server/database/postgres/secureshopBoundProductRepository');
const contract = require('../server/services/secureshopListingEditContract');

const birth = { targetId: '40000000-0000-4000-8000-000000000001',
  launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1,
  platformOwnerId: 4, platformSessionId: 5 };
const binding = createSceneBinding(birth, { sceneId: '50000000-0000-4000-8000-000000000001',
  sceneGeneration: 1, grantId: '60000000-0000-4000-8000-000000000001',
  execution: birth, withLease: work => work() });
const personaSession = { sessionId: '70000000-0000-4000-8000-000000000001', authorityVersion: '2' };
const operationId = '80000000-0000-4000-8000-000000000001';
const sha = value => createHash('sha256').update(value).digest('hex');

function fixture({ generated = false } = {}) {
  const state = { revision: 3, writes: 0, audits: [], receipts: new Map(),
    updated: new Date('2026-10-10T12:00:00.000Z'), stock: 9,
    name: 'Owned lamp', description: 'Original text', descriptionHtml: '<b>Teaching HTML</b>',
    price: '12.50', category: 'Home', imageUrl: null, templateSource: '{{ name }}',
    provenance: generated ? { source_name: 'Owned lamp', source_description: 'Original text',
      html_sha256: sha('<b>Teaching HTML</b>') } : null };
  const rows = () => ({ product_id: 11, retailer_id: 12, source_product_sha256: Buffer.alloc(32, 7),
    name: state.name, description: state.description, description_html: state.descriptionHtml,
    price: state.price, category: state.category, image_url: state.imageUrl,
    template_source: state.templateSource, images: [], stock_quantity: state.stock, status: 'active',
    source_updated_at: state.updated, archived_at: null });
  const client = { async query(sql, args) {
    if (['BEGIN', 'COMMIT', 'ROLLBACK', 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ'].includes(sql))
      return { rows: [] };
    if (sql.includes('assert_scene_execution_grant')) return { rows: [{ allowed: true }] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{
      target_id: birth.targetId, launch_id: birth.launchId, scenario_id: birth.scenarioId,
      generation: birth.generation, original_platform_owner_id: birth.platformOwnerId,
      original_platform_session_id: birth.platformSessionId, own_merchant_id: 12,
      lifecycle: 'active', source_sha256: Buffer.alloc(32, 5), source_count: 1 }] };
    if (sql.includes('FROM secureshop_review.owned_listing_catalog_revisions'))
      return { rows: [{ revision: String(state.revision) }] };
    if (sql.includes('FROM secureshop_review.owned_listing_generated_products'))
      return { rows: state.provenance ? [state.provenance] : [] };
    if (sql.includes('WITH effective AS') && sql.includes('SELECT * FROM effective'))
      return { rows: [rows()] };
    if (sql.includes('INSERT INTO secureshop_review.product_target_listing_overlays')) {
      state.writes++;
      [ , , , state.name, state.description, state.descriptionHtml, state.price,
        state.category, state.imageUrl, , state.stock, , state.templateSource ] = args;
      if (state.provenance && (state.name !== state.provenance.source_name
          || state.description !== state.provenance.source_description)
          && sha(state.descriptionHtml || '') === state.provenance.html_sha256) {
        state.descriptionHtml = null;
        state.provenance = null;
      }
      state.updated = new Date('2026-10-10T12:00:01.000Z'); state.revision++;
      return { rows: [], rowCount: 1 };
    }
    if (sql.includes('INSERT INTO secureshop_review.owned_merchant_listing_edit_receipts')) {
      const keys = ['operation_id', 'target_id', 'launch_id', 'scenario_id', 'generation',
        'original_platform_owner_id', 'original_platform_session_id', 'scene_id', 'scene_generation',
        'grant_id', 'merchant_id', 'persona_session_id', 'authority_version', 'product_id',
        'scope_key', 'catalog_revision', 'request_sha256', 'before_sha256', 'after_sha256', 'receipt_sha256'];
      const row = Object.fromEntries(keys.map((key, i) => [key, args[i]]));
      state.receipts.set(row.operation_id, row);
      return { rows: [row], rowCount: 1 };
    }
    if (sql.includes('FROM secureshop_review.owned_merchant_listing_edit_receipts')) {
      // The immutable receipt table grants the runtime role SELECT and INSERT,
      // but a locking SELECT would also require UPDATE privilege.
      assert.doesNotMatch(sql, /FOR\s+(?:SHARE|UPDATE|NO KEY UPDATE|KEY SHARE)\b/i);
      const row = state.receipts.get(args[0]);
      if (!row || (args.length > 1 && (args[1] !== row.target_id || args[2] !== row.merchant_id
          || args[3] !== row.persona_session_id || !args[4].equals(row.scope_key)))) return { rows: [] };
      return { rows: [row] };
    }
    throw Error(`Unexpected listing-edit query: ${sql}`);
  }, release() {} };
  const pool = { async connect() { return client; }, async query() { throw Error('transaction required'); } };
  const repository = createSecureShopBoundProductRepository(pool, {
    checkCurrent: async () => {}, checkCleanup: async () => {},
    auditStore: { async append(_client, row) { state.audits.push(row); } },
  });
  const scopeKey = contract.listingEditScopeKey(binding, 12, personaSession);
  return { repository, state, scopeKey };
}

test('listing edit preview and confirmation CAS one overlay, immutable receipt, and exact replay', async () => {
  const f = fixture({ generated: true });
  const preview = await f.repository.previewListingEdit(binding, 12, 11,
    { name: 'New lamp', price: 13.75 }, f.scopeKey);
  assert.equal(preview.catalogRevision, '3');
  assert.equal(preview.invalidatesGeneratedHtml, true);
  assert.equal(preview.before.descriptionHtml, '<b>Teaching HTML</b>');
  assert.equal(preview.after.descriptionHtml, null);
  assert.equal(preview.after.price, 13.75);
  assert.deepEqual(contract.validateListingEditPreview(JSON.parse(JSON.stringify(preview))), preview);
  assert.equal(f.state.writes, 0);
  const input = { operationId, preview, personaSession };
  const first = await f.repository.confirmListingEdit(binding, 12, input);
  assert.equal(first.status, 'completed'); assert.equal(first.replayed, false);
  assert.equal(first.scopeKey, f.scopeKey); assert.equal(first.catalogRevision, '3');
  assert.equal(f.state.writes, 1); assert.equal(f.state.audits.length, 1);
  assert.equal(f.state.audits[0].action,'listing_edit_confirm');
  const provenance=JSON.parse(f.state.audits[0].paramsJson);
  assert.deepEqual(provenance.confirmedDescription,{version:1,text:'Original text',
    sha256:contract.listingEditDigest('Original text'),personaSessionId:personaSession.sessionId.toLowerCase(),
    authorityVersion:personaSession.authorityVersion});
  assert.equal(provenance.operationId,operationId);
  assert.equal(provenance.scopeKey,f.scopeKey);
  assert.equal(provenance.afterSha256,first.afterSha256);
  assert.equal(f.state.descriptionHtml, null);
  assert.equal(f.state.price, 13.75);
  assert.deepEqual(contract.validateListingEditReceipt(first, operationId), first);
  const replay = await f.repository.confirmListingEdit(binding, 12, input);
  assert.equal(replay.replayed, true); assert.equal(replay.receiptSha256, first.receiptSha256);
  assert.equal(f.state.writes, 1); assert.equal(f.state.audits.length, 1);
  const read = await f.repository.readListingEdit(binding, 12, { operationId, personaSession });
  assert.equal(read.receiptSha256, first.receiptSha256);
  const absent = await f.repository.readListingEdit(binding, 12, {
    operationId: '80000000-0000-4000-8000-000000000002', personaSession });
  assert.deepEqual(absent, { operationId: '80000000-0000-4000-8000-000000000002',
    status: 'not_found', scopeKey: f.scopeKey });
});

test('intervening owned stock or catalog revision stales preview before any overlay write', async () => {
  for (const change of [f => { f.state.stock++; }, f => { f.state.revision++; }]) {
    const f = fixture();
    const preview = await f.repository.previewListingEdit(binding, 12, 11, { price: 14 }, f.scopeKey);
    change(f);
    await assert.rejects(f.repository.confirmListingEdit(binding, 12,
      { operationId, preview, personaSession }), { code: 'LISTING_EDIT_STALE' });
    assert.equal(f.state.writes, 0);
    assert.equal(f.state.stock >= 9, true);
  }
});

test('raw teaching HTML survives ordinary edit and changed UUID payload cannot replay', async () => {
  const f = fixture();
  const preview = await f.repository.previewListingEdit(binding, 12, 11,
    { description: 'Updated text' }, f.scopeKey);
  assert.equal(preview.invalidatesGeneratedHtml, false);
  assert.equal(preview.after.descriptionHtml, '<b>Teaching HTML</b>');
  await f.repository.confirmListingEdit(binding, 12, { operationId, preview, personaSession });
  assert.equal(f.state.descriptionHtml, '<b>Teaching HTML</b>');
  const changed = { ...preview, requestSha256: 'a'.repeat(64) };
  await assert.rejects(f.repository.confirmListingEdit(binding, 12,
    { operationId, preview: changed, personaSession }), { code: 'LISTING_EDIT_INVALID' });
  assert.equal(f.state.writes, 1);
});
