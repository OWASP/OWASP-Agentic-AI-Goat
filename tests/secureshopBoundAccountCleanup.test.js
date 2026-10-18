'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createSecureShopBoundProductRepository } = require(
  '../server/database/postgres/secureshopBoundProductRepository');

const binding = Object.freeze({ targetId: '30000000-0000-4000-8000-000000000062',
  launchId: '10000000-0000-4000-8000-000000000062',
  scenarioId: '20000000-0000-4000-8000-000000000062', generation: 2,
  platformOwnerId: 62, platformSessionId: 602 });
const operationId = '40000000-0000-4000-8000-000000000062';
const sourceSha256 = Buffer.from('11'.repeat(32), 'hex');
function digest() {
  return crypto.createHash('sha256').update(JSON.stringify({ version: 1, operationId,
    targetId: binding.targetId, kind: 'products', launchId: binding.launchId,
    scenarioId: binding.scenarioId, generation: binding.generation,
    platformOwnerId: binding.platformOwnerId, platformSessionId: binding.platformSessionId,
    deletedProductCount: 1, sourceSha256: sourceSha256.toString('hex') })).digest();
}
function receiptRow() {
  return { operation_id: operationId, target_id: binding.targetId, launch_id: binding.launchId,
    scenario_id: binding.scenarioId, generation: binding.generation,
    original_platform_owner_id: binding.platformOwnerId,
    original_platform_session_id: binding.platformSessionId, deleted_product_count: 1,
    source_count: 1, source_sha256: sourceSha256, receipt_sha256: digest(),
    completed_at: '2026-09-18T00:00:00Z' };
}
function accountReceiptRow(profileCount = 1, addressCount = 1) {
  const receiptSha256 = crypto.createHash('sha256').update(JSON.stringify({ version: 1, operationId,
    targetId: binding.targetId, kind: 'product_account', launchId: binding.launchId,
    scenarioId: binding.scenarioId, generation: binding.generation,
    platformOwnerId: binding.platformOwnerId, platformSessionId: binding.platformSessionId,
    deletedProfileCount: profileCount, deletedAddressCount: addressCount })).digest();
  return { operation_id: operationId, target_id: binding.targetId, launch_id: binding.launchId,
    scenario_id: binding.scenarioId, generation: binding.generation,
    original_platform_owner_id: binding.platformOwnerId,
    original_platform_session_id: binding.platformSessionId,
    deleted_profile_count: profileCount, deleted_address_count: addressCount, receipt_sha256: receiptSha256 };
}
function poolFor(handler, { inventory = null, coupons = null, chat = null } = {}) {
  // Historical fixture schemas predate optional operation ledgers.
  // Present-ledger tests below must still validate exact retained-state SQL.
  const client = { async query(sql, args) {
    if (sql === "SELECT to_regclass('secureshop_review.owned_inventory_operations') AS relation") return {rows:[{relation:inventory}]};
    if (sql === "SELECT to_regclass('secureshop_review.bound_commerce_operations') AS relation") return {rows:[{relation:coupons}]};
    if (sql === "SELECT to_regclass('secureshop_review.chat_commerce_operations') AS relation") return {rows:[{relation:chat}]};
    return handler(sql,args);
  }, release() {} };
  return { async query() { throw new Error('transaction required'); }, async connect() { return client; } };
}

test('historical product receipts remain valid only when new account overlay state is absent', async () => {
  for (const retained of [0, 1]) {
    const row = receiptRow();
    const pool = poolFor(async (sql) => {
      if (['BEGIN','COMMIT','ROLLBACK'].includes(sql)) return { rows: [] };
      if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ ...row,
        lifecycle: 'retired', source_count: 1, source_sha256: sourceSha256 }] };
      if (sql.includes('FROM secureshop_review.product_cleanup_receipts')) return { rows: [row] };
      if (sql.includes('FROM secureshop_review.product_account_cleanup_receipts')) return { rows: [] };
      if (sql.includes('FROM secureshop_review.product_listing_cleanup_receipts')) return { rows: [] };
      if (sql.includes('FROM secureshop_review.product_target_refund_cleanup_receipts')) return { rows: [] };
      // Historical account-only fixtures have no retrieval configuration.
      if (sql.includes('FROM secureshop_review.product_target_retrieval_config c')) return { rows: [] };
      if (sql.includes('product_target_profile_overlays')) return { rows: [{ count: retained }] };
      throw new Error(`unexpected query: ${sql}`);
    });
    const repository = createSecureShopBoundProductRepository(pool,
      { checkCurrent: async () => {}, checkCleanup: async () => {} });
    if (retained) await assert.rejects(repository.cleanup(binding, { operationId }), {
      code: 'PRODUCT_CLEANUP_MISMATCH' });
    else assert.equal((await repository.cleanup(binding, { operationId })).receiptSha256,
      row.receipt_sha256.toString('hex'));
  }
});

test('new cleanup deletes address and profile overlays before commerce and product rows', async () => {
  const statements = [];
  const row = receiptRow();
  const pool = poolFor(async (sql) => {
    if (['BEGIN','COMMIT','ROLLBACK'].includes(sql)) return { rows: [] };
    statements.push(sql);
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{
      target_id: binding.targetId, launch_id: binding.launchId, scenario_id: binding.scenarioId,
      generation: binding.generation, original_platform_owner_id: binding.platformOwnerId,
      original_platform_session_id: binding.platformSessionId, lifecycle: 'active',
      source_count: 1, source_sha256: sourceSha256 }] };
    if (sql.includes('FROM secureshop_review.product_cleanup_receipts')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_account_cleanup_receipts')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_listing_cleanup_receipts')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_target_refund_cleanup_receipts')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_target_retrieval_config c')) return { rows: [] };
    if (sql.includes('AS products')) return { rows: [{ products: 1, created: 0, overlays: 0 }] };
    if (sql.startsWith('DELETE FROM secureshop_review.product_target_products p')) return { rows: [], rowCount: 0 };
    if (sql.startsWith('DELETE FROM secureshop_review.product_target_products')) return { rows: [], rowCount: 1 };
    if (sql.includes('INSERT INTO secureshop_review.product_account_cleanup_receipts')) {
      return { rows: [accountReceiptRow()], rowCount: 1 };
    }
    if (sql.includes('INSERT INTO secureshop_review.product_cleanup_receipts')) return { rows: [row] };
    return { rows: [], rowCount: 1 };
  });
  const repository = createSecureShopBoundProductRepository(pool,
    { checkCurrent: async () => {}, checkCleanup: async () => {} });
  await repository.cleanup(binding, { operationId });
  const names = statements.filter(sql => sql.startsWith('DELETE FROM secureshop_review.'))
    .map(sql => /DELETE FROM secureshop_review\.([a-z_]+)/.exec(sql)[1]);
  assert.deepEqual(names, ['product_target_addresses', 'product_target_profile_overlays',
    'product_target_refund_requests', 'product_target_order_items', 'product_target_orders', 'product_target_cart_items',
    'product_target_products', 'product_target_products']);
});

test('account cleanup receipt binds exact deleted profile and address counts', async () => {
  const row = receiptRow(); const accountRow = accountReceiptRow(1, 2);
  const pool = poolFor(async sql => {
    if (['BEGIN','COMMIT','ROLLBACK'].includes(sql)) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ ...row,
      lifecycle: 'retired', source_count: 1, source_sha256: sourceSha256 }] };
    if (sql.includes('FROM secureshop_review.product_cleanup_receipts')) return { rows: [row] };
    if (sql.includes('FROM secureshop_review.product_account_cleanup_receipts')) return { rows: [accountRow] };
    if (sql.includes('FROM secureshop_review.product_listing_cleanup_receipts')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_target_refund_cleanup_receipts')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_target_retrieval_config c')) return { rows: [] };
    if (sql.includes('product_target_profile_overlays')) return { rows: [{ count: 0 }] };
    throw new Error(`unexpected query: ${sql}`);
  });
  const repository = createSecureShopBoundProductRepository(pool,
    { checkCurrent: async () => {}, checkCleanup: async () => {} });
  assert.deepEqual((await repository.cleanup(binding, { operationId })).accountCleanup, {
    deletedProfileCount: 1, deletedAddressCount: 2,
    receiptSha256: accountRow.receipt_sha256.toString('hex') });
  const forged = accountReceiptRow(1, 2); forged.deleted_address_count = 3;
  const forgedPool = poolFor(async sql => {
    if (['BEGIN','COMMIT','ROLLBACK'].includes(sql)) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ ...row,
      lifecycle: 'retired', source_count: 1, source_sha256: sourceSha256 }] };
    if (sql.includes('FROM secureshop_review.product_cleanup_receipts')) return { rows: [row] };
    if (sql.includes('FROM secureshop_review.product_account_cleanup_receipts')) return { rows: [forged] };
    if (sql.includes('FROM secureshop_review.product_listing_cleanup_receipts')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_target_refund_cleanup_receipts')) return { rows: [] };
    // Historical account-only fixtures have no retrieval configuration.
    if (sql.includes('FROM secureshop_review.product_target_retrieval_config c')) return { rows: [] };
    if (sql.includes('product_target_profile_overlays')) return { rows: [{ count: 0 }] };
    throw new Error(`unexpected query: ${sql}`);
  });
  await assert.rejects(createSecureShopBoundProductRepository(forgedPool,
    { checkCurrent: async () => {}, checkCleanup: async () => {} }).cleanup(binding, { operationId }),
  { code: 'PRODUCT_CLEANUP_MISMATCH' });
});


test('reconciliation receipt reads verify retired target and zero state, including historical receipts', async () => {
  for (const historical of [true, false]) {
    for (const [lifecycle, retained] of [['retired', 0], ['retired', 1], ['active', 0]]) {
      let checks = 0;
      const pool = poolFor(async sql => {
        if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [] };
        if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle }] };
        if (sql.includes('FROM secureshop_review.product_cleanup_receipts')) return { rows: [receiptRow()] };
        if (sql.includes('FROM secureshop_review.product_account_cleanup_receipts')) {
          return { rows: historical ? [] : [accountReceiptRow()] };
        }
        if (sql.includes('FROM secureshop_review.product_listing_cleanup_receipts')) return { rows: [] };
        if (sql.includes('FROM secureshop_review.product_target_refund_cleanup_receipts')) return { rows: [] };
      // Historical account-only fixtures have no retrieval configuration.
      if (sql.includes('FROM secureshop_review.product_target_retrieval_config c')) return { rows: [] };
        if (sql.includes('product_target_profile_overlays')) return { rows: [{ count: retained }] };
        throw new Error(`unexpected query: ${sql}`);
      });
      const repository = createSecureShopBoundProductRepository(pool,
        { checkCurrent: async () => {}, checkCleanup: async () => { checks++; } });
      if (lifecycle === 'retired' && retained === 0) {
        const receipt = await repository.readCleanupReceipt(binding, { operationId });
        assert.equal(receipt.receiptSha256, receiptRow().receipt_sha256.toString('hex'));
        assert.equal(Boolean(receipt.accountCleanup), !historical);
        assert.equal(checks, 2);
      } else await assert.rejects(repository.readCleanupReceipt(binding, { operationId }),
        { code: 'PRODUCT_CLEANUP_MISMATCH' });
    }
  }
});


test('current ledger schemas reject retained inventory, coupon or conversational address state despite historical cleanup receipt', async()=>{
 for(const kind of ['inventory','coupons','chat'])for(const retained of [0,1]){
  let checked=0;
  const pool=poolFor(async(sql,args)=>{
   if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return{rows:[]};
   if(sql.includes('FROM secureshop_review.product_targets'))return{rows:[{lifecycle:'retired'}]};
   if(sql.includes('FROM secureshop_review.product_cleanup_receipts'))return{rows:[receiptRow()]};
   if(/FROM secureshop_review.product_(account|listing|target_refund)_cleanup_receipts/.test(sql))return{rows:[]};
   if(sql.includes('FROM secureshop_review.product_target_retrieval_config c'))return{rows:[]};
   if(sql.includes('product_target_profile_overlays'))return{rows:[{count:0}]};
   if(sql.includes('owned_inventory_operations WHERE')||sql.includes('bound_commerce_operations WHERE')||sql.includes('chat_commerce_operations WHERE')){
    checked++;assert.deepEqual(args,[binding.targetId]);if(kind==='chat'){assert.match(sql,/context_json IS NOT NULL OR request_json IS NOT NULL OR proposal_json IS NOT NULL OR result_json IS NOT NULL/);assert.match(sql,/chat_commerce_choices WHERE target_id=\$1/);}else assert.match(sql,/state<>'redacted' OR request_json IS NOT NULL OR result_json IS NOT NULL/);
    if(kind==='coupons')assert.match(sql,/product_target_cart_coupons WHERE target_id=\$1/);
    return{rows:[{count:retained}]};
   }
   throw Error(`unexpected query: ${sql}`);
  },{[kind]:kind==='inventory'?'secureshop_review.owned_inventory_operations':kind==='chat'?'secureshop_review.chat_commerce_operations':'secureshop_review.bound_commerce_operations'});
  const repo=createSecureShopBoundProductRepository(pool,{checkCurrent:async()=>{},checkCleanup:async()=>{}});
  if(retained)await assert.rejects(repo.readCleanupReceipt(binding,{operationId}),{code:'PRODUCT_CLEANUP_MISMATCH'});
  else assert.equal((await repo.readCleanupReceipt(binding,{operationId})).receiptSha256,receiptRow().receipt_sha256.toString('hex'));
  assert.equal(checked,1);
 }
});
