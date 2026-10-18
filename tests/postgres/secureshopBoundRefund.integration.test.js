'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { createSecureShopBoundRefundRepository } = require('../../server/database/postgres/secureshopBoundRefundRepository');
const { createSecureShopBoundProductRepository } = require('../../server/database/postgres/secureshopBoundProductRepository');

const PREFIX = 'PG_SECURESHOP_BOUND_REFUND_';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && ['REVIEW'].every(store => ['MIGRATION', 'RUNTIME'].every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const root = path.join(__dirname, '../..');
const scope = Object.freeze({ targetId: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 71, platformSessionId: 7101 });
const siblingScope = Object.freeze({ targetId: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 72, platformSessionId: 7201 });

test('bound refund repository performs owned eligible effect and idempotent replay on real PostgreSQL', { skip: !enabled, timeout: 60000 }, async t => {
  const migrationPool = new Pool({ connectionString: process.env[`${PREFIX}REVIEW_MIGRATION_URL`], max: 2 });
  const runtimePool = new Pool({ connectionString: process.env[`${PREFIX}REVIEW_RUNTIME_URL`], max: 2 });
  t.after(async () => { await Promise.all([migrationPool.end(), runtimePool.end()]); });
  const migrations = path.join(root, 'db/postgres/workshop-migrations/secureshop_review');
  await migrate(migrationPool, migrations);
  const seedTarget = async (target, merchant, owner, session, name) => migrationPool.query(`INSERT INTO secureshop_review.product_targets
    (target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,own_merchant_id,source_count,source_sha256)
    VALUES($1,$2,$3,1,$4,$5,$6,1,decode($7,'hex'))`, [target.targetId, target.launchId, target.scenarioId, owner, session, merchant, '11'.repeat(32)]);
  const seedProduct = async (target, name) => migrationPool.query(`INSERT INTO secureshop_review.product_target_products
    (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,price,images,stock_quantity,status)
    VALUES($1,1,9,12,decode($2,'hex'),$3,12.34,'[]',4,'active')`, [target.targetId, '22'.repeat(32), name]);
  const seedOrder = async (target, owner, address) => migrationPool.query(`INSERT INTO secureshop_review.product_target_orders
    (target_id,shop_user_id,total_amount,payment_method,shipping_address)
    VALUES($1,$2,12.34,'card',$3)`, [target.targetId, owner, address]);
  await seedTarget(scope, 12, 71, 7101, 'Refund fixture'); await seedProduct(scope, 'Refund fixture'); await seedOrder(scope, 41, 'owned fixture');
  await seedTarget(siblingScope, 13, 72, 7201, 'Sibling refund fixture'); await seedProduct(siblingScope, 'Sibling refund fixture'); await seedOrder(siblingScope, 42, 'sibling fixture');
  const checkCurrent = async binding => {
    const row = (await runtimePool.query(`SELECT lifecycle FROM secureshop_review.product_targets
      WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
        AND original_platform_owner_id=$5 AND original_platform_session_id=$6`,
    [binding.targetId, binding.launchId, binding.scenarioId, binding.generation,
      binding.platformOwnerId, binding.platformSessionId])).rows[0];
    if (!row || row.lifecycle !== 'active') throw Object.assign(new Error('stale launch'), { code: 'STALE_LAUNCH' });
  };
  const repo = createSecureShopBoundRefundRepository(runtimePool, { checkCurrent });
  const checkCleanup = async binding => {
    const row = (await runtimePool.query(`SELECT 1 FROM secureshop_review.product_targets WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4 AND original_platform_owner_id=$5 AND original_platform_session_id=$6`, [binding.targetId, binding.launchId, binding.scenarioId, binding.generation, binding.platformOwnerId, binding.platformSessionId])).rows[0];
    if (!row) throw Object.assign(new Error('cleanup target unavailable'), { code: 'PRODUCT_TARGET_UNAVAILABLE' });
  };
  const first = await repo.create(scope, { shopUserId: 41, orderId: 1, requestId: randomUUID(), reason: 'owned refund' });
  const replay = await repo.create(scope, { shopUserId: 41, orderId: 1, requestId: randomUUID(), reason: 'retry' });
  assert.equal(first.ok, true); assert.equal(first.replayed, false); assert.equal(typeof first.ticket_id, 'string');
  assert.deepEqual(replay, { ...first, replayed: true });
  const siblingTicket = await repo.create(siblingScope, { shopUserId: 42, orderId: 2, requestId: randomUUID(), reason: 'sibling refund' });
  await assert.rejects(() => repo.create(scope, { shopUserId: 42, orderId: 1, requestId: randomUUID(), reason: 'foreign' }), { code: 'ORDER_NOT_FOUND' });
  const products = createSecureShopBoundProductRepository(runtimePool, { checkCurrent, checkCleanup });
  const receipt = await products.cleanup(scope, { operationId: randomUUID() });
  assert.equal(receipt.refundCleanup.deletedTicketCount, 1);
  const preserved = await runtimePool.query('SELECT ticket_id FROM secureshop_review.product_target_refund_requests WHERE target_id=$1', [siblingScope.targetId]);
  assert.equal(String(preserved.rows[0].ticket_id), siblingTicket.ticket_id);
  const refundReceipt = (await migrationPool.query('SELECT receipt_sha256 FROM secureshop_review.product_target_refund_cleanup_receipts WHERE target_id=$1', [scope.targetId])).rows[0];
  await assert.rejects(() => migrationPool.query('UPDATE secureshop_review.product_target_refund_cleanup_receipts SET deleted_ticket_count=0 WHERE target_id=$1', [scope.targetId]));
  assert.ok(refundReceipt.receipt_sha256);
  await assert.rejects(() => repo.create(scope, { shopUserId: 41, orderId: 1, requestId: randomUUID(), reason: 'stale replay' }), { code: 'STALE_LAUNCH' });
});
