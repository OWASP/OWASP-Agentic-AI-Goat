'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { migrate } = require('../../db/postgres/migrate');

const MIGRATION = '0040_owned_product_price_history.sql';

async function qualifyPopulatedPriceHistoryMigration({ migrationPool, runtimePool, directory, scratch }) {
  assert.equal(typeof migrationPool?.query, 'function');
  assert.equal(typeof runtimePool?.query, 'function');
  assert.equal(path.basename(directory), 'secureshop_review');
  const names = fs.readdirSync(directory).filter(name => /^\d{4}_[a-z0-9_]+\.sql$/.test(name)).sort();
  const migrationIndex = names.indexOf(MIGRATION);
  assert.ok(migrationIndex>0,'0040 must exist after an immutable review migration prefix');
  assert.ok(migrationIndex<names.length-1,'the staged proof must retain forward review migrations');
  const prefix = path.join(scratch, 'review-through-0039');
  fs.mkdirSync(prefix, { mode: 0o700 });
  for (const name of names.slice(0, migrationIndex))
   fs.symlinkSync(path.join(directory, name), path.join(prefix, name));
  await migrate(migrationPool, prefix);
  const targetId = randomUUID(), productId = 71;
  const binding = Object.freeze({ targetId, launchId: randomUUID(), scenarioId: randomUUID(),
   generation: 1, platformOwnerId: 9997, platformSessionId: 9998 });
  await migrationPool.query(`INSERT INTO secureshop_review.product_targets
   (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
    original_platform_session_id,own_merchant_id,source_count,source_sha256)
   VALUES($1,$2,$3,1,9997,9998,12,1,$4)`,
  [targetId, binding.launchId, binding.scenarioId, Buffer.alloc(32, 1)]);
  await migrationPool.query(`INSERT INTO secureshop_review.product_target_products
   (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,
    description,price,images,stock_quantity,status,template_source)
   VALUES($1,$2,12,12,$3,'Populated pricing history fixture','Owned synthetic baseline',
    9.25,'[]',5,'active','{{source}}')`,
  [targetId, productId, Buffer.alloc(32, 2)]);
  await migrationPool.query(`INSERT INTO secureshop_review.product_target_listing_overlays
   (target_id,product_id,shop_user_id,name,description,description_html,price,
    category,image_url,images,stock_quantity,status,template_source)
   SELECT target_id,product_id,retailer_id,name,description,description_html,10.75,
    category,image_url,images,stock_quantity,status,template_source
   FROM secureshop_review.product_target_products WHERE target_id=$1 AND product_id=$2`,
  [targetId, productId]);
  const before = (await migrationPool.query('SELECT clock_timestamp()::text AS stamp')).rows[0].stamp;
  const transition = path.join(scratch, 'review-through-0040');
  fs.mkdirSync(transition, { mode: 0o700 });
  for (const name of names.slice(0, migrationIndex+1))
   fs.symlinkSync(path.join(directory, name), path.join(transition, name));
  assert.deepEqual(await migrate(migrationPool, transition), [MIGRATION]);
  const after = (await migrationPool.query('SELECT clock_timestamp()::text AS stamp')).rows[0].stamp;
  const rows = (await runtimePool.query(`SELECT observation_id::text,target_id,product_id,
   price::text,observed_at,source FROM secureshop_review.product_target_price_history
   WHERE target_id=$1 AND product_id=$2 ORDER BY observation_id`, [targetId, productId])).rows;
  assert.equal(rows.length, 1);
  assert.equal(rows[0].source, 'migration_baseline');
  assert.equal(rows[0].price, '10.75',
   'populated migration observes the effective overlay price rather than the base price');
  const time = (await migrationPool.query(`SELECT observed_at::text AS observed,
   observed_at >= $3::timestamptz AND observed_at <= $4::timestamptz AS within_bounds
   FROM secureshop_review.product_target_price_history
   WHERE target_id=$1 AND product_id=$2`, [targetId, productId, before, after])).rows[0];
  assert.equal(time?.within_bounds, true,
   `baseline must occur during migration on PostgreSQL clock: before=${before}, observed=${time?.observed}, after=${after}`);
  assert.deepEqual(await migrate(migrationPool, directory),names.slice(migrationIndex+1),
   'all immutable review successors must apply after the isolated 0040 transition');
  assert.deepEqual(await migrate(migrationPool, directory), []);
  assert.deepEqual((await runtimePool.query(`SELECT observation_id::text,target_id,product_id,
   price::text,observed_at,source FROM secureshop_review.product_target_price_history
   WHERE target_id=$1 AND product_id=$2 ORDER BY observation_id`, [targetId, productId])).rows, rows);
  await migrationPool.query(`DELETE FROM secureshop_review.product_target_listing_overlays
   WHERE target_id=$1 AND product_id=$2`, [targetId, productId]);
  const restored = (await runtimePool.query(`SELECT observation_id::text,target_id,product_id,
   price::text,observed_at,source FROM secureshop_review.product_target_price_history
   WHERE target_id=$1 AND product_id=$2 ORDER BY observation_id`, [targetId, productId])).rows;
  assert.equal(restored.length, 2);
  assert.deepEqual(restored.map(row => [row.price, row.source]),
   [['10.75', 'migration_baseline'], ['9.25', 'price_change']],
  'overlay deletion observes restored effective base price');
  assert.deepEqual(restored[0], rows[0], 'overlay removal preserves the immutable baseline row');
  const denied = [
    `INSERT INTO secureshop_review.product_target_price_history
      (target_id,product_id,price,source) VALUES($1,$2,1,'price_change')`,
    `UPDATE secureshop_review.product_target_price_history SET price=1
      WHERE target_id=$1 AND product_id=$2`,
    `DELETE FROM secureshop_review.product_target_price_history
      WHERE target_id=$1 AND product_id=$2`,
  ];
  for (const sql of denied) {
    const client = await runtimePool.connect();
    try {
      await client.query('BEGIN');
      await assert.rejects(client.query(sql, [targetId, productId]), { code: '42501' },
       'runtime role must have SELECT only on derived price history');
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
  }
  assert.deepEqual((await runtimePool.query(`SELECT observation_id::text,target_id,product_id,
   price::text,observed_at,source FROM secureshop_review.product_target_price_history
   WHERE target_id=$1 AND product_id=$2 ORDER BY observation_id`, [targetId, productId])).rows, restored);
  const operationId = randomUUID();
  const repository = require('../../server/database/postgres/secureshopBoundProductRepository')
   .createSecureShopBoundProductRepository(runtimePool, {
    checkCurrent: async () => {},
    checkCleanup: async authority => {
     assert.deepEqual(authority, { ...binding, targetKind: 'products', operationId,
      fromGeneration: binding.generation }, 'fixture permits only the exact owned target retirement');
    },
   });
  const receipt = await repository.cleanup(binding, { operationId });
  assert.equal(receipt.deletedProductCount, 1);
  assert.equal((await runtimePool.query(`SELECT lifecycle FROM secureshop_review.product_targets
   WHERE target_id=$1`, [targetId])).rows[0].lifecycle, 'retired');
  assert.equal((await runtimePool.query(`SELECT count(*)::int AS n FROM
   secureshop_review.product_target_price_history WHERE target_id=$1`, [targetId])).rows[0].n, 0,
  'retired target cleanup cascades derived price rows');
  const journal = (await runtimePool.query(`SELECT operation_id,target_id,deleted_product_count,
   receipt_sha256 FROM secureshop_review.product_cleanup_receipts
   WHERE target_id=$1`, [targetId])).rows;
  assert.equal(journal.length, 1);
  assert.equal(journal[0].operation_id, operationId);
  assert.equal(journal[0].target_id, targetId);
  assert.equal(journal[0].deleted_product_count, 1);
  assert.equal(journal[0].receipt_sha256.length, 32);
  assert.deepEqual(await repository.cleanup(binding, { operationId }), receipt,
   'exact cleanup replay preserves the immutable journal');
  assert.deepEqual((await runtimePool.query(`SELECT operation_id,target_id,deleted_product_count,
   receipt_sha256 FROM secureshop_review.product_cleanup_receipts
   WHERE target_id=$1`, [targetId])).rows, journal);
  return Object.freeze({ targetId, productId, baseline: rows[0], restored,
   cleanupReceipt: receipt });
}

module.exports = { qualifyPopulatedPriceHistoryMigration };
