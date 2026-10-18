'use strict';
const assert = require('node:assert/strict'), { randomUUID } = require('node:crypto'), { Pool } = require('pg');
exports.qualifyMerchantMetrics = async function(environment) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  const urls = [environment.SECURESHOP_REVIEW_MIGRATION_DATABASE_URL, environment.SECURESHOP_REVIEW_DATABASE_URL];
  const parsed = urls.map(raw => new URL(raw));
  for (const u of parsed) {
    assert.equal(u.hostname, '127.0.0.1');
    assert.match(u.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  }
  assert.equal(parsed[0].username, 'dvaia_secureshop_review_migration');
  assert.equal(parsed[1].username, 'dvaia_secureshop_review_runtime');
  assert.equal(parsed[0].pathname, parsed[1].pathname);
  assert.equal(parsed[0].port, parsed[1].port);
  const [migration, runtime] = urls.map(connectionString => new Pool({ connectionString, max: 1, statement_timeout: 3000 }));
  const scope = { targetId: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 9301, platformSessionId: 9401 };
  try {
    await migration.query(`INSERT INTO secureshop_review.product_targets(target_id,launch_id,scenario_id,generation,
      original_platform_owner_id,original_platform_session_id,own_merchant_id,source_count,source_sha256)
      VALUES($1,$2,$3,1,9301,9401,12,3,$4)`, [scope.targetId,scope.launchId,scope.scenarioId,Buffer.alloc(32,1)]);
    for (const [id,merchant,price] of [[1,12,2],[2,12,4],[3,99,8]]) {
      await migration.query(`INSERT INTO secureshop_review.product_target_products(target_id,product_id,source_retailer_id,
        retailer_id,source_product_sha256,name,description,price,category,images,stock_quantity,status,template_source)
        VALUES($1,$2,$3,$3,$4,$5,'owned',$6,'Books','[]',99,'active','')`,
      [scope.targetId,id,merchant,Buffer.alloc(32,id),'Product '+id,price]);
    }
    const repository = require('../../server/database/postgres/secureshopBoundCommerceRepository')
      .createSecureShopBoundCommerceRepository(runtime, { checkCurrent: async () => {} });
    async function checkout(items, date, status = 'confirmed', paymentStatus = 'approved') {
      for (const [productId,quantity] of items) await repository.addCart(scope, { shopUserId: 41, productId, quantity });
      const order = await repository.checkout(scope, { shopUserId: 41, shippingAddress: 'Synthetic workshop address', paymentMethod: 'test' });
      await migration.query(`UPDATE secureshop_review.product_target_orders SET order_date=$3,status=$4,payment_status=$5
        WHERE target_id=$1 AND order_id=$2`, [scope.targetId,order.orderId,date,status,paymentStatus]);
    }
    await checkout([[1,3],[2,1],[3,1]], '2026-09-20T12:00:00Z');
    await checkout([[1,2]], '2026-08-21T12:00:00Z');
    await checkout([[1,1]], '2026-09-19T12:00:00Z');
    await checkout([[2,1]], '2026-09-18T12:00:00Z');
    await checkout([[2,2]], '2026-09-20T12:00:00Z', 'cancelled');
    await checkout([[1,1]], '2026-09-20T12:00:00Z', 'confirmed', 'declined');
    await checkout([[2,1]], '2026-09-20T12:00:00Z', 'confirmed', 'refunded');
    const { reportingWindow, projectMerchantMetrics } = require('../../server/services/secureshopMerchantMetrics');
    const window = reportingWindow(30, Date.UTC(2026,8,20));
    const ownRaw = await repository.merchantOverview(scope,12,window);
    assert.deepEqual(ownRaw.current,{revenue:16,orders:3});
    assert.deepEqual(ownRaw.previous,{revenue:4,orders:1});
    assert.deepEqual(ownRaw.days,[
      {day:'2026-09-18',revenue:4,orders:1},
      {day:'2026-09-19',revenue:2,orders:1},
      {day:'2026-09-20',revenue:10,orders:1},
    ]);
    assert.deepEqual(ownRaw.top,{id:1,name:'Product 1',revenue:8});
    assert.deepEqual(ownRaw.products,[
      {id:1,name:'Product 1',revenue:8},
      {id:2,name:'Product 2',revenue:8},
    ]);
    const limited = await repository.merchantOverview(scope,12,window,1);
    assert.deepEqual(limited.products,[{id:1,name:'Product 1',revenue:8}]);
    assert.deepEqual(limited.top,ownRaw.top);
    assert.deepEqual(limited.current,ownRaw.current);
    const own = projectMerchantMetrics(ownRaw,window,12);
    assert.equal(own.kpis.revenue.value,16); assert.equal(own.kpis.orders.value,3);
    assert.equal(own.kpis.revenue.delta_pct,300); assert.equal(own.kpis.top_product.id,1);
    assert.deepEqual(own.kpis.orders.spark,[...Array(27).fill(0),1,1,1]);
    assert.deepEqual(own.kpis.revenue.spark,[...Array(27).fill(0),4,2,10]);
    const siblingRaw = await repository.merchantOverview(scope,99,window);
    assert.deepEqual(siblingRaw.current,{revenue:8,orders:1});
    assert.deepEqual(siblingRaw.previous,{revenue:0,orders:0});
    assert.deepEqual(siblingRaw.products,[{id:3,name:'Product 3',revenue:8}]);
    const other = projectMerchantMetrics(siblingRaw,window,99);
    assert.equal(other.kpis.revenue.value,8); assert.equal(other.kpis.orders.value,1);
    await assert.rejects(repository.merchantOverview({...scope,platformOwnerId:9999},12,window), {code:'PRODUCT_TARGET_UNAVAILABLE'});
    return {passed:true,modelCalls:0,checks:['distinct mixed-merchant order counts','line revenue attribution',
      'previous UTC window','cancelled declined and refunded order exclusion',
      'ordered UTC daily rows and deterministic equal-revenue product IDs',
      'top product limit','foreign owner denial']};
  } finally { await Promise.all([migration.end(),runtime.end()]); }
};
