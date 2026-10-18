'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { reportingWindow, projectMerchantMetrics } = require('../server/services/secureshopMerchantMetrics');
test('merchant reporting uses nonoverlapping UTC calendar windows and real sparse counts', () => {
  const window = reportingWindow(30, Date.UTC(2026, 8, 20, 23, 59));
  assert.equal(window.cutoff, '2026-08-22T00:00:00.000Z');
  assert.equal(window.previousCutoff, '2026-07-23T00:00:00.000Z');
  assert.equal(window.until, '2026-09-21T00:00:00.000Z');
  const value = projectMerchantMetrics({ current: { revenue: 10, orders: 1 },
    previous: { revenue: 4, orders: 1 }, days: [{ day: '2026-09-20', revenue: 10, orders: 1 }],
    top: { id: 1, name: 'Purchased product', revenue: 6 } }, window, 12);
  assert.deepEqual(value.kpis.orders.spark, [...Array(29).fill(0), 1]);
  assert.equal(value.kpis.revenue.delta_pct, 150);
  assert.equal(value.kpis.aov.value, 10);
  assert.equal(value.salesChart.series.length, 30);
  assert.equal(value.kpis.provenance.modelUsed, false);
});
test('merchant reporting rejects invalid windows and nonfinite stored metrics', () => {
  for (const days of [0, 6, 366, 2.5, '30']) assert.throws(() => reportingWindow(days), { code: 'INVALID_ARGUMENT' });
  assert.throws(() => projectMerchantMetrics({ current: { revenue: NaN, orders: 1 }, previous: {}, days: [] }, reportingWindow(), 12));
});

test('real commerce factory exposes merchant reporting and executes its guarded read',async()=>{
  const scope={targetId:'30000000-0000-4000-8000-000000000001',launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:7,platformSessionId:8};
  const data={current:{revenue:0,orders:0},previous:{revenue:0,orders:0},days:[],top:null};
  const calls=[];let released=false, checks=0;
  const client={async query(sql,args){calls.push([sql,args]);if(sql.includes('SELECT lifecycle'))return {rows:[{lifecycle:'active'}]};if(sql.startsWith('WITH lines'))return {rows:[data]};return {rows:[]};},release(){released=true;}};
  const repository=require('../server/database/postgres/secureshopBoundCommerceRepository').createSecureShopBoundCommerceRepository({query:client.query,async connect(){return client;}},{async checkCurrent(value){assert.deepEqual(value,scope);checks++;}});
  assert.equal(typeof repository.merchantOverview,'function');
  const window=reportingWindow();
  assert.deepEqual(await repository.merchantOverview(scope,12,window),data);
  assert.equal(checks,2);assert.equal(released,true);
  assert.equal(calls[0][0],'BEGIN');assert.equal(calls.at(-1)[0],'COMMIT');
  const query=calls.find(([sql])=>sql.startsWith('WITH lines'));
  assert.deepEqual(query[1],[scope.targetId,12,window.cutoff,window.previousCutoff,window.until,8]);
  assert.match(query[0],/o\.target_id=\$1 AND p\.retailer_id=\$2/);
  assert.match(query[0],/o\.status <> 'cancelled'/);
  assert.match(query[0],/o\.payment_status NOT IN \('declined','refunded'\)/);
  assert.match(query[0],/FROM current_lines GROUP BY product_id ORDER BY revenue DESC,product_id LIMIT \$6/);
  assert.match(query[0],/jsonb_agg\(to_jsonb\(top_products\) ORDER BY revenue DESC,id\)/);
  await repository.merchantOverview(scope,12,window,2);
  assert.equal(calls.filter(([sql])=>sql.startsWith('WITH lines')).at(-1)[1][5],2);
  for(const limit of [0,51,1.5,'8'])assert.throws(()=>repository.merchantOverview(scope,12,window,limit),{code:'INVALID_ARGUMENT'});
});
