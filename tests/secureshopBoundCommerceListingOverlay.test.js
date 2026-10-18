'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundCommerceRepository } = require(
  '../server/database/postgres/secureshopBoundCommerceRepository');

const binding = Object.freeze({ targetId: '30000000-0000-4000-8000-000000000071',
  launchId: '10000000-0000-4000-8000-000000000071',
  scenarioId: '20000000-0000-4000-8000-000000000071', generation: 1,
  platformOwnerId: 71, platformSessionId: 701 });
function fixture(cartRows, couponRepository) {
  const queries = [];
  const client = { async query(sql, args) {
    queries.push([sql, args]);
    if (['BEGIN', 'COMMIT', 'ROLLBACK', 'SAVEPOINT empty_cart_checkout', 'ROLLBACK TO SAVEPOINT empty_cart_checkout', 'RELEASE SAVEPOINT empty_cart_checkout'].includes(sql)) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }] };
    if (sql.includes('pg_advisory_xact_lock')) return { rows: [{}] };
    if (sql.startsWith('SELECT product_id FROM secureshop_review.product_target_cart_items')) return { rows: cartRows.map(row=>({product_id:row.product_id})) };
    if (sql.startsWith('SELECT product_id FROM secureshop_review.product_target_products')) return { rows: [...cartRows].sort((a,b)=>a.product_id-b.product_id).map(row=>({product_id:row.product_id})) };
    if (sql.startsWith('SELECT p.product_id,p.retailer_id')) return { rows: [...cartRows].sort((a,b)=>a.product_id-b.product_id).map(row=>({product_id:row.product_id,retailer_id:row.product_id,stock_quantity:row.stock_quantity??99,overlay:false,archived:row.archived,status:'active'})) };
    if(sql.startsWith('INSERT INTO secureshop_review.product_target_listing_overlays'))return{rowCount:1,rows:[]};
    if (sql.includes('SELECT c.product_id')) return { rows: cartRows };
    if (sql.includes('INSERT INTO secureshop_review.product_target_orders')) return { rows: [{ order_id: 81 }] };
    if (sql.includes('INSERT INTO secureshop_review.product_target_order_items')) return { rows: [], rowCount: 1 };
    if (sql.includes('DELETE FROM secureshop_review.product_target_cart_items')) {
      return { rows: [], rowCount: cartRows.length };
    }
    throw new Error(`Unexpected query: ${sql}`);
  }, release() {} };
  const pool = { async query() { throw new Error('transaction required'); }, async connect() { return client; } };
  return { repository: createSecureShopBoundCommerceRepository(pool, { checkCurrent: async () => {}, couponRepository }), queries };
}

test('checkout rejects an item archived after it entered the cart without creating an order', async () => {
  const f = fixture([{ product_id: 72, quantity: 1, name: 'Archived', price: '4.00', archived: true }]);
  assert.equal(await f.repository.checkout(binding, { shopUserId: 41,
    shippingAddress: 'owned', paymentMethod: 'test' }), require('../server/database/postgres/secureshopBoundCommerceRepository').CART_STOCK_REJECTED);
  assert.equal(f.queries.some(([sql]) => sql.includes('INSERT INTO secureshop_review.product_target_orders')), false);
  const read = f.queries.find(([sql]) => sql.includes('SELECT c.product_id'))[0];
  assert.match(read, /product_target_listing_overlays/);
});

test('checkout snapshots the effective overlay name and zero price into the order line', async () => {
  const f = fixture([{ product_id: 72, quantity: 2, name: 'Edited listing', price: '0.00', archived: false }]);
  assert.deepEqual(await f.repository.checkout(binding, { shopUserId: 41,
    shippingAddress: 'owned', paymentMethod: 'test' }), { orderId: 81, total: 0 });
  const line = f.queries.find(([sql]) => sql.includes('INSERT INTO secureshop_review.product_target_order_items'));
  assert.deepEqual(line[1].slice(2), [72, 'Edited listing', 2, '0.00']);
});


test('coupon checkout preserves original unit prices, allocates exact paid cents and replays without a second order', async () => {
  let saved;
  const couponRepository={
    beginCheckoutWithClient:async()=>saved?{state:'completed',result:saved}:{state:'admitted'},
    currentWithClient:async()=>({code:'HALF',discount_percent:50}),
    finishCheckoutWithClient:async(client,context,result)=>{saved=result;},
  };
  const f=fixture([{product_id:1,quantity:3,name:'Merchant A',price:'0.01',archived:false},{product_id:2,quantity:1,name:'Merchant B',price:'0.01',archived:false}],couponRepository);
  const input={shopUserId:41,persona:{id:41},personaSession:{},operationId:'40000000-0000-4000-8000-000000000071',shippingAddress:'owned',paymentMethod:'test'};
  assert.deepEqual(await f.repository.checkout(binding,input),{orderId:81,total:0.02,subtotal:0.04,discount:0.02});
  const lines=f.queries.filter(([sql])=>sql.includes('INSERT INTO secureshop_review.product_target_order_items'));
  assert.deepEqual(lines.map(([,args])=>args.slice(2)),[[1,'Merchant A',3,'0.01',0.02],[2,'Merchant B',1,'0.01',0]]);
  const header=f.queries.find(([sql])=>sql.includes('INSERT INTO secureshop_review.product_target_orders'));
  assert.deepEqual(header[1].slice(2),[0.02,'test','owned',0.04,0.02,'HALF',50]);
  assert.deepEqual(await f.repository.checkout(binding,input),saved);
  assert.equal(f.queries.filter(([sql])=>sql.includes('INSERT INTO secureshop_review.product_target_orders')).length,1);
  assert.equal(f.queries.filter(([sql])=>sql.startsWith('INSERT INTO secureshop_review.product_target_listing_overlays')).length,2);
});


test('insufficient stock in any line prevents all stock writes and order creation',async()=>{
 const couponRepository={beginCheckoutWithClient:async()=>({state:'admitted'}),currentWithClient:async()=>null};
 const f=fixture([{product_id:1,quantity:2,name:'Available',price:'1.00',stock_quantity:10,archived:false},{product_id:2,quantity:2,name:'Short',price:'1.00',stock_quantity:1,archived:false}],couponRepository);
 assert.equal(await f.repository.checkout(binding,{shopUserId:41,persona:{id:41},personaSession:{},operationId:'40000000-0000-4000-8000-000000000071',shippingAddress:'owned',paymentMethod:'test'}),require('../server/database/postgres/secureshopBoundCommerceRepository').CART_STOCK_REJECTED);
 assert.equal(f.queries.some(([sql])=>sql.startsWith('INSERT INTO secureshop_review.product_target_listing_overlays')),false);
 assert.equal(f.queries.some(([sql])=>sql.includes('INSERT INTO secureshop_review.product_target_orders')),false);
 assert.ok(f.queries.some(([sql])=>sql==='ROLLBACK TO SAVEPOINT empty_cart_checkout'));
 assert.equal(f.queries.at(-1)[0],'COMMIT');
});

test('locked cart sum rejection commits a read-only result without mutation or audit', async () => {
  const { CART_QUANTITY_LIMIT_REJECTED } = require('../server/database/postgres/secureshopBoundCommerceRepository');
  const queries = [];
  let released = false, checks = 0;
  const client = { async query(sql, args) {
    queries.push([sql, args]);
    if (['BEGIN', 'COMMIT'].includes(sql)) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }] };
    if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
    if (sql.includes('SELECT cart_item_id,quantity')) return { rows: [{ cart_item_id: 81, quantity: 2 }] };
    throw Error('Unexpected mutation or query');
  }, release() { released = true; } };
  const repository = createSecureShopBoundCommerceRepository({ query() { throw Error('transaction required'); }, async connect() { return client; } }, {
    async checkCurrent() { checks++; }, auditStore: { async append() { throw Error('rejected cart must not audit a mutation'); } },
  });
  assert.equal(await repository.addCart(binding, { shopUserId: 41, productId: 72, quantity: 98 }), CART_QUANTITY_LIMIT_REJECTED);
  assert.deepEqual(queries.map(([sql]) => sql.split(/\s+/)[0]), ['BEGIN', 'SELECT', 'SELECT', 'SELECT', 'COMMIT']);
  assert.match(queries[3][0], /FOR UPDATE/);
  assert.deepEqual(queries[3][1], [binding.targetId, 41, 72]);
  assert.equal(checks, 2);
  assert.equal(released, true);
});

test('empty checkout undoes reservation before returning rejection and preserves completed replay', async () => {
  const { EMPTY_CART_REJECTED } = require('../server/database/postgres/secureshopBoundCommerceRepository');
  for (const completed of [false, true]) {
    let reserved = false, released = false;
    const queries = [];
    const result = { orderId: 19, total: 2 };
    const client = { async query(sql) {
      queries.push(sql);
      if (sql === 'ROLLBACK TO SAVEPOINT empty_cart_checkout') reserved = false;
      if (/^(BEGIN|COMMIT|SAVEPOINT|ROLLBACK TO|RELEASE)/.test(sql)) return { rows: [] };
      if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }] };
      if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
      if (sql.startsWith('SELECT product_id FROM secureshop_review.product_target_cart_items')) return { rows: [] };
      throw Error('Unexpected stock/order mutation');
    }, release() { released = true; } };
    const repository = createSecureShopBoundCommerceRepository({ query() {}, async connect() { return client; } }, {
      async checkCurrent() {}, couponRepository: { async beginCheckoutWithClient() {
        if (completed) return { state: 'completed', result };
        reserved = true; return { state: 'admitted' };
      } }, auditStore: { async append() { throw Error('No audit write allowed'); } },
    });
    assert.equal(await repository.checkout(binding, { shopUserId: 41, persona: { id: 41 }, shippingAddress: 'owned', paymentMethod: 'teaching' }), completed ? result : EMPTY_CART_REJECTED);
    assert.equal(reserved, false); assert.equal(released, true);
    assert.equal(queries.at(-1), 'COMMIT');
    assert.equal(queries.includes('ROLLBACK TO SAVEPOINT empty_cart_checkout'), !completed);
    assert.equal(queries.some(sql => /^(INSERT|UPDATE|DELETE)/.test(sql)), false);
    assert.equal(queries.some(sql => sql.startsWith('SELECT product_id FROM secureshop_review.product_target_cart_items')), !completed);
  }
});

test('empty checkout savepoint rollback and commit failures never return known rejection', async () => {
  for (const failedSql of ['SAVEPOINT empty_cart_checkout', 'ROLLBACK TO SAVEPOINT empty_cart_checkout', 'RELEASE SAVEPOINT empty_cart_checkout', 'COMMIT']) {
    const injected = Error(`controlled ${failedSql} failure`);
    const client = { async query(sql) {
      if (sql === failedSql) throw injected;
      if (/^(BEGIN|COMMIT|SAVEPOINT|ROLLBACK|RELEASE)/.test(sql)) return { rows: [] };
      if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }] };
      if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
      if (sql.startsWith('SELECT product_id FROM secureshop_review.product_target_cart_items')) return { rows: [] };
      throw Error('Unexpected query');
    }, release() {} };
    const repository = createSecureShopBoundCommerceRepository({ query() {}, async connect() { return client; } }, {
      async checkCurrent() {}, couponRepository: { async beginCheckoutWithClient() { return { state: 'admitted' }; } },
    });
    await assert.rejects(repository.checkout(binding, { shopUserId: 41, persona: { id: 41 }, shippingAddress: 'owned', paymentMethod: 'teaching' }), error => error === injected);
  }
});

test('stock availability validates every line before denial and direct consume retains throw contract', async () => {
  const { stockAvailable, consumeStock } = require('../server/database/postgres/secureshopOwnedStock');
  const stock = [{ productId: 1, quantity: 0, status: 'active', archived: false }, { productId: 2, quantity: 8, status: 'active', archived: false }];
  const lines = [{ product_id: 1, quantity: 1 }, { product_id: 2, quantity: 1 }];
  assert.equal(stockAvailable(stock, lines), false);
  assert.throws(() => stockAvailable(stock, [lines[0], { product_id: 2, quantity: 100 }]), { code: 'STOCK_REQUEST_INVALID' });
  await assert.rejects(consumeStock({ query() { throw Error('must not write'); } }, binding.targetId, stock, lines), { code: 'INSUFFICIENT_STOCK' });
  assert.equal(stockAvailable([{ ...stock[0], quantity: 1 }, stock[1]], lines), true);
});

test('archived checkout clears reservation only through confirmed rollback and preserves failures', async () => {
  const { CART_STOCK_REJECTED } = require('../server/database/postgres/secureshopBoundCommerceRepository');
  for (const failureSql of [null, 'ROLLBACK TO SAVEPOINT empty_cart_checkout', 'RELEASE SAVEPOINT empty_cart_checkout', 'COMMIT']) {
    let reserved = false;
    const injected = Error('controlled transaction failure');
    const queries = [];
    const client = { async query(sql) {
      queries.push(sql);
      if (sql === failureSql) throw injected;
      if (sql === 'ROLLBACK TO SAVEPOINT empty_cart_checkout' || sql === 'ROLLBACK') reserved = false;
      if (/^(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)/.test(sql)) return { rows: [] };
      if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }] };
      if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
      if (sql.startsWith('SELECT product_id FROM')) return { rows: [{ product_id: 1 }] };
      if (sql.startsWith('SELECT p.product_id,p.retailer_id')) return { rows: [{ product_id: 1, retailer_id: 1, stock_quantity: 5, status: 'active', archived: true, overlay: true }] };
      if (sql.startsWith('SELECT c.product_id,c.quantity')) return { rows: [{ product_id: 1, quantity: 1, price: '1.00', archived: true }] };
      throw Error('unexpected write');
    }, release() {} };
    const repository = createSecureShopBoundCommerceRepository({ query() {}, async connect() { return client; } }, {
      async checkCurrent() {}, couponRepository: { async beginCheckoutWithClient() { reserved = true; return { state: 'admitted' }; } },
      auditStore: { async append() { throw Error('unexpected audit'); } },
    });
    const work = repository.checkout(binding, { shopUserId: 41, persona: { id: 41 }, shippingAddress: 'owned', paymentMethod: 'test' });
    if (failureSql) await assert.rejects(work, error => error === injected);
    else assert.equal(await work, CART_STOCK_REJECTED);
    assert.equal(reserved, false);
    assert.equal(queries.some(sql => /^(INSERT|UPDATE|DELETE)/.test(sql)), false);
  }
});
