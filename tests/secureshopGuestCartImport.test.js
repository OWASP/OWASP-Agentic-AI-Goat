'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createSecureShopBoundCommerceRepository } = require('../server/database/postgres/secureshopBoundCommerceRepository');
const { createSecureShopBoundCommerce } = require('../server/services/secureshopBoundCommerce');

const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000101',
  scenarioId: '20000000-0000-4000-8000-000000000101', generation: 1,
  platformOwnerId: 101, platformSessionId: 102 });
const target = Object.freeze({ ...scope, targetId: '30000000-0000-4000-8000-000000000101' });
const requestId = '40000000-0000-4000-8000-000000000101';
const session = Object.freeze({ sessionId: '50000000-0000-4000-8000-000000000101', authorityVersion: '1' });
function fixture(stock = 8, options = {}) {
  let receipt = null;
  const cart = new Map();
  const queries = [];
  const products = new Map([
    [7, { product_id: 7, name: 'Current product', price: '3.25', stock_quantity: stock,
      status: 'active', archived: false }],
    [8, { product_id: 8, name: 'Other product', price: '1.00', stock_quantity: 1,
      status: 'active', archived: false }],
  ]);
  if (options.escapedNames) {
    products.clear();
    for (let id = 7; id < 57; id++) products.set(id, { product_id: id,
      name: '"'.repeat(4096), price: '1.00', stock_quantity: 1,
      status: 'active', archived: false });
  }
  const client = { async query(sql, args = []) {
    queries.push([sql, args]);
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql) || sql.includes('pg_advisory_xact_lock')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }] };
    if (sql.includes('FROM secureshop_review.guest_cart_imports')) return { rows: receipt ? [receipt] : [] };
    if (sql.includes('FROM secureshop_review.product_target_products p')) {
      return { rows: args[1].map(id => products.get(id)).filter(Boolean) };
    }
    if (sql.includes('FROM secureshop_review.product_target_cart_items') && sql.includes('FOR UPDATE')) {
      return { rows: args[2].filter(id => cart.has(id)).map(id => ({ product_id: id, quantity: cart.get(id) })) };
    }
    if (sql.startsWith('INSERT INTO secureshop_review.product_target_cart_items')) {
      cart.set(args[2], (cart.get(args[2]) || 0) + args[3]); return { rowCount: 1, rows: [] };
    }
    if (sql.startsWith('INSERT INTO secureshop_review.guest_cart_imports')) {
      receipt = { target_id: args[1], shop_user_id: args[2], intent_sha256: args[3],
        state: 'completed', result_json: args[6], result_sha256: args[7] };
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unexpected query: ${sql}`);
  }, release() {} };
  const pool = { async connect() { return client; }, async query() { throw Error('transaction required'); } };
  return { repository: createSecureShopBoundCommerceRepository(pool, { checkCurrent: async () => {} }),
    queries, cart };
}
const input = (items, id = requestId) => ({ shopUserId: 41, requestId: id, items, personaSession: session });

test('guest import uses current price, adds once, and replays the receipt without a second cart write', async () => {
  const f = fixture();
  const first = await f.repository.importGuestCart(target, input([{ productId: 7, quantity: 2 }]));
  assert.deepEqual(first, { requestId, imported: true, replayed: false,
    items: [{ productId: 7, quantity: 2, price: 3.25, name: 'Current product' }], subtotal: 6.5 });
  const replay = await f.repository.importGuestCart(target, input([{ productId: 7, quantity: 2 }]));
  assert.deepEqual(replay, { ...first, replayed: true });
  assert.equal(f.cart.get(7), 2);
  assert.equal(f.queries.filter(([sql]) => sql.startsWith('INSERT INTO secureshop_review.product_target_cart_items')).length, 1);
  await assert.rejects(f.repository.importGuestCart(target, input([{ productId: 7, quantity: 3 }])),
    { code: 'CART_IMPORT_CONFLICT' });
});

test('one insufficient product rejects every line without cart write or receipt', async () => {
  const f = fixture();
  const result = await f.repository.importGuestCart(target, input([
    { productId: 7, quantity: 2 }, { productId: 8, quantity: 2 },
  ]));
  assert.deepEqual(result, { requestId, imported: false, replayed: false,
    issues: [{ productId: 8, code: 'INSUFFICIENT_STOCK', availableQuantity: 1 }] });
  assert.equal(f.cart.size, 0);
  assert.equal(f.queries.some(([sql]) => sql.startsWith('INSERT INTO secureshop_review.guest_cart_imports')), false);
});

test('negative teaching stock is reported as zero availability without mutating stored stock', async () => {
  const f = fixture(-3);
  const result = await f.repository.importGuestCart(target, input([{ productId: 7, quantity: 1 }]));
  assert.deepEqual(result.issues, [{ productId: 7, code: 'INSUFFICIENT_STOCK', availableQuantity: 0 }]);
  assert.equal(f.cart.size, 0);
  assert.equal(f.queries.some(([sql]) => sql.startsWith('INSERT INTO secureshop_review.guest_cart_imports')), false);
});

test('receipt column fits 50 authoritative names at the 4096-byte escaping limit', async () => {
  const f = fixture(8, { escapedNames: true });
  const items = Array.from({ length: 50 }, (_, index) => ({ productId: index + 7, quantity: 1 }));
  const result = await f.repository.importGuestCart(target, input(items));
  assert.equal(result.imported, true);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) > 262144);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < 2097152);
  const migration = fs.readFileSync(path.join(__dirname,
    '../db/postgres/workshop-migrations/secureshop_review/0033_guest_cart_import.sql'), 'utf8');
  assert.match(migration, /octet_length\(result_json\) <= 2097152/);
});

test('commerce import requires a customer and routes through the bound target', async () => {
  const calls = [];
  const repository = Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder']
    .map(name => [name, async () => null]));
  repository.importGuestCart = async (value, request) => { calls.push([value, request]);
    return { requestId, imported: true, replayed: false, items: [], subtotal: 0 }; };
  const service = createSecureShopBoundCommerce({ repository,
    catalog: { async prepareTarget() { return target; }, async hasProduct() { return true; } } });
  const request = { scope, persona: { id: 41, role: 'customer' }, personaSession: session,
    requestId, items: [{ productId: 7, quantity: 1 }] };
  await assert.rejects(service.importGuestCart({ ...request, persona: { id: 12, role: 'merchant' } }),
    { code: 'OWNER_MISMATCH' });
  assert.equal(calls.length, 0);
  assert.equal((await service.importGuestCart(request)).imported, true);
  assert.equal(calls[0][1].shopUserId, 41);
});
