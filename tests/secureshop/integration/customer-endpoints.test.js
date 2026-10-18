'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const jwt = require('jsonwebtoken');
const Module = require('node:module');

const JWT_SECRET = 'controlled-customer-endpoints-secret';
const previousSecret = process.env.JWT_SECRET;
process.env.JWT_SECRET = JWT_SECRET;
const calls = {};
const reviews = [];
const sessions = new Map();
const repository = {
  async browse(input) { calls.browse = input; return { products: [{ id: 1, name: 'Alpha', price: 12, image_url: '/legacy.png', images: [] }], total: 1 }; },
  async product(id) { calls.product = id; return String(id) === '404' ? null : { product: { id: Number(id), name: 'Alpha', image_url: 'server/uploads/secureshop/product_images/fallback.png', images: ['server/uploads/secureshop/product_images/fallback.png'] }, reviews: [{ id: 3, body: 'good' }] }; },
  async reviews(productId, limit, offset) { calls.reviews = { productId, limit, offset }; return reviews.filter((row) => row.product_id === Number(productId)); },
  async addReview(productId, authorId, body, rating) { calls.addReview = { productId, authorId, body, rating }; const row = { id: reviews.length + 1, product_id: Number(productId), author_id: Number(authorId), body, rating }; reviews.push(row); return row; },
  async cart(userId) { calls.cart = userId; return [{ id: 9, name: 'Alpha', price: 12.5, quantity: 2 }]; },
  async updateCart(id, quantity) { calls.updateCart = { id, quantity }; return { rowCount: 1 }; },
  async deleteCart(id) { calls.deleteCart = id; return { rowCount: 1 }; },
  async coupon(sql) { calls.couponSql = sql; throw new Error('controlled repository refusal'); },
  async orders(userId) { calls.orders = userId; return [{ id: 4, total_amount: 25 }]; },
  async order(id) { calls.order = id; return { order: { id: Number(id) }, items: [{ product_id: 1, image_url: '/one.png' }] }; },
  async latestTrace(owner) { calls.latestTrace = owner; return [{ session_id: 'owned', kind: 'tool_result' }]; },
  async sessionTrace(id) { return [{ session_id: id, kind: 'decision' }]; },
};
const sessionStore = {
  async createSession({ userId, role }) { const id = `customer-${userId}`; sessions.set(id, { id, userId, role }); return { id }; },
  async getSession(id) { return sessions.get(id) || null; },
  async runSessionExclusive(_id, operation) { return operation(); },
};

const originalLoad = Module._load;
Module._load = function controlledLoad(request, parent, isMain) {
  if (request.endsWith('/services/secureshop/sessionStore.js')) return sessionStore;
  if (request.endsWith('/services/secureshop/supervisors/customerSupervisor')) return { customerSupervisor: {} };
  if (request.endsWith('/services/secureshop/streaming')) return { runChatTurn: async () => { throw new Error('unexpected chat'); } };
  if (request.endsWith('/database/postgres/secureshopPools')) return { getCommercePool() { throw new Error('repository injection required'); }, getAgentsPool() { throw new Error('repository injection required'); } };
  if (request.endsWith('/database/postgres/secureshopCustomerRepository')) return { createSecureShopCustomerRepository() { throw new Error('repository injection required'); } };
  if (request.endsWith('/agents/product-search/tools/similar')) return { similar: async (input) => { calls.similar = input; return { products: [{ id: 2 }] }; } };
  if (request.endsWith('/agents/product-search/tools/personalized_feed')) return { personalizedFeed: async (input) => { calls.recommended = input; return { products: [{ id: 7 }] }; } };
  if (request.endsWith('/agents/summarizer/tools/summarize_product')) return { summarizeProduct: async (input) => { calls.summary = input; return { ok: true, product_id: input.product_id, summary: 'controlled DTO' }; } };
  return originalLoad.call(this, request, parent, isMain);
};

let server;
let base;
test.before(async () => {
  const buildRouter = require('../../../server/routes/secureshop/customer');
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', buildRouter({ pool: {}, manifest: {}, provider: {}, repository }));
  app.use((error, _req, res, _next) => res.status(500).json({ error: error.message }));
  server = app.listen(0, '127.0.0.1'); await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}/api/secureshop`;
});
test.beforeEach(() => { for (const key of Object.keys(calls)) delete calls[key]; reviews.length = 0; sessions.clear(); });
test.after(async () => { await new Promise((resolve) => server.close(resolve)); Module._load = originalLoad; if (previousSecret === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = previousSecret; });
function token(id = 1, role = 'customer') { return jwt.sign({ id, username: `user-${id}`, role }, JWT_SECRET, { algorithm: 'HS256' }); }
async function request(method, pathname, body, auth) {
  const response = await fetch(base + pathname, { method, headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(auth ? { authorization: `Bearer ${auth}` } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text(); let parsed; try { parsed = JSON.parse(text); } catch { parsed = text; } return { status: response.status, body: parsed };
}

test('customer product DTOs use async repository filters and mounted image fallback', async () => {
  const list = await request('GET', '/products?search=alp&category=audio&sort=price_asc&limit=2&offset=3');
  assert.equal(list.status, 200); assert.equal(list.body.total, 1);
  assert.deepEqual(calls.browse, { category: 'audio', search: 'alp', sort: 'price_asc', limit: 2, offset: 3 });
  const detail = await request('GET', '/products/1'); assert.equal(detail.status, 200); assert.deepEqual(detail.body.product.images, ['/api/secureshop/uploads/static/product_images/fallback.png']);
  assert.equal((await request('GET', '/products/404')).status, 404);
});

test('customer tool routes preserve numeric argument and response contracts', async () => {
  assert.equal((await request('POST', '/products/8/summary', {})).body.product_id, 8); assert.deepEqual(calls.summary, { product_id: 8 });
  assert.equal((await request('GET', '/recommended?user_id=17')).body.products[0].id, 7); assert.deepEqual(calls.recommended, { user_id: 17 });
  assert.equal((await request('GET', '/products/8/similar')).body.products[0].id, 2); assert.deepEqual(calls.similar, { product_id: 8 });
});

test('customer review route passes raw HTML and paging arguments to the async repository', async () => {
  assert.equal((await request('POST', '/products/1/reviews', { body: '   ' })).status, 400);
  const raw = '<img src=x onerror=alert(1)>';
  const created = await request('POST', '/products/1/reviews', { author_id: 77, body: raw, rating: 1 });
  assert.deepEqual(created.body, { ok: true, review_id: 1 });
  assert.deepEqual(calls.addReview, { productId: '1', authorId: 77, body: raw, rating: 1 });
  await request('GET', '/products/1/reviews?limit=4&offset=2'); assert.deepEqual(calls.reviews, { productId: '1', limit: 4, offset: 2 });
  // Native persistence and rendered execution: secureshopCustomer.integration and secureshopStoredBrowserRendered.integration.
});

test('customer order/cart DTOs retain totals, mutation counts, and repository arguments', async () => {
  const summary = await request('POST', '/orders/summary', { user_id: 5 }); assert.equal(summary.body.total, 25); assert.match(summary.body.summary, /2× Alpha/); assert.equal(calls.cart, 5);
  assert.deepEqual((await request('PATCH', '/cart/9', { quantity: 3 })).body, { ok: true, changes: 1 }); assert.deepEqual(calls.updateCart, { id: '9', quantity: 3 });
  assert.deepEqual((await request('DELETE', '/cart/9')).body, { ok: true, changes: 1 }); assert.equal(calls.deleteCart, '9');
  assert.equal((await request('GET', '/orders?user_id=12')).body.orders[0].id, 4); assert.equal(calls.orders, 12);
  assert.equal((await request('GET', '/orders/4')).body.items[0].product_id, 1);
});

test('coupon route exposes the bounded PostgreSQL statement on repository refusal without faking an SQL result', async () => {
  const result = await request('POST', '/cart/apply-coupon', { user_id: 1, code: "SAVE10' OR '1'='1" });
  assert.equal(result.status, 400); assert.equal(result.body.ok, false); assert.equal(result.body.error, 'controlled repository refusal');
  assert.equal(result.body.sql, calls.couponSql); assert.match(calls.couponSql, /SAVE10' OR '1'='1/);
  // Actual PostgreSQL predicate effect: tests/postgres/secureshopCustomer.integration.test.js:35-37.
});

test('customer trace authorization uses JWT ownership and bounded limit', async () => {
  assert.equal((await request('GET', '/agents/customer/trace/latest', undefined, token(1, 'merchant'))).status, 403);
  const latest = await request('GET', '/agents/customer/trace/latest?limit=500', undefined, token(9)); assert.equal(latest.body.rows[0].kind, 'tool_result');
  assert.deepEqual(calls.latestTrace, { userId: 9, role: 'customer', limit: 50 });
  sessions.set('mine', { id: 'mine', userId: 9, role: 'customer' });
  assert.equal((await request('GET', '/agents/customer/trace/mine', undefined, token(8))).status, 404);
  assert.equal((await request('GET', '/agents/customer/trace/mine', undefined, token(9))).body.rows[0].kind, 'decision');
});
