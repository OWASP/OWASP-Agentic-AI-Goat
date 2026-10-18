'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const jwt = require('jsonwebtoken');
const Module = require('node:module');

const JWT_SECRET = 'controlled-merchant-wave2b-secret';
const previousSecret = process.env.JWT_SECRET;
process.env.JWT_SECRET = JWT_SECRET;
const calls = {};
const repository = {
  async overview(input) { calls.overview = input; const today = new Date().toISOString().slice(0, 10); return { current: { revenue: '328.99', orders: '2' }, previous: { revenue: '100', orders: '1' }, days: [{ day: today, revenue: '79.99', orders: '1' }], top: { id: 1, name: 'Alpha Speaker', revenue: '249' } }; },
  async salesChart(input) { calls.salesChart = input; return [{ day: new Date().toISOString().slice(0, 10), revenue: '50', orders: '1' }]; },
  async listProducts(input) { calls.listProducts = input; return { rows: [{ id: 1, name: 'Alpha Speaker', status: 'active', category: 'audio' }], total: 3, categories: ['audio'] }; },
  async listReviews(input) { calls.listReviews = input; return { rows: [{ id: 1, status: input.status || 'pending' }], total: 1, counts: { pending: 1 } }; },
  async latestMerchantTrace(owner) { calls.latestTrace = owner; return [{ session_id: 'owned', kind: 'tool_result' }]; },
};
const sessionStore = { async createSession({ userId, role }) { return { id: `${role}-${userId}` }; }, async getSession() { return null; }, async runSessionExclusive(_id, operation) { return operation(); } };
const originalLoad = Module._load;
Module._load = function controlledLoad(request, parent, isMain) {
  if (request.endsWith('/services/secureshop/sessionStore.js')) return sessionStore;
  if (request.endsWith('/services/secureshop/supervisors/merchantSupervisor.js')) return { merchantSupervisor: {} };
  if (request.endsWith('/services/secureshop/streaming.js')) return { runChatTurn: async () => {} };
  if (request.endsWith('/database/postgres/secureshopPools.js')) return { getCommercePool() { throw new Error('repository injection required'); }, getAgentsPool() { throw new Error('repository injection required'); } };
  if (request.endsWith('/database/postgres/secureshopMerchantRepository.js')) return { createSecureShopMerchantRepository() { throw new Error('repository injection required'); } };
  if (request.endsWith('/agents/listing/tools/_llmRewrite.js')) return { rewriteDescription: async (input) => { calls.rewrite = input; return '<p>controlled raw DTO</p>'; } };
  if (request.endsWith('/agents/listing/tools/import_bulk.js')) return { import_bulk: async (input) => { calls.importBulk = input; return { ok: true, inserted: [] }; } };
  if (request.endsWith('/agents/review-moderator/tools/index.js')) return {
    approve: async (input) => { calls.approve = input; return { ok: true, review_id: input.review_id, status: 'approved' }; },
    reject: async (input) => { calls.reject = input; return { ok: true, review_id: input.review_id, status: 'rejected', reason: input.reason }; },
    moderate_pending: async (input) => { calls.moderate = input; return { ok: true, processed: 0, decisions: [] }; },
  };
  if (request.endsWith('/agents/price-advisor/tools/index.js')) return {
    compareCompetitor: async (input) => { calls.compare = input; return { ok: true, product_id: input.product_id, competitor_response: 'controlled transport DTO' }; },
    priceHistory: async (input) => { calls.history = input; return { product_id: input.product_id, history: [{ day: '2026-01-01', price: 10 }] }; },
  };
  return originalLoad.call(this, request, parent, isMain);
};

let server;
let base;
test.before(async () => {
  const buildRouter = require('../../../server/routes/secureshop/merchant');
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', buildRouter({ pool: {}, manifest: {}, provider: {}, repository }));
  app.use((error, _req, res, _next) => res.status(500).json({ error: error.message }));
  server = app.listen(0, '127.0.0.1'); await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}/api/secureshop`;
});
test.beforeEach(() => { for (const key of Object.keys(calls)) delete calls[key]; });
test.after(async () => { await new Promise((resolve) => server.close(resolve)); Module._load = originalLoad; if (previousSecret === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = previousSecret; });
function token() { return jwt.sign({ id: 2, username: 'merchant', role: 'merchant' }, JWT_SECRET, { algorithm: 'HS256' }); }
async function request(method, pathname, body) {
  const response = await fetch(base + pathname, { method, headers: { authorization: `Bearer ${token()}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text(); let parsed; try { parsed = JSON.parse(text); } catch { parsed = text; } return { status: response.status, body: parsed };
}

test('merchant overview and sales chart preserve computed DTOs and repository time bounds', async () => {
  const kpis = await request('GET', '/merchant/overview/kpis?retailer_id=2'); assert.equal(kpis.status, 200);
  assert.equal(kpis.body.revenue.value, 328.99); assert.equal(kpis.body.orders.value, 2); assert.equal(kpis.body.aov.value, 164.495); assert.equal(kpis.body.revenue.spark.length, 30);
  assert.equal(calls.overview.retailerId, 2); assert.match(calls.overview.cutoff, /^\d{4}-\d{2}-\d{2}T/);
  const chart = await request('GET', '/merchant/overview/sales-chart?retailer_id=2&days=14'); assert.equal(chart.body.series.length, 14); assert.equal(calls.salesChart.retailerId, 2);
});

test('merchant product/review projections normalize pagination and filters', async () => {
  const products = await request('GET', '/merchant/products?retailer_id=2&status=active&category=audio&search=Alpha&sort=price_asc&per_page=1&page=2');
  assert.equal(products.body.count, 1); assert.equal(products.body.pages, 3);
  assert.deepEqual(calls.listProducts, { retailerId: 2, status: 'active', category: 'audio', search: 'Alpha', sort: 'price_asc', limit: 1, offset: 1 });
  const reviews = await request('GET', '/merchant/reviews?status=pending&product_id=3&min_rating=2&max_rating=4&page=2&per_page=5'); assert.equal(reviews.body.total, 1);
  assert.deepEqual(calls.listReviews, { status: 'pending', productId: 3, minRating: 2, maxRating: 4, limit: 5, offset: 5 });
});

test('merchant listing routes preserve tool arguments and raw response DTOs', async () => {
  const rewrite = await request('POST', '/merchant/listings/assist-write', { title: 'Sneaky', description: '<script>input()</script>' });
  assert.equal(rewrite.body.description_html, '<p>controlled raw DTO</p>'); assert.deepEqual(calls.rewrite, { title: 'Sneaky', description: '<script>input()</script>' });
  const imported = await request('POST', '/merchant/listings/import-bulk', { json_url: 'file:///controlled/items.json' }); assert.deepEqual(imported.body, { ok: true, inserted: [] }); assert.deepEqual(calls.importBulk, { json_url: 'file:///controlled/items.json' });
  // Native raw-HTML persistence: tests/postgres/secureshopMerchant.integration.test.js:85-97.
  // Actual file/XXE effect: tests/secureshop/vuln/web/xxe-import-bulk.test.js. This test makes no filesystem claim.
});

test('merchant moderation routes preserve IDs, reasons, limits, and response envelopes', async () => {
  assert.equal((await request('POST', '/merchant/reviews/11/approve')).body.status, 'approved'); assert.deepEqual(calls.approve, { review_id: 11 });
  assert.equal((await request('POST', '/merchant/reviews/12/reject', { reason: 'bounded reason' })).body.status, 'rejected'); assert.deepEqual(calls.reject, { review_id: 12, reason: 'bounded reason' });
  assert.equal((await request('POST', '/merchant/reviews/moderate-all', { limit: 7 })).body.processed, 0); assert.deepEqual(calls.moderate, { limit: 7 });
  // Actual PostgreSQL prompt-influenced moderation: tests/postgres/secureshopMerchant.integration.test.js:104-110.
});

test('merchant pricing routes validate input and preserve tool arguments/DTOs', async () => {
  assert.equal((await request('POST', '/merchant/pricing/compare', { product_id: 0 })).status, 400);
  const compared = await request('POST', '/merchant/pricing/compare?product_id=4&url=http%3A%2F%2Fcontrolled.invalid%2F'); assert.equal(compared.body.competitor_response, 'controlled transport DTO');
  assert.deepEqual(calls.compare, { product_id: 4, competitor_url: 'http://controlled.invalid/' });
  assert.equal((await request('GET', '/merchant/pricing/history')).status, 400);
  const history = await request('GET', '/merchant/pricing/history?product_id=4'); assert.equal(history.body.history[0].price, 10); assert.deepEqual(calls.history, { product_id: 4 });
  // Actual SSRF response disclosure: tests/secureshop/vuln/web/ssrf-competitor.test.js; no network effect is emulated here.
});

test('merchant trace latest remains owner-scoped and limit-bounded', async () => {
  const result = await request('GET', '/agents/merchant/trace/latest?limit=500'); assert.equal(result.body.count, 1);
  assert.deepEqual(calls.latestTrace, { userId: 2, role: 'merchant', limit: 50 });
});
