'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const jwt = require('jsonwebtoken');
const Module = require('node:module');

const JWT_SECRET = 'controlled-merchant-route-secret';
const previousSecret = process.env.JWT_SECRET;
process.env.JWT_SECRET = JWT_SECRET;
const calls = {};
const sessions = new Map();
const repository = {
  async listProducts(input) { calls.listProducts = input; if (calls.failList) throw new Error('controlled repository failure'); return { rows: [{ id: 1, name: 'Existing', price: 9.99, retailer_id: 2 }], total: 1, categories: ['audio'] }; },
  async latestMerchantTrace(owner) { calls.latestTrace = owner; return [{ session_id: 'owned', kind: 'mcp_result' }]; },
  async merchantTrace(id) { return [{ session_id: id, kind: 'decision' }]; },
};
const sessionStore = {
  async createSession({ userId, role }) { const id = `merchant-${userId}`; sessions.set(id, { id, userId, role }); return { id }; },
  async getSession(id) { return sessions.get(id) || null; },
  async runSessionExclusive(_id, operation) { return operation(); },
};
const originalLoad = Module._load;
Module._load = function controlledLoad(request, parent, isMain) {
  if (request.endsWith('/services/secureshop/sessionStore.js')) return sessionStore;
  if (request.endsWith('/services/secureshop/supervisors/merchantSupervisor.js')) return { merchantSupervisor: {} };
  if (request.endsWith('/services/secureshop/streaming.js')) return { runChatTurn: async (_req, res) => { res.type('text/event-stream'); for (const event of ['tool_call', 'tool_result', 'assistant_message', 'done']) res.write(`event: ${event}\ndata: {}\n\n`); res.end(); } };
  if (request.endsWith('/database/postgres/secureshopPools.js')) return { getCommercePool() { throw new Error('repository injection required'); }, getAgentsPool() { throw new Error('repository injection required'); } };
  if (request.endsWith('/database/postgres/secureshopMerchantRepository.js')) return { createSecureShopMerchantRepository() { throw new Error('repository injection required'); } };
  if (request.endsWith('/agents/pricing-strategy/tools/index.js')) return { suggest_price: async (input) => { calls.suggest = input; return { ok: true, suggested_price: 14.25 }; }, run_pricing_experiment: async () => ({ ok: true }) };
  if (request.endsWith('/agents/analytics/tools/index.js')) return { nl_query: async (input) => { calls.analytics = input; return { ok: true, rows: [{ username: 'controlled DTO' }] }; }, top_products: async () => ({ ok: true, rows: [] }), revenue_breakdown: async () => ({ ok: true }) };
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
test.beforeEach(() => { for (const key of Object.keys(calls)) delete calls[key]; sessions.clear(); });
test.after(async () => { await new Promise((resolve) => server.close(resolve)); Module._load = originalLoad; if (previousSecret === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = previousSecret; });
function token(id = 2, role = 'merchant') { return jwt.sign({ id, username: `user-${id}`, role }, JWT_SECRET, { algorithm: 'HS256' }); }
async function request(method, pathname, body, auth = token()) {
  const response = await fetch(base + pathname, { method, headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(auth ? { authorization: `Bearer ${auth}` } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text(); let parsed; try { parsed = JSON.parse(text); } catch { parsed = text; } return { status: response.status, body: parsed };
}

test('merchant authorization and session creation bind the JWT owner', async () => {
  assert.equal((await request('GET', '/merchant/products', undefined, null)).status, 401);
  assert.equal((await request('GET', '/merchant/products', undefined, token(1, 'customer'))).status, 403);
  const created = await request('POST', '/agents/merchant/session', { userId: 999 });
  assert.equal(created.status, 200); assert.deepEqual(sessions.get(created.body.sessionId), { id: created.body.sessionId, userId: 2, role: 'merchant' });
});

test('merchant products endpoint forwards normalized filters to the async repository', async () => {
  const result = await request('GET', '/merchant/products?retailer_id=2&status=active&category=audio&search=amp&sort=price_asc&page=2&per_page=5');
  assert.equal(result.status, 200); assert.equal(result.body.products[0].name, 'Existing');
  assert.deepEqual(calls.listProducts, { retailerId: 2, status: 'active', category: 'audio', search: 'amp', sort: 'price_asc', limit: 5, offset: 5 });
  assert.equal(result.body.page, 2); assert.equal(result.body.per_page, 5);
  calls.failList = true;
  const failed = await request('GET', '/merchant/products');
  assert.equal(failed.status, 500); assert.equal(failed.body.error, 'controlled repository failure');
});

test('merchant pricing and analytics routes preserve tool argument/DTO contracts', async () => {
  const price = await request('POST', '/merchant/pricing/suggest', { product_id: 7 }); assert.deepEqual(price.body, { ok: true, suggested_price: 14.25 }); assert.deepEqual(calls.suggest, { product_id: 7 });
  const analytics = await request('POST', '/merchant/analytics/query', { question: 'list all customers' }); assert.equal(analytics.body.rows[0].username, 'controlled DTO'); assert.deepEqual(calls.analytics, { question: 'list all customers' });
  // Native PostgreSQL disclosure/pricing effects: secureshopMerchant.integration:108-114 and secureshopCommerce.integration:32-35.
});

test('merchant chat requires an owned session and preserves SSE event names', async () => {
  const created = await request('POST', '/agents/merchant/session', {});
  assert.equal((await request('POST', '/agents/merchant/chat', { sessionId: created.body.sessionId })).status, 400);
  assert.equal((await request('POST', '/agents/merchant/chat', { sessionId: created.body.sessionId, message: 'stock' }, token(3))).status, 404);
  const chat = await request('POST', '/agents/merchant/chat', { sessionId: created.body.sessionId, message: 'stock' }); assert.equal(chat.status, 200);
  for (const event of ['tool_call', 'tool_result', 'assistant_message', 'done']) assert.match(chat.body, new RegExp(`event: ${event}`));
});

test('merchant latest trace is owner-scoped and bounded', async () => {
  const latest = await request('GET', '/agents/merchant/trace/latest?limit=500'); assert.equal(latest.body.count, 1);
  assert.deepEqual(calls.latestTrace, { userId: 2, role: 'merchant', limit: 50 });
});
