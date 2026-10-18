'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const jwt = require('jsonwebtoken');
const Module = require('node:module');

const JWT_SECRET = 'controlled-customer-route-secret';
const previousSecret = process.env.JWT_SECRET;
process.env.JWT_SECRET = JWT_SECRET;

const agentSessions = new Map();
let nextSession = 1;
const sessionStore = {
  async createSession({ userId, role }) {
    const id = `customer-session-${nextSession++}`;
    agentSessions.set(id, { id, userId, role }); return { id };
  },
  async getSession(id) { return agentSessions.get(id) || null; },
  async runSessionExclusive(_id, operation) { return operation(); },
};

const products = [
  { id: 1, name: 'Headphones', description: 'Battery powered', price: 25, category_name: 'Audio' },
  { id: 2, name: 'Yoga Mat', description: 'Non-slip', price: 10, category_name: 'Fitness' },
];
const reviews = [];
let couponSql;
const repository = {
  async browse({ search, limit, offset }) {
    const filtered = search ? products.filter((row) => row.name.toLowerCase().includes(String(search).toLowerCase())) : products;
    return { products: filtered.slice(offset, offset + limit), total: filtered.length };
  },
  async product(id) { const product = products.find((row) => row.id === Number(id)); return product ? { product, reviews: [] } : null; },
  async reviews(productId) { return reviews.filter((row) => row.product_id === Number(productId)); },
  async addReview(productId, authorId, body, rating) {
    const row = { id: reviews.length + 1, product_id: Number(productId), author_id: Number(authorId), body, rating };
    reviews.push(row); return row;
  },
  async categories() { return ['Audio', 'Fitness']; },
  async cart() { return [{ id: 1, name: 'Headphones', price: 25, quantity: 2 }]; },
  async addCart() { return { id: 9 }; },
  async updateCart(id) { return { rowCount: Number(id) === 9 ? 1 : 0 }; },
  async deleteCart(id) { return { rowCount: Number(id) === 9 ? 1 : 0 }; },
  async coupon(sql) { couponSql = sql; return { code: 'SAVE10', discount_percent: 10, active: 1 }; },
  async orders() { return []; },
  async order() { return null; },
  async checkout() { return null; },
  async latestTrace({ userId, role }) { return [{ session_id: 'owned', user_id: userId, role }]; },
  async sessionTrace(sessionId) { return [{ session_id: sessionId, kind: 'decision' }]; },
};

const originalLoad = Module._load;
Module._load = function controlledLoad(request, parent, isMain) {
  if (request.endsWith('/services/secureshop/sessionStore.js')) return sessionStore;
  if (request.endsWith('/services/secureshop/supervisors/customerSupervisor')) return { customerSupervisor: {} };
  if (request.endsWith('/services/secureshop/streaming')) {
    return { runChatTurn: async (_req, res) => {
      res.setHeader('content-type', 'text/event-stream');
      for (const event of ['tool_call', 'tool_result', 'assistant_message', 'done']) {
        res.write(`event: ${event}\ndata: {}\n\n`);
      }
      res.end();
    } };
  }
  if (request.endsWith('/database/postgres/secureshopPools')) return { getCommercePool() { throw new Error('unexpected pool'); }, getAgentsPool() { throw new Error('unexpected pool'); } };
  if (request.endsWith('/database/postgres/secureshopCustomerRepository')) return { createSecureShopCustomerRepository() { throw new Error('repository injection required'); } };
  return originalLoad.call(this, request, parent, isMain);
};

let server;
let base;
test.before(async () => {
  const buildRouter = require('../../../server/routes/secureshop/customer');
  const app = express();
  app.use(express.json());
  app.use('/api/secureshop', buildRouter({ pool: {}, manifest: {}, provider: {}, repository }));
  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}/api/secureshop`;
});
test.beforeEach(() => { agentSessions.clear(); nextSession = 1; reviews.length = 0; couponSql = null; });
test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  Module._load = originalLoad;
  if (previousSecret === undefined) delete process.env.JWT_SECRET;
  else process.env.JWT_SECRET = previousSecret;
});

function token({ id = 1, role = 'customer' } = {}) {
  return jwt.sign({ id, username: `user-${id}`, role }, JWT_SECRET, { algorithm: 'HS256' });
}
async function request(method, pathname, body, authToken) {
  const response = await fetch(base + pathname, {
    method,
    headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(authToken ? { authorization: `Bearer ${authToken}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch { parsed = text; }
  return { status: response.status, body: parsed };
}

test('customer session creation binds JWT owner and rejects wrong roles', async () => {
  assert.equal((await request('POST', '/agents/customer/session', {}, token({ role: 'merchant' }))).status, 403);
  const created = await request('POST', '/agents/customer/session', {}, token({ id: 7 }));
  assert.equal(created.status, 200);
  assert.deepEqual(agentSessions.get(created.body.sessionId), { id: created.body.sessionId, userId: 7, role: 'customer' });
});

test('customer chat requires the owned session and preserves the SSE response contract', async () => {
  const owner = token({ id: 7 });
  const created = await request('POST', '/agents/customer/session', {}, owner);
  assert.equal((await request('POST', '/agents/customer/chat', { sessionId: created.body.sessionId, message: 'cart' }, token({ id: 8 }))).status, 404);
  assert.equal((await request('POST', '/agents/customer/chat', { sessionId: created.body.sessionId }, owner)).status, 400);
  const chat = await request('POST', '/agents/customer/chat', { sessionId: created.body.sessionId, message: 'cart' }, owner);
  assert.equal(chat.status, 200);
  for (const event of ['tool_call', 'tool_result', 'assistant_message', 'done']) assert.match(chat.body, new RegExp(`event: ${event}`));
});

test('product browse and mutation response/error shapes use the injected async repository', async () => {
  const list = await request('GET', '/products?search=head&limit=1');
  assert.equal(list.status, 200);
  assert.deepEqual(list.body.products.map(({ name }) => name), ['Headphones']);
  assert.equal((await request('GET', '/products/999')).status, 404);
  assert.equal((await request('POST', '/cart', { quantity: 1 })).status, 400);
  assert.equal((await request('POST', '/orders', { user_id: 1 })).status, 400);
});

test('stored review preserves raw HTML and caller-selected author (XSS teaching sink)', async () => {
  assert.equal((await request('POST', '/products/1/reviews', { body: '   ' })).status, 400);
  const body = '<img src=x onerror=alert(1)>';
  const created = await request('POST', '/products/1/reviews', { author_id: 77, body, rating: 1 });
  assert.equal(created.body.ok, true);
  assert.deepEqual(reviews[0], { id: 1, product_id: 1, author_id: 77, body, rating: 1 });
});

test('coupon input remains interpolated into the PostgreSQL predicate (SQLi teaching sink)', async () => {
  const attack = "SAVE10' OR '1'='1";
  const applied = await request('POST', '/cart/apply-coupon', { user_id: 1, code: attack });
  assert.equal(applied.body.ok, true);
  assert.match(couponSql, /SAVE10' OR '1'='1/);
  assert.equal(applied.body.applied_amount, 5);
});

test('trace endpoints retain owner filtering', async () => {
  const owned = await request('GET', '/agents/customer/trace/latest?limit=2', undefined, token({ id: 9 }));
  assert.deepEqual(owned.body.rows, [{ session_id: 'owned', user_id: 9, role: 'customer' }]);
  agentSessions.set('mine', { id: 'mine', userId: 9, role: 'customer' });
  assert.equal((await request('GET', '/agents/customer/trace/mine', undefined, token({ id: 8 }))).status, 404);
  assert.equal((await request('GET', '/agents/customer/trace/mine', undefined, token({ id: 9 }))).body.rows[0].kind, 'decision');
});
