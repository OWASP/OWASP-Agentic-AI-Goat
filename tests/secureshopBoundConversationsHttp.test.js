'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { buildBoundConversationRouter } = require('../server/routes/secureshopBoundConversations');
const { createBoundConversationService } = require('../server/services/secureshopBoundConversation');
const id = '11111111-1111-4111-8111-111111111111';
const scope = { launchId: id, scenarioId: '22222222-2222-4222-8222-222222222222', generation: 1, platformOwnerId: 7, platformSessionId: 8 };

test('HTTP conversation lifecycle binds launch and persona and suppresses revoked reads', async t => {
  let revoked = false, revokeDuringRead = false;
  const rows = new Map();
  const launches = {
    async resolveCapability(token) { return token === 'a'.repeat(43) ? scope : { ...scope, platformOwnerId: 9 }; },
    async assertCurrent() { if (revoked) throw Object.assign(new Error('private authority details'), { code: 'STALE_LAUNCH' }); },
  };
  const service = createBoundConversationService({ launches, makeId: () => id, conversations: {
    async acquireBoundSession({ id, binding }) { rows.set(id, { id, binding, state: 'pending' }); return { id, state: 'pending', created: true }; },
    async activateBoundSession(id) { rows.get(id).state = 'active'; return true; },
    async abandonBoundSession(id) { rows.get(id).state = 'abandoned'; },
    async getBoundSession(id) { return rows.get(id); },
    async getMessages() { if (revokeDuringRead) revoked = true; return [{ role: 'user', content: 'private message' }]; },
    async getTrace() { return [{ kind: 'model_decision' }]; },
    async latestTrace(binding, limit) { assert.equal(limit, 20); return [...rows.values()].filter(row => row.binding.platformOwnerId === binding.platformOwnerId).map(row => ({ session_id: row.id })); },
  } });
  const app = express(); app.use(express.json());
  app.use(buildBoundConversationRouter({ launches, service, role: 'customer', authenticatePersona(req, _res, next) {
    req.ssUser = { id: 1, role: req.headers['x-test-role'] || 'customer' }; next();
  } }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  async function call(path, { token = 'a'.repeat(43), body, role } = {}) {
    const response = await fetch(base + path, { method: body === undefined ? 'GET' : 'POST', headers: {
      'x-dvaia-secureshop-launch': token, 'content-type': 'application/json', ...(role ? { 'x-test-role': role } : {}),
    }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    assert.equal(response.headers.get('cache-control'), 'no-store');
    return { status: response.status, body: await response.json() };
  }
  assert.equal((await call('/sessions', { body: { platformOwnerId: 99 } })).status, 400);
  assert.equal((await call('/sessions?owner=7', { body: {} })).status, 400);
  assert.equal(rows.size, 0);
  assert.deepEqual(await call('/sessions', { body: {} }), { status: 200, body: { sessionId: id } });
  assert.equal(rows.get(id).binding.platformOwnerId, 7);
  assert.equal((await call(`/sessions/${id}/messages`)).body.messages[0].content, 'private message');
  assert.equal((await call(`/sessions/${id}/messages`, { token: 'b'.repeat(43) })).status, 404);
  assert.equal((await call(`/sessions/${id}/trace`, { role: 'merchant' })).status, 403);
  assert.equal((await call('/sessions/not-a-uuid/trace')).status, 404);
  assert.deepEqual((await call('/trace', { token: 'b'.repeat(43) })).body, { trace: [] });
  revokeDuringRead = true;
  assert.deepEqual(await call(`/sessions/${id}/messages`), { status: 401, body: { error: 'SecureShop launch unavailable' } });
  assert.deepEqual(await call('/trace'), { status: 401, body: { error: 'SecureShop launch unavailable' } });
});

test('production shop JWT middleware remains separate from launch authority', async t => {
  const jwt = require('jsonwebtoken');
  const { randomBytes } = require('node:crypto');
  const { requireRole } = require('../server/routes/secureshop/_ssAuthMiddleware');
  const previous = process.env.JWT_SECRET;
  const secret = randomBytes(32).toString('hex');
  process.env.JWT_SECRET = secret;
  t.after(() => { if (previous === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = previous; });
  let creates = 0;
  const app = express(); app.use(express.json());
  app.use(require('../server/middleware/applicationCors').createApplicationCors());
  app.use('/api/secureshop/bound', buildBoundConversationRouter({
    role: 'customer', authenticatePersona: requireRole('customer'),
    launches: { async resolveCapability(token) { return token === 'a'.repeat(43) ? scope : null; } },
    service: { async create(actualScope, persona) {
      assert.deepEqual(actualScope, scope); assert.deepEqual(persona, { id: 1, role: 'customer' });
      creates++; return { id };
    } },
  }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  async function request(token, launch = 'a'.repeat(43)) {
    return fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/bound/sessions`, { method: 'POST', headers: {
      Origin: 'http://localhost:3000',
      'content-type': 'application/json', 'x-dvaia-secureshop-launch': launch,
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    }, body: '{}' });
  }
  const sign = (claims, key = secret, options = {}) => jwt.sign(claims, key, { algorithm: 'HS256', ...options });
  const customer = sign({ id: 1, role: 'customer' });
  assert.equal((await request()).status, 401);
  assert.equal((await request(sign({ id: 1, role: 'customer' }, 'wrong-secret'))).status, 401);
  assert.equal((await request(sign({ id: 1, role: 'customer' }, secret, { expiresIn: -1 }))).status, 401);
  assert.equal((await request(sign({ id: 1, role: 'admin' }))).status, 403);
  assert.equal((await request(sign({ id: '1', role: 'customer' }))).status, 401);
  assert.equal((await request(customer, 'b'.repeat(43))).status, 401);
  assert.equal(creates, 0);
  const preflight = await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/bound/sessions`, { method: 'OPTIONS', headers: { Origin: 'http://localhost:3000', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization,content-type,x-dvaia-secureshop-launch' } });
  assert.equal(preflight.status, 204);
  assert.equal(creates, 0);
  const wrongType = await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/bound/sessions`, { method: 'POST', headers: { authorization: `Bearer ${customer}`, 'x-dvaia-secureshop-launch': 'a'.repeat(43), 'content-type': 'text/plain' }, body: '{}' });
  assert.equal(wrongType.status, 415);
  const accepted = await request(customer);
  assert.equal(accepted.status, 200);
  assert.equal(accepted.headers.get('access-control-allow-origin'), 'http://localhost:3000');
  assert.deepEqual(await accepted.json(), { sessionId: id });
  assert.equal(creates, 1);
});
