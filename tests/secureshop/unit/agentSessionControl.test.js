'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');

const REPO = path.resolve(__dirname, '../../..');
const { agentSessionControl } = require(path.join(REPO, 'server/routes/secureshop/_agentSessionControl.js'));
const { runSessionExclusive } = require(path.join(REPO, 'server/services/secureshop/sessionStore.js'));
const { createSecureShopAgentsDb } = require(path.join(REPO, 'server/database/postgres/secureshopAgentsDb.js'));
const { requireRole } = require(path.join(REPO, 'server/routes/secureshop/_ssAuthMiddleware.js'));

function responseRecorder() {
  return {
    statusCode: 200,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

function request(port, method, route, body, token) {
  return new Promise((resolve, reject) => {
    const headers = { 'content-type': 'application/json' };
    if (token) headers.authorization = `Bearer ${token}`;
    const req = http.request({ hostname: '127.0.0.1', port, method, path: route, headers }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data || '{}') }));
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

test('HTTP control plane authenticates role and hides cross-owner sessions', async () => {
  const secret = `agent-session-${crypto.randomBytes(8).toString('hex')}`;
  process.env.JWT_SECRET = secret;
  let saved;
  const store = {
    async createSession(input) { saved = { id: 'owned-session', userId: input.userId, role: input.role }; return { id: saved.id }; },
    async getSession(id) { return id === saved?.id ? saved : null; },
  };
  const control = agentSessionControl('customer', store);
  const app = express();
  app.use(express.json());
  app.use('/agents/customer', requireRole('customer'));
  app.post('/agents/customer/session', control.create);
  app.get('/agents/customer/trace/:sessionId', control.requireOwned, (req, res) => res.json({ ok: true }));
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const port = server.address().port;
  const token = (id, role = 'customer') => jwt.sign({ id, role }, secret, { algorithm: 'HS256' });
  try {
    assert.equal((await request(port, 'POST', '/agents/customer/session', { userId: 999 })).status, 401);
    const created = await request(port, 'POST', '/agents/customer/session', { userId: 999 }, token(7));
    assert.equal(created.status, 200);
    assert.equal(saved.userId, 7);
    assert.equal((await request(port, 'GET', '/agents/customer/trace/owned-session', null, token(8))).status, 404);
    assert.equal((await request(port, 'GET', '/agents/customer/trace/owned-session', null, token(7, 'merchant'))).status, 403);
    assert.equal((await request(port, 'GET', '/agents/customer/trace/owned-session', null, token(7))).status, 200);
  } finally {
    server.close();
  }
});

test('session creation binds the authenticated caller and ignores body userId', async () => {
  let created;
  const control = agentSessionControl('merchant', {
    async createSession(input) { created = input; return { id: 'session-1' }; },
  });
  const req = { ssUser: { id: 22, role: 'merchant' }, body: { userId: 999 } };
  const res = responseRecorder();
  await control.create(req, res, assert.fail);
  assert.deepEqual(created, { userId: 22, role: 'merchant' });
  assert.deepEqual(res.body, { sessionId: 'session-1' });
});

test('session access requires both matching owner and matching role', async () => {
  const store = {
    async getSession(id) {
      return id === 'owned' ? { id, userId: 7, role: 'customer' } : null;
    },
  };
  const control = agentSessionControl('customer', store);

  let nextCalled = false;
  const ownedReq = { ssUser: { id: 7, role: 'customer' }, body: { sessionId: 'owned' }, params: {} };
  await control.requireOwned(ownedReq, responseRecorder(), () => { nextCalled = true; });
  assert.equal(nextCalled, true);
  assert.equal(ownedReq.agentSession.id, 'owned');

  for (const ssUser of [{ id: 8, role: 'customer' }, { id: 7, role: 'merchant' }]) {
    const res = responseRecorder();
    await control.requireOwned({ ssUser, body: { sessionId: 'owned' }, params: {} }, res, assert.fail);
    assert.equal(res.statusCode, 404);
    assert.deepEqual(res.body, { error: 'agent session not found' });
  }
});

test('latest trace projection excludes sessions owned by other callers', async () => {
  const sessions = new Map([
    ['mine', { id: 'mine', userId: 7, role: 'customer' }],
    ['other-user', { id: 'other-user', userId: 8, role: 'customer' }],
    ['other-role', { id: 'other-role', userId: 7, role: 'merchant' }],
  ]);
  const control = agentSessionControl('customer', {
    async getSession(id) { return sessions.get(id) || null; },
  });
  const rows = await control.filterOwnedTraceRows(
    { ssUser: { id: 7, role: 'customer' } },
    [...sessions.keys(), 'missing'].map((session_id) => ({ session_id })),
  );
  assert.deepEqual(rows, [{ session_id: 'mine' }]);
});

test('same-session execution is serialized while different sessions can proceed', async () => {
  const events = [];
  let releaseFirst;
  const firstGate = new Promise((resolve) => { releaseFirst = resolve; });
  const first = runSessionExclusive('shared', async () => {
    events.push('first-start');
    await firstGate;
    events.push('first-end');
  });
  const second = runSessionExclusive('shared', async () => events.push('second'));
  const other = runSessionExclusive('other', async () => events.push('other'));
  await other;
  assert.deepEqual(events, ['first-start', 'other']);
  releaseFirst();
  await Promise.all([first, second]);
  assert.deepEqual(events, ['first-start', 'other', 'first-end', 'second']);
});

test('PostgreSQL adapter normalizes session ownership metadata', async () => {
  const calls = [];
  const pool = {
    async query(sql, args) {
      calls.push({ sql, args });
      return { rows: [{ id: 'pg-session', user_id: 31, role: 'admin' }] };
    },
  };
  const db = createSecureShopAgentsDb(pool);
  assert.deepEqual(await db.getSession('pg-session'), { id: 'pg-session', userId: 31, role: 'admin' });
  assert.match(calls[0].sql, /WHERE s\.id=\$1/);
  assert.match(calls[0].sql, /COALESCE\(to_jsonb\(s\)->>'authority_mode','legacy'\)='legacy'/);
  assert.deepEqual(calls[0].args, ['pg-session']);
});
