'use strict';

const assert = require('node:assert/strict');
const express = require('express');
const { randomUUID } = require('node:crypto');
const { createSecureShopBoundPersonaRepository } = require('../../server/database/postgres/secureshopBoundPersonaRepository');
const { createSecureShopBoundPersonaAuth } = require('../../server/services/secureshopBoundPersonaAuth');
const { createSecureShopBoundGateway } = require('../../server/routes/secureshop/boundGateway');

async function json(response) {
  const body = await response.json();
  return { status: response.status, body };
}

// Exercises the mounted HTTP boundary with the real launch and persona
// repositories. The supplied auditSummary is the parent-owned runner; no
// successful service is fabricated for a missing dependency.
async function qualifyAuditHttp({ identity, commerce, agents, auditStore, launches,
  scope, launchBearer, auditSummary, requestId = randomUUID(), jwtSecret = process.env.JWT_SECRET || `${randomUUID()}${randomUUID()}` } = {}) {
  if ([identity, commerce, agents, auditStore, launches, scope, launchBearer, auditSummary].some(value => !value)
      || typeof auditSummary.createSession !== 'function' || typeof auditSummary.run !== 'function'
      || typeof jwtSecret !== 'string' || Buffer.byteLength(jwtSecret) < 32) {
    throw new TypeError('Audit HTTP qualification dependencies are required');
  }
  const personas = createSecureShopBoundPersonaRepository({ commercePool: commerce,
    agentsPool: agents, auditStore });
  await personas.ensureTemplates();
  const personaAuth = createSecureShopBoundPersonaAuth({ repository: personas, launches, jwtSecret });
  const unavailable = () => { throw new Error('unused gateway dependency'); };
  // Gateway ordering requires these routers to be mounted, but this
  // qualification never exercises their paths.
  const unusedRouter = (_req, _res, next) => next();
  const catalog = Object.fromEntries(['listProducts', 'getProduct', 'listMerchantProducts', 'createMerchantProduct',
    'updateMerchantProduct', 'archiveMerchantProduct', 'categories'].map(name => [name, unavailable]));
  const commerceService = Object.fromEntries(['cart', 'add', 'update', 'remove', 'summary', 'checkout', 'orders', 'order']
    .map(name => [name, unavailable]));
  const account = Object.fromEntries(['profile', 'updateProfile', 'addresses', 'createAddress', 'updateAddress', 'deleteAddress']
    .map(name => [name, unavailable]));
  const app = express();
  app.use(express.json());
  app.use('/api/secureshop', createSecureShopBoundGateway({ launches,
    authenticatePersona: personaAuth.authenticatePersona, personaAuth, auditSummary,
    reviewsRouter: unusedRouter, browserRouter: unusedRouter, catalog,
    commerce: commerceService, account }));
  const server = await new Promise((resolve, reject) => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
    listener.once('error', reject);
  });
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/secureshop`;
    const launchHeaders = { 'x-owasp-ai-goat-secureshop-launch': launchBearer,
      'content-type': 'application/json' };
    const loginResponse = await fetch(`${base}/v2/auth/login`, { method: 'POST', headers: launchHeaders,
      body: JSON.stringify({ username: 'student_admin', password: 'student123' }) });
    const login = await json(loginResponse);
    assert.equal(login.status, 200);
    assert.equal(login.body.user.role, 'admin');
    assert.ok(Number.isSafeInteger(login.body.user.id));
    const adminHeaders = { ...launchHeaders, authorization: `Bearer ${login.body.token}` };

    const missing = await fetch(`${base}/admin/audit/bound-session`, { method: 'POST', headers: launchHeaders, body: '{}' });
    assert.equal(missing.status, 401, 'missing persona token must be denied');
    const sessionResponse = await fetch(`${base}/admin/audit/bound-session`, { method: 'POST', headers: adminHeaders, body: '{}' });
    const session = await json(sessionResponse);
    assert.equal(session.status, 200);
    assert.equal(session.body.ok, true);
    assert.match(session.body.sessionId, /^[0-9a-f-]{36}$/i);
    const body = { session_id: session.body.sessionId, request_id: requestId, limit: 20 };
    const first = await fetch(`${base}/admin/audit/bound-summary`, { method: 'POST', headers: adminHeaders, body: JSON.stringify(body) });
    const result = await json(first);
    assert.equal(result.status, 200);
    assert.equal(result.body.replayed, false);
    assert.equal(result.body.requestedCount, body.limit);
    assert.equal(typeof result.body.summary, 'string');
    const replay = await fetch(`${base}/admin/audit/bound-summary`, { method: 'POST', headers: adminHeaders, body: JSON.stringify(body) });
    const replayResult = await json(replay);
    assert.equal(replayResult.status, 200);
    assert.equal(replayResult.body.replayed, true);
    assert.deepEqual({ ...replayResult.body, replayed: false }, result.body);

    const customerLogin = await fetch(`${base}/v2/auth/login`, { method: 'POST', headers: launchHeaders,
      body: JSON.stringify({ username: 'student_customer', password: 'student123' }) });
    const customer = await json(customerLogin);
    assert.equal(customer.status, 200);
    const customerHeaders = { ...launchHeaders, authorization: `Bearer ${customer.body.token}` };
    const customerDenied = await fetch(`${base}/admin/audit/bound-session`, { method: 'POST', headers: customerHeaders, body: '{}' });
    assert.equal(customerDenied.status, 403, 'customer persona must not create an admin audit session');
    const segments = login.body.token.split('.');
    segments[2] = `${segments[2][0] === 'a' ? 'b' : 'a'}${segments[2].slice(1)}`;
    const forged = segments.join('.');
    const forgedResponse = await fetch(`${base}/admin/audit/bound-session`, { method: 'POST',
      headers: { ...launchHeaders, authorization: `Bearer ${forged}` }, body: '{}' });
    assert.equal(forgedResponse.status, 401, 'forged admin token must be denied');
    return Object.freeze({ sessionId: session.body.sessionId, requestId, result: result.body,
      replay: replayResult.body, adminPersonaId: login.body.user.id });
  } finally {
    await new Promise(resolve => server.close(() => resolve()));
  }
}

module.exports = { qualifyAuditHttp };
