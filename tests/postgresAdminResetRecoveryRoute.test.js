'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const {createPostgresAdminRouter} = require('../server/routes/postgresAdmin');

async function fixture(t, {service, authenticated = true, permitted = true} = {}) {
  const calls = [];
  const pass = (_req, _res, next) => next();
  const auth = {
    authenticateToken(req, res, next) {
      if (!authenticated) return res.sendStatus(401);
      req.user = {id: 2}; req.identitySession = {id: '42'}; next();
    },
    requireAdminLevel: () => pass,
    requirePermission: permission => (req, res, next) => {
      assert.equal(permission, 'manage_progress');
      if (!permitted) return res.sendStatus(403);
      next();
    },
    logActivity: () => pass,
  };
  const resetService = service || {async listPendingBulkResets(input) {
    calls.push(input); return [{operationId: '11111111-1111-4111-8111-111111111111', requestKind: 'all', children: []}];
  }};
  const handler = (_req, res) => res.json({});
  const operational = Object.fromEntries(['providerStatus', 'switchProvider', 'configureProvider',
    'testProvider', 'testLlm', 'appLogs', 'llmLogs', 'logStats', 'systemMonitoring'].map(name => [name, handler]));
  const app = express();
  app.use('/api/admin', createPostgresAdminRouter({adapter: {}, stores: {config: {}, progress: {}},
    auth, repository: {}, resetService, operational, xssLegacyRepository: {}, deletionService: {}}));
  const server = await new Promise(resolve => {const s = app.listen(0, '127.0.0.1', () => resolve(s));});
  t.after(() => new Promise(resolve => server.close(resolve)));
  return {url: `http://127.0.0.1:${server.address().port}/api/admin/workshops/reset-operations`, calls};
}

test('pending reset discovery forwards current immutable authority without creating an operation', async t => {
  const f = await fixture(t);
  const response = await fetch(f.url, {headers: {authorization: 'Bearer controlled-current'}});
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('x-reset-operation-id'), null);
  assert.equal((await response.json()).operations.length, 1);
  assert.equal(f.calls.length, 1);
  const actor = f.calls[0].actorRequest;
  assert.equal(actor.user.id, 2); assert.equal(actor.identitySession.id, '42');
  assert.equal(actor.headers.authorization, 'Bearer controlled-current');
  assert.ok(Object.isFrozen(actor) && Object.isFrozen(actor.user) && Object.isFrozen(actor.headers));
});
for (const [name, options, status] of [
  ['unauthenticated', {authenticated: false}, 401],
  ['permission denied', {permitted: false}, 403],
]) test(`reset discovery rejects ${name} before service access`, async t => {
  const f = await fixture(t, options);
  assert.equal((await fetch(f.url)).status, status); assert.equal(f.calls.length, 0);
});
test('reset discovery rejects caller-selected actor or cohort filters', async t => {
  const f = await fixture(t);
  for (const query of ['actorId=8', 'ownerId=7', 'workshopKey=mcp_workshop']) {
    assert.equal((await fetch(`${f.url}?${query}`)).status, 400);
  }
  assert.equal(f.calls.length, 0);
});
test('reset discovery fails closed when durable storage is not composed', async t => {
  const f = await fixture(t, {service: {}});
  const response = await fetch(f.url);
  assert.equal(response.status, 503); assert.equal((await response.json()).code, 'RESET_STORAGE_NOT_READY');
});
test('fresh service authority rejection is preserved after middleware authentication', async t => {
  const f = await fixture(t, {service: {async listPendingBulkResets() {
    throw Object.assign(new Error('Current reset permission required'), {statusCode: 403, code: 'BULK_RESET_AUTHORITY_REJECTED'});
  }}});
  const response = await fetch(f.url);
  assert.equal(response.status, 403); assert.equal((await response.json()).code, 'BULK_RESET_AUTHORITY_REJECTED');
});

test('scope-specific recovery forwards only normalized scope and retains current authority', async t => {
 const f=await fixture(t);
 for(const [query,scope] of [['requestKind=all',{requestKind:'all'}],['requestKind=workshop&workshopKey=mcp_workshop',{requestKind:'workshop',workshopKey:'mcp_workshop'}]]) {
  assert.equal((await fetch(`${f.url}?${query}`)).status,200);assert.deepEqual(f.calls.at(-1).scope,scope);
 }
 for(const query of ['requestKind=all&workshopKey=mcp_workshop','requestKind=workshop','requestKind=database_reset','requestKind=all&actorId=8','requestKind=all&requestKind=workshop'])assert.equal((await fetch(`${f.url}?${query}`)).status,400);
 assert.equal(f.calls.length,2);
});
