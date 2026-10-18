'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const express = require('express');
const { createBoundSystemConfigRouter } = require('../server/routes/secureshop/boundSystemConfig');

async function fixture(t, service) {
  service = { administration: async () => ({ configReadCapability: 'secureshop-owned-system-config-read.v1', scopeKey: 'a'.repeat(64) }), ...service };
  const app = express(); app.use(express.json({ limit: '32kb' }));
  const scope = { launchId: randomUUID() }, sessionId = randomUUID();
  app.use(createBoundSystemConfigRouter({ service, authenticatePersona(req, res, next) {
    if (req.headers.authorization) {
      req.ssLaunch = scope; req.ssUser = { id: 7, role: req.headers.authorization };
      req.ssPersonaSession = { sessionId, authorityVersion: '2' };
    }
    next();
  } }));
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  async function request(body, { auth = 'admin', suffix = '/admin/system/config-read', method = 'POST', signal } = {}) {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${suffix}`, {
      method, signal, headers: { 'content-type': 'application/json', ...(auth ? { authorization: auth } : {}) },
      ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, cache: response.headers.get('cache-control'), body: await response.json() };
  }
  return { request, scope, sessionId };
}

test('route preserves synthetic config DTO and uses server authentication context', async t => {
  let captured;
  const f = await fixture(t, { operation: async () => {}, read: async value => {
    captured = value;
    return { state: 'completed', operationId: value.operationId, receipt: { operationId: value.operationId,
      status: 'completed', readResult: { ok: true, input: value.path, sanitized: '../.env',
        targetPath: '/app/.env', size: 9, content: 'synthetic', contentSha256: 'fixed' } } };
  } });
  const operationId = randomUUID();
  const out = await f.request({ operationId, path: '....//.env' });
  assert.equal(out.status, 200); assert.equal(out.cache, 'no-store');
  assert.equal(out.body.content, 'synthetic'); assert.equal(out.body.abs, '/app/.env');
  assert.deepEqual(captured.scope, f.scope);
  assert.deepEqual(captured.personaSession, { sessionId: f.sessionId, authorityVersion: '2' });
  assert.deepEqual(captured.persona, { id: 7, role: 'admin' });
});

test('administration requires authenticated admin and cannot accept caller scope', async t => {
  let seen;
  const f = await fixture(t, { read: async () => {}, operation: async () => {}, administration: async input => {
    seen = input; return { scopeKey: 'a'.repeat(64), configReadCapability: 'secureshop-owned-system-config-read.v1' };
  } });
  assert.equal((await f.request(null, { method: 'GET', auth: null, suffix: '/admin/system/config-read' })).status, 401);
  assert.equal((await f.request(null, { method: 'GET', auth: 'customer', suffix: '/admin/system/config-read' })).status, 403);
  assert.equal(seen, undefined);
  const result = await f.request(null, { method: 'GET', suffix: '/admin/system/config-read' });
  assert.equal(result.status, 200); assert.equal(result.body.administration.scopeKey, 'a'.repeat(64));
  assert.deepEqual(seen.scope, f.scope);
  assert.equal((await f.request(null, { method: 'GET', suffix: '/admin/system/config-read?scope=forged' })).status, 400);
});

test('client disconnect aborts the admitted service request', async t => {
  let entered, aborted;
  const started = new Promise(resolve => { entered = resolve; });
  const stopped = new Promise(resolve => { aborted = resolve; });
  const f = await fixture(t, { operation: async () => {}, read: async (_input, { signal }) => {
    entered();
    return new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => { aborted(); reject(signal.reason); }, { once: true });
    });
  } });
  const controller = new AbortController();
  const pending = f.request({ operationId: randomUUID(), path: 'application.json' }, { signal: controller.signal });
  const rejected = assert.rejects(pending, { name: 'AbortError' });
  await started; controller.abort(); await rejected;
  await stopped;
});

test('missing auth, nonadmin and learner-supplied authority never reach service', async t => {
  let calls = 0;
  const f = await fixture(t, { read: async () => { calls++; }, operation: async () => { calls++; } });
  const input = { operationId: randomUUID(), path: 'application.json' };
  assert.equal((await f.request(input, { auth: null })).status, 401);
  assert.equal((await f.request(input, { auth: 'customer' })).status, 403);
  assert.equal((await f.request({ ...input, scope: { launchId: randomUUID() } })).status, 400);
  assert.equal((await f.request(input, { suffix: '/admin/system/config-read?owner=9' })).status, 400);
  assert.equal(calls, 0);
});

test('recovery exposes explicit states without triggering a read and hides private failures', async t => {
  let state = 'pending', reads = 0;
  const f = await fixture(t, {
    read: async () => { reads++; throw Object.assign(new Error('private credentials'), { code: 'SYSTEM_CONFIG_OUTCOME_UNCERTAIN' }); },
    operation: async value => ({ state, operationId: value.operationId }),
  });
  const operationId = randomUUID();
  for (const [nextState, status] of [['pending', 202], ['unknown', 200], ['not_executed', 200], ['not_found', 404]]) {
    state = nextState;
    const out = await f.request(null, { method: 'GET', suffix: `/admin/system/config-operations/${operationId}` });
    assert.equal(out.status, status); assert.equal(out.body.state, state); assert.equal(out.body.ok, false);
  }
  assert.equal(reads, 0);
  const out = await f.request({ operationId, path: 'application.json' });
  assert.equal(out.status, 503); assert.equal(out.body.code, 'SYSTEM_CONFIG_OUTCOME_UNCERTAIN');
  assert.equal(JSON.stringify(out.body).includes('private'), false);
});
