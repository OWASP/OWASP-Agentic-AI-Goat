'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const express = require('express');
const { createSecureShopBoundAccessControl } = require('../server/services/secureshopBoundAccessControl');
const { createBoundAccessControlRouter } = require('../server/routes/secureshop/boundAccessControl');
const { REGISTRY_SHA256 } = require('../server/services/secureshopBoundAclRegistry');
const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 1, platformSessionId: 2 };
const credential = { sessionId: randomUUID(), authorityVersion: '1' };
const trusted = () => ({ scope, persona: { id: 3, role: 'admin' }, personaSession: credential });
function fixture() {
  const calls = [], operations = new Map(); let version = '1', failure;
  const repository = {
    async readPolicy(input) {
      calls.push(['read', input]); if (failure) throw failure;
      return { version, enforcement: false, registrySha256: REGISTRY_SHA256, rows: [
        { toolKey: 'audit.search_by_user', supported: true, readOnly: false, roleApplicability: { customer: false, merchant: false, admin: true }, allowed: { customer: false, merchant: false, admin: false } },
        { toolKey: 'system.health_check', supported: false, readOnly: true, roleApplicability: { customer: false, merchant: false, admin: false }, allowed: { customer: false, merchant: false, admin: true }, unavailableReason: 'No supported bound execution workflow' },
      ] };
    },
    async mutate(input) {
      calls.push(['mutate', input]); if (failure) throw failure;
      const prior = operations.get(input.operationId);
      if (prior) {
        if (JSON.stringify(prior.change) !== JSON.stringify(input.change) || prior.expectedVersion !== input.expectedVersion) throw Object.assign(Error(), { code: 'ACL_OPERATION_CONFLICT' });
        return prior;
      }
      if (input.expectedVersion !== version) throw Object.assign(Error(), { code: 'ACL_VERSION_CONFLICT' });
      version = String(Number(version) + 1);
      const receipt = { operationId: input.operationId, expectedVersion: input.expectedVersion, version, enforcement: false, registrySha256: REGISTRY_SHA256, change: input.change };
      operations.set(input.operationId, receipt); return receipt;
    },
    async readOperation(input) { calls.push(['operation', input]); if (failure) throw failure; return operations.get(input.operationId) || null; },
  };
  return { service: createSecureShopBoundAccessControl({ repository }), calls, operations, fail(code) { failure = Object.assign(Error('private failure'), { code }); } };
}
async function mounted(t, f) {
  const app = express(); app.use(express.json());
  const router = createBoundAccessControlRouter({ service: f.service, authenticatePersona(req, _res, next) {
    // Controlled verified middleware identities; body fields never enter here.
    req.ssLaunch = scope; req.ssUser = { id: 3, role: req.headers['x-test-role'] || 'admin' };
    req.ssPersonaSession = req.headers['x-test-no-session'] ? undefined : credential; next();
  } });
  app.use(router);
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return async (path, body, headers = {}) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/admin/access-control${path}`, {
      method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json', ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: response.status, value: await response.json() };
  };
}
test('application preserves matrix DTO, unsupported rows and captures original admin context before await', async () => {
  const f = fixture(), input = structuredClone(trusted());
  const pending = f.service.read(input); input.persona.id = 999; input.personaSession.sessionId = randomUUID();
  const value = await pending;
  assert.equal(value.enforcement_enabled, false); assert.equal(value.administration.versionedPolicy, true);
  assert.equal(value.tools[1].readOnly, true); assert.equal(value.tools[1].supported, false);
  assert.deepEqual(f.calls[0][1], trusted());
  assert.equal(JSON.stringify(value).includes(credential.sessionId), false);
  await assert.rejects(f.service.read({ ...trusted(), persona: { id: 1, role: 'customer' } }), { code: 'ADMIN_REQUIRED' });
  await assert.rejects(f.service.read({ ...trusted(), personaSession: undefined }), { code: 'SHOP_AUTH_INVALID' });
});
test('mounted permission mutation/readback/replay retain operation and revision; conflict is explicit', async t => {
  const f = fixture(), request = await mounted(t, f);
  assert.equal((await request('')).status, 200);
  const body = { tool_name: 'audit.search_by_user', role: 'admin', allowed: true, operationId: randomUUID(), expectedVersion: '1' };
  const first = await request('/permission', body);
  assert.equal(first.status, 200); assert.equal(first.value.allowed, true); assert.equal(first.value.version, '2');
  assert.deepEqual((await request(`/operations/${body.operationId}`)).value.receipt, first.value.receipt);
  assert.deepEqual((await request('/permission', body)).value, first.value);
  assert.equal(f.operations.size, 1);
  const conflict = await request('/permission', { ...body, allowed: false });
  assert.equal(conflict.status, 409); assert.equal(conflict.value.code, 'ACL_OPERATION_CONFLICT');
  assert.equal((await request('/enforcement', { enabled: true, operationId: randomUUID(), expectedVersion: '1' })).value.code, 'ACL_VERSION_CONFLICT');
  assert.equal((await request('/enforcement', { enabled: true, operationId: randomUUID(), expectedVersion: '2' })).value.enforcement_enabled, true);
  for (const [, input] of f.calls) assert.deepEqual(input.personaSession, credential);
});
test('mounted schema rejects authority injection and legacy nonversioned writes without invoking repository', async t => {
  const f = fixture(), request = await mounted(t, f);
  for (const body of [{ enabled: true }, { enabled: 'true', expectedVersion: '1', operationId: randomUUID() },
    { enabled: true, expectedVersion: '1', operationId: randomUUID(), personaSession: credential }]) assert.equal((await request('/enforcement', body)).status, 400);
  assert.equal((await request('?owner=999')).status, 400);
  assert.equal((await request('', undefined, { 'x-test-role': 'customer' })).status, 403);
  assert.equal((await request('', undefined, { 'x-test-no-session': 'yes' })).status, 401);
  assert.equal(f.calls.length, 0);
});
test('uncertain mutation stays unknown with safe code; stale readback does not leak receipt or cause', async t => {
  const f = fixture(), request = await mounted(t, f);
  f.fail('ACL_RECEIPT_OUTCOME_UNCERTAIN');
  const response = await request('/enforcement', { enabled: true, operationId: randomUUID(), expectedVersion: '1' });
  assert.equal(response.status, 503); assert.equal(response.value.code, 'ACL_RECEIPT_OUTCOME_UNCERTAIN');
  assert.equal(JSON.stringify(response.value).includes('private'), false);
  f.fail('SHOP_AUTH_INVALID');
  assert.equal((await request(`/operations/${randomUUID()}`)).status, 401);
});
test('malformed optional router and application dependencies fail closed', () => {
  assert.throws(() => createSecureShopBoundAccessControl({ repository: {} }), TypeError);
  assert.throws(() => createBoundAccessControlRouter({ service: null, authenticatePersona() {} }), TypeError);
});

test('recovery scope is explicitly ordered and stable across same-persona credential refresh', async () => {
  const f = fixture();
  const first = await f.service.read(trusted());
  const reversed = Object.fromEntries(Object.entries(scope).reverse());
  const fresh = await f.service.read({ ...trusted(), scope: reversed,
    personaSession: { sessionId: randomUUID(), authorityVersion: '2' } });
  assert.equal(first.administration.scopeKey, fresh.administration.scopeKey);
  assert.deepEqual(JSON.parse(first.administration.scopeKey),
    [scope.launchId, scope.scenarioId, scope.generation, scope.platformOwnerId, scope.platformSessionId, 3]);
});
