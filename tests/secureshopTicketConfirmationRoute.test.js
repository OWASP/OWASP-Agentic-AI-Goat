'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const express = require('express');
const { createBoundTicketConfirmationRouter } = require('../server/routes/secureshop/boundTicketConfirmation');
const { createBoundTicketAdminRouter } = require('../server/routes/secureshop/boundTicketAdmin');

test('ticket confirmation forwards only saved identifiers and GET never confirms', async t => {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 1, platformSessionId: 2 };
  const ids = { sessionId: randomUUID(), requestId: randomUUID(), proposalId: randomUUID() };
  const result = { version: 1, kind: 'support_ticket', ticketId: '1',
    operationId: ids.proposalId, requestId: ids.requestId, runId: randomUUID(),
    proposalId: ids.proposalId, status: 'open', subjectSha256: 'a'.repeat(64),
    bodySha256: 'b'.repeat(64), receiptSha256: 'c'.repeat(64) };
  let confirms = 0, reads = 0, role = 'customer', corrupt = false, revoked = false;
  const confirmation = {
    async confirm(context, request) {
      confirms++;
      assert.deepEqual(context.scope, scope);
      assert.deepEqual(context.persona, { id: 3, role: 'customer' });
      assert.deepEqual(request, ids);
      if (revoked) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' });
      return { result: corrupt ? { ...result, privateSource: scope } : result, source: scope };
    },
    async readSaved(context, request) {
      reads++;
      assert.deepEqual(context.scope, scope);
      assert.deepEqual(request, ids);
      return { status: 'completed', result };
    },
  };
  const app = express(); app.use(express.json());
  app.use(createBoundTicketConfirmationRouter({
    launches: { async resolveCapability() { return scope; } },
    authenticatePersona(req, res, next) {
      req.ssUser = { id: 3, role }; req.ssPersonaSession = { sessionId: 'controlled-session' }; next();
    }, confirmation,
  }));
  const server = await new Promise(resolve => { const instance = app.listen(0, '127.0.0.1', () => resolve(instance)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/agents/customer/tickets/confirm`;
  const headers = { 'content-type': 'application/json', 'x-dvaia-secureshop-launch': 'a'.repeat(43) };
  const post = (body, suffix = '') => fetch(base + suffix,
    { method: 'POST', headers, body: JSON.stringify(body) });
  const accepted = await post(ids);
  assert.equal(accepted.status, 200); assert.equal(accepted.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await accepted.json(), result);
  const saved = await fetch(`${base}/${ids.sessionId}/${ids.requestId}/${ids.proposalId}`, { headers });
  assert.equal(saved.status, 200); assert.deepEqual(await saved.json(), { status: 'completed', result });
  assert.equal(confirms, 1); assert.equal(reads, 1);
  assert.equal((await post({ ...ids, body: 'model supplied replacement' })).status, 400);
  assert.equal((await post(ids, '?owner=9')).status, 400);
  role = 'admin'; assert.equal((await post(ids)).status, 403); role = 'customer';
  assert.equal(confirms, 1);
  corrupt = true; assert.equal((await post(ids)).status, 503); corrupt = false;
  revoked = true;
  const unavailable = await post(ids);
  assert.equal(unavailable.status, 401);
  assert.equal(unavailable.headers.get('x-dvaia-secureshop-launch-state'), 'unavailable');
});

test('admin ticket reads reject owner selectors and never expose private service fields', async t => {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 1, platformSessionId: 2 };
  let role = 'customer', calls = 0, corrupt = false, detailValue = 'revoked';
  const selectedTicketIds = [];
  const app = express();
  app.use(createBoundTicketAdminRouter({
    launches: { async resolveCapability() { return scope; } },
    authenticatePersona(req, res, next) {
      req.ssUser = { id: 4, role }; req.ssPersonaSession = { sessionId: 'admin-session' }; next();
    },
    administration: {
      async list(context, options) {
        calls++; assert.equal(context.persona.role, 'admin'); assert.deepEqual(options, { cursor: null });
        return { version: 1, tickets: [], nextCursor: null, ...(corrupt ? { source: scope } : {}) };
      },
      async read(context, { ticketId }) {
        calls++;
        assert.deepEqual(context.scope, scope);
        assert.deepEqual(context.persona, { id: 4, role: 'admin' });
        selectedTicketIds.push(ticketId);
        if (detailValue === 'revoked') throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' });
        return detailValue;
      },
    },
  }));
  const server = await new Promise(resolve => { const instance = app.listen(0, '127.0.0.1', () => resolve(instance)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/admin/tickets`;
  const headers = { 'x-dvaia-secureshop-launch': 'a'.repeat(43) };
  const get = suffix => fetch(base + suffix, { headers });
  assert.equal((await get('')).status, 403); assert.equal(calls, 0);
  role = 'admin';
  assert.equal((await get('?owner=7')).status, 400);
  assert.equal((await get('?cursor=a&cursor=b')).status, 400);
  for (const id of ['0', '01', '9223372036854775808', '9999999999999999999']) {
    assert.equal((await get(`/${id}`)).status, 400);
  }
  assert.equal(calls, 0, 'invalid bigint IDs must not dispatch to the ticket reader');
  const list = await get(''); assert.equal(list.status, 200);
  assert.deepEqual(await list.json(), { version: 1, tickets: [], nextCursor: null });
  corrupt = true; assert.equal((await get('')).status, 503);
  const revoked = await get('/1'); assert.equal(revoked.status, 401);
  assert.equal(revoked.headers.get('x-dvaia-secureshop-launch-state'), 'unavailable');
  detailValue = null;
  const absent = await get('/9223372036854775807');
  assert.equal(absent.status, 404);
  assert.deepEqual(await absent.json(), { error: 'Ticket unavailable' });
  assert.equal(absent.headers.get('cache-control'), 'no-store');
  assert.equal(absent.headers.get('x-dvaia-secureshop-launch-state'), null,
    'an absent ticket does not revoke the current launch');
  assert.equal(selectedTicketIds.at(-1), '9223372036854775807',
    'the maximum bigint is forwarded without Number coercion');
  for (const invalid of [{}, undefined, { privateSource: scope }]) {
    detailValue = invalid;
    const malformed = await get('/2');
    assert.equal(malformed.status, 503);
    assert.deepEqual(await malformed.json(), { error: 'Ticket read unavailable' });
  }
});
