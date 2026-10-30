'use strict';

// Controlled HTTP forwarding/projection only; no genuine persona, Judge or credit proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const http = require('node:http');
const express = require('express');
const { createBoundTicketAssessmentRouter, publicTicketAssessment } =
  require('../server/routes/secureshop/boundTicketAssessment');

async function fixture(t) {
  const scope = Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 2,
    platformOwnerId: 7, platformSessionId: 9 });
  const personaSession = Object.freeze({ sessionId: randomUUID(), expiresAt: '2030-01-01T00:00:00Z', authorityVersion: 3 });
  const state = { role: 'admin', id: 4, personaSession, calls: [], error: null,
    value: { completed: true, replayed: false, judgment: { evaluationId: randomUUID(), verdict: 'pass', canRetry: false } } };
  const service = method => async context => {
    state.calls.push({ method, context });
    assert.deepEqual(context.scope, scope);
    assert.deepEqual(context.persona, { id: 4, role: 'admin' });
    assert.strictEqual(context.personaSession, personaSession);
    assert.deepEqual(Object.keys(context).sort(), ['scope','persona','personaSession','ticketId','requestId','signal'].sort());
    assert.ok(context.signal instanceof AbortSignal);
    if (state.onCall) await state.onCall(context, method);
    if (state.error) throw state.error;
    return state.value;
  };
  const app = express(); app.use(express.json());
  app.use(createBoundTicketAssessmentRouter({
    launches: { resolveCapability: async () => scope },
    authenticatePersona(req, _res, next) {
      req.ssUser = { id: state.id, role: state.role }; req.ssPersonaSession = state.personaSession; next();
    },
    assessment: { runAttempt: service('runAttempt'), readOutcome: service('readOutcome') },
  }));
  const server = await new Promise(resolve => { const instance = app.listen(0, '127.0.0.1', () => resolve(instance)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/admin/tickets`;
  const headers = { 'content-type': 'application/json', 'x-owasp-ai-goat-secureshop-launch': 'a'.repeat(43) };
  return { state, scope, personaSession, base, headers,
    post: (ticketId, body, suffix = '', contentType = 'application/json') => fetch(`${base}/${ticketId}/assessment${suffix}`,
      { method: 'POST', headers: { ...headers, 'content-type': contentType }, body: JSON.stringify(body) }),
    get: (ticketId, requestId, suffix = '') => fetch(`${base}/${ticketId}/assessment/${requestId}${suffix}`, { headers }) };
}

test('ticket assessment POST binds only IDs to verified admin context and GET performs saved read only', async t => {
  const f = await fixture(t), requestId = randomUUID();
  const accepted = await f.post('9223372036854775807', { requestId: requestId.toUpperCase() });
  assert.equal(accepted.status, 200); assert.equal(accepted.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await accepted.json(), f.state.value);
  assert.equal(f.state.calls[0].context.ticketId, '9223372036854775807');
  assert.equal(f.state.calls[0].context.requestId, requestId);
  f.state.value = { ...f.state.value, replayed: true };
  for (let index = 0; index < 2; index++) {
    const saved = await f.get('9223372036854775807', requestId.toUpperCase());
    assert.equal(saved.status, 200); assert.equal(saved.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await saved.json(), f.state.value);
  }
  assert.deepEqual(f.state.calls.map(call => call.method), ['runAttempt', 'readOutcome', 'readOutcome']);
  assert.ok(f.state.calls.every(call => call.context.requestId === requestId));
  assert.ok(f.state.calls.every(call => call.context.signal.aborted === false),
    'normally finished responses must not abort the service signal');
});

test('ticket assessment HTTP disconnect aborts the original service signal without another run or read',
  { timeout: 5000 }, async t => {
    for (const method of ['POST', 'GET']) {
      const f = await fixture(t), requestId = randomUUID();
      let enter, finish, effects = 0;
      const entered = new Promise(resolve => { enter = resolve; });
      const finished = new Promise(resolve => { finish = resolve; });
      f.state.onCall = async context => {
        enter(context);
        try {
          await new Promise(resolve => context.signal.addEventListener('abort', resolve, { once: true }));
          context.signal.throwIfAborted();
          effects++;
        } finally { finish(); }
      };
      const path = method === 'POST' ? `${f.base}/1/assessment` : `${f.base}/1/assessment/${requestId}`;
      let responseSeen = false;
      const request = http.request(path, { method, headers: f.headers }, () => { responseSeen = true; });
      request.on('error', () => {}); // The deliberately closed client must not produce an unhandled socket error.
      t.after(() => request.destroy());
      const closed = new Promise(resolve => request.once('close', resolve));
      request.end(method === 'POST' ? JSON.stringify({ requestId }) : undefined);
      const context = await entered;
      assert.equal(context.signal.aborted, false);
      assert.equal(context.requestId, requestId);
      request.destroy();
      await Promise.all([closed, finished]);
      assert.equal(context.signal.aborted, true);
      assert.equal(responseSeen, false);
      assert.equal(effects, 0);
      assert.deepEqual(f.state.calls.map(call => call.method), [method === 'POST' ? 'runAttempt' : 'readOutcome']);
    }
  });

test('ticket assessment rejects foreign authority selectors, role/session omissions and invalid bigint IDs before dispatch', async t => {
  const f = await fixture(t), requestId = randomUUID();
  for (const body of [{}, { requestId, ownerId: 8 }, { requestId, proof: {} }, { requestId, ticketId: '2' },
    { requestId: 'invalid' }, { requestId: null }]) assert.equal((await f.post('1', body)).status, 400);
  assert.equal((await f.post('1', { requestId }, '?owner=8')).status, 400);
  assert.equal((await f.post('1', { requestId }, '', 'text/plain')).status, 400);
  assert.equal((await f.get('1', requestId, '?generation=1')).status, 400);
  for (const id of ['0', '01', '-1', '1.0', '9223372036854775808', '99999999999999999999']) {
    assert.equal((await f.post(id, { requestId })).status, 400);
    assert.equal((await f.get(id, requestId)).status, 400);
  }
  assert.equal((await f.get('1', 'invalid')).status, 400);
  for (const role of ['customer', 'merchant', undefined]) {
    f.state.role = role;
    assert.equal((await f.post('1', { requestId })).status, 403);
    assert.equal((await f.get('1', requestId)).status, 403);
  }
  f.state.role = 'admin';
  for (const id of [0, '4', NaN]) {
    f.state.id = id; assert.equal((await f.post('1', { requestId })).status, 403);
  }
  f.state.id = 4; f.state.personaSession = null;
  assert.equal((await f.get('1', requestId)).status, 403);
  assert.equal(f.state.calls.length, 0);
});

test('ticket assessment exposes minimal judgment and fails closed on malformed private result', async t => {
  const f = await fixture(t), requestId = randomUUID(), original = f.state.value;
  f.state.value = { ...original, judgment: { ...original.judgment,
    evidence: { bearer: 'controlled-private-placeholder' }, rubric: {}, provider: 'controlled', transcript: 'private' } };
  const saved = await f.get('1', requestId);
  assert.equal(saved.status, 200); assert.deepEqual(await saved.json(), original);
  for (const status of ['disabled', 'ineligible', 'unconfirmed', 'pending']) {
    f.state.value = { completed: false, status, modelEvaluated: false };
    const outcome = await f.get('1', requestId);
    assert.equal(outcome.status, 200); assert.deepEqual(await outcome.json(), f.state.value);
  }
  for (const value of [null, {}, { ...original, source: f.scope },
    { ...original, judgment: { ...original.judgment, evaluationId: 'invalid' } },
    { ...original, judgment: { ...original.judgment, verdict: 'fail' } },
    { completed: false, status: 'pending', modelEvaluated: true }]) {
    f.state.value = value;
    const malformed = await f.get('1', requestId);
    assert.equal(malformed.status, 503);
    assert.deepEqual(await malformed.json(), { error: 'Ticket assessment unavailable' });
    assert.equal(malformed.headers.get('x-owasp-ai-goat-secureshop-launch-state'), null);
  }
  assert.deepEqual(publicTicketAssessment({ completed: false, replayed: true,
    judgment: { evaluationId: original.judgment.evaluationId, verdict: 'unavailable', canRetry: true } }),
  { completed: false, replayed: true, judgment: { evaluationId: original.judgment.evaluationId, verdict: 'unavailable', canRetry: true } });
});

test('ticket assessment preserves stale/conflict/unavailable HTTP lifecycle without leaking private errors', async t => {
  const f = await fixture(t), requestId = randomUUID();
  for (const code of ['STALE_LAUNCH','LAUNCH_UNAVAILABLE','SESSION_UNAVAILABLE','SHOP_AUTH_INVALID','SHOP_SCENE_STALE']) {
    f.state.error = Object.assign(Error('controlled private diagnostic'), { code });
    for (const call of [() => f.post('1', { requestId }), () => f.get('1', requestId)]) {
      const stale = await call(); assert.equal(stale.status, 401);
      assert.equal(stale.headers.get('x-owasp-ai-goat-secureshop-launch-state'), 'unavailable');
      assert.deepEqual(await stale.json(), { error: 'Shop session unavailable' });
    }
  }
  for (const [code, status] of [['TURN_REQUEST_CONFLICT', 409], ['TICKET_RETIRED', 503], ['INTERNAL_PRIVATE', 503]]) {
    f.state.error = Object.assign(Error('controlled private diagnostic'), { code });
    const denied = await f.post('1', { requestId }); assert.equal(denied.status, status);
    assert.equal(denied.headers.get('x-owasp-ai-goat-secureshop-launch-state'), null);
    assert.deepEqual(await denied.json(), { error: 'Ticket assessment unavailable' });
  }
});
