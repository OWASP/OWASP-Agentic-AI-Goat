'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createBoundIdorLessonRouter } =
  require('../server/routes/secureshop/boundIdorLesson');

const id = n => `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`;
const scope = { launchId: id(1), scenarioId: id(2), generation: 3,
  platformOwnerId: 4, platformSessionId: 5 };
const personaSession = { sessionId: id(6), authorityVersion: '1',
  expiresAt: '2026-10-13T00:00:00Z' };
const sessionId = id(7), requestId = id(8);
const modeCapability = { version: 1, featureId: 'customer_idor',
  policyVersion: 'reserved-synthetic-cart-and-order-ownership-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'customer_idor' } };
const cards = [{ action: 'cart_remove', numericId: 1001, label: 'Reserved cart line' },
  { action: 'order_status', numericId: 2001, label: 'Reserved order status' }];

async function setup(t) {
  const calls = [], state = { role: 'customer', authenticated: true,
    launch: true, cards: { cards, modeCapability } };
  const runtime = {
    async prepare(...args) { calls.push(['prepare', args]); return state.cards; },
    async readCards(...args) { calls.push(['cards', args]); return state.cards; },
    async createSession(...args) { calls.push(['session', args]); return { id: sessionId }; },
    async run(input) { calls.push(['chat', input]); input.stream.send('terminal',
      { sessionId, requestId, text: 'Saved answer' }); },
    async readRequest(input) { calls.push(['read', input]); return {
      sessionId, requestId, status: 'completed', text: 'Saved answer',
      result: { action: 'cart_remove', numericId: 1001, status: 'deleted' },
      modeCapability }; },
    async readAssessment(input) { calls.push(['assessment', input]); return {
      completed: false, status: 'unconfirmed', modelEvaluated: false }; },
    async retryAssessment(input) { calls.push(['retry', input]); return {
      completed: false, status: 'ineligible', modelEvaluated: false }; },
  };
  const app = express(); app.use(express.json());
  app.use(createBoundIdorLessonRouter({ runtime,
    launches: { resolveCapability: async () => state.launch ? scope : null },
    authenticatePersona(req, res, next) {
      if (!state.authenticated) return res.status(401).json({ error: 'Authentication required' });
      req.ssUser = { id: 1000000001, role: state.role };
      req.ssPersonaSession = personaSession; next();
    } }));
  const server = app.listen(0, '127.0.0.1');
  t.after(() => new Promise(resolve => server.close(resolve)));
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}/agents/customer/idor`;
  const headers = { 'content-type': 'application/json',
    'x-dvaia-secureshop-launch': 'a'.repeat(43) };
  const post = (path, body, extra = '') => fetch(base + path + extra,
    { method: 'POST', headers, body: JSON.stringify(body) });
  const get = path => fetch(base + path, { headers });
  return { state, calls, base, headers, post, get };
}

test('explicit prepare alone provisions; GET cards and saved outcome are read-only', async t => {
  const { calls, post, get } = await setup(t);
  let response = await get('/cards');
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { cards, modeCapability });
  assert.deepEqual(calls.map(row => row[0]), ['cards']);
  response = await post('/prepare', {});
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { cards, modeCapability });
  response = await post('/session', {});
  assert.deepEqual(await response.json(), { sessionId });
  response = await get(`/operations/${sessionId}/${requestId}`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { sessionId, requestId,
    status: 'completed', text: 'Saved answer',
    result: { action: 'cart_remove', numericId: 1001, status: 'deleted' },
    modeCapability });
  response = await get(`/assessments/${sessionId}/${requestId}`);
  assert.deepEqual(await response.json(), { completed: false, status: 'unconfirmed',
    modelEvaluated: false });
  response = await post('/assessment-retry', { sessionId, requestId });
  assert.deepEqual(await response.json(), { completed: false, status: 'ineligible',
    modelEvaluated: false });
  assert.deepEqual(calls.map(row => row[0]),
    ['cards','prepare','session','read','assessment','retry']);
  for (const [, input] of calls.slice(3)) {
    assert.deepEqual(input.scope, scope);
    assert.deepEqual(input.persona, { id: 1000000001, role: 'customer' });
    assert.equal(input.personaSession, personaSession);
  }
});

test('physical chat forwards only closed selected card and bounded stream', async t => {
  const { calls, post } = await setup(t);
  const response = await post('/chat', { sessionId, requestId,
    message: 'Use the selected reserved cart line.',
    selection: { action: 'cart_remove', numericId: 1001 } });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /^text\/event-stream/);
  assert.match(await response.text(), /event: terminal/);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0][1].selection, { action: 'cart_remove', numericId: 1001 });
  assert.deepEqual(calls[0][1].scope, scope);
});

test('foreign role, stale launch and caller-supplied authority fields never reach runtime', async t => {
  const { state, calls, post, get } = await setup(t);
  for (const body of [{ sessionId, requestId, mode: 'vuln' },
    { sessionId, requestId, persona: { id: 11 } },
    { sessionId, requestId: 'bad' }])
    assert.equal((await post('/assessment-retry', body)).status, 400);
  assert.equal((await post('/prepare', {}, '?mode=vuln')).status, 400);
  assert.equal((await post('/chat', { sessionId, requestId, message: 'x',
    selection: { action: 'order_status', numericId: 2001, ownerId: 11 } })).status, 400);
  state.role = 'merchant';
  assert.equal((await get('/cards')).status, 403);
  state.role = 'customer'; state.authenticated = false;
  assert.equal((await get('/cards')).status, 401);
  state.authenticated = true; state.launch = false;
  assert.equal((await get('/cards')).status, 401);
  assert.equal(calls.length, 0);
});

test('private runtime errors and contradictory saved projections are closed', async t => {
  const { state, calls, get } = await setup(t);
  state.cards = { cards: [{ ...cards[0], birthId: id(9) }, cards[1]], modeCapability };
  let response = await get('/cards');
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Isolated lesson unavailable' });
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(calls.map(row => row[0]), ['cards']);
});
