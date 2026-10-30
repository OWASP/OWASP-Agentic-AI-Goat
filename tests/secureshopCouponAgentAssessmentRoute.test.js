'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const express = require('express');
const { createBoundCouponAgentAssessmentRouter, publicAssessment } =
  require('../server/routes/secureshop/boundCouponAgentAssessment');

const ids = { sessionId: randomUUID(), requestId: randomUUID(),
  proposalId: randomUUID() };
const scope = { launchId: randomUUID(), scenarioId: randomUUID(),
  generation: 1, platformOwnerId: 8, platformSessionId: 9 };
const persona = { id: 1000000001, role: 'customer' };
const personaSession = { sessionId: randomUUID(), authorityVersion: '2' };
const reply = () => ({ statusCode: null, body: null, headers: {},
  status(value) { this.statusCode = value; return this; },
  set(key, value) { this.headers[key] = value; return this; },
  setHeader(key, value) { this.headers[key] = value; return this; },
  json(value) { this.body = value; return this; } });

test('GET remains read-only and POST retries only the exact protected original IDs', async () => {
  const calls = [], assessment = {
    async readOutcome(input) { calls.push(['read', input]);
      return { completed: false, status: 'unconfirmed', modelEvaluated: false }; },
    async runAttempt(input) { calls.push(['retry', input]);
      return { completed: true, replayed: true,
        judgment: { verdict: 'pass', evaluationId: randomUUID(), canRetry: false,
          privatePacket: 'never public' } }; },
  };
  const router = createBoundCouponAgentAssessmentRouter({
    launches: { resolveCapability: async () => scope },
    authenticatePersona: (_req, _res, next) => next(), assessment });
  const get = router.stack.find(layer => layer.route?.path ===
    '/agents/customer/coupons/assessment/:sessionId/:requestId/:proposalId')
    .route.stack.at(-1).handle;
  const post = router.stack.find(layer => layer.route?.path ===
    '/agents/customer/coupons/assessment-retry').route.stack.at(-1).handle;
  const req = { params: ids, body: ids, query: {}, is: () => true,
    ssLaunch: scope, boundPersona: persona, ssPersonaSession: personaSession };
  const saved = reply();
  await get(req, saved);
  assert.equal(saved.statusCode, 200);
  assert.deepEqual(saved.body,
    { completed: false, status: 'unconfirmed', modelEvaluated: false });
  assert.equal(saved.headers['Cache-Control'], 'no-store');
  assert.equal(calls[0][0], 'read');
  assert.deepEqual({ ...calls[0][1], signal: undefined },
    { scope, persona, personaSession, ...ids, signal: undefined });
  const retried = reply();
  await post(req, retried);
  assert.equal(retried.statusCode, 200);
  assert.deepEqual(Object.keys(retried.body), ['completed', 'judgment', 'replayed']);
  assert.deepEqual(Object.keys(retried.body.judgment),
    ['verdict', 'evaluationId', 'canRetry']);
  assert.equal(calls[1][0], 'retry');
  assert.deepEqual({ ...calls[1][1], signal: undefined },
    { scope, persona, personaSession, ...ids, signal: undefined });
  req.body = { ...ids, code: 'UNTRUSTED' };
  await post(req, retried);
  assert.equal(retried.statusCode, 400);
  assert.equal(calls.length, 2);
  req.params = ids; req.query = { code: 'UNTRUSTED' };
  await get(req, saved);
  assert.equal(saved.statusCode, 400);
  assert.equal(calls.length, 2);
  req.query = {};
  req.body = Object.assign(Object.create(null), ids);
  await post(req, retried);
  assert.equal(retried.statusCode, 400, 'POST retains its strict plain-object contract');
  req.params = Object.assign(Object.create(null), ids, { extra: 'rejected' });
  await get(req, saved);
  assert.equal(saved.statusCode, 400, 'copying path params must not drop unknown keys');
  req.params = Object.assign(Object.create(null), ids, { proposalId: 'invalid' });
  await get(req, saved);
  assert.equal(saved.statusCode, 400);
  assert.equal(calls.length, 2);
});

test('real Express GET accepts its null-prototype path IDs without a retry or effect', async t => {
  const calls = [];
  let sawNullPrototype = false;
  const app = express();
  app.use(express.json());
  app.use('/api/secureshop', createBoundCouponAgentAssessmentRouter({
    launches: { resolveCapability: async () => scope },
    authenticatePersona(req, _res, next) {
      sawNullPrototype = Object.getPrototypeOf(req.params) === null;
      req.ssUser = persona;
      req.ssPersonaSession = personaSession;
      next();
    },
    assessment: {
      async readOutcome(input) { calls.push(input);
        return { completed: false, status: 'unconfirmed', modelEvaluated: false }; },
      async runAttempt() { assert.fail('Saved GET must never retry assessment'); },
    },
  }));
  const server = await new Promise(resolve => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const base = `http://127.0.0.1:${server.address().port}/api/secureshop/agents/customer/coupons/assessment`;
  const headers = { 'x-owasp-ai-goat-secureshop-launch': 'd'.repeat(43) };
  const path = `${base}/${ids.sessionId.toUpperCase()}/${ids.requestId.toUpperCase()}/${ids.proposalId.toUpperCase()}`;
  const response = await fetch(path, { headers });
  assert.equal(sawNullPrototype, true);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await response.json(), { completed: false, status: 'unconfirmed', modelEvaluated: false });
  assert.equal(calls.length, 1);
  assert.ok(calls[0].signal instanceof AbortSignal);
  assert.deepEqual({ ...calls[0], signal: undefined },
    { scope, persona, personaSession, ...ids, signal: undefined });
  for (const url of [`${path}?code=unexpected`, `${base}/${ids.sessionId}/${ids.requestId}/invalid`]) {
    const denied = await fetch(url, { headers });
    assert.equal(denied.status, 400);
    await denied.text();
  }
  assert.equal(calls.length, 1);
});

test('route never leaks private packet or treats malformed judgment as completion', async () => {
  const evaluationId = randomUUID();
  assert.deepEqual(publicAssessment({ completed: false, replayed: true,
    judgment: { verdict: 'unavailable', evaluationId, canRetry: true,
      packet: 'PRIVATE' } }), { completed: false, replayed: true,
    judgment: { verdict: 'unavailable', evaluationId, canRetry: true } });
  assert.throws(() => publicAssessment({ completed: true, replayed: false,
    judgment: { verdict: 'made_up', evaluationId, canRetry: false } }));
  assert.throws(() => publicAssessment({ completed: true, replayed: false,
    judgment: { verdict: 'pass', evaluationId: 'bad', canRetry: false } }));
  const router = createBoundCouponAgentAssessmentRouter({
    launches: { resolveCapability: async () => scope },
    authenticatePersona: (_req, _res, next) => next(),
    assessment: { runAttempt: async () => { throw Object.assign(
      new Error('private packet'), { code: 'COUPON_AGENT_ASSESSMENT_UNAVAILABLE' }); },
      readOutcome: async () => { throw Object.assign(
        new Error('private SQL receipt'), { code: 'SHOP_SCENE_STALE' }); } },
  });
  const post = router.stack.find(layer => layer.route?.path ===
    '/agents/customer/coupons/assessment-retry').route.stack.at(-1).handle;
  const get = router.stack.find(layer => layer.route?.path ===
    '/agents/customer/coupons/assessment/:sessionId/:requestId/:proposalId')
    .route.stack.at(-1).handle;
  const req = { params: ids, body: ids, query: {}, is: () => true,
    ssLaunch: scope, boundPersona: persona, ssPersonaSession: personaSession };
  const res = reply();
  await post(req, res);
  assert.equal(res.statusCode, 503);
  assert.deepEqual(res.body, { error: 'Coupon assessment unavailable' });
  await get(req, res);
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: 'Shop session unavailable' });
});
