'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { EventEmitter } = require('node:events');
const express = require('express');
const { createBoundProductSummaryAssessmentRouter, publicProductSummaryAssessment, sourceIds } =
  require('../server/routes/secureshop/boundProductSummaryAssessment');

const events = () => { const emitter = new EventEmitter(); return { once: emitter.once.bind(emitter),
  removeListener: emitter.removeListener.bind(emitter), emit: emitter.emit.bind(emitter),
  listenerCount: emitter.listenerCount.bind(emitter) }; };
const response = () => ({ ...events(), statusCode: 0, headers: {}, status(value) { this.statusCode = value; return this; },
  set(key, value) { this.headers[key] = value; return this; }, setHeader(key, value) { this.headers[key] = value; },
  json(value) { this.body = value; return this; } });
const ids = Object.freeze({ sessionId: randomUUID(), requestId: randomUUID() });

function fixture(assessment) {
  const calls = [];
  const service = assessment || Object.fromEntries(['runAttempt', 'readOutcome'].map(method => [method, async input => {
    calls.push({ method, input });
    return { completed: false, status: 'unconfirmed', modelEvaluated: false };
  }]));
  const router = createBoundProductSummaryAssessmentRouter({ launches: { resolveCapability: async () => ({}) },
    authenticatePersona: (_req, _res, next) => next(), assessment: service });
  const route = method => router.stack.find(layer => layer.route?.methods[method]).route.stack;
  const req = { ...events(), body: ids, params: { ...ids }, query: {}, is: value => value === 'application/json',
    ssLaunch: { launchId: randomUUID() }, ssUser: { id: 17, role: 'customer' },
    ssPersonaSession: { sessionId: randomUUID(), authorityVersion: '1' } };
  return { calls, req, post: route('post'), get: route('get') };
}

test('product summary assessment admits only exact protected IDs and GET is saved read-only', async () => {
  const f = fixture(); const res = response();
  await f.post.at(-1).handle(f.req, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(f.calls[0].input, { scope: f.req.ssLaunch, persona: { id: 17, role: 'customer' },
    personaSession: f.req.ssPersonaSession, ...ids, signal: f.calls[0].input.signal });
  assert.equal(f.calls[0].method, 'runAttempt');
  await f.get.at(-1).handle({ ...f.req, body: undefined }, res);
  assert.equal(f.calls[1].method, 'readOutcome');
  assert.equal(res.headers['Cache-Control'], 'no-store');
  for (const body of [{ ...ids, productId: 7 }, { sessionId: ids.sessionId }, { ...ids, proof: {} }]) {
    await f.post.at(-1).handle({ ...f.req, body }, res);
    assert.equal(res.statusCode, 400);
  }
  await f.get.at(-1).handle({ ...f.req, body: undefined, query: { mode: 'vuln' } }, res);
  assert.equal(res.statusCode, 400);
  await f.get.at(-1).handle(f.req, res);
  assert.equal(res.statusCode, 400);
  assert.equal(f.calls.length, 2);
});

test('product summary assessment accepts null-prototype Express GET params and keeps the saved route ID-only', async () => {
  const f = fixture(); const app = express(); let paramsPrototype;
  app.get('/sessions/:sessionId/requests/:requestId/product-summary/assessment', (req, res) => {
    paramsPrototype = Object.getPrototypeOf(req.params);
    Object.assign(req, { ssLaunch: f.req.ssLaunch, ssUser: f.req.ssUser, ssPersonaSession: f.req.ssPersonaSession });
    return f.get.at(-1).handle(req, res);
  });
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  try {
    const url = `http://127.0.0.1:${server.address().port}/sessions/${ids.sessionId}/requests/${ids.requestId}/product-summary/assessment`;
    const result = await fetch(url);
    assert.equal(paramsPrototype, null); assert.equal(result.status, 200);
    assert.deepEqual(await result.json(), { completed: false, status: 'unconfirmed', modelEvaluated: false });
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0].method, 'readOutcome');
    assert.equal((await fetch(`${url}?step=1`)).status, 400);
    assert.equal(f.calls.length, 1);
  } finally { await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
});

test('product summary assessment rejects malformed path IDs, foreign roles, and duplicate launch routing', () => {
  const f = fixture(); const res = response(); let next;
  f.post[0].handle({ rawHeaders: ['X-DVAIA-SecureShop-Launch', 'a', 'X-DVAIA-SecureShop-Launch', 'b'] }, res, value => { next = value; });
  assert.equal(next, 'route');
  for (const role of ['admin', 'merchant', undefined]) {
    f.post.at(-2).handle({ ...f.req, ssUser: { id: 17, role } }, res, () => assert.fail('continued'));
    assert.equal(res.statusCode, 403);
  }
  for (const value of [{ ...ids, extra: 'x' }, { ...ids, requestId: 'not-a-uuid' }]) assert.equal(sourceIds(value), null);
  const params = Object.assign(Object.create(null), ids);
  assert.deepEqual(sourceIds(params, true), ids);
  params.extra = 'x'; assert.equal(sourceIds(params, true), null);
});

test('product summary assessment projects only closed outcomes and sanitizes failures', async () => {
  const judgment = { evaluationId: randomUUID(), verdict: 'pass', canRetry: false, packet: 'private' };
  assert.deepEqual(publicProductSummaryAssessment({ completed: true, replayed: false, judgment }),
    { completed: true, replayed: false, judgment: { evaluationId: judgment.evaluationId, verdict: 'pass', canRetry: false } });
  assert.throws(() => publicProductSummaryAssessment({ completed: true, replayed: false,
    judgment: { ...judgment, verdict: 'fail' } }));
  const f = fixture({ runAttempt: async () => { throw Error('private SQL'); },
    readOutcome: async () => { throw Object.assign(Error('private current'), { code: 'CONVERSATION_UNAVAILABLE' }); } });
  const res = response();
  await f.post.at(-1).handle(f.req, res);
  assert.equal(res.statusCode, 503); assert.deepEqual(res.body, { error: 'Product summary assessment unavailable' });
  await f.get.at(-1).handle({ ...f.req, body: undefined }, res);
  assert.equal(res.statusCode, 401); assert.deepEqual(res.body, { error: 'Shop session unavailable' });
});

test('product summary assessment aborts one in-flight operation on disconnect', { timeout: 5000 }, async t => {
  let enter; let release; let signal;
  const entered = new Promise(resolve => { enter = resolve; });
  const work = new Promise(resolve => { release = resolve; });
  const f = fixture({ readOutcome: async () => {}, runAttempt: async input => {
    signal = input.signal; enter(); await work;
    return { completed: false, status: 'unconfirmed', modelEvaluated: false };
  } });
  const res = response(); const pending = f.post.at(-1).handle(f.req, res);
  await entered; res.emit('close'); assert.equal(signal.aborted, true); release(); await pending;
  assert.equal(res.body, undefined); assert.equal(f.req.listenerCount('aborted'), 0); assert.equal(res.listenerCount('close'), 0);

  void t;
});
