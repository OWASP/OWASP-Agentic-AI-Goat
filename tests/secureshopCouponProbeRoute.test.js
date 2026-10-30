'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const http = require('node:http');
const express = require('express');
const { createBoundCouponProbeRouter, publicRun, publicAssessment } =
  require('../server/routes/secureshop/boundCouponProbe');

const pair = Object.freeze({ sessionId: randomUUID(), requestId: randomUUID() });
const scope = Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
  platformOwnerId: 7, platformSessionId: 8 });
const personaSession = Object.freeze({ sessionId: randomUUID(), authorityVersion: '2' });
const prefix = '/api/secureshop/customer/coupon-probe';
const launchHeader = { 'x-owasp-ai-goat-secureshop-launch': 'a'.repeat(43) };
const completed = (replayed = false) => ({ status: 'completed', ...pair,
  text: 'The exact probe was not valid.', provider: 'ollama', model: 'local-model',
  stopReason: 'end_turn', probes: [{ code: '', valid: false, discount_percent: 0 }], replayed });

async function fixture(t, overrides = {}) {
  const calls = [];
  const application = {
    async createSession(input) { calls.push(['session', input]); return { sessionId: pair.sessionId }; },
    async run(input) { calls.push(['run', input]); return completed(); },
    async read(input) { calls.push(['read', input]); return completed(true); },
    ...overrides.application,
  };
  const assessment = {
    async runAttempt(input) { calls.push(['assess', input]); return { completed: true,
      judgment: { verdict: 'pass', evaluationId: randomUUID(), canRetry: false,
        privatePacket: 'hidden' }, replayed: false }; },
    async readOutcome(input) { calls.push(['assessment', input]);
      return { completed: false, status: 'unconfirmed', modelEvaluated: false }; },
    ...overrides.assessment,
  };
  const app = express();
  app.use(express.json());
  app.use(prefix.replace('/customer/coupon-probe', ''), createBoundCouponProbeRouter({
    launches: { resolveCapability: async () => scope },
    authenticatePersona(req, _res, next) {
      req.ssUser = { id: 17, role: overrides.role || 'customer' };
      req.ssPersonaSession = personaSession;
      next();
    }, application, assessment,
  }));
  const server = await new Promise(resolve => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  t.after(() => new Promise(resolve => {
    server.closeAllConnections(); server.close(resolve);
  }));
  return { calls, base: `http://127.0.0.1:${server.address().port}${prefix}`,
    port: server.address().port };
}

const post = (url, body, headers = {}) => fetch(url, { method: 'POST',
  headers: { ...launchHeader, 'content-type': 'application/json', ...headers },
  body: JSON.stringify(body) });
const get = (url, headers = {}) => fetch(url, { headers: { ...launchHeader, ...headers } });

test('customer routes project closed DTOs and readiness never starts a session', async t => {
  const f = await fixture(t);
  const capabilities = await get(`${f.base}/capabilities`);
  assert.equal(capabilities.status, 200);
  assert.equal(capabilities.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await capabilities.json(), { ready: true });
  assert.equal(f.calls.length, 0, 'readiness never creates a session or dispatches a model');
  const session = await post(`${f.base}/session`, {});
  assert.equal(session.status, 200);
  assert.deepEqual(await session.json(), { sessionId: pair.sessionId });
  assert.equal(session.headers.get('cache-control'), 'no-store');

  const run = await post(`${f.base}/run`, { ...pair, message: 'Check this exact code' });
  assert.equal(run.status, 200);
  assert.deepEqual(await run.json(), completed());
  assert.equal(f.calls[1][1].message, 'Check this exact code');
  assert.deepEqual({ ...f.calls[1][1], signal: undefined }, { scope,
    persona: { id: 17, role: 'customer' }, personaSession, ...pair,
    message: 'Check this exact code', signal: undefined });
  assert.ok(f.calls[1][1].signal instanceof AbortSignal);

  const saved = await get(`${f.base}/operations/${pair.sessionId.toUpperCase()}/${pair.requestId.toUpperCase()}`);
  assert.equal(saved.status, 200);
  assert.deepEqual(await saved.json(), completed(true));
  assert.equal(f.calls[2][0], 'read');
  assert.deepEqual({ ...f.calls[2][1], signal: undefined }, { scope,
    persona: { id: 17, role: 'customer' }, personaSession, ...pair, signal: undefined });

  const assessed = await post(`${f.base}/assess`, pair);
  assert.equal(assessed.status, 200);
  const publicResult = await assessed.json();
  assert.deepEqual(Object.keys(publicResult), ['completed', 'judgment', 'replayed']);
  assert.deepEqual(Object.keys(publicResult.judgment), ['verdict', 'evaluationId', 'canRetry']);
  assert.equal(publicResult.completed, true);
  const priorCalls = f.calls.length;
  const assessment = await get(`${f.base}/assess/${pair.sessionId}/${pair.requestId}`);
  assert.equal(assessment.status, 200);
  assert.deepEqual(await assessment.json(), { completed: false, status: 'unconfirmed', modelEvaluated: false });
  assert.equal(f.calls.length, priorCalls + 1);
  assert.equal(f.calls.at(-1)[0], 'assessment');
});

test('closed request bodies, query and raw GET body reject before application calls', async t => {
  const f = await fixture(t);
  for (const [path, body] of [
    ['/session', { targetId: randomUUID() }],
    ['/run', { ...pair, message: 'probe', couponBank: ['private'] }],
    ['/run', { ...pair, message: '' }],
    ['/assess', { ...pair, targetId: randomUUID() }],
  ]) {
    const response = await post(`${f.base}${path}`, body);
    assert.equal(response.status, 400); await response.text();
  }
  assert.equal((await get(`${f.base}/operations/${pair.sessionId}/${pair.requestId}?mode=vuln`)).status, 400);
  assert.equal((await get(`${f.base}/capabilities?target=foreign`)).status, 400);
  assert.equal((await get(`${f.base}/assess/${pair.sessionId}/bad`)).status, 400);
  assert.equal(f.calls.length, 0);

  const raw = await new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: f.port, method: 'GET',
      path: `${prefix}/operations/${pair.sessionId}/${pair.requestId}`,
      headers: { ...launchHeader, 'content-length': '2' } }, res => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.end('{}');
  });
  assert.equal(raw, 400);
  const capabilityBody = await new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: f.port, method: 'GET',
      path: `${prefix}/capabilities`,
      headers: { ...launchHeader, 'content-length': '2' } }, res => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.end('{}');
  });
  assert.equal(capabilityBody, 400);
  assert.equal(f.calls.length, 0);
});

test('foreign role, duplicate launch header, conflicts and private failure stay isolated', async t => {
  const foreign = await fixture(t, { role: 'merchant' });
  const denied = await post(`${foreign.base}/session`, {});
  assert.equal(denied.status, 403);
  assert.equal((await get(`${foreign.base}/capabilities`)).status, 403);
  assert.equal(foreign.calls.length, 0);

  const missingLaunch = await fetch(`${foreign.base}/session`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(missingLaunch.status, 401);
  assert.equal((await fetch(`${foreign.base}/capabilities`)).status, 401);
  assert.equal(foreign.calls.length, 0);

  const f = await fixture(t, { application: {
    async run() { throw Object.assign(new Error('private SQL and coupon'),
      { code: 'TURN_REQUEST_CONFLICT' }); },
    async read() { throw Object.assign(new Error('private target'),
      { code: 'COUPON_PROBE_UNAVAILABLE' }); },
  } });
  const conflict = await post(`${f.base}/run`, { ...pair, message: 'probe' });
  assert.equal(conflict.status, 409);
  assert.deepEqual(await conflict.json(), { error: 'Coupon probe request conflicts with its original admission' });
  const unavailable = await get(`${f.base}/operations/${pair.sessionId}/${pair.requestId}`);
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), { error: 'Coupon probe unavailable' });

  const duplicate = await new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: f.port, method: 'POST',
      path: `${prefix}/session`, headers: [
        'X-OWASP-AI-GOAT-SecureShop-Launch', 'a'.repeat(43),
        'x-owasp-ai-goat-secureshop-launch', 'a'.repeat(43),
        'Content-Type', 'application/json', 'Content-Length', '2',
      ] }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject); req.end('{}');
  });
  assert.equal(duplicate, 400);
});

test('public projections reject malformed state and drop private judgment fields', () => {
  assert.throws(() => publicRun({ ...completed(), privateTarget: 'hidden' }, pair));
  assert.throws(() => publicRun({ ...completed(), probes: new Array(1) }, pair));
  assert.throws(() => publicRun({ ...completed(), probes: [{ code: 'x', valid: false,
    discount_percent: 10 }] }, pair));
  assert.throws(() => publicRun({ ...completed(), status: 'uncertain' }, pair, true));
  const assessment = { completed: false, replayed: true,
    judgment: { verdict: 'fail', evaluationId: randomUUID(), canRetry: false,
      packet: 'private' } };
  assert.deepEqual(publicAssessment(assessment), { completed: false, replayed: true,
    judgment: { verdict: 'fail', evaluationId: assessment.judgment.evaluationId, canRetry: false } });
  assert.throws(() => publicAssessment({ ...assessment, completed: true }));
});

test('guided protocol is an explicit closed optional run selector and raw stays unchanged',async t=>{
 const f=await fixture(t),body={...pair,message:'Investigate this character.'};
 for(const protocol of ['guided-boolean-v1','guided-boolean-v2']){
  const guided=await post(`${f.base}/run`,{...body,protocol});
  assert.equal(guided.status,200);assert.equal(f.calls.at(-1)[1].protocol,protocol);
 }
 const raw=await post(`${f.base}/run`,body);assert.equal(raw.status,200);assert.equal(Object.hasOwn(f.calls.at(-1)[1],'protocol'),false);
 for(const protocol of [null,'raw','guided-boolean-v3',1,{},true])assert.equal((await post(`${f.base}/run`,{...body,protocol})).status,400);
 assert.equal(f.calls.length,3);
});
