'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createBoundBrowserRouter } = require('../server/routes/secureshop/boundBrowser');

const bearer = 'b'.repeat(43);
const requestId = '30000000-0000-4000-8000-000000000001';
const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 2,
  platformOwnerId: 7, platformSessionId: 8 });
async function fixture(t, personaSession) {
  const calls = []; const lifecycle = []; let legacy = 0;
  const router = createBoundBrowserRouter({ launches: { async resolveCapability(value) {
    return value === bearer ? scope : null;
  } }, authenticatePersona(req, res, next) {
    const match = /^Bearer (customer|merchant)-(\d+)$/.exec(req.get('authorization') || '');
    if (!match) return res.status(401).json({ error: 'Shop authentication required' });
    req.ssUser = { role: match[1], id: Number(match[2]) }; if(personaSession)req.ssPersonaSession=personaSession; next();
  }, assessment: { async runAttempt(input) { calls.push(input); return { completed: true,
    judgment: { verdict: 'pass' }, browser: { executed: true }, replayed: false }; } },
  observeLifecycle: event => lifecycle.push(event) });
  const app = express(); app.use(express.json()); app.use('/api/secureshop', router);
  app.use('/api/secureshop', (_req, res) => { legacy++; res.json({ legacy: true }); });
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { base: `http://127.0.0.1:${server.address().port}/api/secureshop`, calls, lifecycle,
    legacy: () => legacy };
}
const headers = (role = 'customer', launch = bearer) => ({ authorization: `Bearer ${role}-9`,
  'x-owasp-ai-goat-secureshop-launch': launch, 'content-type': 'application/json' });

test('bound browser route accepts only exact owner-authenticated source identifiers', async t => {
  const f = await fixture(t);
  const response = await fetch(`${f.base}/products/7/reviews/41/browser-attempt`, {
    method: 'POST', headers: headers(), body: JSON.stringify({ request_id: requestId }) });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).completed, true);
  assert.equal(f.calls.length, 1);
  assert.deepEqual({ ...f.calls[0], signal: undefined }, { scope, persona: { id: 9, role: 'customer' },
    requestId, productId: 7, reviewId: 41, signal: undefined });
  assert.equal(f.calls[0].signal instanceof AbortSignal, true);
  assert.deepEqual(f.lifecycle, [
    { type: 'assessment_start' },
    { type: 'assessment_settled', outcome: 'fulfilled' },
  ]);
  assert.equal(f.legacy(), 0);
});

test('missing launch falls through while present invalid authority and invalid requests never do', async t => {
  const f = await fixture(t); const url = `${f.base}/products/7/reviews/41/browser-attempt`;
  const missing = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ request_id: requestId }) });
  assert.equal(missing.status, 200); assert.equal((await missing.json()).legacy, true);
  for (const response of [
    await fetch(url, { method: 'POST', headers: headers('customer', 'x'.repeat(43)),
      body: JSON.stringify({ request_id: requestId }) }),
    await fetch(url, { method: 'POST', headers: headers('merchant'),
      body: JSON.stringify({ request_id: requestId }) }),
    await fetch(url, { method: 'POST', headers: headers(),
      body: JSON.stringify({ request_id: requestId, html: '<img onerror=alert(1)>' }) }),
    await fetch(`${f.base}/products/7.5/reviews/41/browser-attempt`, { method: 'POST', headers: headers(),
      body: JSON.stringify({ request_id: requestId }) }),
  ]) assert.notEqual(response.status, 200);
  assert.equal(f.calls.length, 0); assert.equal(f.legacy(), 1);
});

test('browser route forwards only middleware credential session',async t=>{const credential={sessionId:'70000000-0000-4000-8000-000000000001',authorityVersion:'2',private:'omit'};const f=await fixture(t,credential);const url=`${f.base}/products/7/reviews/41/browser-attempt`;const good=await fetch(url,{method:'POST',headers:headers(),body:JSON.stringify({request_id:requestId})});assert.equal(good.status,200);assert.deepEqual(f.calls[0].personaSession,{sessionId:credential.sessionId,authorityVersion:'2'});const bad=await fetch(url,{method:'POST',headers:headers(),body:JSON.stringify({request_id:requestId,personaSession:{sessionId:'forged'}})});assert.equal(bad.status,400);assert.equal(f.calls.length,1);});
