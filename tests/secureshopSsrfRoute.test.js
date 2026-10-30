'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createBoundSsrfRouter } = require('../server/routes/secureshop/boundSsrf');
const { markSecureShopFailure } = require('../server/services/secureshopFailureDiagnostic');
const scope = { launchId: '10000000-0000-4000-8000-000000000001', scenarioId: '20000000-0000-4000-8000-000000000001',
  platformOwnerId: 7, platformSessionId: 8, generation: 1 };
const requestId = '30000000-0000-4000-8000-000000000001', capability = 'a'.repeat(43);
async function setup(t) {
  const calls = [], htmlCalls = [], diagnostics = []; let enabled = true, failure;
  let result = { response: 'Observed fixture', replayed: false };
  const feature = { ready: true, availability: { async read() { return { registered: true, visible: true, enabled }; } },
    htmlAssessment: Object.fromEntries(['readRun','readOutcome','runAttempt'].map(method=>[method,async input=>{htmlCalls.push({method,input});if(failure)throw failure;return result;}])),
    application: { async run(input) { calls.push(input); if (failure) throw failure; return result; } } };
  const app = express(); app.use(express.json());
  app.use((req, _res, next) => { req.requestId = req.get('x-request-id'); next(); });
  app.use(createBoundSsrfRouter({ launches: { async resolveCapability(value) { return value === capability ? scope : null; } },
    authenticatePersona(req, res, next) {
      if (req.get('authorization') !== 'Bearer shop-fixture') return res.status(401).end();
      req.ssUser = { id: 11, role: 'customer' }; next();
    }, feature, logger: { error(event, metadata) { diagnostics.push([event, metadata]); } } }));
  app.use((_req, res) => res.status(404).end());
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const headers = { 'content-type': 'application/json', 'x-owasp-ai-goat-secureshop-launch': capability,
    'x-request-id': '40000000-0000-4000-8000-000000000001', authorization: 'Bearer shop-fixture' };
  return { calls, htmlCalls, diagnostics, hide() { enabled = false; }, fail(value) { failure = value; }, respond(value) { result = value; },
    get: (url, supplied = headers) => fetch(base + url, { headers: supplied }),
    post: body => fetch(base + '/v2/controlled-ssrf/run', { method: 'POST', headers, body: JSON.stringify(body) }),
    htmlPost: (suffix,body) => fetch(base+'/v2/controlled-ssrf/html/'+suffix,{method:'POST',headers,body:JSON.stringify(body)}) };
}

test('SSRF route binds server launch/persona and exposes only two controlled resource selections', async t => {
  const f = await setup(t);
  for (const resource of ['public-policy', 'private-policy']) {
    const response = await f.post({ resource, request_id: requestId }); assert.equal(response.status, 200);
    const input = f.calls.at(-1); assert.deepEqual(input.scope, scope); assert.deepEqual(input.persona, { id: 11, role: 'customer' });
    assert.equal(input.resourceKind, resource); assert.equal(input.requestId, requestId); assert.ok(input.signal instanceof AbortSignal);
  }
  const invalid = [
    { resource: 'http://localhost/private', request_id: requestId },
    { resource: 'private-policy', request_id: [requestId] },
    { resource: 'private-policy', request_id: requestId, platformOwnerId: 999 },
    { resource: 'private-policy', request_id: requestId, url: 'http://example.invalid' },
    { resource: 'private-policy' }, [], null,
  ];
  for (const body of invalid) assert.equal((await f.post(body)).status, 400);
  assert.equal(f.calls.length, 2, 'invalid input never reaches target admission');
});

test('SSRF route requires both identities, projects readiness and does not leak internal errors', async t => {
  const f = await setup(t);
  assert.equal((await f.get('/v2/controlled-ssrf/readiness', {})).status, 401);
  assert.equal((await f.get('/v2/controlled-ssrf/readiness', { 'x-owasp-ai-goat-secureshop-launch': capability })).status, 401);
  assert.deepEqual(await (await f.get('/v2/controlled-ssrf/readiness')).json(), { ready: true });
  f.hide(); assert.deepEqual(await (await f.get('/v2/controlled-ssrf/readiness')).json(), { ready: false });
  const secret = 'private URL, bearer, nonce, stack and internal connection data';
  const failure = Object.assign(new Error(secret), { code: 'BOUND_SSRF_UNAVAILABLE', name: secret });
  markSecureShopFailure(failure, 'external_observation', 'external_tool_error'); f.fail(failure);
  const unavailable = await f.post({ resource: 'private-policy', request_id: requestId });
  assert.equal(unavailable.status, 503); assert.deepEqual(await unavailable.json(), { error: 'Controlled SSRF exercise unavailable' });
  assert.deepEqual(f.diagnostics, [['secureshop_controlled_ssrf_failure', {
    component: 'secureshop_controlled_ssrf', requestId: '40000000-0000-4000-8000-000000000001',
    resourceKind: 'private-policy', phase: 'external_observation', failureCategory: 'external_tool_error',
    errorCode: 'BOUND_SSRF_UNAVAILABLE', errorName: 'UnknownError',
  }]]);
  assert.equal(JSON.stringify(f.diagnostics).includes(secret), false);
  f.fail(Object.assign(new Error(secret), { code: secret }));
  const unclassified = await f.post({ resource: 'private-policy', request_id: requestId });
  assert.equal(unclassified.status, 503); await unclassified.arrayBuffer();
  assert.deepEqual(f.diagnostics.at(-1)[1], {
    component: 'secureshop_controlled_ssrf', requestId: '40000000-0000-4000-8000-000000000001',
    resourceKind: 'private-policy', phase: 'route', failureCategory: 'unclassified',
    errorCode: 'UNCLASSIFIED', errorName: 'Error',
  });
  assert.equal(JSON.stringify(f.diagnostics).includes(secret), false);
  f.fail(Object.assign(new Error('stale private scope'), { code: 'STALE_LAUNCH' }));
  const stale = await f.post({ resource: 'private-policy', request_id: requestId });
  assert.equal(stale.status, 401);
  assert.equal(stale.headers.get('x-owasp-ai-goat-secureshop-launch-state'), 'unavailable');
  f.fail(Object.assign(new Error('foreign owner'), { code: 'OWNER_MISMATCH' }));
  const foreign = await f.post({ resource: 'private-policy', request_id: requestId });
  assert.equal(foreign.status, 401);
  assert.equal(foreign.headers.get('x-owasp-ai-goat-secureshop-launch-state'), null);
  assert.equal(f.diagnostics.length, 2, 'ordinary launch failures are not reported as SSRF execution failures');
  f.fail(null); f.respond({ resourceKind:'private-policy', replayed:false, stopReason:'error',
    response:'[AI provider unavailable]' });
  const providerError = await f.post({ resource: 'private-policy', request_id: requestId });
  assert.equal(providerError.status, 200, 'a provider error terminal remains a normal HTTP result');
  assert.equal(f.diagnostics.length, 2);
  f.respond({ resourceKind:'private-policy', replayed:false, stopReason:'end_turn', response:'I cannot do that.' });
  const refusal = await f.post({ resource: 'private-policy', request_id: requestId });
  assert.equal(refusal.status, 200, 'a settled model response remains a normal HTTP result');
  assert.equal((await f.get('/unrelated', {})).status, 404, 'SSRF middleware does not intercept unrelated routes');
});


test('V27 closed routes preserve original source and separate saved reads from execution', async t => {
  const f=await setup(t), sessionId='50000000-0000-4000-8000-000000000001';
  const html='<p>Original policy</p>';
  assert.deepEqual(await(await f.get('/v2/controlled-ssrf/html/readiness')).json(),{ready:true});
  assert.equal((await f.htmlPost('run',{request_id:requestId,policy_html:html})).status,200);
  assert.equal(f.calls.length,1);assert.equal(f.calls[0].policyHtml,html);assert.equal(f.calls[0].resourceKind,'html-policy');
  assert.deepEqual(f.calls[0].scope,scope);assert.deepEqual(f.calls[0].persona,{id:11,role:'customer'});
  for(const body of [{request_id:requestId,policy_html:html,url:'http://foreign.invalid'},
    {request_id:requestId,policy_html:html,session_id:sessionId},{request_id:requestId,policy_html:'a'.repeat(8193)},
    {request_id:requestId,policy_html:''},{request_id:requestId,policy_html:'x\u0000y'}])
    assert.equal((await f.htmlPost('run',body)).status,400);
  assert.equal((await f.htmlPost('assess',{session_id:sessionId,request_id:requestId})).status,200);
  assert.equal((await f.htmlPost('assess',{session_id:sessionId,request_id:requestId,response:'authored'})).status,400);
  assert.equal((await f.get('/v2/controlled-ssrf/html/run/'+requestId)).status,200);
  assert.equal((await f.get('/v2/controlled-ssrf/html/assessment/'+sessionId+'/'+requestId)).status,200);
  assert.deepEqual(f.htmlCalls.map(v=>v.method),['runAttempt','readRun','readOutcome']);
  for(const {input} of f.htmlCalls){assert.deepEqual(input.scope,scope);assert.equal(input.requestId,requestId);assert.ok(input.signal instanceof AbortSignal);}
  assert.equal(f.calls.length,1,'saved GET never invokes actor application');
  assert.equal((await f.get('/v2/controlled-ssrf/html/run/'+requestId+'?policy_html=replace')).status,400);
  assert.equal((await f.get('/v2/controlled-ssrf/html/run/'+requestId,{})).status,401);
  f.fail(new Error('private original receipt detail'));
  const unavailable=await f.get('/v2/controlled-ssrf/html/run/'+requestId);
  assert.equal(unavailable.status,503);assert.deepEqual(await unavailable.json(),{error:'Controlled SSRF exercise unavailable'});
  assert.equal(f.calls.length,1);
  f.hide();assert.deepEqual(await(await f.get('/v2/controlled-ssrf/html/readiness')).json(),{ready:false});
});
