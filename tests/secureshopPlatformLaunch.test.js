'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createApplicationCors } = require('../server/middleware/applicationCors');
const { createSecureShopLaunchRouter } = require('../server/routes/secureshopPlatformLaunch');

const TRUSTED_ORIGIN = 'https://workshop.example';
const PLATFORM_TOKEN = 'platform-test-token';
const OLD_BEARER = 'o'.repeat(43);
const NEW_BEARER = 'n'.repeat(43);
const LAUNCH_ID = '11111111-1111-4111-8111-111111111111';
const EXPIRES_AT = '2026-09-13T20:30:00.000Z';
const BINDING = Object.freeze({
  launchId: LAUNCH_ID,
  platformSessionId: 19,
  platformOwnerId: 7,
  scenarioId: '22222222-2222-4222-8222-222222222222',
  generation: 3,
  credentialVersion: 5,
  status: 'active',
  expiresAt: EXPIRES_AT,
});

function codedError(code, message) {
  return Object.assign(new Error(message), { code });
}

async function fixture(t, options = {}) {
  const calls = [];
  const audits = [];
  let authCalls = 0;
  const repository = {
    async readActiveMetadata(scope) { calls.push(['metadata', scope]); return BINDING; },
    async issueOrRenew(args) { calls.push(['issueOrRenew', args]); return { binding: BINDING, bearer: NEW_BEARER }; },
    async recoverCredential(args) { calls.push(['recoverCredential', args]); return { binding: BINDING, bearer: NEW_BEARER }; },
    async revoke(args) { calls.push(['revoke', args]); return { revoked: true, generation: BINDING.generation }; },
    ...options.repository,
  };
  const authenticateToken = options.authenticateToken || ((req, res, next) => {
    authCalls += 1;
    if (req.get('authorization') !== `Bearer ${PLATFORM_TOKEN}`) return res.status(401).json({ error: 'Authentication required' });
    req.user = { id: 7 };
    req.identitySession = { id: 19 };
    next();
  });
  const audit = options.audit || (async event => { audits.push(event); });
  const app = express();
  app.use(createApplicationCors({ secureShopOrigins: [TRUSTED_ORIGIN], platformOrigins: [TRUSTED_ORIGIN] }));
  app.use(express.json());
  app.use('/api/auth/secureshop-launch', createSecureShopLaunchRouter({
    enabled: options.enabled ?? true,
    engine: options.engine ?? 'postgres',
    authenticateToken,
    repository,
    audit,
    resetCoordinator: options.resetCoordinator, progress:options.progress, modeService:options.modeService,
    ttlMs: options.ttlMs ?? 60_000,
    now: options.now || (() => Date.parse('2026-09-13T20:00:00.000Z')),
  }));
  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  const server = await new Promise(resolve => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  async function request(path = '', { method = 'GET', body, rawBody, contentType, token = PLATFORM_TOKEN,
    origin = TRUSTED_ORIGIN, headers = {} } = {}) {
    const requestHeaders = { ...headers };
    if (origin !== undefined) requestHeaders.Origin = origin;
    if (token != null) requestHeaders.Authorization = `Bearer ${token}`;
    let payload;
    if (rawBody !== undefined) payload = rawBody;
    else if (body !== undefined) payload = JSON.stringify(body);
    if (contentType !== null && (body !== undefined || rawBody !== undefined)) {
      requestHeaders['Content-Type'] = contentType || 'application/json';
    }
    const response = await fetch(`${base}/api/auth/secureshop-launch${path}`, {
      method, headers: requestHeaders, body: payload,
    });
    const text = await response.text();
    let json;
    try { json = JSON.parse(text); } catch { json = null; }
    return { response, text, json };
  }
  return { request, calls, audits, repository, get authCalls() { return authCalls; } };
}

test('aggregate reset is absent on preparation-only mounts', async t => {
  const f = await fixture(t);
  const { response } = await f.request('/reset', { method: 'POST', body: {
    launchId: LAUNCH_ID, expectedGeneration: 3, idempotencyKey: 'reset-1',
  } });
  assert.equal(response.status, 404);
  assert.equal(f.calls.length, 0);
});

test('aggregate reset receives platform scope and returns only committed public metadata', async t => {
  let received;
  const f = await fixture(t, { resetCoordinator: { async reset(input) {
    received = input;
    return { resetId: '33333333-3333-4333-8333-333333333333', status: 'committed',
      fromGeneration: 3, toGeneration: 4, binding: { ...BINDING, generation: 4 },
      targets: [{ privateResource: 'must-not-leak' }] };
  } } });
  const body = { launchId: LAUNCH_ID, expectedGeneration: 3, idempotencyKey: 'reset-1' };
  const { response, json, text } = await f.request('/reset', { method: 'POST', body });
  assert.equal(response.status, 200);
  assert.equal(received.platformOwnerId, 7);
  assert.equal(received.platformSessionId, 19);
  assert.equal(received.idempotencyKey, body.idempotencyKey);
  assert.ok(received.signal instanceof AbortSignal);
  assert.equal(json.cleanupComplete, true);
  assert.equal(json.launch.generation, 4);
  assert.doesNotMatch(text, /privateResource|must-not-leak|scenarioId|platformOwnerId/);
  const forged = await f.request('/reset', { method: 'POST', body: { ...body, platformOwnerId: 8 } });
  assert.equal(forged.response.status, 400);
});

test('aggregate reset rejects incomplete or mismatched cleanup receipts', async t => {
  for (const patch of [{ status: 'aborted' }, { toGeneration: 5 },
    { binding: { ...BINDING, generation: 4, platformOwnerId: 8 } }]) {
    const f = await fixture(t, { resetCoordinator: { async reset() {
      return { resetId: '33333333-3333-4333-8333-333333333333', status: 'committed',
        fromGeneration: 3, toGeneration: 4, binding: { ...BINDING, generation: 4 }, ...patch };
    } } });
    const { response, json } = await f.request('/reset', { method: 'POST', body: {
      launchId: LAUNCH_ID, expectedGeneration: 3, idempotencyKey: 'reset-1',
    } });
    assert.equal(response.status, 503);
    assert.equal(json.error, 'Launch store unavailable');
    assert.equal(json.cleanupComplete, undefined);
  }
});

test('launch router is absent when disabled or outside PostgreSQL', async t => {
  for (const config of [{ enabled: false, engine: 'postgres' }, { enabled: true, engine: 'sqlite' }]) {
    await t.test(JSON.stringify(config), async t => {
      const f = await fixture(t, config);
      const result = await f.request();
      assert.equal(result.response.status, 404);
      assert.equal(f.authCalls, 0);
      assert.deepEqual(f.calls, []);
      assert.deepEqual(f.audits, []);
    });
  }
});

test('metadata and issuance use only trusted scope, redact internal binding fields, and disable storage', async t => {
  const f = await fixture(t);
  const metadata = await f.request();
  assert.equal(metadata.response.status, 200);
  assert.equal(metadata.response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(metadata.json, {
    preparationOnly: true,
    launch: { launchId: LAUNCH_ID, generation: 3, credentialVersion: 5, expiresAt: EXPIRES_AT },
  });
  assert.equal(JSON.stringify(metadata.json).includes('platformOwnerId'), false);
  assert.equal(JSON.stringify(metadata.json).includes('platformSessionId'), false);
  assert.equal(JSON.stringify(metadata.json).includes('scenarioId'), false);
  assert.deepEqual(f.audits, [], 'GET metadata is not a mutation attempt');

  const issued = await f.request('', { method: 'POST', body: {} });
  assert.equal(issued.response.status, 201);
  assert.equal(issued.response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(issued.json, {
    preparationOnly: true,
    launch: { launchId: LAUNCH_ID, generation: 3, credentialVersion: 5, expiresAt: EXPIRES_AT },
    bearer: NEW_BEARER,
  });
  assert.deepEqual(f.calls[1], ['issueOrRenew', {
    platformOwnerId: 7,
    platformSessionId: 19,
    expiresAt: '2026-09-13T20:01:00.000Z',
  }]);
  assert.deepEqual(f.audits, [{
    userId: 7,
    actionType: 'secureshop_launch_attempt',
    details: { method: 'POST', operation: '/', platformSessionId: 19 },
  }]);
  assert.equal(JSON.stringify(f.audits).includes(NEW_BEARER), false);
});

test('exact query, JSON content type, and body contracts reject caller-selected authority', async t => {
  const f = await fixture(t);
  const cases = [
    () => f.request('?platformOwnerId=99'),
    () => f.request('', { method: 'POST', body: { platformOwnerId: 99 } }),
    () => f.request('', { method: 'POST', rawBody: '{}', contentType: 'text/plain' }),
    () => f.request('', { method: 'PATCH', body: {} }),
    () => f.request('/recover', { method: 'POST', body: { launchId: LAUNCH_ID } }),
    () => f.request('', { method: 'DELETE', body: { launchId: LAUNCH_ID, expectedGeneration: 3, bearer: OLD_BEARER } }),
  ];
  for (const invoke of cases) {
    const result = await invoke();
    assert.equal(result.response.status, 400);
    assert.deepEqual(result.json, { error: 'Invalid launch request' });
    assert.equal(result.response.headers.get('cache-control'), 'no-store');
  }
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.audits, []);
});

test('recovery and renewal dispatch exact DTOs and redact conflict failures', async t => {
  const secretMessage = `repository exposed ${OLD_BEARER}`;
  const f = await fixture(t, { repository: {
    async issueOrRenew(args) {
      f.calls.push(['issueOrRenew', args]);
      throw codedError('STALE_HANDLE', secretMessage);
    },
  } });
  const recovered = await f.request('/recover', { method: 'POST', body: {
    launchId: LAUNCH_ID, expectedCredentialVersion: 5,
  } });
  assert.equal(recovered.response.status, 200);
  assert.equal(recovered.json.bearer, NEW_BEARER);
  assert.deepEqual(f.calls[0], ['recoverCredential', {
    platformOwnerId: 7, platformSessionId: 19, launchId: LAUNCH_ID, expectedCredentialVersion: 5,
  }]);

  const renewed = await f.request('', { method: 'PATCH', body: { bearer: OLD_BEARER } });
  assert.equal(renewed.response.status, 409);
  assert.deepEqual(renewed.json, { error: 'Launch request could not be completed' });
  assert.equal(renewed.text.includes(OLD_BEARER), false);
  assert.equal(renewed.text.includes(secretMessage), false);
  assert.deepEqual(f.calls[1], ['issueOrRenew', {
    platformOwnerId: 7, platformSessionId: 19, expectedBearer: OLD_BEARER,
    expiresAt: '2026-09-13T20:01:00.000Z',
  }]);
  assert.deepEqual(f.audits.map(event => [event.details.method, event.details.operation]), [
    ['POST', '/recover'], ['PATCH', '/'],
  ]);
  assert.equal(JSON.stringify(f.audits).includes(OLD_BEARER), false);
});

test('terminal launch conflict exposes only a stable code and no stored authority', async t => {
  const f = await fixture(t, { repository: {
    async readActiveMetadata() { return null; },
    async issueOrRenew() { throw codedError('LAUNCH_SESSION_TERMINAL', `expired ${OLD_BEARER}`); },
  } });
  const metadata = await f.request();
  assert.equal(metadata.response.status, 200);
  assert.equal(metadata.json.launch, null);
  const issued = await f.request('', { method: 'POST', body: {} });
  assert.equal(issued.response.status, 409);
  assert.deepEqual(issued.json, {
    error: 'Launch request could not be completed', code: 'LAUNCH_SESSION_TERMINAL',
  });
  assert.equal(issued.text.includes(OLD_BEARER), false);
});

test('retained session capacity reports a recoverable conflict without exposing authority', async t => {
  const f = await fixture(t, { repository: {
    async issueOrRenew() { throw codedError('LAUNCH_CAPACITY', `retained ${OLD_BEARER}`); },
  } });
  const result = await f.request('', { method: 'POST', body: {} });
  assert.equal(result.response.status, 409);
  assert.equal(result.json.code, 'LAUNCH_CAPACITY');
  assert.match(result.json.error, /retained session limit/);
  assert.equal(result.text.includes(OLD_BEARER), false);
});

test('audit failure is redacted and prevents launch mutation', async t => {
  const f = await fixture(t, { audit: async () => { throw new Error(`audit leaked ${OLD_BEARER}`); } });
  const result = await f.request('', { method: 'POST', body: {} });
  assert.equal(result.response.status, 503);
  assert.deepEqual(result.json, { error: 'Launch store unavailable' });
  assert.equal(result.text.includes(OLD_BEARER), false);
  assert.deepEqual(f.calls, []);
});

test('generation-scoped DELETE intentionally terminates after credential rotation', async t => {
  const f = await fixture(t);
  const renewed = await f.request('', { method: 'PATCH', body: { bearer: OLD_BEARER } });
  assert.equal(renewed.response.status, 200);
  assert.equal(renewed.json.launch.generation, 3);
  const revoked = await f.request('', { method: 'DELETE', body: {
    launchId: LAUNCH_ID, expectedGeneration: 3,
  } });
  assert.equal(revoked.response.status, 200);
  assert.deepEqual(revoked.json, { revoked: true, preparationOnly: true, cleanupComplete: false });
  assert.deepEqual(f.calls[1], ['revoke', {
    platformOwnerId: 7,
    platformSessionId: 19,
    launchId: LAUNCH_ID,
    expectedGeneration: 3,
    reason: 'platform_launch_revoked',
  }]);
  assert.equal(Object.hasOwn(f.calls[1][1], 'bearer'), false);
});

test('platform authentication and application CORS reject untrusted callers before repository use', async t => {
  const f = await fixture(t);
  const unauthenticated = await f.request('', { token: null });
  assert.equal(unauthenticated.response.status, 401);
  assert.equal(unauthenticated.response.headers.get('cache-control'), 'no-store');

  const evil = await f.request('', { origin: 'https://evil.example' });
  assert.equal(evil.response.status, 403);
  assert.equal(evil.response.headers.get('access-control-allow-origin'), null);
  const opaque = await f.request('', { origin: 'null' });
  assert.equal(opaque.response.status, 403);

  const preflight = await f.request('', { method: 'OPTIONS', token: undefined, headers: {
    'Access-Control-Request-Method': 'PATCH',
    'Access-Control-Request-Headers': 'authorization, content-type',
  } });
  assert.equal(preflight.response.status, 204);
  assert.equal(preflight.response.headers.get('access-control-allow-origin'), TRUSTED_ORIGIN);
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.audits, []);
});

test('launch rate limit allows thirty requests per authenticated platform session each minute', async t => {
  const f = await fixture(t);
  for (let index = 0; index < 30; index += 1) {
    const result = await f.request();
    assert.equal(result.response.status, 200, `request ${index + 1}`);
  }
  const limited = await f.request();
  assert.equal(limited.response.status, 429);
  assert.deepEqual(limited.json, { error: 'Too many launch requests' });
  assert.equal(limited.response.headers.get('cache-control'), 'no-store');
  assert.equal(f.calls.length, 30);
});

test('heartbeat derives exact canonical scope without launch audit and denies stale or forged scope',async t=>{
 const writes=[];let valid=true;
 const f=await fixture(t,{resetCoordinator:{reset:async()=>{}},repository:{resolve:async q=>{assert.deepEqual(q,{platformOwnerId:7,platformSessionId:19,bearer:OLD_BEARER});return valid?BINDING:null;}},progress:{recordHeartbeat:async q=>{writes.push(q);return{added:30};}}});
 const body={bearer:OLD_BEARER,expectedGeneration:3};
 assert.equal((await f.request('/heartbeat',{method:'POST',body})).response.status,200);
 assert.deepEqual(writes,[{userId:7,workshopKey:'secureshop_agent_security',instanceScope:BINDING}]);assert.equal(f.audits.length,0);
 assert.equal((await f.request('/heartbeat',{method:'POST',body:{...body,platformOwnerId:8}})).response.status,400);
 assert.equal((await f.request('/heartbeat',{method:'POST',body:{...body,expectedGeneration:2}})).response.status,409);
 valid=false;assert.equal((await f.request('/heartbeat',{method:'POST',body})).response.status,409);assert.equal(writes.length,1);
});
test('preparation-only launch has no heartbeat endpoint',async t=>{const f=await fixture(t,{progress:{recordHeartbeat:async()=>{throw Error('must not write');}}});assert.equal((await f.request('/heartbeat',{method:'POST',body:{bearer:OLD_BEARER,expectedGeneration:3}})).response.status,404);});


test('owner mode endpoint uses canonical owner and authoritative readback with a closed request', async t => {
  let mode='vuln'; const calls=[];
  const f=await fixture(t,{modeService:{async getMode(input){calls.push(['get',input]);return mode;},async setMode(input){calls.push(['set',input]);mode=input.mode;}}});
  const first=await f.request('/mode');assert.equal(first.response.status,200);assert.equal(first.json.effectiveMode,'vuln');
  const updated=await f.request('/mode',{method:'POST',body:{mode:'fixed'}});assert.equal(updated.response.status,200);assert.equal(updated.json.effectiveMode,'fixed');assert.equal(updated.response.headers.get('cache-control'),'no-store');
  assert.deepEqual(calls.at(-2),['set',{userId:7,workshopKey:'secureshop_agent_security',mode:'fixed'}]);
  assert.ok(updated.json.features.some(x=>x.featureId==='inventory'));assert.equal(updated.json.fixedSupported,undefined);
  const count=calls.length;
  for(const body of [{mode:'fixed',platformOwnerId:8},{mode:'fixed',modeCapability:{}},{mode:'secure'}])assert.equal((await f.request('/mode',{method:'POST',body})).response.status,400);
  assert.equal((await f.request('/mode',{token:OLD_BEARER})).response.status,401);assert.equal(calls.length,count);
  assert.equal(f.calls.length,0);
});
