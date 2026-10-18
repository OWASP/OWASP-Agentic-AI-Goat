'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createSecureShopStandaloneAuthRouter, projectBootstrap } = require('../server/routes/secureshopStandaloneAuth');

const token = 's'.repeat(43), origin = 'http://localhost:3000';
const context = Object.freeze({ principalId: 'shop-principal', shopUserId: 1000000001,
  username: 'customer', role: 'customer', email: 'customer@shop.invalid',
  ownerId: 91, sessionId: 73, internalOnly: 'private' });
function bootstrapDto() {
  const expiresAt = new Date(Date.now() + 60000).toISOString();
  return { launch: { launchId: 'af8ea882-bcde-4123-8e11-321ef739daca', generation: 1,
    credentialVersion: 1, expiresAt }, bearer: 'b'.repeat(43),
  persona: { token: 'header.payload.signature', expiresAt, user: { id: 1000000001,
    username: 'customer', email: 'customer@shop.invalid', role: 'customer', full_name: null, phone: null } } };
}
async function fixture(t, overrides = {}, options = {}) {
  const calls = [];
  let active = true;
  const result = () => ({ token, user: { ...context, passwordHash: 'never-public' },
    context, expiresAt: new Date(Date.now() + 60000).toISOString() });
  const service = {
    login: async input => { calls.push(['login', input]); return result(); },
    register: async input => { calls.push(['register', input]); return result(); },
    authenticate: async value => { calls.push(['authenticate', value]); return active && value === token ? context : null; },
    renew: async () => result(),
    changePassword: async (value, input) => { calls.push(['changePassword', value, input]); active = false; return { ok: true }; },
    logout: async value => { calls.push(['logout', value]); active = false; }, ...overrides,
  };
  const app = express(); app.use(express.json());
  app.use('/api/secureshop/auth', createSecureShopStandaloneAuthRouter({ service,
    allowedOrigins: [origin], bootstrap: async user => {
      assert.equal(user, context); calls.push(['bootstrap']); return bootstrapDto();
    }, ...options }));
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api/secureshop/auth`;
  const request = (route, body = {}, headers = {}) => fetch(base + route, { method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
  return { base, calls, request };
}

test('independent shop login uses hardened scoped cookie and strips internal authority', async t => {
  const f = await fixture(t, {}, { secureCookies: true });
  const response = await f.request('/login', { username: 'customer', password: 'fixture' });
  assert.equal(response.status, 200);
  const cookie = response.headers.get('set-cookie');
  for (const value of ['dvaia_shop_session=', 'Path=/api/secureshop', 'HttpOnly', 'SameSite=Strict', 'Secure']) assert.ok(cookie.includes(value));
  const data = await response.json();
  assert.equal(data.user.username, 'customer');
  for (const forbidden of ['token', 'context', 'ownerId', 'sessionId', 'passwordHash', 'internalOnly']) assert.ok(!JSON.stringify(data).includes(forbidden));
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('shop login and renewal cookies retain the exact service expiry',async t=>{
  const expiresAt=new Date(Math.floor(Date.now()/1000)*1000+120000).toISOString();
  const value={token,user:context,context,expiresAt};
  const f=await fixture(t,{login:async()=>value,renew:async()=>value});
  for(const endpoint of ['/login','/renew']){
    const response=await f.request(endpoint,endpoint==='/login'?{username:'customer',password:'fixture'}:{},
      {Cookie:`dvaia_shop_session=${token}`});
    assert.equal(response.status,200);
    const cookieExpiry=/Expires=([^;]+)/i.exec(response.headers.get('set-cookie'))?.[1];
    assert.equal(Date.parse(cookieExpiry),Date.parse(expiresAt));
    assert.equal((await response.json()).expiresAt,expiresAt);
  }
});

test('workshop bearer and identity cookie cannot authorize shop session or bootstrap', async t => {
  const f = await fixture(t);
  const headers = { Authorization: 'Bearer workshop-jwt', Cookie: 'connect.sid=workshop-session' };
  assert.deepEqual(await (await fetch(f.base + '/session', { headers })).json(), { authenticated: false, user: null });
  assert.equal((await f.request('/bootstrap', {}, headers)).status, 401);
  assert.equal(f.calls.length, 0);
});

test('canonical workshop authentication rejects a shop token before querying workshop users', async () => {
  const { createPostgresIdentityAdapter } = require('../server/services/postgresIdentityAdapter');
  let reads = 0;
  const adapter = createPostgresIdentityAdapter({ jwtSecret: 'isolated-workshop-signing-key',
    progress: {}, repository: {
      checkAccountLockout: async () => { reads += 1; throw new Error('Unexpected workshop lookup'); },
      findActiveSession: async () => { reads += 1; throw new Error('Unexpected workshop lookup'); },
    } });
  await assert.rejects(adapter.validateSession(token), { name: 'JsonWebTokenError' });
  assert.equal(reads, 0);
});

test('shop writes reject foreign, opaque and missing origins before credentials', async t => {
  const f = await fixture(t);
  for (const value of ['https://foreign.invalid', 'null', '']) {
    const response = await f.request('/login', { username: 'customer', password: 'fixture' }, { Origin: value });
    assert.equal(response.status, 403);
  }
  assert.equal(f.calls.length, 0);
});

test('public registration cannot assign admin or inject authority identifiers', async t => {
  const f = await fixture(t);
  const body = { username: 'new', email: 'new@shop.invalid', password: 'fixture', role: 'admin' };
  assert.equal((await f.request('/register', body)).status, 400);
  assert.equal((await f.request('/register', { ...body, role: 'customer', ownerId: 91 })).status, 400);
  assert.equal(f.calls.length, 0);
});

test('status is read-only, bootstrap uses validated shop context, logout revokes only shop token', async t => {
  const f = await fixture(t); const headers = { Cookie: `dvaia_shop_session=${token}` };
  const signedIn = await (await f.request('/login', { username: 'customer', password: 'fixture' })).json();
  const status = await (await fetch(f.base + '/session', { headers })).json();
  assert.equal(status.authenticated, true);
  assert.deepEqual(status.user, signedIn.user);
  assert.equal(f.calls.filter(call => call[0] === 'bootstrap').length, 0);
  assert.equal((await f.request('/bootstrap', {}, headers)).status, 200);
  assert.equal((await f.request('/logout', {}, headers)).status, 200);
  assert.deepEqual(f.calls.find(call => call[0] === 'logout'), ['logout', token]);
  assert.equal((await f.request('/bootstrap', {}, headers)).status, 401);
});
test('only the exact expired shop launch exposes a bounded renewal signal', async t => {
  for (const code of ['SHOP_LAUNCH_EXPIRED', 'LAUNCH_SESSION_TERMINAL', 'SHOP_AUTH_INVALID']) {
    const f = await fixture(t, {}, { bootstrap: async () => {
      throw Object.assign(Error('private launch state'), { code });
    } });
    const response = await f.request('/bootstrap', {}, { Cookie: `dvaia_shop_session=${token}` });
    const body = await response.json();
    if (code === 'SHOP_LAUNCH_EXPIRED') {
      assert.equal(response.status, 409);assert.equal(body.code, code);
    } else {
      assert.equal(response.status, code === 'SHOP_AUTH_INVALID' ? 401 : 503);
      assert.equal(Object.hasOwn(body, 'code'), false);
    }
    assert.equal(JSON.stringify(body).includes('private launch state'), false);
  }
});

test('ambiguous shop cookies fail closed instead of choosing a session', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('/bootstrap', {}, { Cookie: `dvaia_shop_session=${token}; dvaia_shop_session=${token}` })).status, 401);
  assert.equal(f.calls.length, 0);
});

test('authentication failures remain generic and attempts are bounded', async t => {
  const f = await fixture(t, { login: async () => { throw Object.assign(new Error('private database detail'), { code: 'SHOP_CREDENTIALS_INVALID' }); } }, { loginLimit: 1 });
  const first = await f.request('/login', { username: 'customer', password: 'fixture' });
  assert.equal(first.status, 401); assert.deepEqual(await first.json(), { error: 'Invalid shop credentials' });
  assert.equal((await f.request('/login', { username: 'customer', password: 'fixture' })).status, 429);
});

test('bootstrap denies private authority fields at every projection boundary', () => {
  assert.deepEqual(projectBootstrap(bootstrapDto()).persona.user.role, 'customer');
  for (const target of ['root', 'launch', 'persona', 'user']) {
    const dto = bootstrapDto();
    const object = target === 'root' ? dto : target === 'user' ? dto.persona.user : dto[target];
    object.ownerId = 'PRIVATE_AUTHORITY_SENTINEL';
    assert.throws(() => projectBootstrap(dto), /Invalid shop bootstrap/);
  }
  const dto = bootstrapDto(); dto.persona.token = token;
  assert.throws(() => projectBootstrap(dto), /Invalid shop bootstrap/);
});

test('password change requires shop authority, clears its cookie and requires fresh sign-in', async t => {
  const f = await fixture(t);
  const input = { currentPassword: 'old-fixture', newPassword: 'new-fixture' };
  assert.equal((await f.request('/password', input, { Authorization: 'Bearer workshop-jwt' })).status, 401);
  const response = await f.request('/password', input, { Cookie: `dvaia_shop_session=${token}` });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { authenticated: false, passwordChanged: true });
  assert.match(response.headers.get('set-cookie'), /dvaia_shop_session=;/);
  assert.match(response.headers.get('set-cookie'), /Path=\/api\/secureshop/);
  assert.equal((await f.request('/bootstrap', {}, { Cookie: `dvaia_shop_session=${token}` })).status, 401);
});

test('failed password change retains cookie and does not claim success', async t => {
  const f = await fixture(t, { changePassword: async () => { throw Object.assign(new Error('private'), { code: 'SHOP_CREDENTIALS_INVALID' }); } });
  const response = await f.request('/password', { currentPassword: 'wrong', newPassword: 'new-fixture' }, { Cookie: `dvaia_shop_session=${token}` });
  assert.equal(response.status, 401); assert.equal(response.headers.get('set-cookie'), null);
  assert.deepEqual(await response.json(), { error: 'Invalid shop credentials' });
});

test('guest cart import requires shop cookie and passes only bounded item intent', async t => {
  const requestId = 'ca81c02d-abcd-4000-8000-010203040506';
  const input = { requestId, items: [{ productId: 1, quantity: 2 }] };
  let imports = 0;
  const outcome = { requestId, imported: true, replayed: false,
    items: [{ productId: 1, quantity: 2, price: 10, name: 'Product' }], subtotal: 20 };
  const f = await fixture(t, {}, { cartImport: async (principal, request) => {
    imports++; assert.equal(principal, context); assert.deepEqual(request, input); return outcome;
  } });
  assert.equal((await f.request('/cart-import', input)).status, 401);
  const response = await f.request('/cart-import', input, { Cookie: `dvaia_shop_session=${token}` });
  assert.equal(response.status, 200); assert.deepEqual(await response.json(), outcome);
  assert.equal(imports, 1);
  assert.equal((await f.request('/cart-import', { ...input, items: [{ productId: 1, quantity: 2, price: 0 }] },
    { Cookie: `dvaia_shop_session=${token}` })).status, 400);
  assert.equal(imports, 1);
});

test('cart import denies authority leakage and preserves structured stock rejection', async t => {
  const requestId = 'ca81c02d-abcd-4000-8000-010203040506';
  let leak = false;
  const rejection = { requestId, imported: false, replayed: false,
    issues: [{ productId: 1, code: 'INSUFFICIENT_STOCK', availableQuantity: 0 }] };
  const f = await fixture(t, {}, { cartImport: async () => leak ? { ...rejection, token: 'private' } : rejection });
  const input = { requestId, items: [{ productId: 1, quantity: 2 }] };
  const headers = { Cookie: `dvaia_shop_session=${token}` };
  assert.deepEqual(await (await f.request('/cart-import', input, headers)).json(), rejection);
  leak = true;
  const response = await f.request('/cart-import', input, headers);
  assert.equal(response.status, 503); assert.ok(!(await response.text()).includes('private'));
});

test('cart import canonicalizes a valid uppercase request ID before any effect or replay', async t => {
  const requestId = 'CA81C02D-ABCD-4000-8000-010203040506';
  let calls = 0;
  const f = await fixture(t, {}, { cartImport: async (_principal, input) => {
    assert.equal(input.requestId, requestId.toLowerCase());
    return { requestId: input.requestId, imported: true, replayed: calls++ > 0,
      items: [{ productId: 1, quantity: 1, price: 10, name: 'Product' }], subtotal: 10 };
  } });
  for (const replayed of [false, true]) {
    const response = await f.request('/cart-import', { requestId, items: [{ productId: 1, quantity: 1 }] },
      { Cookie: `dvaia_shop_session=${token}` });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.requestId, requestId.toLowerCase()); assert.equal(result.replayed, replayed);
  }
});

test('independent mode reads and CAS changes use only the cookie principal', async t => {
  let value = {mode:'vuln',revision:'1'};
  const f = await fixture(t, {}, { mode: {
    get:async principal=>{assert.equal(principal,context);return value;},
    set:async(principal,input)=>{assert.equal(principal,context);if(input.expectedRevision!==value.revision)throw Object.assign(Error('changed'),{code:'SHOP_MODE_CONFLICT'});value={mode:input.mode,revision:'2'};return value;},
  } });
  assert.equal((await fetch(f.base+'/mode')).status,401);
  const headers={Cookie:`dvaia_shop_session=${token}`};
  assert.deepEqual(await(await fetch(f.base+'/mode',{headers})).json(),value);
  assert.deepEqual(await(await f.request('/mode',{mode:'fixed',expectedRevision:'1'},headers)).json(),{mode:'fixed',revision:'2'});
  assert.equal((await f.request('/mode',{mode:'vuln',expectedRevision:'1'},headers)).status,409);
  assert.equal((await f.request('/mode',{mode:'vuln',expectedRevision:'2',principalId:'other'},headers)).status,400);
  assert.equal((await f.request('/mode',{mode:'vuln',expectedRevision:'2'},{...headers,Origin:'https://foreign.invalid'})).status,403);
});

test('objective configuration requires independent immutable shop admin cookie and exact input', async t => {
  let mutations = 0;
  const catalog = { list: async () => ({ objectives: [] }), set: async () => { mutations++; } };
  const f = await fixture(t, {}, { assessmentObjectives: catalog });
  assert.equal((await fetch(f.base + '/assessment-objectives')).status, 401);
  assert.equal((await fetch(f.base + '/assessment-objectives', {headers:{Cookie:`dvaia_shop_session=${token}`}})).status,403);
  assert.equal((await f.request('/assessment-objectives', {objectiveId:'ss_loop_observation',enabled:true,expectedRevision:'1'}, {Cookie:`dvaia_shop_session=${token}`})).status,403);
  assert.equal(mutations,0);
});
test('shop objective catalog projects exact safe DTO and rejects stale or unqualified changes', async t => {
  const admin = {...context,role:'admin'};
  let mode = 'ok'; const row={objectiveId:'ss_loop_observation',enabled:false,qualification:'native-model',revision:'1'};
  const f=await fixture(t,{authenticate:async value=>value===token?admin:null},{assessmentObjectives:{
    list:async user=>{assert.equal(user,admin);return {objectives:[{...row,label:'Observe the loop'}]};},
    set:async (user,input)=>{assert.equal(user,admin);if(mode!=='ok')throw Object.assign(Error('private'),{code:mode});return {...row,enabled:input.enabled,revision:'2'};}
  }});
  const headers={Cookie:`dvaia_shop_session=${token}`};
  const listed=await fetch(f.base+'/assessment-objectives',{headers});assert.equal(listed.status,200);assert.equal((await listed.json()).objectives.length,1);
  const input={objectiveId:row.objectiveId,enabled:true,expectedRevision:'1'};
  assert.equal((await f.request('/assessment-objectives',input,headers)).status,200);
  for(const code of ['SHOP_OBJECTIVE_CONFLICT','SHOP_OBJECTIVE_UNQUALIFIED']){mode=code;assert.equal((await f.request('/assessment-objectives',input,headers)).status,409);}
  assert.equal((await f.request('/assessment-objectives',{...input,tenantId:'forged'},headers)).status,400);
  assert.equal((await f.request('/assessment-objectives',{...input,expectedRevision:'9223372036854775808'},headers)).status,400);
  assert.equal((await f.request('/assessment-objectives',input,{...headers,Origin:'https://foreign.invalid'})).status,403);
});
test('objective catalog fails closed on private output or mismatched mutation receipt', async t => {
  const row={objectiveId:'ss_loop_observation',enabled:false,qualification:'native-model',revision:'1'};
  const f=await fixture(t,{authenticate:async()=>({...context,role:'admin'})},{assessmentObjectives:{
    list:async()=>({objectives:[{...row,label:'Loop',secret:'private'}]}),set:async()=>row
  }});
  const headers={Cookie:`dvaia_shop_session=${token}`};
  const response=await fetch(f.base+'/assessment-objectives',{headers});assert.equal(response.status,503);assert(!JSON.stringify(await response.json()).includes('private'));
  assert.equal((await f.request('/assessment-objectives',{objectiveId:row.objectiveId,enabled:true,expectedRevision:'1'},headers)).status,503);
});

test('shop assessment recovery is cookie scoped, bounded, and passes only canonical evaluation ID',async t=>{
 const evaluationId='af8ea882-bcde-4123-8e11-321ef739daca';let calls=0;
 const row={evaluationId,objectiveId:'ss_loop_observation',verdict:'unavailable',disposition:'not_pass',
  createdAt:'2026-10-09T00:00:00.000Z',evaluatedAt:null,canRetry:true,childEvaluationId:null};
 const f=await fixture(t,{}, {assessmentRecovery:{list:async user=>{assert.equal(user,context);return{judgments:[row]};},
  retry:async(user,input)=>{assert.equal(user,context);assert.deepEqual(input,{evaluationId});calls++;return{evaluationId,
   childEvaluationId:'bf8ea882-bcde-4123-8e11-321ef739daca',verdict:'fail',disposition:'not_pass',completed:false,replayed:false};}}});
 const headers={Cookie:`dvaia_shop_session=${token}`};
 assert.equal((await fetch(f.base+'/assessments',{headers})).status,200);
 assert.equal((await fetch(f.base+'/assessments?userId=other',{headers})).status,400);
 assert.equal((await f.request('/assessments/retry',{evaluationId})).status,401);
 assert.equal((await f.request('/assessments/retry',{evaluationId,ownerId:91},headers)).status,400);
 assert.equal((await f.request('/assessments/retry',{evaluationId:evaluationId.toUpperCase()},headers)).status,200);
 assert.equal(calls,1);
});
test('shop recovery strips no authority silently and rejects false completion or stale retry',async t=>{
 const evaluationId='af8ea882-bcde-4123-8e11-321ef739daca';let stale=false;
 const f=await fixture(t,{}, {assessmentRecovery:{list:async()=>({judgments:[],privateToken:'private'}),
  retry:async()=>{if(stale)throw Object.assign(Error('private'),{code:'SHOP_ASSESSMENT_STALE'});return{
   evaluationId,childEvaluationId:'bf8ea882-bcde-4123-8e11-321ef739daca',verdict:'fail',disposition:'not_pass',completed:true,replayed:false};}}});
 const headers={Cookie:`dvaia_shop_session=${token}`};
 const listed=await fetch(f.base+'/assessments',{headers});assert.equal(listed.status,503);assert(!JSON.stringify(await listed.json()).includes('private'));
 assert.equal((await f.request('/assessments/retry',{evaluationId},headers)).status,503);
 stale=true;assert.equal((await f.request('/assessments/retry',{evaluationId},headers)).status,409);
});

test('registered reset requires independent admin cookie before service mutation', async t => {
  let resets = 0;
  const f = await fixture(t, {}, { registeredAdminReset: { reset: async () => { resets++; } } });
  const input = { operationId: '550e8400-e29b-41d4-a716-446655440000', expectedCredentialVersion: '1',
    expectedAuthorityVersion: '1', expectedMembershipVersion: '1' };
  assert.equal((await f.request('/admin/users/123/reset-password', input,
    { Authorization: 'Bearer workshop-admin', Cookie: 'connect.sid=workshop' })).status, 401);
  assert.equal((await f.request('/admin/users/123/reset-password', input,
    { Cookie: `dvaia_shop_session=${token}` })).status, 403);
  assert.equal(resets, 0);
});

test('registered reset projects exact protected receipts and confines secret to reveal', async t => {
  const operationId = '550e8400-e29b-41d4-a716-446655440000', targetId = 123;
  const receipt = { operationId, targetId, credentialVersion: '2', authorityVersion: '2',
    receiptSha256: 'a'.repeat(64), expiresAt: new Date(Date.now() + 60000).toISOString() };
  const seen = [];
  const resetService = {
    preview: async input => { seen.push(input); return { id: targetId, username: 'registered', email: 'registered@example.invalid',
      credentialVersion: '1', authorityVersion: '1', membershipVersion: '1', resetAvailable: true }; },
    reset: async input => { seen.push(input); return { receipt, secretAvailable: true, replayed: false }; },
    read: async () => ({ receipt, secretAvailable: true }),
    reveal: async () => ({ receipt, temporaryPassword: 'p'.repeat(43) }),
    acknowledge: async () => ({ receipt, secretAvailable: false }),
  };
  const f = await fixture(t, { authenticate: async value => value === token ? { ...context, role: 'admin' } : null },
    { registeredAdminReset: resetService });
  const headers = { Cookie: `dvaia_shop_session=${token}` }, base = '/admin/users/123';
  const ready = await fetch(f.base + base + '/reset-readiness', { headers });
  assert.equal(ready.status, 200); assert.equal((await ready.json()).user.id, targetId);
  const input = { operationId: operationId.toUpperCase(), expectedCredentialVersion: '1', expectedAuthorityVersion: '1', expectedMembershipVersion: '1' };
  const reset = await f.request(base + '/reset-password', input, headers);
  assert.equal(reset.status, 200); assert.equal(reset.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await reset.json(), { ok: true, receipt, secretAvailable: true, replayed: false });
  assert.equal(seen[1].operationId, operationId); assert.equal(seen[1].token, token);
  const path = `${base}/password-resets/${operationId}`;
  assert.deepEqual(await (await fetch(f.base + path, { headers })).json(), { ok: true, receipt, secretAvailable: true });
  assert.deepEqual(await (await f.request(path + '/reveal', {}, headers)).json(), { ok: true, receipt, temporaryPassword: 'p'.repeat(43) });
  assert.deepEqual(await (await f.request(path + '/acknowledge', {}, headers)).json(), { ok: true, receipt, secretAvailable: false });
  const before = seen.length;
  assert.equal((await f.request(base + '/reset-password', input, { ...headers, Origin: 'null' })).status, 403);
  assert.equal((await f.request(base + '/reset-password', { ...input, targetId: 456 }, headers)).status, 400);
  assert.equal((await fetch(f.base + base + '/reset-readiness?ownerId=456', { headers })).status, 400);
  assert.equal(seen.length, before);
  resetService.read = async () => ({ receipt, secretAvailable: true, temporaryPassword: 'must-not-leak' });
  const rejected = await fetch(f.base + path, { headers });
  assert.equal(rejected.status, 503); assert.ok(!(await rejected.text()).includes('must-not-leak'));
  resetService.read = async () => null;
  assert.equal((await fetch(f.base + path, { headers })).status, 404);
});

test('shared-practice reset uses only shop admin cookie, exact confirmation, and canonical request IDs', async t => {
  const launchId = 'af8ea882-bcde-4123-8e11-321ef739daca';
  const sceneId = 'bf8ea882-bcde-4123-8e11-321ef739daca';
  const requestId = 'cf8ea882-bcde-4123-8e11-321ef739daca';
  const resetId = 'df8ea882-bcde-4123-8e11-321ef739daca';
  const calls = [];
  const f = await fixture(t, { authenticate: async value => value === token
    ? { ...context, role: 'admin' } : null }, { reset: {
    readiness: async user => { calls.push(['readiness', user]); return { available: true,
      scope: 'shared_practice', launchId, generation: 3,
      scene: { id: sceneId, label: 'Shop practice 1' } }; },
    reset: async (user, input) => { calls.push(['reset', user, input]); return {
      resetId, status: 'committed', cleanupComplete: true }; },
  } });
  const headers = { Cookie: `dvaia_shop_session=${token}` };
  const ready = await fetch(f.base + '/reset-readiness', { headers });
  assert.equal(ready.status, 200);
  assert.deepEqual(await ready.json(), { available: true, scope: 'shared_practice',
    launchId, generation: 3, scene: { id: sceneId, label: 'Shop practice 1' } });
  assert.equal((await fetch(f.base + '/reset-readiness?ownerId=91', { headers })).status, 400);
  const input = { launchId: launchId.toUpperCase(), expectedGeneration: 3,
    idempotencyKey: requestId.toUpperCase(), sceneId: sceneId.toUpperCase(),
    confirmation: 'RESET_SHARED_PRACTICE' };
  assert.equal((await f.request('/reset', input)).status, 401);
  assert.equal((await f.request('/reset', { ...input, confirmation: 'RESET' }, headers)).status, 400);
  assert.equal((await f.request('/reset', { ...input, ownerId: 91 }, headers)).status, 400);
  assert.equal((await f.request('/reset', input, { ...headers, Origin: 'null' })).status, 403);
  const response = await f.request('/reset', input, headers);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { resetId, status: 'committed', cleanupComplete: true });
  assert.deepEqual(calls[1], ['reset', calls[0][1], { launchId, expectedGeneration: 3,
    idempotencyKey: requestId, sceneId, confirmation: 'RESET_SHARED_PRACTICE' }]);
});

test('shared-practice reset fails closed on missing composition, non-admin authority and unconfirmed completion', async t => {
  const headers = { Cookie: `dvaia_shop_session=${token}` };
  const absent = await fixture(t);
  assert.equal((await fetch(absent.base + '/reset-readiness', { headers })).status, 403);
  assert.equal((await absent.request('/reset', { launchId: 'af8ea882-bcde-4123-8e11-321ef739daca',
    expectedGeneration: 1, idempotencyKey: 'cf8ea882-bcde-4123-8e11-321ef739daca',
    sceneId: 'bf8ea882-bcde-4123-8e11-321ef739daca', confirmation: 'RESET_SHARED_PRACTICE' }, headers)).status, 403);
  const admin = { authenticate: async () => ({ ...context, role: 'admin' }) };
  const unavailable = await fixture(t, admin);
  assert.equal((await fetch(unavailable.base + '/reset-readiness', { headers })).status, 503);
  const broken = await fixture(t, admin, { reset: {
    readiness: async () => ({ available: true, scope: 'shared_practice',
      launchId: 'af8ea882-bcde-4123-8e11-321ef739daca', generation: 1,
      scene: { id: 'bf8ea882-bcde-4123-8e11-321ef739daca', label: 'Shop practice 1' }, privateKey: 'never-public' }),
    reset: async () => ({ resetId: 'df8ea882-bcde-4123-8e11-321ef739daca',
      status: 'fenced', cleanupComplete: false, privateKey: 'never-public' }),
  } });
  const response = await fetch(broken.base + '/reset-readiness', { headers });
  assert.equal(response.status, 503);
  assert.ok(!(await response.text()).includes('never-public'));
});

test('reset recovery is cookie-admin scoped and projects only exact retained journal status', async t => {
  const resetId = 'df8ea882-bcde-4123-8e11-321ef739daca';
  const launchId = 'af8ea882-bcde-4123-8e11-321ef739daca';
  const sceneId = 'bf8ea882-bcde-4123-8e11-321ef739daca';
  const calls = [];
  const f = await fixture(t, { authenticate: async value => value === token
    ? { ...context, role: 'admin' } : null }, { reset: {
    readRecovery: async user => { calls.push(['readRecovery', user]); return { pending: {
      resetId, launchId, fromGeneration: 3, toGeneration: 4, status: 'fenced',
      scene: { id: sceneId, label: 'Shop practice' }, cleanupComplete: false,
      sameExecution: false } }; },
    recover: async (user, input) => { calls.push(['recover', user, input]); return {
      resetId, status: 'fenced', cleanupComplete: true, activated: false }; },
  } });
  const headers = { Cookie: `dvaia_shop_session=${token}` };
  assert.equal((await fetch(f.base + '/reset-recovery')).status, 401);
  const read = await fetch(f.base + '/reset-recovery', { headers });
  assert.equal(read.status, 200);
  assert.deepEqual(await read.json(), { pending: { resetId, launchId,
    fromGeneration: 3, toGeneration: 4, status: 'fenced',
    scene: { id: sceneId, label: 'Shop practice' }, cleanupComplete: false,
    sameExecution: false } });
  assert.equal((await fetch(f.base + '/reset-recovery?ownerId=91', { headers })).status, 400);
  assert.equal((await f.request('/reset-recovery', { resetId })).status, 401);
  assert.equal((await f.request('/reset-recovery', { resetId, ownerId: 91 }, headers)).status, 400);
  assert.equal((await f.request('/reset-recovery', { resetId }, { ...headers, Origin: 'null' })).status, 403);
  const completed = await f.request('/reset-recovery', { resetId: resetId.toUpperCase() }, headers);
  assert.equal(completed.status, 200);
  assert.deepEqual(await completed.json(), { resetId, status: 'fenced', cleanupComplete: true,
    activated: false });
  assert.deepEqual(calls[1], ['recover', calls[0][1], { resetId }]);
});

test('reset recovery rejects false activation and private output, and returns 404 for foreign journal', async t => {
  const headers = { Cookie: `dvaia_shop_session=${token}` };
  const admin = { authenticate: async () => ({ ...context, role: 'admin' }) };
  const absent = await fixture(t, admin);
  assert.equal((await fetch(absent.base + '/reset-recovery', { headers })).status, 503);
  const f = await fixture(t, admin, { reset: {
    readRecovery: async () => ({ pending: null }),
    recover: async () => { throw Object.assign(new Error('foreign'), { code: 'SHOP_RESET_NOT_FOUND' }); },
  } });
  assert.deepEqual(await (await fetch(f.base + '/reset-recovery', { headers })).json(), { pending: null });
  assert.equal((await f.request('/reset-recovery', {
    resetId: 'df8ea882-bcde-4123-8e11-321ef739daca' }, headers)).status, 404);
  const broken = await fixture(t, admin, { reset: {
    readRecovery: async () => ({ pending: { resetId: 'df8ea882-bcde-4123-8e11-321ef739daca',
      privateKey: 'never-public' } }),
    recover: async () => ({ resetId: 'df8ea882-bcde-4123-8e11-321ef739daca',
      status: 'aborted', cleanupComplete: true, activated: true, privateKey: 'never-public' }),
  } });
  const read = await fetch(broken.base + '/reset-recovery', { headers });
  assert.equal(read.status, 503);
  assert.ok(!(await read.text()).includes('never-public'));
  const post = await broken.request('/reset-recovery', {
    resetId: 'df8ea882-bcde-4123-8e11-321ef739daca' }, headers);
  assert.equal(post.status, 503);
  assert.ok(!(await post.text()).includes('never-public'));
});


test('practice POST and exact GET use only current shop cookie authority and a closed DTO', async t => {
  const operationId='11111111-1111-4111-8111-111111111111';
  const value={operationId,status:'pending',sceneId:null,canResume:true};
  const calls=[];
  const f=await fixture(t,{}, {practices:{
    create:async(user,id)=>{assert.equal(user,context);calls.push(['create',id]);return value;},
    read:async(user,id)=>{assert.equal(user,context);calls.push(['read',id]);return value;},
  }});
  const headers={Cookie:`dvaia_shop_session=${token}`};
  assert.equal((await f.request('/practices',{operationId})).status,401);
  assert.equal((await f.request('/practices',{operationId,ownerId:91},headers)).status,400);
  assert.deepEqual(await (await f.request('/practices',{operationId},headers)).json(),value);
  assert.deepEqual(await (await fetch(f.base+'/practices/'+operationId,{headers})).json(),value);
  assert.deepEqual(calls,[['create',operationId],['read',operationId]]);
});
test('practice capacity rejection identifies exact UUID and never reports publication', async t => {
  const operationId='11111111-1111-4111-8111-111111111111';
  const f=await fixture(t,{}, {practices:{create:async()=>{throw Object.assign(Error('private detail'),{code:'SHOP_PRACTICE_CAPACITY'});}}});
  const response=await f.request('/practices',{operationId},{Cookie:`dvaia_shop_session=${token}`});
  assert.equal(response.status,409);const body=await response.json();
  assert.equal(body.code,'SHOP_PRACTICE_CAPACITY');assert.equal(body.operationId,operationId);
  assert.equal(JSON.stringify(body).includes('private detail'),false);
});
test('practice router denies malformed or excessive service projections', async t => {
  const operationId='11111111-1111-4111-8111-111111111111';
  const f=await fixture(t,{}, {practices:{create:async()=>({operationId,status:'published',sceneId:operationId,canResume:false,bearer:'private'})}});
  const response=await f.request('/practices',{operationId},{Cookie:`dvaia_shop_session=${token}`});
  assert.equal(response.status,503);assert.equal(JSON.stringify(await response.json()).includes('private'),false);
});

test('shop progress reads bind cookie identity and admin role with bounded selectors', async t => {
  const principalId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  const admin = { ...context, role: 'admin' };
  let current = context;
  const calls = [];
  const f = await fixture(t, { authenticate: async value => value === token ? current : null }, {
    assessmentProgress: {
      readSelf: async user => { calls.push(['self', user]); return { completedObjectives: 0 }; },
      listLearners: async (user, input) => { calls.push(['list', user, input]); return { learners: [], nextCursor: null }; },
      readLearner: async (user, input) => { calls.push(['learner', user, input]); return { completedObjectives: 0 }; },
    },
  });
  const headers = { Cookie: `dvaia_shop_session=${token}` };
  assert.equal((await fetch(f.base + '/progress')).status, 401);
  assert.equal((await fetch(f.base + '/progress', { headers })).status, 200);
  assert.equal(calls[0][1], context);
  assert.equal((await fetch(f.base + '/progress?tenantId=foreign', { headers })).status, 400);
  assert.equal((await fetch(f.base + '/admin/progress/learners', { headers })).status, 403);
  assert.equal((await fetch(f.base + '/admin/progress/' + principalId, { headers })).status, 403);
  current = admin;
  assert.equal((await fetch(f.base + '/admin/progress/learners?limit=5&cursor=12', { headers })).status, 200);
  assert.deepEqual(calls.at(-1), ['list', admin, { limit: 5, cursor: 12 }]);
  assert.equal((await fetch(f.base + '/admin/progress/' + principalId.toUpperCase(), { headers })).status, 200);
  assert.deepEqual(calls.at(-1), ['learner', admin, { targetPrincipalId: principalId }]);
  const before = calls.length;
  for (const query of ['limit=51', 'limit=0', 'cursor=-1', 'cursor=1e2', 'cursor=9999999999', 'limit=1&limit=2', 'tenantId=foreign']) {
    assert.equal((await fetch(f.base + '/admin/progress/learners?' + query, { headers })).status, 400);
  }
  assert.equal(calls.length, before);
  assert.equal(f.calls.some(row => row[0] === 'bootstrap'), false);
});


test('mounted progress uses the standalone cookie across practice reset and denies the same token as bearer',async t=>{
 const {createSecureShopStandaloneAuthService,assertSecureShopStandaloneAuthPrincipal}=require('../server/services/secureshopStandaloneAuth');
 const principalId='11111111-1111-4111-8111-111111111111';
 const shop={...context,principalId,role:'admin',credentialVersion:'1',authorityVersion:'1',expiresAt:new Date(Date.now()+60000).toISOString()};
 let sessionReads=0,progressReads=0,completed=true,resets=0;
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession','rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll','readOrCreateDefaultExecutionSession']
  .map(name=>[name,async()=>assert.fail('Unexpected shop session mutation: '+name)]));
 repository.readCurrentSession=async hash=>{sessionReads++;assert.equal(hash,require('node:crypto').createHash('sha256').update(token).digest('hex'));return shop;};
 const service=createSecureShopStandaloneAuthService({repository});
 const resetId='df8ea882-bcde-4123-8e11-321ef739daca';
 const f=await fixture(t,{authenticate:service.authenticate},{assessmentProgress:{readSelf:async user=>{
  assertSecureShopStandaloneAuthPrincipal(user);assert.equal(user.principalId,principalId);assert.equal(user.sessionId,context.sessionId);progressReads++;
  return {completedObjectives:completed?1:0,totalObjectives:1,objectives:[{objectiveId:'ss_file_path_traversal_read',completed}]};}},
  reset:{reset:async(user)=>{assertSecureShopStandaloneAuthPrincipal(user);assert.equal(user.principalId,principalId);resets++;completed=false;return{resetId,status:'committed',cleanupComplete:true};}}});
 const bearer=await fetch(f.base+'/progress',{headers:{Authorization:'Bearer '+token}});assert.equal(bearer.status,401);assert.equal(sessionReads,0);assert.equal(progressReads,0);
 const headers={Cookie:'dvaia_shop_session='+token};
 const host=require('node:fs').readFileSync(require('node:path').join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8');
 const readSource=host.slice(host.indexOf('        const publicProgress=async()=>'),host.indexOf('        const sourceFor=async reference=>'));
 const page={evaluate:async work=>require('node:vm').runInNewContext('('+String(work)+')()',{
  AbortSignal,fetch:async(url,options)=>{assert.equal(url,'/api/secureshop/auth/progress');assert.equal(options.credentials,'same-origin');assert.equal(options.headers,undefined);return fetch(f.base+'/progress',{...options,headers});}})};
 const readProgress=Function('page','assert',readSource+';return publicProgress;')(page,assert);
 assert.equal((await readProgress()).completedObjectives,1);
 const reset=await f.request('/reset',{launchId:'af8ea882-bcde-4123-8e11-321ef739daca',expectedGeneration:1,idempotencyKey:'cf8ea882-bcde-4123-8e11-321ef739daca',sceneId:'bf8ea882-bcde-4123-8e11-321ef739daca',confirmation:'RESET_SHARED_PRACTICE'},headers);
 assert.equal(reset.status,200);assert.equal(resets,1);
 assert.equal((await readProgress()).completedObjectives,0);
 assert.equal(progressReads,2);assert.equal(sessionReads,3);
});
