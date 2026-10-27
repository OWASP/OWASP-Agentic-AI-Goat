'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createSecureShopBoundGateway } = require('../server/routes/secureshop/boundGateway');
const { createBoundReviewsRouter } = require('../server/routes/secureshop/boundReviews');
const { createBoundPromptPolicyService } = require('../server/services/secureshopBoundPromptPolicyService');

const launchBearer = 'g'.repeat(43);
const siblingLaunchBearer = 'h'.repeat(43);
const currentSessionId = '30000000-0000-4000-8000-000000000091';
const otherSessionId = '40000000-0000-4000-8000-0000000000aa';
const launchScope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000091',
  scenarioId: '20000000-0000-4000-8000-000000000091', generation: 4,
  platformOwnerId: 91, platformSessionId: 901 });
const siblingLaunchScope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000092',
  scenarioId: '20000000-0000-4000-8000-000000000092', generation: 2,
  platformOwnerId: 92, platformSessionId: 902 });

async function fixture(t,{resolveCapabilityOverride, boundDispatch=false, customerChatRouter, couponProbeRouter, avatarUploadRouter, accountAvatar, productManualIngestion, fileSummaryRouter, filePathSummaryRouter, productSearchRouter, orderStatusRouter, idorLessonRouter, ticketAgentRouter, searchEchoRouter, commerceOverrides, ownedMcpService, mcpTrustRouter, systemConfigRouter, systemDiagnosticRouter, systemRestartRouter, adminAssistantRuntime, personaAuthOverrides, catalogOverrides, accountOverrides, admin, personaObservations, promptPolicies, promptPolicyTaskTargets, assertLaunchCurrent = async () => {}}={}) {
  const calls = []; let legacyCalls = 0; let launchCalls = 0;
  const launches = { assertCurrent: assertLaunchCurrent, async resolveCapability(value) {
    launchCalls += 1;
    return resolveCapabilityOverride ? resolveCapabilityOverride(value) : value === launchBearer ? launchScope : value === siblingLaunchBearer ? siblingLaunchScope : null;
  } };
  function authenticatePersona(req, res, next) {
    const match = /^Bearer (customer|merchant|admin)-(\d+)$/.exec(req.get('authorization') || '');
    if (!match) return res.status(401).json({ error: 'Shop authentication required' });
    req.ssUser = { id: Number(match[2]), role: match[1], username: `${match[1]}-name`,
      email: `${match[1]}@example.test`, password: 'private', platformOwnerId: 999 };
    req.ssPersonaSession = Object.freeze({ sessionId: currentSessionId, authorityVersion:'2',
      expiresAt: '2026-09-19T00:00:00.000Z' });
    return next();
  }
  const reviews = {
    async listProductReviews(input) { calls.push(['reviews', input]); return { reviews: [], total: 0 }; },
    async submitReview(input) { calls.push(['submit', input]); return { id: 7 }; },
    async listMerchantReviews(input) { calls.push(['merchantReviews', input]);
      return { rows: [], total: 0, counts: { pending: 0, approved: 0, rejected: 0 } }; },
    async approveReview(input) { calls.push(['approve', input]); return { applied: true }; },
    async rejectReview(input) { calls.push(['reject', input]); return { applied: true }; },
  };
  const reviewsRouter = createBoundReviewsRouter({ launches, authenticatePersona,
    service: reviews, moderation: { async moderateReviews(input) {
      calls.push(['moderate', input]);
      return { ok: true, processed: 0, decisions: [], stopReason: 'end_turn', replayed: false };
    } } });
  const personaAuth = {
    async login(input) { calls.push(['login', input]); return { ok: true,
      token: 'bound-token', user: { id: 41, username: input.username, role: 'customer' } }; },
    async logout(input) { calls.push(['logout', input]); return { ok: true }; },
    async renew(input) { calls.push(['renew', input]); return { ok: true, token: 'renewed-token',
      user: { id: 41, username: 'student_customer', role: 'customer' },
      expiresAt: '2026-09-13T23:30:00.000Z' }; },
    async listSessions(input) { calls.push(['sessions', input]); return [{ id: currentSessionId,
      user_agent: 'Controlled Browser', ip: '127.0.0.1', created_at: '2026-09-18T00:00:00.000Z',
      last_seen_at: '2026-09-18T00:01:00.000Z', is_current: true }]; },
    async revokeOwnedSession(input) { calls.push(['sessionRevoke', input]); return true; },
    async changePassword(input) { calls.push(['passwordChange', input]); return { ok: true }; },
    async listApiKey(input) { calls.push(['apiKeyList', input]); return {
      api_key: 'sk_ss_live_11111111111111111111111111111111',
      created_at: '2026-09-18T00:00:00.000Z', version: 1 }; },
    async rotateApiKey(input) { calls.push(['apiKeyRotate', input]); return { ok: true,
      api_key: 'sk_ss_live_22222222222222222222222222222222',
      created_at: '2026-09-18T00:00:00.000Z', version: 2 }; },
    async authenticateApiKey(input) { calls.push(['apiKeyAuthenticate', input]);
      if (input.presentedKey !== 'sk_ss_live_11111111111111111111111111111111'
          || input.scope.launchId !== launchScope.launchId) {
        throw Object.assign(new Error('invalid'), { code: 'SHOP_API_KEY_INVALID' });
      }
      return { user: { id: 41, username: 'student_customer', email: 'customer@example.test',
        role: 'customer', full_name: null, phone: null }, apiKeyVersion: 1 }; },
    ...personaAuthOverrides,
  };
  const catalog = {
    async listProducts(input) {
      calls.push(['products', input]);
      return { products: [{ id: 3, name: 'Trail mug', description: 'Public', price: 12,
        avg_rating: 4, review_count: 2, private_owner: 91 }], count: 1, total: 1,
      privateGeneration: 4 };
    },
    async getProduct(input) {
      calls.push(['product', input]);
      return { product: { id: input.productId, name: 'Trail mug', description_html: '<b>Raw teaching text</b>',
        images: ['/owned.png'], secret: 'omit' }, reviews: [{ id: 8, body: '<i>review</i>', rating: 5,
        status: 'approved', moderator_kind: 'manual', created_at: '2026-09-13T00:00:00Z',
        body_sha256: 'omit' }] };
    },
    async listMerchantProducts(input) {
      calls.push(['merchantProducts', input]);
      return { products: [{ id: 3, name: 'Trail mug', retailer_id: 12, template_source: 'raw' }],
        total: 1, categories: ['Home'], private: true };
    },
    async createMerchantProduct(input) { calls.push(['merchantProductCreate', input]); return { productId: 71 }; },
    async updateMerchantProduct(input) { calls.push(['merchantProductUpdate', input]); return { productId: input.productId }; },
    async archiveMerchantProduct(input) { calls.push(['merchantProductArchive', input]); return true; },
    async categories(input) {
      calls.push(['categories', input]);
      return { categories: [{ id: 1, name: 'Home', description: 'Home category' },
        { id: 2, name: 'Outdoors', description: null }], private: true };
    },
  };
  Object.assign(catalog, catalogOverrides);
  const commerce = {
    async merchantTopProducts(input) { calls.push(['merchantTopProducts', input]); return {rows:[{id:3,name:'Owned purchase',revenue:6.75}],periodDays:input.days,source:'owned-commerce'}; },
    async merchantOverview(input) { calls.push(['merchantOverview', input]); return {
      kpis: { ok: true, retailer_id: input.persona.id, orders: { value: 3 } },
      salesChart: { ok: true, retailer_id: input.persona.id, days: input.days, series: [] },
    }; },
    async recommendations(input) { calls.push(['recommendations', input]); return {feed:[{id:3,name:'Owned',price:2,private:'hidden',recommendation_reason:'catalog_fallback'}],provenance:{algorithm:'local-category-affinity-v1',modelUsed:false}}; },
    async cart(input){calls.push(['cart',input]);return {items:[],subtotal:0};},
    async applyCoupon(input){calls.push(['coupon',input]);return {ok:true,code:'HALF',discount_percent:50,applied_amount:6};},
    async add(input){calls.push(['cartAdd',input]);return {id:17};},
    async update(input){calls.push(['cartUpdate',input]);return 1;},
    async remove(input){calls.push(['cartRemove',input]);return 1;},
    async summary(input){calls.push(['summary',input]);return {items:[],subtotal:0};},
    async checkout(input){calls.push(['checkout',input]);return {orderId:19,total:12};},
    async orders(input){calls.push(['orders',input]);return [];},
    async order(input){calls.push(['order',input]);return {order:{id:input.orderId,user_id:input.persona.id,total_amount:12,status:'confirmed'},items:[]};},
  };
  Object.assign(commerce, commerceOverrides);
  const account = {
    async profile(input) { calls.push(['profile', input]); return { id: input.persona.id,
      username: `${input.persona.role}-name`, email: `${input.persona.role}@example.test`,
      role: input.persona.role, full_name: null, phone: null }; },
    async updateProfile(input) { calls.push(['profileUpdate', input]); return { id: input.persona.id,
      username: `${input.persona.role}-name`, email: input.email, role: input.persona.role,
      full_name: input.fullName, phone: input.phone }; },
    async addresses(input) { calls.push(['addresses', input]); return []; },
    async createAddress(input) { calls.push(['addressCreate', input]); return { id: 31 }; },
    async updateAddress(input) { calls.push(['addressUpdate', input]); return { id: input.addressId }; },
    async deleteAddress(input) { calls.push(['addressDelete', input]); return 1; },
    ...accountOverrides,
  };
  const app = express();
  app.use(express.json());
  const browserRouter = express.Router();
  const gateway = createSecureShopBoundGateway({ launches, authenticatePersona,
    personaAuth, reviewsRouter, browserRouter, customerChatRouter, couponProbeRouter, avatarUploadRouter, accountAvatar, productManualIngestion, fileSummaryRouter, filePathSummaryRouter, productSearchRouter, orderStatusRouter, idorLessonRouter, catalog, commerce, account, admin, personaObservations, promptPolicies, promptPolicyTaskTargets,
    ...(systemConfigRouter?{systemConfigRouter}:{}),
    ...(systemDiagnosticRouter?{systemDiagnosticRouter}:{}),
    ...(systemRestartRouter?{systemRestartRouter}:{}),
    ...(adminAssistantRuntime ? { adminAssistantRouter:
      require('../server/routes/secureshop/boundRoleChat').createBoundRoleChatRouter({
        role: 'admin', launches, authenticatePersona, runtime: adminAssistantRuntime,
      }) } : {}),
    ...(ownedMcpService?{ownedMcpRegistryRouter:require('../server/routes/secureshop/boundMcpRegistry').createBoundMcpRegistryRouter({service:ownedMcpService,authenticatePersona})}:{}),
    ...(mcpTrustRouter?{mcpTrustRouter}:{}),
    ...(ticketAgentRouter?{ticketAgentRouter}:{}), ...(searchEchoRouter?{searchEchoRouter}:{}), });
  app.use('/api/secureshop',boundDispatch
    ?require('../server/middleware/secureshopBoundDispatch').createSecureShopBoundDispatch({getGateway:()=>gateway})
    :gateway);
  app.use('/api/secureshop', (req, res) => {
    legacyCalls += 1;
    res.json({ legacy: true, method: req.method, path: req.path });
  });
  const server = await new Promise(resolve => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { base: `http://127.0.0.1:${server.address().port}/api/secureshop`, calls,
    legacyCalls: () => legacyCalls, launchCalls: () => launchCalls };
}

test('absent admin assistant assessment retries return explicit unavailable and retain the launch fence', async t => {
  const f = await fixture(t);
  for (const leaf of ['system/config', 'policy/instruction']) {
    const url = `${f.base}/agents/admin/assistant/${leaf}/assessment-retry`;
    const request = { method: 'POST', headers: { ...headers('admin', 13),
      'content-type': 'application/json' },
    body: JSON.stringify({ sessionId: currentSessionId, requestId: otherSessionId }) };
    const response = await fetch(url, request);
    assert.equal(response.status, 503, leaf);
    assert.deepEqual(await response.json(), { error: 'Bound SecureShop operation unavailable' });
    const stale = await fetch(url, { ...request, headers: { ...request.headers,
      'x-dvaia-secureshop-launch': 'invalid' } });
    assert.equal(stale.status, 401);
    assert.deepEqual(await stale.json(), { error: 'SecureShop launch unavailable' });
  }
  assert.equal(f.legacyCalls(), 0);
  assert.deepEqual(f.calls, []);
});

test('mounted admin assessment retries retain production persona guards and exact runtime dispatch', async t => {
  const calls = [];
  const runtime = Object.fromEntries(['createSession', 'run', 'readRequest',
    'confirmUserAdministration', 'confirmPolicy', 'confirmMcpRegistry', 'confirmSystemRestart',
    'confirmAcl', 'runAuditJob', 'readAuditJob', 'readAuditOperation', 'readSystemConfigOperation']
    .map(name => [name, async () => { throw Error(`Unexpected runtime call: ${name}`); }]));
  const result = { completed: false, status: 'unconfirmed', modelEvaluated: false };
  for (const name of ['retrySystemConfigAssessment', 'retryPolicyInstructionAssessment']) {
    runtime[name] = async input => { calls.push({ name, input }); return result; };
  }
  const f = await fixture(t, { adminAssistantRuntime: runtime });
  for (const [leaf, method] of [['system/config', 'retrySystemConfigAssessment'],
    ['policy/instruction', 'retryPolicyInstructionAssessment']]) {
    const url = `${f.base}/agents/admin/assistant/${leaf}/assessment-retry`;
    const request = { method: 'POST', headers: { ...headers('admin', 13),
      'content-type': 'application/json' },
    body: JSON.stringify({ sessionId: currentSessionId, requestId: otherSessionId }) };
    const response = await fetch(url, request);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), result);
    const observed = calls.at(-1);
    assert.equal(observed.name, method);
    assert.deepEqual(observed.input.scope, launchScope);
    assert.deepEqual(observed.input.persona, { id: 13, role: 'admin' });
    assert.equal(observed.input.personaSession.sessionId, currentSessionId);
    assert.equal(observed.input.sessionId, currentSessionId);
    assert.equal(observed.input.requestId, otherSessionId);
    const count = calls.length;
    const missingAuth = await fetch(url, { ...request, headers: {
      'x-dvaia-secureshop-launch': launchBearer, 'content-type': 'application/json' } });
    assert.equal(missingAuth.status, 401);
    const wrongRole = await fetch(url, { ...request, headers: { ...request.headers,
      authorization: 'Bearer merchant-13' } });
    assert.equal(wrongRole.status, 403);
    assert.equal(calls.length, count);
  }
  assert.equal(calls.length, 2);
  assert.equal(f.legacyCalls(), 0);
});

test('product capacity reports a conflict without losing authentication or falling through', async t => {
  const f = await fixture(t, { catalogOverrides: {
    async listProducts() { throw Object.assign(new Error(`private ${launchBearer}`), { code: 'PRODUCT_TARGET_CAPACITY' }); },
  } });
  const response = await fetch(`${f.base}/products`, { headers: headers() });
  assert.equal(response.status, 409);
  const body = await response.json();
  assert.match(body.error, /retained shop limit/);
  assert.equal(JSON.stringify(body).includes(launchBearer), false);
  assert.equal(f.legacyCalls(), 0);
});

test('MCP trust routes fail closed by default and an explicit router owns only its mounted paths',async t=>{
  const disabled=await fixture(t);const unavailable=await fetch(`${disabled.base}/v2/mcp-trust/readiness`,{headers:headers('admin',13)});
  assert.equal(unavailable.status,200);assert.deepEqual(await unavailable.json(),{ready:false});
  const route=express.Router();route.get('/v2/mcp-trust/readiness',(_req,res)=>res.json({ready:true}));
  const enabled=await fixture(t,{mcpTrustRouter:route});const ready=await fetch(`${enabled.base}/v2/mcp-trust/readiness`,{headers:headers('admin',13)});
  assert.equal(ready.status,200);assert.deepEqual(await ready.json(),{ready:true});
});

for (const [option, endpoint] of [['systemConfigRouter','config-read'],['systemDiagnosticRouter','diagnostic'],['systemRestartRouter','restart']]) {
 test(`prepared ${option} is mounted only through the bound launch gateway`,async t=>{
  const route=express.Router();route.get(`/admin/system/${endpoint}`,(req,res)=>res.json({ok:true,
   launchId:req.ssLaunch.launchId}));
  const enabled=await fixture(t,{[option]:route});
  const response=await fetch(`${enabled.base}/admin/system/${endpoint}`,{headers:headers('admin',13)});
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{ok:true,launchId:launchScope.launchId});
  assert.equal(enabled.legacyCalls(),0);
  const absent=await fixture(t);const unavailable=await fetch(`${absent.base}/admin/system/${endpoint}`,{headers:headers('admin',13)});
  assert.equal(unavailable.status,503);assert.deepEqual(await unavailable.json(),{error:'Bound SecureShop operation unavailable'});
  assert.equal(absent.legacyCalls(),0);
 });
}

function headers(role = 'customer', id = 41, launch = launchBearer) {
  return { authorization: `Bearer ${role}-${id}`, 'x-dvaia-secureshop-launch': launch };
}

test('separate bound Account avatar multipart admits all roles without changing merchant manual authority', async t => {
  const observed = [];
  const requestId = '70000000-0000-4000-8000-000000000041';
  const accountAvatar = {
    async upload(input) {
      observed.push(['post', input]);
      return { ok: true, kind: 'avatar', scope_id: String(input.persona.id),
        requestId: input.requestId, status: 'completed',
        operationId: '80000000-0000-4000-8000-000000000041',
        filename: input.filename, mime: input.mime, size_bytes: input.bytes.length,
        public: input.public, is_traversal: input.filename.includes('....//'), replayed: false };
    },
    async read(input) {
      observed.push(['get', input]);
      return { ok: false, kind: 'avatar', scope_id: String(input.persona.id),
        requestId: input.requestId, status: 'uncertain', operationId: null,
        filename: '', mime: '', size_bytes: 0, public: false,
        is_traversal: false, replayed: false };
    }
  };
  const f = await fixture(t, { accountAvatar });
  const form = scope => {
    const body = new FormData();
    body.append('file', new Blob(['<svg>test</svg>'], { type: 'image/svg+xml' }), '....//chosen.svg');
    body.append('kind', 'avatar'); body.append('scope_id', String(scope));
    body.append('mime', 'image/svg+xml'); body.append('public', 'true');
    body.append('requestId', requestId);
    return body;
  };
  for (const role of ['customer', 'merchant', 'admin']) {
    const response = await fetch(`${f.base}/uploads/avatar`, { method: 'POST',
      headers: headers(role, 41), body: form(41) });
    assert.equal(response.status, 200);
    const receipt = await response.json();
    assert.equal(receipt.filename, '....//chosen.svg');
    assert.equal(receipt.mime, 'image/svg+xml');
    assert.equal(receipt.public, true);
    assert.equal(receipt.is_traversal, true);
    assert.equal(receipt.scope_id, '41');
    assert.equal(receipt.requestId, requestId);
  }
  assert.equal(observed.length, 3);
  assert.deepEqual(observed.map(([, value]) => value.persona.role), ['customer', 'merchant', 'admin']);
  assert.ok(observed.every(([, value]) => value.filename === '....//chosen.svg'
    && value.personaSession.sessionId === currentSessionId));
  for (const [role, scope] of [['customer', 42], ['merchant', 42], ['admin', 42]]) {
    const denied = await fetch(`${f.base}/uploads/avatar`, { method: 'POST',
      headers: headers(role, 41), body: form(scope) });
    assert.equal(denied.status, 400);
  }
  assert.equal(observed.length, 3);
  const read = await fetch(`${f.base}/uploads/avatar/operations/${requestId}`, {
    headers: headers('customer', 41) });
  assert.equal(read.status, 200);
  assert.equal((await read.json()).status, 'uncertain');
  assert.equal(observed.length, 4);
  const manual = await fetch(`${f.base}/uploads`, { method: 'POST',
    headers: headers('customer', 41), body: form(41) });
  assert.equal(manual.status, 503, 'avatar route cannot broaden the existing manual route');
  assert.equal(observed.length, 4);
  assert.equal(f.legacyCalls(), 0);
});

test('actual Account avatar multipart reaches owner journal and legacy sink inside private operation root', async t => {
  const directory = await fs.mkdtemp(path.join(__dirname, '../tasks/tmp/account-avatar-gateway-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const environment = { SECURESHOP_UPLOAD_ROOT: directory };
  const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
  const { normalizeAdmission, normalizeEffect } = require('../server/services/secureshopBoundUploadReceipt');
  const { createSecureShopBoundAccountAvatar } = require('../server/services/secureshopBoundAccountAvatar');
  const execution = launchScope, target = createSceneBinding({ ...execution,
    targetId: '50000000-0000-4000-8000-000000000041' }, {
    sceneId: '60000000-0000-4000-8000-000000000041', sceneGeneration: 2,
    grantId: '70000000-0000-4000-8000-000000000041', execution,
    withLease: work => work()
  });
  const admissions = [], effects = new Map();
  const service = createSecureShopBoundAccountAvatar({
    pool: { async query() { return { rows: [] }; } },
    launches: { async assertCurrent() {} }, resolveTarget: async () => target,
    personaAuthority: { async capture(input) { return {
      binding: { ...execution, personaId: input.personaId, role: input.role,
        sessionId: input.sessionId, authorityVersion: input.authorityVersion },
      async assertRemoteAdmission() {} };
    } },
    modeAuthority: { async capture() { return {
      snapshot: { mode: 'vuln', generation: 1, modeStamp: 'a'.repeat(64) },
      async assertCurrent() {} };
    }, assertToken: value => value },
    journal: { async claim(value) { const admitted = normalizeAdmission(value);
      admissions.push(admitted); return admitted; },
    async recordEffect(admitted, value) { const effect = normalizeEffect(value, admitted);
      effects.set(admitted.operationId, effect); return effect; } },
    effects: { async find(admitted) { return effects.get(admitted.operationId) || null; } },
    writer: require('../server/services/secureshopUploadWriter').createSecureShopUploadWriter({ environment }),
    traversalWriter: require('../server/services/secureshopV46TraversalWriter').createSecureShopV46TraversalWriter({ environment }),
    read: require('../server/services/secureshopUploadAssetReader').createSecureShopUploadAssetReader({ environment }),
    readTraversal: require('../server/services/secureshopV46TraversalAssetReader').createSecureShopV46TraversalAssetReader({ environment })
  });
  const f = await fixture(t, { accountAvatar: service });
  const body = new FormData();
  body.append('file', new Blob(['<svg>owned</svg>'], { type: 'image/svg+xml' }), '....//picked.svg');
  for (const [key, value] of Object.entries({ kind: 'avatar', scope_id: '41',
    mime: 'image/svg+xml', public: 'true', requestId: '80000000-0000-4000-8000-000000000041' }))
    body.append(key, value);
  const response = await fetch(`${f.base}/uploads/avatar`, { method: 'POST',
    headers: headers('customer', 41), body });
  assert.equal(response.status, 200);
  const receipt = await response.json();
  assert.equal(receipt.status, 'completed');
  assert.equal(receipt.filename, '....//picked.svg');
  assert.equal(receipt.public, true);
  assert.equal(receipt.is_traversal, true);
  assert.equal(admissions.length, 1);
  const effect = effects.get(receipt.operationId);
  assert.equal(effect.file.storedVirtualPath,
    `operations/${admissions[0].storageKey}/avatars/picked.svg`);
  assert.deepEqual(await fs.readFile(path.join(directory, effect.file.storedVirtualPath)),
    Buffer.from('<svg>owned</svg>'));
});

test('enabled merchant manual route still denies other roles before parser or service effects', async t => {
  let manualCalls = 0, avatarCalls = 0;
  const f = await fixture(t, {
    productManualIngestion: { async upload() { manualCalls += 1; throw Error('unexpected manual write'); },
      async readReceipt() { manualCalls += 1; throw Error('unexpected manual read'); } },
    accountAvatar: { async upload() { avatarCalls += 1; throw Error('unexpected avatar write'); },
      async read() { avatarCalls += 1; throw Error('unexpected avatar read'); } }
  });
  for (const role of ['customer', 'admin']) {
    const body = new FormData();
    body.append('file', new Blob(['x']), 'chosen.txt');
    body.append('kind', 'product_manual');
    body.append('scope_id', '41');
    body.append('mime', 'text/plain');
    body.append('public', 'true');
    const response = await fetch(`${f.base}/uploads`, { method: 'POST',
      headers: headers(role, 41), body });
    assert.equal(response.status, 403);
  }
  assert.equal(manualCalls, 0);
  assert.equal(avatarCalls, 0);
});

test('missing launch delegates unchanged while body and query authority cannot select bound mode', async t => {
  const f = await fixture(t);
  for (const [path, init] of [
    ['/products', {}],
    ['/v2/auth/users/me/addresses', {}],
    [`/products?${new URLSearchParams({ 'x-dvaia-secureshop-launch': launchBearer })}`, {}],
    ['/cart', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ launch: launchBearer }) }],
  ]) {
    const response = await fetch(f.base + path, init);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).legacy, true);
  }
  assert.equal(f.legacyCalls(), 4);
  assert.equal(f.launchCalls(), 0);
  assert.deepEqual(f.calls, []);
});

test('invalid or duplicate launch authority fails before persona and never reaches legacy', async t => {
  const f = await fixture(t);
  const invalid = await fetch(`${f.base}/cart`, { headers: headers('customer', 41, 'x'.repeat(43)) });
  assert.equal(invalid.status, 401);
  assert.deepEqual(await invalid.json(), { error: 'SecureShop launch unavailable' });
  assert.equal(invalid.headers.get('x-dvaia-secureshop-launch-state'), 'unavailable');

  const duplicate = await new Promise((resolve, reject) => {
    const url = new URL(`${f.base}/products`);
    const request = require('node:http').request({ hostname: url.hostname, port: url.port,
      path: url.pathname, method: 'GET', headers: {
        authorization: 'Bearer customer-41',
        'x-dvaia-secureshop-launch': [launchBearer, launchBearer],
      } }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers,
        body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    request.on('error', reject); request.end();
  });
  assert.equal(duplicate.status, 401);
  assert.deepEqual(duplicate.body, { error: 'SecureShop launch unavailable' });
  assert.equal(duplicate.headers['x-dvaia-secureshop-launch-state'], 'unavailable');
  assert.equal(f.legacyCalls(), 0);
  assert.deepEqual(f.calls, []);
});

test('only launch authority failures carry the unavailable marker', async t => {
  const invalidCredentials = await fixture(t, { personaAuthOverrides: {
    async login() {
      throw Object.assign(new Error('wrong password'), { code: 'SHOP_CREDENTIALS_INVALID' });
    },
  } });
  const denied = await fetch(`${invalidCredentials.base}/v2/auth/login`, { method: 'POST', headers: {
    'content-type': 'application/json', 'x-dvaia-secureshop-launch': launchBearer,
  }, body: JSON.stringify({ username: 'student_customer', password: 'wrong' }) });
  assert.equal(denied.status, 401);
  assert.deepEqual(await denied.json(), { error: 'Invalid shop credentials' });
  assert.equal(denied.headers.get('x-dvaia-secureshop-launch-state'), null);

  const staleLaunch = await fixture(t, { personaAuthOverrides: {
    async login() {
      throw Object.assign(new Error('stale launch'), { code: 'STALE_LAUNCH' });
    },
  } });
  const stale = await fetch(`${staleLaunch.base}/v2/auth/login`, { method: 'POST', headers: {
    'content-type': 'application/json', 'x-dvaia-secureshop-launch': launchBearer,
  }, body: JSON.stringify({ username: 'student_customer', password: 'student-password' }) });
  assert.equal(stale.status, 401);
  assert.deepEqual(await stale.json(), { error: 'SecureShop launch unavailable' });
  assert.equal(stale.headers.get('x-dvaia-secureshop-launch-state'), 'unavailable');

  const foreignOwner = await fixture(t, { personaAuthOverrides: {
    async login() {
      throw Object.assign(new Error('foreign owner'), { code: 'OWNER_MISMATCH' });
    },
  } });
  const foreign = await fetch(`${foreignOwner.base}/v2/auth/login`, { method: 'POST', headers: {
    'content-type': 'application/json', 'x-dvaia-secureshop-launch': launchBearer,
  }, body: JSON.stringify({ username: 'student_customer', password: 'student-password' }) });
  assert.equal(foreign.status, 401);
  assert.deepEqual(await foreign.json(), { error: 'SecureShop launch unavailable' });
  assert.equal(foreign.headers.get('x-dvaia-secureshop-launch-state'), null);
});

test('present launch permits only scoped review routes and never falls through on unknown review paths', async t => {
  const f = await fixture(t);
  const list = await fetch(`${f.base}/products/3/reviews?limit=20`, { headers: headers() });
  assert.equal(list.status, 200);
  assert.deepEqual(await list.json(), { reviews: [], total: 0 });
  assert.equal(f.calls[0][0], 'reviews');
  assert.deepEqual(f.calls[0][1].scope, launchScope);
  assert.deepEqual(f.calls[0][1].persona, { id: 41, role: 'customer' });

  const unknown = await fetch(`${f.base}/products/3/reviews/export`, { headers: headers() });
  assert.equal(unknown.status, 404);
  assert.deepEqual(await unknown.json(), { error: 'Bound SecureShop route not found' });
  assert.equal(f.legacyCalls(), 0);
});

test('persona inbox stays hidden and closed when its feature adapter is absent', async t => {
  const f = await fixture(t);
  const readiness = await fetch(`${f.base}/v2/persona-inbox/readiness`, { headers: headers('merchant', 77) });
  assert.equal(readiness.status, 200);
  assert.deepEqual(await readiness.json(), { ready: false });
  const operation = await fetch(`${f.base}/v2/persona-inbox/read`, { method: 'POST',
    headers: { ...headers('merchant', 77), 'content-type': 'application/json' }, body: '{}' });
  assert.equal(operation.status, 503);
  assert.deepEqual(await operation.json(), { error: 'Persona inbox exercise unavailable' });
  assert.equal(f.legacyCalls(), 0);
});

test('read-only catalog routes keep UI envelopes and strip private service metadata', async t => {
  const f = await fixture(t);
  const listed = await fetch(`${f.base}/products?search=mug&sort=newest&limit=24&offset=0`, { headers: headers() });
  assert.equal(listed.status, 200);
  assert.deepEqual(await listed.json(), { products: [{ id: 3, name: 'Trail mug', description: 'Public',
    price: 12, avg_rating: 4, review_count: 2 }], count: 1, total: 1 });
  assert.deepEqual(f.calls[0][1], { scope: launchScope, persona: { id: 41, role: 'customer' },
    query: { search: 'mug', category: null, minRating: null, maxPrice: null,
      sort: 'newest', page: 1, limit: 24, offset: 0 } });

  const detail = await fetch(`${f.base}/products/3`, { headers: headers() });
  assert.equal(detail.status, 200);
  assert.deepEqual(await detail.json(), { product: { id: 3, name: 'Trail mug',
    description_html: '<b>Raw teaching text</b>', images: ['/owned.png'] },
  reviews: [{ id: 8, body: '<i>review</i>', rating: 5, status: 'approved',
    moderator_kind: 'manual', created_at: '2026-09-13T00:00:00Z' }] });
  assert.equal(f.legacyCalls(), 0);
});

test('bound shop categories require the exact launch and preserve the public envelope', async t => {
  const f = await fixture(t);
  const response = await fetch(`${f.base}/categories`, { headers: headers() });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { categories: [
    { id: 1, name: 'Home', description: 'Home category' },
    { id: 2, name: 'Outdoors', description: null },
  ] });
  assert.deepEqual(f.calls[0][1], { scope: launchScope, persona: { id: 41, role: 'customer' } });
  const stale = await fetch(`${f.base}/categories`, { headers: headers('customer', 41, 'x'.repeat(43)) });
  assert.equal(stale.status, 401);
  assert.equal(stale.headers.get('x-dvaia-secureshop-launch-state'), 'unavailable');
  const foreignPersona = await fetch(`${f.base}/categories`, { headers: headers('merchant', 77) });
  assert.equal(foreignPersona.status, 200);
  assert.equal((await foreignPersona.json()).categories[0].name, 'Home');
  assert.equal(f.legacyCalls(), 0);
});

test('merchant product lookup requires merchant persona and retains legacy response shape', async t => {
  const f = await fixture(t);
  const denied = await fetch(`${f.base}/merchant/products?per_page=100`, { headers: headers() });
  assert.equal(denied.status, 403);
  const response = await fetch(`${f.base}/merchant/products?per_page=100`, { headers: headers('merchant', 77) });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { products: [{ id: 3, name: 'Trail mug', retailer_id: 12,
    template_source: 'raw' }], count: 1, total: 1, page: 1, per_page: 100, pages: 1,
  categories: ['Home'] });
  assert.deepEqual(f.calls[0][1], { scope: launchScope, persona: { id: 77, role: 'merchant' },
    personaSession:{sessionId:currentSessionId,authorityVersion:'2'},
    query: { retailerId: null, page: 1, perPage: 100, sort: 'updated_desc', search: null,
      status: null, category: null } });
  assert.equal(f.legacyCalls(), 0);
});

test('merchant listing create update and archive preserve the visible UI contract and trusted persona', async t => {
  const f = await fixture(t);
  const create = await fetch(`${f.base}/merchant/products`, { method: 'POST',
    headers: { ...headers('merchant', 12), 'content-type': 'application/json' },
    body: JSON.stringify({ title: 'Raw listing', description: '<img src=x onerror=owned()>',
      price: 12.5, images: ['/owned.png'], category: 'Home', template_source: '{{raw}}', retailer_id: 999 }) });
  assert.equal(create.status, 200); assert.deepEqual(await create.json(), { ok: true, product_id: 71 });
  const update = await fetch(`${f.base}/merchant/products/71`, { method: 'PUT',
    headers: { ...headers('merchant', 12), 'content-type': 'application/json' },
    body: JSON.stringify({ patch: { name: 'Renamed', description: '<svg onload=owned()>',
      price: 14, category: null, template_source: '{{still_raw}}', image_url: null } }) });
  assert.equal(update.status, 200); assert.deepEqual(await update.json(), { ok: true, product_id: 71 });
  const archive = await fetch(`${f.base}/merchant/products/71`, { method: 'DELETE',
    headers: headers('merchant', 12) });
  assert.equal(archive.status, 200); assert.deepEqual(await archive.json(), { ok: true });
  const createCall = f.calls.find(([name]) => name === 'merchantProductCreate')[1];
  assert.equal(createCall.persona.id, 12); assert.equal(createCall.listing.retailerId, undefined);
  assert.equal(createCall.listing.description, '<img src=x onerror=owned()>');
  const archived = await fetch(`${f.base}/merchant/products?retailer_id=12&per_page=20&status=archived&sort=stock_asc`,
    { headers: headers('merchant', 12) });
  assert.equal(archived.status, 200);
  const listCall = f.calls.filter(([name]) => name === 'merchantProducts').at(-1)[1];
  assert.equal(listCall.query.status, 'archived'); assert.equal(listCall.query.sort, 'stock_asc');
  assert.equal(f.legacyCalls(), 0);
});

test('merchant listing writes reject malformed values and non-merchant personas before effects', async t => {
  const f = await fixture(t);
  for (const [path, init] of [
    ['/merchant/products', { method: 'POST', headers: { ...headers('merchant', 12), 'content-type': 'application/json' },
      body: JSON.stringify({ title: 'bad', description: '', price: '12', images: [], category: null,
        template_source: null, retailer_id: 12 }) }],
    ['/merchant/products/71', { method: 'PUT', headers: { ...headers('merchant', 12), 'content-type': 'application/json' },
      body: JSON.stringify({ patch: {} }) }],
    ['/merchant/products/71', { method: 'DELETE', headers: { ...headers('merchant', 12), 'content-type': 'application/json' },
      body: JSON.stringify({ force: true }) }],
    ['/merchant/products', { method: 'POST', headers: { ...headers('customer', 41), 'content-type': 'application/json' },
      body: JSON.stringify({ title: 'x', description: '', price: 1, images: [], category: null,
        template_source: null, retailer_id: 41 }) }],
  ]) {
    const response = await fetch(f.base + path, init);
    assert.ok([400, 403].includes(response.status), `${path}: ${response.status}`);
  }
  assert.equal(f.calls.some(([name]) => name.startsWith('merchantProduct') && name !== 'merchantProducts'), false);
});

test('bound login/logout and profile reads work while shared registration remains unavailable', async t => {
  const f = await fixture(t);
  const login = await fetch(`${f.base}/v2/auth/login`, { method: 'POST', headers: {
    'content-type': 'application/json', 'x-dvaia-secureshop-launch': launchBearer,
  }, body: JSON.stringify({ username: 'student_customer', password: 'student-password' }) });
  assert.equal(login.status, 200);
  assert.equal((await login.json()).token, 'bound-token');
  const loginInput = f.calls.find(call => call[0] === 'login')[1];
  assert.equal(loginInput.ip, '127.0.0.1');
  assert.equal(typeof loginInput.userAgent, 'string');
  assert.ok(Buffer.byteLength(loginInput.userAgent, 'utf8') > 0);

  const whoami = await fetch(`${f.base}/v2/auth/whoami`, { headers: headers('merchant', 77) });
  assert.equal(whoami.status, 200);
  assert.deepEqual(await whoami.json(), { ok: true, user: { id: 77, username: 'merchant-name',
    email: 'merchant@example.test', role: 'merchant', full_name: null, phone: null },
  expiresAt: '2026-09-19T00:00:00.000Z' });

  const logout = await fetch(`${f.base}/v2/auth/logout`, { method: 'POST',
    headers: headers('customer', 41) });
  assert.equal(logout.status, 200);
  assert.deepEqual(await logout.json(), { ok: true, next: 'login' });

  const renewed = await fetch(`${f.base}/v2/auth/renew`, { method: 'PATCH', headers: headers('customer', 41) });
  assert.equal(renewed.status, 200);
  assert.equal((await renewed.json()).token, 'renewed-token');

  for (const [path, method] of [['/v2/auth/register', 'POST'],
    ['/v2/auth/switch-role', 'POST']]) {
    const response = await fetch(f.base + path, { method, headers: { ...headers(),
      'content-type': 'application/json' }, body: '{}' });
    assert.equal(response.status, 503, `${method} ${path}`);
    assert.deepEqual(await response.json(), { error: 'Bound SecureShop operation unavailable' });
  }
  assert.deepEqual(f.calls.find(call => call[0] === 'login')[1].scope, launchScope);
  assert.equal(f.calls.find(call => call[0] === 'logout')[1].token, 'customer-41');
  assert.equal(f.calls.find(call => call[0] === 'renew')[1].token, 'customer-41');
  assert.equal(f.legacyCalls(), 0);
});

test('profile and address routes preserve UI DTOs and authenticated persona ownership', async t => {
  const address = { label: 'Home', line1: '1 Main', line2: '', city: 'Oakland', state: 'CA',
    zip: '94601', phone: '', is_default: true };
  const f = await fixture(t, { accountOverrides: {
    async addresses(input) { f.calls.push(['addresses', input]); return [{ id: 31, ...address,
      line2: null, phone: null, created_at: '2026-09-18T00:00:00Z', private: true }]; },
  } });
  const profile = await fetch(`${f.base}/v2/auth/users/me`, { headers: headers() });
  assert.deepEqual(await profile.json(), { ok: true, user: { id: 41, username: 'customer-name',
    email: 'customer@example.test', role: 'customer', full_name: null, phone: null } });
  const updated = await fetch(`${f.base}/v2/auth/users/me`, { method: 'PUT', headers: {
    ...headers(), 'content-type': 'application/json' }, body: JSON.stringify({
    full_name: 'Student Customer', email: 'student@example.test', phone: '555-0100' }) });
  assert.deepEqual(await updated.json(), { ok: true, user: { id: 41, username: 'customer-name',
    email: 'student@example.test', role: 'customer', full_name: 'Student Customer', phone: '555-0100' } });
  const listed = await fetch(`${f.base}/v2/auth/users/me/addresses`, { headers: headers() });
  assert.deepEqual(await listed.json(), { addresses: [{ id: 31, ...address, line2: null, phone: null,
    created_at: '2026-09-18T00:00:00Z' }] });
  const created = await fetch(`${f.base}/v2/auth/users/me/addresses`, { method: 'POST', headers: {
    ...headers(), 'content-type': 'application/json' }, body: JSON.stringify(address) });
  assert.deepEqual(await created.json(), { ok: true, id: 31 });
  const changed = await fetch(`${f.base}/v2/auth/users/me/addresses/31`, { method: 'PUT', headers: {
    ...headers(), 'content-type': 'application/json' }, body: JSON.stringify(address) });
  assert.deepEqual(await changed.json(), { ok: true });
  const removed = await fetch(`${f.base}/v2/auth/users/me/addresses/31`, { method: 'DELETE',
    headers: headers() });
  assert.deepEqual(await removed.json(), { ok: true });
  for (const name of ['profile', 'profileUpdate', 'addresses', 'addressCreate', 'addressUpdate', 'addressDelete']) {
    const call = f.calls.find(row => row[0] === name);
    assert.equal(call[1].persona.id, 41); assert.deepEqual(call[1].scope, launchScope);
    assert.deepEqual(call[1].personaSession,{sessionId:currentSessionId,authorityVersion:'2'});
  }
});

test('account routes reject caller ownership, malformed values and foreign address updates', async t => {
  const f = await fixture(t, { accountOverrides: { async updateAddress() { return null; } } });
  for (const body of [
    { full_name: 'A', email: 'a@example.test', phone: null, user_id: 99 },
    { full_name: 'A', email: true, phone: null },
  ]) assert.equal((await fetch(`${f.base}/v2/auth/users/me`, { method: 'PUT', headers: {
    ...headers(), 'content-type': 'application/json' }, body: JSON.stringify(body) })).status, 400);
  const base = { label: null, line1: '1 Main', line2: null, city: null, state: null,
    zip: null, phone: null, is_default: false };
  for (const body of [{ ...base, is_default: 1 }, { ...base, user_id: 99 }, [base]]) {
    assert.equal((await fetch(`${f.base}/v2/auth/users/me/addresses`, { method: 'POST', headers: {
      ...headers(), 'content-type': 'application/json' }, body: JSON.stringify(body) })).status, 400);
  }
  const foreign = await fetch(`${f.base}/v2/auth/users/me/addresses/31`, { method: 'PUT', headers: {
    ...headers(), 'content-type': 'application/json' }, body: JSON.stringify(base) });
  assert.equal(foreign.status, 404);
  assert.equal((await fetch(`${f.base}/v2/auth/users/me/addresses/31`, { method: 'DELETE', headers: {
    ...headers(), 'content-type': 'application/json' }, body: JSON.stringify({ unexpected: true }) })).status, 400);
  for (const [path, method] of [['/v2/auth/register', 'POST']]) {
    const response = await fetch(f.base + path, { method, headers: { ...headers(),
      ...(method === 'GET' ? {} : { 'content-type': 'application/json' }) },
    ...(method === 'GET' ? {} : { body: '{}' }) });
    assert.equal(response.status, 503, `${method} ${path}`);
    assert.deepEqual(await response.json(), { error: 'Bound SecureShop operation unavailable' });
  }
});

test('API keys list and rotate only for the JWT persona inside the trusted launch', async t => {
  const f = await fixture(t);
  const listed = await fetch(`${f.base}/v2/auth/users/me/api-keys`, { headers: headers() });
  assert.equal(listed.status, 200);
  assert.deepEqual(await listed.json(), { api_key: 'sk_ss_live_11111111111111111111111111111111',
    created_at: '2026-09-18T00:00:00.000Z', version: 1 });
  const rotated = await fetch(`${f.base}/v2/auth/users/me/api-keys/rotate`, {
    method: 'POST', headers: headers(),
  });
  assert.equal(rotated.status, 200);
  assert.deepEqual(await rotated.json(), { ok: true,
    api_key: 'sk_ss_live_22222222222222222222222222222222',
    created_at: '2026-09-18T00:00:00.000Z', version: 2 });
  for (const name of ['apiKeyList', 'apiKeyRotate']) {
    const input = f.calls.find(call => call[0] === name)[1];
    assert.deepEqual(input.scope, launchScope);
    assert.deepEqual(input.shopPersona, { id: 41, role: 'customer' });
  }
  assert.equal((await fetch(`${f.base}/v2/auth/users/me/api-keys?owner=91`, {
    headers: headers() })).status, 400);
  assert.equal((await fetch(`${f.base}/v2/auth/users/me/api-keys/rotate`, {
    method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ key: 'caller-selected' }),
  })).status, 400);
});

test('API-key order reads require both current host launch authority and its child key', async t => {
  const f = await fixture(t);
  const key = 'sk_ss_live_11111111111111111111111111111111';
  const listed = await fetch(`${f.base}/v2/api/orders`, { headers: {
    'x-dvaia-secureshop-launch': launchBearer, 'x-api-key': key,
  } });
  assert.equal(listed.status, 200);
  assert.deepEqual(await listed.json(), { orders: [] });
  const detail = await fetch(`${f.base}/v2/api/orders/19`, { headers: {
    'x-dvaia-secureshop-launch': launchBearer, 'x-api-key': key,
  } });
  assert.equal(detail.status, 200);
  assert.equal((await detail.json()).order.id, 19);
  for (const name of ['apiKeyAuthenticate', 'orders', 'order']) {
    const input = f.calls.find(call => call[0] === name)[1];
    assert.deepEqual(input.scope, launchScope);
  }
  assert.equal(f.calls.find(call => call[0] === 'orders')[1].persona.id, 41);

  assert.equal((await fetch(`${f.base}/v2/api/orders`, { headers: {
    'x-api-key': key,
  } })).status, 200, 'without host authority the request delegates to legacy instead of selecting bound mode');
  assert.equal((await fetch(`${f.base}/v2/api/orders`, { headers: {
    'x-dvaia-secureshop-launch': 'x'.repeat(43), 'x-api-key': key,
  } })).status, 401);
  assert.equal((await fetch(`${f.base}/v2/api/orders`, { headers: {
    'x-dvaia-secureshop-launch': siblingLaunchBearer, 'x-api-key': key,
  } })).status, 401, 'learner A child key cannot select learner A through learner B host authority');
  assert.equal((await fetch(`${f.base}/v2/api/orders`, { headers: {
    'x-dvaia-secureshop-launch': launchBearer, 'x-api-key': key,
    authorization: 'Bearer customer-41',
  } })).status, 401);
  assert.equal((await fetch(`${f.base}/v2/api/orders?user_id=41`, { headers: {
    'x-dvaia-secureshop-launch': launchBearer, 'x-api-key': key,
  } })).status, 400);
});

test('password change accepts only exact strings and forwards authenticated session authority', async t => {
  const f = await fixture(t);
  const changed = await fetch(`${f.base}/v2/auth/users/me/password`, { method: 'POST', headers: {
    ...headers(), 'content-type': 'application/json' }, body: JSON.stringify({
    current_password: 'current-password', new_password: 'replacement-password',
  }) });
  assert.equal(changed.status, 200);
  assert.deepEqual(await changed.json(), { ok: true });
  const call = f.calls.find(row => row[0] === 'passwordChange')[1];
  assert.deepEqual(call.scope, launchScope);
  assert.deepEqual(call.shopPersona, { id: 41, role: 'customer' });
  assert.equal(call.currentSessionId, currentSessionId);
  assert.equal(call.currentPassword, 'current-password');
  assert.equal(call.newPassword, 'replacement-password');
  for (const body of [
    { current_password: true, new_password: 'replacement-password' },
    { current_password: 'current-password', new_password: ['replacement-password'] },
    { current_password: 'current-password', new_password: 'replacement-password', user_id: 99 },
  ]) assert.equal((await fetch(`${f.base}/v2/auth/users/me/password`, { method: 'POST', headers: {
    ...headers(), 'content-type': 'application/json' }, body: JSON.stringify(body) })).status, 400);
});

test('password mismatch and weak replacement have distinct closed public errors', async t => {
  for (const [code, status, error] of [
    ['SHOP_PASSWORD_MISMATCH', 403, 'Current shop password is incorrect'],
    ['SHOP_PASSWORD_INVALID', 400, 'Invalid shop password'],
  ]) {
    const f = await fixture(t, { personaAuthOverrides: { async changePassword() {
      throw Object.assign(new Error('private password detail'), { code });
    } } });
    const response = await fetch(`${f.base}/v2/auth/users/me/password`, { method: 'POST', headers: {
      ...headers(), 'content-type': 'application/json' }, body: JSON.stringify({
      current_password: 'current-password', new_password: 'replacement-password',
    }) });
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), { error });
  }
});

test('session inventory and UUID revocation preserve UI DTOs and internal authority', async t => {
  const f = await fixture(t);
  const listed = await fetch(`${f.base}/v2/auth/users/me/sessions`, { headers: headers() });
  assert.equal(listed.status, 200);
  assert.deepEqual(await listed.json(), { sessions: [{ id: currentSessionId,
    user_agent: 'Controlled Browser', ip: '127.0.0.1', created_at: '2026-09-18T00:00:00.000Z',
    last_seen_at: '2026-09-18T00:01:00.000Z', is_current: true }] });
  const listInput = f.calls.find(call => call[0] === 'sessions')[1];
  assert.deepEqual(listInput.scope, launchScope);
  assert.deepEqual(listInput.shopPersona, { id: 41, role: 'customer' });
  assert.equal(listInput.currentSessionId, currentSessionId);

  const revoked = await fetch(`${f.base}/v2/auth/users/me/sessions/${otherSessionId}/revoke`, {
    method: 'POST', headers: headers() });
  assert.equal(revoked.status, 200);
  assert.deepEqual(await revoked.json(), { ok: true });
  const revokeInput = f.calls.find(call => call[0] === 'sessionRevoke')[1];
  assert.deepEqual(revokeInput.scope, launchScope);
  assert.deepEqual(revokeInput.shopPersona, { id: 41, role: 'customer' });
  assert.equal(revokeInput.currentSessionId, currentSessionId);
  assert.equal(revokeInput.sessionId, otherSessionId);
  assert.equal(f.legacyCalls(), 0);
});

test('session routes reject malformed UUIDs, query/body fields and unavailable rows', async t => {
  const f = await fixture(t, { personaAuthOverrides: {
    async revokeOwnedSession(input) { f.calls.push(['sessionRevoke', input]); return false; },
  } });
  assert.equal((await fetch(`${f.base}/v2/auth/users/me/sessions?user_id=41`, {
    headers: headers() })).status, 400);
  for (const id of ['1', otherSessionId.toUpperCase(), 'not-a-uuid']) {
    assert.equal((await fetch(`${f.base}/v2/auth/users/me/sessions/${id}/revoke`, {
      method: 'POST', headers: headers() })).status, 400);
  }
  assert.equal((await fetch(`${f.base}/v2/auth/users/me/sessions/${otherSessionId}/revoke`, {
    method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 41 }) })).status, 400);
  const missing = await fetch(`${f.base}/v2/auth/users/me/sessions/${otherSessionId}/revoke`, {
    method: 'POST', headers: headers() });
  assert.deepEqual(await missing.json(), { ok: false });
});

test('renewal of a concurrently revoked persona session returns 401 without retiring the launch',async t=>{
  const f=await fixture(t,{personaAuthOverrides:{async renew(){throw Object.assign(new Error('revoked'),{code:'SHOP_AUTH_INVALID'});}}});
  const response=await fetch(`${f.base}/v2/auth/renew`,{method:'PATCH',headers:headers('customer',41)});
  assert.equal(response.status,401);
  assert.deepEqual(await response.json(),{error:'Shop authentication required'});
  assert.equal(response.headers.get('x-dvaia-secureshop-launch-state'),null);
  assert.equal(f.legacyCalls(),0);
});

test('agent, admin, MCP and unscoped AI paths are stopped inside bound gateway', async t => {
  const f = await fixture(t);
  for (const [path, method] of [['/products/3/summary', 'POST'], ['/products/3/similar', 'GET'],
    ['/agents/customer/session', 'POST'], ['/agents/merchant/chat', 'POST'],
    ['/admin/users', 'GET'], ['/admin/mcp/servers', 'GET'], ['/uploads', 'POST']]) {
    const response = await fetch(f.base + path, { method, headers: headers() });
    assert.equal(response.status, 503, `${method} ${path}`);
    assert.deepEqual(await response.json(), { error: 'Bound SecureShop operation unavailable' });
  }
  assert.equal(f.legacyCalls(), 0);
  assert.deepEqual(f.calls, []);
});

test('bound cart and orders derive ownership from customer persona and reject caller user_id',async t=>{
  const f=await fixture(t);
  const cart=await fetch(`${f.base}/cart`,{headers:headers('customer',41)});
  assert.deepEqual(await cart.json(),{items:[],subtotal:0,couponAvailable:false});
  const add=await fetch(`${f.base}/cart`,{method:'POST',headers:{...headers('customer',41),'content-type':'application/json'},body:JSON.stringify({product_id:3,quantity:2})});
  assert.deepEqual(await add.json(),{ok:true,cart_item_id:17});
  const rejected=await fetch(`${f.base}/orders`,{headers:headers('customer',41),method:'POST',body:JSON.stringify({user_id:99,shipping_address:'A',payment_method:'card'}),'headers':{...headers('customer',41),'content-type':'application/json'}});
  assert.equal(rejected.status,400);
  for(const invalid of [true,[1]])assert.equal((await fetch(`${f.base}/cart`,{method:'POST',headers:{...headers('customer',41),'content-type':'application/json'},body:JSON.stringify({product_id:invalid,quantity:1})})).status,400);
  assert.equal((await fetch(`${f.base}/cart/17`,{method:'DELETE',headers:{...headers('customer',41),'content-type':'application/json'},body:JSON.stringify({unexpected:true})})).status,400);
  assert.equal(f.calls.find(call=>call[0]==='cart')[1].persona.id,41);
  assert.equal(f.calls.find(call=>call[0]==='cartAdd')[1].persona.id,41);
  assert.equal(f.legacyCalls(),0);
});

test('invalid catalog input and service failures do not cross into legacy routers', async t => {
  const f = await fixture(t);
  for (const path of ['/products/1.5', '/products/2147483648', '/products?limit=101',
    '/products?limit=4&limit=5', '/products?minRating=0', '/products?minRating=6',
    '/products?minRating=4.5', '/products?maxPrice=-1', '/products?maxPrice=200000',
    '/products?maxPrice=1.234', '/products?maxPrice=2&maxPrice=3',
    '/merchant/products?per_page=0']) {
    const response = await fetch(f.base + path, { headers: headers('merchant', 77) });
    assert.equal(response.status, 400, path);
  }
  assert.equal(f.legacyCalls(), 0);
  assert.deepEqual(f.calls, []);
});

test('bound rating and price constraints reach the owned catalog before pagination', async t => {
  const f = await fixture(t);
  const response = await fetch(`${f.base}/products?minRating=5&maxPrice=2000&limit=12&page=2`,
    { headers: headers('merchant', 77) });
  assert.equal(response.status, 200);
  assert.deepEqual(f.calls[0][1].query, { search: null, category: null, minRating: 5,
    maxPrice: 2000, sort: '', page: 2, limit: 12, offset: 12 });
  assert.equal(f.calls[0][1].persona.role, 'merchant');
});


test('bound catalog pagination accepts the real UI offset and page-only requests with the actual catalog service', async t => {
  const { createSecureShopBoundCatalog } = require('../server/services/secureshopBoundCatalog');
  const products = Array.from({ length: 60 }, (_, index) => ({ id: index + 1, name: `Product ${index + 1}` }));
  const reads = [];
  const catalog = createSecureShopBoundCatalog({
    sourcePool: { query() { throw Error('Existing owner target must not reseed'); } },
    resolveTarget: async scope => ({ ...scope, kind: 'products', targetId: '30000000-0000-4000-8000-000000000091' }),
    checkCurrent: async () => {},
    repository: {
      open: async () => ({ ownMerchantId: 12 }),
      provision() { throw Error('Existing owner target must not reprovision'); },
      get: async () => null,
      categories: async () => [],
      createListing: async () => 61,
      updateListing: async (_binding, _actor, id) => id,
      archiveListing: async () => 1,
      list: async (binding, options) => {
        reads.push({ binding, options });
        return { rows: products.slice(options.offset, options.offset + options.limit), total: products.length };
      },
    },
  });
  const f = await fixture(t, { catalogOverrides: { listProducts: catalog.listProducts } });
  for (const [query, firstId, count] of [
    ['limit=24&offset=24&sort=newest', 25, 24],
    ['limit=24&page=2&sort=newest', 25, 24],
    ['limit=24&page=3&offset=48&sort=newest', 49, 12],
    ['limit=24&offset=0&sort=newest', 1, 24],
  ]) {
    const response = await fetch(`${f.base}/products?${query}`, { headers: headers() });
    assert.equal(response.status, 200, query);
    const result = await response.json();
    assert.equal(result.products[0].id, firstId); assert.equal(result.products.length, count);
    assert.equal(result.total, 60);
  }
  assert.ok(reads.every(row => row.binding.launchId === launchScope.launchId
    && row.binding.generation === launchScope.generation));
  const before = reads.length;
  for (const query of ['page=1&limit=24&offset=24', 'limit=24&offset=25',
    'page=2147483647&limit=100', 'limit=1&offset=2147483647', 'limit=0&offset=24', 'page=0', 'offset=-1', 'offset=24&offset=48']) {
    const response = await fetch(`${f.base}/products?${query}`, { headers: headers() });
    assert.equal(response.status, 400, query);
  }
  assert.equal(reads.length, before, 'Invalid pagination must not reach the owner target');
  assert.equal(f.legacyCalls(), 0);
});


test('bound admin users admits only admin persona and closed query authority', async t => {
  const inputs = [];
  const f = await fixture(t, { admin: { async users(input) { inputs.push(input);
    return { users: [{ id: 13, username: 'student_admin', role: 'admin' }], total: 1, pages: 1 };
  } } });
  const admitted = await fetch(`${f.base}/admin/users?page=1&pageSize=25&role=admin`,
    { headers: headers('admin', 13) });
  assert.equal(admitted.status, 200);
  assert.equal((await admitted.json()).users[0].id, 13);
  assert.deepEqual(inputs[0].scope, launchScope);
  assert.deepEqual(inputs[0].persona, { id: 13, role: 'admin' });
  assert.deepEqual(inputs[0].personaSession, { sessionId: currentSessionId, authorityVersion: '2' });
  assert.equal((await fetch(`${f.base}/admin/users`, { headers: headers() })).status, 403);
  assert.equal((await fetch(`${f.base}/admin/users?platformOwnerId=92`,
    { headers: headers('admin', 13) })).status, 400);
  assert.equal((await fetch(`${f.base}/admin/users?pageSize=101`,
    { headers: headers('admin', 13) })).status, 400);
  assert.equal(inputs.length, 1);
  assert.equal(f.legacyCalls(), 0);
});


test('bound admin KPI endpoint rejects non-admin and query-selected scope', async t => {
  const inputs = [];
  const f = await fixture(t, { admin: { async users() { return {}; }, async kpis(input) {
    inputs.push(input); return { total_users: 3, total_products: 5, total_orders: 1,
      total_revenue: 12, active_sessions: 2, admin_count: 1, banned_count: 0 };
  } } });
  const response = await fetch(`${f.base}/admin/overview/kpis`, { headers: headers('admin', 13) });
  assert.equal(response.status, 200); assert.equal((await response.json()).total_orders, 1);
  assert.deepEqual(inputs[0].scope, launchScope);
  assert.deepEqual(inputs[0].personaSession, { sessionId: currentSessionId, authorityVersion: '2' });
  assert.equal((await fetch(`${f.base}/admin/overview/kpis`, { headers: headers() })).status, 403);
  assert.equal((await fetch(`${f.base}/admin/overview/kpis?targetId=other`,
    { headers: headers('admin', 13) })).status, 400);
  assert.equal(inputs.length, 1); assert.equal(f.legacyCalls(), 0);
});

test('admin observations keep provider and trace reads behind role and closed-query gates', async t => {
  const inputs = [];
  const f = await fixture(t, { admin: { async users() { return {}; },
    async providers(input) { inputs.push(input); return [{ role: 'customer', active_provider: 'observed' }]; },
    async latestTrace(input) { inputs.push(input); return []; },
  } });
  for (const path of ['/admin/provider-state', '/agents/admin/trace/latest?limit=5']) {
    const response = await fetch(f.base + path, { headers: headers('admin', 13) });
    assert.equal(response.status, 200);
    assert.equal((await fetch(f.base + path, { headers: headers() })).status, 403);
  }
  assert.equal((await fetch(`${f.base}/agents/admin/trace/latest?limit=201`, { headers: headers('admin', 13) })).status, 400);
  assert.equal((await fetch(`${f.base}/admin/provider-state?role=customer`, { headers: headers('admin', 13) })).status, 400);
  assert.equal(inputs.length, 2); assert.equal(inputs[1].limit, 5);
  assert.ok(inputs.every(input => input.persona.role === 'admin' && input.scope.platformOwnerId === 91));
  assert.ok(inputs.every(input => input.personaSession.sessionId === currentSessionId
    && input.personaSession.authorityVersion === '2'));
  assert.equal(f.legacyCalls(), 0);
});

test('bound audit HTTP contracts reject ownership selection and invalid filters before the read',async t=>{
  const inputs=[];
  const f=await fixture(t,{admin:{async users(){return {};},async audit(input){inputs.push(input);return {count:0,events:[]};}}});
  const response=await fetch(`${f.base}/admin/audit?limit=10000&from=2024-02-29&to=2024-02-29&q=%25`,{headers:headers('admin',13)});
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{ok:true,count:0,events:[]});
  assert.equal(inputs[0].scope.platformOwnerId,91);assert.equal(inputs[0].query.q,'%');
  assert.deepEqual(inputs[0].personaSession,{sessionId:currentSessionId,authorityVersion:'2'});
  for(const query of ['owner=92','limit=10001','from=2026-02-30','q=a&q=b']) assert.equal((await fetch(`${f.base}/admin/audit?${query}`,{headers:headers('admin',13)})).status,400);
  assert.equal((await fetch(`${f.base}/admin/audit`,{headers:headers()})).status,403);
  assert.equal(inputs.length,1);assert.equal(f.legacyCalls(),0);
});

test('scoped operational read endpoints deny injected authority and retain explicit unavailable state',async t=>{
 const calls=[];const admin={users:async()=>({users:[]})};const paths=[['/admin/mcp/servers','mcpServers'],['/admin/mcp/schema-history','mcpHistory'],['/admin/db-sizes','dbSizes'],['/admin/agent-host/health','runtimeHealth']];
 for(const [,name] of paths)admin[name]=async input=>{calls.push(input);if(name==='runtimeHealth')throw Object.assign(Error('Probe unavailable'),{statusCode:503,code:'BOUND_ADMIN_READ_UNAVAILABLE'});return{basis:'scoped-test'};};
 const f=await fixture(t,{admin});
 for(const [url,name] of paths){const r=await fetch(f.base+url,{headers:headers('admin',13)});assert.equal(r.status,name==='runtimeHealth'?503:200);if(name==='runtimeHealth')assert.equal((await r.json()).code,'BOUND_ADMIN_READ_UNAVAILABLE');assert.equal((await fetch(f.base+url+'?platformOwnerId=9',{headers:headers('admin',13)})).status,400);assert.equal((await fetch(f.base+url,{headers:headers()})).status,403);}
 assert.equal(calls.length,4);assert.ok(calls.every(x=>JSON.stringify(x.scope)===JSON.stringify(launchScope)));assert.equal(f.legacyCalls(),0);
});

test('real account service rejects revoked route credential before storage and accepts trusted session snapshot',async t=>{
 let revoked=false,writes=0;const check=async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});};
 const account=require('../server/services/secureshopBoundAccount').createSecureShopBoundAccount({personaAuthority:{capture:async input=>{assert.equal(input.sessionId,currentSessionId);assert.equal(input.authorityVersion,'2');return{binding:{...input.scope,personaId:input.personaId,role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},assertRemoteAdmission:check,withCrossStoreEffect:async work=>{await check();return work();}};}},personaRepository:{readPersona:async()=>({id:41,username:'stable',role:'customer',email:'customer@example.test'})},catalog:{prepareTarget:async input=>{await input.personaEffect.check(input.scope);return{...input.scope,targetId:'30000000-0000-4000-8000-000000000061'};}},repository:{readProfile:async()=>null,listAddresses:async()=>[],saveAddress:async()=>({id:1}),deleteAddress:async()=>1,updateProfile:async(_scope,_id,input)=>{writes++;return{email:input.email,full_name:input.fullName,phone:input.phone};}}});
 const f=await fixture(t,{accountOverrides:account});const request=()=>fetch(`${f.base}/v2/auth/users/me`,{method:'PUT',headers:{...headers(),'content-type':'application/json'},body:JSON.stringify({full_name:'owned',email:'owned@example.test',phone:null})});assert.equal((await request()).status,200);assert.equal(writes,1);revoked=true;assert.equal((await request()).status,401);assert.equal(writes,1);
});

test('mounted policy gateway binds bridge mutations to authenticated launch and original admin session', async t => {
  const { compileOperation } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  const seen = [];
  const promptPolicies = { async list() { return {version:'1',policies:[]}; }, async remove() {}, async operation() {},
    async render(input) { seen.push(input); return {state:'pending',operationId:input.request.operationId}; } };
  const f = await fixture(t,{promptPolicies});
  const op = compileOperation('admin.policies.upsert',{body:{name:'owned',markdown:'{{ raw }}',injected_into:['admin'],
    operationId:'11111111-1111-4111-8111-111111111111',expectedVersion:'1'}});
  const url = `${f.base}${op.path.slice('/api/secureshop'.length)}`;
  const send = role => fetch(url,{method:op.method,headers:{...headers(role,13),'content-type':'application/json'},body:JSON.stringify(op.body)});
  assert.equal((await send('customer')).status,403); assert.equal(seen.length,0);
  const response = await send('admin'); assert.equal(response.status,202); assert.equal(response.headers.get('cache-control'),'no-store');
  assert.equal((await response.json()).state,'pending'); assert.equal(seen.length,1);
  assert.deepEqual(seen[0].scope,launchScope); assert.deepEqual(seen[0].persona,{id:13,role:'admin'});
  assert.deepEqual(seen[0].personaSession,{sessionId:currentSessionId,authorityVersion:'2'});
  assert.equal(seen[0].request.markdown,'{{ raw }}'); assert.equal(f.legacyCalls(),0);
  const disabled = await fixture(t); const unavailable = await fetch(`${disabled.base}/admin/policies`,{headers:headers('admin',13)});
  assert.equal(unavailable.status,503); assert.equal(disabled.legacyCalls(),0);
});


test('gateway advertises and admits only composition-selected task policies', async t => {
  const seen = [];
  const promptPolicies = { async list() { return { version: '1', policies: [] }; },
    async remove() {}, async operation() {},
    async render(input) { seen.push(input); return { state: 'pending', operationId: input.request.operationId }; } };
  const f = await fixture(t, { promptPolicies, promptPolicyTaskTargets: ['summarizer'] });
  const read = await fetch(`${f.base}/admin/policies`, { headers: headers('admin', 13) });
  assert.equal(read.status, 200);
  assert.deepEqual((await read.json()).supported_task_targets, ['summarizer']);
  const send = targets => fetch(`${f.base}/admin/policies`, { method: 'POST',
    headers: { ...headers('admin', 13), 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'task', markdown: 'POLICY', injected_into: targets,
      operationId: '11111111-1111-4111-8111-111111111111', expectedVersion: '1' }) });
  assert.equal((await send(['review-moderator'])).status, 400);
  assert.equal(seen.length, 0);
  assert.equal((await send(['summarizer'])).status, 202);
  assert.equal(seen[0].request.contractVersion, 2);
  assert.deepEqual(seen[0].request.targets, ['summarizer']);
  assert.equal(f.legacyCalls(), 0);
});

test('bound MCP tools read uses current admin authority without legacy fallback',async t=>{
 const inputs=[];const f=await fixture(t,{admin:{async users(){return{};},async mcpTools(input){inputs.push(input);if(input.name==='missing')throw Object.assign(new Error('No discovered server in this launch'),{statusCode:404});return{tools:[{tool_name:'owned',description:'teaching text',input_schema_json:'{}'}]};}}});
 const url=f.base+'/admin/mcp/servers/owned%20name/tools';
 const response=await fetch(url,{headers:headers('admin',13)});assert.equal(response.status,200);assert.equal((await response.json()).tools[0].tool_name,'owned');
 assert.equal(inputs[0].name,'owned name');assert.equal(inputs[0].scope.platformOwnerId,91);assert.deepEqual(inputs[0].personaSession,{sessionId:currentSessionId,authorityVersion:'2'});
 assert.equal((await fetch(url,{headers:headers()})).status,403);
 assert.equal((await fetch(url+'?owner=92',{headers:headers('admin',13)})).status,400);
 assert.equal((await fetch(f.base+'/admin/mcp/servers/missing/tools',{headers:headers('admin',13)})).status,404);
 assert.equal(inputs.length,2);assert.equal(f.legacyCalls(),0);
});

 test('customer recommendations use bound identity and reject caller authority or other roles', async t => {
  const f = await fixture(t);
  const response = await fetch(`${f.base}/recommended`, {headers:headers()});
  assert.equal(response.status,200); assert.equal(response.headers.get('cache-control'),'no-store');
  const body=await response.json(); assert.equal(body.feed[0].private,undefined); assert.equal(body.provenance.modelUsed,false);
  const call=f.calls.find(row=>row[0]==='recommendations');
  assert.equal(call[1].persona.id,41); assert.equal(call[1].scope.platformOwnerId,91);
  assert.equal(call[1].personaSession.sessionId,currentSessionId);
  for(const query of ['?user_id=42','?limit=99','?user_id=41&user_id=42']) {
    assert.equal((await fetch(`${f.base}/recommended${query}`,{headers:headers()})).status,400);
  }
  for(const role of ['merchant','admin']) assert.equal((await fetch(`${f.base}/recommended`,{headers:headers(role)})).status,403);
  assert.equal((await fetch(`${f.base}/recommended`,{headers:{'x-dvaia-secureshop-launch':launchBearer}})).status,401);
  assert.equal(f.calls.filter(row=>row[0]==='recommendations').length,1);
  assert.equal(f.legacyCalls(),0);
 });

test('bound merchant reporting scopes to authenticated merchant and rejects foreign IDs', async t => {
  const f = await fixture(t);
  const response = await fetch(f.base + '/merchant/overview/kpis?retailer_id=77', { headers: headers('merchant', 77) });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).retailer_id, 77);
  const call = f.calls.find(row => row[0] === 'merchantOverview')[1];
  assert.deepEqual(call.scope, launchScope);
  assert.equal(call.persona.id, 77);
  assert.equal(call.personaSession.sessionId, currentSessionId);
  const chart = await fetch(f.base + '/merchant/overview/sales-chart?days=14', { headers: headers('merchant', 77) });
  assert.equal(chart.status, 200); assert.equal((await chart.json()).days, 14);
  for (const query of ['?retailer_id=78', '?user_id=77', '?days=0', '?days=366']) {
    assert.equal((await fetch(f.base + '/merchant/overview/sales-chart' + query,
      { headers: headers('merchant', 77) })).status, 400);
  }
  assert.equal((await fetch(f.base + '/merchant/overview/kpis', { headers: headers('customer', 77) })).status, 403);
  assert.equal(f.calls.filter(row => row[0] === 'merchantOverview').length, 2);
});
test('bound merchant top products admits only bounded owned-commerce reads',async t=>{
 const f=await fixture(t);
 const response=await fetch(f.base+'/merchant/overview/top-products?limit=8&days=30',{headers:headers('merchant',77)});
 assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');
 assert.deepEqual(await response.json(),{rows:[{id:3,name:'Owned purchase',revenue:6.75}],periodDays:30,source:'owned-commerce'});
 const input=f.calls.find(row=>row[0]==='merchantTopProducts')[1];assert.deepEqual(input.scope,launchScope);assert.equal(input.persona.id,77);assert.equal(input.personaSession.sessionId,currentSessionId);assert.equal(input.days,30);assert.equal(input.limit,8);
 const defaultResponse=await fetch(f.base+'/merchant/overview/top-products',{headers:headers('merchant',77)});assert.equal(defaultResponse.status,200);
 for(const query of ['?limit=0','?limit=51','?limit=1.5','?days=6','?days=366','?days=30&days=31','?retailer_id=77','?targetId=other','?user_id=1'])assert.equal((await fetch(f.base+'/merchant/overview/top-products'+query,{headers:headers('merchant',77)})).status,400);
 for(const role of ['customer','admin'])assert.equal((await fetch(f.base+'/merchant/overview/top-products',{headers:headers(role,77)})).status,403);
 assert.equal((await fetch(f.base+'/merchant/overview/top-products',{headers:{'x-dvaia-secureshop-launch':launchBearer}})).status,401);
 assert.equal(f.calls.filter(row=>row[0]==='merchantTopProducts').length,2);assert.equal(f.legacyCalls(),0);
});

test('customer and merchant trace reads use their own role, session and launch coordinates',async t=>{
  const calls=[];
  const f=await fixture(t,{personaObservations:{async latestTrace(input){calls.push(input);return [{id:1,kind:'tool_result'}];}}});
  for(const role of ['customer','merchant']) {
    const response=await fetch(f.base+`/agents/${role}/trace/latest?limit=10`,{headers:headers(role,77)});
    assert.equal(response.status,200);assert.equal((await response.json()).count,1);
    const captured=calls.at(-1);assert.deepEqual(captured.scope,launchScope);
    assert.equal(captured.persona.role,role);assert.equal(captured.personaSession.sessionId,currentSessionId);
    assert.equal((await fetch(f.base+`/agents/${role}/trace/latest?user_id=1`,{headers:headers(role,77)})).status,400);
    assert.equal((await fetch(f.base+`/agents/${role}/trace/latest?limit=51`,{headers:headers(role,77)})).status,400);
  }
  assert.equal((await fetch(f.base+'/agents/merchant/trace/latest',{headers:headers('customer',77)})).status,403);
  assert.equal(calls.length,2);assert.equal(f.legacyCalls(),0);
});


test('coupon route preserves raw teaching input while binding persona and rejecting client authority',async t=>{
 const f=await fixture(t),operationId='50000000-0000-4000-8000-000000000091',code="' OR 1=1--";
 const post=(body,role='customer')=>fetch(`${f.base}/cart/apply-coupon`,{method:'POST',headers:{...headers(role), 'content-type':'application/json'},body:JSON.stringify(body)});
 assert.equal((await post({code,operationId})).status,200);
 const input=f.calls.find(([kind])=>kind==='coupon')[1];assert.equal(input.code,code);assert.equal(input.operationId,operationId);assert.equal(input.persona.id,41);assert.equal(input.scope.launchId,launchScope.launchId);assert.equal(input.personaSession.sessionId,currentSessionId);
 for(const body of [{code},{code,operationId,user_id:99},{code,operationId,scope:launchScope},{code,operationId:'bad'}])assert.equal((await post(body)).status,400);
 assert.equal((await post({code,operationId},'merchant')).status,403);assert.equal(f.calls.filter(([kind])=>kind==='coupon').length,1);
});
test('bound cart reports coupon readiness from composed workflow without changing cart access',async t=>{
 for(const available of [false,true]){
  const f=await fixture(t,{commerceOverrides:{couponAvailable:available}});
  const response=await fetch(`${f.base}/cart`,{headers:headers()});
  assert.equal(response.status,200);
  const body=await response.json();
  assert.equal(body.couponAvailable,available);
  assert.deepEqual(body.items,[]);
  assert.equal(body.subtotal,0);
 }
});
test('bound checkout requires a stable UUID before any commerce effect',async t=>{
 const f=await fixture(t),body={shipping_address:'owned',payment_method:'synthetic'},post=value=>fetch(`${f.base}/orders`,{method:'POST',headers:{...headers(),'content-type':'application/json'},body:JSON.stringify(value)});
 assert.equal((await post(body)).status,400);assert.equal(f.calls.some(([kind])=>kind==='checkout'),false);
 const operationId='60000000-0000-4000-8000-000000000091';assert.equal((await post({...body,operationId})).status,200);assert.equal(f.calls.find(([kind])=>kind==='checkout')[1].operationId,operationId);
});
test('general registry router reaches exact bound admin authority and closed DTO without legacy fallthrough',async t=>{
 const calls=[],operationId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
 const f=await fixture(t,{ownedMcpService:{async mutate(input){calls.push(input);return{state:'completed',operationId};},async read(input){calls.push(input);return{state:'completed',operationId};}}});
 const body={version:1,action:'register',operationId,expectedVersion:'0',name:'poisoned-catalog',transport:'sse',url:'http://127.0.0.1:8099/mcp',stdio_cmd:''};
 const send=role=>fetch(f.base+'/admin/mcp/register',{method:'POST',headers:{...headers(role,13),'content-type':'application/json'},body:JSON.stringify(body)});
 assert.equal((await send('merchant')).status,403);assert.equal(calls.length,0);
 assert.equal((await send('admin')).status,200);assert.deepEqual(calls[0].scope,launchScope);assert.equal(calls[0].persona.role,'admin');assert.equal(calls[0].personaSession.sessionId,currentSessionId);
 assert.equal((await fetch(f.base+'/admin/mcp/operations/'+operationId,{headers:headers('admin',13)})).status,200);assert.equal(calls[1].operationId,operationId);assert.equal(f.legacyCalls(),0);
});

test('mounted coupon operation conflicts stay denied with409 while unknown failures remain503',async t=>{
 for(const [code,status] of [['COMMERCE_OPERATION_CONFLICT',409],['COMMERCE_INTEGRITY_UNAVAILABLE',503]]){
  let calls=0;const f=await fixture(t,{commerceOverrides:{async applyCoupon(){calls++;throw Object.assign(new Error('private receipt/session details'),{code});}}});
  const response=await fetch(`${f.base}/cart/apply-coupon`,{method:'POST',headers:{...headers(),'content-type':'application/json'},body:JSON.stringify({code:'WELCOME10',operationId:'60000000-0000-4000-8000-000000000091'})});
  assert.equal(response.status,status);const body=await response.json();assert.equal(JSON.stringify(body).includes('private receipt'),false);assert.equal(calls,1);
 }
});

test('checkout history routes use current customer authority and expose no effect retry', async t => {
 const operationId='50000000-0000-4000-8000-000000000001',scopeKey='a'.repeat(64);let missing=false;
 const f=await fixture(t,{commerceOverrides:{
  async checkoutHistory(input){assert.equal(input.persona.id,41);assert.deepEqual(input.scope,launchScope);return{scopeKey,operations:[{operationId,orderId:7,createdAt:'2026-10-01T00:00:00.000Z'}]};},
  async checkoutReceipt(input){assert.equal(input.operationId,operationId);assert.equal(input.personaSession.sessionId,currentSessionId);if(missing)throw Object.assign(Error('missing'),{code:'CHECKOUT_RECEIPT_NOT_FOUND'});return{scopeKey,operationId,status:'completed',order:{id:7,total:9,subtotal:10,discount:1}};},
 }});
 let r=await fetch(`${f.base}/orders/operations`,{headers:headers()});assert.equal(r.status,200);assert.equal(r.headers.get('cache-control'),'no-store');assert.equal((await r.json()).operations[0].operationId,operationId);
 r=await fetch(`${f.base}/orders/operations/${operationId}`,{headers:headers()});assert.equal(r.status,200);assert.equal((await r.json()).order.id,7);
 for(const path of ['/orders/operations?owner=99','/orders/operations/not-uuid']){r=await fetch(`${f.base}${path}`,{headers:headers()});assert.equal(r.status,400);}
 r=await fetch(`${f.base}/orders/operations`,{headers:headers('merchant',12)});assert.equal(r.status,403);
 missing=true;r=await fetch(`${f.base}/orders/operations/${operationId}`,{headers:headers()});assert.equal(r.status,404);assert.deepEqual(await r.json(),{error:'Checkout outcome is not confirmed'});
 assert.equal(f.calls.some(([name])=>name==='checkout'),false);
});

test('policy readiness is admin-only and explicitly false only for an uncomposed workflow', async t => {
 const f=await fixture(t);
 let r=await fetch(`${f.base}/admin/policies/readiness`,{headers:headers('admin',13)});
 assert.equal(r.status,200);assert.equal(r.headers.get('cache-control'),'no-store');assert.deepEqual(await r.json(),{ready:false});
 for(const role of ['customer','merchant']){r=await fetch(`${f.base}/admin/policies/readiness`,{headers:headers(role,41)});assert.equal(r.status,403);}
 r=await fetch(`${f.base}/admin/policies/readiness`,{headers:{'x-dvaia-secureshop-launch':launchBearer}});assert.equal(r.status,401);
 r=await fetch(`${f.base}/admin/policies/readiness?ready=true`,{headers:headers('admin',13)});assert.equal(r.status,400);
});
test('composed policy readiness probes the strict renderer and never disguises health or stale authority errors as disabled',async t=>{
 let probes=0,health='ready',current=true;
 const promptPolicies={async list(){throw Error('No policy list or write');},async render(){throw Error('No render');},async remove(){throw Error('No remove');},async operation(){throw Error('No operation');},async readiness(){probes++;if(health==='error')throw Object.assign(Error('private URL detail'),{code:'POLICY_RENDER_UNAVAILABLE'});return{ready:health==='ready',private:'never returned'};}};
 const f=await fixture(t,{promptPolicies,assertLaunchCurrent:async()=>{if(!current)throw Object.assign(Error('revoked'),{code:'SESSION_UNAVAILABLE'});}});
 let r=await fetch(`${f.base}/admin/policies/readiness`,{headers:headers('customer',41)});assert.equal(r.status,403);assert.equal(probes,0);
 r=await fetch(`${f.base}/admin/policies/readiness`,{headers:headers('admin',13)});assert.equal(r.status,200);assert.deepEqual(await r.json(),{ready:true});assert.equal(probes,1);
 for(const value of ['error','false']){health=value;r=await fetch(`${f.base}/admin/policies/readiness`,{headers:headers('admin',13)});assert.equal(r.status,503);assert.deepEqual(await r.json(),{error:'Bound SecureShop operation unavailable'});}
 health='ready';current=false;r=await fetch(`${f.base}/admin/policies/readiness`,{headers:headers('admin',13)});assert.equal(r.status,401);
});
test('fixed policy readiness uses authenticated context without renderer and rechecks revoked authority',async t=>{
 let mode='fixed',probes=0,current=true,revokeAfter=false,captured;
 const modeAuthority={async capture(scope,featureId){captured={scope,featureId};
   return Object.freeze({snapshot:Object.freeze({featureId:'policy',scope,mode}),async assertCurrent(){}});},
  assertToken(token){return token;}};
 const repository={async beginRender(){},async publish(){},async remove(){},async operation(){},async list(){}};
 const renderer={async render(){throw Error('Renderer must not execute for readiness');},
  async checkReadiness(){probes++;throw Object.assign(Error('unsafe renderer unavailable'),{code:'POLICY_RENDER_UNAVAILABLE'});}};
 const service=createBoundPromptPolicyService({repository,renderer,modeAuthority});
 const promptPolicies={...service,async readiness(input){
  assert.deepEqual(input,{scope:launchScope,persona:{id:13,role:'admin'},
   personaSession:{sessionId:currentSessionId,authorityVersion:'2'}});
  const result=await service.readiness(input);if(revokeAfter)current=false;return result;}};
 const f=await fixture(t,{promptPolicies,assertLaunchCurrent:async()=>{
  if(!current)throw Object.assign(Error('revoked'),{code:'SESSION_UNAVAILABLE'});}});
 let r=await fetch(`${f.base}/admin/policies/readiness`,{headers:headers('admin',13)});
 assert.equal(r.status,200);assert.deepEqual(await r.json(),{ready:true});assert.equal(probes,0);
 assert.equal(captured.featureId,'policy');assert.deepEqual(captured.scope,launchScope);
 mode='vuln';r=await fetch(`${f.base}/admin/policies/readiness`,{headers:headers('admin',13)});
 assert.equal(r.status,503);assert.equal(probes,1);
 mode='fixed';revokeAfter=true;r=await fetch(`${f.base}/admin/policies/readiness`,{headers:headers('admin',13)});
 assert.equal(r.status,401);assert.equal(probes,1);
});
test('trusted conversational confirm is exact JSON customer-only and forwards captured authority',async t=>{
 const proposalId='50000000-0000-4000-8000-000000000099';
 const f=await fixture(t,{commerceOverrides:{async conversational(input){f.calls.push(['domain',input]);return {version:1,scopeKey:'a'.repeat(64),operationId:input.args.proposalId,kind:'checkout.confirm',status:'declined',currency:'USD',totalCents:100,order:null,replayed:false};}}});
 const post=(role,body)=>fetch(`${f.base}/customer/commerce/checkout/confirm`,{method:'POST',headers:{...headers(role.split('-')[0],Number(role.split('-')[1])),'content-type':'application/json'},body:JSON.stringify(body)});
 const response=await post('customer-41',{proposalId});assert.equal(response.status,200);assert.equal((await response.json()).status,'declined');
 const call=f.calls.find(([kind])=>kind==='domain')[1];assert.deepEqual(call.args,{proposalId});assert.equal(call.method,'confirmCheckout');assert.equal(call.persona.id,41);assert.equal(call.personaSession.sessionId,currentSessionId);
 assert.equal((await post('merchant-12',{proposalId})).status,403);assert.equal((await post('customer-41',{proposalId,payment_method:'arbitrary'})).status,400);assert.equal((await post('customer-41',{proposalId:'forged'})).status,400);assert.equal(f.calls.filter(([kind])=>kind==='domain').length,1);assert.equal(f.legacyCalls(),0);
});

test('trusted cart confirm is exact JSON customer-only and forwards captured authority',async t=>{
 const proposalId='50000000-0000-4000-8000-000000000099';
 const f=await fixture(t,{commerceOverrides:{async conversational(input){f.calls.push(['domain',input]);return {version:1,scopeKey:'a'.repeat(64),operationId:input.args.proposalId,kind:'cart.add',status:'completed',result:{id:1},replayed:false};}}});
 const post=(role,body)=>fetch(`${f.base}/customer/commerce/cart/confirm`,{method:'POST',headers:{...headers(role.split('-')[0],Number(role.split('-')[1])),'content-type':'application/json'},body:JSON.stringify(body)});
 const response=await post('customer-41',{proposalId});assert.equal(response.status,200);assert.equal((await response.json()).status,'completed');
 const call=f.calls.find(([kind])=>kind==='domain')[1];assert.deepEqual(call.args,{proposalId});assert.equal(call.method,'confirmCart');assert.equal(call.persona.id,41);assert.equal(call.personaSession.sessionId,currentSessionId);
 assert.equal((await post('merchant-12',{proposalId})).status,403);assert.equal((await post('customer-41',{proposalId,payment_method:'arbitrary'})).status,400);assert.equal((await post('customer-41',{proposalId:'forged'})).status,400);assert.equal(f.calls.filter(([kind])=>kind==='domain').length,1);assert.equal(f.legacyCalls(),0);
});


test('avatar upload routes traverse the canonical agents prefix through the bound gateway',async t=>{
 const express=require('express');
 const routeCalls=[];
 const avatarLaunches={async resolveCapability(value){return value===launchBearer?launchScope:null;}};
 const avatarPersona=(req,res,next)=>{const match=/^Bearer (customer|merchant)-(\d+)$/.exec(req.get('authorization')||'');if(!match)return res.status(401).json({error:'Shop authentication required'});req.ssUser={id:Number(match[2]),role:match[1]};req.ssPersonaSession={sessionId:currentSessionId,authorityVersion:'2'};next();};
 const uploadRequestId='50000000-0000-4000-8000-000000000091',operationId='60000000-0000-4000-8000-000000000091',evaluationId='70000000-0000-4000-8000-000000000091';
 const avatarUploadRouter=require('../server/routes/secureshop/boundAvatarUpload').createBoundAvatarUploadRouter({
  launches:avatarLaunches,authenticatePersona:avatarPersona,
  svgAssessment:{async runAttempt(){return{completed:false,status:'ineligible',modelEvaluated:false};},async readOutcome(){return{completed:false,status:'unconfirmed',modelEvaluated:false};}},
  graph:{async createSession(input){routeCalls.push(['session',input]);return{id:currentSessionId};},async run(input){routeCalls.push(['run',input]);return{text:'saved',replayed:false,taskMetadata:{boundUpload:{operationId,uploadRequestId,outcome:'completed'}}};}},
  saved:{async read(input){routeCalls.push(['read',input]);return{operationId,uploadRequestId,status:'completed',filename:'owned.html',byteCount:5,bodySha256:'a'.repeat(64)};},async asset(input){routeCalls.push(['asset',input]);return{operationId,assetUrl:'http://[::1]:9083/a',expiresAt:Date.now()+60000};}},
  assessment:{async runAttempt(input){routeCalls.push(['assess',input]);return{completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:false};},async readOutcome(input){routeCalls.push(['assessment',input]);return{completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:true};}}
 });
 const f=await fixture(t,{avatarUploadRouter}),customer=headers('customer',41),json={...customer,'content-type':'application/json'};
 const session=await fetch(`${f.base}/agents/customer/avatar-upload/session`,{method:'POST',headers:json,body:'{}'});assert.equal(session.status,200);assert.deepEqual(await session.json(),{id:currentSessionId});
 const form=new FormData();form.set('sessionId',currentSessionId);form.set('requestId',uploadRequestId);form.set('message','Upload owned bytes.');form.set('public','true');form.set('file',new Blob([Buffer.from('owned')],{type:'text/html'}),'owned.html');
 const run=await fetch(`${f.base}/agents/customer/avatar-upload/run`,{method:'POST',headers:customer,body:form});assert.equal(run.status,200);assert.equal((await run.json()).operationId,operationId);
 for(const [method,path,kind,body] of [
  ['GET',`/agents/customer/avatar-upload/requests/${uploadRequestId}`,'read'],
  ['GET',`/agents/customer/avatar-upload/operations/${operationId}`,'read'],
  ['POST',`/agents/customer/avatar-upload/operations/${operationId}/asset`,'asset','{}'],
  ['POST','/agents/customer/avatar-upload/assess','assess',JSON.stringify({sessionId:currentSessionId,requestId:uploadRequestId})],
  ['GET',`/agents/customer/avatar-upload/assess/${currentSessionId}/${uploadRequestId}`,'assessment'],
 ]){const response=await fetch(f.base+path,{method,headers:method==='POST'?json:customer,...(body===undefined?{}:{body})});assert.equal(response.status,200,`${method} ${path}`);await response.json();assert.ok(routeCalls.some(([value])=>value===kind),kind);}
 const beforeMissing=routeCalls.length;const missing=await fetch(`${f.base}/agents/customer/avatar-upload/session`,{method:'POST',headers:{authorization:'Bearer customer-41','content-type':'application/json'},body:'{}'});assert.equal(missing.status,200);assert.deepEqual(await missing.json(),{legacy:true,method:'POST',path:'/agents/customer/avatar-upload/session'});assert.equal(routeCalls.length,beforeMissing);
 const beforeDenied=routeCalls.length;const missingPersona=await fetch(`${f.base}/agents/customer/avatar-upload/session`,{method:'POST',headers:{'x-dvaia-secureshop-launch':launchBearer,'content-type':'application/json'},body:'{}'});assert.equal(missingPersona.status,401);assert.equal(routeCalls.length,beforeDenied);
 const invalidLaunch=await fetch(`${f.base}/agents/customer/avatar-upload/session`,{method:'POST',headers:{authorization:'Bearer customer-41','x-dvaia-secureshop-launch':'invalid','content-type':'application/json'},body:'{}'});assert.equal(invalidLaunch.status,401);assert.equal(routeCalls.length,beforeDenied);
 const wrongRole=await fetch(`${f.base}/agents/customer/avatar-upload/session`,{method:'POST',headers:{...headers('merchant',12),'content-type':'application/json'},body:'{}'});assert.equal(wrongRole.status,403);assert.equal(routeCalls.length,beforeDenied);
 const former=await fetch(`${f.base}/customer/avatar-upload/session`,{method:'POST',headers:json,body:'{}'});assert.equal(former.status,404);assert.deepEqual(await former.json(),{error:'Bound SecureShop route not found'});
 assert.equal(f.legacyCalls(),1);
});

test('customer chat and isolated lesson fallbacks remain independent',async t=>{
 const idorLessonRouter=express.Router();
 idorLessonRouter.post('/agents/customer/idor/session',(_req,res)=>res.json({mounted:'idor'}));
 const idorOnly=await fixture(t,{idorLessonRouter});
 assert.equal((await fetch(`${idorOnly.base}/agents/customer/session`,{method:'POST',headers:headers('customer',11)})).status,503);
 assert.equal((await fetch(`${idorOnly.base}/agents/customer/idor/session`,{method:'POST',headers:headers('customer',11)})).status,200);
 assert.equal(idorOnly.legacyCalls(),0);
 const customerChatRouter=express.Router();
 customerChatRouter.post('/agents/customer/session',(_req,res)=>res.json({mounted:'customer'}));
 const chatOnly=await fixture(t,{customerChatRouter});
 assert.equal((await fetch(`${chatOnly.base}/agents/customer/session`,{method:'POST',headers:headers('customer',11)})).status,200);
 assert.equal((await fetch(`${chatOnly.base}/agents/customer/idor/session`,{method:'POST',headers:headers('customer',11)})).status,503);
 assert.equal(chatOnly.legacyCalls(),0);
});

test('search assessment mounts exact paths and never falls through to legacy handlers', async t => {
 const router=express.Router();
 const paths=[['POST','/agents/customer/search-echo/assess'],
  ['GET','/agents/customer/sessions/10000000-0000-4000-8000-000000000001/requests/20000000-0000-4000-8000-000000000001/search-echo/2/assessment']];
 for(const [method,path] of paths)router[method.toLowerCase()](path,(_req,res)=>res.json({mounted:true}));
 const mounted=await fixture(t,{searchEchoRouter:router}),absent=await fixture(t);
 for(const [method,path] of paths){
  const response=await fetch(mounted.base+path,{method,headers:headers('customer',41)});
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{mounted:true});
  const denied=await fetch(absent.base+path,{method,headers:headers('customer',41)});
  assert.equal(denied.status,503);
 }
 assert.equal(mounted.legacyCalls(),0);assert.equal(absent.legacyCalls(),0);
});

test('ticket confirmation and admin paths are exact mounts with honest disabled fallbacks', async t => {
 const mountedRouter = express.Router();
 mountedRouter.post('/agents/customer/tickets/confirm', (_req, res) => res.json({ mounted: 'customer-ticket' }));
 mountedRouter.get('/agents/customer/tickets/confirm/:sessionId/:requestId/:proposalId', (_req, res) => res.json({ mounted: 'saved-ticket' }));
 mountedRouter.get('/admin/tickets', (_req, res) => res.json({ mounted: 'admin-ticket-list' }));
 mountedRouter.get('/admin/tickets/:ticketId', (_req, res) => res.json({ mounted: 'admin-ticket-detail' }));
 const mounted = await fixture(t, { ticketAgentRouter: mountedRouter });
 const customer = headers('customer', 41);
 const admin = headers('admin', 13);
 for (const [path, method, expected, requestHeaders] of [
   ['/agents/customer/tickets/confirm', 'POST', 'customer-ticket', customer],
   ['/agents/customer/tickets/confirm/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000001/30000000-0000-4000-8000-000000000001', 'GET', 'saved-ticket', customer],
   ['/admin/tickets', 'GET', 'admin-ticket-list', admin],
   ['/admin/tickets/7', 'GET', 'admin-ticket-detail', admin],
 ]) {
   const response = await fetch(mounted.base + path, { method, headers: requestHeaders });
   assert.equal(response.status, 200, `${method} ${path}`);
   assert.deepEqual(await response.json(), { mounted: expected });
 }
 const unknown = await fetch(mounted.base + '/admin/tickets/7/export', { headers: admin });
 assert.equal(unknown.status, 404);
 assert.deepEqual(await unknown.json(), { error: 'Bound SecureShop route not found' });
 assert.equal(mounted.legacyCalls(), 0);

 const absent = await fixture(t);
 for (const [path, method, requestHeaders] of [
   ['/agents/customer/tickets/confirm', 'POST', customer],
   ['/agents/customer/tickets/confirm/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000001/30000000-0000-4000-8000-000000000001', 'GET', customer],
   ['/admin/tickets', 'GET', admin],
   ['/admin/tickets/7', 'GET', admin],
 ]) {
   const response = await fetch(absent.base + path, { method, headers: requestHeaders });
   assert.equal(response.status, 503, `${method} ${path}`);
   assert.deepEqual(await response.json(), { error: 'Bound SecureShop operation unavailable' });
 }
 assert.equal(absent.legacyCalls(), 0);
});

test('product search and coupon probe capability availability remain independent',async t=>{
 for(const enabled of ['productSearchRouter','couponProbeRouter']){
  const slug=enabled==='productSearchRouter'?'product-search':'coupon-probe',other=slug==='product-search'?'coupon-probe':'product-search';
  const route=express.Router();route.get(`/customer/${slug}/capabilities`,(_req,res)=>res.json({ready:true}));
  const f=await fixture(t,{[enabled]:route});
  const ready=await fetch(`${f.base}/customer/${slug}/capabilities`,{headers:headers()});assert.equal(ready.status,200);assert.deepEqual(await ready.json(),{ready:true});
  const disabled=await fetch(`${f.base}/customer/${other}/capabilities`,{headers:headers()});assert.equal(disabled.status,200);assert.deepEqual(await disabled.json(),{ready:false});
  const unavailable=await fetch(`${f.base}/customer/${other}/session`,{method:'POST',headers:{...headers(),'content-type':'application/json'},body:'{}'});assert.equal(unavailable.status,503);assert.equal(f.legacyCalls(),0);
 }
});

test('order status and coupon probe capability availability remain independent',async t=>{
 for(const enabled of ['orderStatusRouter','couponProbeRouter']){
  const slug=enabled==='orderStatusRouter'?'order-status':'coupon-probe',other=slug==='order-status'?'coupon-probe':'order-status';
  const route=express.Router();route.get(`/customer/${slug}/capabilities`,(_req,res)=>res.json({ready:true}));
  const f=await fixture(t,{[enabled]:route});
  const ready=await fetch(`${f.base}/customer/${slug}/capabilities`,{headers:headers()});assert.equal(ready.status,200);assert.deepEqual(await ready.json(),{ready:true});
  const disabled=await fetch(`${f.base}/customer/${other}/capabilities`,{headers:headers()});assert.equal(disabled.status,200);assert.deepEqual(await disabled.json(),{ready:false});
  const unavailable=await fetch(`${f.base}/customer/${other}/session`,{method:'POST',headers:{...headers(),'content-type':'application/json'},body:'{}'});assert.equal(unavailable.status,503);assert.equal(f.legacyCalls(),0);
 }
});

test('file summary real multipart reaches the mounted gateway with bounded canonical bytes', async t => {
  const calls = [];
  const requestId = '50000000-0000-4000-8000-000000000091';
  const operationId = '60000000-0000-4000-8000-000000000091';
  const authenticatePersona = (req, res, next) => {
    if (req.get('authorization') !== 'Bearer customer-41') return res.status(401).json({ error: 'Unavailable' });
    req.ssUser = { id: 41, role: 'customer' };
    req.ssPersonaSession = { sessionId: currentSessionId, authorityVersion: '2' }; next();
  };
  const fileSummaryRouter = require('../server/routes/secureshop/boundFileSummary').createBoundFileSummaryRouter({
    launches: { async resolveCapability(value) { return value === launchBearer ? launchScope : null; } },
    authenticatePersona,
    graph: {
      async createSession() { return { id: currentSessionId }; },
      async run(input) {
        calls.push(input);
        return { text: 'Controlled summary', stopReason: 'end_turn', taskMetadata: { boundFileSummary: {
          originalEnvelope: JSON.stringify({ attachment: { filename: input.attachment.filename,
            byteCount: input.attachment.bytes.length } }), operationId, outcome: 'read', privateTrace: 'hidden'
        } } };
      }
    },
    saved: { async read(input) { return { sessionId: input.sessionId, requestId: input.requestId, status: 'unconfirmed' }; } },
    assessment: { async runAttempt() {}, async readOutcome() {} },
    modeAuthority: { capture() {}, assertToken() {} }
  });
  const f = await fixture(t, { fileSummaryRouter }), auth = headers('customer', 41);
  const url = f.base + '/agents/customer/file-summary';
  const session = await fetch(url + '/session', { method: 'POST', headers: { ...auth, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(session.status, 200); assert.deepEqual(await session.json(), { id: currentSessionId });
  function form({ filename = 'notes.md', mime = 'application/octet-stream', bytes = Buffer.from('# Exact source'), message = 'Summarize this attachment.', extra, duplicate = false } = {}) {
    const body = new FormData(); body.set('sessionId', currentSessionId); body.set('requestId', requestId);
    body.set('message', message); body.set('file', new Blob([bytes], { type: mime }), filename);
    if (extra) body.set(extra, 'unexpected');
    if (duplicate) body.append('message', 'second');
    return body;
  }
  for (const mime of ['', 'application/octet-stream', 'text/plain', 'text/markdown']) {
    const response = await fetch(url + '/run', { method: 'POST', headers: auth, body: form({ mime }) });
    assert.equal(response.status, 200, mime);
    const dto = await response.json(); assert.equal(dto.status, 'completed');
    assert.deepEqual(Object.keys(dto).sort(), ['byteCount','filename','operationId','replayed','requestId','sessionId','status','text']);
    assert.equal(calls.at(-1).attachment.mime, 'text/markdown');
    assert.deepEqual(calls.at(-1).attachment.bytes, Buffer.from('# Exact source'));
  }
  const max = await fetch(url + '/run', { method: 'POST', headers: auth,
    body: form({ filename: 'notes.txt', bytes: Buffer.alloc(8192, 97), message: 'a'.repeat(8192) }) });
  assert.equal(max.status, 200); await max.json(); assert.equal(calls.at(-1).attachment.mime, 'text/plain');
  const before = calls.length;
  for (const input of [{ extra: 'public' }, { duplicate: true }, { message: 'x'.repeat(8193) },
    { bytes: Buffer.alloc(8193, 97) }, { bytes: Buffer.from([255]) }, { bytes: Buffer.from([0]) },
    { filename: 'notes.html' }, { mime: 'text/html' }]) {
    const response = await fetch(url + '/run', { method: 'POST', headers: auth, body: form(input) });
    assert.equal(response.status, 400, JSON.stringify(input)); await response.json();
  }
  assert.equal(calls.length, before);
  const saved = await fetch(url + '/requests/' + currentSessionId + '/' + requestId, { headers: auth });
  assert.equal(saved.status, 200); assert.deepEqual(await saved.json(), { sessionId: currentSessionId, requestId, status: 'unconfirmed' });
  assert.equal(calls.length, before); assert.equal(f.legacyCalls(), 0);
});

test('mounted traversal GETs reject old-generation persona JWT after reset capability resolves the new generation', async t => {
  const jwt = require('jsonwebtoken');
  const { createSecureShopBoundPersonaAuth, ISSUER, AUDIENCE } = require('../server/services/secureshopBoundPersonaAuth');
  const { createBoundAvatarUploadRouter } = require('../server/routes/secureshop/boundAvatarUpload');
  let generation = launchScope.generation, sessionReads = 0, authorityChecks = 0, operationReads = 0, assessmentReads = 0;
  const scope = () => ({ ...launchScope, generation });
  const launches = {
    async resolveCapability(value) { return value === launchBearer ? scope() : null; },
    async assertCurrent(value) { authorityChecks++; assert.equal(value.generation, generation); }
  };
  const repository = Object.fromEntries(['findCredential','createSession','extendSession','revokeSession',
    'listSessions','revokeOwnedSession','changePassword','readApiKey','rotateApiKey','authenticateApiKey']
    .map(name => [name, async () => assert.fail('unexpected authentication write: ' + name)]));
  repository.readSession = async () => { sessionReads++; return { session_id: currentSessionId, shop_user_id: 41,
    username: 'student_customer', email: 'customer@owned.invalid', role: 'customer', full_name: null,
    phone: null, expires_at: new Date(Date.now() + 60000).toISOString() }; };
  const secret = 'mounted-v46-reset-auth-synthetic-secret-32-bytes';
  const auth = createSecureShopBoundPersonaAuth({ repository, launches, jwtSecret: secret });
  const token = jwt.sign({ role:'customer', username:'student_customer', ss_launch_id:launchScope.launchId,
    ss_scenario_id:launchScope.scenarioId, ss_generation:launchScope.generation,
    ss_owner_id:launchScope.platformOwnerId, ss_platform_session_id:launchScope.platformSessionId }, secret,
  { algorithm:'HS256', issuer:ISSUER, audience:AUDIENCE, subject:'41', jwtid:'mounted-v46-original', expiresIn:3600 });
  const unavailable = async () => assert.fail('request must not create model, effect, Judge or credit');
  const saved = { operationId:currentSessionId, uploadRequestId:otherSessionId, status:'denied',
    filename:'....//owned.txt', byteCount:9, denialCode:'PATH_TRAVERSAL_DENIED' };
  const avatarUploadRouter = createBoundAvatarUploadRouter({ launches, authenticatePersona:auth.authenticatePersona,
    graph:{createSession:unavailable,run:unavailable},traversalGraph:{createSession:unavailable,run:unavailable},
    saved:{async read(){operationReads++;return saved;},asset:unavailable},
    assessment:{runAttempt:unavailable,readOutcome:unavailable},
    svgAssessment:{runAttempt:unavailable,readOutcome:unavailable},
    traversalAssessment:{runAttempt:unavailable,async readOutcome(){assessmentReads++;return {completed:false,status:'ineligible',modelEvaluated:false};}}
  });
  const f = await fixture(t, { avatarUploadRouter, boundDispatch:true, resolveCapabilityOverride:launches.resolveCapability });
  const paths = [`/agents/customer/avatar-upload/path-traversal/requests/${otherSessionId}`,
    `/agents/customer/avatar-upload/path-traversal/assessment/${currentSessionId}/${otherSessionId}`];
  const request = path => fetch(f.base + path, { headers:{authorization:`Bearer ${token}`,'x-dvaia-secureshop-launch':launchBearer} });
  for (const path of paths) assert.equal((await request(path)).status,200);
  assert.equal(operationReads,1);assert.equal(assessmentReads,1);
  generation++;
  const before={sessionReads,authorityChecks,operationReads,assessmentReads};
  for (const path of paths) {
    const response=await request(path);assert.equal(response.status,401);
    assert.deepEqual(await response.json(),{error:'Shop authentication required'});
    assert.equal(response.headers.get('x-dvaia-secureshop-launch-state'),null);
  }
  assert.deepEqual({sessionReads,authorityChecks,operationReads,assessmentReads},before);
  assert.equal(f.legacyCalls(),0);assert.deepEqual(f.calls,[]);
});

test('mounted file-path summary routes preserve exact fixed and sibling DTOs and reject old-generation persona JWT after reset capability resolves the new generation', async t => {
  const jwt = require('jsonwebtoken');
  const { createSecureShopBoundPersonaAuth, ISSUER, AUDIENCE } = require('../server/services/secureshopBoundPersonaAuth');
  const { createBoundFilePathSummaryRouter } = require('../server/routes/secureshop/boundFilePathSummary');
  let generation = launchScope.generation, sessionReads = 0, authorityChecks = 0, operationReads = 0, assessmentReads = 0;
  const scope = () => ({ ...launchScope, generation });
  const launches = {
    async resolveCapability(value) { return value === launchBearer ? scope() : null; },
    async assertCurrent(value) { authorityChecks++; assert.equal(value.generation, generation); }
  };
  const repository = Object.fromEntries(['findCredential','createSession','extendSession','revokeSession',
    'listSessions','revokeOwnedSession','changePassword','readApiKey','rotateApiKey','authenticateApiKey']
    .map(name => [name, async () => assert.fail('unexpected authentication write: ' + name)]));
  repository.readSession = async () => { sessionReads++; return { session_id: currentSessionId, shop_user_id: 41,
    username: 'student_customer', email: 'customer@owned.invalid', role: 'customer', full_name: null,
    phone: null, expires_at: new Date(Date.now() + 60000).toISOString() }; };
  const secret = 'mounted-v46-reset-auth-synthetic-secret-32-bytes';
  const auth = createSecureShopBoundPersonaAuth({ repository, launches, jwtSecret: secret });
  const token = jwt.sign({ role:'customer', username:'student_customer', ss_launch_id:launchScope.launchId,
    ss_scenario_id:launchScope.scenarioId, ss_generation:launchScope.generation,
    ss_owner_id:launchScope.platformOwnerId, ss_platform_session_id:launchScope.platformSessionId }, secret,
  { algorithm:'HS256', issuer:ISSUER, audience:AUDIENCE, subject:'41', jwtid:'mounted-v46-original', expiresIn:3600 });
  const unavailable = async () => assert.fail('request must not create model, effect, Judge or credit');
  let denySaved=false, peerRead=false, attempts=0;
  const fixed={completed:false,status:'ineligible',modelEvaluated:false};
  const filePathSummaryRouter=createBoundFilePathSummaryRouter({launches,authenticatePersona:auth.authenticatePersona,
    graph:{createSession:unavailable,run:unavailable},modeAuthority:{capture:unavailable,assertToken:unavailable},
    saved:{async read(input){operationReads++;assert.equal(input.sessionId,currentSessionId);assert.equal(input.requestId,otherSessionId);
      if(denySaved)throw Object.assign(Error('denied'),{code:'FILE_PATH_SUMMARY_UNAVAILABLE'});
      return {sessionId:currentSessionId,requestId:otherSessionId,status:'unconfirmed'};}},
    assessment:{async runAttempt(input){attempts++;assert.equal(input.sessionId,currentSessionId);assert.equal(input.requestId,otherSessionId);return fixed;},
      async readOutcome(){assessmentReads++;if(denySaved||peerRead)throw Object.assign(Error('denied'),{code:'CONVERSATION_UNAVAILABLE'});return fixed;}}
  });
  const f=await fixture(t,{filePathSummaryRouter,boundDispatch:true,resolveCapabilityOverride:launches.resolveCapability});
  const base='/agents/customer/file-path-summary';
  const paths=[`${base}/requests/${currentSessionId}/${otherSessionId}`,`${base}/assess/${currentSessionId}/${otherSessionId}`];
  const request = path => fetch(f.base + path, { headers:{authorization:`Bearer ${token}`,'x-dvaia-secureshop-launch':launchBearer} });
  for (const path of paths) assert.equal((await request(path)).status,200);
  assert.equal(operationReads,1);assert.equal(assessmentReads,1);
  const assessment=await fetch(f.base+base+'/assess',{method:'POST',headers:{authorization:`Bearer ${token}`,
    'x-dvaia-secureshop-launch':launchBearer,'content-type':'application/json'},body:JSON.stringify({sessionId:currentSessionId,requestId:otherSessionId})});
  assert.equal(assessment.status,200);assert.deepEqual(await assessment.json(),fixed);assert.equal(attempts,1);
  peerRead=true;
  const peerRequest=await request(paths[0]);assert.equal(peerRequest.status,200);
  assert.deepEqual(await peerRequest.json(),{sessionId:currentSessionId,requestId:otherSessionId,status:'unconfirmed'});
  const peerAssessment=await request(paths[1]);assert.equal(peerAssessment.status,503);
  assert.deepEqual(await peerAssessment.json(),{error:'File path summary unavailable'});
  assert.equal(attempts,1);peerRead=false;
  denySaved=true;
  for(const path of paths){const response=await request(path);assert.equal(response.status,503);assert.deepEqual(await response.json(),{error:'File path summary unavailable'});}
  generation++;
  const before={sessionReads,authorityChecks,operationReads,assessmentReads,attempts};
  for (const path of paths) {
    const response=await request(path);assert.equal(response.status,401);
    assert.deepEqual(await response.json(),{error:'Shop authentication required'});
    assert.equal(response.headers.get('x-dvaia-secureshop-launch-state'),null);
  }
  assert.deepEqual({sessionReads,authorityChecks,operationReads,assessmentReads,attempts},before);
  assert.equal(f.legacyCalls(),0);assert.deepEqual(f.calls,[]);
});
