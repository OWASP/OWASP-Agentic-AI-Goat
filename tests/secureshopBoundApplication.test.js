'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createSecureShopBoundApplication } = require('../server/services/secureshopBoundApplication');
const { createSecureShopBoundDispatch } = require('../server/middleware/secureshopBoundDispatch');
const { releasePhase } = require('./helpers/workshopCatalogReleasePhase');
const phase = releasePhase();

function fixture() {
  const calls = [];
  const binding = { launchId: '10000000-0000-4000-8000-000000000071', generation: 2,
    platformOwnerId: 17, platformSessionId: 23, credentialVersion: 3, expiresAt: '2026-09-14T00:00:00.000Z' };
  const composition = {
    launches: { resolveCapability: async () => binding, readActiveMetadata: async () => binding },
    router: express.Router(),
    browserRouter: express.Router(),
    personaInbox: { ready: true, router: express.Router() },
    mcpTrust: { ready: true, router: express.Router() },
    ssrf: { ready: true, router: express.Router() },
    catalog: { listProducts: async () => ({ products: [], total: 0 }), getProduct: async () => null,
      listMerchantProducts: async () => ({ products: [] }), categories: async () => ({ categories: [] }),
      createMerchantProduct: async () => ({ product: { id: 1 } }),
      updateMerchantProduct: async () => ({ product: { id: 1 } }),
      archiveMerchantProduct: async () => ({ id: 1 }) },
    commerce: { cart: async()=>({items:[],subtotal:0}),add:async()=>({id:1}),update:async()=>1,
      remove:async()=>1,summary:async()=>({items:[],subtotal:0}),checkout:async()=>({orderId:1,total:0}),
      orders:async()=>[],order:async()=>null },
    account: { profile: async()=>({id:1,username:'fixture',email:'fixture@example.test',role:'customer'}),
      updateProfile:async()=>({}),addresses:async()=>[],createAddress:async()=>({id:1}),
      updateAddress:async()=>({id:1}),deleteAddress:async()=>1 },
    personaAuth: { login: async () => ({}), logout: async () => ({}), renew: async () => ({}),
      listSessions: async () => [], revokeOwnedSession: async () => false,
      changePassword: async () => ({ ok: true }),
      listApiKey: async () => ({ api_key: null, created_at: null, version: null }),
      rotateApiKey: async () => ({ ok: true, api_key: 'sk_ss_live_' + '1'.repeat(32) }),
      authenticateApiKey: async () => ({ user: { id: 1, role: 'customer' }, apiKeyVersion: 1 }),
      authenticatePersona: (_req, res) => res.sendStatus(401) },
    launchResetCoordinator: { recover: async () => ({}), reset: async input => { calls.push(input); return {
      status: 'committed', resetId: '20000000-0000-4000-8000-000000000071',
      fromGeneration: 2, toGeneration: 3, binding: { ...binding, generation: 3 },
    }; } },
    ownerResetService: { assertReady: async () => true,
      resetOwner: async () => ({ completed: true }) },
    createStudentDeletionCleanup: repository => ({ repository }),
  };
  const options = { engine: 'postgres', shopEnabled: true, agentRuntime: {}, audit: async () => {},
    authenticateToken: (req, _res, next) => { req.user = { id: 17 }; req.identitySession = { id: 23 }; next(); },
    getComposition: async () => composition };
  return { options, composition, binding, calls };
}

test('bound application rejects incompatible startup and missing aggregate cleanup', async () => {
  const f = fixture();
  await assert.rejects(createSecureShopBoundApplication({ ...f.options, engine: 'sqlite' }), /PostgreSQL/);
  await assert.rejects(createSecureShopBoundApplication({ ...f.options, shopEnabled: false }), /enabled shop/);
  delete f.composition.launchResetCoordinator;
  await assert.rejects(createSecureShopBoundApplication(f.options), /aggregate launch reset/);
});

test('bound application rejects partial reset/deletion lifecycle and awaits owner reset readiness', async () => {
  const f = fixture();
  delete f.composition.launchResetCoordinator.recover;
  await assert.rejects(createSecureShopBoundApplication(f.options), /aggregate launch reset/);
  f.composition.launchResetCoordinator.recover = async () => ({});
  delete f.composition.createStudentDeletionCleanup;
  await assert.rejects(createSecureShopBoundApplication(f.options), /aggregate launch reset/);
  f.composition.createStudentDeletionCleanup = repository => ({ repository });
  let release;
  f.composition.ownerResetService.assertReady = () => new Promise(resolve => { release = resolve; });
  let settled = false;
  const creating = createSecureShopBoundApplication(f.options).then(value => { settled = true; return value; });
  await Promise.resolve();
  assert.equal(settled, false);
  release(true);
  const application = await creating;
  assert.equal(application.ownerResetService, f.composition.ownerResetService);
  assert.equal(application.createStudentDeletionCleanup, f.composition.createStudentDeletionCleanup);
});

test('application awaits retained composition readiness before exposing either router', async () => {
  const f = fixture(); let release; let resolved = false;
  const pending = new Promise(resolve => { release = resolve; });
  const building = createSecureShopBoundApplication({ ...f.options, getComposition: () => pending });
  building.then(() => { resolved = true; });
  await Promise.resolve(); assert.equal(resolved, false);
  release(f.composition);
  const app = await building;
  assert.equal(typeof app.gateway, 'function'); assert.equal(typeof app.launchRouter, 'function');
  assert.ok(Object.isFrozen(app));
});

test('persona inbox composition and gateway mount require the exact readiness switch', async () => {
  const previous = process.env.SS_PERSONA_INBOX_READY;
  const previousPlatform = process.env.PLATFORM_DATABASE_ENGINE;
  const previousWorkshop = process.env.WORKSHOP_DATABASE_ENGINE;
  try {
    process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
    process.env.WORKSHOP_DATABASE_ENGINE = 'postgres';
    delete process.env.SS_PERSONA_INBOX_READY;
    const disabled = fixture(); let disabledOptions;
    await createSecureShopBoundApplication({ ...disabled.options,
      getComposition: async options => { disabledOptions = options; return disabled.composition; } });
    assert.equal(disabledOptions.personaInboxFeature, phase.generated);

    process.env.SS_PERSONA_INBOX_READY = phase.generated ? 'false' : 'true';
    const enabled = fixture(); let enabledOptions;
    const featureRouter = express.Router();
    featureRouter.get('/v2/persona-inbox/readiness', (_req, res) => res.json({ ready: true }));
    if (!phase.generated) enabled.composition.personaInbox = { ready: true, router: featureRouter };
    const application = await createSecureShopBoundApplication({ ...enabled.options,
      getComposition: async options => { enabledOptions = options; return enabled.composition; } });
    assert.equal(enabledOptions.personaInboxFeature, !phase.generated);
    assert.equal(typeof application.gateway, 'function');
  } finally {
    if (previous === undefined) delete process.env.SS_PERSONA_INBOX_READY;
    else process.env.SS_PERSONA_INBOX_READY = previous;
    if (previousPlatform === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = previousPlatform;
    if (previousWorkshop === undefined) delete process.env.WORKSHOP_DATABASE_ENGINE;
    else process.env.WORKSHOP_DATABASE_ENGINE = previousWorkshop;
  }
});

test('MCP trust mounting is explicitly default-off and carries the owned fixture root only when enabled',async()=>{
  const prior={platform:process.env.PLATFORM_DATABASE_ENGINE,workshop:process.env.WORKSHOP_DATABASE_ENGINE,
    flag:process.env.SS_MCP_TRUST_READY,root:process.env.SS_MCP_TRUST_FIXTURE_ROOT};
  try{process.env.PLATFORM_DATABASE_ENGINE='postgres';process.env.WORKSHOP_DATABASE_ENGINE='postgres';
    delete process.env.SS_MCP_TRUST_READY;delete process.env.SS_MCP_TRUST_FIXTURE_ROOT;
    const disabled=fixture();let disabledOptions;await createSecureShopBoundApplication({...disabled.options,
      getComposition:async options=>{disabledOptions=options;return disabled.composition;}});
    assert.equal(disabledOptions.mcpTrustFeature,false);assert.equal(Object.hasOwn(disabledOptions,'mcpTrustFixtureRoot'),false);
    process.env.SS_MCP_TRUST_READY='true';process.env.SS_MCP_TRUST_FIXTURE_ROOT='/tmp/dvaia-owned-mcp-trust';
    const enabled=fixture();enabled.composition.mcpTrust={ready:true,router:express.Router()};let enabledOptions;
    await createSecureShopBoundApplication({...enabled.options,getComposition:async options=>{enabledOptions=options;return enabled.composition;}});
    assert.equal(enabledOptions.mcpTrustFeature,true);assert.equal(enabledOptions.mcpTrustFixtureRoot,'/tmp/dvaia-owned-mcp-trust');
  } finally {for(const [key,value] of [['PLATFORM_DATABASE_ENGINE',prior.platform],['WORKSHOP_DATABASE_ENGINE',prior.workshop],
    ['SS_MCP_TRUST_READY',prior.flag],['SS_MCP_TRUST_FIXTURE_ROOT',prior.root]]){
    if(value===undefined)delete process.env[key];else process.env[key]=value;}}
});

test('controlled SSRF mounting is explicit and exposes its router only through the bound gateway', async t => {
  const prior = { platform: process.env.PLATFORM_DATABASE_ENGINE,
    workshop: process.env.WORKSHOP_DATABASE_ENGINE, flag: process.env.SS_CONTROLLED_SSRF_READY,
    root: process.env.SS_CONTROLLED_SSRF_FIXTURE_ROOT };
  try {
    process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
    process.env.WORKSHOP_DATABASE_ENGINE = 'postgres';
    delete process.env.SS_CONTROLLED_SSRF_READY;
    delete process.env.SS_CONTROLLED_SSRF_FIXTURE_ROOT;
    const disabled = fixture(); let disabledOptions;
    await createSecureShopBoundApplication({ ...disabled.options,
      getComposition: async options => { disabledOptions = options; return disabled.composition; } });
    assert.equal(disabledOptions.ssrfFeature, false);
    assert.equal(Object.hasOwn(disabledOptions, 'ssrfFixtureRoot'), false);

    process.env.SS_CONTROLLED_SSRF_READY = 'true';
    process.env.SS_CONTROLLED_SSRF_FIXTURE_ROOT = '/tmp/dvaia-owned-ssrf';
    const enabled = fixture(); let enabledOptions;
    enabled.binding.scenarioId = '40000000-0000-4000-8000-000000000071';
    enabled.composition.launches.resolveCapability = async () => enabled.binding;
    enabled.composition.personaAuth.authenticatePersona = (req, _res, next) => {
      req.ssUser = Object.freeze({ id: 91, role: 'customer' }); next();
    };
    const featureRouter = require('../server/routes/secureshop/boundSsrf').createBoundSsrfRouter({
      launches: enabled.composition.launches,
      authenticatePersona: enabled.composition.personaAuth.authenticatePersona,
      feature: { ready: true, availability: { async read() {
        return { registered: true, visible: true, enabled: true };
      } }, application: { async run() { throw new Error('unexpected SSRF run'); } } },
    });
    enabled.composition.ssrf = { ready: true, router: featureRouter };
    const application = await createSecureShopBoundApplication({ ...enabled.options,
      getComposition: async options => { enabledOptions = options; return enabled.composition; } });
    assert.equal(enabledOptions.ssrfFeature, true);
    assert.equal(enabledOptions.ssrfFixtureRoot, '/tmp/dvaia-owned-ssrf');
    let observedPersona;
    const app = express();
    app.use('/api/secureshop', (req, res, next) => {
      res.once('finish', () => { observedPersona = req.ssUser?.id; });
      next();
    }, application.gateway);
    const server = await new Promise(resolve => {
      const value = app.listen(0, '127.0.0.1', () => resolve(value));
    });
    t.after(() => new Promise(resolve => server.close(() => resolve())));
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/v2/controlled-ssrf/readiness`, {
      headers: { 'x-dvaia-secureshop-launch': 'a'.repeat(43) },
    });
    const body = await response.json();
    assert.equal(response.status, 200, JSON.stringify(body));
    assert.deepEqual(body, { ready: true });
    assert.equal(observedPersona, 91, 'the completed real readiness route retains the authenticated persona');
  } finally {
    for (const [key, value] of [['PLATFORM_DATABASE_ENGINE', prior.platform],
      ['WORKSHOP_DATABASE_ENGINE', prior.workshop], ['SS_CONTROLLED_SSRF_READY', prior.flag],
      ['SS_CONTROLLED_SSRF_FIXTURE_ROOT', prior.root]]) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test('composed public launch reset uses platform authority and preserves the legacy boundary', async t => {
  const f = fixture(); const bound = await createSecureShopBoundApplication(f.options);
  const app = express(); app.use(express.json());
  app.use('/api/auth/secureshop-launch', bound.launchRouter);
  app.use('/api/secureshop', createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
  let legacyEffects = 0;
  app.use('/api/secureshop', (_req, res) => { legacyEffects++; res.json({ legacy: true }); });
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const metadata = await fetch(`${origin}/api/auth/secureshop-launch`);
  assert.equal(metadata.status, 200);
  assert.equal((await metadata.json()).preparationOnly, false);
  const result = await fetch(`${origin}/api/auth/secureshop-launch/reset`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ launchId: f.binding.launchId,
      expectedGeneration: 2, idempotencyKey: '30000000-0000-4000-8000-000000000071' }) });
  assert.equal(result.status, 200);
  assert.equal((await result.json()).cleanupComplete, true);
  const resetCall = f.calls.find(item => !Array.isArray(item));
  assert.equal(resetCall.platformOwnerId, 17); assert.equal(resetCall.platformSessionId, 23);
  const unknown = await fetch(`${origin}/api/secureshop/unscoped-write`, {
    headers: { 'x-dvaia-secureshop-launch': 'invalid' } });
  assert.notEqual(unknown.status, 200); await unknown.arrayBuffer();
  assert.equal(legacyEffects, 0);
});

test('bound application rejects every missing installed panel rather than claiming readiness', async () => {
  for (const panel of ['personaInbox', 'mcpTrust', 'ssrf']) {
    const missing = fixture();
    delete missing.composition[panel];
    await assert.rejects(createSecureShopBoundApplication(missing.options), /panel readiness incomplete/);
    const unavailable = fixture();
    unavailable.composition[panel].ready = false;
    await assert.rejects(createSecureShopBoundApplication(unavailable.options), /panel readiness incomplete/);
  }
});

test('requested audit summary capability must exist before gateway readiness',async()=>{
 const previous=process.env.SS_AUDIT_SUMMARY_ENABLED;
 try{
  process.env.SS_AUDIT_SUMMARY_ENABLED='true';const f=fixture();let received;
  f.options.getComposition=async options=>{received=options;return f.composition;};
  await assert.rejects(createSecureShopBoundApplication(f.options),/audit summary runtime unavailable/);
  assert.equal(received.auditSummaryFeature,true);
 }finally{if(previous===undefined)delete process.env.SS_AUDIT_SUMMARY_ENABLED;else process.env.SS_AUDIT_SUMMARY_ENABLED=previous;}
});

test('bound application forwards the startup grading core unchanged before publishing gateways',async()=>{
  const f=fixture(),core=Object.freeze({serverOwned:'test forwarding identity'});let received;
  const app=await createSecureShopBoundApplication({...f.options,gradingCore:core,getComposition:async input=>{received=input.gradingCore;return f.composition;}});
  assert.equal(received,core);assert.equal(typeof app.gateway,'function');
});

test('bound application forwards prepared grading bootstrap and rejects partial mixed configuration',async()=>{
 const f=fixture(),prepared=Object.freeze({fixtureIdentity:true});let received;
 await createSecureShopBoundApplication({...f.options,gradingBootstrap:prepared,getComposition:async input=>{received=input;return f.composition;}});
 assert.equal(received.gradingBootstrap,prepared);assert.equal(Object.hasOwn(received,'gradingCore'),false);
 let composed=false;
 await assert.rejects(createSecureShopBoundApplication({...f.options,gradingCore:{},gradingBootstrap:prepared,getComposition:async()=>{composed=true;return f.composition;}}),/Choose one SecureShop grading configuration/);
 assert.equal(composed,false);
});

test('bound application forwards the prepared policy renderer by identity and fails closed when policy composition is absent',async()=>{
 const renderer=Object.freeze({render:async()=>{throw new Error('not called during composition');}});
 const accepted=fixture();accepted.composition.promptPolicies=Object.freeze({
  list:async()=>[],render:async()=>({}),remove:async()=>({}),operation:async()=>({}),
 });let received;
 const application=await createSecureShopBoundApplication({...accepted.options,promptPolicyRenderer:renderer,
  getComposition:async input=>{received=input;return accepted.composition;}});
 assert.equal(received.promptPolicyRenderer,renderer);assert.equal(typeof application.gateway,'function');

 const missing=fixture();let missingReceived;
 await assert.rejects(createSecureShopBoundApplication({...missing.options,promptPolicyRenderer:renderer,
  getComposition:async input=>{missingReceived=input;return missing.composition;}}),/prompt policy service unavailable/);
 assert.equal(missingReceived.promptPolicyRenderer,renderer);

 const disabled=fixture();let disabledReceived;
 await createSecureShopBoundApplication({...disabled.options,getComposition:async input=>{disabledReceived=input;return disabled.composition;}});
 assert.equal(Object.hasOwn(disabledReceived,'promptPolicyRenderer'),false);
});

test('bound application forwards a prepared System client and advertises it only after composed readiness',async()=>{
 const client=Object.freeze({assertReady:async()=>true,read:async()=>({})});
 const accepted=fixture();accepted.composition.systemConfig=Object.freeze({ready:true,router:express.Router()});let received;
 const application=await createSecureShopBoundApplication({...accepted.options,systemConfigClient:client,
  getComposition:async input=>{received=input;return accepted.composition;}});
 assert.equal(received.systemConfigClient,client);
 assert.deepEqual(application.readiness.capabilities,
  {boundSystemConfigRead:'secureshop-owned-system-config-read.v1'});

 const missing=fixture();await assert.rejects(createSecureShopBoundApplication({...missing.options,
  systemConfigClient:client,getComposition:async input=>{received=input;return missing.composition;}}),
 /System config service unavailable/);assert.equal(received.systemConfigClient,client);
 const disabled=fixture();await createSecureShopBoundApplication({...disabled.options,
  getComposition:async input=>{received=input;return disabled.composition;}});
 assert.equal(Object.hasOwn(received,'systemConfigClient'),false);
 assert.equal(Object.hasOwn(disabled.composition,'systemConfig'),false);
});

test('bound application forwards a prepared diagnostic client and advertises it only after composed readiness',async()=>{
 const client=Object.freeze({assertReady:async()=>true,read:async()=>({})});
 const accepted=fixture();accepted.composition.systemDiagnostic=Object.freeze({ready:true,router:express.Router()});let received;
 const application=await createSecureShopBoundApplication({...accepted.options,systemDiagnosticClient:client,
  getComposition:async input=>{received=input;return accepted.composition;}});
 assert.equal(received.systemDiagnosticClient,client);
 assert.deepEqual(application.readiness.capabilities,
  {boundSystemDiagnostic:'secureshop-owned-system-diagnostic.v1'});

 const missing=fixture();await assert.rejects(createSecureShopBoundApplication({...missing.options,
  systemDiagnosticClient:client,getComposition:async input=>{received=input;return missing.composition;}}),
 /System diagnostic service unavailable/);assert.equal(received.systemDiagnosticClient,client);
 const disabled=fixture();await createSecureShopBoundApplication({...disabled.options,
  getComposition:async input=>{received=input;return disabled.composition;}});
 assert.equal(Object.hasOwn(received,'systemDiagnosticClient'),false);
 assert.equal(Object.hasOwn(disabled.composition,'systemDiagnostic'),false);
});

test('bound System rebuild is explicitly default-disabled and mounts only after composed readiness',async()=>{
 const accepted=fixture();accepted.composition.systemRebuild=Object.freeze({ready:true,router:express.Router()});let received;
 const application=await createSecureShopBoundApplication({...accepted.options,systemRebuildEnabled:true,
  getComposition:async input=>{received=input;return accepted.composition;}});
 assert.equal(received.systemRebuildEnabled,true);assert.deepEqual(application.readiness.capabilities,
  {boundSystemRebuild:'secureshop-owned-system-rebuild.v1'});
 const missing=fixture();await assert.rejects(createSecureShopBoundApplication({...missing.options,
  systemRebuildEnabled:true,getComposition:async input=>{received=input;return missing.composition;}}),
 /System rebuild service unavailable/);assert.equal(received.systemRebuildEnabled,true);
 const disabled=fixture();await createSecureShopBoundApplication({...disabled.options,
  getComposition:async input=>{received=input;return disabled.composition;}});
 assert.equal(received.systemRebuildEnabled,false);assert.equal(Object.hasOwn(disabled.composition,'systemRebuild'),false);
 await assert.rejects(createSecureShopBoundApplication({...disabled.options,systemRebuildEnabled:'true'}),/option must be boolean/);
});
test('prepared owned restart client mounts and advertises only a ready restart composition',async()=>{
 const client=Object.freeze({health:async()=>({}),execute:async()=>({})});
 const accepted=fixture();accepted.composition.systemRestart=Object.freeze({ready:true,router:express.Router()});let received;
 const application=await createSecureShopBoundApplication({...accepted.options,systemRestartClient:client,
  getComposition:async input=>{received=input;return accepted.composition;}});
 assert.equal(received.systemRestartClient,client);assert.deepEqual(application.readiness.capabilities,
  {boundSystemRestart:'secureshop-owned-system-restart.v2'});
 const missing=fixture();await assert.rejects(createSecureShopBoundApplication({...missing.options,
  systemRestartClient:client,getComposition:async input=>{received=input;return missing.composition;}}),
 /System restart service unavailable/);assert.equal(received.systemRestartClient,client);
 const disabled=fixture();await createSecureShopBoundApplication({...disabled.options,
  getComposition:async input=>{received=input;return disabled.composition;}});
 assert.equal(Object.hasOwn(received,'systemRestartClient'),false);
});
test('Analytics capability is advertised only for a ready mounted composition',async()=>{
 const accepted=fixture();accepted.composition.analytics={ready:true,router:express.Router()};const app=await createSecureShopBoundApplication({...accepted.options,getComposition:async()=>accepted.composition});assert.equal(app.readiness.capabilities.boundAnalytics,'secureshop-owned-analytics.v1');
 const disabled=fixture();const closed=await createSecureShopBoundApplication({...disabled.options,getComposition:async()=>disabled.composition});assert.equal(closed.readiness.capabilities?.boundAnalytics,undefined);
});

test('prepared Pricing client is forwarded unchanged and cannot mount partial readiness',async()=>{
 const client=Object.freeze({checkReadiness:async()=>({ready:true})});let received;
 const missing=fixture();await assert.rejects(createSecureShopBoundApplication({...missing.options,pricingHttpClient:client,getComposition:async input=>{received=input;return missing.composition;}}),/Pricing service unavailable/);assert.equal(received.pricingHttpClient,client);
 const good=fixture();good.composition.pricing={ready:true,router:express.Router()};await createSecureShopBoundApplication({...good.options,pricingHttpClient:client,getComposition:async input=>{received=input;return good.composition;}});assert.equal(received.pricingHttpClient,client);
 const disabled=fixture();await createSecureShopBoundApplication({...disabled.options,getComposition:async input=>{received=input;return disabled.composition;}});assert.equal(Object.hasOwn(received,'pricingHttpClient'),false);
});
test('only ready Listings is mounted and advertised by the actual bound application',async()=>{const disabled=fixture();disabled.composition.listings={ready:false,router:express.Router()};const a=await createSecureShopBoundApplication(disabled.options);assert.equal(a.readiness.capabilities?.boundListings,undefined);assert.ok(!a.gateway.stack.some(layer=>layer.handle===disabled.composition.listings.router));const enabled=fixture();enabled.composition.listings={ready:true,router:express.Router()};const b=await createSecureShopBoundApplication(enabled.options);assert.equal(b.readiness.capabilities.boundListings,'secureshop-owned-listings.v1');assert.ok(b.gateway.stack.some(layer=>layer.handle===enabled.composition.listings.router));});

test('mail is mounted and advertised only after composed readiness',async()=>{const disabled=fixture();disabled.composition.mail={ready:false,router:express.Router()};const a=await createSecureShopBoundApplication(disabled.options);assert.equal(a.readiness.capabilities?.boundMail,undefined);assert.ok(!a.gateway.stack.some(layer=>layer.handle===disabled.composition.mail.router));const enabled=fixture();enabled.composition.mail={ready:true,router:express.Router()};const b=await createSecureShopBoundApplication(enabled.options);assert.equal(b.readiness.capabilities.boundMail,'secureshop-owned-mail.v1');assert.ok(b.gateway.stack.some(layer=>layer.handle===enabled.composition.mail.router));});

test('registered admin chat mounts only its separately ready router',async()=>{
 const disabled=fixture(),router=express.Router();disabled.composition.registeredInvocation={ready:false,router};
 const absent=await createSecureShopBoundApplication(disabled.options);assert.equal(absent.gateway.stack.some(layer=>layer.handle===router),false);
 const enabled=fixture();enabled.composition.registeredInvocation={ready:true,router};
 const present=await createSecureShopBoundApplication(enabled.options);assert.equal(present.gateway.stack.some(layer=>layer.handle===router),true);
 const invalid=fixture();invalid.composition.registeredInvocation={ready:true,router:{}};await assert.rejects(createSecureShopBoundApplication(invalid.options));
});

for(const feature of ['idorLesson','couponAgent','couponProbe','productSearch','orderStatus','searchEcho','manualRag','productSummary','filePathSummary']) test(`${feature} mounts only a ready callable router`,async()=>{
 const router=express.Router(),disabled=fixture();
 disabled.composition[feature]={ready:false,router};
 const absent=await createSecureShopBoundApplication(disabled.options);
 assert.equal(absent.gateway.stack.some(layer=>layer.handle===router),false);
 const enabled=fixture();enabled.composition[feature]={ready:true,router};
 const present=await createSecureShopBoundApplication(enabled.options);
 assert.equal(present.gateway.stack.some(layer=>layer.handle===router),true);
 const invalid=fixture();invalid.composition[feature]={ready:true,router:{}};
 await assert.rejects(createSecureShopBoundApplication(invalid.options));
});

test('independent shop authentication and public catalog are exposed without platform account linking', async () => {
  const f = fixture();
  const standaloneAuth = { service: { authenticate: async () => null }, bootstrap: async () => ({}) };
  const publicCatalog = { browse: async () => ({ products: [], total: 0 }) };
  Object.assign(f.composition, { standaloneAuth, publicCatalog });
  const application = await createSecureShopBoundApplication(f.options);
  assert.equal(application.standaloneAuth, standaloneAuth);
  assert.equal(application.publicCatalog, publicCatalog);
  f.composition.standaloneAuth = { service: standaloneAuth.service };
  await assert.rejects(createSecureShopBoundApplication(f.options), /Standalone SecureShop authority unavailable/);
});

test('standalone mode exposes real core without granting full-panel launch readiness', async () => {
  const f = fixture(); const methods = names => Object.fromEntries(names.split(' ').map(name => [name, async () => ({})]));
  f.composition.standaloneAuth = { service: methods('authenticate register login renew logout changePassword establishTenantContext'),
    bootstrap: async () => ({}), cartImport: async () => ({}), reset: methods('readiness reset readRecovery recover'),
    registeredAdminReset: methods('preview reset read reveal acknowledge'), mode: methods('get set'),
    assessmentObjectives: methods('list set'), assessmentRecovery: methods('list retry') };
  f.composition.publicCatalog = methods('browse product related categories reviews');
  f.composition.admin = methods('users kpis');
  delete f.composition.mcpTrust; delete f.composition.ssrf;
  const app = await createSecureShopBoundApplication({ ...f.options, applicationMode: 'standalone' });
  assert.equal(app.readiness, null); assert.equal(app.launchRouter, null);
  assert.equal(app.standaloneReadiness.ready, true); assert.equal(typeof app.gateway, 'function');
  assert.equal(app.standaloneAuth, f.composition.standaloneAuth);
  assert.equal(app.publicCatalog, f.composition.publicCatalog);
  await assert.rejects(createSecureShopBoundApplication(f.options), /panel readiness incomplete/);
  delete f.composition.standaloneAuth.reset;
  await assert.rejects(createSecureShopBoundApplication({ ...f.options, applicationMode: 'standalone' }), /core readiness incomplete/);
  await assert.rejects(createSecureShopBoundApplication({ ...f.options, applicationMode: 'partial' }), /Unknown SecureShop application mode/);
});

test('actual application projects composed unbounded and timing audit readiness through the protected gateway', async t => {
  const previous = process.env.SS_AUDIT_SUMMARY_ENABLED;
  t.after(() => { if (previous === undefined) delete process.env.SS_AUDIT_SUMMARY_ENABLED;
    else process.env.SS_AUDIT_SUMMARY_ENABLED = previous; });
  process.env.SS_AUDIT_SUMMARY_ENABLED = 'true';
  const f = fixture();
  f.binding.scenarioId = '40000000-0000-4000-8000-000000000071';
  f.composition.personaAuth.authenticatePersona = (req, _res, next) => {
    req.ssUser = { id: 91, role: 'admin' }; next();
  };
  f.composition.auditSummary = { createSession: async () => ({}), run: async () => ({}) };
  f.composition.auditUnbounded = { createSession: async () => ({}), run: async () => ({}) };
  f.composition.auditSearch = { createTimingSession: async () => ({}), runTimingAgent: async () => ({}) };
  f.composition.auditTimingReady = true;
  const application = await createSecureShopBoundApplication(f.options);
  const app = express(); app.use('/api/secureshop', application.gateway);
  const server = await new Promise(resolve => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/admin/audit/capabilities`, {
    headers: { 'x-dvaia-secureshop-launch': 'a'.repeat(43) },
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.capabilities.unbounded, { ready: true });
  assert.deepEqual(body.capabilities.timingAgent, { ready: true });
});

for (const [flag, service] of [['fileSummaryFeature', 'fileSummary'], ['filePathSummaryFeature', 'filePathSummary']]) {
  test(`${flag} forwards explicit activation and rejects absent or partial delivery`, async () => {
    for (const supplied of [undefined, { ready: false, router: express.Router() }, { ready: true, router: {} }]) {
      const f = fixture(); f.composition[service] = supplied; let received;
      await assert.rejects(createSecureShopBoundApplication({ ...f.options, [flag]: true,
        getComposition: async value => { received = value; return f.composition; } }),
      new RegExp(`Bound ${service} service unavailable`));
      assert.equal(received[flag], true);
    }
    const f = fixture(), router = express.Router(); f.composition[service] = { ready: true, router }; let received;
    const app = await createSecureShopBoundApplication({ ...f.options, [flag]: true,
      getComposition: async value => { received = value; return f.composition; } });
    assert.equal(received[flag], true); assert.ok(app.gateway.stack.some(layer => layer.handle === router));
    await assert.rejects(createSecureShopBoundApplication({ ...f.options, [flag]: 'true' }), /options must be boolean/);
  });
}
