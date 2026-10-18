'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict');
const fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto');
const ROOT = path.resolve(__dirname, '../..'),
  PREFIX = 'PG_SECURESHOP_STANDALONE_SSRF_RENDERED_';
const NATIVE = 'SECURESHOP_STANDALONE_SSRF_RENDERED_NATIVE',
  BUILD = 'SECURESHOP_STANDALONE_SSRF_RENDERED_BUILD',
  EVIDENCE = 'SECURESHOP_STANDALONE_SSRF_RENDERED_EVIDENCE_PATH';
const POLICY_OUTPUT_NATIVE='SECURESHOP_POLICY_OUTPUT_BROWSER_NATIVE';
const POLICY_OUTPUT=process.env[POLICY_OUTPUT_NATIVE]==='1';
const POLICY_OUTPUT_TITLE='registered standalone customer renders genuine final policy HTML with canonical Judge, saved recovery and launch reset';
const POLICY_OUTPUT_SCOPE='V27 launch-owned policy HTTP and genuine final model HTML; isolated attributed execution, two independent Judge criteria, cookie progress, GET recovery and owner/persona/mode/reset/sibling fences';
const POLICY_OUTPUT_FLAGS=Object.freeze(['passed','isolatedStores','committedFresh110','registeredAuthority','compiledRendererPreflight',
 'baselineNoCredit','originalModelAndHttpBound','canonicalJudgeEvidence','canonicalTenantCredit','fixedSameSourceInertNoCredit',
 'savedRunRecovery','savedAssessmentRecovery','publicProgress','sessionDenied','resetFenced','siblingPositivePreserved','immutablePreserved','fixtureCleaned']);
const TITLE = 'registered standalone customer renders genuine SSRF HTTP and Judge receipts with exact retry and native reset';
const SCOPE = 'current-main registered customer SSRF; three physical real-model actions, same-ID retry, tenant Judge credit, current-launch native coordinator reset, admitted pending sibling preservation';
const FLAGS = Object.freeze(['passed', 'isolatedStores', 'registeredAuthority', 'physicalPublic', 'physicalPrivate', 'privateHttpBound', 'physicalFixed', 'fixedNoHttpNoCredit', 'exactSameIdReplay', 'canonicalJudgeEvidence', 'canonicalTenantCredit', 'sessionDenied', 'resetFenced', 'siblingPositivePreserved', 'immutablePreserved', 'fixtureCleaned']);
const sha = value => crypto.createHash('sha256').update(value).digest('hex'),
  uuid = crypto.randomUUID;
const STORES = Object.freeze({
  IDENTITY: 'identity',
  AGENTS: 'secureshop_agents',
  COMMERCE: 'secureshop',
  REVIEW: 'secureshop_review'
});
function nativeConfig(env = process.env) {
  assert.equal(env[NATIVE], '1');
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(path.resolve(env.DVAIA_CURRENT_MAIN_WORKSPACE || ''), ROOT);
  assert.equal(process.cwd(), ROOT);
  const urls = {};
  for (const [name, store] of Object.entries(STORES)) {
    urls[name] = {};
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const url = new URL(env[PREFIX + name + '_' + role + '_URL']);
      assert.equal(url.protocol, 'postgresql:');
      assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
      assert.equal(url.username, `dvaia_${store}_${role.toLowerCase()}`);
      assert.equal(url.password, '');
      assert.equal(url.search, '');
      assert.equal(url.hash, '');
      urls[name][role] = url.href;
    }
    assert.notEqual(urls[name].RUNTIME, urls[name].MIGRATION);
    const runtime = new URL(urls[name].RUNTIME),
      migration = new URL(urls[name].MIGRATION);
    assert.equal(runtime.pathname, migration.pathname);
    assert.equal(runtime.host, migration.host);
  }
  assert.equal(new Set(Object.values(urls).map(pair => new URL(pair.RUNTIME).pathname)).size, 4);
  assert.equal(env[BUILD], path.join(ROOT, 'client/build'));
  assert(path.isAbsolute(env[EVIDENCE] || ''));
  assert.notEqual(path.resolve(env[EVIDENCE]), ROOT);
  assert(!path.resolve(env[EVIDENCE]).startsWith(ROOT + path.sep));
  return {
    urls,
    build: env[BUILD],
    evidencePath: env[EVIDENCE],
    directory: path.dirname(env[EVIDENCE])
  };
}
function assertPolicyOutputReceipt(value) {
  assert.deepEqual(Object.keys(value).sort(),[...POLICY_OUTPUT_FLAGS,'scope','catalogAdmission','actorCalls','judgeCalls','actionCount','freshPosts','retryPosts','httpEffects','genuineCredit','errors'].sort());
  for(const flag of POLICY_OUTPUT_FLAGS)assert.equal(value[flag],true,flag);
  assert.equal(value.scope,POLICY_OUTPUT_SCOPE);
  assert.deepEqual(value.catalogAdmission,{objectiveId:'ss_policy_final_html_execution',fixtureLocalCandidateAdmission:true,productionQualification:'pending',productionDefaultEnabled:false});
  for(const [key,count] of Object.entries({actorCalls:6,judgeCalls:2,actionCount:3,freshPosts:3,retryPosts:0,httpEffects:3,genuineCredit:1}))assert.equal(value[key],count,key);
  assert.deepEqual(value.errors,[]);return value;
}
function assertReceipt(value) {
  assert(value && Object.getPrototypeOf(value) === Object.prototype);
  assert.deepEqual(Object.keys(value).sort(), [...FLAGS, 'scope', 'actorCalls', 'judgeCalls', 'actionCount', 'freshPosts', 'retryPosts', 'httpEffects', 'genuineCredit', 'errors'].sort());
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  assert.equal(value.scope, SCOPE);
  assert(Number.isSafeInteger(value.actorCalls) && value.actorCalls >= 6);
  assert(Number.isSafeInteger(value.judgeCalls) && value.judgeCalls >= 1 && value.judgeCalls <= 4);
  assert(value.actorCalls + value.judgeCalls <= 14);
  for (const [key, count] of Object.entries({
    actionCount: 3,
    freshPosts: 3,
    retryPosts: 1,
    httpEffects: 2,
    genuineCredit: 1
  })) assert.equal(value[key], count);
  assert.deepEqual(value.errors, []);
  return value;
}
function traceProjection(row) {
  return Object.fromEntries('session_id step kind provider agent_ns tool_name params_json result_json'.split(' ').map(key => [key, row[key] ?? null]));
}
function rawAnswer(call) {
  return call.response.trim().split('\n').map(line => JSON.parse(line).message?.content || '').join('');
}
async function qualifyPolicyRendererSandbox({browser,html,onCapture=async()=>{}}) {
  const H=require('../fixtures/secureshopStandaloneSsrfQualification');
  const code=fs.readFileSync(path.join(ROOT,'client/src/pages/secureshop/bridge/handshake.mjs'),'utf8');
  const sandbox=/frame\.setAttribute\('sandbox', '([^']+)'\)/.exec(code)?.[1];
  assert.equal(sandbox,'allow-scripts allow-forms');
  const loaded=require('../../server/services/secureshopPolicyOutputBrowserQualification').loadPolicyOutputClientArtifact();
  const receipt={version:1,sandbox,sourceSha256:sha(html),component:loaded.component,vuln:null,fixed:null,contextClosed:false};
  let context;
  try{
    context=await browser.createBrowserContext();
    for(const mode of ['vuln','fixed']){
      const page=await context.newPage(),dialogs=[];
      try{
        await page.setRequestInterception(true);page.on('request',request=>void request.abort().catch(()=>{}));
        page.on('dialog',dialog=>{dialogs.push(dialog.type());void dialog.dismiss().catch(()=>{});});
        await page.setContent('<iframe id="owned-policy-frame" sandbox="'+sandbox+'" srcdoc="&lt;base href=\'https://policy-smoke.invalid/\'&gt;&lt;div id=\'sink\'&gt;&lt;/div&gt;"></iframe>');
        const frame=await(await page.$('#owned-policy-frame')).contentFrame();assert(frame);
        const markerAbsentBefore=await frame.evaluate(selector=>document.querySelector(selector)===null,H.POLICY_OUTPUT_MARKER_SELECTOR);
        assert.equal(markerAbsentBefore,true);
        const parsed=await frame.evaluate(({html,selector,handler})=>{
          const doc=new DOMParser().parseFromString(html,'text/html');return{staticMarkers:doc.querySelectorAll(selector).length,
            handlers:[...doc.querySelectorAll('img[onerror]')].map(e=>e.getAttribute('onerror'))};
        },{html,selector:H.POLICY_OUTPUT_MARKER_SELECTOR,handler:H.POLICY_OUTPUT_HANDLER});
        assert.deepEqual(parsed,{staticMarkers:0,handlers:[H.POLICY_OUTPUT_HANDLER]});
        await frame.addScriptTag({content:loaded.script});
        await frame.evaluate(input=>globalThis.__DVAIA_POLICY_OUTPUT_MOUNT__(input),{html,modeCapability:{version:1,
          featureId:'controlled_ssrf',policyVersion:'owned-public-destination-v1',effectiveMode:mode,
          scope:{kind:'launch_feature',id:'controlled_ssrf'}}});
        await frame.waitForFunction(({mode,html,selector,text,handler})=>{
          const reply=document.querySelector('[data-testid="agent-turn-reply"]');if(!reply)return false;
          const markers=reply.querySelectorAll(selector);
          if(mode==='fixed')return reply.textContent===html&&markers.length===0&&reply.querySelectorAll('img,script').length===0;
          if(markers.length!==1||markers[0].textContent!==text||markers[0].childElementCount!==0)return false;
          const image=markers[0].previousElementSibling,rect=markers[0].getBoundingClientRect();
          return image?.localName==='img'&&image.getAttribute('onerror')===handler&&rect.width>0&&rect.height>0;
        },{timeout:10000},{mode,html,selector:H.POLICY_OUTPUT_MARKER_SELECTOR,text:H.POLICY_OUTPUT_MARKER_TEXT,handler:H.POLICY_OUTPUT_HANDLER});
        const observed=await frame.evaluate(({html,selector,mode})=>{
          const reply=document.querySelector('[data-testid="agent-turn-reply"]'),clone=reply.cloneNode(true);
          const count=clone.querySelectorAll(selector).length;for(const marker of clone.querySelectorAll(selector))marker.remove();
          return{markerCount:count,originalDomPreserved:mode==='fixed'?reply.textContent===html:
            clone.innerHTML===new DOMParser().parseFromString(html,'text/html').body.innerHTML};
        },{html,selector:H.POLICY_OUTPUT_MARKER_SELECTOR,mode});
        assert.equal(observed.markerCount,mode==='vuln'?1:0);assert.equal(observed.originalDomPreserved,true);
        assert.deepEqual(dialogs,[],'The production sandbox must continue to suppress modal dialogs');
        receipt[mode]={markerAbsentBefore,staticMarkers:parsed.staticMarkers,markerCount:observed.markerCount,
          originalDomPreserved:observed.originalDomPreserved,dialogs:dialogs.length};await onCapture(structuredClone(receipt));
      }finally{await page.close();}
    }
  }finally{if(context){await context.close();receipt.contextClosed=true;}await onCapture(structuredClone(receipt));}
  return receipt;
}
async function qualifyCompiledPolicyRenderer({browser,onCapture=async()=>{},createQualification,qualifySandbox=qualifyPolicyRendererSandbox}={}) {
  assert.equal(typeof browser?.wsEndpoint,'function');
  const html=require('../fixtures/secureshopStandaloneSsrfQualification').POLICY_OUTPUT_CANARY_HTML;
  const adapter=(createQualification || require('../../server/services/secureshopPolicyOutputBrowserQualification').createSecureShopPolicyOutputBrowserQualification)({
    connectBrowser:()=>require('puppeteer').connect({browserWSEndpoint:browser.wsEndpoint(),protocolTimeout:15000})
  });
  const receipt={controlled:true,actualModel:false,genuineCredit:false,source:html,sourceSha256:sha(html),vuln:null,fixed:null,sandbox:null,adapterClosed:false};
  try {
    for (const mode of ['vuln','fixed']) {
      receipt[mode]=await adapter.qualifyPolicyOutput({html,modeCapability:{version:1,featureId:'controlled_ssrf',
        policyVersion:'owned-public-destination-v1',effectiveMode:mode,scope:{kind:'launch_feature',id:'controlled_ssrf'}}});
      await onCapture(structuredClone(receipt));
      assert.equal(receipt[mode].component.id,'SecureShop.PolicyFinalResponse');
      assert.equal(receipt[mode].renderedSourceSha256,receipt.sourceSha256);
      assert.equal(receipt[mode].renderingMode,'client');
      assert.equal(receipt[mode].syntheticCookieOnly,true);assert.equal(receipt[mode].finalCookieIsSyntheticOnly,true);
      assert.equal(receipt[mode].executed,mode==='vuln');
      assert.equal(receipt[mode].targetEventExecuted,mode==='vuln');
      assert.equal(receipt[mode].targetEffectObserved,mode==='vuln');
    }
    receipt.sandbox=await qualifySandbox({browser,html,onCapture:async value=>{receipt.sandbox=value;await onCapture(structuredClone(receipt));}});
    assert.equal(receipt.sandbox.contextClosed,true);assert.equal(receipt.sandbox.sourceSha256,receipt.sourceSha256);
  } finally {await adapter.close();receipt.adapterClosed=true;await onCapture(structuredClone(receipt));}
  return Object.freeze(receipt);
}
function assertConsumedPolicyHttpAuthority(consumed,scope,original) {
  const keys=require('../../server/services/secureshopSsrfTargetPool').SSRF_SCOPE_KEYS;
  const request=original.proof.request;
  assert.deepEqual(Object.fromEntries(keys.map(key=>[key,consumed.binding[key]])),{...scope,targetId:request.targetId});
  assert.deepEqual(consumed.input,{nonce:request.nonce,requestId:request.requestId});
  for(const key of ['operationId','targetId','nonce','requestId'])assert.equal(consumed.receipt[key],request[key],key);
}
function observeConsumedSsrfReceipts(createBundle, observe) {
  assert.equal(typeof createBundle, 'function');
  assert.equal(typeof observe, 'function');
  return options => {
    const bundle = createBundle(options);
    assert.equal(typeof bundle.targetPool?.consume, 'function');
    return Object.freeze({
      ...bundle,
      targetPool: Object.freeze({
        ...bundle.targetPool,
        consume(binding, input) {
          // Capture only the original successful return. Production deletes its
          // transient receipt here, after the immutable invocation is committed.
          const receipt = bundle.targetPool.consume(binding, input);
          observe(binding, input, receipt);
          return receipt;
        }
      })
    });
  };
}
function createSsrfCore(options, env = process.env) {
  const personaInboxFeature = require('../../server/services/secureshopPersonaInboxActivationPolicy').activationPolicy(env).requested;
  return require('../../server/services/secureshopBoundReviewComposition').createSecureShopBoundReviewComposition({
    ...options,
    personaInboxFeature
  });
}

// Reuse the supported standalone application contract. The isolated process
// owns this ephemeral real encryption key; no installed key or account is read.
async function createStandaloneSsrfMount({
  composition,
  identityPool,
  standalone,
  bootstrap,
  reset,
  mode,
  catalog,
  publicCatalog,
  personaAuthority,
  judge,
  policyOutput=false
}) {
  const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope').createRegisteredAdminResetEnvelope({
    activeKeyId: 'c32-owned',
    keys: new Map([['c32-owned', crypto.randomBytes(32)]])
  });
  const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository').createRegisteredAdminResetRepository({
    pool: identityPool,
    envelope: resetEnvelope
  });
  await resetRepository.checkReadiness();
  const registeredAdminReset = require('../../server/services/secureshopRegisteredAdminReset').createRegisteredAdminResetService({
    repository: resetRepository
  });
  const assessmentRecovery = require('../../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({
    identityPool,
    authService: standalone,
    bootstrap,
    launches: composition.launches,
    personaAuth: composition.personaAuth,
    personaAuthority,
    judge
  });
  const cartImport = require('../../server/services/secureshopStandaloneCartImport').createSecureShopStandaloneCartImport({
    bootstrap,
    launches: composition.launches,
    personaAuth: composition.personaAuth,
    commerce: composition.commerce
  });
  const practices = require('../../server/services/secureshopPracticeAdmission').createSecureShopPracticeAdmission({
    repository: require('../../server/database/postgres/secureshopPracticeAdmissionRepository').createSecureShopPracticeAdmissionRepository({
      pool: identityPool
    }),
    catalog: composition.catalog
  });
  const mounted = {
    ...composition,
    publicCatalog,
    standaloneAuth: {
      service: standalone,
      bootstrap,
      reset,
      mode,
      assessmentObjectives: catalog,
      registeredAdminReset,
      assessmentRecovery,
      ...(policyOutput ? {assessmentProgress:require('../../server/services/secureshopAssessmentProgress').createSecureShopAssessmentProgress({
        repository:require('../../server/database/postgres/secureshopAssessmentProgressRepository').createSecureShopAssessmentProgressRepository({pool:identityPool})})} : {}),
      cartImport,
      practices
    }
  };
  const bound = await require('../../server/services/secureshopBoundApplication').createSecureShopBoundApplication({
    engine: 'postgres',
    shopEnabled: true,
    applicationMode: 'standalone',
    authenticateToken: (_req, res) => res.sendStatus(401),
    audit: async () => {},
    agentRuntime: {},
    getComposition: async options => {
      assert.equal(options.ssrfFeature, true, 'The genuine SSRF panel must be requested');
      return mounted;
    }
  });
  assert.equal(bound.readiness, null);
  assert.equal(bound.launchRouter, null);
  assert.equal(bound.standaloneReadiness.ready, true);
  assert(Object.values(bound.standaloneReadiness.checks).every(value => value === true));
  assert(bound.gateway.stack.some(layer => layer.handle === composition.ssrf.router));
  return {
    mounted,
    bound
  };
}
test(POLICY_OUTPUT?POLICY_OUTPUT_TITLE:TITLE, {
  skip: process.env[NATIVE] !== '1',
  timeout: 900000
}, async () => {
  const cfg = nativeConfig();
  assert.equal(process.versions.node, '26.10.0');
  assert.equal(fs.realpathSync(ROOT), ROOT);
  assert.equal(fs.realpathSync(cfg.build), cfg.build);
  assert(fs.statSync(path.join(cfg.build, 'index.html')).isFile());
  assert.equal(fs.realpathSync(cfg.directory), cfg.directory);
  const stat = fs.statSync(cfg.directory);
  assert.equal(stat.uid, process.getuid());
  assert.equal(stat.mode & 0o077, 0);
  const status = Object.fromEntries((POLICY_OUTPUT?POLICY_OUTPUT_FLAGS:FLAGS).map(key => [key, false]));
  Object.assign(status, {
    scope: POLICY_OUTPUT?POLICY_OUTPUT_SCOPE:SCOPE,
    ...(POLICY_OUTPUT?{catalogAdmission:null}:{}),
    actorCalls: 0,
    judgeCalls: 0,
    actionCount: 0,
    freshPosts: 0,
    retryPosts: 0,
    httpEffects: 0,
    genuineCredit: 0,
    errors: []
  });
  const retained = {
    version: 1,
    phase: 'initializing',
    sourcePins: {
      before: {},
      after: {}
    },
    wire: [],
    transcripts: [],
    fullSnapshots: [],
    cases: [],
    requests: [],
    lifecycle: {},
    rendered: null
  };
  const save = () => {
    const bytes = JSON.stringify(retained, null, 2);
    assert(Buffer.byteLength(bytes) <= 16 * 1024 * 1024);
    fs.writeFileSync(path.join(cfg.directory, 'standalone-ssrf-capture.json'), bytes, {
      mode: 0o600
    });
    fs.writeFileSync(cfg.evidencePath, JSON.stringify(status, null, 2), {
      mode: 0o600
    });
  };
  const pinned = ['tests/postgres/secureshopStandaloneSsrfRendered.integration.test.js', 'tests/fixtures/secureshopStandaloneSsrfQualification.js', 'tests/fixtures/secureshopStandaloneSsrfRenderedQualification.js', 'tests/fixtures/secureshopAnalyticsBrowserOwner.js', 'tests/fixtures/browserProcessOwnership.js', 'tests/postgres/secureshopMailActualTransport.js', 'server/routes/secureshopStandaloneAuth.js', 'server/routes/secureshop/boundSsrf.js', 'server/services/secureshopStandaloneBootstrap.js', 'server/services/secureshopSsrfComposition.js', 'server/services/secureshopSsrfExternalAdapter.js', 'server/services/secureshopSsrfEvidence.js', 'server/database/postgres/secureshopAssessmentStore.js', 'server/agent-runtime/objectiveJudge.js', 'client/src/pages/secureshop/components/ControlledSsrfLab.jsx', 'client/src/pages/secureshop/SecureShopStandaloneBound.jsx', 'client/src/pages/secureshop/SecureShopStandaloneModeControl.jsx'];
  if(POLICY_OUTPUT)pinned.push(...['server/services/secureshopPolicyFinalHtmlContract.js','server/services/secureshopPolicyFinalHtmlOriginal.js',
    'server/services/secureshopPolicyFinalHtmlEvidence.js','server/services/secureshopPolicyFinalHtmlAssessment.js',
    'server/services/secureshopPolicyOutputBrowserQualification.js','client/src/pages/secureshop/policyOutputClientRenderer.jsx',
    'client/src/pages/secureshop/components/PolicyFinalHtmlLab.jsx','client/src/pages/secureshop/utils/policyFinalHtmlReference.mjs',
    'client/src/pages/secureshop/components/AgentLane/Turn.jsx','client/vite.policy-output-renderer.config.mjs',
    'db/postgres/workshop-migrations/secureshop_agents/0110_policy_final_html.sql','client/src/pages/secureshop/bridge/handshake.mjs']);
  for (const file of pinned) retained.sourcePins.before[file] = sha(fs.readFileSync(path.join(ROOT, file)));
  save();
  const pools = [],
    resources = [],
    oldEnv = Object.fromEntries(['SECURESHOP_DATABASE_URL', 'JUDGE_PROVIDER', 'JUDGE_MODEL', 'OLLAMA_BASE_URL', 'SS_CONTROLLED_SSRF_READY', 'SS_CONTROLLED_SSRF_FIXTURE_ROOT'].map(key => [key, process.env[key]]));
  const {
      Pool
    } = require('pg'),
    make = (name, role, max = 4) => {
      const pool = new Pool({
        connectionString: cfg.urls[name][role],
        max,
        connectionTimeoutMillis: 5000,
        statement_timeout: 10000
      });
      pools.push(pool);
      return pool;
    };
  const identity = make('IDENTITY', 'RUNTIME', 6),
    im = make('IDENTITY', 'MIGRATION'),
    agents = make('AGENTS', 'RUNTIME', 6),
    am = make('AGENTS', 'MIGRATION'),
    commerce = make('COMMERCE', 'RUNTIME'),
    cm = make('COMMERCE', 'MIGRATION'),
    review = make('REVIEW', 'RUNTIME'),
    rm = make('REVIEW', 'MIGRATION'),
    lease = make('IDENTITY', 'RUNTIME'),
    provision = make('IDENTITY', 'RUNTIME', 1);
  let transport,
    policyBrowser,
    browser,
    httpServer,
    lifecycle,
    composition,
    standalone,
    bootstrap,
    ownerBase,
    owner,
    ownerPrincipal,
    sibling,
    modeRepository,
    currentCase = null,
    failure;
  const heads = new Map(),
    runHeads = new Map(),
    normalized = new Map(),
    judgeByRun = new Map(),
    originalResults = new Map(),
    consumedReceipts = new Map();
  const targetRoot = path.join(cfg.directory, 'ssrf-owned-targets');
  const runtime = path.join(cfg.directory,'runtime');
  fs.mkdirSync(targetRoot, {
    mode: 0o700
  });
  const snapshot = async (context, label) => {
    const s = context.scope,
      args = [s.launchId, s.platformOwnerId, s.platformSessionId, s.generation];
    const targets = (await agents.query('SELECT * FROM secureshop_agents.bound_ssrf_targets WHERE launch_id=$1 AND original_platform_owner_id=$2 AND original_platform_session_id=$3 AND generation=$4 ORDER BY target_id', args)).rows;
    const requests = (await agents.query('SELECT r.* FROM secureshop_agents.bound_ssrf_requests r JOIN secureshop_agents.bound_ssrf_targets t USING(target_id) WHERE t.launch_id=$1 AND t.original_platform_owner_id=$2 AND t.original_platform_session_id=$3 AND t.generation=$4 ORDER BY r.operation_id', args)).rows;
    const invocations = (await agents.query('SELECT i.* FROM secureshop_agents.bound_ssrf_invocations i JOIN secureshop_agents.bound_ssrf_targets t USING(target_id) WHERE t.launch_id=$1 AND t.original_platform_owner_id=$2 AND t.original_platform_session_id=$3 AND t.generation=$4 ORDER BY i.operation_id', args)).rows;
    const sessions = (await agents.query('SELECT * FROM secureshop_agents.agent_sessions WHERE platform_launch_id=$1 AND original_platform_owner_id=$2 AND original_platform_session_id=$3 AND platform_launch_generation=$4 ORDER BY id', args)).rows;
    const turns = (await agents.query('SELECT r.* FROM secureshop_agents.turn_requests r JOIN secureshop_agents.agent_sessions s ON s.id=r.session_id WHERE s.platform_launch_id=$1 AND s.original_platform_owner_id=$2 AND s.original_platform_session_id=$3 AND s.platform_launch_generation=$4 ORDER BY r.session_id,r.request_id', args)).rows;
    const traces = (await agents.query('SELECT t.* FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id WHERE s.platform_launch_id=$1 AND s.original_platform_owner_id=$2 AND s.original_platform_session_id=$3 AND s.platform_launch_generation=$4 ORDER BY t.id', args)).rows;
    const ownerKeys = sessions.map(s => JSON.stringify(['SecureShopBoundConversation', s.id]));
    const runs = (await identity.query('SELECT * FROM graph_runtime.runs WHERE owner_key=ANY($1::text[]) ORDER BY run_id', [ownerKeys])).rows;
    const effects = (await identity.query('SELECT * FROM graph_runtime.effects WHERE owner_key=ANY($1::text[]) ORDER BY run_id,effect_key', [ownerKeys])).rows;
    const judgments = (await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id', [context.principal.tenantId, context.principal.principalId])).rows;
    const contributions = (await identity.query('SELECT * FROM secureshop_auth.assessment_contributions WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id', [context.principal.tenantId, context.principal.principalId])).rows;
    const completions = (await identity.query('SELECT * FROM secureshop_auth.assessment_completions WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id', [context.principal.tenantId, context.principal.principalId])).rows;
    const value = {
      targets,
      requests,
      invocations,
      sessions,
      turns,
      traces,
      runs,
      effects,
      judgments,
      contributions,
      completions
    };
    retained.fullSnapshots.push({
      label,
      value
    });
    save();
    return value;
  };
  const counters = async () => {
    const snap = owner ? await snapshot(owner, 'counter-read') : null;
    return {
      actor: transport?.calls.filter(c => c.kind === 'actor').length || 0,
      judge: transport?.calls.filter(c => c.kind === 'judge').length || 0,
      http: snap?.invocations.length || 0,
      turns: snap?.turns.length || 0,
      invocations: snap?.invocations.length || 0,
      traces: snap?.traces.length || 0,
      judgments: snap?.judgments.length || 0,
      contributions: snap?.contributions.length || 0
    };
  };
  const readCase = async ({
    id,
    request,
    response,
    authority
  }) => {
    const snap = await snapshot(owner, id + '-full-source');
    retained.cases.push({
      id,
      request,
      response,
      snapshot: snap
    });
    save();
    assert.equal(authority.scope.launchId, owner.scope.launchId);
    const target = await composition.ssrf.application.resolveExistingTarget(owner.scope);
    const req = await composition.ssrf.repository.readRequest(target, {
      requestId: request.request_id
    });
    assert(req);
    const interval = snap.traces.filter(t => Number(t.id) > Number(heads.get(request.request_id) || 0));
    const invocation = snap.invocations.find(i => i.request_id === request.request_id),
      mode = await modeRepository.getEvaluationScope(owner.scope.platformOwnerId, 'secureshop_agent_security', owner.scope);
    const requestValue = {
      operationId: req.operationId,
      targetId: target.targetId,
      nonce: req.nonce,
      requestId: request.request_id,
      resourceKind: req.resourceKind,
      url: req.url,
      policyDecision: req.resourceKind === 'public-policy' ? 'allowed' : 'denied',
      egressPolicySha256: require('../../server/services/secureshopSsrfExternalAdapter').SSRF_EGRESS_POLICY_SHA256
    };
    const decision = interval.find(t => t.kind === 'model_decision' && JSON.parse(t.params_json || '{}').toolCalls?.some(call => call.name === 'summarizer.explain_return_policy' && call.args?.policy_url === req.url && (invocation ? call.id === invocation.call_id : true)));
    assert(decision, 'Real model must select the exact admitted SSRF tool and URL');
    const call = JSON.parse(decision.params_json).toolCalls.find(c => c.name === 'summarizer.explain_return_policy' && c.args?.policy_url === req.url && (invocation ? c.id === invocation.call_id : true));
    const result = interval.find(t => t.kind === 'mcp_result' && t.step === decision.step && t.session_id === decision.session_id && t.agent_ns === 'summarizer' && t.tool_name === 'explain_return_policy');
    const terminal = interval.filter(t => t.kind === 'terminal' && t.session_id === decision.session_id).at(-1);
    assert(result && terminal);
    const actor = retained.wire.map((c, index) => ({
      ...c,
      index
    })).filter(c => c.role === 'actor' && c.caseId === id);
    const selectedWire = actor.find(c => {
      try {
        return JSON.stringify(JSON.parse(rawAnswer(c)).tool_calls) === JSON.stringify([{
          agent: 'summarizer',
          tool: 'explain_return_policy',
          args: call.args
        }]);
      } catch {
        return false;
      }
    });
    const finalWire = actor.findLast(c => {
      try {
        return require('../fixtures/secureshopStandaloneSsrfQualification')
          .normalizeStandaloneSsrfFinalWire(c, { fixed: id === 'fixed-private' }) === response.body.response;
      } catch {
        return false;
      }
    });
    assert(selectedWire && finalWire);
    const turn = snap.turns.find(t => t.session_id === decision.session_id && t.request_id === request.request_id);
    assert.equal(turn?.status, 'completed');
    assert.equal(turn.result_json.text, response.body.response);
    assert.equal(turn.result_json.stopReason, 'end_turn');
    const ownerKey = JSON.stringify(['SecureShopBoundConversation', decision.session_id]);
    const effectKey = `${request.request_id}:${JSON.stringify([decision.step, call.id, call.name])}`;
    const rawEffect = snap.effects.find(e => e.effect_key === effectKey);
    if (invocation) assert(rawEffect, 'The HTTP invocation requires its exact durable effect');
    const effect = invocation ? {
      version: 1,
      runId: invocation.run_id,
      ownerKey,
      generation: String(rawEffect.generation),
      effectKey,
      status: rawEffect.status
    } : null;
    const admittedRuns = snap.runs.filter(run => !runHeads.get(request.request_id)?.has(run.run_id));
    assert.equal(admittedRuns.length, 1, 'One fresh request must bind one actual durable run');
    const admittedRun = admittedRuns[0];
    assert.equal(admittedRun.owner_key, ownerKey);
    assert.equal(admittedRun.status, 'completed');
    const runId = admittedRun.run_id;
    if (invocation) assert.equal(runId, invocation.run_id);
    const inv = invocation ? await composition.ssrf.repository.readInvocation(target, invocation.operation_id) : null;
    const normalizedInvocation = inv ? Object.fromEntries('targetId operationId requestId sessionId runId callId requestMethod requestPath responseStatus resourceKind policyDecision egressPolicySha256 argumentsSha256 resultSha256 responseSha256 egressReceiptSha256'.split(' ').map(k => [k, inv[k]])) : null;
    if (inv) normalizedInvocation.launch = owner.scope;
    const consumed = inv ? consumedReceipts.get(inv.operationId) : null;
    if (inv) {
      assert(consumed, 'The invocation requires its original consumed HTTP receipt');
      for (const key of require('../../server/services/secureshopSsrfTargetPool').SSRF_SCOPE_KEYS)
        assert.equal(consumed.binding[key], target[key], key);
      assert.deepEqual(consumed.input, { nonce: req.nonce, requestId: request.request_id });
      assert.equal(consumed.receipt.operationId, inv.operationId);
      assert.equal(consumed.receipt.targetId, target.targetId);
      assert.equal(consumed.receipt.requestId, request.request_id);
      assert.equal(consumed.receipt.nonce, req.nonce);
    }
    const httpReceipt = consumed?.receipt ?? null;
    const judgments = snap.judgments.filter(j => j.run_id === runId),
      contributions = snap.contributions.filter(c => judgments.some(j => j.evaluation_id === c.evaluation_id));
    const judgmentKeys = 'tenant_id principal_id shop_user_id evaluation_id objective_id run_id generation mode mode_stamp execution_json packet evidence_digest owner_key owner_generation verdict disposition result_json result_serialized result_digest judge_result_json judge_observations'.split(' ');
    const value = {
      id,
      mode: mode.mode,
      modeStamp: mode.modeStamp,
      modeGeneration: mode.generation,
      modeRevision: (await modeRepository.getPrincipalMode(owner.principal)).revision,
      resource: request.resource,
      requestId: request.request_id,
      sessionId: decision.session_id,
      runId,
      ownerKey,
      ownerGeneration: String(JSON.parse(result.result_json)._meta?.generation ?? (await identity.query('SELECT generation FROM graph_runtime.runs WHERE run_id=$1', [runId])).rows[0].generation),
      decision: {
        wireIndex: selectedWire.index,
        step: decision.step,
        callId: call.id,
        tool: call.name,
        args: call.args
      },
      final: {
        wireIndex: finalWire.index,
        text: response.body.response
      },
      traces: {
        decision: traceProjection(decision),
        result: traceProjection(result),
        terminal: traceProjection(terminal)
      },
      request: requestValue,
      invocation: normalizedInvocation,
      httpReceipt,
      effect,
      effectCounts: {
        http: invocation ? 1 : 0,
        invocations: invocation ? 1 : 0,
        judgments: judgments.length,
        contributions: contributions.length
      },
      judgments: judgments.map(j => Object.fromEntries(judgmentKeys.map(k => [k, j[k]]))),
      contributions: contributions.map(c => ({
        tenant_id: c.tenant_id,
        principal_id: c.principal_id,
        evaluation_id: c.evaluation_id
      }))
    };
    if (judgments.length) {
      const result = judgeByRun.get(runId);
      assert(result);
      originalResults.set(judgments[0].evaluation_id, result);
    }
    normalized.set(id, value);
    save();
    return value;
  };
  try {
    const {
      migrate
    } = require('../../db/postgres/migrate');
    for (const [pool, dir] of [[im, 'identity-migrations'], [am, 'workshop-migrations/secureshop_agents'], [cm, 'workshop-migrations/secureshop'], [rm, 'workshop-migrations/secureshop_review']]) {
      await migrate(pool, path.join(ROOT, 'db/postgres', dir));
      assert.deepEqual(await migrate(pool, path.join(ROOT, 'db/postgres', dir)), []);
    }
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
    await require('../../server/database/postgres/secureshopStandaloneSeed').seedSecureShopStandaloneDefaults(im);
    await require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults(im);
    status.isolatedStores = true;
    const workshop = 'secureshop_agent_security',
      objective = POLICY_OUTPUT?'ss_policy_final_html_execution':'ss_controlled_ssrf';
    await im.query('UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key=$1', [workshop]);
    await im.query('UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key=$1 AND objective_id=$2', [workshop, objective]);
    if(POLICY_OUTPUT){
      const ledger=(await am.query("SELECT name,checksum FROM dvaia_migrations.ledger WHERE name='0110_policy_final_html.sql'")).rows;
      retained.committedFresh110={ledger,columns:(await am.query("SELECT data_type FROM information_schema.columns WHERE table_schema='secureshop_agents' AND table_name='bound_ssrf_requests' AND column_name='policy_html'")).rows};
      save();assert.deepEqual(ledger,[{name:'0110_policy_final_html.sql',checksum:sha(fs.readFileSync(path.join(ROOT,'db/postgres/workshop-migrations/secureshop_agents/0110_policy_final_html.sql')))}]);assert.deepEqual(retained.committedFresh110.columns,[{data_type:'text'}]);status.committedFresh110=true;
    }
    const launches = require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),
      cleanupAuthority = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository').createSecureShopResetCleanupAuthorityRepository(identity);
    const audit = require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({
      agentsPool: agents,
      reviewPool: review,
      includeRunArtifacts: true
    });
    lifecycle = require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({
      identityPool: identity,
      agentsPool: agents,
      reviewPool: review,
      leasePool: lease,
      provisionPool: provision,
      launches,
      cleanupAuthority,
      audit,
      ssrfFactory: observeConsumedSsrfReceipts(
        require('../../server/services/secureshopSsrfProduction').createSecureShopSsrfRepositoryBundle,
        (binding, input, receipt) => {
          assert(!consumedReceipts.has(receipt.operationId), 'Each HTTP receipt is consumed once');
          consumedReceipts.set(receipt.operationId, {
            binding: structuredClone(binding), input: structuredClone(input), receipt
          });
        }),
      ssrfFixtureRoot: targetRoot
    });
    resources.push(['ssrf-targets', () => lifecycle.ssrf.close()]);
    if(POLICY_OUTPUT){
      fs.mkdirSync(runtime,{mode:0o700});
      browser=await require('../fixtures/secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(runtime,'browser');
      resources.push(['browser-process',()=>browser.close()]);
      retained.rendererPreflight=await qualifyCompiledPolicyRenderer({browser,onCapture:async value=>{retained.rendererPreflight=value;save();}});
      assert.equal(transport,undefined);status.compiledRendererPreflight=true;save();
      policyBrowser=require('../../server/services/secureshopPolicyOutputBrowserQualification').createSecureShopPolicyOutputBrowserQualification({
        connectBrowser:()=>require('puppeteer').connect({browserWSEndpoint:browser.wsEndpoint(),protocolTimeout:15000})});
      resources.push(['policy-output-browser',()=>policyBrowser.close()]);
    }
    transport = await require('./secureshopMailActualTransport').createMailActualTransport({
      allowMetadata: true,
      maxHttpCalls: POLICY_OUTPUT?8:14,
      record: () => {
        retained.wire = transport?.calls.filter(c => c.request).map(c => {
          c.caseId ??= currentCase;
          return {
            role: c.kind,
            caseId: c.caseId,
            status: c.responseComplete && c.status === 200 ? 'returned' : 'pending',
            request: c.request,
            response: c.response || '',
            requestSha256: c.requestSha256,
            responseSha256: c.responseSha256 || null
          };
        }) || [];
        save();
      }
    });
    resources.push(['model-transport', () => transport.close()]);
    const provider = new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
      model: transport.model,
      baseUrl: transport.actorUrl
    });
    // Preserve original configured result identities. The wrapper observes and
    // returns unchanged values; it does not inject a model or replace inference.
    process.env.JUDGE_PROVIDER = 'ollama';
    process.env.JUDGE_MODEL = transport.model;
    process.env.OLLAMA_BASE_URL = transport.judgeUrl;
    const configuredJudge = require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({
      observeExecutionTranscript: value => {
        retained.transcripts.push(value);
        save();
      }
    });
    const judge = async input => {
      const result = await configuredJudge(input);
      judgeByRun.set(input.execution.runId, result);
      return result;
    };
    require('../../server/agent-runtime/judgeProviderConfiguration').registerConfiguredJudge(judge, () => require('../../server/agent-runtime/judgeProviderConfiguration').readJudgeProviderConfig(configuredJudge));
    const grading = await require('../../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({
      identityPool: identity,
      agentsPool: agents,
      resetComposition: lifecycle,
      progress: require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity),
      judge,
      expectedIdentityDatabase: new URL(cfg.urls.IDENTITY.RUNTIME).pathname.slice(1),
      expectedAgentsDatabase: new URL(cfg.urls.AGENTS.RUNTIME).pathname.slice(1)
    });
    const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
      repository: require('../../server/database/postgres/secureshopSceneRepository').createSecureShopProductionSceneRepository({
        pool: identity,
        provisionPool: provision,
        leasePool: lease,
        launches
      }),
      reviewPool: review,
      launches
    });
    modeRepository = require('../../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity);
    const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({
      progress: modeRepository,
      launches
    });
    await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness').assertBoundToolPolicyReadiness(agents);
    const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({
      personaAuthority: grading.personaAuthority,
      audit: audit.agents
    });
    process.env.SECURESHOP_DATABASE_URL = cfg.urls.COMMERCE.RUNTIME;
    const {
        Client
      } = await import('@modelcontextprotocol/sdk/client/index.js'),
      {
        InMemoryTransport
      } = await import('@modelcontextprotocol/sdk/inMemory.js');
    const sdkServer = require('../../agent-host/agents/summarizer/server').createServer(),
      [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair(),
      client = new Client({
        name: 'standalone-ssrf-qualification',
        version: '1.0.0'
      });
    for (const [name, value] of [['sdk-client', client], ['sdk-client-wire', clientTransport], ['sdk-server-wire', serverTransport], ['sdk-server', sdkServer]]) resources.push([name, () => value.close()]);
    resources.push(['sdk-pools', () => require('../../server/database/postgres/secureshopPools').closeSecureShopPools()]);
    await sdkServer.connect(serverTransport);
    await client.connect(clientTransport);
    const upstreamPool = {
      callTool(agent, tool, args, options) {
        assert.equal(agent, 'summarizer');
        assert.equal(tool, 'explain_return_policy');
        return client.callTool({
          name: tool,
          arguments: args
        }, undefined, {
          signal: options?.signal
        });
      }
    };
    composition = createSsrfCore({
      identityPool: identity,
      agentsPool: agents,
      reviewPool: review,
      commercePool: commerce,
      leasePool: lease,
      resetComposition: lifecycle,
      gradingBootstrap: grading,
      scenes,
      modeAuthority,
      toolPolicyRepository,
      agentRuntime: {
        provider,
        pool: upstreamPool
      },
      judge,
      ssrfFeature: true,
      ...(POLICY_OUTPUT?{policyOutputBrowserQualification:policyBrowser}:{}),
      jwtSecret: crypto.randomBytes(32).toString('hex')
    });
    assert.equal(composition.ssrf.ready, true);
    resources.push(['composition-browser', () => composition.closeBrowserAssessment()]);
    standalone = require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({
      repository: require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({
        pool: identity
      })
    });
    bootstrap = require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
      launches,
      personaAuth: composition.personaAuth,
      authService: standalone
    });
    const suffix = uuid().slice(0, 8),
      password = 'standalone-ssrf-owned-only',
      registration = await standalone.register({
        username: 'c32_customer_' + suffix,
        email: 'c32_customer_' + suffix + '@example.invalid',
        password,
        role: 'customer'
      });
    const admin = await standalone.login({
        username: 'student_admin',
        password: 'student123'
      }),
      catalog = require('../../server/services/secureshopAssessmentCatalog').createSecureShopAssessmentCatalog({
        pool: identity,
        authService: standalone
      });
    let catalogRow;
    if(POLICY_OUTPUT){
      status.catalogAdmission=await require('../fixtures/secureshopStandaloneSsrfQualification').admitPolicyOutputDisposableCandidate({
        migration:im,catalog,administratorContext:admin.context,curriculum:require('../../server/config/secureshopCurriculum')});
      catalogRow=(await catalog.list(admin.context)).objectives.find(row=>row.objectiveId===objective);
    }else{
      const catalogRow = (await catalog.list(admin.context)).objectives.find(o => o.objectiveId === objective);
      assert.equal(catalogRow.enabled, false);
      await catalog.set(admin.context, {
        objectiveId: objective,
        enabled: true,
        expectedRevision: catalogRow.revision
      });
    }
    // Explicit pending sibling setup, through canonical APIs. It is not a
    // completed sibling run and creates no terminal, HTTP effect or Judge row.
    const peerId = uuid(),
      peerTenant = uuid(),
      peerSlug = 'c32_peer_' + suffix,
      peerName = 'c32_sibling_' + suffix,
      hash = await require('bcryptjs').hash(password, 12);
    const peer = (await im.query("INSERT INTO secureshop_auth.principals(principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'customer') RETURNING shop_user_id", [peerId, peerName, peerName + '@example.invalid', hash])).rows[0];
    await im.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)', [peerTenant, peerSlug]);
    await im.query("INSERT INTO secureshop_auth.tenant_memberships(tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')", [peerTenant, peerId, peer.shop_user_id]);
    const peerAuth = require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({
        repository: require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({
          pool: identity,
          executionTenantSlug: peerSlug
        })
      }),
      peerLogin = await peerAuth.login({
        username: peerName,
        password
      }),
      peerPrincipal = await peerAuth.establishTenantContext(peerLogin.context),
      peerBootstrap = await require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
        launches,
        personaAuth: composition.personaAuth,
        authService: peerAuth
      })(peerLogin.context);
    async function bind(packet, principal) {
      const resolved = await launches.resolveCapability(packet.bearer);
      assert(resolved);
      const scope = require('../../server/services/secureshopConversationBinding').createLaunchScope(resolved),
        actor = await composition.personaAuth.authenticateBoundToken({
          scope,
          token: packet.persona.token
        });
      return {
        scope,
        principal,
        persona: {
          id: actor.user.id,
          role: actor.user.role
        },
        personaSession: {
          sessionId: actor.sessionId,
          authorityVersion: actor.authorityVersion
        },
        bearer: packet.bearer,
        token: packet.persona.token
      };
    }
    sibling = await bind(peerBootstrap, peerPrincipal);
    const siblingTarget = await composition.ssrf.application.resolveTarget(sibling.scope),
      siblingRequestId = uuid(),
      claimed = await composition.ssrf.repository.claimRequest(siblingTarget, {
        requestId: siblingRequestId,
        resourceKind: 'public-policy'
      }),
      issued = await lifecycle.ssrf.targetPool.issue(siblingTarget, {
        requestId: siblingRequestId,
        resourceKind: 'public-policy',
        operationId: claimed.operationId
      });
    await composition.ssrf.repository.attachRequest(siblingTarget, issued);
    const siblingPending = await composition.ssrf.repository.readRequest(siblingTarget, {
      requestId: siblingRequestId
    });
    assert.equal(siblingPending.completed, false);
    const express = require('express'),
      app = express();
    app.use(express.json());
    const flow = require('../fixtures/secureshopStandaloneSsrfRenderedQualification');
    const ackLoss = flow.createCommittedSsrfAckLoss({
      policyOutput:POLICY_OUTPUT,
      onCommitted: async ({
        request,
        packet
      }) => {
        const snap = await snapshot(owner, 'private-committed-before-ack-loss'),
          inv = snap.invocations.find(i => i.request_id === request.request_id);
        assert(inv);
        const turn = snap.turns.find(t => t.session_id === inv.session_id && t.request_id === request.request_id);
        assert.equal(turn.status, 'completed');
        assert.equal(turn.result_json.text, packet.response);
        return {
          requestId: request.request_id,
          sessionId: inv.session_id,
          status: turn.status,
          result: turn.result_json
        };
      }
    });
    app.use(ackLoss.middleware);
    app.use(async (req, res, next) => {
      try {
        if (req.method === 'POST' && req.path === (POLICY_OUTPUT?flow.HTML_RUN_PATH:flow.RUN_PATH)) {
          retained.requests.push(structuredClone(req.body));
          if (!heads.has(req.body.request_id)) {
            const snap = await snapshot(owner, 'before-' + req.body.resource);
            heads.set(req.body.request_id, Math.max(0, ...snap.traces.map(t => Number(t.id))));
            runHeads.set(req.body.request_id, new Set(snap.runs.map(run => run.run_id)));
            currentCase = POLICY_OUTPUT?['baseline','attack','fixed'][retained.requests.length-1]:req.body.resource === 'public-policy' ? 'public' : normalized.has('private') ? 'fixed-private' : 'private';
          } else currentCase = 'private';
        }
        next();
      } catch (error) {
        next(error);
      }
    });
    const mode = require('../../server/services/secureshopStandaloneMode').createSecureShopStandaloneMode({
        authService: standalone,
        repository: modeRepository
      }),
      reset = require('../../server/services/secureshopStandaloneReset').createSecureShopStandaloneReset({
        identityPool: identity,
        authService: standalone,
        launches,
        scenes,
        resetCoordinator: lifecycle.launchResetCoordinator,
        preflight: lifecycle.sceneResetPreflight
      }),
      publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository').createSecureShopStorePublicCatalogRepository({
        identityPool: identity,
        reviewPool: review,
        commercePool: commerce
      });
    process.env.SS_CONTROLLED_SSRF_READY = 'true';
    process.env.SS_CONTROLLED_SSRF_FIXTURE_ROOT = targetRoot;
    const {
      mounted,
      bound
    } = await createStandaloneSsrfMount({
      composition,
      identityPool: identity,
      standalone,
      bootstrap,
      reset,
      mode,
      catalog,
      publicCatalog,
      personaAuthority: grading.personaAuthority,
      judge,
      policyOutput:POLICY_OUTPUT
    });
    httpServer = await new Promise(resolve => {
      const server = app.listen(0, '127.0.0.1', () => resolve(server));
    });
    resources.push(['http-server', async () => {
      httpServer.closeAllConnections();
      await new Promise(resolve => httpServer.close(resolve));
    }]);
    const origin = 'http://127.0.0.1:' + httpServer.address().port;
    app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth').createSecureShopStandaloneAuthRouter({
      ...mounted.standaloneAuth,
      bootstrap: async raw => {
        ownerBase = raw;
        return bootstrap(raw);
      },
      reset,
      mode,
      assessmentObjectives: catalog,
      allowedOrigins: [origin],
      secureCookies: false
    }));
    app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch').createSecureShopBoundDispatch({
      getGateway: () => bound.gateway
    }));
    app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog').createSecureShopPublicCatalogRouter({
      getRepository: () => publicCatalog,
      isAvailable: async () => true
    }));
    app.use('/api', (_req, res) => res.status(404).json({
      error: 'Outside standalone SSRF qualification'
    }));
    app.use(express.static(cfg.build, {
      setHeaders: res => res.set('Access-Control-Allow-Origin', '*')
    }));
    app.get(/.*/, (_req, res) => res.sendFile(path.join(cfg.build, 'index.html')));
    async function readiness(context) {
      const response = await fetch(origin + '/api/secureshop/v2/controlled-ssrf/'+(POLICY_OUTPUT?'html/readiness':'readiness'), {
        headers: {
          'x-dvaia-secureshop-launch': context.bearer,
          authorization: 'Bearer ' + context.token
        },
        signal: AbortSignal.timeout(15000)
      });
      return {
        status: response.status,
        body: await response.json()
      };
    }
    const siblingPositiveBefore = await readiness(sibling);
    assert.deepEqual(siblingPositiveBefore, {
      status: 200,
      body: {
        ready: true
      }
    });
    const siblingBefore = await snapshot(sibling, 'sibling-pending-before-owner-actions');
    assert.equal(siblingBefore.turns.length, 0);
    assert.equal(siblingBefore.invocations.length, 0);
    assert.equal(siblingBefore.judgments.length, 0);
    assert.equal(siblingBefore.effects.length, 0);
    if(!browser){
      fs.mkdirSync(runtime,{mode:0o700});
      browser=await require('../fixtures/secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(runtime,'browser');
      resources.push(['browser-process',()=>browser.close()]);
    }
    if(POLICY_OUTPUT){
      retained.browser={executableSha256:process.env.ANALYTICS_BROWSER_SHA256,pid:JSON.parse(fs.readFileSync(path.join(runtime,'browser-process.json'))).pid,owned:true,closed:false};save();
      const H=require('../fixtures/secureshopStandaloneSsrfQualification');
      const originals=new Map();
      const originalReader=require('../../server/services/secureshopPolicyFinalHtmlOriginal').createPolicyFinalHtmlOriginalReader({
        repository:composition.ssrf.repository,conversations:lifecycle.conversations,agentsPool:agents,identityPool:identity,
        resolveTarget:composition.ssrf.application.resolveExistingTarget,
        qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider)});
      async function readOriginal({id,request,response,authority}){
        assert.equal(authority.scope.launchId,owner.scope.launchId);
        const binding=require('../../server/services/secureshopConversationBinding').createConversationBinding(owner.scope,owner.persona);
        const token=await require('../../server/services/secureshopFeatureModeAuthority').captureFeatureMode(modeAuthority,binding,'controlled_ssrf');
        const fence=grading.personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,
          sessionId:owner.personaSession.sessionId,authorityVersion:owner.personaSession.authorityVersion});
        const check=async()=>{await launches.assertCurrent(binding);await fence.assertRemoteAdmission();await token.assertCurrent();};
        const original=await originalReader({binding,requestId:request.request_id,sessionId:response.body.sessionId,mode:token.snapshot,check});
        retained.cases.push({id,request,response,original});save();
        assert.equal(original.proof.request.policyHtml,id==='baseline'?H.POLICY_OUTPUT_BASELINE:H.POLICY_OUTPUT_ATTACK);
        assert.equal(original.html,response.body.response);assert.equal(original.source.requestId,request.request_id);
        assert.deepEqual(response.body.modeCapability,original.proof.turn.result_json.modeCapability);
        H.assertPolicyOutputOriginalWire(original,retained.wire.filter(row=>row.role==='actor'&&row.caseId===id));
        const consumed=consumedReceipts.get(original.proof.request.operationId);assert(consumed);
        assertConsumedPolicyHttpAuthority(consumed,owner.scope,original);
        const receipt=consumed.receipt;
        assert.equal(receipt.requestId,request.request_id);assert.equal(receipt.responseSha256,sha(request.policy_html));
        assert.equal(receipt.resourceKind,'html-policy');assert.equal(receipt.status,200);assert.equal(receipt.method,'GET');
        assert.equal(receipt.receiptSha256,original.proof.invocation.egressReceiptSha256);
        assert.equal(receipt.path,new URL(original.proof.request.url).pathname);
        const body=Object.fromEntries('version targetId nonce operationId requestId method path resourceKind status responseSha256'.split(' ').map(key=>[key,receipt[key]]));
        assert.equal(sha(JSON.stringify(body)),receipt.receiptSha256);
        originals.set(id,original);status.originalModelAndHttpBound=originals.size===3;return original;
      }
      async function readAssessment({id,reference,response}){
        const outcome=response.body;retained.assessments??=[];retained.assessments.push({id,reference,response});save();
        assert.equal(response.status,200);
        if(id!=='attack'){
          assert.deepEqual(outcome,{completed:false,status:'ineligible',modelEvaluated:false,...(id==='baseline'?{replayed:false}:{})});
          const counts=await counters();assert.equal(counts.judgments,id==='baseline'?0:1);assert.equal(counts.contributions,id==='baseline'?0:1);
          if(id==='baseline'){assert.equal(counts.judge,0);status.baselineNoCredit=true;}
          else {assert.equal(counts.judge,2);status.fixedSameSourceInertNoCredit=true;}
          return outcome;
        }
        assert.equal(outcome.completed,true);assert.equal(outcome.judgment.verdict,'pass');
        const rows=(await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1 AND tenant_id=$2 AND principal_id=$3',
          [outcome.judgment.evaluationId,ownerPrincipal.tenantId,ownerPrincipal.principalId])).rows;
        assert.equal(rows.length,1);const stored=rows[0],result=judgeByRun.get(stored.run_id);assert(result);
        retained.canonicalJudgment=stored;save();originalResults.set(stored.evaluation_id,result);
        assert.deepEqual(stored.execution_json.scope,owner.scope);assert.equal(stored.execution_json.shopUserId,owner.persona.id);
        assert.equal(stored.execution_json.personaSessionId,owner.personaSession.sessionId);
        assert.equal(stored.execution_json.personaAuthorityVersion,owner.personaSession.authorityVersion);
        assert.equal(stored.tenant_id,ownerPrincipal.tenantId);assert.equal(stored.principal_id,ownerPrincipal.principalId);
        H.assertPolicyOutputJudgment({original:originals.get('attack'),stored,result,
          wire:retained.wire.filter(row=>row.role==='judge'),transcript:retained.transcripts.find(row=>row.header.runId===stored.run_id)});
        for(const table of ['active_assessment_contributions','assessment_completions']){
          const credit=(await identity.query(`SELECT evaluation_id::text FROM secureshop_auth.${table} WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3`,
            [ownerPrincipal.tenantId,ownerPrincipal.principalId,objective])).rows;
          assert.deepEqual(credit,[{evaluation_id:stored.evaluation_id}]);
        }
        status.canonicalJudgeEvidence=true;status.canonicalTenantCredit=true;return stored;
      }
      async function readPublicProgress({page,completed}){
        const value=await page.evaluate(async()=>{const response=await fetch('/api/secureshop/auth/progress',{credentials:'same-origin'});
          return{status:response.status,body:await response.json()};});
        retained.progress??=[];retained.progress.push({completed,...value});save();assert.equal(value.status,200);
        assert.equal(value.body.principalId,ownerPrincipal.principalId);assert.equal(value.body.shopUserId,owner.persona.id);
        H.assertPolicyOutputProgress(value.body,completed);return value.body;
      }
      async function protectedGet(context,route){
        const response=await fetch(origin+'/api/secureshop/v2/controlled-ssrf/html/'+route,{headers:{
          'x-dvaia-secureshop-launch':context.bearer,authorization:'Bearer '+context.token},signal:AbortSignal.timeout(15000)});
        return{status:response.status,body:await response.json()};
      }
      const rendered=await flow.qualifyPolicyOutputRendered({browser,origin,credentials:{username:registration.user.username,password},
        evidenceDirectory:cfg.directory,ackLoss,bindBootstrap:async packet=>{
          ownerPrincipal=await standalone.establishTenantContext(ownerBase);owner=await bind(packet,ownerPrincipal);
          assert.equal(owner.persona.role,'customer');assert.equal(owner.persona.id,ownerPrincipal.shopUserId);
          assert.notEqual(owner.scope.launchId,sibling.scope.launchId);assert.notEqual(owner.scope.platformOwnerId,sibling.scope.platformOwnerId);
          retained.lifecycle.originalReadiness=await readiness(owner);save();assert.deepEqual(retained.lifecycle.originalReadiness,{status:200,body:{ready:true}});
          status.registeredAuthority=true;return owner;
        },readOriginal,readAssessment,readCounters:counters,readPublicProgress,
        verifyLifecycle:async({page,cases})=>{
          assert.equal(originals.size,3);const attack=originals.get('attack'),fixed=originals.get('fixed');
          assert.equal(attack.proof.request.policyHtml,fixed.proof.request.policyHtml);
          assert.equal(fixed.proof.mode.mode,'fixed');
          const before=await snapshot(owner,'owner-before-session-denial'),countBefore=await counters();
          const peerRun=await protectedGet(sibling,'run/'+attack.source.requestId);
          const peerAssessment=await protectedGet(sibling,'assessment/'+attack.source.sessionId+'/'+attack.source.requestId);
          retained.lifecycle.peerDenials={run:peerRun,assessment:peerAssessment};save();
          assert.deepEqual(peerRun,{status:503,body:{error:'Controlled SSRF exercise unavailable'}});
          assert.deepEqual(peerAssessment,{status:503,body:{error:'Controlled SSRF exercise unavailable'}});
          assert.deepEqual(await counters(),countBefore);assert.deepEqual(await snapshot(sibling,'sibling-after-foreign-reads'),siblingBefore);
          const original=owner;
          await composition.personaAuth.revokeOwnedSession({scope:owner.scope,shopPersona:owner.persona,
            currentSessionId:owner.personaSession.sessionId,authorityVersion:owner.personaSession.authorityVersion,sessionId:owner.personaSession.sessionId});
          retained.lifecycle.revokedRun=await protectedGet(original,'run/'+fixed.source.requestId);
          retained.lifecycle.revokedAssessment=await protectedGet(original,'assessment/'+fixed.source.sessionId+'/'+fixed.source.requestId);save();
          for(const value of [retained.lifecycle.revokedRun,retained.lifecycle.revokedAssessment])assert.deepEqual(value,{status:401,body:{error:'Shop authentication required'}});
          status.sessionDenied=true;
          const renewed=await bind(await bootstrap(ownerBase),await standalone.establishTenantContext(ownerBase));
          assert.deepEqual(renewed.scope,original.scope);assert.notEqual(renewed.personaSession.sessionId,original.personaSession.sessionId);
          retained.lifecycle.preResetRun=await protectedGet(renewed,'run/'+fixed.source.requestId);save();
          assert.deepEqual(retained.lifecycle.preResetRun,{status:200,body:{sessionId:fixed.source.sessionId,requestId:fixed.source.requestId,
            response:fixed.html,stopReason:'end_turn',replayed:true,modeCapability:fixed.proof.turn.result_json.modeCapability}});
          const priorBinding=await launches.resolveCapability(renewed.bearer);assert(priorBinding);
          const reset=await lifecycle.launchResetCoordinator.reset({...renewed.scope,expectedGeneration:renewed.scope.generation,idempotencyKey:uuid()});
          retained.lifecycle.reset=reset;retained.lifecycle.resetRun=await protectedGet(renewed,'run/'+fixed.source.requestId);
          retained.lifecycle.resetAssessment=await protectedGet(renewed,'assessment/'+attack.source.sessionId+'/'+attack.source.requestId);save();
          assert.equal(reset.status,'committed');assert.deepEqual(reset.binding,{...priorBinding,generation:renewed.scope.generation+1,status:'active'});
          assert.equal(reset.fromGeneration,renewed.scope.generation);assert.equal(reset.toGeneration,renewed.scope.generation+1);
          for(const value of [retained.lifecycle.resetRun,retained.lifecycle.resetAssessment])assert.deepEqual(value,{status:401,body:{error:'Shop authentication required'}});
          const cleanupReceipt=await composition.ssrf.reset.readCleanupReceipt({...renewed.scope,fromGeneration:renewed.scope.generation,
            targetId:attack.proof.request.targetId},{operationId:reset.resetId});
          retained.lifecycle.cleanupReceipt=cleanupReceipt;save();
          assert.deepEqual(Object.keys(cleanupReceipt).sort(),'targetId kind launchId scenarioId generation platformOwnerId platformSessionId operationId version receiptSha256 completedAt'.split(' ').sort());
          assert.deepEqual({...cleanupReceipt,receiptSha256:null,completedAt:null},{...renewed.scope,targetId:attack.proof.request.targetId,
            kind:'controlled_ssrf',operationId:reset.resetId,version:1,receiptSha256:null,completedAt:null});
          assert.equal(cleanupReceipt.completedAt,new Date(cleanupReceipt.completedAt).toISOString());
          assert.equal(cleanupReceipt.receiptSha256,require('../../server/services/secureshopMcpTrustTools').digestMcpValue({version:1,
            operationId:reset.resetId,targetId:attack.proof.request.targetId,...renewed.scope,ownedFixtureAbsent:true}));
          const after=await snapshot(renewed,'owner-after-launch-reset');
          for(const key of ['judgments','contributions','completions','effects','invocations','turns','traces'])assert.deepEqual(after[key],before[key],key);
          assert.equal(after.judgments.length,1);assert.equal(after.invocations.length,3);
          const active=(await identity.query('SELECT * FROM secureshop_auth.active_assessment_contributions WHERE tenant_id=$1 AND principal_id=$2',
            [ownerPrincipal.tenantId,ownerPrincipal.principalId])).rows;assert.deepEqual(active,[]);retained.lifecycle.activeAfterReset=active;
          await readPublicProgress({page,completed:false});status.publicProgress=true;status.resetFenced=true;status.immutablePreserved=true;
          const peerAfter=await snapshot(sibling,'sibling-after-owner-reset');assert.deepEqual(peerAfter,siblingBefore);
          assert.deepEqual(await readiness(sibling),siblingPositiveBefore);
          assert.deepEqual(await composition.ssrf.repository.readRequest(siblingTarget,{requestId:siblingRequestId}),siblingPending);
          status.siblingPositivePreserved=true;
          await lifecycle.launchResetCoordinator.reset({...sibling.scope,expectedGeneration:sibling.scope.generation,idempotencyKey:uuid()});
          assert.deepEqual(fs.readdirSync(targetRoot),[]);return structuredClone(retained.lifecycle);
        },onCapture:async value=>{retained.rendered=value;save();}});
      retained.rendered=rendered.evidence;assert.equal(rendered.renderedControlsVerified,true);
      status.savedRunRecovery=true;status.savedAssessmentRecovery=true;
      Object.assign(status,{actionCount:3,freshPosts:3,retryPosts:0,httpEffects:3,genuineCredit:1});
      assert.equal(transport.calls.filter(row=>row.kind==='actor').length,6);assert.equal(transport.calls.filter(row=>row.kind==='judge').length,2);
      for(const file of pinned)retained.sourcePins.after[file]=sha(fs.readFileSync(path.join(ROOT,file)));
      assert.deepEqual(retained.sourcePins.after,retained.sourcePins.before);retained.phase='actual-evidence-verified';save();
    }else{
    const rendered = await flow.qualifyStandaloneSsrfRendered({
      browser,
      origin,
      credentials: {
        username: registration.user.username,
        password
      },
      evidenceDirectory: cfg.directory,
      ackLoss,
      bindBootstrap: async packet => {
        ownerPrincipal = await standalone.establishTenantContext(ownerBase);
        owner = await bind(packet, ownerPrincipal);
        assert.equal(owner.persona.role, 'customer');
        assert.equal(owner.persona.id, ownerPrincipal.shopUserId);
        assert.notEqual(owner.scope.platformOwnerId, sibling.scope.platformOwnerId);
        assert.notEqual(owner.scope.launchId, sibling.scope.launchId);
        retained.lifecycle.originalReadiness = await readiness(owner);
        assert.deepEqual(retained.lifecycle.originalReadiness, {
          status: 200,
          body: {
            ready: true
          }
        });
        status.registeredAuthority = true;
        return owner;
      },
      readCase,
      readCounters: counters,
      readPrivateSnapshot: async () => snapshot(owner, 'exact-private-retry-full-snapshot'),
      onCapture: value => {
        retained.rendered = value;
        save();
      }
    });
    assert(rendered.renderedControlsVerified);
    for (const row of rendered.evidence.cases) {
      normalized.get(row.id).physical = row.physical;
      status[row.id === 'public' ? 'physicalPublic' : row.id === 'private' ? 'physicalPrivate' : 'physicalFixed'] = true;
    }
    status.privateHttpBound = true;
    status.fixedNoHttpNoCredit = true;
    status.exactSameIdReplay = true;
    Object.assign(status, {
      actionCount: rendered.actionCount,
      freshPosts: rendered.freshPosts,
      retryPosts: rendered.retryPosts
    });
    const original = owner;
    await composition.personaAuth.revokeOwnedSession({
      scope: owner.scope,
      shopPersona: owner.persona,
      currentSessionId: owner.personaSession.sessionId,
      authorityVersion: owner.personaSession.authorityVersion,
      sessionId: owner.personaSession.sessionId
    });
    retained.lifecycle.revokedReadiness = await readiness(original);
    assert.equal(retained.lifecycle.revokedReadiness.status, 401);
    status.sessionDenied = true;
    const renewed = await bind(await bootstrap(ownerBase), await standalone.establishTenantContext(ownerBase));
    assert.deepEqual(renewed.scope, original.scope);
    assert.notEqual(renewed.personaSession.sessionId, original.personaSession.sessionId);
    retained.lifecycle.immediatePreReset = await readiness(renewed);
    assert.deepEqual(retained.lifecycle.immediatePreReset, {
      status: 200,
      body: {
        ready: true
      }
    });
    const beforeReset = await snapshot(renewed, 'owner-immediately-before-current-native-reset'),
      resetResult = await lifecycle.launchResetCoordinator.reset({
        ...renewed.scope,
        expectedGeneration: renewed.scope.generation,
        idempotencyKey: uuid()
      });
    assert.equal(resetResult.status, 'committed');
    assert.equal(resetResult.toGeneration, renewed.scope.generation + 1);
    retained.lifecycle.reset = resetResult;
    retained.lifecycle.resetReadiness = await readiness(renewed);
    assert.equal(retained.lifecycle.resetReadiness.status, 401);
    status.resetFenced = true;
    const afterReset = await snapshot(renewed, 'owner-after-current-native-reset');
    for (const key of ['judgments', 'contributions', 'completions', 'effects', 'invocations']) assert.deepEqual(afterReset[key], beforeReset[key]);
    const active = (await identity.query('SELECT * FROM secureshop_auth.active_assessment_contributions WHERE tenant_id=$1 AND principal_id=$2', [ownerPrincipal.tenantId, ownerPrincipal.principalId])).rows;
    assert.deepEqual(active, []);
    status.immutablePreserved = true;
    const siblingAfter = await snapshot(sibling, 'sibling-pending-after-owner-reset');
    assert.deepEqual(siblingAfter, siblingBefore);
    assert.deepEqual(await composition.ssrf.repository.readRequest(siblingTarget, {
      requestId: siblingRequestId
    }), siblingPending);
    const siblingPositiveAfter = await readiness(sibling);
    assert.deepEqual(siblingPositiveAfter, siblingPositiveBefore);
    status.siblingPositivePreserved = true;
    const privateCase = normalized.get('private'),
      subject = privateCase.judgments[0].execution_json;
    const capture = {
      version: 1,
      subject: {
        tenantId: subject.tenantId,
        principalId: subject.principalId,
        shopUserId: subject.shopUserId,
        membershipVersion: subject.membershipVersion,
        personaSessionId: subject.personaSessionId,
        personaAuthorityVersion: subject.personaAuthorityVersion,
        role: subject.role,
        ...subject.scope
      },
      catalog: {
        objectiveId: objective,
        qualification: catalogRow.qualification,
        tenantId: ownerPrincipal.tenantId,
        explicitlyEnabled: true,
        workshopAvailability: await composition.ssrf.availability.read()
      },
      cases: ['public', 'private', 'fixed-private'].map(id => normalized.get(id)),
      wire: retained.wire,
      retry: null,
      lifecycle: null,
      browser: {
        executableSha256: process.env.ANALYTICS_BROWSER_SHA256,
        pid: JSON.parse(fs.readFileSync(path.join(runtime, 'browser-process.json'))).pid,
        owned: true,
        closed: false
      },
      sourcePins: retained.sourcePins
    };
    const projection = {
      requests: [privateCase.request],
      turns: [{
        sessionId: privateCase.sessionId,
        requestId: privateCase.requestId,
        status: 'completed',
        result: privateCase.physical.response.body
      }],
      traces: Object.values(privateCase.traces),
      invocations: [privateCase.invocation],
      http: [privateCase.httpReceipt],
      effects: [privateCase.effect],
      judgments: privateCase.judgments,
      contributions: privateCase.contributions
    };
    capture.retry = {
      requestId: privateCase.requestId,
      postBody: rendered.evidence.retry.request,
      response: rendered.evidence.retry.response,
      renderedText: privateCase.physical.renderedText,
      before: projection,
      after: structuredClone(projection),
      countsBefore: rendered.evidence.retry.countsBefore,
      countsAfter: rendered.evidence.retry.countsAfter
    };
    const siblingSubject = {
        ...capture.subject,
        tenantId: peerPrincipal.tenantId,
        principalId: peerPrincipal.principalId,
        shopUserId: peerPrincipal.shopUserId,
        membershipVersion: peerPrincipal.membershipVersion,
        personaSessionId: sibling.personaSession.sessionId,
        personaAuthorityVersion: sibling.personaSession.authorityVersion,
        role: sibling.persona.role,
        ...sibling.scope
      },
      positive = (context, value) => ({
        status: value.status,
        scope: context.scope,
        personaSessionId: context.personaSession.sessionId,
        body: value.body
      });
    const siblingProjection = {
        requests: siblingBefore.requests,
        turns: [],
        traces: [],
        invocations: [],
        http: [],
        effects: [],
        judgments: [],
        contributions: []
      },
      immutable = {
        judgments: privateCase.judgments,
        contributions: privateCase.contributions,
        http: capture.cases.slice(0, 2).map(c => c.httpReceipt),
        effects: capture.cases.slice(0, 2).map(c => c.effect)
      };
    capture.lifecycle = {
      ownerPositive: positive(original, retained.lifecycle.originalReadiness),
      sessionDenied: retained.lifecycle.revokedReadiness.status,
      resetDenied: retained.lifecycle.resetReadiness.status,
      siblingSubject,
      siblingPositiveBefore: positive(sibling, siblingPositiveBefore),
      siblingPositiveAfter: positive(sibling, siblingPositiveAfter),
      siblingBefore: siblingProjection,
      siblingAfter: structuredClone(siblingProjection),
      immutableBefore: immutable,
      immutableAfter: structuredClone(immutable),
      activeAfterReset: active,
      targetsRetired: true
    };
    await lifecycle.launchResetCoordinator.reset({
      ...sibling.scope,
      expectedGeneration: sibling.scope.generation,
      idempotencyKey: uuid()
    });
    assert.deepEqual(fs.readdirSync(targetRoot), []);
    for (const file of pinned) retained.sourcePins.after[file] = sha(fs.readFileSync(path.join(ROOT, file)));
    assert.deepEqual(retained.sourcePins.after, retained.sourcePins.before);
    retained.normalizedCapture = capture;
    for (const call of transport.calls) {
      assert.equal(call.status, 200);
      assert.equal(call.responseComplete, true);
      assert.equal(call.responseCaptureTruncated, false);
      assert.equal(call.requestSha256, sha(call.request));
      assert.equal(call.responseSha256, sha(call.response));
      const request = JSON.parse(call.request);
      assert.equal(request.model, transport.model);
      const chunks = call.response.trim().split('\n').map(s => JSON.parse(s));
      assert(chunks.every(c => c.model === transport.model));
      assert.equal(chunks.at(-1).done, true);
      assert.equal(chunks.at(-1).done_reason, 'stop');
    }
    assert.equal(transport.digest, '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e');
    assert.equal(privateCase.judgments[0].disposition, 'awarded');
    assert.equal(privateCase.contributions.length, 1);
    status.canonicalTenantCredit = true;
    status.genuineCredit = 1;
    retained.phase = 'actual-evidence-verified';
    Object.assign(status, {
      actorCalls: transport.calls.filter(c => c.kind === 'actor').length,
      judgeCalls: transport.calls.filter(c => c.kind === 'judge').length,
      httpEffects: capture.cases.filter(c => c.httpReceipt).length
    });
    save();
    }
  } catch (error) {
    failure = error;
    retained.phase = 'failed';
    retained.failure = {
      name: error.name,
      code: error.code || null,
      message: error.message,
      stack: error.stack
    };
    status.errors.push({
      name: error.name,
      code: error.code || null,
      message: error.message
    });
  } finally {
    const cleanup = [];
    for (const [name, close] of resources.reverse()) {
      try {
        await close();
        cleanup.push({
          name,
          status: 'fulfilled'
        });
      } catch (error) {
        cleanup.push({
          name,
          status: 'rejected',
          message: error.message
        });
        failure ??= error;
      }
    }
    for (const pool of pools) {
      try {
        await pool.end();
      } catch (error) {
        cleanup.push({
          name: 'pool',
          status: 'rejected',
          message: error.message
        });
        failure ??= error;
      }
    }
    for (const [key, value] of Object.entries(oldEnv)) if (value === undefined) delete process.env[key];else process.env[key] = value;
    status.actorCalls = transport?.calls.filter(c => c.kind === 'actor').length || 0;
    status.judgeCalls = transport?.calls.filter(c => c.kind === 'judge').length || 0;
    retained.cleanup = cleanup;
    status.fixtureCleaned = cleanup.every(c => c.status === 'fulfilled');
    if (!failure) {
      try {
        if(POLICY_OUTPUT){retained.browser.closed=cleanup.find(c=>c.name==='browser-process')?.status==='fulfilled';assert.equal(retained.browser.closed,true);status.passed=true;assertPolicyOutputReceipt(status);}
        else{
        retained.normalizedCapture.browser.closed = cleanup.find(c => c.name === 'browser-process')?.status === 'fulfilled';
        const validated = require('../fixtures/secureshopStandaloneSsrfQualification').validateStandaloneSsrfCapture(retained.normalizedCapture, {
          judgeResults: originalResults
        });
        assert.equal(validated.configuredJudgeProof, true);
        assert.equal(validated.actualModelProof, false);
        status.canonicalJudgeEvidence = true;
        status.passed = true;
        assertReceipt(status);
        }
      } catch (error) {
        failure = error;
        status.passed = false;
        status.errors.push({
          name: error.name,
          code: error.code || null,
          message: error.message
        });
        retained.failure = {
          name: error.name,
          code: error.code || null,
          message: error.message,
          stack: error.stack
        };
      }
    }
    save();
  }
  if (failure) throw failure;
});
module.exports = {
  qualifyPolicyRendererSandbox, assertConsumedPolicyHttpAuthority, qualifyCompiledPolicyRenderer, assertPolicyOutputReceipt, POLICY_OUTPUT_FLAGS, POLICY_OUTPUT_SCOPE, POLICY_OUTPUT_TITLE, POLICY_OUTPUT_NATIVE,
  observeConsumedSsrfReceipts,
  createSsrfCore,
  createStandaloneSsrfMount,
  nativeConfig,
  assertReceipt,
  FLAGS,
  SCOPE,
  TITLE,
  PREFIX,
  NATIVE,
  BUILD,
  EVIDENCE
};
