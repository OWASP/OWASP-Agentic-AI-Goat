'use strict';

// This actual-model/browser qualification is gated and runs only through the
// disposable main launcher. Receipt validation remains importable without any
// database, model, browser, or sidecar work.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const express = require('express');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

const PREFIX = 'PG_SECURESHOP_ADMIN_RESTART_CHAT_BROWSER_';
const STORES = Object.freeze(['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE']);
const STORE_NAMES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const ASSERTION = 'standalone administrator earns canonical isolated restart injection credit with genuine model and fixed denial';
const {MODEL,DIGEST,NAME,OBJECTIVE,SCOPE,FLAGS,browserErrorEvidence,assertPrivateReceipt,assertProtectedProposalRecovery,assertActualWire,clickEnabledButton,selectFixedShopMode}=require('./secureshopRestartInjectionActualContract');
const ENABLED = process.env.SECURESHOP_ADMIN_RESTART_CHAT_BROWSER_NATIVE === '1'
  && process.env.SECURESHOP_RESTART_INJECTION_GRADED === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && STORES.every(store => ['MIGRATION', 'RUNTIME'].every(role =>
    process.env[`${PREFIX}${store}_${role}_URL`]));

function systemRestartDependencies({ restartClient, grading, reviewPool, composition, reset, modeAuthority }) {
  return Object.freeze({ systemRestartClient: restartClient, preparedGrading: grading, reviewPool,
    launches: composition.launches, products: composition.repositories.products,
    scenes: composition.scenes, audit: reset.audit.review, modeAuthority,
    authenticatePersona: composition.personaAuth.authenticatePersona });
}

function urlsFromEnvironment() {
  const urls = {}; let nonce; let port;
  for (const store of STORES) {
    for (const role of ['MIGRATION', 'RUNTIME']) {
      const key = `${store}_${role}`;
      const value = new URL(process.env[`${PREFIX}${key}_URL`]);
      assert.equal(value.protocol, 'postgresql:'); assert.equal(value.hostname, '127.0.0.1');
      assert.equal(value.password, ''); assert.equal(value.search, ''); assert.equal(value.hash, '');
      assert.equal(value.username, `dvaia_${STORE_NAMES[store]}_${role.toLowerCase()}`);
      const match = new RegExp(`^/dvaia_test_agent_host_([0-9a-f]{12})_${STORE_NAMES[store]}$`)
        .exec(value.pathname);
      assert.ok(match, `closed disposable database name required for ${key}`);
      nonce ??= match[1]; port ??= value.port;
      assert.equal(match[1], nonce); assert.equal(value.port, port);
      urls[key] = value.href;
    }
    assert.equal(new URL(urls[`${store}_MIGRATION`]).pathname,
      new URL(urls[`${store}_RUNTIME`]).pathname);
  }
  assert.equal(new Set(STORES.map(store => new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return Object.freeze(urls);
}

async function migrateAndSeed(pools, workspace) {
  for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
    ['AGENTS', 'workshop-migrations/secureshop_agents'],
    ['REVIEW', 'workshop-migrations/secureshop_review'],
    ['COMMERCE', 'workshop-migrations/secureshop']]) {
    await migrate(pools[`${store}_MIGRATION`], path.join(workspace, 'db/postgres', directory));
  }
  await require('../../server/database/postgres/workshopPlatformSeed')
    .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopAssessmentSeed')
    .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopStandaloneSeed')
    .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
  const seed = await pools.COMMERCE_MIGRATION.connect();
  try {
    await seed.query('BEGIN');
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seed);
    await seed.query('COMMIT');
  } catch (error) { await seed.query('ROLLBACK'); throw error; }
  finally { seed.release(); }
}

async function listen(app) {
  return await new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) =>
    server.close(error => error ? reject(error) : resolve()));
}
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function observeRequestLog(requestLog, predicate, { timeout = 30000, interval = 20 } = {}) {
  const deadline = Date.now() + timeout;
  return new Promise(resolve => {
    const check = () => {
      const match = requestLog.find(predicate);
      if (match || Date.now() >= deadline) return resolve(match || null);
      const timer = setTimeout(check, interval); timer.unref?.();
    };
    check();
  });
}
async function frameFor(page) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const iframe = await page.$('iframe[title="SecureShop"]');
    const frame = iframe && await iframe.contentFrame().catch(() => null);
    if (frame && !frame.detached) return frame;
    await sleep(50);
  }
  throw new Error('Standalone SecureShop frame did not mount');
}
async function visibleSetupState(page) {
  return page.evaluate(() => [...document.querySelectorAll('h1,h2,[role="alert"],[role="status"],button')]
    .filter(node => node.getClientRects().length && getComputedStyle(node).visibility !== 'hidden')
    .map(node => String(node.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 160))
    .filter(Boolean).slice(0, 16)).catch(() => []);
}
async function boundedRestartResponse(response, limit = 131072) {
  const reader = response.clone().body?.getReader?.();
  if (!reader) return { bodyUnavailable: true };
  const chunks = []; let size = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.byteLength;
      if (size > limit) { await reader.cancel().catch(() => {}); return { oversized: true, bytes: size }; }
      chunks.push(Buffer.from(item.value));
    }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size));
    return { bytes: size, value: JSON.parse(text),text,sha256:createHash('sha256').update(text).digest('hex') };
  } catch (error) { return { bytes: size, decodeError: error.name || 'response-decode-failed' }; }
  finally { reader.releaseLock?.(); }
}
function restartResponseShape(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { kind: typeof value };
  const shape = { keys: Object.keys(value).sort() };
  for (const key of ['version', 'targetId', 'operationId', 'requestSha256', 'beforeInstanceId',
    'afterInstanceId', 'beforeGeneration', 'afterGeneration', 'effectSha256', 'outputSha256',
    'outputBytes', 'ownedCommandEffectSha256', 'ownedCommandEffectFiles',
    'ownedCommandEffectBytes', 'command', 'status', 'isolation', 'resident', 'generation',
    'instanceId', 'error']) {
    if (Object.hasOwn(value, key)) shape[key] = typeof value[key] === 'string'
      ? value[key].slice(0, 180) : value[key];
  }
  if (typeof value.outputText === 'string') shape.outputText = {
    bytes: Buffer.byteLength(value.outputText),
    sha256: createHash('sha256').update(value.outputText).digest('hex'),
  };
  return shape;
}
async function clickButton(frame, label) {
  await clickEnabledButton(frame, label);
}
async function loginShop(page, origin, username, password) {
  const landing = await page.goto(`${origin}/secureshop/login`, { waitUntil: 'domcontentloaded' });
  assert.ok([200, 304].includes(landing.status()));
  await page.waitForSelector('#ss-login-user');
  await page.type('#ss-login-user', username); await page.type('#ss-login-pw', password);
  const pending = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.origin === origin && url.pathname === '/api/secureshop/auth/bootstrap'
      && response.request().method() === 'POST';
  }, { timeout: 30000 });
  await page.click('button[type="submit"]');
  const response = await pending; assert.equal(response.status(), 200);
  const frame = await frameFor(page);
  await frame.waitForSelector('[aria-label="Account menu"]');
  return frame;
}
async function logoutShop(frame, page, origin) {
  await frame.click('[aria-label="Account menu"]');
  const pending = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.origin === origin && url.pathname === '/api/secureshop/auth/logout'
      && response.request().method() === 'POST';
  }, { timeout: 30000 });
  await clickButton(frame, 'Sign out'); assert.equal((await pending).status(), 200);
  await page.waitForFunction(() => location.pathname === '/secureshop');
}

test(ASSERTION, { skip: !ENABLED, timeout: 600000 }, async t => {
  const workspace = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '');
  assert.equal(workspace, process.cwd(), 'current checkout required; no source copy');
  const build = path.resolve(process.env.SECURESHOP_ADMIN_RESTART_CHAT_BROWSER_BUILD || '');
  assert.equal(build, path.join(workspace, 'client/build'));
  const executablePath = path.resolve(process.env.PUPPETEER_EXECUTABLE_PATH || '');
  const restartURL = new URL(process.env.SECURESHOP_ADMIN_RESTART_CHAT_BROWSER_RESTART_URL || '');
  assert.equal(restartURL.hostname, '127.0.0.1'); assert.equal(restartURL.pathname, '/');
  const restartToken = process.env.SECURESHOP_ADMIN_RESTART_CHAT_BROWSER_RESTART_TOKEN;
  assert.match(restartToken || '', /^[A-Za-z0-9_-]{43,128}$/);
  const evidencePath = path.resolve(process.env.SECURESHOP_ADMIN_RESTART_CHAT_BROWSER_EVIDENCE_PATH || '');
  assert.equal(path.dirname(evidencePath), path.resolve(process.env.TMPDIR, '../..'));
  const urls = urlsFromEnvironment();
  const pools = Object.fromEntries(STORES.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role =>
    [`${store}_${role}`, new Pool({ connectionString: urls[`${store}_${role}`],
      max: role === 'RUNTIME' ? 12 : 3 })])));
  const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 3 });
  const status = Object.fromEntries(FLAGS.map(flag => [flag, false]));
  Object.assign(status, { scope: SCOPE, actorCalls: 0, roleTurns: 0, judgeCalls: 0, errors: [] });
  const pageErrors = [], requestFailures = [], authEvents = [], cleanupErrors = [],
    modelCalls = [], actualModelRequests = [], requestLog = [], bootstraps = [], confirmOutcomes = [],
    restartTransport = [],
    savedProposals = [], assessmentOutcomes=[], judgeTranscripts=[], turns=[];
  let actorTransport,judgeTransport,judgeInvocations=0,assessmentEvidence,privateReceipt,fixedEvidence;
  const oldJudgeEnv={OLLAMA_BASE_URL:process.env.OLLAMA_BASE_URL,JUDGE_PROVIDER:process.env.JUDGE_PROVIDER,JUDGE_MODEL:process.env.JUDGE_MODEL};
  let reset, composition, restart, restartClient, server, browser, page, profile, failure, stage = 'setup';
  let browserPhase = 'before-browser', browserStartedAt = null;
  let confirmResponsesLost = 0, recoveryReadsFaulted = 0, confirmPosts = 0;
  let requestPhase = 'initial', protectedProposalLifecycle = [];
  try {
    await migrateAndSeed(pools, workspace); status.isolatedStores = true;
    const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
    const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
    const auth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity }) });
    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(identity);
    const audit = require('../../server/services/secureshopBoundAuditComposition')
      .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
        includeRunArtifacts: true });
    const observedRestartFetch = async (input, init) => {
      const url = new URL(input); const method = init?.method || 'GET';
      const response = await fetch(input, init);
      const observed = await boundedRestartResponse(response);
      const event = { method, path: url.pathname, status: response.status, ok: response.ok,
        bytes: observed.bytes ?? null, ...(observed.oversized ? { oversized: true } : {}),
        ...(observed.decodeError ? { decodeError: observed.decodeError } : {}),
        ...(observed.bodyUnavailable ? { bodyUnavailable: true } : {}),
        ...(observed.value === undefined ? {} : { body: restartResponseShape(observed.value) }) };
      if (url.pathname === '/secureshop/system/restart' && observed.value !== undefined) {
        try {
          event.requestBody=init.body;event.responseBody=observed.text;event.responseSha256=observed.sha256;
          const wire = JSON.parse(init?.body || 'null');
          require('../../sidecars/sandbox-runner/owned-system/restart-wire')
            .validateRestartReceipt(wire, observed.value);
          event.receiptValidation = 'valid';
        } catch (error) { event.receiptValidation = String(error.message || error.name).slice(0, 120); }
      }
      assert.ok(restartTransport.length < 256, 'Bounded complete owned executor transcript'); restartTransport.push(event);
      return response;
    };
    restartClient = require('../../server/services/secureshopSystemRestartClient')
      .createSecureShopSystemRestartClient({ baseURL: restartURL.href, token: restartToken,
        fetchImpl: observedRestartFetch });
    reset = require('../../server/services/secureshopCleanupComposition')
      .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, leasePool, audit, systemRestartClient: restartClient });
    judgeTransport=await require('./secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:3,allowMetadata:true});
    actorTransport=await require('./secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:10,allowMetadata:true});
    assert.equal(actorTransport.digest,DIGEST);assert.equal(judgeTransport.digest,DIGEST);
    process.env.OLLAMA_BASE_URL=judgeTransport.judgeUrl;
    process.env.JUDGE_PROVIDER='ollama';process.env.JUDGE_MODEL=MODEL;
    const configuredJudge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({
      observeExecutionTranscript:value=>judgeTranscripts.push(structuredClone(value))});
    const judge=async input=>{assert.ok(++judgeInvocations<=1);return configuredJudge(input);};
    require('../../server/agent-runtime/judgeProviderConfiguration').registerConfiguredJudge(judge,
      ()=>require('../../server/agent-runtime/judgeProviderConfiguration').readJudgeProviderConfig(configuredJudge));
    const grading = await require('../../server/services/secureshopGradingBootstrap')
      .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents, progress,
        resetComposition: reset, judge,
        expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
        expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
    const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({ repository:
      require('../../server/database/postgres/secureshopSceneRepository')
        .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
      reviewPool: review, launches: reset.launches });
    const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
      .createSecureShopModeRepository(identity);
    const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
      .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
    const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
      .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
        audit: reset.audit.agents });
    const provider = new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
      baseUrl: actorTransport.actorUrl, model: MODEL });
    const transportChat = provider.transport.chat.bind(provider.transport);
    provider.transport.chat = async (...args) => {
      assert.ok(actualModelRequests.length < 10,
        'one restart preparation remains within five actual provider requests');
      actualModelRequests.push({ ordinal: actualModelRequests.length + 1 });
      return transportChat(...args);
    };
    for (const method of ['chat', 'finalResponse']) {
      const original = provider[method].bind(provider);
      provider[method] = async input => {
        assert.ok(modelCalls.length < 10, 'one restart preparation remains within five actual calls');
        const result = await original({ ...input, signal: AbortSignal.any([
          AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
        assert.equal(result.provider, 'ollama'); assert.equal(result.model, MODEL);
        assert.equal(result.mocked, false); assert.notEqual(result.fallback, true);
        modelCalls.push({ method, offeredTools: (input.tools || []).map(tool => `${tool.agent}.${tool.tool}`),
          stopReason: result.stop_reason || null,
          tools: (result.tool_uses || []).map(tool => ({ name: tool.name, args: tool.args })) });
        return result;
      };
    }
    let restartValue;
    composition = require('../../server/services/secureshopBoundReviewComposition')
      .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, commercePool: commerce, resetComposition: reset,
        gradingBootstrap: grading, scenes, modeAuthority, toolPolicyRepository,
        getSystemRestart: () => restartValue, fixtures: [],
        requiredObjectives: [OBJECTIVE],
        jwtSecret: 'disposable-restart-chat-persona-secret-at-least-32-bytes',
        agentRuntime: { provider }, judge });
    restart = await require('../../server/services/secureshopBoundReviewComposition')
      .createOptionalSystemRestartComposition(systemRestartDependencies({ restartClient,
        grading, reviewPool: review, composition, reset, modeAuthority }));
    restartValue = restart;
    assert.equal(restart.ready, true); assert.equal(composition.roleAssistants.admin.ready, true);
    await composition.repositories.personas.ensureTemplates();
    await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness')
      .assertBoundToolPolicyReadiness(agents);
    const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: auth });
    const standaloneMode = require('../../server/services/secureshopStandaloneMode')
      .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
    const assessmentCatalog = require('../../server/services/secureshopAssessmentCatalog')
      .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
    const adminLogin=await auth.login({username:'student_admin',password:'student123'});
    const objective=(await assessmentCatalog.list(adminLogin.context)).objectives.find(row=>row.objectiveId===OBJECTIVE);
    const checkedInQualification=require('../../server/config/secureshopCurriculum').OBJECTIVES
      .find(row=>row.id===OBJECTIVE)?.qualification;
    assert.ok(['pending','native-browser-judge'].includes(checkedInQualification));
    assert.equal(objective?.enabled,false);assert.equal(objective?.qualification,checkedInQualification);
    let candidate=objective;
    if(checkedInQualification==='pending'){
      const enable={objectiveId:OBJECTIVE,enabled:true,expectedRevision:objective.revision};
      await assert.rejects(assessmentCatalog.set(adminLogin.context,enable),
        {code:'SHOP_OBJECTIVE_UNQUALIFIED'});
      const admitted=await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.assessment_objectives
        SET qualification='native-browser-judge' WHERE objective_id=$1 AND qualification='pending'
          AND is_enabled=false AND catalog_active=true
          AND configuration_source='checked_in_default'
          AND source_document->>'qualification'='pending'
        RETURNING objective_id,qualification,is_enabled`,[OBJECTIVE]);
      assert.equal(admitted.rowCount,1);
      assert.deepEqual(admitted.rows,[{objective_id:OBJECTIVE,
        qualification:'native-browser-judge',is_enabled:false}]);
      candidate=(await assessmentCatalog.list(adminLogin.context)).objectives
        .find(row=>row.objectiveId===OBJECTIVE);
      assert.equal(candidate.qualification,'native-browser-judge');assert.equal(candidate.enabled,false);
      assert.equal(candidate.revision,objective.revision);status.fixtureLocalCandidateAdmission=true;
      t.diagnostic('Fixture-local admission in an owned disposable identity store; checked-in objective remains pending');
    }else{
      assert.equal(candidate.qualification,'native-browser-judge');assert.equal(candidate.enabled,false);
      assert.equal(candidate.revision,objective.revision);status.fixtureLocalCandidateAdmission=false;
      t.diagnostic('Checked-in qualified objective enabled normally in the owned disposable identity store');
    }
    assert.equal((await assessmentCatalog.set(adminLogin.context,{objectiveId:OBJECTIVE,enabled:true,
      expectedRevision:candidate.revision})).enabled,true);status.canonicalObjectiveEnabled=true;
    const siblingAdmin = await auth.login({ username: 'student_admin', password: 'student123' });
    const siblingBase = await bootstrap(siblingAdmin.context);
    assert.equal(siblingBase.persona.user.role, 'admin');
    const protectedReset = require('../../server/services/secureshopStandaloneReset')
      .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
        launches: composition.launches, scenes, resetCoordinator: reset.launchResetCoordinator,
        preflight: reset.sceneResetPreflight });
    const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
      .createSecureShopStorePublicCatalogRepository({ identityPool: identity, reviewPool: review,
        commercePool: commerce });
    const mounted = Object.freeze({ ...composition, systemRestart: restart,
      standaloneAuth: Object.freeze({ service: auth, bootstrap, reset: protectedReset,
        mode: standaloneMode, assessmentObjectives: assessmentCatalog }), publicCatalog,
      personaInbox: Object.freeze({ ready: true, router: express.Router() }),
      mcpTrust: Object.freeze({ ready: true, router: express.Router() }),
      ssrf: Object.freeze({ ready: true, router: express.Router() }) });
    const bound = await require('../../server/services/secureshopBoundApplication')
      .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
        authenticateToken: (_request, response) => response.sendStatus(401), audit: async () => {},
        agentRuntime: {}, getComposition: async () => mounted });
    const app = express(); app.use(express.json()); server = await listen(app);
    const origin = `http://127.0.0.1:${server.address().port}`;
    app.use('/api/secureshop/auth', (request, response, next) => {
      const event = { method: request.method, path: request.path };
      response.once('finish', () => {
        event.status = response.statusCode;
        if (authEvents.length < 32) authEvents.push(event);
      });
      const original = response.json.bind(response);
      response.json = value => {
        event.result = {
          authenticated: typeof value?.authenticated === 'boolean' ? value.authenticated : null,
          role: typeof value?.user?.role === 'string' ? value.user.role
            : typeof value?.persona?.user?.role === 'string' ? value.persona.user.role : null,
          error: typeof value?.error === 'string' ? value.error.slice(0, 160) : null,
          code: typeof value?.code === 'string' ? value.code.slice(0, 80) : null,
          launchIssued: typeof value?.bearer === 'string' && value?.launch !== null,
        };
        if (request.method === 'POST' && request.path === '/bootstrap'
          && response.statusCode === 200 && value?.persona?.user?.role === 'admin') {
          bootstraps.push({ launch: value.bearer, authorization: `Bearer ${value.persona.token}` });
        }
        return original(value);
      };
      next();
    });
    app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthRouter({ service: auth, bootstrap, reset: protectedReset,
        mode: standaloneMode, assessmentObjectives: assessmentCatalog,
        allowedOrigins: [origin], secureCookies: false }));
    app.use('/api/secureshop', (request, response, next) => {
      const entry = { method: request.method, path: request.path, phase: requestPhase,
        launch: request.get('x-dvaia-secureshop-launch') || null,
        authorization: request.get('authorization') || null,
        ...(request.method === 'POST' ? { body: structuredClone(request.body) } : {}) };
      if (/assistant|restart/.test(request.path)) {
        entry.lifecycle = 'pending'; requestLog.push(entry);
        response.once('finish', () => {
          entry.status = response.statusCode; entry.headersSent = response.headersSent;
          entry.lifecycle = 'finished';
        });
        response.once('close', () => {
          if (!response.writableFinished) {
            entry.status = response.headersSent ? response.statusCode : null;
            entry.headersSent = response.headersSent; entry.lifecycle = 'closed-before-finish';
          }
        });
      }
      if (request.method === 'GET'
        && /^\/agents\/admin\/assistant\/operations\/[0-9a-f-]{36}\/[0-9a-f-]{36}$/i.test(request.path)) {
        const original = response.json.bind(response);
        response.json = value => {
          if (response.statusCode === 200) savedProposals.push(structuredClone(value));
          return original(value);
        };
      }
      if(request.path.startsWith('/agents/admin/assistant/system/restart/assess')){
        const original=response.json.bind(response);
        response.json=value=>{assessmentOutcomes.push({method:request.method,path:request.path,
          status:response.statusCode,requestBody:request.method==='POST'?structuredClone(request.body):null,
          body:structuredClone(value)});return original(value);};
      }
      if (request.method === 'POST'
        && request.path === '/agents/admin/assistant/system/restart/confirm') {
        confirmPosts += 1;
        const original = response.json.bind(response);
        response.json = value => {
          confirmOutcomes.push({ status: response.statusCode,
            ok: typeof value?.ok === 'boolean' ? value.ok : null,
            state: typeof value?.state === 'string' ? value.state.slice(0, 40) : null,
            error: typeof value?.error === 'string' ? value.error.slice(0, 160) : null,
            code: typeof value?.code === 'string' ? value.code.slice(0, 80) : null,
            failureCode: typeof value?.failureCode === 'string' ? value.failureCode.slice(0, 80) : null,
            automaticRetry: typeof value?.automaticRetry === 'boolean' ? value.automaticRetry : null });
          if (value?.state === 'completed' && confirmResponsesLost === 0) {
            confirmResponsesLost += 1;
            response.status(503);
            return original({ error: 'Controlled restart acknowledgement unavailable',
              code: 'SYSTEM_RESTART_OUTCOME_UNCERTAIN' });
          }
          return original(value);
        };
      }
      if (request.method === 'GET' && confirmResponsesLost === 1 && recoveryReadsFaulted === 0
        && /^\/admin\/system\/restart-operations\/[0-9a-f-]{36}$/i.test(request.path)) {
        recoveryReadsFaulted += 1;
        return response.status(503).json({ error: 'Controlled restart read acknowledgement unavailable' });
      }
      next();
    });
    app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
      .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
    app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog')
      .createSecureShopPublicCatalogRouter({ getRepository: () => publicCatalog,
        isAvailable: async () => true }));
    app.use(express.static(build, { setHeaders: response =>
      response.set('Access-Control-Allow-Origin', '*') }));
    app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));

    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-admin-restart-chat-'));
    browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
      executablePath, args: ['--disable-background-networking'] });
    page = await browser.newPage(); browserStartedAt = Date.now(); browserPhase = 'browser-created';
    await page.setViewport({ width: 1280, height: 900 });
    await page.setRequestInterception(true);
    page.on('request', request => request.url().startsWith(`${origin}/`)
      ? request.continue() : request.abort());
    page.on('pageerror', error => {
      if (pageErrors.length < 16) pageErrors.push(browserErrorEvidence(error, { stage,
        phase: browserPhase, elapsedMs: Date.now() - browserStartedAt, url: page.url() }));
    });
    page.on('requestfailed', request => {
      const url = new URL(request.url());
      if (url.origin === origin && requestFailures.length < 16) requestFailures.push({
        method: request.method(), path: url.pathname,
        error: String(request.failure()?.errorText || 'request failed').slice(0, 120),
      });
    });
    stage = 'customer-parent-login'; browserPhase = stage;
    let frame = await loginShop(page, origin, 'student_customer', 'student123');
    const product = await frame.evaluate(async () => {
      const response = await fetch('/api/secureshop/products?limit=1');
      if (!response.ok) throw Error('Product target preparation failed'); return response.json();
    });
    assert.ok(Array.isArray(product.products) && product.products.length === 1);
    await logoutShop(frame, page, origin);
    stage = 'admin-parent-login'; browserPhase = stage;
    frame = await loginShop(page, origin, 'student_admin', 'student123');
    await frame.waitForSelector('a[href="/secureshop/admin"]');
    await frame.click('a[href="/secureshop/admin"]');
    await frame.waitForSelector('[data-testid="admin-role-assistant"]');
    assert.equal(bootstraps.length, 1); status.genuineAdminUiSession = true;
    const operationBefore = await review.query(
      'SELECT operation_id,state FROM secureshop_review.bound_system_restart_operations ORDER BY operation_id');
    assert.deepEqual(operationBefore.rows, []);
    const completionsBefore = await identity.query(
      'SELECT objective_id FROM workshop_platform.completions ORDER BY objective_id');
    stage = 'restart-prepare'; browserPhase = stage;
    const message = `Prepare a System restart for the exact owned service name ${JSON.stringify(NAME)}. Keep the name unchanged and wait for my confirmation.`;
    await frame.waitForSelector('[data-testid="admin-role-composer-slot"] textarea');
    await frame.type('[data-testid="admin-role-composer-slot"] textarea', message);
    await clickButton(frame, 'Send to admin assistant');
    await frame.waitForSelector('section[aria-label="Admin System restart review"] button',
      { timeout: 120000 });
    const proposalRows = await review.query(
      'SELECT operation_id FROM secureshop_review.bound_system_restart_operations');
    assert.deepEqual(proposalRows.rows, []); status.renderedProposalNoEffect = true;
    assert.ok(modelCalls.some(call => call.method === 'chat' && call.stopReason === 'tool_use'
      && call.offeredTools.includes('admin.system_restart_prepare')
      && call.tools.some(tool => tool.name === 'admin.system_restart_prepare'
        && tool.args?.name === NAME)));
    assert.ok(modelCalls.some(call => ['chat', 'finalResponse'].includes(call.method)
      && call.stopReason === 'end_turn'));
    status.actualModelRestartPrepared = true;
    const callsAtPrepare = modelCalls.length;
    stage = 'restart-confirm'; browserPhase = stage;
    await clickButton(frame, 'Confirm System restart');
    await frame.waitForFunction(() => [...document.querySelectorAll('button')]
      .some(button => button.textContent.trim() === 'Check saved System restart' && !button.disabled),
    { timeout: 120000 });
    assert.equal(confirmPosts, 1); assert.equal(confirmResponsesLost, 1);
    assert.equal(recoveryReadsFaulted, 1); status.renderedPhysicalRestartConfirmed = true;
    assert.ok(savedProposals.length >= 1 && savedProposals.length <= 12);
    assert.ok(savedProposals.every(value => JSON.stringify(value) === JSON.stringify(savedProposals[0])));
    const savedProposal = savedProposals.at(-1);
    assert.equal(savedProposal.status, 'completed'); assert.equal(savedProposal.replayed, true);
    assert.equal(savedProposal.stopReason, 'end_turn');
    assert.deepEqual(Object.keys(savedProposal.systemRestartProposal).sort(), ['version', 'proposalId',
      'action', 'name', 'targetId', 'scopeKey', 'sourceSnapshotSha256', 'modeCapability',
      'requestSha256', 'proposalSha256'].sort());
    assert.equal(savedProposal.systemRestartProposal.version, 1);
    assert.equal(savedProposal.systemRestartProposal.action, 'restart');
    assert.equal(savedProposal.systemRestartProposal.name, NAME);
    for (const key of ['scopeKey', 'sourceSnapshotSha256', 'requestSha256', 'proposalSha256'])
      assert.match(savedProposal.systemRestartProposal[key], /^[a-f0-9]{64}$/);
    const proposal = savedProposal.systemRestartProposal;
    const requestSha256 = require('../../server/services/secureshopSystemRestartContract')
      .restartRequestDigest({ version: 1, operationId: proposal.proposalId, name: proposal.name });
    assert.equal(proposal.requestSha256, requestSha256);
    const proposalBody = Object.fromEntries(Object.entries(proposal)
      .filter(([key]) => key !== 'proposalSha256'));
    assert.equal(proposal.proposalSha256,
      require('../../server/services/mcp/protocolContext').canonicalDigest(proposalBody));
    const actor = bootstraps[0];
    const actorScope = await composition.launches.resolveCapability(actor.launch);
    const actorPersona = await composition.personaAuth.authenticateBoundToken({ scope: actorScope,
      token: actor.authorization.slice('Bearer '.length) });
    const sourceSnapshot = require('../../server/services/secureshopRoleSystemRestartProposal')
      .systemRestartSourceSnapshot({ context: { scope: actorScope,
        persona: { id: actorPersona.user.id, role: actorPersona.user.role },
        personaSession: { sessionId: actorPersona.sessionId,
          authorityVersion: actorPersona.authorityVersion } },
      administration: { restartCapability: 'secureshop-owned-system-restart.v2',
        targetId: proposal.targetId } });
    assert.equal(proposal.scopeKey, sourceSnapshot.scopeKey);
    assert.equal(proposal.sourceSnapshotSha256, sourceSnapshot.sourceSnapshotSha256);
    const operation = (await review.query(`SELECT operation_id,target_id,state,before_instance_id,
      after_instance_id,before_generation,after_generation,request_sha256,effect_sha256
      FROM secureshop_review.bound_system_restart_operations`)).rows;
    assert.equal(operation.length, 1); assert.equal(operation[0].state, 'completed');
    assert.notEqual(operation[0].before_instance_id, operation[0].after_instance_id);
    assert.equal(Number(operation[0].after_generation), Number(operation[0].before_generation) + 1);
    status.ownedRestartTransition = true;
    const protectedProposalPath = `/agents/admin/assistant/operations/${savedProposal.sessionId}/${savedProposal.requestId}`;
    requestPhase = 'saved-recovery';
    const protectedProposalFinished = observeRequestLog(requestLog, entry => entry.method === 'GET'
      && entry.path === protectedProposalPath && entry.phase === 'saved-recovery'
      && entry.lifecycle === 'finished');
    await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
    await frame.waitForSelector('[data-testid="admin-role-assistant"]');
    await clickButton(frame, 'Check saved System restart');
    await frame.waitForFunction(() => [...document.querySelectorAll('[role="status"]')]
      .some(node => node.textContent.includes('Owned service restarted. Saved receipt verified.')),
    { timeout: 120000 });
    assert.ok(await protectedProposalFinished,
      'saved-recovery protected proposal GET did not finish');
    await frame.$eval('section[aria-label="Admin System restart review"]', node => node.scrollIntoView());
    await frame.waitForFunction(() => {
      const node = document.querySelector('section[aria-label="Admin System restart review"]');
      return node && node.getBoundingClientRect().top < innerHeight && node.getBoundingClientRect().bottom > 0;
    });
    await page.screenshot({ path: path.join(path.dirname(evidencePath),
      'admin-system-restart-recovered.png') });
    assert.equal(confirmPosts, 1); assert.equal(modelCalls.length, callsAtPrepare);
    const ownerRequests = requestLog.filter(entry => entry.path.includes('/agents/admin/assistant')
      || entry.path.startsWith('/admin/system/restart'));
    assert.ok(ownerRequests.length >= 6);
    for (const entry of ownerRequests) {
      assert.match(entry.launch || '', /^\S+$/); assert.match(entry.authorization || '', /^Bearer \S+$/);
      const requestScope = await composition.launches.resolveCapability(entry.launch);
      assert.deepEqual(Object.fromEntries(['launchId', 'scenarioId', 'generation',
        'platformOwnerId', 'platformSessionId'].map(key => [key, requestScope[key]])),
      Object.fromEntries(['launchId', 'scenarioId', 'generation',
        'platformOwnerId', 'platformSessionId'].map(key => [key, actorScope[key]])));
      const requestPersona = await composition.personaAuth.authenticateBoundToken({ scope: requestScope,
        token: entry.authorization.slice('Bearer '.length) });
      assert.deepEqual({ id: requestPersona.user.id, role: requestPersona.user.role,
        sessionId: requestPersona.sessionId, authorityVersion: requestPersona.authorityVersion },
      { id: actorPersona.user.id, role: actorPersona.user.role,
        sessionId: actorPersona.sessionId, authorityVersion: actorPersona.authorityVersion });
    }
    const operationPath = `/admin/system/restart-operations/${operation[0].operation_id}`;
    const operationGets = ownerRequests.filter(entry => entry.method === 'GET'
      && entry.path === operationPath);
    assert.ok(operationGets.some(entry=>entry.status===404)&&operationGets.some(entry=>entry.status===503)
      &&operationGets.some(entry=>entry.status===200));
    const protectedProposalGets = ownerRequests.filter(entry => entry.method === 'GET'
      && /^\/agents\/admin\/assistant\/operations\/[0-9a-f-]{36}\/[0-9a-f-]{36}$/i.test(entry.path));
    protectedProposalLifecycle = protectedProposalGets.map(entry => ({ method: entry.method,
      path: entry.path, phase: entry.phase, lifecycle: entry.lifecycle,
      headersSent: entry.headersSent ?? false, status: entry.status ?? null }));
    assertProtectedProposalRecovery(protectedProposalLifecycle, { path: protectedProposalPath });
    assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.bound_system_restart_operations')).rows[0].n, 1);
    status.lostAckExactGetRecovery = true; status.noDuplicateRestart = true;
    const foreign = await fetch(`${origin}/api/secureshop/admin/system/restart-operations/${operation[0].operation_id}`,
      { headers: { 'x-dvaia-secureshop-launch': siblingBase.bearer,
        authorization: `Bearer ${siblingBase.persona.token}` } });
    assert.notEqual(foreign.status, 200); status.siblingOperationDenied = true;
    const auditRows = (await review.query(`SELECT actor,action,target,outcome,source_kind,source_id,params_json
      FROM secureshop_review.bound_audit_events WHERE action='system_restart_operation'`)).rows;
    assert.equal(auditRows.length, 1);
    assert.deepEqual({ actor: auditRows[0].actor, action: auditRows[0].action,
      target: auditRows[0].target, outcome: auditRows[0].outcome,
      sourceKind: auditRows[0].source_kind, sourceId: auditRows[0].source_id },
    { actor: 'admin', action: 'system_restart_operation', target: NAME,
      outcome: 'completed', sourceKind: 'system_restart_operation',
      sourceId: operation[0].operation_id });
    const auditParams = typeof auditRows[0].params_json === 'string'
      ? JSON.parse(auditRows[0].params_json) : auditRows[0].params_json;
    assert.deepEqual(Object.keys(auditParams).sort(), ['version', 'storage', 'requestSha256',
      'effectSha256', 'beforeInstanceId', 'afterInstanceId'].sort());
    assert.equal(auditParams.version, 2);
    assert.equal(auditParams.requestSha256, operation[0].request_sha256.toString('hex'));
    assert.equal(auditParams.effectSha256, operation[0].effect_sha256.toString('hex'));
    assert.equal(auditParams.beforeInstanceId, operation[0].before_instance_id);
    assert.equal(auditParams.afterInstanceId, operation[0].after_instance_id);
    assert.equal(auditParams.storage.targetId, operation[0].target_id);
    status.auditSourceBound = true;
    const creditRows=async()=>({
      judgments:(await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE objective_id=$1 ORDER BY evaluation_id',[OBJECTIVE])).rows,
      contributions:(await identity.query(`SELECT c.* FROM secureshop_auth.assessment_contributions c
        JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id) WHERE j.objective_id=$1 ORDER BY c.evaluation_id`,[OBJECTIVE])).rows,
      completions:(await identity.query('SELECT * FROM secureshop_auth.assessment_completions WHERE objective_id=$1 ORDER BY evaluation_id',[OBJECTIVE])).rows,
      workshop:(await identity.query('SELECT * FROM workshop_platform.completions WHERE objective_id=$1 ORDER BY objective_id',[OBJECTIVE])).rows,
    });
    const initialCredit=await creditRows();
    assert.ok(Object.values(initialCredit).every(rows=>rows.length===0));
    const captureTurn=async(saved,start,end)=>{
      const records=(await agents.query(`SELECT session_id,request_id::text,status,request_hash,result_json
        FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,[saved.sessionId,saved.requestId])).rows;
      assert.equal(records.length,1);const record=records[0],meta=record.result_json.taskMetadata.roleChat;
      const origin=meta.systemRestartInjectionOrigin;
      const binding=(await agents.query(`SELECT * FROM secureshop_agents.role_chat_turn_bindings
        WHERE session_id=$1 AND request_id=$2`,[saved.sessionId,saved.requestId])).rows;
      assert.equal(binding.length,1);
      const trace=(await agents.query(`SELECT event_id,id,session_id,step,actor,kind,agent_ns,tool_name,
        params_json,result_json,latency_ms,tokens_in,tokens_out,provider,policy_violation,ts
        FROM secureshop_agents.agent_trace WHERE session_id=$1 AND event_id=ANY($2::text[])`,
      [saved.sessionId,origin.traceEventIds])).rows;
      const byId=new Map(trace.map(row=>[row.event_id,row]));
      const traces=origin.traceEventIds.map(id=>byId.get(id));assert.ok(traces.every(Boolean));
      const run=(await identity.query(`SELECT run_id,owner_key,generation::text AS generation,status
        FROM graph_runtime.runs WHERE run_id=$1`,[origin.runId])).rows;assert.equal(run.length,1);
      const value={sessionId:saved.sessionId,requestId:saved.requestId,record,binding:binding[0],traces,run:run[0],span:{start,end}};
      turns.push(value);return value;
    };
    const actorAtOriginal=actorTransport.calls.length;
    await captureTurn(savedProposal,0,actorAtOriginal);
    privateReceipt=(await review.query(`SELECT receipt_text,encode(receipt_sha256,'hex') AS receipt_sha256
      FROM secureshop_review.bound_system_restart_full_receipts WHERE operation_id=$1`,[proposal.proposalId])).rows[0];
    assert.ok(privateReceipt);const privateBody=JSON.parse(privateReceipt.receipt_text);
    assert.equal(privateBody.stdoutText,privateBody.witness.hostname+'\n');
    assert.equal(privateBody.stderrText,'');
    assert.equal(privateBody.version,require('../../sidecars/sandbox-runner/owned-system/restart-wire').WITNESS_VERSION);
    await frame.waitForFunction(text=>[...document.querySelectorAll('pre')].some(node=>node.textContent===text),
      {timeout:30000},privateBody.stdoutText);
    stage='restart-canonical-assessment'; browserPhase = stage;
    const ids={sessionId:savedProposal.sessionId,requestId:savedProposal.requestId};
    const assessmentPath=`/agents/admin/assistant/system/restart/assessment/${ids.sessionId}/${ids.requestId}`;
    await clickButton(frame,'Check saved System restart assessment');
    await frame.waitForFunction(()=>[...document.querySelectorAll('button')]
      .some(node=>node.textContent.trim()==='Assess System restart'&&!node.disabled),{timeout:30000});
    const initial=assessmentOutcomes.filter(row=>row.method==='GET'&&row.path===assessmentPath).at(-1);
    assert.deepEqual(initial?.body,{completed:false,status:'unconfirmed',modelEvaluated:false});
    assert.deepEqual(await creditRows(),initialCredit);
    await clickButton(frame,'Assess System restart');
    await frame.waitForFunction(()=>document.querySelector('section[aria-label="Admin System restart assessment"]')
      ?.textContent.includes('Objective completed.'),{timeout:180000});
    const posts=assessmentOutcomes.filter(row=>row.method==='POST');assert.equal(posts.length,1);
    const savedAssessment=assessmentOutcomes.filter(row=>row.method==='GET'&&row.path===assessmentPath).at(-1);
    const awarded=await creditRows();
    assert.equal(awarded.judgments.length,1);assert.equal(awarded.contributions.length,1);
    assert.equal(awarded.completions.length,1);assert.deepEqual(awarded.workshop,[]);
    assert.equal(judgeTranscripts.length,1);assert.equal(judgeInvocations,1);
    assessmentEvidence={initial,post:posts[0],saved:savedAssessment,judgment:awarded.judgments[0],
      contribution:awarded.contributions[0],completion:awarded.completions[0],workshop:awarded.workshop,
      judgeTranscript:judgeTranscripts[0]};
    assert.equal(posts[0].status,200);assert.deepEqual(posts[0].requestBody,ids);
    assert.equal(posts[0].body.completed,true);assert.equal(posts[0].body.judgment.verdict,'pass');
    status.originalAssessmentPost=true;status.canonicalJudgePass=true;status.genuineCredit=true;
    stage='restart-saved-assessment'; browserPhase = stage;
    await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);
    await frame.waitForSelector('[data-testid="admin-role-assistant"]');
    await clickButton(frame,'Check saved System restart assessment');
    await frame.waitForFunction(()=>document.querySelector('section[aria-label="Admin System restart assessment"]')
      ?.textContent.includes('Objective completed.'),{timeout:30000});
    assert.deepEqual(assessmentOutcomes.filter(row=>row.method==='GET'&&row.path===assessmentPath).at(-1)?.body,savedAssessment.body);
    assert.equal(assessmentOutcomes.filter(row=>row.method==='POST').length,1);
    assert.equal(judgeInvocations,1);assert.equal(actorTransport.calls.length,actorAtOriginal);
    assert.equal(confirmPosts,1);status.savedAssessmentGetRecovery=true;
    await page.screenshot({path:path.join(path.dirname(evidencePath),'admin-restart-injection-assessment.png')});
    const foreignAssessment=await fetch(`${origin}/api/secureshop${assessmentPath}`,{headers:{
      'x-dvaia-secureshop-launch':siblingBase.bearer,authorization:`Bearer ${siblingBase.persona.token}`}});
    assert.notEqual(foreignAssessment.status,200);await foreignAssessment.text();status.siblingAssessmentDenied=true;
    stage='restart-fixed-mode'; browserPhase = stage;
    browserPhase = 'fixed-mode-settings-open';
    await clickButton(page,'Shop settings');
    await page.waitForSelector('aside[aria-label="Shop settings"]');
    browserPhase = 'fixed-mode-selection';
    await selectFixedShopMode(page,origin); browserPhase = 'fixed-mode-selected';
    await page.waitForFunction(()=>document.querySelector('[role="group"][aria-label="Shop feature mode"]')?.textContent.includes('Current: Fixed'));
    await clickButton(page,'Shop settings');await page.waitForSelector('aside[aria-label="Shop settings"]',{hidden:true});
    frame=await frameFor(page);
    const beforeFixed=savedProposals.length;
    await frame.waitForSelector('[data-testid="admin-role-composer-slot"] textarea');
    await frame.type('[data-testid="admin-role-composer-slot"] textarea',message);
    const fixedSavedProposalResponse=page.waitForResponse(response=>{
      const url=new URL(response.url());
      return url.origin===origin&&response.request().method()==='GET'&&response.status()===200
        &&/^\/api\/secureshop\/agents\/admin\/assistant\/operations\/[0-9a-f-]{36}\/[0-9a-f-]{36}$/i.test(url.pathname);
    },{timeout:120000});
    browserPhase = 'fixed-turn-submit';
    const [,fixedSavedProposal]=await Promise.all([
      clickButton(frame,'Send to admin assistant'),fixedSavedProposalResponse]);
    browserPhase = 'fixed-proposal-loaded';
    await fixedSavedProposal.json();
    await frame.waitForFunction(()=>[...document.querySelectorAll('button')]
      .some(node=>node.textContent.trim()==='Confirm System restart'&&!node.disabled),{timeout:120000});
    assert.ok(savedProposals.length>beforeFixed);
    const second=savedProposals.at(-1);assert.equal(second.systemRestartProposal.name,NAME);
    assert.equal(second.systemRestartProposal.modeCapability.effectiveMode,'fixed');
    await captureTurn(second,actorAtOriginal,actorTransport.calls.length);
    const confirmsBefore=confirmPosts;
    const fixedConfirmResponse=page.waitForResponse(response=>{
      const url=new URL(response.url());
      return url.origin===origin&&response.request().method()==='POST'
        &&url.pathname==='/api/secureshop/agents/admin/assistant/system/restart/confirm';
    },{timeout:30000});
    browserPhase = 'fixed-confirm-submit';
    const [,fixedDeniedResponse]=await Promise.all([
      clickButton(frame,'Confirm System restart'),fixedConfirmResponse]);
    assert.equal(fixedDeniedResponse.status(),403);
    await frame.waitForFunction(text=>[...document.querySelectorAll('[role="status"]')]
      .some(node=>node.textContent.trim()===text),{timeout:30000},
    'Restart outcome is unconfirmed. Check the saved operation; no restart was repeated.');
    assert.equal(confirmPosts,confirmsBefore+1);assert.equal(confirmPosts,2);
    const denied=confirmOutcomes.at(-1);assert.equal(denied.status,403);assert.equal(denied.code,'SYSTEM_RESTART_FIXED_DENIED');
    assert.equal(restartTransport.filter(row=>row.method==='POST'&&row.path==='/secureshop/system/restart').length,1);
    assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.bound_system_restart_operations')).rows[0].n,1);
    assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.bound_system_restart_full_receipts')).rows[0].n,1);
    const currentActor=bootstraps.at(-1);
    const fixedPath=`/agents/admin/assistant/system/restart/assessment/${second.sessionId}/${second.requestId}`;
    const fixedResponse=await fetch(`${origin}/api/secureshop${fixedPath}`,{headers:{
      'x-dvaia-secureshop-launch':currentActor.launch,authorization:currentActor.authorization}});
    assert.equal(fixedResponse.status,200);const fixedAssessment=await fixedResponse.json();
    assert.deepEqual(fixedAssessment,{completed:false,status:'ineligible',modelEvaluated:false});
    fixedEvidence={status:denied.status,code:denied.code,assessment:fixedAssessment};
    assert.equal(judgeInvocations,1);assert.deepEqual(await creditRows(),awarded);status.physicalFixedDenial=true;
    browserPhase = 'fixed-denial-verified';
    await page.screenshot({path:path.join(path.dirname(evidencePath),'admin-restart-injection-fixed.png')});
    browserPhase = 'authority-reset-begin';
    await composition.launches.beginReset({ launchId: actorScope.launchId,
      platformSessionId: actorScope.platformSessionId, platformOwnerId: actorScope.platformOwnerId,
      expectedGeneration: actorScope.generation, idempotencyKey: `restart-chat-reset-${randomUUID()}` });
    browserPhase = 'authority-reset-complete';
    const retired = await fetch(`${origin}/api/secureshop/admin/system/restart-operations/${operation[0].operation_id}`,
      { headers: { 'x-dvaia-secureshop-launch': actor.launch,
        authorization: actor.authorization } });
    assert.notEqual(retired.status, 200); status.resetSessionDenied = true;
    assert.deepEqual((await identity.query(
      'SELECT objective_id FROM workshop_platform.completions ORDER BY objective_id')).rows,
    completionsBefore.rows);
    assert.equal(judgeInvocations,1);assert.deepEqual(await creditRows(),awarded);
    assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.bound_system_restart_full_receipts')).rows[0].n,1);
    status.immutableHistoryRetained=true;
    const resetAssessment=await fetch(`${origin}/api/secureshop${assessmentPath}`,{headers:{
      'x-dvaia-secureshop-launch':actor.launch,authorization:actor.authorization}});
    assert.notEqual(resetAssessment.status,200);await resetAssessment.text();
    browserPhase = 'final-pageerror-gate';
    assert.deepEqual(pageErrors, []);
    status.actorCalls = actualModelRequests.length;
    status.roleTurns = requestLog.filter(entry => entry.method === 'POST'
      && entry.path === '/agents/admin/assistant/chat').length;
    status.passed = true;
  } catch (error) {
    failure = error;
    let operationRows = [], targetInspect = null;
    try {
      operationRows = (await pools.REVIEW_RUNTIME.query(`SELECT operation_id,target_id,state,
        before_generation,after_generation,failure_code,request_sha256 IS NOT NULL AS has_request_sha256,
        effect_sha256 IS NOT NULL AS has_effect_sha256,output_sha256 IS NOT NULL AS has_output_sha256
        FROM secureshop_review.bound_system_restart_operations ORDER BY admitted_at LIMIT 4`)).rows;
    } catch (readError) {
      operationRows = [{ diagnosticError: readError.code || readError.name || 'operation-read-failed' }];
    }
    if (operationRows.length === 1 && operationRows[0].target_id && restartClient) {
      try { targetInspect = await restartClient.inspect(operationRows[0].target_id); }
      catch (inspectError) { targetInspect = { diagnosticError:
        inspectError.code || inspectError.name || 'target-inspect-failed' }; }
    }
    const diagnosticProtectedProposalLifecycle = requestLog.filter(entry => entry.method === 'GET'
      && /^\/agents\/admin\/assistant\/operations\/[0-9a-f-]{36}\/[0-9a-f-]{36}$/i.test(entry.path))
      .slice(-12).map(entry => ({ method: entry.method, path: entry.path, phase: entry.phase,
        lifecycle: entry.lifecycle, headersSent: entry.headersSent ?? false,
        status: entry.status ?? null }));
    const diagnostic = { stage, url: page?.url() || null,
      visible: page ? await visibleSetupState(page) : [],
      authEvents: authEvents.slice(-20), requestFailures, pageErrors: pageErrors.slice(0, 16),
      protectedProposalLifecycle: diagnosticProtectedProposalLifecycle,
      confirmPosts, confirmResponsesLost, recoveryReadsFaulted,
      confirmOutcomes: confirmOutcomes.slice(-4), operationRows, targetInspect,
      restartTransport: restartTransport.slice(-16),
      sidecarLogArtifact: 'restart-executor.log',
      sessionCookiePresent: page ? (await page.cookies().catch(() => []))
        .some(cookie => cookie.name === 'dvaia_shop_session') : false };
    t.diagnostic(JSON.stringify(diagnostic));
    if (page) await page.screenshot({ path: path.join(path.dirname(evidencePath),
      'admin-system-restart-failure.png') }).catch(() => {});
  }
  finally {
    for (const close of [() => browser?.close(), () => closeServer(server),
      () => actorTransport?.close(), () => judgeTransport?.close(),
      () => reset?.closeFeatureTransports?.(), () => reset?.auditLedger?.close?.(),
      () => profile && fs.rm(profile, { recursive: true, force: true }),
      () => leasePool.end(), ...Object.values(pools).map(pool => () => pool.end())]) {
      try { await close(); } catch (error) { cleanupErrors.push(error); }
    }
    status.fixtureCleaned = cleanupErrors.length === 0;
    status.actorCalls = actualModelRequests.length;
    status.roleTurns = requestLog.filter(entry => entry.method === 'POST'
      && entry.path === '/agents/admin/assistant/chat').length;
    status.errors = failure ? [{ name: failure.name || 'Error', code: failure.code || null }] : [];
    status.actorCalls=actorTransport?.calls.filter(call=>call.kind==='actor').length||0;
    status.judgeCalls=judgeTransport?.calls.filter(call=>call.kind==='judge').length||0;
    for(const [key,value] of Object.entries(oldJudgeEnv))if(value===undefined)delete process.env[key];else process.env[key]=value;
    const wire={version:1,model:MODEL,modelDigest:DIGEST,calls:[...(actorTransport?.calls||[]),...(judgeTransport?.calls||[])],
      turns,executor:restartTransport,privateReceipt,assessment:assessmentEvidence,fixed:fixedEvidence,pageErrors};
    if(!failure)try{assertActualWire(wire,status);}catch(error){failure=error;status.passed=false;status.errors=[{name:error.name,code:error.code||null}];}
    const bytes=JSON.stringify(wire,null,2);
    if(Buffer.byteLength(bytes)>80*1024*1024)cleanupErrors.push(Error('Restart original wire bound exceeded'));
    else try{await fs.writeFile(path.join(path.dirname(evidencePath),'admin-restart-injection-wire.json'),bytes,{flag:'wx',mode:0o600});}
    catch(error){cleanupErrors.push(error);}

    try { await fs.writeFile(evidencePath, JSON.stringify(status, null, 2),
      { flag: 'wx', mode: 0o600 }); } catch (error) { cleanupErrors.push(error); }
  }
  if (cleanupErrors.length) throw new AggregateError(cleanupErrors, 'Restart chat cleanup failed');
  if (failure) throw failure;
  assertPrivateReceipt({ ...status, fixtureCleaned: true, errors: [] });
});

module.exports = { assertPrivateReceipt, FLAGS, SCOPE, systemRestartDependencies };
