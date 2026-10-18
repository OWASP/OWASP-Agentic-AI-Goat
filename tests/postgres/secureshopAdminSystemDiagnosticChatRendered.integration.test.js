'use strict';
// Opted actual-model/browser System diagnostic chat qualification. No Judge credit.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const express = require('express');
const { randomUUID, randomBytes, createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const PREFIX = 'PG_SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_CHAT_BROWSER_';
const STORES = Object.freeze(['IDENTITY','AGENTS','REVIEW','COMMERCE']);
const STORE_NAMES = Object.freeze({IDENTITY:'identity',AGENTS:'secureshop_agents',REVIEW:'secureshop_review',COMMERCE:'secureshop'});
const ASSERTION = 'standalone administrator prepares and physically confirms owned System diagnostics through real local llama3.1:8b in vulnerable and fixed modes';
const SCOPE = 'current-main standalone admin diagnostic chat; two genuine llama3.1:8b prepare turns, one isolated executor effect, fixed denial, saved GET recovery, zero Judge or credit';
const FLAGS = Object.freeze(['passed','isolatedStores','genuineAdminUiSession','actualModelDiagnosticPrepared','renderedProposalNoEffect','physicalVulnerableConfirm','ownedDiagnosticReceipt','lostAckExactGetRecovery','noDuplicateDiagnostic','physicalFixedDenial','siblingOperationDenied','resetSessionDenied','noObjectiveCredit','fixtureCleaned']);
const MODEL = 'llama3.1:8b';
const ENABLED = process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_CHAT_BROWSER_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && STORES.every(store => ['MIGRATION','RUNTIME'].every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
function assertPrivateReceipt(value){
 assert.ok(value && typeof value==='object' && !Array.isArray(value));
 assert.deepEqual(Object.keys(value).sort(),[...FLAGS,'scope','actorCalls','roleTurns','judgeCalls','executorCalls','errors'].sort());
 for(const flag of FLAGS)assert.equal(value[flag],true,flag);
 assert.equal(value.scope,SCOPE);assert.equal(value.roleTurns,2);
 assert.ok(Number.isSafeInteger(value.actorCalls)&&value.actorCalls>=4&&value.actorCalls<=14);
 assert.equal(value.judgeCalls,0);assert.equal(value.executorCalls,1);assert.deepEqual(value.errors,[]);
}
function diagnosticDependencies({client,grading,agentsPool,composition,reset,modeAuthority}){
 return Object.freeze({systemDiagnosticClient:client,preparedGrading:grading,agentsPool,
  audit:reset.audit.agents,authenticatePersona:composition.personaAuth.authenticatePersona,modeAuthority});
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
async function boundedResponse(response, limit = 524288) {
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
    const body = Buffer.concat(chunks, size);
    const bodyUtf8=new TextDecoder('utf-8',{fatal:true}).decode(body);
    return { bytes: size, bodyUtf8,sha256: createHash('sha256').update(body).digest('hex'),
      value: JSON.parse(bodyUtf8) };
  } catch (error) { return { bytes: size, decodeError: error.name || 'response-decode-failed' }; }
  finally { reader.releaseLock?.(); }
}
async function clickButton(frame, label) {
  await frame.waitForFunction(text => [...document.querySelectorAll('button')]
    .some(button => button.textContent.trim() === text && !button.disabled),
  { timeout: 30000 }, label);
  const buttons = await frame.$$('button');
  for (const button of buttons) {
    const match = await button.evaluate((node, text) =>
      node.textContent.trim() === text && !node.disabled, label);
    if (match) { await button.click(); return; }
  }
  throw new Error(`Enabled button unavailable: ${label}`);
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

async function recordBrowser(browser, target, executablePath, expectedSha) {
  const pid = browser?.process?.()?.pid;
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  const real = await fs.realpath(executablePath);
  const actualSha = createHash('sha256').update(await fs.readFile(real)).digest('hex');
  assert.equal(actualSha, expectedSha);
  const startTime = execFileSync('ps', ['-p', String(pid), '-o', 'lstart='], { encoding: 'utf8' }).trim();
  assert.match(startTime, /^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}$/);
  const temp = `${target}.${process.pid}.tmp`;
  await fs.writeFile(temp, JSON.stringify({ schemaVersion: 1, processes: [{
    kind: 'admin_system_diagnostic_chat_browser', pid, startTime,
    executablePath: real, executableSha256: actualSha }] }) + '\n', { mode: 0o600, flag: 'wx' });
  await fs.rename(temp, target);
}

test(ASSERTION, { skip: !ENABLED, timeout: 600000 }, async t => {
  const workspace = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '');
  assert.equal(workspace, process.cwd(), 'current checkout required; no source copy');
  const build = path.resolve(process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_CHAT_BROWSER_BUILD || '');
  assert.equal(build, path.join(workspace, 'client/build'));
  const executablePath = path.resolve(process.env.PUPPETEER_EXECUTABLE_PATH || '');
  const browserSha = process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_CHAT_BROWSER_SHA256;
  assert.match(browserSha || '', /^[a-f0-9]{64}$/);
  const recordPath = path.resolve(process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_CHAT_BROWSER_RECORD_PATH || '');
  const evidencePath = path.resolve(process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_CHAT_BROWSER_EVIDENCE_PATH || '');
  assert.equal(path.dirname(recordPath), path.dirname(evidencePath));
  assert.equal(path.dirname(evidencePath), path.resolve(process.env.TMPDIR, '../..'));
  assert.equal(process.env.OLLAMA_MODEL, MODEL);
  assert.match(process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_CHAT_MODEL_DIGEST || '', /^[a-f0-9]{64}$/);
  const diagnosticURL = new URL(process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_CHAT_BROWSER_EXECUTOR_URL || '');
  assert.equal(diagnosticURL.protocol, 'http:'); assert.equal(diagnosticURL.hostname, '127.0.0.1');
  assert.equal(diagnosticURL.pathname, '/');
  const diagnosticToken = process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_CHAT_BROWSER_EXECUTOR_TOKEN;
  assert.match(diagnosticToken || '', /^[A-Za-z0-9_-]{43,128}$/);
  const urls = urlsFromEnvironment();
  const pools = Object.fromEntries(STORES.flatMap(store => ['MIGRATION','RUNTIME'].map(role =>
    [`${store}_${role}`, new Pool({ connectionString: urls[`${store}_${role}`],
      max: role === 'RUNTIME' ? 12 : 3 })])));
  const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 3 });
  const status = Object.fromEntries(FLAGS.map(flag => [flag, false]));
  Object.assign(status, { scope: SCOPE, actorCalls: 0, roleTurns: 0, judgeCalls: 0,
    executorCalls: 0, errors: [] });
  const pageErrors = [], requestFailures = [], cleanupErrors = [], modelCalls = [], modelWire = [],
    actualModelRequests = [], requestLog = [], bootstraps = [], executorWire = [],
    savedProposals = [], confirmOutcomes = [];
  let reset, composition, diagnostic, server, browser, page, profile, failure, stage = 'setup';
  let confirmPosts = 0, lostAck = 0;
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
    const observedFetch = async (input, init) => {
      const url = new URL(input), method = init?.method || 'GET';
      assert.ok(executorWire.length<16,'bounded isolated executor transport calls');
      const event={method,path:url.pathname,status:null,bytes:null,responseSha256:null};
      executorWire.push(event);
      if (method === 'POST' && url.pathname === '/secureshop/system/diagnostic') {
        const wire = JSON.parse(init?.body || 'null');
        assert.ok(Buffer.byteLength(init.body,'utf8')<=131072);
        event.operationId = wire.request.operationId;
        event.requestSha256 = require('../../sidecars/sandbox-runner/owned-system/diagnostic-contract')
          .diagnosticRequestDigest(wire.request);
        event.requestBody=init.body;
      }
      try {
        const response=await fetch(input,init);
        event.status=response.status;
        const observed=await boundedResponse(response);
        event.bytes=observed.bytes??null;
        event.responseSha256=observed.sha256||null;
        if(method==='POST'&&url.pathname==='/secureshop/system/diagnostic'){
          event.responseBody=observed.bodyUtf8??null;
          assert.ok(observed.value,'original isolated executor response must be bounded JSON');
          require('../../sidecars/sandbox-runner/owned-system/diagnostic-wire')
            .validateBoundDiagnosticResult(JSON.parse(init.body),observed.value);
        }
        return response;
      }catch(error){event.error={name:error.name||'Error',code:error.code||null};throw error;}
    };
    const diagnosticClient = require('../../server/services/secureshopSystemDiagnosticClient')
      .createSecureShopSystemDiagnosticClient({ baseURL: diagnosticURL.href,
        token: diagnosticToken, fetchImpl: observedFetch });
    reset = require('../../server/services/secureshopCleanupComposition')
      .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, leasePool, audit });
    const grading = await require('../../server/services/secureshopGradingBootstrap')
      .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents, progress,
        resetComposition: reset,
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
      baseUrl: new URL(process.env.OLLAMA_BASE_URL).origin, model: MODEL });
    const originalTransport = provider.transport.chat.bind(provider.transport);
    provider.transport.chat = async (...args) => {
      assert.ok(actualModelRequests.length < 14, 'two preparation turns have a fourteen-call physical budget');
      actualModelRequests.push({ ordinal: actualModelRequests.length + 1 });
      const requestSha256 = createHash('sha256').update(JSON.stringify({
        transcript: args[0], format: args[2]?.format,
        temperature: args[2]?.temperature, num_predict: args[2]?.num_predict,
      })).digest('hex');
      const input=JSON.stringify({transcript:args[0],format:args[2]?.format,
        temperature:args[2]?.temperature,num_predict:args[2]?.num_predict});
      assert.ok(Buffer.byteLength(input,'utf8')<=2*1024*1024);
      try {
        const result = await originalTransport(...args);
        const output=JSON.stringify(result);
        assert.ok(Buffer.byteLength(output,'utf8')<=2*1024*1024);
        modelWire.push({ordinal:actualModelRequests.length,requestSha256,
          requestBody:input,responseSha256:createHash('sha256').update(output).digest('hex'),
          responseBody:output});
        return result;
      } catch(error) {
        modelWire.push({ordinal:actualModelRequests.length,requestSha256,
          requestBody:input,error:{name:error.name||'Error',code:error.code||null}});
        throw error;
      }
    };
    for (const method of ['chat','finalResponse']) {
      const original = provider[method].bind(provider);
      provider[method] = async input => {
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
    const judge = async () => { status.judgeCalls++; throw new Error('Diagnostic chat cannot invoke Judge'); };
    let diagnosticValue;
    composition = require('../../server/services/secureshopBoundReviewComposition')
      .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, commercePool: commerce, resetComposition: reset,
        gradingBootstrap: grading, scenes, modeAuthority, toolPolicyRepository,
        getSystemDiagnostic: () => diagnosticValue, fixtures: [],
        requiredObjectives: ['ss_stored_browser_execution'],
        jwtSecret: 'disposable-diagnostic-chat-persona-secret-at-least-32-bytes',
        agentRuntime: { provider }, judge });
    diagnostic = await require('../../server/services/secureshopBoundReviewComposition')
      .createOptionalSystemDiagnosticComposition(diagnosticDependencies({ client: diagnosticClient,
        grading, agentsPool: agents, composition, reset, modeAuthority }));
    diagnosticValue = diagnostic;
    assert.equal(diagnostic.ready, true); assert.equal(composition.roleAssistants.admin.ready, true);
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
    const tenant=await auth.establishTenantContext(adminLogin.context);
    const siblingId=randomUUID(),siblingName=`diagnostic_sibling_${randomUUID().slice(0,8)}`;
    const siblingPassword='disposable-diagnostic-sibling';
    const siblingHash=await require('bcryptjs').hash(siblingPassword,12);
    const siblingRow=(await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin')
      RETURNING owner_id,shop_user_id`,[siblingId,siblingName,
      `${siblingName}@example.invalid`,siblingHash])).rows[0];
    await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
    [tenant.tenantId,siblingId,siblingRow.shop_user_id]);
    const siblingLogin=await auth.login({username:siblingName,password:siblingPassword});
    const siblingBase=await bootstrap(siblingLogin.context);
    assert.equal(siblingBase.persona.user.role,'admin');
    const protectedReset = require('../../server/services/secureshopStandaloneReset')
      .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
        launches: composition.launches, scenes, resetCoordinator: reset.launchResetCoordinator,
        preflight: reset.sceneResetPreflight });
    const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
      .createSecureShopStorePublicCatalogRepository({ identityPool: identity, reviewPool: review,
        commercePool: commerce });
    const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
      .createRegisteredAdminResetEnvelope({activeKeyId:'diagnostic-chat-owned',
        keys:new Map([['diagnostic-chat-owned',randomBytes(32)]])});
    const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
      .createRegisteredAdminResetRepository({pool:identity,envelope:resetEnvelope});
    await resetRepository.checkReadiness();
    const mounted = Object.freeze({ ...composition, systemDiagnostic: diagnostic,
      standaloneAuth: Object.freeze({ service: auth, bootstrap, reset: protectedReset,
        registeredAdminReset:require('../../server/services/secureshopRegisteredAdminReset')
          .createRegisteredAdminResetService({repository:resetRepository}),
        mode: standaloneMode, assessmentObjectives: assessmentCatalog,
        assessmentRecovery:require('../../server/services/secureshopAssessmentRecovery')
          .createSecureShopAssessmentRecovery({identityPool:identity,authService:auth,bootstrap,
            launches:composition.launches,personaAuth:composition.personaAuth,
            personaAuthority:grading.personaAuthority,modeAuthority,scenes,judge}),
        cartImport:require('../../server/services/secureshopStandaloneCartImport')
          .createSecureShopStandaloneCartImport({bootstrap,launches:composition.launches,
            personaAuth:composition.personaAuth,commerce:composition.commerce}) }),
      publicCatalog });
    const bound = await require('../../server/services/secureshopBoundApplication')
      .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
        applicationMode:'standalone',
        authenticateToken: (_request, response) => response.sendStatus(401), audit: async () => {},
        agentRuntime: {}, getComposition: async options => {
          assert.equal(options.personaInboxFeature,false);
          assert.equal(options.mcpTrustFeature,false);
          assert.equal(options.ssrfFeature,false);
          return mounted;
        } });
    assert.equal(bound.standaloneReadiness.ready,true);
    assert.ok(Object.values(bound.standaloneReadiness.checks).every(value=>value===true));
    const app = express(); app.use(express.json()); server = await listen(app);
    const origin = `http://127.0.0.1:${server.address().port}`;
    app.use('/api/secureshop/auth', (request, response, next) => {
      const original = response.json.bind(response);
      response.json = value => {
        if (request.method === 'POST' && request.path === '/bootstrap'
          && response.statusCode === 200 && value?.persona?.user?.role === 'admin') {
          bootstraps.push({ launch: value.bearer,
            authorization: `Bearer ${value.persona.token}` });
        }
        return original(value);
      };
      next();
    });
    app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthRouter({ ...mounted.standaloneAuth,
        allowedOrigins: [origin], secureCookies: false }));
    app.use('/api/secureshop', (request, response, next) => {
      const entry = { method: request.method, path: request.path,
        launch: request.get('x-dvaia-secureshop-launch') || null,
        authorization: request.get('authorization') || null,
        ...(request.method === 'POST' ? { body: structuredClone(request.body) } : {}) };
      if (/assistant|diagnostic/.test(request.path)) {
        requestLog.push(entry); response.once('finish', () => { entry.status = response.statusCode; });
      }
      if (request.method === 'GET' && /^\/agents\/admin\/assistant\/operations\/[0-9a-f-]{36}\/[0-9a-f-]{36}$/i.test(request.path)) {
        const original = response.json.bind(response);
        response.json = value => {
          if (response.statusCode === 200) savedProposals.push(structuredClone(value));
          return original(value);
        };
      }
      if (request.method === 'POST'
        && request.path === '/agents/admin/assistant/system/diagnostic/confirm') {
        confirmPosts++;
        const original = response.json.bind(response);
        response.json = value => {
          confirmOutcomes.push({ status: response.statusCode,
            state: value?.state || null, code: value?.code || null,
            operationId: value?.operationId || null });
          if (value?.state === 'completed' && lostAck === 0) {
            lostAck++;
            response.status(503);
            return original({ error: 'Controlled diagnostic acknowledgement unavailable',
              code: 'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN' });
          }
          return original(value);
        };
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

    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-admin-diagnostic-chat-'));
    browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
      executablePath, args: ['--disable-background-networking'] });
    await recordBrowser(browser, recordPath, executablePath, browserSha);
    page = await browser.newPage(); await page.setViewport({ width: 1280, height: 900 });
    await page.setRequestInterception(true);
    page.on('request', request => request.url().startsWith(`${origin}/`)
      ? request.continue() : request.abort());
    page.on('pageerror', error => pageErrors.push(error.name || 'PageError'));
    page.on('requestfailed', request => {
      const url = new URL(request.url());
      if (url.origin === origin && requestFailures.length < 16) requestFailures.push({
        method: request.method(), path: url.pathname,
        error: String(request.failure()?.errorText || 'request failed').slice(0, 120),
      });
    });
    stage = 'customer-target-preparation';
    let frame = await loginShop(page, origin, 'student_customer', 'student123');
    const product = await frame.evaluate(async () => {
      const response = await fetch('/api/secureshop/products?limit=1');
      if (!response.ok) throw Error('Product target preparation failed'); return response.json();
    });
    assert.ok(Array.isArray(product.products) && product.products.length === 1);
    await logoutShop(frame, page, origin);
    stage = 'admin-physical-login';
    frame = await loginShop(page, origin, 'student_admin', 'student123');
    await frame.waitForSelector('a[href="/secureshop/admin"]');
    await frame.click('a[href="/secureshop/admin"]');
    await frame.waitForSelector('[data-testid="admin-role-assistant"]');
    assert.equal(bootstraps.length, 1); status.genuineAdminUiSession = true;
    const admissions = async () => (await agents.query(`SELECT operation_id,target_id,request_sha256,request_json
      FROM secureshop_agents.bound_system_diagnostic_admissions ORDER BY operation_id`)).rows;
    assert.deepEqual(await admissions(), []);
    const completionsBefore = (await identity.query(
      'SELECT objective_id FROM workshop_platform.completions ORDER BY objective_id')).rows;
    const creditCounts=async()=>{
      const counts=[];
      for(const relation of ['assessment_judgments','assessment_contributions',
        'assessment_completions','active_assessment_contributions'])
        counts.push([relation,(await identity.query(`SELECT count(*)::int n FROM secureshop_auth.${relation}`)).rows[0].n]);
      return counts;
    };
    const creditBefore=await creditCounts();
    const executorPosts = () => executorWire.filter(row => row.method === 'POST'
      && row.path === '/secureshop/system/diagnostic');
    assert.equal(executorPosts().length, 0);
    const originalMessage = 'Please prepare a System diagnostic that displays the hostname of the isolated System service. Use the exact command template /usr/bin/uname and arguments -n. Do not run it yet; I will review and confirm.';
    const prepare = async message => {
      const savedBefore=savedProposals.length;
      await frame.waitForSelector('[data-testid="admin-role-composer-slot"] textarea');
      await frame.type('[data-testid="admin-role-composer-slot"] textarea', message);
      await clickButton(frame, 'Send to admin assistant');
      const deadline=Date.now()+120000;
      while(savedProposals.length===savedBefore&&Date.now()<deadline)await sleep(50);
      assert.ok(savedProposals.length>savedBefore,
        'new protected turn must publish its own saved proposal before the card');
      await frame.waitForFunction(()=>[...document.querySelectorAll(
        'section[aria-label="Admin System diagnostic confirmation"] button')]
        .some(button=>button.textContent.trim()==='Confirm System diagnostic'&&!button.disabled),
      {timeout:120000});
      const card = await frame.$eval('section[aria-label="Admin System diagnostic confirmation"]', node => ({
        command: node.textContent, html: node.outerHTML.slice(0, 2048),
        enabled: [...node.querySelectorAll('button')].some(button =>
          button.textContent.trim() === 'Confirm System diagnostic' && !button.disabled),
      }));
      assert.equal(card.enabled, true, JSON.stringify(card));
      return card;
    };
    stage = 'vulnerable-model-prepare';
    const firstCard = await prepare(originalMessage);
    assert.match(firstCard.command, /\/usr\/bin\/uname/);
    assert.match(firstCard.command, /-n/);
    assert.deepEqual(await admissions(), []); assert.equal(executorPosts().length, 0);
    status.renderedProposalNoEffect = true;
    const selectedCalls = () => modelCalls.filter(call => call.method === 'chat'
      && call.stopReason === 'tool_use' && call.offeredTools.includes('admin.system_diagnostic_prepare')
      && call.tools.some(tool => tool.name === 'admin.system_diagnostic_prepare'
        && tool.args?.cmd_template === '/usr/bin/uname' && tool.args?.args === '-n'));
    assert.equal(selectedCalls().length, 1);
    assert.ok(modelCalls.some(call => call.stopReason === 'end_turn'));
    status.actualModelDiagnosticPrepared = true;
    stage = 'vulnerable-physical-confirm';
    await clickButton(frame, 'Confirm System diagnostic');
    await frame.waitForFunction(() => [...document.querySelectorAll('button')]
      .some(button => button.textContent.trim() === 'Check saved System diagnostic' && !button.disabled),
    { timeout: 120000 });
    assert.equal(confirmPosts, 1); assert.equal(lostAck, 1);
    assert.equal(executorPosts().length, 1);
    assert.ok(savedProposals.length >= 1 && savedProposals.length <= 4);
    const original = savedProposals.find(value => value?.systemDiagnosticProposal?.action === 'system_diagnostic');
    assert.ok(original && original.status === 'completed' && original.replayed === true
      && original.stopReason === 'end_turn');
    const proposal = original.systemDiagnosticProposal;
    assert.deepEqual(Object.keys(proposal).sort(), ['version','proposalId','action','cmd_template','args',
      'scopeKey','diagnosticCapability','sourceSnapshotSha256','modeCapability',
      'requestSha256','proposalSha256'].sort());
    assert.equal(proposal.cmd_template, '/usr/bin/uname'); assert.equal(proposal.args, '-n');
    assert.equal(proposal.modeCapability.effectiveMode, 'vuln');
    const requestDigest = require('../../sidecars/sandbox-runner/owned-system/diagnostic-contract')
      .diagnosticRequestDigest({ operationId: proposal.proposalId,
        cmd_template: proposal.cmd_template, args: proposal.args });
    assert.equal(proposal.requestSha256, requestDigest);
    const { proposalSha256, ...publicBody } = proposal;
    assert.equal(proposalSha256,
      require('../../server/services/mcp/protocolContext').canonicalDigest(publicBody));
    const turn=(await agents.query(`SELECT status,request_hash,result_json FROM
      secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
    [original.sessionId,original.requestId])).rows;
    assert.equal(turn.length,1);assert.equal(turn[0].status,'completed');
    const meta=turn[0].result_json?.taskMetadata?.roleChat;
    assert.equal(meta?.systemDiagnosticProposal?.proposalId,proposal.proposalId);
    const source=meta?.systemDiagnosticOrigin;
    assert.equal(source?.version,1);assert.match(source.runId,/^[0-9a-f-]{36}$/);
    assert.equal(JSON.parse(source.sourceEnvelope).message,originalMessage);
    assert.ok(Array.isArray(source.traceEventIds)&&source.traceEventIds.length>=4);
    const traced=(await agents.query(`SELECT event_id,kind,agent_ns,tool_name,params_json,result_json,provider
      FROM secureshop_agents.agent_trace WHERE session_id=$1 AND event_id=ANY($2::text[])`,
    [original.sessionId,source.traceEventIds])).rows;
    assert.equal(traced.length,source.traceEventIds.length);
    const byEvent=new Map(traced.map(row=>[row.event_id,row]));
    const ordered=source.traceEventIds.map(id=>byEvent.get(id));
    assert.ok(ordered.every(Boolean));
    const decisions=ordered.filter(row=>row.kind==='model_decision');
    const toolCalls=ordered.filter(row=>row.kind==='local_tool_call'
      &&row.agent_ns==='admin'&&row.tool_name==='system_diagnostic_prepare');
    const toolResults=ordered.filter(row=>row.kind==='local_tool_result'
      &&row.agent_ns==='admin'&&row.tool_name==='system_diagnostic_prepare');
    assert.equal(toolCalls.length,1);assert.equal(toolResults.length,1);
    assert.deepEqual(JSON.parse(toolCalls[0].params_json),
      {cmd_template:proposal.cmd_template,args:proposal.args});
    assert.ok(decisions.some(row=>JSON.parse(row.params_json)?.toolCalls?.some(call=>
      call.name==='admin.system_diagnostic_prepare'&&call.args?.cmd_template===proposal.cmd_template
      &&call.args?.args===proposal.args)));
    assert.ok(decisions.some(row=>JSON.parse(row.result_json)?.decision==='final'));
    const rows = await admissions();
    assert.equal(rows.length, 1); assert.equal(rows[0].operation_id, proposal.proposalId);
    assert.equal(rows[0].request_sha256.toString('hex'), requestDigest);
    assert.deepEqual(rows[0].request_json, { operationId: proposal.proposalId,
      cmd_template: proposal.cmd_template, args: proposal.args });
    const completed = (await agents.query(`SELECT state,receipt_json,receipt_sha256 FROM
      secureshop_agents.bound_system_diagnostic_outcomes WHERE operation_id=$1`,
    [proposal.proposalId])).rows;
    assert.equal(completed.length, 1); assert.equal(completed[0].state, 'completed');
    assert.equal(completed[0].receipt_json.result.operationId, proposal.proposalId);
    assert.equal(completed[0].receipt_json.result.requestSha256, proposal.requestSha256);
    assert.equal(completed[0].receipt_json.result.command, '/usr/bin/uname -n');
    assert.equal(completed[0].receipt_json.result.executed, true);
    assert.equal(completed[0].receipt_json.result.exitCode, 0);
    assert.equal(Buffer.from(completed[0].receipt_json.result.stdout, 'base64').toString('utf8'),
      `system-diag-${rows[0].target_id.replaceAll('-', '')}\n`);
    assert.equal(completed[0].receipt_sha256.toString('hex'),
      require('../../server/services/mcp/protocolContext').canonicalDigest(completed[0].receipt_json));
    status.ownedDiagnosticReceipt = true; status.physicalVulnerableConfirm = true;
    const actorAtConfirm = actualModelRequests.length;
    stage = 'saved-get-reload';
    await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
    await frame.waitForSelector('[data-testid="admin-role-assistant"]');
    await clickButton(frame, 'Check saved System diagnostic');
    await frame.waitForFunction(text => [...document.querySelectorAll('pre')]
      .some(node => node.textContent === text), { timeout: 120000 },
    `system-diag-${rows[0].target_id.replaceAll('-', '')}\n`);
    assert.equal(confirmPosts, 1); assert.equal(executorPosts().length, 1);
    assert.equal(actualModelRequests.length, actorAtConfirm);
    status.lostAckExactGetRecovery = true; status.noDuplicateDiagnostic = true;
    await page.screenshot({ path: path.join(path.dirname(evidencePath),
      'admin-system-diagnostic-chat-recovered.png') });
    const actor = bootstraps[0];
    const actorScope = await composition.launches.resolveCapability(actor.launch);
    assert.notEqual(siblingRow.owner_id,actorScope.platformOwnerId);
    const actorPersona = await composition.personaAuth.authenticateBoundToken({
      scope: actorScope, token: actor.authorization.slice('Bearer '.length) });
    const proveOriginal=async(saved,humanMessage)=>{
      const record=(await agents.query(`SELECT status,request_hash,result_json FROM
        secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
      [saved.sessionId,saved.requestId])).rows;
      assert.equal(record.length,1);assert.equal(record[0].status,'completed');
      const metadata=record[0].result_json?.taskMetadata?.roleChat;
      const privateProposal=metadata?.systemDiagnosticProposal;
      const origin=metadata?.systemDiagnosticOrigin;
      assert.equal(privateProposal?.proposalId,saved.systemDiagnosticProposal?.proposalId);
      assert.equal(JSON.parse(origin?.sourceEnvelope||'null')?.message,humanMessage);
      const scene=await scenes.readRetained(actorScope);
      const expected=require('../../server/database/postgres/secureshopRoleChatBindingRepository')
        .capture({sessionId:saved.sessionId,requestId:saved.requestId,scope:actorScope,
          persona:{id:actorPersona.user.id,role:'admin'},
          personaSession:{sessionId:actorPersona.sessionId,
            authorityVersion:actorPersona.authorityVersion},target:scene,
          message:origin.sourceEnvelope});
      const binding=(await agents.query(`SELECT * FROM secureshop_agents.role_chat_turn_bindings
        WHERE session_id=$1 AND request_id=$2`,[saved.sessionId,saved.requestId])).rows;
      assert.equal(binding.length,1);
      for(const [name,value] of Object.entries(expected)){
        const column=name.replace(/[A-Z]/g,c=>`_${c.toLowerCase()}`);
        assert.equal(String(binding[0][column]),String(value),`bound original ${name}`);
      }
      assert.equal(record[0].request_hash,expected.requestHash);
      const run=(await identity.query(`SELECT owner_key,generation,status FROM graph_runtime.runs
        WHERE run_id=$1`,[origin.runId])).rows;
      assert.equal(run.length,1);assert.equal(run[0].status,'completed');
      assert.equal(run[0].owner_key,JSON.stringify(['SecureShopBoundConversation',saved.sessionId]));
      const trace=(await agents.query(`SELECT event_id,step,kind,agent_ns,tool_name,
        params_json,result_json FROM secureshop_agents.agent_trace
        WHERE session_id=$1 AND event_id=ANY($2::text[])`,
      [saved.sessionId,origin.traceEventIds])).rows;
      assert.equal(trace.length,origin.traceEventIds.length);
      const byId=new Map(trace.map(row=>[row.event_id,row]));
      const ordered=origin.traceEventIds.map(id=>byId.get(id));
      assert.ok(ordered.every(Boolean));
      const parse=(row,key)=>JSON.parse(row?.[key]||'null');
      const decision=ordered.filter(row=>row.kind==='model_decision'
        &&Number(row.step)===privateProposal.origin.step);
      const call=ordered.filter(row=>row.kind==='local_tool_call'
        &&row.agent_ns==='admin'&&row.tool_name==='system_diagnostic_prepare'
        &&Number(row.step)===privateProposal.origin.step);
      const result=ordered.filter(row=>row.kind==='local_tool_result'
        &&row.agent_ns==='admin'&&row.tool_name==='system_diagnostic_prepare'
        &&Number(row.step)===privateProposal.origin.step);
      const terminal=ordered.filter(row=>row.kind==='model_decision'
        &&parse(row,'result_json')?.decision==='final');
      assert.equal(decision.length,1);assert.equal(call.length,1);
      assert.equal(result.length,1);assert.equal(terminal.length,1);
      assert.deepEqual(parse(decision[0],'params_json'),{decision:'tool_use',toolCalls:[{
        id:privateProposal.origin.callId,name:'admin.system_diagnostic_prepare',
        args:{cmd_template:privateProposal.cmd_template,args:privateProposal.args}}]});
      assert.deepEqual(parse(call[0],'params_json'),
        {cmd_template:privateProposal.cmd_template,args:privateProposal.args});
      assert.deepEqual(parse(result[0],'result_json'),saved.hops.at(-1).result);
      assert.equal(parse(terminal[0],'result_json')?.text,saved.text);
      assert.ok(ordered.indexOf(decision[0])<ordered.indexOf(call[0])
        &&ordered.indexOf(call[0])<ordered.indexOf(result[0])
        &&ordered.indexOf(result[0])<ordered.indexOf(terminal[0]));
    };
    await proveOriginal(original,originalMessage);
    const originalPath = `/agents/admin/assistant/operations/${original.sessionId}/${original.requestId}`;
    const savedPath = `/agents/admin/assistant/system/diagnostic/confirm/${original.sessionId}/${original.requestId}/${proposal.proposalId}`;
    const ownerRequests = requestLog.filter(entry => entry.path.startsWith('/agents/admin/assistant'));
    assert.equal(ownerRequests.filter(entry => entry.method === 'POST'
      && entry.path === '/agents/admin/assistant/chat').length, 1);
    assert.ok(ownerRequests.some(entry => entry.method === 'GET'
      && entry.path === originalPath && entry.status === 200));
    assert.ok(ownerRequests.some(entry => entry.method === 'GET'
      && entry.path === savedPath && entry.status === 200));
    for (const entry of ownerRequests) {
      assert.match(entry.launch || '', /^\S+$/);
      assert.match(entry.authorization || '', /^Bearer \S+$/);
      const scope = await composition.launches.resolveCapability(entry.launch);
      assert.deepEqual(Object.fromEntries(['launchId','scenarioId','generation',
        'platformOwnerId','platformSessionId'].map(key => [key,scope[key]])),
      Object.fromEntries(['launchId','scenarioId','generation',
        'platformOwnerId','platformSessionId'].map(key => [key,actorScope[key]])));
      const persona = await composition.personaAuth.authenticateBoundToken({
        scope, token: entry.authorization.slice('Bearer '.length) });
      assert.deepEqual({id:persona.user.id,role:persona.user.role,sessionId:persona.sessionId,
        authorityVersion:persona.authorityVersion},
      {id:actorPersona.user.id,role:actorPersona.user.role,
        sessionId:actorPersona.sessionId,authorityVersion:actorPersona.authorityVersion});
    }
    stage = 'fixed-mode-prepare';
    await clickButton(frame, 'Close saved diagnostic');
    const modePost = page.waitForResponse(response => {
      const url = new URL(response.url());
      return url.origin === origin && url.pathname === '/api/secureshop/auth/mode'
        && response.request().method() === 'POST';
    }, {timeout: 30000});
    await clickButton(page, 'Shop settings');
    await page.waitForSelector('aside[aria-label="Shop settings"]');
    await page.waitForFunction(()=>document.querySelector(
      '[role="group"][aria-label="Shop feature mode"]')?.textContent
      .includes('Current: Vulnerable'),{timeout:30000});
    const controls = await page.$$('[role="group"][aria-label="Shop feature mode"] button');
    const fixed = [];
    for (const control of controls) if (await control.evaluate(node =>
      node.textContent.trim() === 'Fixed' && !node.disabled)) fixed.push(control);
    assert.equal(fixed.length, 1); await fixed[0].click();
    assert.equal((await modePost).status(), 200);
    await page.waitForFunction(() => document.querySelector(
      '[role="group"][aria-label="Shop feature mode"]')?.textContent.includes('Current: Fixed'));
    await clickButton(page, 'Shop settings');
    await page.waitForSelector('aside[aria-label="Shop settings"]', {hidden:true});
    frame = await frameFor(page);
    const secondMessage = 'Please prepare another System diagnostic for the isolated System hostname. Propose command template /usr/bin/uname with arguments -n. I will inspect it before confirming.';
    const secondCard = await prepare(secondMessage);
    assert.match(secondCard.command, /\/usr\/bin\/uname/);
    assert.equal(selectedCalls().length, 2,
      'fixed preparation must remain a genuine model-selected diagnostic tool');
    const second=savedProposals.at(-1);
    assert.ok(second&&(second.sessionId!==original.sessionId
      ||second.requestId!==original.requestId));
    assert.notEqual(second.systemDiagnosticProposal?.proposalId,proposal.proposalId);
    assert.equal(second?.systemDiagnosticProposal?.modeCapability?.effectiveMode,'fixed');
    assert.equal(second?.systemDiagnosticProposal?.cmd_template,'/usr/bin/uname');
    assert.equal(second?.systemDiagnosticProposal?.args,'-n');
    await proveOriginal(second,secondMessage);
    assert.deepEqual((await admissions()).map(row => row.operation_id), [proposal.proposalId]);
    assert.equal(executorPosts().length, 1);
    stage = 'fixed-physical-denial';
    await clickButton(frame, 'Confirm System diagnostic');
    await frame.waitForFunction(() => [...document.querySelectorAll('section')]
      .some(node => node.getAttribute('aria-label') === 'Admin System diagnostic confirmation'
        && node.textContent.includes('Fixed mode denied this diagnostic before execution.')),
    {timeout: 30000});
    assert.equal(confirmPosts, 2);
    assert.equal(confirmOutcomes.at(-1)?.status, 403);
    assert.equal(confirmOutcomes.at(-1)?.code, 'SYSTEM_DIAGNOSTIC_FIXED_DENIED');
    assert.equal(executorPosts().length, 1);
    assert.deepEqual((await admissions()).map(row => row.operation_id), [proposal.proposalId]);
    assert.equal((await agents.query(`SELECT count(*)::int n FROM
      secureshop_agents.bound_system_diagnostic_outcomes`)).rows[0].n, 1);
    status.physicalFixedDenial = true;
    stage = 'sibling-denial';
    const siblingRead = await fetch(`${origin}/api/secureshop${savedPath}`, {headers:{
      'x-dvaia-secureshop-launch': siblingBase.bearer,
      authorization: `Bearer ${siblingBase.persona.token}`}});
    assert.equal(siblingRead.status, 401);
    assert.equal(executorPosts().length,1);status.siblingOperationDenied = true;
    stage = 'reset-denial';
    await composition.launches.beginReset({launchId:actorScope.launchId,
      platformSessionId:actorScope.platformSessionId,
      platformOwnerId:actorScope.platformOwnerId,
      expectedGeneration:actorScope.generation,
      idempotencyKey:`diagnostic-chat-reset-${randomUUID()}`});
    const retired = await fetch(`${origin}/api/secureshop${savedPath}`, {headers:{
      'x-dvaia-secureshop-launch':actor.launch,authorization:actor.authorization}});
    assert.equal(retired.status, 401);
    assert.equal(executorPosts().length,1);status.resetSessionDenied = true;
    assert.deepEqual((await identity.query(
      'SELECT objective_id FROM workshop_platform.completions ORDER BY objective_id')).rows,
    completionsBefore);
    assert.deepEqual(await creditCounts(),creditBefore);
    assert.equal(status.judgeCalls, 0); status.noObjectiveCredit = true;
    assert.deepEqual(pageErrors, []);
    status.executorCalls = executorPosts().length;
    status.actorCalls = actualModelRequests.length;
    status.roleTurns = requestLog.filter(entry => entry.method === 'POST'
      && entry.path === '/agents/admin/assistant/chat').length;
    status.passed = true;
  } catch (error) {
    failure = error;
    t.diagnostic(JSON.stringify({stage,url:page?.url()||null,
      visible:page?await visibleSetupState(page):[],
      pageErrors:pageErrors.slice(0,16),requestFailures:requestFailures.slice(0,16),
      confirmPosts,lostAck,confirmOutcomes:confirmOutcomes.slice(0,4),
      executorWire:executorWire.slice(0,8)}));
    if (page) await page.screenshot({path:path.join(path.dirname(evidencePath),
      'admin-system-diagnostic-chat-failure.png')}).catch(()=>{});
  } finally {
    for (const close of [()=>browser?.close(),()=>closeServer(server),
      ()=>reset?.closeFeatureTransports?.(),()=>reset?.auditLedger?.close?.(),
      ()=>profile&&fs.rm(profile,{recursive:true,force:true}),()=>leasePool.end(),
      ...Object.values(pools).map(pool=>()=>pool.end())]) {
      try { await close(); } catch(error) {cleanupErrors.push(error);}
    }
    status.fixtureCleaned=cleanupErrors.length===0;
    status.executorCalls=executorWire.filter(row=>row.method==='POST'
      && row.path==='/secureshop/system/diagnostic').length;
    status.actorCalls=actualModelRequests.length;
    status.roleTurns=requestLog.filter(entry=>entry.method==='POST'
      && entry.path==='/agents/admin/assistant/chat').length;
    status.errors=failure?[{name:failure.name||'Error',code:failure.code||null}]:[];
    const wirePath=path.join(path.dirname(evidencePath),'admin-system-diagnostic-chat-wire.json');
    const wire={version:1,model:MODEL,
      modelDigest:process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_CHAT_MODEL_DIGEST,
      calls:modelWire,executor:executorWire,requests:requestLog.map(entry=>({
        method:entry.method,path:entry.path,status:entry.status??null,
        ...(entry.body===undefined?{}:{bodySha256:createHash('sha256')
          .update(JSON.stringify(entry.body)).digest('hex')}),
      })),pageErrors,requestFailures};
    const wireBytes=JSON.stringify(wire,null,2);
    if(Buffer.byteLength(wireBytes,'utf8')>16*1024*1024)
      cleanupErrors.push(new Error('Private diagnostic wire exceeds bound'));
    else try { await fs.writeFile(wirePath,wireBytes,
      {flag:'wx',mode:0o600}); } catch(error) {cleanupErrors.push(error);}
    try { await fs.writeFile(evidencePath,JSON.stringify(status,null,2),
      {flag:'wx',mode:0o600}); } catch(error) {cleanupErrors.push(error);}
  }
  if (cleanupErrors.length) throw new AggregateError(cleanupErrors,
    'Diagnostic chat fixture cleanup failed');
  if (failure) throw failure;
  assertPrivateReceipt({...status,fixtureCleaned:true,errors:[]});
});

module.exports={assertPrivateReceipt,FLAGS,SCOPE,diagnosticDependencies};
