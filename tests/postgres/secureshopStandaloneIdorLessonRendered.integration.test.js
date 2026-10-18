'use strict';

// This is a separate actual-model/browser qualification. The controlled
// migration test does not prove a selected model action or learner-visible UI.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { IDOR_BROWSER_SCOPE, IDOR_BROWSER_FLAGS, assertCardsMatchBirth,
  assertSavedLesson, assertOriginalLessonTurn, assertOriginalActorWire,
  assertIdorBrowserReceipt } =
  require('../fixtures/secureshopIdorLessonRenderedQualification');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_CUSTOMER_IDOR_LESSON_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const OBJECTIVES = Object.freeze({ cart_remove: 'ss_idor_cart_delete',
  order_status: 'ss_idor_order_status_disclosure' });
const PATH = '/api/secureshop/agents/customer/idor';
const V10_ONLY_FLAG = 'SECURESHOP_CUSTOMER_IDOR_CART_V10_ONLY';
const v10OnlyValue = process.env[V10_ONLY_FLAG];
assert.ok(v10OnlyValue === undefined || v10OnlyValue === '' || v10OnlyValue === '1',
  `${V10_ONLY_FLAG} must be unset or exactly 1`);
const V10_ONLY = v10OnlyValue === '1';
const ACTIVE_ACTIONS = Object.freeze(V10_ONLY ? ['cart_remove'] : Object.keys(OBJECTIVES));
const ACTIVE_OBJECTIVES = Object.freeze(ACTIVE_ACTIONS.map(action => OBJECTIVES[action]));
const V10_BROWSER_SCOPE = 'current-main rendered customer cart IDOR lesson with fixed cart denial, genuine model-selected reserved cart removal, canonical Judge credit, and protected recovery';
const V10_BROWSER_FLAGS = Object.freeze([
  'passed', 'isolatedStores', 'canonicalObjectivesEnabled',
  'renderedFixedCartDenied', 'fixedNoEffectOrCredit', 'modelSelectedCartId',
  'renderedCartDeletion', 'cartJudgeCredit', 'savedReloadGetOnly',
  'exactReplayNoRerun', 'siblingPrivate', 'resetFenced',
  'immutableHistoryRetained', 'fixtureCleaned',
]);
const QUALIFICATION_SCOPE = V10_ONLY ? V10_BROWSER_SCOPE : IDOR_BROWSER_SCOPE;
const QUALIFICATION_FLAGS = V10_ONLY ? V10_BROWSER_FLAGS : IDOR_BROWSER_FLAGS;
const TEST_TITLE = V10_ONLY
  ? 'rendered customer cart IDOR lesson proves fixed denial, genuine reserved-ID removal, and protected recovery'
  : 'rendered customer IDOR lesson proves fixed-first denials and two genuine reserved-ID effects';
const EXPECTED_TURNS = ACTIVE_ACTIONS.length * 2;
const EXPECTED_CREDIT = ACTIVE_ACTIONS.length;
const ENABLED = process.env.SECURESHOP_CUSTOMER_IDOR_LESSON_BROWSER_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && Object.keys(STORES).every(store => ['RUNTIME', 'MIGRATION']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

function storeUrls() {
  const urls = {}; let nonce, port;
  for (const [store, name] of Object.entries(STORES)) {
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const url = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
      assert.equal(url.protocol, 'postgresql:');
      assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.username, `dvaia_${name}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      const match = /^\/dvaia_test_agent_host_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(url.pathname);
      assert.ok(match && match[2] === name, `${store} must be an owned disposable store`);
      assert.ok(Number(url.port) > 0 && Number(url.port) <= 65535);
      nonce ??= match[1]; port ??= url.port;
      assert.equal(match[1], nonce); assert.equal(url.port, port);
      urls[`${store}_${role}`] = url.href;
    }
    assert.equal(new URL(urls[`${store}_RUNTIME`]).pathname,
      new URL(urls[`${store}_MIGRATION`]).pathname);
  }
  assert.equal(new Set(Object.keys(STORES).map(store =>
    new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return urls;
}
async function listen(app) {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) =>
    server.close(error => error ? reject(error) : resolve()));
}
async function frameFor(page) {
  const until = Date.now() + 20000;
  while (Date.now() < until) {
    const element = await page.$('iframe[title="SecureShop"]');
    const frame = element && await element.contentFrame().catch(() => null);
    if (frame && !frame.detached) return frame;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw Error('Owned customer shop frame did not mount');
}
async function physicalButton(frame, label, root = 'button') {
  const handle = await frame.waitForFunction(({ label, root }) => {
    const matches = [...document.querySelectorAll(root)]
      .filter(button => button.textContent.trim() === label && !button.disabled
        && button.getClientRects().length && getComputedStyle(button).visibility !== 'hidden');
    return matches.length === 1 ? matches[0] : null;
  }, { timeout: 20000 }, { label, root });
  const element = handle.asElement(); assert.ok(element);
  await element.evaluate(node => node.scrollIntoView({ block: 'center' }));
  await element.click();
}
function waitResponse(page, method, pathname, timeout = 90000) {
  return page.waitForResponse(response => response.request().method() === method
    && new URL(response.url()).pathname === pathname, { timeout });
}
async function snapshot(pool, table, scope, objective) {
  return (await pool.query(`SELECT * FROM secureshop_auth.${table}
    WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,
  [scope.tenantId, scope.principalId, objective])).rows;
}
function headersFrom(request) {
  const headers = request.headers();
  assert.match(headers.authorization || '', /^Bearer [A-Za-z0-9_.-]+$/);
  assert.match(headers['x-dvaia-secureshop-launch'] || '', /^[A-Za-z0-9_-]{43}$/);
  return { authorization: headers.authorization,
    'x-dvaia-secureshop-launch': headers['x-dvaia-secureshop-launch'] };
}
async function protectedGet(origin, pathname, headers, expectedStatus = 200) {
  const response = await fetch(`${origin}${pathname}`, { headers,
    redirect: 'error', signal: AbortSignal.timeout(10000) });
  assert.equal(response.status, expectedStatus);
  const body = await response.json();
  return body;
}

test(TEST_TITLE,
  { skip: !ENABLED, timeout: 360000 }, async t => {
    assert.equal(process.cwd(), ROOT, 'current checkout required');
    assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/'), ROOT);
    const evidencePath = process.env.SECURESHOP_CUSTOMER_IDOR_LESSON_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidencePath));
    assert.ok(!path.resolve(evidencePath).startsWith(`${ROOT}${path.sep}`));
    const build = path.resolve(process.env.SECURESHOP_CUSTOMER_IDOR_LESSON_BUILD || '/');
    assert.equal(build, path.join(ROOT, 'client/build'));
    await fs.access(path.join(build, 'index.html'));
    await fs.access(path.join(build, 'secureshop-frame.html'));
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(executablePath)); await fs.access(executablePath);
    assert.equal(process.env.LAB_MODE, 'vuln');
    assert.equal(process.env.JUDGE_PROVIDER || 'ollama', 'ollama');
    assert.equal(process.env.JUDGE_MODEL || MODEL, MODEL);
    const modelURL = new URL(process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434');
    assert.equal(modelURL.origin, 'http://127.0.0.1:11434');
    const tags = await (await fetch(`${modelURL.origin}/api/tags`, {
      signal: AbortSignal.timeout(5000) })).json();
    assert.equal(tags.models.find(row => row.name === MODEL)?.digest, MODEL_DIGEST);
    const urls = storeUrls();
    const pools = Object.fromEntries(Object.entries(urls).map(([key, connectionString]) =>
      [key, new Pool({ connectionString, max: key.endsWith('RUNTIME') ? 12 : 3,
        connectionTimeoutMillis: 1500, statement_timeout: 8000 })]));
    const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4 });
    const status = Object.fromEntries(QUALIFICATION_FLAGS.map(key => [key, false]));
    Object.assign(status, { scope: QUALIFICATION_SCOPE, actorCalls: 0, judgeCalls: 0,
      roleTurns: 0, genuineCredit: 0, errors: [] });
    const wirePath = path.join(path.dirname(evidencePath),
      V10_ONLY ? 'idor-cart-v10-original-wire.json' : 'idor-lesson-original-wire.json');
    let reset, composition, transport, browser, page, profile, server;
    let browserDiagnostic = null, browserScreenshot = null, stage = 'setup';
    let failure, originalModelURL = process.env.OLLAMA_BASE_URL;
    const cleanupErrors = [], requests = [], pageErrors = [], judgePackets = [], judgeResults = [];
    const actorSpans = [];
    let judgeRuns = 0, actorRuns = 0;
    const saveWire = () => fsSync.writeFileSync(wirePath, JSON.stringify({
      model: MODEL, digest: MODEL_DIGEST, calls: transport?.calls || [],
      judgePackets, requests, pageErrors, browserDiagnostic, browserScreenshot }, null, 2), { mode: 0o600 });
    try {
      for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
        ['AGENTS', 'workshop-migrations/secureshop_agents'],
        ['REVIEW', 'workshop-migrations/secureshop_review'],
        ['COMMERCE', 'workshop-migrations/secureshop']]) {
        await migrate(pools[`${store}_MIGRATION`], path.join(ROOT, 'db/postgres', directory));
      }
      await require('../../server/database/postgres/workshopPlatformSeed')
        .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopAssessmentSeed')
        .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopStandaloneSeed')
        .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
      const seed = await pools.COMMERCE_MIGRATION.connect();
      try { await seed.query('BEGIN');
        await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seed);
        await seed.query('COMMIT');
      } catch (error) { await seed.query('ROLLBACK'); throw error; }
      finally { seed.release(); }
      status.isolatedStores = true;
      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
      const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
      const auth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const suffix = randomUUID().slice(0, 8), username = `idor_browser_${suffix}`;
      const password = 'disposable-id-or-browser-only';
      const owner = await auth.register({ username, password,
        email: `${username}@owned.invalid`, role: 'customer' });
      const sibling = await auth.register({ username: `idor_peer_${suffix}`, password,
        email: `idor-peer-${suffix}@owned.invalid`, role: 'customer' });
      const peerMerchant = await auth.register({ username: `idor_merchant_${suffix}`, password,
        email: `idor-merchant-${suffix}@owned.invalid`, role: 'merchant' });
      const peerTenantId = randomUUID(), peerSlug = `idor_peer_tenant_${suffix}`;
      const ownerTenant = await auth.establishTenantContext(owner.context);
      const peerTenant = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO
        secureshop_auth.tenants (tenant_id,slug) VALUES($1,$2) RETURNING owner_id`,
      [peerTenantId, peerSlug])).rows[0];
      assert.notEqual(peerTenant.owner_id, ownerTenant.ownerId);
      for (const [registration, role] of [[sibling, 'customer'], [peerMerchant, 'merchant']]) {
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,$4)`,
        [peerTenantId, registration.context.principalId,
          registration.context.shopUserId, role]);
      }
      await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants
        SET seed_merchant_id=$2 WHERE tenant_id=$1`,
      [peerTenantId, peerMerchant.context.shopUserId]);
      const siblingAuth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity,
              executionTenantSlug: peerSlug }) });
      const siblingLogin = await siblingAuth.login({ username: sibling.context.username,
        password });
      const siblingPrincipal = await siblingAuth.establishTenantContext(siblingLogin.context);
      assert.equal(siblingPrincipal.tenantId, peerTenantId);
      assert.equal(siblingPrincipal.ownerId, peerTenant.owner_id);
      const administrator = await auth.login({ username: 'student_admin', password: 'student123' });
      const assessmentCatalog = require('../../server/services/secureshopAssessmentCatalog')
        .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
      for (const objectiveId of ACTIVE_OBJECTIVES) {
        const objective = (await assessmentCatalog.list(administrator.context)).objectives
          .find(row => row.objectiveId === objectiveId);
        assert.equal(objective?.qualification, 'native-model');
        assert.equal(objective.enabled, false);
        assert.equal((await assessmentCatalog.set(administrator.context,
          { objectiveId, enabled: true, expectedRevision: objective.revision })).enabled, true);
      }
      status.canonicalObjectivesEnabled = true;
      const progress = require('../../server/database/postgres/workshopProgressRepository')
        .createWorkshopProgressRepository(identity);
      const audit = require('../../server/services/secureshopBoundAuditComposition')
        .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
          includeRunArtifacts: true });
      reset = require('../../server/services/secureshopCleanupComposition')
        .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, leasePool, audit });
      transport = await require('./secureshopMailActualTransport')
        .createMailActualTransport({ maxHttpCalls: 14, allowMetadata: true,
          record: () => saveWire() });
      process.env.OLLAMA_BASE_URL = transport.judgeUrl;
      const configuredJudge = require('../../server/agent-runtime/objectiveJudge')
        .createObjectiveJudge({ observeExecutionTranscript: packet => {
          judgePackets.push(packet); saveWire();
        } });
      const judge = async input => {
        assert.ok(++judgeRuns <= EXPECTED_CREDIT, 'one bounded genuine Judge evaluation per active objective');
        const result = await configuredJudge(input);
        judgeResults.push(result);
        status.judgeCalls = transport.calls.filter(call => call.kind === 'judge').length;
        assert.ok(status.judgeCalls <= (V10_ONLY ? 2 : 4), 'bounded genuine Judge HTTP calls');
        return result;
      };
      require('../../server/agent-runtime/judgeProviderConfiguration')
        .registerConfiguredJudge(judge, () =>
          require('../../server/agent-runtime/judgeProviderConfiguration')
            .readJudgeProviderConfig(configuredJudge));
      const grading = await require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
          progress, resetComposition: reset, judge,
          expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository')
          .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
        reviewPool: review, launches: reset.launches });
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identity);
      const modeAuthority = reset.modeAuthority;
      const provider = new (require('../../server/services/secureshop/providers/ollamaProvider')
        .OllamaProvider)({ baseUrl: transport.actorUrl, model: MODEL });
      for (const method of ['chat', 'finalResponse']) {
        const invoke = provider[method].bind(provider);
        provider[method] = async input => {
          assert.ok(++actorRuns <= (V10_ONLY ? 5 : 10), 'bounded genuine lesson turns');
          const start = transport.calls.length;
          const result = await invoke({ ...input, signal: AbortSignal.any([
            AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
          assert.equal(result.provider, 'ollama'); assert.equal(result.model, MODEL);
          assert.equal(result.mocked, false); assert.notEqual(result.fallback, true);
          const wires = transport.calls.slice(start);
          assert.ok(wires.length >= 1 && wires.every(wire => wire.kind === 'actor'));
          actorSpans.push({ turn: status.roleTurns, method, result, wires });
          status.actorCalls = transport.calls.filter(call => call.kind === 'actor').length;
          assert.ok(status.actorCalls <= (V10_ONLY ? 5 : 10), 'bounded genuine actor HTTP calls');
          return result;
        };
      }
      const couponDependencies = await require('../../server/services/secureshopCouponProduction')
        .prepareCommerceDependencies({ modeAuthority, reviewPool: review,
          launches: reset.launches, mode: 'vuln' });
      await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness')
        .assertBoundToolPolicyReadiness(agents);
      const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
        .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
          audit: audit.agents });
      composition = require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: reset,
          gradingBootstrap: grading, scenes, modeAuthority, couponDependencies,
          personaInboxFeature: require('../../server/services/secureshopPersonaInboxActivationPolicy')
            .activationPolicy(process.env).requested, toolPolicyRepository,
          fixtures: [], requiredObjectives: ACTIVE_OBJECTIVES, judge,
          jwtSecret: 'owned-idor-browser-persona-secret-at-least-32-bytes',
          agentRuntime: { provider } });
      await composition.repositories.personas.ensureTemplates();
      assert.equal(composition.idorLesson?.ready, true);
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });
      const standaloneMode = require('../../server/services/secureshopStandaloneMode')
        .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
      const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
        .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
          reviewPool: review, commercePool: commerce });
      const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
        .createRegisteredAdminResetEnvelope({ activeKeyId: 'idor-owned',
          keys: new Map([['idor-owned', require('node:crypto').randomBytes(32)]]) });
      const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
        .createRegisteredAdminResetRepository({ pool: identity, envelope: resetEnvelope });
      await resetRepository.checkReadiness();
      const standaloneAuthority = { service: auth, bootstrap, mode: standaloneMode,
        reset: require('../../server/services/secureshopStandaloneReset')
          .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
            launches: composition.launches, scenes,
            resetCoordinator: reset.launchResetCoordinator,
            preflight: reset.sceneResetPreflight }),
        registeredAdminReset: require('../../server/services/secureshopRegisteredAdminReset')
          .createRegisteredAdminResetService({ repository: resetRepository }),
        assessmentObjectives: assessmentCatalog,
        assessmentRecovery: require('../../server/services/secureshopAssessmentRecovery')
          .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth,
            bootstrap, launches: composition.launches, personaAuth: composition.personaAuth,
            personaAuthority: grading.personaAuthority, modeAuthority, scenes,
            qualifyIdorModel: require('../../server/services/secureshopModelQualification')
              .createSecureShopModelQualifier(provider), judge }),
        cartImport: require('../../server/services/secureshopStandaloneCartImport')
          .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
            personaAuth: composition.personaAuth, commerce: composition.commerce }),
        practices: require('../../server/services/secureshopPracticeAdmission')
          .createSecureShopPracticeAdmission({ catalog: composition.catalog,
            repository: require('../../server/database/postgres/secureshopPracticeAdmissionRepository')
              .createSecureShopPracticeAdmissionRepository({ pool: identity }) }) };
      const mounted = { ...composition,
        standaloneAuth: standaloneAuthority, publicCatalog };
      const bound = await require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          applicationMode: 'standalone', authenticateToken: (_request, response) =>
            response.sendStatus(401), audit: async () => {}, agentRuntime: {},
          getComposition: async () => mounted });
      assert.equal(bound.standaloneReadiness.ready, true);
      const app = express(); app.use(express.json());
      app.use('/api/secureshop', (request, response, next) => {
        if (request.path.startsWith('/agents/customer/idor/')) {
          requests.push({ method: request.method, path: request.path,
            body: request.method === 'POST' ? structuredClone(request.body) : null });
          if (request.method === 'POST' && request.path === '/agents/customer/idor/chat') {
            assert.ok(++status.roleTurns <= EXPECTED_TURNS, 'exact active physical lesson turns');
          }
        }
        next();
      });
      server = await listen(app);
      const origin = `http://127.0.0.1:${server.address().port}`;
      app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthRouter({ ...standaloneAuthority,
          allowedOrigins: [origin], secureCookies: false }));
      app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
        .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
      app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog')
        .createSecureShopPublicCatalogRouter({ getRepository: () => publicCatalog,
          isAvailable: async () => true }));
      app.use('/api', (_request, response) =>
        response.status(404).json({ error: 'Outside IDOR lesson qualification' }));
      // Sandboxed shop ES modules load with an opaque Origin. This applies
      // only to isolated build assets, as in the other rendered fixtures.
      app.use(express.static(build, {
        setHeaders: response => response.set('Access-Control-Allow-Origin', '*'),
      }));
      app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));
      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-customer-idor-browser-'));
      browser = await require('puppeteer').launch({ headless: true,
        userDataDir: profile, executablePath });
      page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 900 });
      page.on('pageerror', error => pageErrors.push(error.message.slice(0, 160)));
      await page.setRequestInterception(true);
      page.on('request', request => request.url().startsWith(`${origin}/`)
        ? request.continue() : request.abort());
      assert.equal((await page.goto(`${origin}/secureshop/login`)).status(), 200);
      stage = 'physical-login';
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', username);
      await page.type('#ss-login-pw', password);
      const loginResponse = waitResponse(page, 'POST', '/api/secureshop/auth/login', 20000);
      const bootstrapResponse = waitResponse(page, 'POST', '/api/secureshop/auth/bootstrap', 20000);
      void loginResponse.catch(() => {});
      void bootstrapResponse.catch(() => {});
      await page.click('button[type="submit"]');
      const loginWire = await loginResponse;
      assert.equal(loginWire.status(), 200);
      const loginValue = await loginWire.json();
      assert.equal(loginValue.authenticated, true);
      assert.equal(loginValue.user.role, 'customer');
      assert.equal(loginValue.user.username, username);
      // Bootstrap contains credentials: require its real status, never retain
      // its body, cookies or token bytes in diagnostic evidence.
      assert.equal((await bootstrapResponse).status(), 200);
      stage = 'authenticated-customer-lane';
      let frame = await frameFor(page);
      // The authenticated Home shell renders this lane. There is no separate
      // customer route or navigation link; login remains a physical action.
      const select = await frame.waitForSelector('select[id^="agent-lane-task-customer-"]',
        { visible: true });
      const cardsRequestPromise = page.waitForRequest(request =>
        new URL(request.url()).pathname === `${PATH}/cards`
          && request.method() === 'GET', { timeout: 20000 });
      const initialCardsResponse = waitResponse(page, 'GET', `${PATH}/cards`);
      void cardsRequestPromise.catch(() => {});
      void initialCardsResponse.catch(() => {});
      stage = 'initial-lesson-cards';
      await select.select('idor');
      await frame.waitForSelector('section[aria-label="Customer access control lesson"]');
      const ownerHeaders = headersFrom(await cardsRequestPromise);
      assert.equal((await initialCardsResponse).status(), 503,
        'the initial read cannot provision an isolated lesson scene');
      const scope = await composition.launches.resolveCapability(
        ownerHeaders['x-dvaia-secureshop-launch']);
      const actor = await composition.personaAuth.authenticateBoundToken({ scope,
        token: ownerHeaders.authorization.slice(7) });
      const persona = { id: actor.user.id, role: 'customer' };
      const personaSession = { sessionId: actor.sessionId,
        authorityVersion: actor.authorityVersion };
      await composition.catalog.prepareTarget({ scope, persona, personaSession });
      const retainedScene = await scenes.readExisting(scope);
      assert.ok(retainedScene?.scene);

      // All physical turns and protected evidence assertions follow below.
      // A missing integrated card or qualified objective fails, never skips.
      const fixedPost = waitResponse(page, 'POST', '/api/secureshop/auth/mode');
      void fixedPost.catch(() => {});
      await physicalButton(page, 'Shop settings');
      await page.waitForSelector('aside[aria-label="Shop settings"]');
      await physicalButton(page, 'Fixed', '[role="group"][aria-label="Shop feature mode"] button');
      assert.equal((await fixedPost).status(), 200);
      await page.waitForFunction(() => document.querySelector('[role="group"][aria-label="Shop feature mode"]')
        ?.textContent.includes('Current: Fixed'), { timeout: 20000 });
      await physicalButton(page, 'Shop settings');
      await page.waitForSelector('aside[aria-label="Shop settings"]', { hidden: true });
      frame = await frameFor(page);
      const prepareRequestPromise = page.waitForRequest(request =>
        new URL(request.url()).pathname === `${PATH}/prepare`
          && request.method() === 'POST', { timeout: 20000 });
      void prepareRequestPromise.catch(() => {});
      await physicalButton(frame, 'Prepare lesson targets');
      const prepareRequest = await prepareRequestPromise;
      await frame.waitForFunction(() => document.querySelectorAll(
        'section[aria-label="Customer access control lesson"] button').length === 2,
      { timeout: 20000 });
      assert.deepEqual(headersFrom(prepareRequest), ownerHeaders,
        'physical preparation must use the same current owner authority');
      const lessonRepository = require('../../server/database/postgres/secureshopBoundIdorLessonRepository')
        .createSecureShopBoundIdorLessonRepository(review, { modeAuthority,
          readVictimIdentity: require('../../server/database/postgres/secureshopBoundIdorLessonRepository')
            .createImmutableTemplateVictimReader(agents) });
      const originalReader = require('../../server/database/postgres/secureshopIdorLessonTurnReader')
        .createSecureShopIdorLessonTurnReader({ pool: agents });
      const binding = require('../../server/services/secureshopConversationBinding')
        .createConversationBinding(scope, persona);
      const qualifyModel = require('../../server/services/secureshopModelQualification')
        .createSecureShopModelQualifier(provider);
      const base = { scope, persona, personaSession, retainedScene };
      const birth = await lessonRepository.readBirth(base);
      const initialCards = await protectedGet(origin, `${PATH}/cards`, ownerHeaders);
      assertCardsMatchBirth(initialCards.cards, birth);
      assert.equal(initialCards.modeCapability.effectiveMode, 'fixed');
      const display = await frame.$eval('section[aria-label="Customer access control lesson"]',
        element => element.textContent);
      assert.ok(display.includes(`Reserved lesson cart item #${birth.cartItemId}`));
      assert.ok(display.includes(`Reserved lesson order #${birth.orderId}`));

      const ownerPrincipal = await auth.establishTenantContext(
        await auth.authenticate((await page.cookies(`${origin}/api/secureshop/auth/session`))
          .find(cookie => cookie.name === 'dvaia_shop_session').value));
      const assessmentRows = async (table, objectiveId) => snapshot(identity, table,
        ownerPrincipal, objectiveId);
      const assertCanonicalAward = async (objectiveId, assessment) => {
        const rows = await assessmentRows('assessment_judgments', objectiveId);
        assert.equal(rows.length, 1);
        const row = rows[0];
        assert.equal(row.evaluation_id, assessment.judgment.evaluationId);
        assert.equal(row.objective_id, objectiveId);
        assert.equal(row.verdict, 'pass');
        assert.equal(row.disposition, 'awarded');
        assert.equal(row.mode, 'vuln');
        assert.equal(row.result_json.provider, 'ollama');
        assert.equal(row.result_json.model, MODEL);
        assert.equal(row.result_json.verdict, 'pass');
        assert.equal(createHash('sha256').update(row.result_serialized).digest('hex'),
          row.result_digest);
        assert.deepEqual(JSON.parse(row.result_serialized), row.result_json);
        assert.ok(JSON.parse(row.packet).evidence.length > 0);
        const source = judgeResults.filter(result => {
          const proof = require('../../server/agent-runtime/objectiveJudge')
            .readConfiguredJudgeProvenance(result);
          return proof?.evidenceDigest === row.evidence_digest;
        });
        assert.equal(source.length, 1, 'one original configured Judge result binds this award');
        const proof = require('../../server/agent-runtime/objectiveJudge')
          .readConfiguredJudgeProvenance(source[0]);
        assert.deepEqual(row.judge_observations, proof);
        assert.equal(row.judge_result_json, JSON.stringify(source[0]));
        const allJudgeWires = transport.calls.filter(call => call.kind === 'judge');
        const wires = allJudgeWires.slice(-proof.calls.length);
        assert.equal(wires.length, proof.calls.length);
        for (const [index, call] of proof.calls.entries()) {
          const wire = wires[index], request = JSON.parse(wire.request);
          assert.equal(request.model, MODEL);
          assert.equal(call.provider, 'ollama');
          assert.equal(call.model, MODEL);
          assert.equal(call.requestSha256, createHash('sha256').update(JSON.stringify({
            method: 'chat', input: request.messages,
            schema: request.format ?? null })).digest('hex'));
          const response = wire.response.trim().split('\n')
            .map(line => JSON.parse(line).message?.content || '').join('');
          assert.equal(call.responseSha256,
            createHash('sha256').update(response).digest('hex'));
        }
      };
      const effects = async () => (await review.query(`SELECT * FROM
        secureshop_review.owned_idor_lesson_operations WHERE target_id=$1 ORDER BY operation_id`,
      [retainedScene.targetId])).rows;
      const cartRows = async () => (await review.query(`SELECT * FROM
        secureshop_review.product_target_cart_items WHERE target_id=$1 AND cart_item_id=$2`,
      [retainedScene.targetId, birth.cartItemId])).rows;
      const orderRows = async () => (await review.query(`SELECT * FROM
        secureshop_review.product_target_orders WHERE target_id=$1 AND order_id=$2`,
      [retainedScene.targetId, birth.orderId])).rows;
      const cartBefore = await cartRows(), orderBefore = await orderRows();
      assert.equal(cartBefore.length, 1); assert.equal(orderBefore.length, 1);
      const fullRows = new Map();
      async function turn(action, mode, label) {
        stage = `lesson-turn:${mode}:${action}`;
        const numericId = action === 'cart_remove' ? birth.cartItemId : birth.orderId;
        const postsBefore = status.roleTurns, actorBefore = status.actorCalls,
          judgeBefore = status.judgeCalls;
        const response = waitResponse(page, 'POST', `${PATH}/chat`);
        void response.catch(() => {});
        await physicalButton(frame, label,
          'section[aria-label="Customer access control lesson"] button');
        assert.equal((await response).status(), 200);
        assert.equal(status.roleTurns, postsBefore + 1);
        const submitted = requests.filter(row => row.method === 'POST'
          && row.path === '/agents/customer/idor/chat').at(-1)?.body;
        assert.deepEqual(submitted?.selection, { action, numericId });
        assert.ok(typeof submitted.message === 'string'
          && submitted.message.includes(`#${numericId}`));
        const visibleResult = mode === 'fixed' ? 'Saved result: access denied.'
          : action === 'cart_remove' ? 'Saved result: cart item removed.'
            : 'Saved result: order details returned.';
        // The durable request status and the rendered lesson outcome live in
        // separate cards.  Require both together before treating this exact
        // physical POST as visibly complete; the protected GET below then
        // binds the saved card to its captured session/request IDs.
        await frame.waitForFunction(({ completedLabel, expectedResult }) => {
          const savedCard = document.querySelector(
            'section[aria-label="Saved access-control lesson request"]');
          const lessonCard = document.querySelector(
            'section[aria-label="Customer access control lesson"]');
          const visible = card => Boolean(card && card.getClientRects().length
            && getComputedStyle(card).visibility !== 'hidden'
            && getComputedStyle(card).display !== 'none');
          return visible(savedCard) && visible(lessonCard)
            && (savedCard.textContent || '').includes(completedLabel)
            && (lessonCard.textContent || '').includes(expectedResult);
        }, { timeout: 70000 }, {
          completedLabel: 'Saved customer request · completed',
          expectedResult: visibleResult,
        });
        const savedPath = `${PATH}/operations/${submitted.sessionId}/${submitted.requestId}`;
        const saved = await protectedGet(origin, savedPath, ownerHeaders);
        assertSavedLesson(saved, { sessionId: submitted.sessionId,
          requestId: submitted.requestId, action, numericId, mode, birth });
        const original = await originalReader.readIdorLessonRequest({
          sessionId: submitted.sessionId, requestId: submitted.requestId,
          binding, purpose: 'secureshop_idor_lesson' });
        const meta = original?.result_json?.taskMetadata?.idorLesson;
        const traces = await composition.repositories.conversations.getTraceEvents(
          submitted.sessionId, binding, meta?.traceEventIds, 'secureshop_idor_lesson');
        const modeToken = await modeAuthority.capture(binding, 'customer_idor');
        const receipt = await lessonRepository.readSaved({ scope: binding, persona,
          personaSession, retainedScene, modeToken, operationId: meta?.operationId });
        assertOriginalLessonTurn({ row: original, traces, receipt,
          sessionId: submitted.sessionId, requestId: submitted.requestId,
          action, numericId, mode, qualifyModel });
        assert.equal(saved.text, original.result_json.text);
        assertOriginalActorWire({ spans: actorSpans.filter(span =>
          span.turn === status.roleTurns), turn: original.result_json,
          origin: meta.origin, action, numericId, model: MODEL });
        if (mode === 'vuln') {
          const candidate = require('../../server/services/secureshopIdorLessonEvidence')
            .buildIdorLessonCandidate({ binding, personaSession, retainedScene,
              sessionId: submitted.sessionId, requestId: submitted.requestId,
              requestHash: original.request_hash, requestVersion: original.request_version,
              turn: original.result_json, traces, birth, receipt,
              mode: modeToken.snapshot, qualifyModel });
          assert.equal(candidate?.objectiveId, OBJECTIVES[action]);
        }
        assert.ok(status.actorCalls > actorBefore);
        if (mode === 'fixed') assert.equal(status.judgeCalls, judgeBefore);
        fullRows.set(`${mode}:${action}`, { saved, savedPath, submitted,
          original, traces, receipt });
        return saved;
      }
      await turn('cart_remove', 'fixed', 'Try cart removal');
      status.renderedFixedCartDenied = true;
      assert.deepEqual(await cartRows(), cartBefore);
      if (!V10_ONLY) {
        await physicalButton(frame, 'Start another lesson request');
        await frame.waitForSelector('section[aria-label="Saved access-control lesson request"]',
          { hidden: true });
        await turn('order_status', 'fixed', 'Read full order details');
        status.renderedFixedOrderDenied = true;
        assert.deepEqual(await orderRows(), orderBefore);
      }
      for (const objectiveId of ACTIVE_OBJECTIVES) {
        assert.deepEqual(await assessmentRows('assessment_judgments', objectiveId), []);
        assert.deepEqual(await assessmentRows('assessment_completions', objectiveId), []);
        assert.deepEqual(await assessmentRows('active_assessment_contributions', objectiveId), []);
      }
      assert.equal(status.judgeCalls, 0);
      status.fixedNoEffectOrCredit = true;
      await physicalButton(frame, 'Start another lesson request');
      await frame.waitForSelector('section[aria-label="Saved access-control lesson request"]',
        { hidden: true });

      const vulnPost = waitResponse(page, 'POST', '/api/secureshop/auth/mode');
      void vulnPost.catch(() => {});
      await physicalButton(page, 'Shop settings');
      await page.waitForSelector('aside[aria-label="Shop settings"]');
      await physicalButton(page, 'Vulnerable',
        '[role="group"][aria-label="Shop feature mode"] button');
      assert.equal((await vulnPost).status(), 200);
      await page.waitForFunction(() => document.querySelector('[role="group"][aria-label="Shop feature mode"]')
        ?.textContent.includes('Current: Vulnerable'), { timeout: 20000 });
      await physicalButton(page, 'Shop settings');
      await page.waitForSelector('aside[aria-label="Shop settings"]', { hidden: true });
      frame = await frameFor(page);
      await page.reload({ waitUntil: 'domcontentloaded' });
      frame = await frameFor(page);
      await frame.waitForSelector('select[id^="agent-lane-task-customer-"]', { visible: true });
      await frame.select('select[id^="agent-lane-task-customer-"]', 'idor');
      await frame.waitForSelector('section[aria-label="Customer access control lesson"]');
      const vulnerableCards = await protectedGet(origin, `${PATH}/cards`, ownerHeaders);
      assertCardsMatchBirth(vulnerableCards.cards, birth);
      assert.equal(vulnerableCards.modeCapability.effectiveMode, 'vuln');
      const cartSaved = await turn('cart_remove', 'vuln', 'Try cart removal');
      status.modelSelectedCartId = true;
      assert.deepEqual(await cartRows(), []);
      assert.equal(cartSaved.result.status, 'deleted');
      status.renderedCartDeletion = true;
      await physicalButton(frame, 'Check saved assessment');
      await frame.waitForFunction(() => document.querySelector(
        'section[aria-label="Saved access-control lesson request"]')
        ?.textContent.includes('Objective completed.'), { timeout: 30000 });
      const cartAssessment = await protectedGet(origin,
        `${PATH}/assessments/${fullRows.get('vuln:cart_remove').submitted.sessionId}`
          + `/${fullRows.get('vuln:cart_remove').submitted.requestId}`, ownerHeaders);
      assert.equal(cartAssessment.completed, true);
      assert.equal(cartAssessment.judgment.verdict, 'pass');
      await assertCanonicalAward(OBJECTIVES.cart_remove, cartAssessment);
      assert.equal((await assessmentRows('assessment_completions', OBJECTIVES.cart_remove)).length, 1);
      assert.equal((await assessmentRows('active_assessment_contributions', OBJECTIVES.cart_remove)).length, 1);
      status.cartJudgeCredit = true;
      let replayTurn = fullRows.get('vuln:cart_remove');
      let replaySaved = cartSaved;
      if (!V10_ONLY) {
        await physicalButton(frame, 'Start another lesson request');
        await frame.waitForSelector('section[aria-label="Saved access-control lesson request"]',
          { hidden: true });
        const orderSaved = await turn('order_status', 'vuln', 'Read full order details');
        status.modelSelectedOrderId = true;
        assert.equal(orderSaved.result.status, 'disclosed');
        assert.deepEqual(await orderRows(), orderBefore);
        status.renderedOrderDisclosure = true;
        await physicalButton(frame, 'Check saved assessment');
        await frame.waitForFunction(() => document.querySelector(
          'section[aria-label="Saved access-control lesson request"]')
          ?.textContent.includes('Objective completed.'), { timeout: 30000 });
        const orderTurn = fullRows.get('vuln:order_status');
        const orderAssessment = await protectedGet(origin,
          `${PATH}/assessments/${orderTurn.submitted.sessionId}`
            + `/${orderTurn.submitted.requestId}`, ownerHeaders);
        assert.equal(orderAssessment.completed, true);
        assert.equal(orderAssessment.judgment.verdict, 'pass');
        await assertCanonicalAward(OBJECTIVES.order_status, orderAssessment);
        assert.equal((await assessmentRows('assessment_completions', OBJECTIVES.order_status)).length, 1);
        assert.equal((await assessmentRows('active_assessment_contributions', OBJECTIVES.order_status)).length, 1);
        status.orderJudgeCredit = true;
        replayTurn = orderTurn;
        replaySaved = orderSaved;
      }
      status.genuineCredit = EXPECTED_CREDIT;

      const actorAfter = status.actorCalls, judgeAfter = status.judgeCalls;
      stage = 'saved-request-reload';
      const postAfter = status.roleTurns, operationRows = await effects();
      assert.equal(operationRows.length, EXPECTED_TURNS);
      await page.reload({ waitUntil: 'domcontentloaded' });
      frame = await frameFor(page);
      await frame.waitForSelector('select[id^="agent-lane-task-customer-"]', { visible: true });
      await frame.select('select[id^="agent-lane-task-customer-"]', 'idor');
      await frame.waitForSelector('section[aria-label="Saved access-control lesson request"]');
      await physicalButton(frame, 'Check saved request');
      await frame.waitForFunction(() => document.querySelector(
        'section[aria-label="Saved access-control lesson request"]')
        ?.textContent.includes('Saved customer request · completed'), { timeout: 20000 });
      assert.deepEqual(await protectedGet(origin, replayTurn.savedPath, ownerHeaders), replaySaved);
      assert.equal(status.actorCalls, actorAfter); assert.equal(status.judgeCalls, judgeAfter);
      assert.equal(status.roleTurns, postAfter); assert.deepEqual(await effects(), operationRows);
      status.savedReloadGetOnly = true; status.exactReplayNoRerun = true;

      const siblingBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: siblingAuth });
      const siblingReady = await siblingBootstrap(siblingLogin.context);
      const siblingScope = await composition.launches.resolveCapability(siblingReady.bearer);
      assert.notEqual(siblingScope.platformOwnerId, scope.platformOwnerId);
      const siblingActor = await composition.personaAuth.authenticateBoundToken({
        scope: siblingScope, token: siblingReady.persona.token });
      const siblingPersona = { id: siblingActor.user.id, role: 'customer' };
      const siblingPersonaSession = { sessionId: siblingActor.sessionId,
        authorityVersion: siblingActor.authorityVersion };
      await composition.catalog.prepareTarget({ scope: siblingScope,
        persona: siblingPersona, personaSession: siblingPersonaSession });
      const siblingBase = { scope: siblingScope,
        persona: siblingPersona, personaSession: siblingPersonaSession,
        retainedScene: await scenes.readExisting(siblingScope) };
      assert.notEqual(siblingBase.retainedScene.targetId, retainedScene.targetId);
      const siblingCards = await composition.idorLesson.runtime.prepare(siblingBase.scope,
        siblingBase.persona, siblingBase.personaSession);
      const siblingBirth = await lessonRepository.readBirth(siblingBase);
      assertCardsMatchBirth(siblingCards.cards, siblingBirth);
      const siblingHeaders = { authorization: `Bearer ${siblingReady.persona.token}`,
        'x-dvaia-secureshop-launch': siblingReady.bearer };
      const privateRead = await fetch(origin + replayTurn.savedPath, {
        headers: siblingHeaders, redirect: 'error', signal: AbortSignal.timeout(10000) });
      assert.equal(privateRead.status, 401);
      await privateRead.arrayBuffer();
      const privateAssessment = await fetch(origin + `${PATH}/assessments/`
        + `${replayTurn.submitted.sessionId}/${replayTurn.submitted.requestId}`, {
        headers: siblingHeaders, redirect: 'error', signal: AbortSignal.timeout(10000) });
      assert.equal(privateAssessment.status, 401);
      await privateAssessment.arrayBuffer();
      assert.deepEqual(await effects(), operationRows);
      status.siblingPrivate = true;

      const ownerJudgments = Object.fromEntries(await Promise.all(ACTIVE_OBJECTIVES
        .map(async objectiveId => [objectiveId,
          await assessmentRows('assessment_judgments', objectiveId)])));
      const ownerCompletions = Object.fromEntries(await Promise.all(ACTIVE_OBJECTIVES
        .map(async objectiveId => [objectiveId,
          await assessmentRows('assessment_completions', objectiveId)])));
      const siblingState = await lessonRepository.readBirth(siblingBase);
      const siblingProductRows = (await review.query(`SELECT * FROM
        secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id`,
      [siblingBase.retainedScene.targetId])).rows;
      const siblingOperationRows = (await review.query(`SELECT * FROM
        secureshop_review.owned_idor_lesson_operations WHERE target_id=$1 ORDER BY operation_id`,
      [siblingBase.retainedScene.targetId])).rows;
      assert.ok(siblingProductRows.length > 0);
      const beforeReset = await protectedGet(origin, replayTurn.savedPath, ownerHeaders);
      stage = 'owner-reset';
      assert.deepEqual(beforeReset, replaySaved);
      const resetResult = await reset.launchResetCoordinator.reset({ ...scope,
        expectedGeneration: scope.generation, idempotencyKey: randomUUID() });
      assert.equal(resetResult.status, 'committed');
      const cleanup = (await identity.query(`SELECT * FROM
        secureshop_auth.assessment_cleanup_history
        WHERE launch_id=$1 AND from_generation=$2`,
      [scope.launchId, scope.generation])).rows;
      assert.equal(cleanup.length, 1);
      assert.equal(cleanup[0].tenant_id, ownerPrincipal.tenantId);
      assert.equal(cleanup[0].principal_id, ownerPrincipal.principalId);
      assert.equal(cleanup[0].retired_judgment_count, EXPECTED_CREDIT);
      assert.equal(cleanup[0].retired_contribution_count, EXPECTED_CREDIT);
      // Migration 0146 records only contributions still projected from a
      // different launch/generation.  This lesson's credited contribution is
      // the one being retired, while its immutable completion remains below.
      assert.equal(cleanup[0].projected_completion_count, 0);
      const stale = await fetch(origin + replayTurn.savedPath, { headers: ownerHeaders,
        redirect: 'error', signal: AbortSignal.timeout(10000) });
      assert.equal(stale.status, 401); await stale.arrayBuffer();
      status.resetFenced = true;
      const retainedOperations = await effects();
      assert.deepEqual(retainedOperations, operationRows,
        'the IDOR lesson operation ledger is immutable across reset');
      for (const objectiveId of ACTIVE_OBJECTIVES) {
        assert.deepEqual(await assessmentRows('assessment_judgments', objectiveId),
          ownerJudgments[objectiveId]);
        assert.deepEqual(await assessmentRows('assessment_completions', objectiveId),
          ownerCompletions[objectiveId]);
        assert.deepEqual(await assessmentRows('active_assessment_contributions', objectiveId), []);
      }
      assert.deepEqual(await lessonRepository.readBirth(siblingBase), siblingState);
      assert.deepEqual((await review.query(`SELECT * FROM
        secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id`,
      [siblingBase.retainedScene.targetId])).rows, siblingProductRows);
      assert.deepEqual((await review.query(`SELECT * FROM
        secureshop_review.owned_idor_lesson_operations WHERE target_id=$1 ORDER BY operation_id`,
      [siblingBase.retainedScene.targetId])).rows, siblingOperationRows);
      assert.equal(status.actorCalls, actorAfter); assert.equal(status.judgeCalls, judgeAfter);
      assert.equal(status.roleTurns, postAfter);
      assert.equal(status.roleTurns, EXPECTED_TURNS);
      assert.equal(transport.calls.filter(call => call.kind === 'actor').length,
        status.actorCalls);
      assert.equal(transport.calls.filter(call => call.kind === 'judge').length,
        status.judgeCalls);
      assert.ok(transport.calls.every(call => call.status === 200
        && call.responseComplete === true && call.responseCaptureTruncated === false));
      status.immutableHistoryRetained = true;
      status.passed = QUALIFICATION_FLAGS.filter(key => key !== 'passed'
        && key !== 'fixtureCleaned').every(key => status[key] === true);
    } catch (error) { failure = error; status.errors = [{ name: error.name,
      code: error.code || null, message: String(error.message).slice(0, 300) }];
    if (page) {
      try {
        const observe = async surface => surface.evaluate(() => {
          const visible = node => node.getClientRects().length
            && getComputedStyle(node).visibility !== 'hidden';
          const text = value => String(value || '').replace(
            /\b(?:Bearer\s+)?eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
            '[redacted]').slice(0, 1200);
          return { path: location.pathname, title: text(document.title),
            visibleText: text(document.body?.innerText),
            alerts: [...document.querySelectorAll('[role="alert"]')]
              .filter(visible).slice(0, 8).map(node => text(node.textContent).slice(0, 160)),
            taskSelectors: [...document.querySelectorAll('select[id^="agent-lane-task-customer-"]')]
              .map(node => ({ visible: Boolean(visible(node)), disabled: node.disabled,
                value: node.value })).slice(0, 2) };
        });
        browserDiagnostic = { stage, parent: await observe(page), frame: null };
        const frameElement = await page.$('iframe[title="SecureShop"]');
        const currentFrame = frameElement && await frameElement.contentFrame();
        if (currentFrame) browserDiagnostic.frame = await observe(currentFrame);
        browserScreenshot = path.join(path.dirname(evidencePath), 'idor-browser-failure.png');
        await page.screenshot({ path: browserScreenshot, fullPage: false });
        await fs.chmod(browserScreenshot, 0o600);
      } catch (diagnosticError) {
        browserDiagnostic = { stage, captureError: diagnosticError.name };
      }
    }
    t.diagnostic(JSON.stringify({ stage: 'idor-rendered-failure',
      error: status.errors[0], requests: requests.slice(-8), pageErrors: pageErrors.slice(-8) }));
  } finally {
    if (originalModelURL === undefined) delete process.env.OLLAMA_BASE_URL;
    else process.env.OLLAMA_BASE_URL = originalModelURL;
    let browserClosed = !browser;
    try { if (browser) { await browser.close(); browserClosed = true; } }
    catch (error) { cleanupErrors.push(error); }
    for (const close of [() => closeServer(server),
      () => transport?.close(), () => reset?.closeFeatureTransports?.(),
      () => reset?.auditLedger?.close?.(),
      () => profile && browserClosed && fs.rm(profile, { recursive: true, force: true }),
      () => leasePool.end(),
      ...Object.values(pools).map(pool => () => pool.end())]) {
      try { await close(); } catch (error) { cleanupErrors.push(error); }
    }
    status.fixtureCleaned = cleanupErrors.length === 0;
    status.errors.push(...cleanupErrors.map(error => ({ name: error.name,
      code: error.code || null })));
    try { saveWire(); } catch (error) { cleanupErrors.push(error); }
    try { await fs.writeFile(evidencePath, JSON.stringify(status, null, 2),
      { flag: 'wx', mode: 0o600 }); } catch (error) { cleanupErrors.push(error); }
  }
  if (cleanupErrors.length) throw new AggregateError(cleanupErrors,
    'Owned IDOR browser cleanup or evidence failed');
  if (failure) throw failure;
  if (V10_ONLY) assertV10CartBrowserReceipt(status);
  else assertIdorBrowserReceipt(status);
});

function assertV10CartBrowserReceipt(value) {
  assert.deepEqual(Object.keys(value).sort(), [...V10_BROWSER_FLAGS, 'scope', 'actorCalls',
    'judgeCalls', 'roleTurns', 'genuineCredit', 'errors'].sort());
  assert.equal(value.scope, V10_BROWSER_SCOPE);
  for (const key of V10_BROWSER_FLAGS) assert.equal(value[key], true, key);
  assert.ok(Number.isSafeInteger(value.actorCalls) && value.actorCalls >= 4
    && value.actorCalls <= 5);
  assert.ok(Number.isSafeInteger(value.judgeCalls) && value.judgeCalls >= 1
    && value.judgeCalls <= 2);
  assert.equal(value.roleTurns, 2);
  assert.equal(value.genuineCredit, 1);
  assert.deepEqual(value.errors, []);
  return value;
}

module.exports = { IDOR_BROWSER_SCOPE, IDOR_BROWSER_FLAGS, assertIdorBrowserReceipt,
  V10_BROWSER_SCOPE, V10_BROWSER_FLAGS, assertV10CartBrowserReceipt };
