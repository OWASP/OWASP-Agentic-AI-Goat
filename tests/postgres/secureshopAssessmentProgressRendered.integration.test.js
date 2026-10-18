'use strict';

// Rendered projection qualification over controlled contribution rows. This
// fixture does not run an actor or Judge and cannot establish objective credit.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { PROGRESS_RENDERED_SCOPE, PROGRESS_RENDERED_FLAGS,
  assertProgressRenderedReceipt, assertProgressProjection } =
  require('../fixtures/secureshopAssessmentProgressRenderedQualification');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_ASSESSMENT_PROGRESS_RENDERED_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const OBJECTIVE = 'ss_loop_observation';
const ENABLED = process.env.SECURESHOP_ASSESSMENT_PROGRESS_RENDERED_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
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
      assert.ok(match && match[2] === name, `${store} must be an owned disposable database`);
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
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1');
    server.once('listening', () => resolve(server));
    server.once('error', reject);
  });
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) => server.close(error =>
    error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(error) : resolve()));
}
async function boundedCleanup(label, action) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(action), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} cleanup timed out`)), 10000);
      timer.unref?.();
    })]);
  } finally { clearTimeout(timer); }
}
async function browserExited(browser) {
  if (!browser) return true;
  const child = browser.process?.();
  if (!child) return browser.connected?.() === false;
  const until = Date.now() + 10000;
  while (child.exitCode === null && child.signalCode === null && Date.now() < until) {
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  return child.exitCode !== null || child.signalCode !== null;
}
async function physicalButton(page, label, selector = 'button') {
  const handle = await page.waitForFunction(({ label, selector }) => {
    const found = [...document.querySelectorAll(selector)]
      .filter(element => element.textContent.trim() === label && !element.disabled
        && element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden');
    return found.length === 1 ? found[0] : null;
  }, { timeout: 20000 }, { label, selector });
  const button = handle.asElement(); assert.ok(button);
  await button.evaluate(node => node.scrollIntoView({ block: 'center' }));
  await button.click();
}
function waitResponse(page, method, route) {
  return page.waitForResponse(response => response.request().method() === method
    && new URL(response.url()).pathname === route, { timeout: 20000 });
}
async function physicalLogin(browser, origin, username, password) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  page.setDefaultTimeout(20000);
  await page.setViewport({ width: 1280, height: 900 });
  await page.setRequestInterception(true);
  page.on('request', request => request.url().startsWith(`${origin}/`)
    ? request.continue() : request.abort());
  assert.equal((await page.goto(`${origin}/secureshop/login`,
    { waitUntil: 'domcontentloaded' })).status(), 200);
  await page.waitForSelector('#ss-login-user');
  await page.type('#ss-login-user', username);
  await page.type('#ss-login-pw', password);
  const login = waitResponse(page, 'POST', '/api/secureshop/auth/login');
  const bootstrap = waitResponse(page, 'POST', '/api/secureshop/auth/bootstrap');
  void login.catch(() => {}); void bootstrap.catch(() => {});
  await page.click('button[type="submit"]');
  const admitted = await login;
  assert.equal(admitted.status(), 200);
  const account = await admitted.json();
  assert.equal(account.authenticated, true);
  assert.equal(account.user.username, username);
  const launchResponse = await bootstrap;
  assert.equal(launchResponse.status(), 200);
  const launch = await launchResponse.json();
  // Keep the launch secret in memory only; neither receipt nor diagnostics
  // serialize the bootstrap body, cookie, or authenticated request headers.
  await page.waitForSelector('button[aria-controls="secureshop-settings"]', { visible: true });
  return { context, page, account, launch };
}

async function controlledContribution(migration, identity, launch) {
  const evaluationId = randomUUID();
  const mode = (await migration.query(`SELECT generation,mode FROM secureshop_auth.tenant_modes
    WHERE tenant_id=$1 AND principal_id=$2`, [identity.tenantId, identity.principalId])).rows[0];
  assert.ok(mode);
  const result = JSON.stringify({ verdict: 'pass', provenance: 'controlled-rendered-progress-fixture',
    actualModel: false, actualJudge: false });
  await migration.query(`INSERT INTO secureshop_auth.assessment_judgments
    (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,
     family,scenario,rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,
     judge_version,owner_key,owner_generation,verdict,disposition,result_json,
     result_digest,evaluated_at)
    VALUES($1,$2,$3,$4,$5::jsonb,$6,'SecureShop','rendered-progress-fixture','fixture-only-v1',
      $7,$8,$9,$10,'controlled-fixture-mode','fixture-only',
      'controlled-rendered-progress-fixture',0,'pass','awarded',$11::jsonb,$12,clock_timestamp())`,
  [identity.tenantId, identity.principalId, evaluationId, identity.shopUserId,
    JSON.stringify({ fixture: 'controlled-rendered-progress-only',
      scope: { launchId: launch.launchId, generation: launch.generation } }),
    OBJECTIVE, 'a'.repeat(64), randomUUID(), mode.generation, mode.mode, result,
    createHash('sha256').update(result).digest('hex')]);
  await migration.query(`INSERT INTO secureshop_auth.assessment_completions
    (tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,$4,$5)`,
  [identity.tenantId, identity.principalId, OBJECTIVE, mode.generation, evaluationId]);
  await migration.query(`INSERT INTO secureshop_auth.assessment_contributions
    (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)`,
  [identity.tenantId, identity.principalId, evaluationId]);
  return evaluationId;
}

test('rendered standalone progress shows controlled current awards, admin tenant scope, and reset retirement',
  { skip: !ENABLED, timeout: 240000 }, async () => {
    assert.equal(process.cwd(), ROOT);
    assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/'), ROOT);
    const evidencePath = process.env.SECURESHOP_ASSESSMENT_PROGRESS_RENDERED_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidencePath));
    assert.ok(!path.resolve(evidencePath).startsWith(`${ROOT}${path.sep}`));
    const build = path.resolve(process.env.SECURESHOP_ASSESSMENT_PROGRESS_RENDERED_BUILD || '/');
    assert.equal(build, path.join(ROOT, 'client/build'));
    await fs.access(path.join(build, 'index.html'));
    await fs.access(path.join(build, 'secureshop-frame.html'));
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(executablePath)); await fs.access(executablePath);
    const urls = storeUrls();
    const pools = Object.fromEntries(Object.entries(urls).map(([key, connectionString]) =>
      [key, new Pool({ connectionString, max: key.endsWith('RUNTIME') ? 12 : 3,
        connectionTimeoutMillis: 1500, statement_timeout: 8000 })]));
    const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4 });
    const status = Object.fromEntries(PROGRESS_RENDERED_FLAGS.map(key => [key, false]));
    Object.assign(status, { scope: PROGRESS_RENDERED_SCOPE, actorCalls: 0, judgeCalls: 0, errors: [] });
    let composition, browser, server, profile, failure, customerPage, adminPage;
    const contexts = [], cleanupErrors = [];
    try {
      for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
        ['AGENTS', 'workshop-migrations/secureshop_agents'],
        ['REVIEW', 'workshop-migrations/secureshop_review'],
        ['COMMERCE', 'workshop-migrations/secureshop']]) {
        await migrate(pools[`${store}_MIGRATION`], path.join(ROOT, 'db/postgres', directory));
      }
      const migration = pools.IDENTITY_MIGRATION, identity = pools.IDENTITY_RUNTIME;
      const agents = pools.AGENTS_RUNTIME, review = pools.REVIEW_RUNTIME;
      const commerce = pools.COMMERCE_RUNTIME;
      await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
      await require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults(migration);
      await require('../../server/database/postgres/secureshopStandaloneSeed').seedSecureShopStandaloneDefaults(migration,
        { hashPassword: value => bcrypt.hash(value, 4) });
      const seed = await pools.COMMERCE_MIGRATION.connect();
      try { await seed.query('BEGIN');
        await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seed);
        await seed.query('COMMIT');
      } catch (error) { await seed.query('ROLLBACK'); throw error; }
      finally { seed.release(); }
      status.isolatedStores = true;

      const auth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const suffix = randomUUID().slice(0, 8), password = 'disposable-progress-browser';
      const customerName = `progress_customer_${suffix}`;
      const siblingName = `progress_sibling_${suffix}`;
      const customer = await auth.register({ username: customerName,
        email: `${customerName}@example.invalid`, password, role: 'customer' });
      const sibling = await auth.register({ username: siblingName,
        email: `${siblingName}@example.invalid`, password, role: 'customer' });
      const admin = await auth.login({ username: 'student_admin', password: 'student123' });
      const customerExecution = await auth.establishTenantContext(customer.context);
      const siblingExecution = await auth.establishTenantContext(sibling.context);
      assert.equal(customerExecution.tenantId, siblingExecution.tenantId);
      const catalog = require('../../server/services/secureshopAssessmentCatalog')
        .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
      const objective = (await catalog.list(admin.context)).objectives
        .find(row => row.objectiveId === OBJECTIVE);
      assert.ok(objective);
      assert.equal((await catalog.set(admin.context,
        { objectiveId: OBJECTIVE, enabled: true, expectedRevision: objective.revision })).enabled, true);

      const audit = require('../../server/services/secureshopBoundAuditComposition')
        .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
          includeRunArtifacts: true });
      const reset = require('../../server/services/secureshopCleanupComposition')
        .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, leasePool, audit });
      const grading = await require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
          progress: require('../../server/database/postgres/workshopProgressRepository')
            .createWorkshopProgressRepository(identity), resetComposition: reset,
          expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository')
          .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
        reviewPool: review, launches: reset.launches });
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identity);
      const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
        .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
      const provider = { async chat() { throw Error('Progress fixture cannot invoke an actor'); },
        async finalResponse() { throw Error('Progress fixture cannot invoke an actor'); } };
      composition = await require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: reset,
          gradingBootstrap: grading, scenes, modeAuthority, fixtures: [],
          requiredObjectives: [OBJECTIVE],
          jwtSecret: 'disposable-progress-persona-secret-at-least-32-bytes',
          agentRuntime: { provider } });
      await composition.repositories.personas.ensureTemplates();
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });
      const standaloneMode = require('../../server/services/secureshopStandaloneMode')
        .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
      const progress = require('../../server/services/secureshopAssessmentProgress')
        .createSecureShopAssessmentProgress({ repository:
          require('../../server/database/postgres/secureshopAssessmentProgressRepository')
            .createSecureShopAssessmentProgressRepository({ pool: identity }) });
      const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
        .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
          reviewPool: review, commercePool: commerce });
      const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
        .createRegisteredAdminResetEnvelope({ activeKeyId: 'progress-owned',
          keys: new Map([['progress-owned', require('node:crypto').randomBytes(32)]]) });
      const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
        .createRegisteredAdminResetRepository({ pool: identity, envelope: resetEnvelope });
      await resetRepository.checkReadiness();
      const standaloneAuthority = { service: auth, bootstrap, mode: standaloneMode,
        reset: require('../../server/services/secureshopStandaloneReset')
          .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
            launches: composition.launches, scenes,
            resetCoordinator: reset.launchResetCoordinator, preflight: reset.sceneResetPreflight }),
        registeredAdminReset: require('../../server/services/secureshopRegisteredAdminReset')
          .createRegisteredAdminResetService({ repository: resetRepository }),
        assessmentObjectives: catalog,
        assessmentRecovery: require('../../server/services/secureshopAssessmentRecovery')
          .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth, bootstrap,
            launches: composition.launches, personaAuth: composition.personaAuth,
            personaAuthority: grading.personaAuthority, modeAuthority }),
        assessmentProgress: progress,
        cartImport: require('../../server/services/secureshopStandaloneCartImport')
          .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
            personaAuth: composition.personaAuth, commerce: composition.commerce }) };
      const mounted = Object.freeze({ ...composition,
        standaloneAuth: Object.freeze(standaloneAuthority), publicCatalog,
        personaInbox: Object.freeze({ ready: true, router: express.Router() }),
        mcpTrust: Object.freeze({ ready: true, router: express.Router() }),
        ssrf: Object.freeze({ ready: true, router: express.Router() }) });
      const bound = await require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          applicationMode: 'standalone', authenticateToken: (_request, response) => response.sendStatus(401),
          audit: async () => {}, agentRuntime: {}, getComposition: async () => mounted });
      assert.equal(bound.standaloneReadiness.ready, true);
      assert.deepEqual(Object.keys(bound.standaloneReadiness.checks).sort(), [
        'authentication', 'reset', 'settings', 'publicCatalog', 'catalog', 'commerce',
        'account', 'administration', 'authority', 'requestedPanels',
      ].sort());
      assert.ok(Object.values(bound.standaloneReadiness.checks).every(Boolean));

      const app = express(); app.use(express.json());
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
        response.status(404).json({ error: 'Outside progress projection fixture' }));
      app.use(express.static(build, { setHeaders: response =>
        response.set('Access-Control-Allow-Origin', '*') }));
      app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));

      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-progress-rendered-'));
      browser = await require('puppeteer').launch({ headless: true,
        userDataDir: profile, executablePath, timeout: 20000, protocolTimeout: 20000 });
      const customerBrowser = await physicalLogin(browser, origin, customerName, password);
      contexts.push(customerBrowser.context); customerPage = customerBrowser.page;
      assert.equal(customerBrowser.account.user.role, 'customer');
      const customerScope = await composition.launches.resolveCapability(customerBrowser.launch.bearer);
      assert.equal(customerScope.platformOwnerId, customerExecution.ownerId);
      const siblingLaunch = await reset.launches.issueOrRenew({
        platformOwnerId: siblingExecution.ownerId,
        platformSessionId: siblingExecution.sessionId,
        expiresAt: new Date(Date.now() + 20 * 60 * 1000).toISOString(),
        shopPrincipal: siblingExecution });
      const customerEvaluation = await controlledContribution(migration, customerExecution, customerScope);
      const siblingEvaluation = await controlledContribution(migration, siblingExecution, siblingLaunch.binding);
      status.controlledContributionLabeled = true;

      const customerRead = waitResponse(customerPage, 'GET', '/api/secureshop/auth/progress');
      void customerRead.catch(() => {});
      await physicalButton(customerPage, 'Shop settings');
      await customerPage.waitForSelector('section[aria-label="Shop progress"]');
      const customerWire = await customerRead;
      assert.equal(customerWire.status(), 200);
      assertProgressProjection(await customerWire.json(), {
        principalId: customer.context.principalId, objectiveId: OBJECTIVE, completed: true });
      await customerPage.waitForFunction(() => document.querySelector('[aria-label="Your progress"]')
        ?.textContent.includes('Completed') && document.querySelector('[aria-label="Your progress"]')
        ?.textContent.includes('Observe a real model selecting a tool'), { timeout: 20000 });
      status.physicalLearnerSelf = true;

      const adminBrowser = await physicalLogin(browser, origin, 'student_admin', 'student123');
      contexts.push(adminBrowser.context); adminPage = adminBrowser.page;
      assert.equal(adminBrowser.account.user.role, 'admin');
      const adminListRead = waitResponse(adminPage, 'GET', '/api/secureshop/auth/admin/progress/learners');
      void adminListRead.catch(() => {});
      await physicalButton(adminPage, 'Shop settings');
      const listWire = await adminListRead;
      assert.equal(listWire.status(), 200);
      const page = await listWire.json();
      assert.deepEqual(Object.keys(page).sort(), ['learners', 'nextCursor']);
      assert.ok(page.learners.some(row => row.principalId === customer.context.principalId));
      assert.ok(page.learners.some(row => row.principalId === sibling.context.principalId));
      assert.ok(page.learners.every(row => row.principalId !== admin.context.principalId
        || row.role === 'admin'));
      await adminPage.waitForFunction(name => [...document.querySelectorAll(
        '[aria-label="Learner progress"] button')].some(button => button.textContent.includes(name)),
      { timeout: 20000 }, customerName);
      status.physicalAdminList = true;
      const detailRoute = `/api/secureshop/auth/admin/progress/${customer.context.principalId}`;
      const detailRead = waitResponse(adminPage, 'GET', detailRoute);
      void detailRead.catch(() => {});
      await physicalButton(adminPage, `${customerName} · 1/${page.learners.find(row =>
        row.principalId === customer.context.principalId).totalObjectives} completed`,
      '[aria-label="Learner progress"] button');
      const detailWire = await detailRead;
      assert.equal(detailWire.status(), 200);
      assertProgressProjection(await detailWire.json(), {
        principalId: customer.context.principalId, objectiveId: OBJECTIVE, completed: true });
      await adminPage.waitForFunction(name => document.querySelector(`[aria-label="${name} objectives"]`)
        ?.textContent.includes('Completed'), { timeout: 20000 }, customerName);
      status.physicalAdminDetail = true;

      const peerId = randomUUID(), peerTenant = randomUUID(), peerSlug = `progress_peer_${suffix}`;
      const peerUser = `progress_peer_${suffix}`;
      const peerRow = (await migration.query(`INSERT INTO secureshop_auth.principals
        (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'customer')
        RETURNING shop_user_id`, [peerId, peerUser, `${peerUser}@example.invalid`,
        await bcrypt.hash(password, 4)])).rows[0];
      await migration.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)`,
        [peerTenant, peerSlug]);
      await migration.query(`INSERT INTO secureshop_auth.tenant_memberships
        (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
      [peerTenant, peerId, peerRow.shop_user_id]);
      const adminCookie = (await adminPage.cookies(`${origin}/api/secureshop/auth/session`))
        .find(cookie => cookie.name === 'dvaia_shop_session');
      assert.ok(adminCookie);
      const foreign = await fetch(`${origin}/api/secureshop/auth/admin/progress/${peerId}`,
        { headers: { Cookie: `${adminCookie.name}=${adminCookie.value}` },
          signal: AbortSignal.timeout(10000) });
      assert.equal(foreign.status, 503);
      assert.deepEqual(await foreign.json(), { error: 'Shop service unavailable' });
      status.foreignDenied = true;

      const begun = await reset.launches.beginReset({ launchId: customerScope.launchId,
        platformOwnerId: customerScope.platformOwnerId,
        platformSessionId: customerScope.platformSessionId,
        expectedGeneration: customerScope.generation, idempotencyKey: randomUUID() });
      const checkpoint = await require('../../server/database/postgres/secureshopRealmProgressCleanupCheckpointRepository')
        .createSecureShopRealmProgressCleanupCheckpointRepository(identity).finalize(begun.resetId);
      assert.equal(checkpoint.checkpoint.retired_contribution_count, 1);
      assert.equal((await identity.query(`SELECT count(*)::integer AS n
        FROM secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1`,
      [customerEvaluation])).rows[0].n, 0);
      assert.equal((await identity.query(`SELECT count(*)::integer AS n
        FROM secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1`,
      [siblingEvaluation])).rows[0].n, 1);
      const refreshed = waitResponse(adminPage, 'GET', detailRoute);
      void refreshed.catch(() => {});
      await physicalButton(adminPage, 'Refresh progress');
      // Refresh progress is the self button. Re-select the learner to obtain
      // an authoritative current detail GET after the reset checkpoint.
      await physicalButton(adminPage, `${customerName} · 1/${page.learners.find(row =>
        row.principalId === customer.context.principalId).totalObjectives} completed`,
      '[aria-label="Learner progress"] button');
      const retiredWire = await refreshed;
      assert.equal(retiredWire.status(), 200);
      assertProgressProjection(await retiredWire.json(), {
        principalId: customer.context.principalId, objectiveId: OBJECTIVE, completed: false });
      await adminPage.waitForFunction(name => document.querySelector(`[aria-label="${name} objectives"]`)
        ?.textContent.includes('Open'), { timeout: 20000 }, customerName);
      status.resetRetiresOwnerOnly = true;
      const siblingCurrent = await progress.readSelf(sibling.context);
      assertProgressProjection(siblingCurrent, {
        principalId: sibling.context.principalId, objectiveId: OBJECTIVE, completed: true });
      const siblingBrowser = await physicalLogin(browser, origin, siblingName, password);
      contexts.push(siblingBrowser.context);
      assert.equal(siblingBrowser.account.user.role, 'customer');
      const siblingRead = waitResponse(siblingBrowser.page, 'GET', '/api/secureshop/auth/progress');
      void siblingRead.catch(() => {});
      await physicalButton(siblingBrowser.page, 'Shop settings');
      const siblingWire = await siblingRead;
      assert.equal(siblingWire.status(), 200);
      assertProgressProjection(await siblingWire.json(), {
        principalId: sibling.context.principalId, objectiveId: OBJECTIVE, completed: true });
      await siblingBrowser.page.waitForFunction(() => document.querySelector('[aria-label="Your progress"]')
        ?.textContent.includes('Completed'), { timeout: 20000 });
      status.siblingPreserved = true;

      const customerCookie = (await customerPage.cookies(`${origin}/api/secureshop/auth/session`))
        .find(cookie => cookie.name === 'dvaia_shop_session');
      assert.ok(customerCookie);
      assert.equal(await auth.logout(customerCookie.value), true);
      const denied = waitResponse(customerPage, 'GET', '/api/secureshop/auth/progress');
      void denied.catch(() => {});
      await physicalButton(customerPage, 'Refresh progress');
      assert.equal((await denied).status(), 401);
      await customerPage.waitForFunction(() => document.querySelector('section[aria-label="Shop progress"]')
        ?.textContent.includes('Sign in again to view progress.'), { timeout: 20000 });
      assert.equal(await customerPage.$('[aria-label="Your progress"]'), null);
      status.staleSessionDenied = true;
      status.noModelOrJudge = true;
    } catch (error) { failure = error; status.errors.push(String(error.message || error).slice(0, 512)); }
    finally {
      for (const context of contexts.reverse()) {
        try { await boundedCleanup('browser context', () => context.close()); }
        catch (error) { cleanupErrors.push(error); }
      }
      let browserClosed = false;
      if (browser) {
        try { await boundedCleanup('browser', () => browser.close()); browserClosed = true; }
        catch (error) { cleanupErrors.push(error); }
      }
      status.browserClosed = browserClosed && await browserExited(browser);
      if (status.browserClosed && profile) {
        try { await fs.rm(profile, { recursive: true, force: true }); status.profileRemoved = true; }
        catch (error) { cleanupErrors.push(error); }
      }
      try { await boundedCleanup('server', () => closeServer(server)); }
      catch (error) { cleanupErrors.push(error); }
      try { await boundedCleanup('browser assessment', () => composition?.closeBrowserAssessment?.()); }
      catch (error) { cleanupErrors.push(error); }
      for (const pool of [leasePool, ...Object.values(pools)]) {
        try { await boundedCleanup('database pool', () => pool.end()); }
        catch (error) { cleanupErrors.push(error); }
      }
      status.cleanupComplete = cleanupErrors.length === 0;
      status.errors.push(...cleanupErrors.map(error => String(error.message || error).slice(0, 512)));
      await fs.writeFile(evidencePath, JSON.stringify(status, null, 2), { flag: 'wx', mode: 0o600 });
    }
    if (failure) throw failure;
    if (cleanupErrors.length) throw new AggregateError(cleanupErrors,
      'Rendered progress owned cleanup failed');
    assertProgressRenderedReceipt(status);
  });
