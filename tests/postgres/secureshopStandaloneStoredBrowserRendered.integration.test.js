'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { waitForObservedCount } = require('../helpers/waitForObservedCount');

const PREFIX = 'PG_SECURESHOP_STANDALONE_BROWSER_';
const STORES = ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE'];
const OBJECTIVE = 'ss_stored_browser_execution';
const PAYLOAD = '<img src="invalid://owned-standalone-review" onerror="alert(\'owned-standalone-review\')">';
const ENABLED = process.env.SECURESHOP_STANDALONE_BROWSER_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && STORES.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

function disposableUrl(key) {
  const url = new URL(process.env[`${PREFIX}${key}_URL`]);
  assert.equal(url.protocol, 'postgresql:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.match(url.port, /^[1-9][0-9]{0,4}$/);
  assert.ok(Number(url.port) <= 65535);
  assert.equal(url.password, '');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  return url;
}
function disposableStoreUrls() {
  const names = { IDENTITY: 'identity', AGENTS: 'secureshop_agents',
    REVIEW: 'secureshop_review', COMMERCE: 'secureshop' };
  const urls = {}; let nonce; let port;
  for (const store of STORES) {
    const name = names[store];
    for (const role of ['MIGRATION', 'RUNTIME']) {
      const key = `${store}_${role}`;
      const url = disposableUrl(key);
      const match = new RegExp(`^/dvaia_test_agent_host_([0-9a-f]{12})_${name}$`).exec(url.pathname);
      assert.ok(match, `closed disposable database name required for ${key}`);
      assert.equal(url.username, `dvaia_${name}_${role.toLowerCase()}`);
      nonce ??= match[1]; port ??= url.port;
      assert.equal(match[1], nonce, 'all four stores require the same disposable run');
      assert.equal(url.port, port, 'all four stores require the same disposable cluster');
      urls[key] = url.href;
    }
    assert.equal(new URL(urls[`${store}_MIGRATION`]).pathname,
      new URL(urls[`${store}_RUNTIME`]).pathname);
  }
  assert.equal(new Set(STORES.map(store => new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return Object.freeze(urls);
}
async function count(pool, table, where, args) {
  return Number((await pool.query(`SELECT count(*)::int AS n FROM ${table} WHERE ${where}`, args)).rows[0].n);
}
async function listen(app) {
  return new Promise(resolve => { const server = app.listen(0, '127.0.0.1', () => resolve(server)); });
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
async function waitForRow(read, timeoutMs) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const value = await read();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw Object.assign(new Error('Expected durable C29 assessment was not observed'),
    { code: 'OBSERVATION_TIMEOUT' });
}
async function stableFrame(page) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const element = await page.$('iframe[title="SecureShop"]');
    const frame = element && await element.contentFrame().catch(() => null);
    if (frame && !frame.detached) return frame;
    await new Promise(resolve => setTimeout(resolve, 40));
  }
  throw new Error('Standalone opaque shop frame did not mount');
}
async function submitReview(frame, body) {
  await frame.waitForSelector('textarea[aria-label="Review body"]');
  await frame.$eval('textarea[aria-label="Review body"]', (element, value) => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(element, value);
    element.dispatchEvent(new Event('input', { bubbles: true }));
  }, body);
  await frame.waitForFunction(value => {
    const input = document.querySelector('textarea[aria-label="Review body"]');
    return input?.value === value && input.closest('form')?.querySelector('button[type="submit"]')?.disabled === false;
  }, {}, body);
  await frame.$eval('textarea[aria-label="Review body"]', element =>
    element.closest('form').querySelector('button[type="submit"]').click());
}

test('standalone customer earns C29 only from the rendered ReviewCard, browser effect, and actual Judge',
  { skip: !ENABLED, timeout: 300000 }, async t => {
    const workspace = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/');
    assert.equal(workspace, process.cwd(), 'qualification must use the current checkout without a source copy');
    const receiptPath = process.env.SECURESHOP_STANDALONE_BROWSER_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(receiptPath));
    assert.ok(!path.resolve(receiptPath).startsWith(`${workspace}${path.sep}`));
    const build = path.resolve(process.env.SECURESHOP_STANDALONE_BROWSER_BUILD || path.join(workspace, 'client/build'));
    assert.equal(build, path.join(workspace, 'client/build'), 'render the pinned current-main client build');
    await fs.access(path.join(build, 'index.html'));
    await fs.access(path.join(build, 'secureshop-frame.html'));
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(executablePath), 'pinned qualification browser executable required');
    await fs.access(executablePath);
    const modelURL = new URL(process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434');
    assert.equal(modelURL.protocol, 'http:');
    assert.ok(['127.0.0.1', 'localhost'].includes(modelURL.hostname));
    assert.equal(modelURL.port, '11434');
    assert.equal(modelURL.pathname, '/');
    assert.equal(process.env.JUDGE_PROVIDER || 'ollama', 'ollama');
    assert.equal(process.env.JUDGE_MODEL || process.env.OLLAMA_MODEL || 'llama3.1:8b', 'llama3.1:8b');

    const storeUrls = disposableStoreUrls();
    const pools = Object.fromEntries(STORES.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
      const key = `${store}_${role}`;
      return [key, new Pool({ connectionString: storeUrls[key], max: role === 'RUNTIME' ? 12 : 3 })];
    })));
    const leasePool = new Pool({ connectionString: storeUrls.IDENTITY_RUNTIME, max: 4 });
    const browserVerifier = require('../../server/services/xssBrowserQualification')
      .createXssBrowserQualification({ idleCloseMs: 1000,
        puppeteer: { launch: options => require('puppeteer').launch({ ...options, executablePath }) } });
    const status = { scope: 'current-main standalone cookie, shared scene, rendered ReviewCard, isolated browser and actual local llama3.1:8b Judge',
      passed: false, standaloneRendered: false, protectedTenantOnly: false,
      actualBrowserEffect: false, actualJudgeCredit: false, exactReplay: false,
      inertDenied: false, fixedDenied: false, siblingPrivate: false, resetFenced: false,
      renderedAdminResetCommitted: false, renderedResetRecoveryCleanupOnly: false };
    let composition; let server; let uiBrowser; let profile; let failure;
    const cleanupErrors = [];
    try {
      for (const [store, directory] of [
        ['IDENTITY', 'identity-migrations'],
        ['AGENTS', 'workshop-migrations/secureshop_agents'],
        ['REVIEW', 'workshop-migrations/secureshop_review'],
        ['COMMERCE', 'workshop-migrations/secureshop'],
      ]) await migrate(pools[`${store}_MIGRATION`], path.join(workspace, 'db/postgres', directory));
      await require('../../server/database/postgres/workshopPlatformSeed')
        .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopAssessmentSeed')
        .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopStandaloneSeed')
        .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
      const seedClient = await pools.COMMERCE_MIGRATION.connect();
      try {
        await seedClient.query('BEGIN');
        await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seedClient);
        await seedClient.query('COMMIT');
      } catch (error) { await seedClient.query('ROLLBACK'); throw error; }
      finally { seedClient.release(); }

      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
      const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
      const auth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const suffix = randomUUID().slice(0, 8);
      const customerUsername = `render_${suffix}`;
      const password = 'disposable-rendered-c29';
      const customerRegistration = await auth.register({ username: customerUsername,
        email: `${customerUsername}@example.invalid`, password, role: 'customer' });
      const siblingRegistration = await auth.register({ username: `sibling_${suffix}`,
        email: `sibling_${suffix}@example.invalid`, password, role: 'customer' });
      const admin = await auth.login({ username: 'student_admin', password: 'student123' });
      const objectiveCatalog = require('../../server/services/secureshopAssessmentCatalog')
        .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
      const beforeSetting = (await objectiveCatalog.list(admin.context)).objectives
        .find(value => value.objectiveId === OBJECTIVE);
      assert.equal(beforeSetting.qualification, 'native-browser-judge');
      assert.equal(beforeSetting.enabled, false);
      const enabled = await objectiveCatalog.set(admin.context,
        { objectiveId: OBJECTIVE, enabled: true, expectedRevision: beforeSetting.revision });
      assert.equal(enabled.enabled, true);
      assert.equal(await count(identity, 'secureshop_auth.assessment_configuration',
        'objective_id=$1', [OBJECTIVE]), 1, 'enablement is scoped to the disposable tenant');
      assert.equal(await count(identity, 'workshop_platform.objective_judgments',
        'objective_id=$1', [OBJECTIVE]), 0, 'no platform progress may be written');
      status.protectedTenantOnly = true;

      const progress = require('../../server/database/postgres/workshopProgressRepository')
        .createWorkshopProgressRepository(identity);
      const reset = require('../../server/services/secureshopCleanupComposition')
        .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, leasePool });
      const gradingBootstrap = await require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
          progress, resetComposition: reset,
          expectedIdentityDatabase: new URL(storeUrls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(storeUrls.AGENTS_RUNTIME).pathname.slice(1) });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository')
          .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
        reviewPool: review, launches: reset.launches });
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identity);
      const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
        .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
      const actualJudge = require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge();
      let browserCalls = 0; let judgeCalls = 0; let positiveBrowser = null;
      const judge = async input => { judgeCalls++; return actualJudge(input); };
      const browserQualification = { async qualify(...args) {
        browserCalls++;
        const value = await browserVerifier.qualify(...args);
        if (!positiveBrowser) positiveBrowser = value;
        return value;
      } };
      composition = require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: reset,
          gradingBootstrap, scenes, modeAuthority, fixtures: [], requiredObjectives: [OBJECTIVE],
          jwtSecret: 'disposable-rendered-c29-persona-secret-at-least-32-bytes',
          agentRuntime: { provider: {
            async chat() { throw Error('Product or review model outside C29'); },
            async finalResponse() { throw Error('Product or review final model outside C29'); },
          } },
          judge, browserQualification });
      await composition.repositories.personas.ensureTemplates();
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });
      const protectedReset = require('../../server/services/secureshopStandaloneReset')
        .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
          launches: composition.launches, scenes,
          resetCoordinator: reset.launchResetCoordinator,
          preflight: reset.sceneResetPreflight });
      // Provision the durable product/review scene under the registration
      // session. The rendered login below creates a different execution grant.
      const firstReady = await bootstrap(customerRegistration.context);
      const firstScope = await composition.launches.resolveCapability(firstReady.bearer);
      const firstActor = await composition.personaAuth.authenticateBoundToken({ scope: firstScope,
        token: firstReady.persona.token });
      await composition.catalog.prepareTarget({ scope: firstScope, persona: firstActor.user });
      const firstReviewTarget = await composition.runtime.application.resolveTarget(firstScope);
      assert.match(firstReviewTarget.targetId, /^[0-9a-f-]{36}$/i);
      await auth.logout(customerRegistration.token);
      const mode = require('../../server/services/secureshopStandaloneMode')
        .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
      const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
        .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
          reviewPool: review, commercePool: commerce });
      const mounted = Object.freeze({ ...composition,
        standaloneAuth: Object.freeze({ service: auth, bootstrap, mode,
          assessmentObjectives: objectiveCatalog, reset: protectedReset }), publicCatalog,
        personaInbox: Object.freeze({ ready: true, router: express.Router() }),
        mcpTrust: Object.freeze({ ready: true, router: express.Router() }),
        ssrf: Object.freeze({ ready: true, router: express.Router() }),
      });
      const bound = await require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          authenticateToken: (_req, response) => response.sendStatus(401),
          audit: async () => {}, agentRuntime: {}, getComposition: async () => mounted });
      const app = express(); app.use(express.json());
      const browserAttempts = []; let reviewPosts = 0;
      app.use('/api/secureshop', (req, _res, next) => {
        if (req.method === 'POST' && /^\/products\/\d+\/reviews$/.test(req.path)) reviewPosts++;
        if (req.method === 'POST' && /\/browser-attempt$/.test(req.path)) browserAttempts.push(req.body?.request_id);
        next();
      });
      server = await listen(app);
      const origin = `http://127.0.0.1:${server.address().port}`;
      app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthRouter({ service: auth, bootstrap, mode,
          assessmentObjectives: objectiveCatalog, reset: protectedReset,
          allowedOrigins: [origin], secureCookies: false }));
      app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
        .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
      app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog')
        .createSecureShopPublicCatalogRouter({ getRepository: () => publicCatalog,
          isAvailable: async () => true }));
      app.use('/api', (_request, response) => response.status(404).json({ error: 'Outside C29 qualifier' }));
      app.use(express.static(build, { setHeaders: response => response.set('Access-Control-Allow-Origin', '*') }));
      app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));

      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-standalone-browser-'));
      uiBrowser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
        executablePath });
      const page = await uiBrowser.newPage();
      await page.setViewport({ width: 1280, height: 900 });
      const pageErrors = []; const dialogs = []; const browserAttemptResponses = [];
      page.on('pageerror', error => pageErrors.push(error.message.slice(0, 200)));
      page.on('dialog', dialog => { dialogs.push(dialog.message()); void dialog.dismiss(); });
      page.on('response', response => {
        if (response.request().method() === 'POST' && /\/browser-attempt$/.test(new URL(response.url()).pathname))
          browserAttemptResponses.push(response.status());
      });
      await page.setRequestInterception(true);
      let holdAdminCatalog = false;
      const heldAdminCatalog = [];
      page.on('request', request => {
        if (!request.url().startsWith(`${origin}/`)) return request.abort();
        if (holdAdminCatalog && request.method() === 'GET'
            && new URL(request.url()).pathname === '/api/secureshop/products') {
          heldAdminCatalog.push(request);
          return;
        }
        return request.continue();
      });
      const navigation = await page.goto(`${origin}/secureshop/login`);
      assert.equal(navigation.status(), 200);
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', customerUsername);
      await page.type('#ss-login-pw', password);
      await page.click('button[type="submit"]');
      const frame = await stableFrame(page);
      await frame.waitForSelector('a[href="/secureshop/catalog"]', { timeout: 20000 });
      await frame.click('a[href="/secureshop/catalog"]');
      await frame.waitForSelector('a[href^="/secureshop/product/"]', { timeout: 20000 });
      const productId = Number(await frame.$eval('a[href^="/secureshop/product/"]',
        anchor => new URL(anchor.href).pathname.match(/\/(\d+)$/)?.[1]));
      assert.ok(Number.isSafeInteger(productId) && productId > 0);
      await frame.$eval('a[href^="/secureshop/product/"]', element => element.click());
      await submitReview(frame, PAYLOAD);
      await waitForObservedCount({ read: () => browserAttempts.length, expected: 1, timeoutMs: 30000 });
      await waitForObservedCount({ read: () => browserAttemptResponses.length, expected: 1, timeoutMs: 30000 });
      assert.equal(browserAttemptResponses[0], 200, 'rendered browser-attempt request must be admitted');
      const requestId = browserAttempts[0];
      assert.match(requestId, /^[0-9a-f-]{36}$/i);
      const cookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.equal(cookie?.httpOnly, true);
      const base = await auth.authenticate(cookie.value);
      const customer = await auth.establishTenantContext(base);
      assert.equal(customer.principalId, customerRegistration.context.principalId);
      const ready = await bootstrap(base);
      const scope = await composition.launches.resolveCapability(ready.bearer);
      const verified = await composition.personaAuth.authenticateBoundToken({ scope,
        token: ready.persona.token });
      assert.equal(verified.user.id, customer.shopUserId);
      assert.notEqual(scope.launchId, firstScope.launchId);
      assert.notEqual(scope.platformSessionId, firstScope.platformSessionId);
      const judgments = async () => (await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
        WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY created_at`,
      [customer.tenantId, customer.principalId, OBJECTIVE])).rows;
      const judgment = await waitForRow(async () => (await judgments())
        .find(row => row.verdict !== null), 115000);
      assert.equal(judgment.verdict, 'pass', 'actual Judge must accept the attributed browser effect');
      assert.equal(judgment.disposition, 'awarded');
      assert.equal(judgment.result_json.provider, 'ollama');
      assert.equal(judgment.result_json.model, 'llama3.1:8b');
      assert.equal(judgment.judge_observations?.calls?.some(call =>
        call.provider === 'ollama' && call.model === 'llama3.1:8b'), true);
      assert.equal(browserCalls, 1); assert.equal(judgeCalls, 1); assert.equal(reviewPosts, 1);
      assert.equal(positiveBrowser?.targetEventExecuted, true);
      assert.equal(positiveBrowser?.targetEffectObserved, true);
      assert.ok(dialogs.every(value => value === 'owned-standalone-review'),
        'only the owned review marker may open a browser dialog');
      status.standaloneRendered = true; status.actualBrowserEffect = true;
      status.actualJudgeCredit = true;

      const reviews = (await review.query(`SELECT r.id,r.body,r.body_sha256,r.submission_id,
        r.submitted_by_shop_user_id,t.target_id,t.launch_id,t.generation,t.original_platform_owner_id,
        t.original_platform_session_id
        FROM secureshop_review.reviews r JOIN secureshop_review.review_targets t USING(target_id)
        WHERE r.source_kind='learner' AND r.submitted_by_shop_user_id=$1`,
      [customer.shopUserId])).rows;
      assert.equal(reviews.length, 1);
      assert.equal(reviews[0].body, PAYLOAD);
      assert.equal(reviews[0].target_id, firstReviewTarget.targetId);
      assert.equal(reviews[0].launch_id, firstScope.launchId);
      assert.equal(Number(reviews[0].original_platform_session_id), firstScope.platformSessionId);
      assert.notEqual(reviews[0].launch_id, scope.launchId,
        'the accepted review retains immutable storage birth after a new login');
      assert.equal(reviews[0].body_sha256.toString('hex'), createHash('sha256').update(PAYLOAD).digest('hex'));
      assert.equal(reviews[0].original_platform_owner_id, customer.ownerId);
      const packet = JSON.parse(judgment.packet);
      const proof = packet.evidence.find(value => value.id === 'stored_browser_receipt').content;
      const renderer = require('../../server/services/secureshopReviewCardRenderer')
        .loadSecureShopReviewCardRenderer();
      assert.equal(proof.component.id, 'SecureShop.ReviewCard');
      assert.equal(proof.component.sourceSha256, renderer.sourceSha256);
      assert.equal(proof.component.artifactSha256, renderer.artifactSha256);
      assert.equal(proof.source.reviewId, Number(reviews[0].id));
      assert.equal(proof.source.submissionId, reviews[0].submission_id);
      assert.equal(proof.browser.targetEventExecuted, true);
      assert.equal(proof.browser.targetEffectObserved, true);
      assert.equal(proof.execution.effectReceipt.status, 'completed');
      assert.equal(proof.execution.effectReceipt.runId, judgment.run_id);
      assert.equal(await count(identity, 'secureshop_auth.assessment_completions',
        'tenant_id=$1 AND principal_id=$2 AND objective_id=$3',
        [customer.tenantId, customer.principalId, OBJECTIVE]), 1);
      assert.equal(await count(identity, 'workshop_platform.completions',
        'workshop_key=$1 AND objective_id=$2', ['secureshop_agent_security', OBJECTIVE]), 0);

      const replay = await composition.browserAssessment.runAttempt({ scope,
        persona: verified.user, personaSession: { sessionId: verified.sessionId,
          authorityVersion: verified.authorityVersion }, requestId, productId, reviewId: Number(reviews[0].id) });
      assert.equal(replay.replayed, true);
      assert.equal(replay.completed, true);
      assert.equal(browserCalls, 1); assert.equal(judgeCalls, 1);
      assert.equal((await judgments()).length, 1);
      status.exactReplay = true;

      const sibling = await auth.establishTenantContext(siblingRegistration.context);
      assert.equal(sibling.tenantId, customer.tenantId, 'principals share the same shop practice');
      assert.notEqual(sibling.principalId, customer.principalId);
      assert.equal(await count(identity, 'secureshop_auth.assessment_completions',
        'tenant_id=$1 AND principal_id=$2 AND objective_id=$3',
        [sibling.tenantId, sibling.principalId, OBJECTIVE]), 0);
      const recovery = require('../../server/services/secureshopAssessmentRecovery')
        .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth,
          bootstrap, launches: composition.launches, personaAuth: composition.personaAuth,
          personaAuthority: gradingBootstrap.personaAuthority, judge });
      assert.deepEqual((await recovery.list(siblingRegistration.context)).judgments, []);
      status.siblingPrivate = true;

      // The inert source and fixed mode use the same current actor and real
      // browser/Judge dependencies. Neither can create a second completion.
      const inert = await composition.runtime.application.submitReview({ scope,
        persona: verified.user, personaSession: { sessionId: verified.sessionId,
          authorityVersion: verified.authorityVersion }, submissionId: randomUUID(), productId,
        authorId: customer.shopUserId, body: 'Ordinary product feedback without active content.', rating: 4 });
      const inertResult = await composition.browserAssessment.runAttempt({ scope,
        persona: verified.user, personaSession: { sessionId: verified.sessionId,
          authorityVersion: verified.authorityVersion }, requestId: randomUUID(),
        productId, reviewId: inert.id });
      assert.equal(inertResult.completed, false);
      assert.equal(inertResult.browser.executed, false);
      const inertJudgment = (await identity.query(`SELECT verdict,disposition,packet
        FROM secureshop_auth.assessment_judgments
        WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3`,
      [customer.tenantId, customer.principalId, inertResult.judgment.evaluationId])).rows[0];
      assert.ok(inertJudgment, 'inert attempt retains its own canonical judgment');
      assert.ok(!['awarded', 'already_complete'].includes(inertJudgment.disposition));
      assert.equal(JSON.parse(inertJudgment.packet).facts.attributed_browser_execution, false);
      assert.equal(await count(identity, 'secureshop_auth.assessment_completions',
        'tenant_id=$1 AND principal_id=$2 AND objective_id=$3',
        [customer.tenantId, customer.principalId, OBJECTIVE]), 1);
      status.inertDenied = true;
      const initialMode = await mode.get(base);
      const fixed = await mode.set(base, { mode: 'fixed', expectedRevision: initialMode.revision });
      assert.equal(fixed.mode, 'fixed');
      const fixedCalls = { browser: browserCalls, judge: judgeCalls };
      const fixedResult = await composition.browserAssessment.runAttempt({ scope,
        persona: verified.user, personaSession: { sessionId: verified.sessionId,
          authorityVersion: verified.authorityVersion }, requestId: randomUUID(),
        productId, reviewId: Number(reviews[0].id) });
      assert.equal(fixedResult.status, 'ineligible');
      assert.equal(browserCalls, fixedCalls.browser); assert.equal(judgeCalls, fixedCalls.judge);
      status.fixedDenied = true;

      // Begin-reset is a durable authority fence. Full standalone cleanup is
      // deliberately not inferred from this operation; its aggregate path
      // requires a separately qualified tenant progress checkpoint.
      const resetResult = await composition.launches.beginReset({
        launchId: scope.launchId, platformSessionId: scope.platformSessionId,
        platformOwnerId: scope.platformOwnerId, expectedGeneration: scope.generation,
        idempotencyKey: randomUUID() });
      assert.match(resetResult.resetId, /^[0-9a-f-]{36}$/i);
      assert.equal((await identity.query(`SELECT status FROM identity.secureshop_launch_resets
        WHERE reset_id=$1`, [resetResult.resetId])).rows[0].status, 'fenced');
      assert.equal(await count(identity, 'secureshop_auth.assessment_contributions',
        'tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3',
        [customer.tenantId, customer.principalId, judgment.evaluation_id]), 1,
      'accepted assessment history remains immutable');
      await assert.rejects(composition.browserAssessment.runAttempt({ scope,
        persona: verified.user, personaSession: { sessionId: verified.sessionId,
          authorityVersion: verified.authorityVersion }, requestId: randomUUID(),
        productId, reviewId: Number(reviews[0].id) }), error => Boolean(error));
      assert.equal(judgeCalls, fixedCalls.judge);
      status.resetFenced = true;
      assert.deepEqual(pageErrors, []);
      t.diagnostic(JSON.stringify({ stage: 'standalone-c29-qualified',
        tenantId: customer.tenantId, principalId: customer.principalId,
        evaluationId: judgment.evaluation_id, runId: judgment.run_id,
        sourceSha256: reviews[0].body_sha256.toString('hex'),
        provider: judgment.result_json.provider, model: judgment.result_json.model,
        effectKey: proof.execution.effectReceipt.effectKey,
        browserCalls, judgeCalls, resetId: resetResult.resetId,
        resetScope: 'durable admission fence only; aggregate standalone cleanup unqualified' }));

      // Finish the customer fence as fixture preparation through the canonical
      // aggregate coordinator. This is not a customer-authorized HTTP reset.
      const prepared = await reset.launchResetCoordinator.recover(resetResult.resetId);
      assert.equal(prepared.status, 'fenced');
      const originalAssessment = (await judgments()).find(row => row.evaluation_id === judgment.evaluation_id);
      assert.equal(originalAssessment.verdict, 'pass', 'immutable C29 judgment remains readable after cleanup');
      const adminPreparation = await bootstrap(admin.context);
      const adminPreparationScope = await composition.launches.resolveCapability(adminPreparation.bearer);
      const adminPreparationActor = await composition.personaAuth.authenticateBoundToken({
        scope: adminPreparationScope, token: adminPreparation.persona.token });
      await composition.catalog.prepareTarget({ scope: adminPreparationScope,
        persona: adminPreparationActor.user });
      await composition.runtime.application.resolveTarget(adminPreparationScope);
      const preparedScenes = await scenes.list(adminPreparationScope);
      assert.equal(preparedScenes.length, 1, 'admin UI receives one selected shared practice');

      await auth.logout(cookie.value);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/login`)).status()),
        'repeat navigation must load the current login document or validate its cached copy');
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', 'student_admin');
      await page.type('#ss-login-pw', 'student123');
      // If this route issues a catalog read, hold it so it cannot create this
      // session's scene grant before reset readiness does.
      holdAdminCatalog = true;
      await page.click('button[type="submit"]');
      await stableFrame(page);
      const adminCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.equal(adminCookie?.httpOnly, true);
      const adminUiBase = await auth.authenticate(adminCookie.value);
      const adminUiExecution = await auth.establishTenantContext(adminUiBase);
      const adminUiScope = await composition.launches.readActiveMetadata({
        platformOwnerId: adminUiExecution.ownerId,
        platformSessionId: adminUiExecution.sessionId,
      });
      assert.ok(adminUiScope, 'admin UI has its own active launch before readiness');
      assert.notEqual(adminUiScope.launchId, adminPreparationScope.launchId);
      const adminGrantCount = async () => count(identity, 'identity.secureshop_scene_execution_grants',
        'scene_id=$1 AND launch_id=$2 AND generation=$3 AND original_platform_session_id=$4',
        [preparedScenes[0].id, adminUiScope.launchId, adminUiScope.generation,
          adminUiExecution.sessionId]);
      assert.equal(await adminGrantCount(), 0,
        'admin readiness must not depend on an unrelated Home catalog read');
      const readinessResponse = page.waitForResponse(response => response.request().method() === 'GET'
        && new URL(response.url()).pathname === '/api/secureshop/auth/reset-readiness');
      await page.waitForSelector('button[aria-controls="secureshop-settings"]');
      await page.click('button[aria-controls="secureshop-settings"]');
      const readinessHttp = await readinessResponse;
      assert.equal(readinessHttp.status(), 200);
      const adminReadiness = await readinessHttp.json();
      assert.equal(adminReadiness.available, true);
      assert.equal(adminReadiness.scene.id, preparedScenes[0].id);
      assert.equal(await adminGrantCount(), 1,
        'readiness binds the existing selected scene to the current admin launch');
      await page.waitForFunction(() => [...document.querySelectorAll('#secureshop-settings button')]
        .some(button => button.textContent === 'Reset shared practice'));
      await page.$eval('#secureshop-settings', element => [...element.querySelectorAll('button')]
        .find(button => button.textContent === 'Reset shared practice').click());
      await page.waitForSelector('[role="alertdialog"] button[data-confirm-reset]');
      assert.equal(await page.$eval('[role="alertdialog"]', element =>
        element.textContent.includes('This clears mutable practice data for every customer and merchant')), true);
      const resetResponse = page.waitForResponse(response => response.request().method() === 'POST'
        && new URL(response.url()).pathname === '/api/secureshop/auth/reset');
      await page.click('[role="alertdialog"] button[data-confirm-reset]');
      const resetHttp = await resetResponse;
      assert.equal(resetHttp.status(), 200);
      const adminReset = await resetHttp.json();
      assert.equal(adminReset.status, 'committed');
      assert.equal(adminReset.cleanupComplete, true);
      holdAdminCatalog = false;
      await Promise.allSettled(heldAdminCatalog.map(request => request.abort()));
      assert.equal((await identity.query(`SELECT status FROM identity.secureshop_launch_resets
        WHERE reset_id=$1`, [adminReset.resetId])).rows[0].status, 'committed');
      assert.equal(await count(identity, 'identity.secureshop_scene_target_retirements',
        'scene_id=$1', [adminReadiness.scene.id]) >= 1, true);
      assert.equal(await count(identity, 'identity.secureshop_target_cleanup_history',
        'operation_id=$1', [adminReset.resetId]) >= 2, true);
      assert.equal(browserCalls, fixedCalls.browser);
      assert.equal(judgeCalls, fixedCalls.judge);
      status.renderedAdminResetCommitted = true;

      await stableFrame(page);
      const activeCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.equal(activeCookie?.httpOnly, true);
      const activeBase = await auth.authenticate(activeCookie.value);
      const activeReady = await bootstrap(activeBase);
      const activeScope = await composition.launches.resolveCapability(activeReady.bearer);
      const activeActor = await composition.personaAuth.authenticateBoundToken({
        scope: activeScope, token: activeReady.persona.token });
      await composition.catalog.prepareTarget({ scope: activeScope, persona: activeActor.user });
      await composition.runtime.application.resolveTarget(activeScope);
      const laterScenes = await scenes.list(activeScope);
      assert.equal(laterScenes.length, 1);
      const pendingReset = await composition.launches.beginReset({ ...activeScope,
        expectedGeneration: activeScope.generation, idempotencyKey: randomUUID() });
      assert.equal((await identity.query(`SELECT status FROM identity.secureshop_launch_resets
        WHERE reset_id=$1`, [pendingReset.resetId])).rows[0].status, 'fenced');
      await auth.logout(activeCookie.value);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/login`)).status()),
        'repeat navigation must load the current login document or validate its cached copy');
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', 'student_admin');
      await page.type('#ss-login-pw', 'student123');
      await page.click('button[type="submit"]');
      await page.waitForFunction(() => document.body.textContent.includes('Finish a saved practice reset.'));
      assert.equal(await page.$('iframe[title="SecureShop"]'), null,
        'pending recovery is shown before another frame bootstrap');
      assert.equal(await page.$eval('main', element => element.textContent
        .includes('The original shop session is no longer active.')), true);
      const recoveryResponse = page.waitForResponse(response => response.request().method() === 'POST'
        && new URL(response.url()).pathname === '/api/secureshop/auth/reset-recovery');
      await page.$eval('main', element => [...element.querySelectorAll('button')]
        .find(button => button.textContent === 'Read and resume saved reset').click());
      const recoveryHttp = await recoveryResponse;
      assert.equal(recoveryHttp.status(), 200);
      const recoveredReset = await recoveryHttp.json();
      assert.equal(recoveredReset.resetId, pendingReset.resetId);
      assert.equal(recoveredReset.cleanupComplete, true);
      assert.equal(recoveredReset.activated, false);
      assert.notEqual((await identity.query(`SELECT status FROM identity.secureshop_launches
        WHERE launch_id=$1`, [activeScope.launchId])).rows[0].status, 'active');
      assert.equal(await count(identity, 'identity.secureshop_target_cleanup_history',
        'operation_id=$1', [pendingReset.resetId]) >= 2, true);
      await stableFrame(page);
      const recoveredCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.equal(recoveredCookie?.httpOnly, true);
      const recoveredBase = await auth.authenticate(recoveredCookie.value);
      const recoveredLaunch = await bootstrap(recoveredBase);
      const recoveredScope = await composition.launches.resolveCapability(recoveredLaunch.bearer);
      assert.notEqual(recoveredScope.launchId, activeScope.launchId,
        'cleanup-only recovery never reactivates the original launch');
      assert.equal((await scenes.list(recoveredScope)).some(row => row.id === laterScenes[0].id), false,
        'retired practice stays absent after the rendered recovery remount');
      assert.equal(browserCalls, fixedCalls.browser);
      assert.equal(judgeCalls, fixedCalls.judge);
      status.renderedResetRecoveryCleanupOnly = true;
      assert.deepEqual(pageErrors, []);
      status.passed = true;
    } catch (error) { failure = error; }
    finally {
      for (const close of [() => uiBrowser?.close(), () => closeServer(server),
        () => composition?.closeBrowserAssessment(), () => browserVerifier.close(),
        () => profile && fs.rm(profile, { recursive: true, force: true }),
        () => leasePool.end(), ...Object.values(pools).map(pool => () => pool.end())]) {
        try { await close(); } catch (error) { cleanupErrors.push(error); }
      }
      if (cleanupErrors.length) status.passed = false;
      const written = { ...status, cleanupComplete: cleanupErrors.length === 0,
        ...(failure ? { failure: { name: failure.name, code: failure.code || null } } : {}) };
      try { await fs.writeFile(receiptPath, JSON.stringify(written, null, 2),
        { flag: 'wx', mode: 0o600 }); }
      catch (error) { cleanupErrors.push(error); }
    }
    if (cleanupErrors.length) throw new AggregateError(cleanupErrors,
      'Standalone rendered C29 cleanup or evidence write failed');
    if (failure) throw failure;
    assert.equal(status.passed, true);
  });
