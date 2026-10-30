'use strict';

// Actual-model and rendered-browser qualification. The launcher owns every
// PostgreSQL store, browser profile, model connection, and evidence path.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomUUID, createHash, randomBytes } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { TICKET_SCOPE, TICKET_FLAGS, assertTicketRenderedReceipt, assertTicketActorWire,
  captureTicketAssessmentResponse, waitForOriginalAssessment } =
  require('../fixtures/secureshopTicketRenderedQualification');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_CUSTOMER_TICKET_BROWSER_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const OBJECTIVE = 'ss_ticket_stored_browser_execution';
const ENABLED = process.env.SECURESHOP_CUSTOMER_TICKET_BROWSER_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && Object.keys(STORES).every(store => ['RUNTIME', 'MIGRATION']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const sha = value => createHash('sha256').update(value).digest('hex');

function storeUrls() {
  const urls = {}; let nonce, port;
  for (const [store, name] of Object.entries(STORES)) {
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const url = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
      assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.username, `dvaia_${name}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      const match = /^\/owasp_ai_goat_test_agent_host_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(url.pathname);
      assert.ok(match && match[2] === name); assert.ok(Number(url.port) > 0 && Number(url.port) <= 65535);
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
  return new Promise(resolve => { const server = app.listen(0, '127.0.0.1', () => resolve(server)); });
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
  throw Error('Owned shop frame did not mount');
}
async function clickText(frame, label, root = 'button') {
  const handle = await frame.waitForFunction(({ label, root }) => {
    const matches = [...document.querySelectorAll(root)].filter(node =>
      node.textContent.trim() === label && !node.disabled
      && node.getClientRects().length && getComputedStyle(node).visibility !== 'hidden');
    return matches.length === 1 ? matches[0] : null;
  }, { timeout: 20000, polling: 'raf' }, { label, root });
  const element = handle.asElement(); assert.ok(element);
  await element.evaluate(node => node.scrollIntoView({ block: 'center' }));
  await element.click();
}
async function clickTicketRow(frame, ticketId, subject) {
  const selector = `button[aria-label="Read ticket ${ticketId}: ${subject}"]`;
  const button = await frame.waitForSelector(selector, { visible: true, timeout: 20000 });
  assert.equal(await button.evaluate(node => node.disabled), false);
  await button.click();
}
const waitResponse = (page, method, pathname, timeout = 90000) =>
  page.waitForResponse(response => response.request().method() === method
    && new URL(response.url()).pathname === pathname, { timeout });
async function physicalMode(page, label) {
  await clickText(page, 'Shop settings');
  await page.waitForSelector('aside[aria-label="Shop settings"]');
  await page.waitForFunction(() => document.querySelector(
    '[role="group"][aria-label="Shop feature mode"]')?.textContent.includes('Current:'),
  { timeout: 20000 });
  const current = await page.$eval('[role="group"][aria-label="Shop feature mode"]',
    node => node.textContent.includes('Current: Fixed') ? 'Fixed'
      : node.textContent.includes('Current: Vulnerable') ? 'Vulnerable' : null);
  assert.ok(current, 'real current shop mode required');
  if (current !== label) {
    const response = waitResponse(page, 'POST', '/api/secureshop/auth/mode', 20000);
    void response.catch(() => {});
    await clickText(page, label, '[role="group"][aria-label="Shop feature mode"] button');
    assert.equal((await response).status(), 200);
  }
  await page.waitForFunction(expected => document.querySelector(
    '[role="group"][aria-label="Shop feature mode"]')
    ?.textContent.includes(`Current: ${expected}`), { timeout: 20000 }, label);
  await clickText(page, 'Shop settings');
  await page.waitForSelector('aside[aria-label="Shop settings"]', { hidden: true });
}
function headersFrom(request) {
  const headers = request.headers();
  assert.match(headers.authorization || '', /^Bearer [A-Za-z0-9_.-]+$/);
  assert.match(headers['x-owasp-ai-goat-secureshop-launch'] || '', /^[A-Za-z0-9_-]{43}$/);
  return { authorization: headers.authorization,
    'x-owasp-ai-goat-secureshop-launch': headers['x-owasp-ai-goat-secureshop-launch'] };
}
async function protectedGet(origin, pathname, headers, status = 200) {
  const response = await fetch(`${origin}${pathname}`, { headers,
    redirect: 'error', signal: AbortSignal.timeout(10000) });
  assert.equal(response.status, status);
  return response.json();
}
async function assessmentRows(identity, principal) {
  return (await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
    WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,
  [principal.tenantId, principal.principalId, OBJECTIVE])).rows;
}

test('one genuine customer ticket is fixed-inert then browser-executed in a distinct admin grant',
  { skip: !ENABLED, timeout: 300000 }, async () => {
    assert.equal(process.cwd(), ROOT); assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'), ROOT);
    const evidencePath = process.env.SECURESHOP_CUSTOMER_TICKET_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidencePath));
    assert.ok(!path.resolve(evidencePath).startsWith(`${ROOT}${path.sep}`));
    const build = path.resolve(process.env.SECURESHOP_CUSTOMER_TICKET_BUILD || '/');
    assert.equal(build, path.join(ROOT, 'client/build'));
    for (const filename of ['index.html', 'secureshop-frame.html',
      'secureshop-ticket-renderer/manifest.json', 'secureshop-ticket-renderer/renderer.js'])
      await fs.access(path.join(build, filename));
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(executablePath)); await fs.access(executablePath);
    assert.equal(process.env.LAB_MODE, 'vuln');
    assert.equal(process.env.JUDGE_PROVIDER || 'ollama', 'ollama');
    assert.equal(process.env.JUDGE_MODEL || MODEL, MODEL);
    const modelURL = new URL(process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434');
    assert.equal(modelURL.origin, 'http://127.0.0.1:11434');
    const tags = await (await fetch(`${modelURL.origin}/api/tags`,
      { signal: AbortSignal.timeout(5000) })).json();
    assert.equal(tags.models.find(row => row.name === MODEL)?.digest, MODEL_DIGEST);
    const urls = storeUrls();
    const pools = Object.fromEntries(Object.entries(urls).map(([key, connectionString]) =>
      [key, new Pool({ connectionString, max: key.endsWith('RUNTIME') ? 12 : 3,
        connectionTimeoutMillis: 1500, statement_timeout: 8000 })]));
    const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4 });
    const status = Object.fromEntries(TICKET_FLAGS.map(flag => [flag, false]));
    Object.assign(status, { scope: TICKET_SCOPE, passed: false, actorCalls: 0,
      judgeCalls: 0, roleTurns: 0, browserEffects: 0, genuineCredit: 0,
      cleanupErrors: [], errors: [] });
    const wirePath = path.join(path.dirname(evidencePath), 'ticket-original-wire.json');
    let reset, composition, transport, browser, page, profile, server, failure;
    let stage = 'setup', originalModelURL = process.env.OLLAMA_BASE_URL;
    const requests = [], pageErrors = [], dialogs = [], judgePackets = [], judgeResults = [], actorSpans = [];
    const assessmentHttpCaptures = [];
    const saveWire = async () => fs.writeFile(wirePath, JSON.stringify({ model: MODEL,
      digest: MODEL_DIGEST, calls: transport?.calls || [], requests, pageErrors,
      judgePackets, assessmentHttpCaptures, stage }, null, 2), { mode: 0o600 });
    try {
      for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
        ['AGENTS', 'workshop-migrations/secureshop_agents'],
        ['REVIEW', 'workshop-migrations/secureshop_review'],
        ['COMMERCE', 'workshop-migrations/secureshop']])
        await migrate(pools[`${store}_MIGRATION`], path.join(ROOT, 'db/postgres', directory));
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
      const suffix = randomUUID().slice(0, 8), username = `ticket_browser_${suffix}`;
      const password = 'disposable-ticket-browser-only';
      const customerRegistration = await auth.register({ username, password,
        email: `${username}@owned.invalid`, role: 'customer' });
      const siblingRegistration = await auth.register({ username: `ticket_peer_${suffix}`, password,
        email: `ticket-peer-${suffix}@owned.invalid`, role: 'customer' });
      const peerMerchant = await auth.register({ username: `ticket_merchant_${suffix}`, password,
        email: `ticket-merchant-${suffix}@owned.invalid`, role: 'merchant' });
      const peerTenantId = randomUUID(), peerSlug = `ticket_peer_tenant_${suffix}`;
      const peerTenant = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO
        secureshop_auth.tenants (tenant_id,slug) VALUES($1,$2) RETURNING owner_id`,
      [peerTenantId, peerSlug])).rows[0];
      for (const [registration, role] of [[siblingRegistration, 'customer'],
        [peerMerchant, 'merchant']]) {
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,$4)`,
        [peerTenantId, registration.context.principalId,
          registration.context.shopUserId, role]);
      }
      await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants
        SET seed_merchant_id=$2 WHERE tenant_id=$1`,
      [peerTenantId, peerMerchant.context.shopUserId]);
      const peerAdminId = randomUUID(), peerAdminName = `ticket_admin_${suffix}`;
      const peerAdminPassword = 'disposable-ticket-peer-admin';
      const peerAdminHash = await require('bcryptjs').hash(peerAdminPassword, 12);
      const peerAdminRow = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO
        secureshop_auth.principals (principal_id,username,email,password_hash,role)
        VALUES($1,$2,$3,$4,'admin') RETURNING shop_user_id`,
      [peerAdminId, peerAdminName, `${peerAdminName}@owned.invalid`,
        peerAdminHash])).rows[0];
      await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
        (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
      [peerTenantId, peerAdminId, peerAdminRow.shop_user_id]);
      const peerAuth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity,
              executionTenantSlug: peerSlug }) });
      const peerAdminLogin = await peerAuth.login({ username: peerAdminName,
        password: peerAdminPassword });
      const peerPrincipal = await peerAuth.establishTenantContext(peerAdminLogin.context);
      assert.equal(peerPrincipal.tenantId, peerTenantId);
      assert.equal(peerPrincipal.ownerId, peerTenant.owner_id);
      const adminLogin = await auth.login({ username: 'student_admin', password: 'student123' });
      const objectiveCatalog = require('../../server/services/secureshopAssessmentCatalog')
        .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
      const objective = (await objectiveCatalog.list(adminLogin.context)).objectives
        .find(row => row.objectiveId === OBJECTIVE);
      assert.equal(objective?.qualification, 'native-browser-judge');
      assert.equal(objective.enabled, false);
      assert.equal((await objectiveCatalog.set(adminLogin.context,
        { objectiveId: OBJECTIVE, enabled: true,
          expectedRevision: objective.revision })).enabled, true);
      status.canonicalObjectiveEnabled = true;
      const progress = require('../../server/database/postgres/workshopProgressRepository')
        .createWorkshopProgressRepository(identity);
      const audit = require('../../server/services/secureshopBoundAuditComposition')
        .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
          includeRunArtifacts: true });
      reset = require('../../server/services/secureshopCleanupComposition')
        .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, leasePool, audit });
      transport = await require('./secureshopMailActualTransport')
        .createMailActualTransport({ maxHttpCalls: 6, allowMetadata: true });
      process.env.OLLAMA_BASE_URL = transport.judgeUrl;
      const configuredJudge = require('../../server/agent-runtime/objectiveJudge')
        .createObjectiveJudge({ observeExecutionTranscript: packet => judgePackets.push(packet) });
      const judge = async input => {
        const result = await configuredJudge(input); judgeResults.push(result);
        status.judgeCalls = transport.calls.filter(call => call.kind === 'judge').length;
        assert.ok(status.judgeCalls <= 2); return result;
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
          const start = transport.calls.length;
          const result = await invoke({ ...input, signal: AbortSignal.any([
            AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
          assert.equal(result.provider, 'ollama'); assert.equal(result.model, MODEL);
          assert.equal(result.mocked, false); assert.notEqual(result.fallback, true);
          const wires = transport.calls.slice(start);
          assert.ok(wires.length >= 1 && wires.every(wire => wire.kind === 'actor'));
          actorSpans.push({ method, result, wires });
          status.actorCalls = transport.calls.filter(call => call.kind === 'actor').length;
          assert.ok(status.actorCalls <= 4); return result;
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
          fixtures: [], requiredObjectives: [OBJECTIVE], judge,
          jwtSecret: 'owned-ticket-browser-persona-secret-at-least-32-bytes',
          agentRuntime: { provider } });
      await composition.repositories.personas.ensureTemplates();
      assert.equal(composition.ticketAgent?.ready, true);
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });
      const standaloneMode = require('../../server/services/secureshopStandaloneMode')
        .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
      const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
        .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
          reviewPool: review, commercePool: commerce });
      const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
        .createRegisteredAdminResetEnvelope({ activeKeyId: 'ticket-owned',
          keys: new Map([['ticket-owned', randomBytes(32)]]) });
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
        assessmentObjectives: objectiveCatalog,
        assessmentRecovery: require('../../server/services/secureshopAssessmentRecovery')
          .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth,
            bootstrap, launches: composition.launches, personaAuth: composition.personaAuth,
            personaAuthority: grading.personaAuthority, modeAuthority, scenes,
            judge, ticketAssessment: composition.ticketAgent.assessment }),
        cartImport: require('../../server/services/secureshopStandaloneCartImport')
          .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
            personaAuth: composition.personaAuth, commerce: composition.commerce }),
        practices: require('../../server/services/secureshopPracticeAdmission')
          .createSecureShopPracticeAdmission({ catalog: composition.catalog,
            repository: require('../../server/database/postgres/secureshopPracticeAdmissionRepository')
              .createSecureShopPracticeAdmissionRepository({ pool: identity }) }) };
      const bound = await require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          applicationMode: 'standalone', authenticateToken: (_request, response) => response.sendStatus(401),
          audit: async () => {}, agentRuntime: {}, getComposition: async () =>
            ({ ...composition, standaloneAuth: standaloneAuthority, publicCatalog }) });
      assert.equal(bound.standaloneReadiness.ready, true);
      const app = express(); app.use(express.json());
      app.use('/api/secureshop', (request, response, next) => {
        if (request.path.startsWith('/agents/customer/chat')
            || request.path.startsWith('/agents/customer/tickets/')
            || request.path.startsWith('/admin/tickets')) {
          requests.push({ method: request.method, path: request.path,
            body: request.method === 'POST' ? structuredClone(request.body) : null });
          if (request.method === 'POST' && request.path === '/agents/customer/chat')
            assert.ok(++status.roleTurns <= 1);
        }
        if (request.method === 'POST'
            && /^\/admin\/tickets\/[1-9]\d*\/assessment$/.test(request.path))
          captureTicketAssessmentResponse(request, response, value =>
            assessmentHttpCaptures.push(value));
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
      app.use('/api', (_request, response) => response.status(404)
        .json({ error: 'Outside ticket browser qualification' }));
      app.use(express.static(build, { setHeaders: response =>
        response.set('Access-Control-Allow-Origin', '*') }));
      app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));
      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-customer-ticket-browser-'));
      browser = await require('puppeteer').launch({ headless: true,
        userDataDir: profile, executablePath });
      page = await browser.newPage(); await page.setViewport({ width: 1280, height: 900 });
      page.on('pageerror', error => pageErrors.push(error.message.slice(0, 160)));
      page.on('dialog', dialog => {
        dialogs.push({ type: dialog.type(), message: dialog.message(),
          framePath: page.frames().map(candidate => {
            try { return new URL(candidate.url()).pathname; }
            catch { return null; }
          }).find(value => value === '/secureshop/admin/tickets') || null });
        void dialog.dismiss();
      });
      await page.setRequestInterception(true);
      page.on('request', request => request.url().startsWith(`${origin}/`)
        ? request.continue() : request.abort());

      const subject = `Owned ticket ${suffix}`;
      const body = `<img src=x onerror="this.closest('[data-testid=ticket-vulnerable-body]').dataset.ownedTicketBrowser='executed';alert('owned-ticket-browser')">`;
      const humanMessage = JSON.stringify({ subject, body });
      stage = 'customer-login';
      assert.equal((await page.goto(`${origin}/secureshop/login`)).status(), 200);
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', username); await page.type('#ss-login-pw', password);
      const loginResponse = waitResponse(page, 'POST', '/api/secureshop/auth/login', 20000);
      const bootstrapResponse = waitResponse(page, 'POST', '/api/secureshop/auth/bootstrap', 20000);
      void loginResponse.catch(() => {}); void bootstrapResponse.catch(() => {});
      await page.click('button[type="submit"]');
      assert.equal((await loginResponse).status(), 200);
      assert.equal((await bootstrapResponse).status(), 200);
      let frame = await frameFor(page);
      const selector = await frame.waitForSelector('select[id^="agent-lane-task-customer-"]',
        { visible: true });
      await selector.select('chat');
      await frame.waitForSelector('section[aria-label="Prepare support ticket"]');
      const customerCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(cookie => cookie.name === 'owasp_ai_goat_shop_session');
      assert.equal(customerCookie?.httpOnly, true);
      const customerBase = await auth.authenticate(customerCookie.value);
      const customerPrincipal = await auth.establishTenantContext(customerBase);
      const currentCustomer = await bootstrap(customerBase);
      const customerScope = await composition.launches.resolveCapability(currentCustomer.bearer);
      const customerActor = await composition.personaAuth.authenticateBoundToken({
        scope: customerScope, token: currentCustomer.persona.token });
      await composition.catalog.prepareTarget({ scope: customerScope,
        persona: customerActor.user, personaSession: { sessionId: customerActor.sessionId,
          authorityVersion: customerActor.authorityVersion } });
      const customerScene = await scenes.readExisting(customerScope);
      assert.ok(customerScene?.scene && customerScene.targetId);
      const customerSceneRow = (await scenes.list(customerScope))
        .find(scene => scene.id === customerScene.scene.sceneId);
      assert.ok(customerSceneRow?.label);
      // Prepare under fixed feature mode. The confirmed ticket is normal
      // durable data in either mode; only its later admin rendering differs.
      stage = 'fixed-customer-mode';
      await physicalMode(page, 'Fixed');
      frame = await frameFor(page);
      await frame.waitForSelector('section[aria-label="Prepare support ticket"]');
      stage = 'physical-customer-prepare';
      await frame.type('input[id^="lane-ticket-subject-"]', subject);
      await frame.type('textarea[id^="lane-ticket-body-"]', body);
      const chatRequest = page.waitForRequest(request => request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/secureshop/agents/customer/chat',
      { timeout: 20000 });
      const chatResponse = waitResponse(page, 'POST', '/api/secureshop/agents/customer/chat');
      void chatRequest.catch(() => {}); void chatResponse.catch(() => {});
      await clickText(frame, 'Prepare support ticket');
      const originalRequest = await chatRequest;
      const customerHeaders = headersFrom(originalRequest);
      assert.equal((await chatResponse).status(), 200);
      const submitted = requests.filter(row => row.method === 'POST'
        && row.path === '/agents/customer/chat').at(-1)?.body;
      assert.equal(submitted?.message, humanMessage);
      assert.equal(status.roleTurns, 1);
      status.exactHumanRequest = true;
      await frame.waitForSelector('section[aria-label="Customer support ticket confirmation"] button',
        { visible: true, timeout: 70000 });
      await frame.waitForFunction(() => [...document.querySelectorAll(
        'section[aria-label="Customer support ticket confirmation"] button')]
        .some(button => button.textContent.trim() === 'Open support ticket'),
      { timeout: 70000 });
      const savedPath = `/api/secureshop/agents/customer/operations/${submitted.sessionId}/${submitted.requestId}`;
      const savedTurn = await protectedGet(origin, savedPath, customerHeaders);
      assert.equal(savedTurn.status, 'completed');
      assert.equal(savedTurn.stopReason, 'end_turn');
      assert.equal(savedTurn.ticketProposal.subject, subject);
      assert.equal(savedTurn.ticketProposal.body, body);
      assert.equal(savedTurn.ticketProposal.subjectSha256, sha(subject));
      assert.equal(savedTurn.ticketProposal.bodySha256, sha(body));
      // The assessment's protected original reader remains authoritative.
      // Independently join its saved, model-selected reference to the exact
      // authenticated human bytes. The model never supplies ticket body bytes.
      const originalTurn = (await agents.query(`SELECT * FROM secureshop_agents.turn_requests
        WHERE session_id=$1 AND request_id=$2`,
      [submitted.sessionId, submitted.requestId])).rows;
      assert.equal(originalTurn.length, 1);
      assert.equal(originalTurn[0].status, 'completed');
      assert.equal(originalTurn[0].result_json.text, savedTurn.text);
      const Ticket = require('../../server/services/secureshopTicketContract');
      const ticketMeta = originalTurn[0].result_json.taskMetadata?.ticketAgent;
      assert.equal(ticketMeta?.version, 2);
      const boundRequest = (await agents.query(`SELECT * FROM
        secureshop_agents.customer_chat_turn_bindings WHERE session_id=$1 AND request_id=$2`,
      [submitted.sessionId, submitted.requestId])).rows;
      assert.equal(boundRequest.length, 1);
      assert.equal(boundRequest[0].request_hash, originalTurn[0].request_hash);
      assert.equal(boundRequest[0].launch_id, customerScope.launchId);
      assert.equal(boundRequest[0].scene_id, customerScene.scene.sceneId);
      assert.equal(boundRequest[0].grant_id, customerScene.scene.grantId);
      assert.equal(boundRequest[0].target_id, customerScene.targetId);
      assert.equal(boundRequest[0].persona_id, customerActor.user.id);
      assert.equal(boundRequest[0].persona_session_id, customerActor.sessionId);
      const requestRef = Ticket.requestRef({ requestHash: originalTurn[0].request_hash,
        envelopeSha256: boundRequest[0].envelope_sha256 });
      assert.equal(ticketMeta.requestRef, requestRef);
      const toolOrigin = Ticket.origin(ticketMeta.origin);
      assert.deepEqual(Ticket.projectProposal(ticketMeta.proposal,
        { message: humanMessage, sourceOrigin: toolOrigin }), savedTurn.ticketProposal);
      const originalTrace = (await agents.query(`SELECT id,event_id,kind,actor,step,
        agent_ns,tool_name,params_json::jsonb AS params_json,
        result_json::jsonb AS result_json FROM secureshop_agents.agent_trace
        WHERE session_id=$1 AND event_id=ANY($2::text[]) ORDER BY id`,
      [submitted.sessionId, ticketMeta.traceEventIds])).rows;
      assert.deepEqual(originalTrace.map(row => row.event_id), ticketMeta.traceEventIds);
      const selected = originalTrace.filter(row => row.kind === 'model_decision'
        && row.actor === 'supervisor' && row.step === toolOrigin.invocationStep);
      assert.equal(selected.length, 1);
      assert.equal(selected[0].params_json?.decision, 'tool_use');
      assert.deepEqual(selected[0].params_json.toolCalls, [{ id: toolOrigin.callId,
        name: 'support.ticket_prepare', args: { requestRef } }]);
      const localCall = originalTrace.filter(row => row.kind === 'local_tool_call'
        && row.agent_ns === 'support' && row.tool_name === 'ticket_prepare'
        && row.step === toolOrigin.invocationStep);
      assert.equal(localCall.length, 1);
      assert.deepEqual(localCall[0].params_json, { requestRef });
      const savedHops = originalTurn[0].result_json.hops.filter(hop =>
        hop.tool === Ticket.TOOL && hop.step === toolOrigin.invocationStep);
      assert.equal(savedHops.length, 1);
      assert.deepEqual(savedHops[0].params, { requestRef });
      const originalObservation = { status: 'confirmation_required',
        ticketProposal: ticketMeta.proposal, ticketOrigin: toolOrigin };
      assert.deepEqual(JSON.parse(savedHops[0].result.content[0].text), originalObservation);
      const localResult = originalTrace.filter(row => row.kind === 'local_tool_result'
        && row.agent_ns === 'support' && row.tool_name === 'ticket_prepare'
        && row.step === toolOrigin.invocationStep);
      assert.equal(localResult.length, 1);
      assert.deepEqual(localResult[0].result_json, savedHops[0].result);
      assertTicketActorWire({ spans: actorSpans, turn: originalTurn[0].result_json,
        origin: toolOrigin, requestRef, model: MODEL });
      assert.ok(status.actorCalls >= 2 && status.actorCalls <= 4);
      assert.ok(actorSpans.some(span => span.method === 'chat'));
      status.modelSelectedPrepare = true;
      const ticketRows = async () => (await review.query(`SELECT * FROM
        secureshop_review.product_target_support_tickets WHERE target_id=$1 ORDER BY ticket_id`,
      [customerScene.targetId])).rows;
      assert.deepEqual(await ticketRows(), [], 'model preparation has no ticket effect');
      status.noTicketBeforeConfirm = true;
      stage = 'physical-confirm';
      const confirmPath = '/api/secureshop/agents/customer/tickets/confirm';
      const confirmRequest = page.waitForRequest(request => request.method() === 'POST'
        && new URL(request.url()).pathname === confirmPath, { timeout: 20000 });
      const confirmResponse = waitResponse(page, 'POST', confirmPath, 20000);
      void confirmRequest.catch(() => {}); void confirmResponse.catch(() => {});
      await clickText(frame, 'Open support ticket',
        'section[aria-label="Customer support ticket confirmation"] button');
      assert.deepEqual(headersFrom(await confirmRequest), customerHeaders);
      assert.equal((await confirmResponse).status(), 200);
      const confirmation = requests.filter(row => row.method === 'POST'
        && row.path === '/agents/customer/tickets/confirm').at(-1)?.body;
      assert.deepEqual(confirmation, { sessionId: submitted.sessionId,
        requestId: submitted.requestId,
        proposalId: savedTurn.ticketProposal.proposalId });
      status.physicalConfirm = true;
      await frame.waitForFunction(() => document.querySelector(
        'section[aria-label="Customer support ticket confirmation"]')
        ?.textContent.includes(' is open.'), { timeout: 20000 });
      const rows = await ticketRows(); assert.equal(rows.length, 1);
      const ticket = rows[0];
      assert.equal(ticket.subject, subject); assert.equal(ticket.body, body);
      assert.equal(ticket.subject_sha256.toString('hex'), sha(subject));
      assert.equal(ticket.body_sha256.toString('hex'), sha(body));
      assert.equal(ticket.target_id, customerScene.targetId);
      assert.equal(ticket.operation_id, savedTurn.ticketProposal.proposalId);
      const receiptRows = (await review.query(`SELECT * FROM
        secureshop_review.product_target_support_ticket_receipts WHERE ticket_id=$1`,
      [ticket.ticket_id])).rows;
      assert.equal(receiptRows.length, 1);
      status.oneImmutableTicket = true;
      const savedConfirmPath = `${confirmPath}/${confirmation.sessionId}/${confirmation.requestId}/${confirmation.proposalId}`;
      const savedConfirmation = await protectedGet(origin, savedConfirmPath, customerHeaders);
      assert.equal(savedConfirmation.status, 'completed');
      assert.equal(savedConfirmation.result.ticketId, String(ticket.ticket_id));
      assert.equal(savedConfirmation.result.receiptSha256,
        receiptRows[0].receipt_sha256.toString('hex'));
      const rowsAfterGet = await ticketRows();
      assert.deepEqual(rowsAfterGet, rows);
      assert.equal(status.roleTurns, 1);
      assert.equal(status.judgeCalls, 0);
      status.savedGetNoDuplicate = true;

      // A separate current administrator chooses the retained customer scene.
      // Its grant, session and launch are never copied from the customer.
      stage = 'admin-login-and-scene';
      await auth.logout(customerCookie.value);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/login`)).status()));
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', 'student_admin');
      await page.type('#ss-login-pw', 'student123');
      const adminLoginResponse = waitResponse(page, 'POST', '/api/secureshop/auth/login', 20000);
      const adminBootstrap = waitResponse(page, 'POST', '/api/secureshop/auth/bootstrap', 20000);
      void adminLoginResponse.catch(() => {}); void adminBootstrap.catch(() => {});
      await page.click('button[type="submit"]');
      assert.equal((await adminLoginResponse).status(), 200);
      assert.equal((await adminBootstrap).status(), 200);
      const adminCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(cookie => cookie.name === 'owasp_ai_goat_shop_session');
      assert.equal(adminCookie?.httpOnly, true);
      const adminBase = await auth.authenticate(adminCookie.value);
      const adminPrincipal = await auth.establishTenantContext(adminBase);
      assert.equal(adminPrincipal.ownerId, customerPrincipal.ownerId);
      assert.notEqual(adminPrincipal.principalId, customerPrincipal.principalId);
      const adminReady = await bootstrap(adminBase);
      const adminScope = await composition.launches.resolveCapability(adminReady.bearer);
      assert.notEqual(adminScope.launchId, customerScope.launchId);
      const adminActor = await composition.personaAuth.authenticateBoundToken({
        scope: adminScope, token: adminReady.persona.token });
      assert.equal(adminActor.user.role, 'admin');
      await clickText(page, 'Shop settings');
      await page.waitForSelector('aside[aria-label="Shop settings"]');
      await clickText(page, 'Choose retained practice');
      const sceneChoice = await page.waitForFunction(label => [...document.querySelectorAll('main button')]
        .find(button => button.textContent.includes(label)), { timeout: 20000 },
      customerSceneRow.label);
      const scenePost = waitResponse(page, 'POST', '/api/secureshop/v2/scenes/select', 20000);
      void scenePost.catch(() => {});
      await sceneChoice.asElement().click();
      assert.equal((await scenePost).status(), 200);
      await frameFor(page);
      await composition.catalog.prepareTarget({ scope: adminScope, persona: adminActor.user,
        personaSession: { sessionId: adminActor.sessionId,
          authorityVersion: adminActor.authorityVersion } });
      const adminScene = await scenes.readRetained(adminScope);
      assert.equal(adminScene.targetId, customerScene.targetId);
      assert.equal(adminScene.scene.sceneId, customerScene.scene.sceneId);
      // Top-level binding is the shared target's original birth. The scene
      // grant carries this reader's distinct, current admin execution.
      assert.equal(adminScene.launchId, customerScene.launchId);
      assert.deepEqual(adminScene.scene.execution,
        require('../../server/services/secureshopConversationBinding')
          .createLaunchScope(adminScope));
      assert.notEqual(adminScene.scene.execution.launchId,
        customerScene.scene.execution.launchId);
      assert.notEqual(adminScene.scene.grantId, customerScene.scene.grantId);
      status.distinctAdminGrant = true;
      stage = 'fixed-admin-render';
      await physicalMode(page, 'Fixed');
      frame = await frameFor(page);
      const listRequest = page.waitForRequest(request => request.method() === 'GET'
        && new URL(request.url()).pathname === '/api/secureshop/admin/tickets',
      { timeout: 20000 });
      const listResponse = waitResponse(page, 'GET', '/api/secureshop/admin/tickets', 20000);
      void listRequest.catch(() => {});
      void listResponse.catch(() => {});
      await frame.waitForSelector('a[href="/secureshop/admin/tickets"]');
      await frame.click('a[href="/secureshop/admin/tickets"]');
      const adminHeaders = headersFrom(await listRequest);
      assert.equal((await listResponse).status(), 200);
      const list = await protectedGet(origin, '/api/secureshop/admin/tickets', adminHeaders);
      assert.equal(list.tickets.length, 1);
      assert.equal(list.tickets[0].ticketId, String(ticket.ticket_id));
      await frame.waitForSelector('section[aria-label="Admin support tickets"]');
      await clickTicketRow(frame, ticket.ticket_id, subject);
      await frame.waitForSelector('[data-testid="ticket-fixed-body"]');
      assert.equal(await frame.$eval('[data-testid="ticket-fixed-body"]', node => node.textContent), body);
      assert.equal(await frame.$('[data-testid="ticket-fixed-body"] img'), null);
      assert.equal(await frame.$eval('[data-testid="ticket-fixed-body"]',
        node => node.dataset.ownedTicketBrowser), undefined);
      assert.deepEqual(dialogs, []);
      const fixedDetail = await protectedGet(origin,
        `/api/secureshop/admin/tickets/${ticket.ticket_id}`, adminHeaders);
      assert.equal(fixedDetail.body, body);
      assert.equal(fixedDetail.modeCapability.effectiveMode, 'fixed');
      assert.deepEqual(await ticketRows(), rows);
      const fixedAssessment = await protectedGet(origin,
        `/api/secureshop/admin/tickets/${ticket.ticket_id}/assessment/${randomUUID()}`,
      adminHeaders);
      assert.equal(fixedAssessment.completed, false);
      assert.equal(fixedAssessment.modelEvaluated, false);
      assert.equal(status.judgeCalls, 0);
      assert.deepEqual(await assessmentRows(identity, adminPrincipal), []);
      status.fixedSameBytesInert = true;
      status.fixedNoCredit = true;

      // The original source is never edited: switch only the current admin
      // feature mode, then physically reread the same protected ticket.
      stage = 'vulnerable-admin-render';
      await physicalMode(page, 'Vulnerable');
      frame = await frameFor(page);
      await frame.waitForSelector('section[aria-label="Admin support tickets"]',
        { visible: true, timeout: 20000 });
      await clickTicketRow(frame, ticket.ticket_id, subject);
      await frame.waitForSelector('[data-testid="ticket-vulnerable-body"]');
      await frame.waitForFunction(() => document.querySelector(
        '[data-testid="ticket-vulnerable-body"] img'), { timeout: 20000 });
      await frame.waitForFunction(() => document.querySelector(
        '[data-testid="ticket-vulnerable-body"]')?.dataset.ownedTicketBrowser === 'executed',
      { timeout: 20000 });
      const vulnDetail = await protectedGet(origin,
        `/api/secureshop/admin/tickets/${ticket.ticket_id}`, adminHeaders);
      assert.equal(vulnDetail.body, body);
      assert.equal(vulnDetail.modeCapability.effectiveMode, 'vuln');
      assert.deepEqual(await ticketRows(), rows);
      const assessmentPost = page.waitForRequest(request => request.method() === 'POST'
        && new URL(request.url()).pathname ===
          `/api/secureshop/admin/tickets/${ticket.ticket_id}/assessment`,
      { timeout: 20000 });
      const assessmentResponse = waitResponse(page, 'POST',
        `/api/secureshop/admin/tickets/${ticket.ticket_id}/assessment`);
      void assessmentPost.catch(() => {}); void assessmentResponse.catch(() => {});
      await clickText(frame, 'Check ticket');
      const assessmentRequest = await assessmentPost;
      assert.deepEqual(headersFrom(assessmentRequest), adminHeaders);
      const assessmentBody = assessmentRequest.postData();
      assert.equal(typeof assessmentBody, 'string');
      const assessmentInput = JSON.parse(assessmentBody);
      assert.deepEqual(Object.keys(assessmentInput).sort(), ['requestId']);
      assert.match(assessmentInput.requestId,
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
      const assessmentHttp = await assessmentResponse;
      assert.equal(assessmentHttp.status(), 200);
      const originalAssessment = await waitForOriginalAssessment(assessmentHttpCaptures,
        `/admin/tickets/${ticket.ticket_id}/assessment`, assessmentInput.requestId);
      assert.equal(originalAssessment.method, 'POST');
      assert.equal(originalAssessment.path,
        `/admin/tickets/${ticket.ticket_id}/assessment`);
      assert.deepEqual(originalAssessment.requestBody, assessmentInput);
      assert.equal(originalAssessment.status, assessmentHttp.status());
      assert.match(originalAssessment.contentType, /^application\/json\b/);
      assert.equal(originalAssessment.error, null);
      const assessed = JSON.parse(originalAssessment.body);
      assert.deepEqual(Object.keys(assessed).sort(), ['completed', 'judgment', 'replayed']);
      assert.deepEqual(Object.keys(assessed.judgment).sort(),
        ['canRetry', 'evaluationId', 'verdict']);
      assert.equal(assessed.completed, true);
      assert.equal(assessed.replayed, false);
      assert.equal(assessed.judgment.verdict, 'pass');
      const assessmentPath = `/api/secureshop/admin/tickets/${ticket.ticket_id}/assessment/${assessmentInput.requestId}`;
      const beforeSavedAssessment = { actor: transport.calls.filter(call => call.kind === 'actor').length,
        judge: transport.calls.filter(call => call.kind === 'judge').length,
        tickets: await ticketRows(), judgments: await assessmentRows(identity, adminPrincipal) };
      const savedAssessment = await protectedGet(origin, assessmentPath, adminHeaders);
      assert.equal(savedAssessment.completed, true);
      assert.deepEqual(savedAssessment.judgment, assessed.judgment);
      assert.equal(savedAssessment.replayed, true);
      assert.equal(transport.calls.filter(call => call.kind === 'actor').length,
        beforeSavedAssessment.actor);
      assert.equal(transport.calls.filter(call => call.kind === 'judge').length,
        beforeSavedAssessment.judge);
      assert.deepEqual(await ticketRows(), beforeSavedAssessment.tickets);
      assert.deepEqual(await assessmentRows(identity, adminPrincipal), beforeSavedAssessment.judgments);
      assert.equal(status.roleTurns, 1);
      assert.deepEqual(await ticketRows(), rows);
      const judgmentRows = await assessmentRows(identity, adminPrincipal);
      assert.equal(judgmentRows.length, 1);
      const judgment = judgmentRows[0];
      assert.equal(judgment.evaluation_id, assessed.judgment.evaluationId);
      assert.equal(judgment.verdict, 'pass'); assert.equal(judgment.disposition, 'awarded');
      assert.equal(judgment.mode, 'vuln');
      assert.equal(judgment.result_json.provider, 'ollama');
      assert.equal(judgment.result_json.model, MODEL);
      assert.equal(sha(judgment.result_serialized), judgment.result_digest);
      assert.deepEqual(JSON.parse(judgment.result_serialized), judgment.result_json);
      const packet = JSON.parse(judgment.packet);
      const proof = packet.evidence.find(item => item.id === 'ticket_browser')?.content;
      assert.equal(proof?.ticket?.result?.ticketId, String(ticket.ticket_id));
      assert.equal(proof?.ticket?.body, body);
      assert.equal(proof?.currentAdmin?.consumer?.admin?.shopUserId, adminActor.user.id);
      assert.equal(proof?.browser?.targetEventExecuted, true);
      assert.equal(proof?.browser?.targetEffectObserved, true);
      assert.equal(proof?.component?.id, 'SecureShop.AdminTicketBody');
      const effectReceipt = proof?.effectReceipt;
      assert.equal(effectReceipt?.status, 'completed');
      const graphEffects = (await identity.query(`SELECT owner_key,generation::text,
        effect_key,run_id,status FROM graph_runtime.effects
        WHERE owner_key=$1 AND generation=$2 AND effect_key=$3 AND run_id=$4`,
      [effectReceipt.ownerKey, effectReceipt.generation, effectReceipt.effectKey,
        effectReceipt.runId])).rows;
      assert.equal(graphEffects.length, 1);
      assert.deepEqual(graphEffects[0], { owner_key: effectReceipt.ownerKey,
        generation: String(effectReceipt.generation), effect_key: effectReceipt.effectKey,
        run_id: effectReceipt.runId, status: 'completed' });
      const configuredProof = judgeResults.map(result =>
        require('../../server/agent-runtime/objectiveJudge')
          .readConfiguredJudgeProvenance(result))
        .find(value => value?.evidenceDigest === judgment.evidence_digest);
      assert.ok(configuredProof && configuredProof.calls.length >= 1);
      assert.deepEqual(judgment.judge_observations, configuredProof);
      assert.equal(judgment.judge_result_json, JSON.stringify(judgeResults.at(-1)));
      const judgeWires = transport.calls.filter(call => call.kind === 'judge');
      assert.equal(judgeWires.length, configuredProof.calls.length);
      for (const [index, call] of configuredProof.calls.entries()) {
        const wire = judgeWires[index], request = JSON.parse(wire.request);
        assert.equal(wire.status, 200); assert.equal(wire.responseComplete, true);
        assert.equal(wire.responseCaptureTruncated, false);
        assert.equal(request.model, MODEL); assert.equal(call.provider, 'ollama');
        assert.equal(call.model, MODEL);
        assert.equal(wire.requestSha256, sha(wire.request));
        assert.equal(wire.responseSha256, sha(wire.response));
        assert.equal(call.requestSha256, sha(JSON.stringify({ method: 'chat',
          input: request.messages, schema: request.format ?? null })));
        const responseText = wire.response.trim().split('\n')
          .map(line => JSON.parse(line).message?.content || '').join('');
        assert.equal(call.responseSha256, sha(responseText));
      }
      status.browserEffects = graphEffects.length;
      status.genuineCredit = 1;
      status.vulnerableSameBytesExecuted = true;
      status.genuineJudge = true;
      status.savedAssessmentReadback = true;
      assert.equal((await identity.query(`SELECT count(*)::int AS n FROM
        secureshop_auth.assessment_completions WHERE tenant_id=$1 AND principal_id=$2
        AND objective_id=$3`, [adminPrincipal.tenantId, adminPrincipal.principalId,
        OBJECTIVE])).rows[0].n, 1);
      assert.equal((await identity.query(`SELECT count(*)::int AS n FROM
        secureshop_auth.assessment_contributions WHERE evaluation_id=$1`,
      [judgment.evaluation_id])).rows[0].n, 1);
      const activeContributions = async () => (await identity.query(`SELECT * FROM
        secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1`,
      [judgment.evaluation_id])).rows;
      assert.equal((await activeContributions()).length, 1);

      stage = 'sibling-and-reset';
      const peerBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: peerAuth });
      const siblingReady = await peerBootstrap(peerAdminLogin.context);
      const siblingScope = await composition.launches.resolveCapability(siblingReady.bearer);
      assert.notEqual(siblingScope.platformOwnerId, adminScope.platformOwnerId);
      const siblingActor = await composition.personaAuth.authenticateBoundToken({
        scope: siblingScope, token: siblingReady.persona.token });
      assert.equal(siblingActor.user.role, 'admin');
      await composition.catalog.prepareTarget({ scope: siblingScope,
        persona: siblingActor.user, personaSession: {
          sessionId: siblingActor.sessionId,
          authorityVersion: siblingActor.authorityVersion } });
      const siblingScene = await scenes.readExisting(siblingScope);
      assert.ok(siblingScene?.targetId);
      assert.notEqual(siblingScene.targetId, customerScene.targetId);
      const siblingHeaders = { authorization: `Bearer ${siblingReady.persona.token}`,
        'x-owasp-ai-goat-secureshop-launch': siblingReady.bearer };
      await protectedGet(origin, `/api/secureshop/admin/tickets/${ticket.ticket_id}`,
        siblingHeaders, 404);
      assert.equal((await assessmentRows(identity, peerPrincipal)).length, 0);
      const siblingBefore = {
        scene: siblingScene,
        launch: (await identity.query(`SELECT * FROM identity.secureshop_launches
          WHERE launch_id=$1`, [siblingScope.launchId])).rows,
        target: (await review.query(`SELECT * FROM secureshop_review.product_targets
          WHERE target_id=$1`, [siblingScene.targetId])).rows,
      };
      assert.equal(siblingBefore.launch.length, 1);
      assert.equal(siblingBefore.target.length, 1);
      assert.deepEqual(await ticketRows(), rows);
      status.siblingPrivate = true;
      const immutableBeforeReset = {
        judgment: await assessmentRows(identity, adminPrincipal),
        completion: (await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
          WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3`,
        [adminPrincipal.tenantId, adminPrincipal.principalId, OBJECTIVE])).rows,
        contribution: (await identity.query(`SELECT * FROM secureshop_auth.assessment_contributions
          WHERE evaluation_id=$1`, [judgment.evaluation_id])).rows,
      };
      const resetResult = await reset.launchResetCoordinator.reset({
        launchId: adminScope.launchId, platformSessionId: adminScope.platformSessionId,
        platformOwnerId: adminScope.platformOwnerId,
        expectedGeneration: adminScope.generation, idempotencyKey: randomUUID() });
      assert.equal(resetResult.status, 'committed');
      assert.equal((await review.query(`SELECT count(*)::int AS n FROM
        secureshop_review.product_target_support_ticket_retirements WHERE ticket_id=$1`,
      [ticket.ticket_id])).rows[0].n, 1);
      await protectedGet(origin,
        `/api/secureshop/admin/tickets/${ticket.ticket_id}`, adminHeaders, 401);
      assert.deepEqual(await assessmentRows(identity, adminPrincipal), immutableBeforeReset.judgment);
      assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
        WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3`,
      [adminPrincipal.tenantId, adminPrincipal.principalId, OBJECTIVE])).rows,
      immutableBeforeReset.completion);
      assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_contributions
        WHERE evaluation_id=$1`, [judgment.evaluation_id])).rows,
      immutableBeforeReset.contribution);
      assert.deepEqual(await activeContributions(), []);
      assert.deepEqual(await scenes.readRetained(siblingScope), siblingBefore.scene);
      assert.deepEqual((await identity.query(`SELECT * FROM identity.secureshop_launches
        WHERE launch_id=$1`, [siblingScope.launchId])).rows, siblingBefore.launch);
      assert.deepEqual((await review.query(`SELECT * FROM secureshop_review.product_targets
        WHERE target_id=$1`, [siblingScene.targetId])).rows, siblingBefore.target);
      assert.deepEqual(await assessmentRows(identity, peerPrincipal), []);
      assert.equal(status.actorCalls, transport.calls.filter(call => call.kind === 'actor').length);
      assert.equal(status.judgeCalls, transport.calls.filter(call => call.kind === 'judge').length);
      assert.deepEqual(pageErrors, []);
      status.resetRetiresCredit = true;
    } catch (error) {
      failure = error;
      status.errors.push({ stage, name: error.name, code: error.code || null,
        message: String(error.message).slice(0, 300) });
    }
    finally {
      if (originalModelURL === undefined) delete process.env.OLLAMA_BASE_URL;
      else process.env.OLLAMA_BASE_URL = originalModelURL;
      let browserClosed = !browser;
      try { if (browser) { await browser.close(); browserClosed = true; } }
      catch (error) { status.cleanupErrors.push(error.message); }
      for (const close of [() => closeServer(server),
        () => composition?.ticketAgent?.close(), () => transport?.close(),
        () => reset?.closeFeatureTransports?.(), () => reset?.auditLedger?.close?.(),
        () => profile && browserClosed && fs.rm(profile, { recursive: true, force: true }),
        () => leasePool.end(), ...Object.values(pools).map(pool => () => pool.end())]) {
        try { await close(); } catch (error) { status.cleanupErrors.push(error.message); }
      }
      try { await saveWire(); } catch (error) { status.cleanupErrors.push(error.message); }
      status.fixtureCleaned = status.cleanupErrors.length === 0;
      status.passed = !failure && status.fixtureCleaned
        && TICKET_FLAGS.every(flag => status[flag]);
      try { await fs.writeFile(evidencePath, JSON.stringify(status, null, 2),
        { flag: 'wx', mode: 0o600 }); }
      catch (error) { status.cleanupErrors.push(error.message); }
    }
    if (status.cleanupErrors.length) throw new AggregateError(status.cleanupErrors.map(message => Error(message)),
      'Ticket browser fixture cleanup failed');
    if (failure) throw failure;
    assertTicketRenderedReceipt(status);
  });
