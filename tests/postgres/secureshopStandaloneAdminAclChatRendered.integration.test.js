'use strict';

// Q64 is a disposable current-main qualification. No installed store, browser
// profile, model credential, or workshop account is read by this test.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomBytes, randomUUID } = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { SCOPE, FLAGS, validateQ64Receipt } = require('../fixtures/secureshopAdminAclChatReceipt');
const { createD22AuditApplication } = require('../helpers/secureshopD22ProductionAssembly');

const ASSERTION = 'standalone administrator lists ACL policy and physically confirms one permission and one enforcement change through real local llama3.1:8b and exact recovery';
const GATE = 'SECURESHOP_ADMIN_ACL_CHAT_BROWSER_NATIVE';
const BASE = 'SECURESHOP_ADMIN_ACL_CHAT_BROWSER_';
const PREFIX = 'PG_SECURESHOP_ADMIN_ACL_CHAT_BROWSER_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function admission() {
  assert.equal(process.env[GATE], '1');
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(process.env.LIVE_OLLAMA_TEST, '1');
  assert.equal(process.env.LAB_MODE, 'vuln');
  assert.equal(process.env.AI_PROVIDER, 'ollama');
  assert.equal(process.env.OLLAMA_MODEL, 'llama3.1:8b');
  assert.equal(process.env.OLLAMA_BASE_URL, 'http://127.0.0.1:11434');
  const workspace = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/');
  assert.equal(workspace, process.cwd(), 'run against the current main checkout only');
  const build = path.resolve(process.env[`${BASE}BUILD`] || '/');
  assert.equal(build, path.join(workspace, 'client/build'));
  const evidence = path.resolve(process.env[`${BASE}EVIDENCE_PATH`] || '/');
  assert.notEqual(evidence, '/');
  require('../fixtures/secureshopNativeEvidencePath').assertNativeEvidencePath(evidence,
    { root: workspace, dockerHost: process.env.DOCKER_HOST, basename: 'admin-acl-chat-browser.json' });
  const browser = path.resolve(process.env.PUPPETEER_EXECUTABLE_PATH || '/');
  assert.notEqual(browser, '/');
  const urls = {}; let nonce, port;
  for (const [store, suffix] of Object.entries(STORES)) {
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const source = process.env[`${PREFIX}${store}_${role}_URL`];
      assert.ok(source, `missing owned ${store} ${role}`);
      const url = new URL(source);
      assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.port, /^[1-9]\d{0,4}$/); assert.ok(Number(url.port) <= 65535);
      assert.equal(url.username, `dvaia_${suffix}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      const match = new RegExp(`^/dvaia_test_agent_host_([0-9a-f]{12})_${suffix}$`).exec(url.pathname);
      assert.ok(match, `closed disposable ${store} database`);
      nonce ??= match[1]; port ??= url.port;
      assert.equal(match[1], nonce); assert.equal(url.port, port);
      urls[`${store}_${role}`] = source;
    }
    assert.equal(new URL(urls[`${store}_RUNTIME`]).pathname,
      new URL(urls[`${store}_MIGRATION`]).pathname);
  }
  assert.equal(new Set(Object.keys(STORES).map(store => new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  const auditUrl = new URL(process.env[`${BASE}AUDIT_CONTROL_URL`] || '/');
  assert.equal(auditUrl.protocol, 'postgresql:'); assert.equal(auditUrl.hostname, '127.0.0.1');
  assert.match(auditUrl.port, /^[1-9]\d{0,4}$/); assert.ok(Number(auditUrl.port) <= 65535);
  assert.match(auditUrl.pathname, /^\/dvaia_audit_control_[a-f0-9]+$/);
  assert.equal(auditUrl.username, 'postgres'); assert.equal(auditUrl.password, '');
  assert.equal(auditUrl.search, ''); assert.equal(auditUrl.hash, '');
  assert.notEqual(auditUrl.port, port, 'owned audit SQL target is a separate cluster');
  return { workspace, build, evidence, browser, urls, auditUrl };
}

async function listen(app) {
  return new Promise(resolve => { const server = app.listen(0, '127.0.0.1', () => resolve(server)); });
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
async function frameFor(page) {
  const until = Date.now() + 30000;
  while (Date.now() < until) {
    const element = await page.$('iframe[title="SecureShop"]');
    const frame = element && await element.contentFrame().catch(() => null);
    if (frame && !frame.detached && await frame.evaluate(() =>
      Boolean(document.querySelector('[data-testid="admin-role-assistant"]'))).catch(() => false)) return frame;
    await delay(50);
  }
  throw Error('Admin assistant frame did not mount');
}
async function physical(frame, label, container = 'body') {
  await frame.waitForFunction((text, root) => [...document.querySelectorAll(`${root} button`)]
    .some(node => (node.getAttribute('aria-label') === text || node.textContent?.trim() === text)
      && !node.disabled), { timeout: 30000 }, label, container);
  const handle = await frame.evaluateHandle((text, root) => [...document.querySelectorAll(`${root} button`)]
    .find(node => (node.getAttribute('aria-label') === text || node.textContent?.trim() === text)
      && !node.disabled), label, container);
  assert.ok(handle);
  try {
    await handle.evaluate(node => node.scrollIntoView({ block: 'center', inline: 'center' }));
    await frame.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    const hit = await handle.evaluate(node => {
      const r = node.getBoundingClientRect(), x = r.left + r.width / 2, y = r.top + r.height / 2;
      return r.width > 0 && r.height > 0 && x > 0 && y > 0 && x < innerWidth && y < innerHeight
        && (node === document.elementFromPoint(x, y) || node.contains(document.elementFromPoint(x, y)));
    });
    assert.equal(hit, true, `${label} must be physically hit-testable`);
    await handle.click();
  } finally { await handle.dispose(); }
}
async function composeMessage(frame, message) {
  const selector = '[data-testid="admin-role-composer-slot"] textarea';
  await frame.waitForSelector(selector);
  await frame.$eval(selector, node => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(node, '');
    node.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await frame.type(selector, message);
  await physical(frame, 'Send to admin assistant', '[data-testid="admin-role-composer-slot"]');
}

async function roleTurn({ page, frame, origin, authority, posts, expectedPosts,
  message = null, button = null }) {
  const responsePromise = page.waitForResponse(response => response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/api/secureshop/agents/admin/assistant/chat',
  { timeout: 120000 });
  responsePromise.catch(() => {});
  if (button) await physical(frame, button, '[data-testid="admin-role-assistant"]');
  else await composeMessage(frame, message);
  const response = await responsePromise;
  assert.equal(response.status(), 200, `real assistant stream ${expectedPosts} must be admitted`);
  const until = Date.now() + 120000;
  while (Date.now() < until) {
    if (posts.length !== expectedPosts) { await delay(50); continue; }
    const submitted = posts.at(-1);
    assert.ok(UUID.test(submitted.sessionId) && UUID.test(submitted.requestId));
    const read = await fetch(`${origin}/api/secureshop/agents/admin/assistant/operations/${submitted.sessionId}/${submitted.requestId}`,
      { headers: { 'x-dvaia-secureshop-launch': authority.launch,
        authorization: `Bearer ${authority.token}` } });
    if (read.status === 200) {
      const value = await read.json();
      if (value.status === 'completed') {
        assert.equal(value.stopReason, 'end_turn');
        assert.equal(value.replayed, true);
        assert.equal(value.sessionId, submitted.sessionId);
        assert.equal(value.requestId, submitted.requestId);
        return value;
      }
    }
    await delay(100);
  }
  throw Error(`Real assistant turn ${expectedPosts} did not have exact terminal readback`);
}

async function operationRows(pool, scope) {
  return (await pool.query(`SELECT operation_id,persona_id,persona_session_id,
      expected_version,policy_version,receipt_json
    FROM secureshop_agents.bound_tool_policy_operations
    WHERE platform_launch_id=$1 AND platform_scenario_id=$2
      AND platform_launch_generation=$3 AND original_platform_owner_id=$4
      AND original_platform_session_id=$5 ORDER BY created_at,operation_id`,
  [scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId])).rows;
}

async function admissionRows(pool, scope) {
  return (await pool.query(`SELECT admission_id,run_id,invocation_id,persona_id,persona_session_id,
      tool_key,policy_version,enforcement_enabled,allowed,action
    FROM secureshop_agents.bound_tool_admissions
    WHERE platform_launch_id=$1 AND platform_scenario_id=$2
      AND platform_launch_generation=$3 AND original_platform_owner_id=$4
      AND original_platform_session_id=$5 ORDER BY created_at,admission_id`,
  [scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId])).rows;
}

function queryCount(pool, sql, args = []) {
  return pool.query(sql, args).then(result => Number(result.rows[0].n));
}

test(ASSERTION, { skip: process.env[GATE] !== '1', timeout: 540000 }, async t => {
  const a = admission();
  await fs.access(path.join(a.build, 'index.html'));
  await fs.access(path.join(a.build, 'secureshop-frame.html'));
  await fs.access(a.browser);
  await assert.rejects(fs.lstat(a.evidence), { code: 'ENOENT' });
  const status = Object.fromEntries(FLAGS.map(flag => [flag, false]));
  Object.assign(status, { scope: SCOPE, roleTurns: 0, actorCalls: 0, judgeCalls: 0, errors: [] });
  const pools = Object.fromEntries(Object.keys(STORES).flatMap(store => ['RUNTIME', 'MIGRATION']
    .map(role => [`${store}_${role}`, new Pool({ connectionString: a.urls[`${store}_${role}`],
      max: role === 'RUNTIME' ? 12 : 3 })])));
  const leasePool = new Pool({ connectionString: a.urls.IDENTITY_RUNTIME, max: 4 });
  const controlConfig = { host: a.auditUrl.hostname, port: Number(a.auditUrl.port),
    user: a.auditUrl.username, database: a.auditUrl.pathname.slice(1) };
  const control = new Pool({ ...controlConfig, max: 2 });
  let browser, earlyBrowserDiagnostic, profile, server, auditHttp, targetService, auditBackend, rawAuditClient;
    let actorCalls = 0, judgeCalls = 0;
  const modelDecisions = [], cleanupErrors = [], ownedScopes = [];
  try {
    for (const [store, directory] of [
      ['IDENTITY', 'identity-migrations'], ['AGENTS', 'workshop-migrations/secureshop_agents'],
      ['REVIEW', 'workshop-migrations/secureshop_review'], ['COMMERCE', 'workshop-migrations/secureshop'],
    ]) await migrate(pools[`${store}_MIGRATION`], path.join(a.workspace, 'db/postgres', directory));
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
    for (const file of ['schema.sql', 'migrations/0002_query_receipts.sql',
      'migrations/0003_query_destruction_tombstones.sql'])
      await control.query(await fs.readFile(path.join(a.workspace, 'sidecars/audit-sql-target', file), 'utf8'));
    targetService = require('../../sidecars/audit-sql-target/service')
      .createService({ controlPool: control, clusterConfig: controlConfig });
    auditBackend = require('../../server/services/secureshopOwnedAuditSearchBackend')
      .createOwnedAuditBackend({ journal: require('../../sidecars/audit-sql-target/journal')
        .createJournal({ pool: control }), service: targetService,
      checkReadiness: () => require('../../sidecars/audit-sql-target/readiness')
        .assertReadiness({ pool: control, controlDatabase: controlConfig.database,
          administrator: controlConfig.user }) });
    const privateToken = randomBytes(32).toString('base64url');
    auditHttp = require('../../sidecars/audit-sql-target/http')
      .createPrivateAuditServer({ token: privateToken, backend: auditBackend });
    const privateAddress = await auditHttp.listen();
    rawAuditClient = require('../../server/services/secureshopOwnedAuditHttpClient')
      .createOwnedAuditHttpClient({ url: `http://127.0.0.1:${privateAddress.port}`, token: privateToken });
    const serviceCalls = { target: 0, provision: 0, search: 0, receipt: 0 };
    const auditClient = Object.freeze({ ...rawAuditClient,
      ...Object.fromEntries(Object.keys(serviceCalls).map(method => [method, async input => {
        serviceCalls[method]++; return rawAuditClient[method](input);
      }])) });
    const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
    const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
    const auth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity }) });
    const admin = await auth.login({ username: 'student_admin', password: 'student123' });
    const tenant = await auth.establishTenantContext(admin.context);
    const siblingId = randomUUID(), siblingName = `q64_sibling_${randomUUID().slice(0, 8)}`;
    const siblingHash = await require('bcryptjs').hash('disposable-q64-admin', 12);
    const sibling = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin')
      RETURNING owner_id,shop_user_id`, [siblingId, siblingName,
      `${siblingName}@example.invalid`, siblingHash])).rows[0];
    await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
    [tenant.tenantId, siblingId, sibling.shop_user_id]);
    const siblingLogin = await auth.login({ username: siblingName, password: 'disposable-q64-admin' });
    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(identity);
    const audit = require('../../server/services/secureshopBoundAuditComposition')
      .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
        includeRunArtifacts: true });
    const reset = require('../../server/services/secureshopCleanupComposition')
      .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, leasePool, audit });
    const judge = async () => { judgeCalls++; throw Error('Q64 must not invoke Judge'); };
    const grading = await require('../../server/services/secureshopGradingBootstrap')
      .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
        progress, resetComposition: reset, judge,
        expectedIdentityDatabase: new URL(a.urls.IDENTITY_RUNTIME).pathname.slice(1),
        expectedAgentsDatabase: new URL(a.urls.AGENTS_RUNTIME).pathname.slice(1) });
    const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
      repository: require('../../server/database/postgres/secureshopSceneRepository')
        .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
      reviewPool: review, launches: reset.launches });
    const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
      .createSecureShopModeRepository(identity);
    const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
      .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
    const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
      .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
        audit: audit.agents });
    const ollama = new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)
      ({ baseUrl: process.env.OLLAMA_BASE_URL, model: 'llama3.1:8b' });
    const wireChat = ollama.transport.chat.bind(ollama.transport);
    ollama.transport.chat = async (...args) => {
      assert.ok(++actorCalls <= 15, 'bounded real Ollama wire requests');
      return wireChat(...args);
    };
    const provider = Object.freeze(Object.fromEntries(['chat', 'finalResponse'].map(method => [method,
      async input => {
        const output = await ollama[method]({ ...input, signal: AbortSignal.any([
          AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
        assert.equal(output.provider, 'ollama'); assert.equal(output.model, 'llama3.1:8b');
        assert.equal(output.mocked, false); assert.notEqual(output.fallback, true);
        modelDecisions.push({ method, stopReason: output.stop_reason || null,
          tools: (output.tool_uses || []).map(item => item.name) });
        return output;
      }])));
    let auditApplication;
    const composition = require('../../server/services/secureshopBoundReviewComposition')
      .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, commercePool: commerce, resetComposition: reset,
        gradingBootstrap: grading, scenes, modeAuthority, toolPolicyRepository,
        getAuditSearch: () => auditApplication,
        fixtures: [], requiredObjectives: ['ss_audit_sql_extraction'],
        jwtSecret: 'disposable-q64-persona-secret-at-least-32-bytes',
        agentRuntime: { provider }, judge });
    await composition.repositories.personas.ensureTemplates();
    const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: auth });
    const siblingFirst = await bootstrap(siblingLogin.context);
    const siblingScope = await composition.launches.resolveCapability(siblingFirst.bearer);
    ownedScopes.push(siblingScope);
    auditApplication = await createD22AuditApplication({ identityPool: identity,
      agentsPool: agents, resetComposition: reset, gradingBootstrap: grading,
      launches: composition.launches, personaAuth: composition.personaAuth,
      auditReader: audit.reader, client: auditClient, provider, judge,
      toolPolicyRepository, modeAuthority });
    const standaloneMode = require('../../server/services/secureshopStandaloneMode')
      .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
    const protectedReset = require('../../server/services/secureshopStandaloneReset')
      .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
        launches: composition.launches, scenes,
        resetCoordinator: reset.launchResetCoordinator,
        preflight: reset.sceneResetPreflight });
    const mounted = Object.freeze({ ...composition, auditSearch: auditApplication,
      auditAgentReady: true, standaloneAuth: Object.freeze({ service: auth,
        bootstrap, mode: standaloneMode, reset: protectedReset }),
      personaInbox: Object.freeze({ ready: true, router: express.Router() }),
      mcpTrust: Object.freeze({ ready: true, router: express.Router() }),
      ssrf: Object.freeze({ ready: true, router: express.Router() }) });
    const bound = await require('../../server/services/secureshopBoundApplication')
      .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
        authenticateToken: (_request, response) => response.sendStatus(401),
        audit: async () => {}, agentRuntime: {}, getComposition: async () => mounted });
    assert.equal(mounted.roleAssistants.admin.ready, true);
    const app = express(); app.use(express.json());
    const api = [], chatPosts = [], confirms = [];
    let browserAuth;
    const responseFault = { enabled: false, operationId: null, committed: null,
      lostPost: false, lostFirstGet: false };
    app.use('/api/secureshop', (request, response, next) => {
      const pathname = request.path;
      response.once('finish', () => { if (api.length < 128) api.push({ method: request.method,
        path: pathname, status: response.statusCode }); });
      if (request.method === 'POST' && pathname === '/agents/admin/assistant/chat')
        chatPosts.push(structuredClone(request.body));
      if (request.method === 'POST' && pathname === '/agents/admin/assistant/acl/confirm')
        confirms.push(structuredClone(request.body));
      // A one-shot response-stage fault preserves the real committed service
      // effect. It never replaces a request, a tool result, or a database row.
      const sendJson = response.json.bind(response);
      response.json = body => {
        if (request.method === 'POST' && pathname === '/auth/bootstrap'
          && response.statusCode === 200 && body?.persona?.user?.role === 'admin')
          browserAuth = { launch: body.bearer, token: body.persona.token };
        if (responseFault.enabled && response.statusCode === 200
          && request.method === 'POST'
          && pathname === '/agents/admin/assistant/acl/confirm'
          && body?.ok === true && body.receipt?.operationId === responseFault.operationId
          && !responseFault.lostPost) {
          responseFault.committed = structuredClone(body);
          responseFault.lostPost = true;
          return response.status(502).json({ error: 'Committed acknowledgement lost' });
        }
        if (responseFault.enabled && responseFault.lostPost && !responseFault.lostFirstGet
          && request.method === 'GET'
          && pathname === `/admin/access-control/operations/${responseFault.operationId}`
          && response.statusCode === 200 && body?.ok === true
          && body.receipt?.operationId === responseFault.operationId) {
          responseFault.lostFirstGet = true;
          return response.status(503).json({ error: 'Saved read temporarily unavailable' });
        }
        return sendJson(body);
      };
      next();
    });
    server = await listen(app);
    const origin = `http://127.0.0.1:${server.address().port}`;
    app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthRouter({ service: auth, bootstrap,
        mode: standaloneMode, reset: protectedReset,
        allowedOrigins: [origin], secureCookies: false }));
    app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
      .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
    app.use('/api', (_request, response) => response.status(404).json({ error: 'Outside Q64 qualifier' }));
    app.use(express.static(a.build, { setHeaders: response => response.set('Access-Control-Allow-Origin', '*') }));
    app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: a.build }));
    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-q64-admin-acl-'));
    browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
      executablePath: a.browser, args: await require('../fixtures/secureshopAdminOwnedBrowserAdmission')
        .browserArgs({ cohort: 'admin-acl-chat-browser', root: a.workspace, evidencePath: a.evidence,
          profile, executablePath: a.browser, origin }) });
    earlyBrowserDiagnostic = require('../fixtures/secureshopEarlyBrowserDiagnostic').observeEarlyBrowser(browser);
    if (process.env.SECURESHOP_ROLECHOICES_BROWSER_RECORD_PATH)
      await require('../fixtures/secureshopRoleChoicesBrowserBirth').acknowledge({ root: a.workspace, evidencePath: a.evidence, profile, browser });
    earlyBrowserDiagnostic.stage('new-page');
    const page = await browser.newPage();
    earlyBrowserDiagnostic.stage('viewport');
    await page.setViewport({ width: 1280, height: 900 });
    earlyBrowserDiagnostic.stage('ready'); earlyBrowserDiagnostic.detach();
    const pageErrors = []; page.on('pageerror', error => pageErrors.push(error.message.slice(0, 160)));
    await page.setRequestInterception(true);
    page.on('request', request => request.url().startsWith(`${origin}/`)
      ? request.continue() : request.abort());
    assert.equal((await page.goto(`${origin}/secureshop/login?next=%2Fsecureshop%2Fadmin`)).status(), 200);
    await page.waitForSelector('#ss-login-user');
    await page.type('#ss-login-user', 'student_admin'); await page.type('#ss-login-pw', 'student123');
    await page.click('button[type="submit"]');
    await page.waitForFunction(() => location.pathname === '/secureshop/admin', { timeout: 30000 });
    let frame = await frameFor(page);
    await frame.waitForSelector('[data-testid="admin-role-composer-slot"] textarea');
    assert.equal(pageErrors.length, 0);
    const cookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
      .find(item => item.name === 'dvaia_shop_session');
    assert.equal(cookie?.httpOnly, true);
    const current = await auth.authenticate(cookie.value);
    assert.equal(current?.principalId, tenant.principalId);
    assert.ok(browserAuth?.launch && browserAuth?.token);
    const adminScope = await composition.launches.resolveCapability(browserAuth.launch);
    ownedScopes.push(adminScope);
    const adminActor = await composition.personaAuth.authenticateBoundToken({
      scope: adminScope, token: browserAuth.token });
    assert.equal(adminActor.user.role, 'admin');
    const actor = { id: adminActor.user.id, role: 'admin' };
    const actorSession = { sessionId: adminActor.sessionId,
      authorityVersion: adminActor.authorityVersion };
    assert.notEqual(adminScope.launchId, siblingScope.launchId);
    assert.notEqual(current.principalId, siblingLogin.context.principalId);
    status.genuineAdminUiSession = true;
    const headers = { 'x-dvaia-secureshop-launch': browserAuth.launch,
      authorization: `Bearer ${browserAuth.token}` };
    const policyInput = { scope: adminScope, persona: actor, personaSession: actorSession };
    const baseline = await toolPolicyRepository.readPolicy(policyInput);
    const auditTool = baseline.rows.find(row => row.toolKey === 'admin.audit_search');
    assert.equal(auditTool?.supported, true);
    assert.equal(auditTool.roleApplicability.admin, true);
    assert.equal(auditTool.allowed.admin, true);
    assert.equal(baseline.enforcement, false);
    assert.equal((await operationRows(agents, adminScope)).length, 0);
    const beforeJudgments = await queryCount(identity,
      'SELECT count(*)::int AS n FROM secureshop_auth.assessment_judgments WHERE principal_id=$1',
      [tenant.principalId]);
    const beforeCredit = await queryCount(identity,
      'SELECT count(*)::int AS n FROM secureshop_auth.assessment_completions WHERE principal_id=$1',
      [tenant.principalId]);

    const turn = async options => {
      const next = chatPosts.length + 1;
      const value = await roleTurn({ page, frame, origin, authority: browserAuth,
        posts: chatPosts, expectedPosts: next, ...options });
      status.roleTurns = next;
      assert.equal(chatPosts.length, next);
      assert.ok(value.hops.length > 0);
      return value;
    };
    const listed = await turn({ message: 'List access-control permissions matching admin.audit_search.' });
    assert.equal(listed.aclPage?.page, 1);
    assert.ok(listed.aclPage.total >= 1);
    assert.equal(listed.aclPage.search, 'admin.audit_search');
    const choice = listed.cards?.find(card => card.kind === 'admin_acl_permission'
      && card.title === 'admin.audit_search');
    assert.ok(choice && UUID.test(choice.choiceId));
    assert.ok(listed.hops.some(hop => hop.tool === 'admin.acl_list' && !hop.error));
    await frame.waitForSelector('[aria-label="Admin permission choices"]');
    await frame.waitForFunction(() => [...document.querySelectorAll(
      '[aria-label="Admin permission choices"] strong')]
      .some(node => node.textContent === 'admin.audit_search'));
    status.actualModelAclListed = true;

    const deny = await turn({ button: 'Review deny permission for admin.audit_search' });
    const permission = deny.aclProposal;
    assert.equal(permission?.action, 'permission');
    assert.equal(permission.choiceId, choice.choiceId);
    assert.deepEqual(permission.tool, { toolKey: 'admin.audit_search', role: 'admin' });
    assert.deepEqual(permission.before, { allowed: true, enforcement: false });
    assert.deepEqual(permission.after, { allowed: false, enforcement: false });
    assert.equal(permission.expectedVersion, baseline.version);
    assert.ok(deny.hops.some(hop => hop.tool === 'admin.acl_permission_prepare' && !hop.error));
    assert.deepEqual(await operationRows(agents, adminScope), []);
    assert.equal((await toolPolicyRepository.readPolicy(policyInput)).version, baseline.version);
    await frame.waitForFunction(() => [...document.querySelectorAll(
      'section[aria-label="Admin access control review"] button')]
      .some(node => node.textContent?.trim() === 'Confirm ACL change' && !node.disabled));
    status.permissionProposalNoEffect = true;

    // Lose a real committed HTTP 200 ACK and the first following exact GET.
    // The only recovery path is a saved GET after a rendered reload.
    const operationPath = `/api/secureshop/admin/access-control/operations/${permission.proposalId}`;
    responseFault.operationId = permission.proposalId;
    responseFault.enabled = true;
    await physical(frame, 'Confirm ACL change', 'section[aria-label="Admin access control review"]');
    await frame.waitForFunction(() => [...document.querySelectorAll(
      'section[aria-label="Admin access control review"] button')]
      .some(node => node.textContent?.trim() === 'Check saved ACL change' && !node.disabled),
    { timeout: 30000 });
    assert.equal(responseFault.lostPost, true);
    assert.equal(responseFault.lostFirstGet, true);
    const committed = responseFault.committed;
    assert.equal(committed?.ok, true);
    assert.equal(committed.receipt.operationId, permission.proposalId);
    responseFault.enabled = false;
    assert.equal(confirms.length, 1);
    assert.deepEqual(confirms[0], { sessionId: deny.sessionId,
      requestId: deny.requestId, proposalId: permission.proposalId });
    const savedPermission = (await operationRows(agents, adminScope));
    assert.equal(savedPermission.length, 1);
    assert.deepEqual(savedPermission[0].receipt_json, committed.receipt);
    assert.equal(savedPermission[0].persona_id, actor.id);
    assert.equal(savedPermission[0].persona_session_id, actorSession.sessionId);
    assert.equal(String(savedPermission[0].policy_version), committed.receipt.version);
    status.physicalPermissionConfirmed = true;

    const beforeRecoveryCalls = actorCalls, beforeRecoveryPosts = confirms.length;
    assert.ok([200, 304].includes((await page.reload({ waitUntil: 'domcontentloaded' })).status()));
    frame = await frameFor(page);
    await physical(frame, 'Check saved ACL change', 'section[aria-label="Admin access control review"]');
    await frame.waitForFunction(expected => [...document.querySelectorAll(
      'section[aria-label="Admin access control review"] [role="status"]')]
      .some(node => node.textContent?.includes(`Saved policy version ${expected}`)),
    { timeout: 30000 }, committed.receipt.version);
    const permissionRead = await fetch(`${origin}${operationPath}`, { headers });
    assert.equal(permissionRead.status, 200);
    assert.deepEqual(await permissionRead.json(), committed);
    assert.equal(confirms.length, beforeRecoveryPosts);
    assert.equal(actorCalls, beforeRecoveryCalls);
    assert.deepEqual((await operationRows(agents, adminScope))[0].receipt_json, committed.receipt);
    status.permissionLostAckExactGetRecovery = true;

    // Denied permission is advisory until enforcement is physically enabled.
    const beforeSearchCalls = serviceCalls.search;
    const allowed = await turn({ message: 'Use the owned audit SQL search for the exact username student_admin.' });
    assert.ok(allowed.hops.some(hop => hop.tool === 'admin.audit_search' && !hop.error));
    assert.equal(allowed.auditSearch?.status, 'completed');
    assert.ok(UUID.test(allowed.auditSearch.operationId));
    const query = (await identity.query(`SELECT operation_id,request_json,receipt_json
      FROM identity.secureshop_audit_manual_operations WHERE operation_id=$1`,
    [allowed.auditSearch.operationId])).rows[0];
    assert.ok(query?.receipt_json);
    assert.equal(query.receipt_json.result.ok, true);
    assert.equal(query.receipt_json.result.username, 'student_admin');
    const privateReceipt = await rawAuditClient.receipt({ binding: adminScope,
      operationId: allowed.auditSearch.operationId, username: 'student_admin' });
    assert.deepEqual(privateReceipt, query.receipt_json,
      'owned audit SQL target and durable central receipt must agree exactly');
    assert.equal(serviceCalls.search, beforeSearchCalls + 1);
    const auditDetail = await fetch(`${origin}/api/secureshop/agents/admin/assistant/audit/operations/${allowed.sessionId}/${allowed.requestId}/${allowed.auditSearch.operationId}`,
      { headers });
    assert.equal(auditDetail.status, 200);
    assert.deepEqual((await auditDetail.json()).result, query.receipt_json.result);

    const enforce = await turn({ message: 'Turn access-control enforcement on now.' });
    const enforcement = enforce.aclProposal;
    assert.equal(enforcement?.action, 'enforcement');
    assert.deepEqual(enforcement.before, { enforcement: false });
    assert.deepEqual(enforcement.after, { enforcement: true });
    assert.equal(enforcement.expectedVersion, committed.receipt.version);
    assert.ok(enforce.hops.some(hop => hop.tool === 'admin.acl_enforcement_prepare' && !hop.error));
    assert.equal((await operationRows(agents, adminScope)).length, 1);
    assert.equal((await toolPolicyRepository.readPolicy(policyInput)).enforcement, false);
    status.enforcementProposalNoEffect = true;
    await physical(frame, 'Confirm ACL change', 'section[aria-label="Admin access control review"]');
    await frame.waitForFunction(() => [...document.querySelectorAll(
      'section[aria-label="Admin access control review"] [role="status"]')]
      .some(node => node.textContent?.includes('enforcement on')), { timeout: 30000 });
    assert.equal(confirms.length, 2);
    const enforcedRows = await operationRows(agents, adminScope);
    assert.equal(enforcedRows.length, 2);
    const enforced = enforcedRows.find(row => row.operation_id === enforcement.proposalId);
    assert.ok(enforced);
    assert.equal(enforced.receipt_json.enforcement, true);
    assert.equal(enforced.receipt_json.version, String(BigInt(committed.receipt.version) + 1n));
    status.physicalEnforcementConfirmed = true;
    const beforeEnforceReplayCalls = actorCalls;
    const enforcementRead = await fetch(`${origin}/api/secureshop/admin/access-control/operations/${enforcement.proposalId}`,
      { headers });
    assert.equal(enforcementRead.status, 200);
    assert.deepEqual((await enforcementRead.json()).receipt, enforced.receipt_json);
    assert.equal(confirms.length, 2);
    assert.equal(actorCalls, beforeEnforceReplayCalls);
    status.enforcementExactGetNoReplay = true;

    const beforeDeniedSearch = serviceCalls.search;
    const beforeEffects = await queryCount(identity,
      "SELECT count(*)::int AS n FROM graph_runtime.effects WHERE effect_key LIKE '%:owned-audit-query:%'");
    const beforeAuditOperations = await queryCount(identity,
      'SELECT count(*)::int AS n FROM identity.secureshop_audit_manual_operations');
    const blocked = await turn({ message: 'Use the owned audit SQL search for the exact username student_admin.' });
    assert.ok(blocked.hops.some(hop => hop.tool === 'admin.audit_search' && (hop.error || hop.result?.isError)));
    assert.equal(blocked.auditSearch, null);
    assert.equal(serviceCalls.search, beforeDeniedSearch);
    assert.equal(await queryCount(identity,
      "SELECT count(*)::int AS n FROM graph_runtime.effects WHERE effect_key LIKE '%:owned-audit-query:%'"), beforeEffects);
    assert.equal(await queryCount(identity,
      'SELECT count(*)::int AS n FROM identity.secureshop_audit_manual_operations'), beforeAuditOperations);
    const auditAdmissions = (await admissionRows(agents, adminScope))
      .filter(row => row.tool_key === 'admin.audit_search');
    assert.equal(auditAdmissions.length, 2);
    assert.deepEqual(auditAdmissions.map(row => [row.allowed, row.enforcement_enabled, row.action]),
      [[false, false, 'dispatch'], [false, true, 'block']]);
    assert.equal(auditAdmissions[0].persona_id, actor.id);
    assert.equal(auditAdmissions[1].persona_id, actor.id);
    assert.equal(auditAdmissions[0].persona_session_id, actorSession.sessionId);
    assert.equal(auditAdmissions[1].persona_session_id, actorSession.sessionId);
    assert.equal(String(auditAdmissions[0].policy_version), committed.receipt.version);
    assert.equal(String(auditAdmissions[1].policy_version), enforced.receipt_json.version);
    status.allowedDeniedAclEffects = true;

    const foreign = await fetch(`${origin}${operationPath}`, { headers: {
      'x-dvaia-secureshop-launch': siblingFirst.bearer,
      authorization: `Bearer ${siblingFirst.persona.token}` } });
    assert.equal(foreign.status, 404);
    assert.equal((await operationRows(agents, siblingScope)).length, 0);
    status.siblingOperationDenied = true;

    for (const row of [...enforcedRows, ...auditAdmissions]) {
      const id = row.operation_id || row.admission_id;
      const action = row.operation_id ? 'tool_policy_changed' : 'tool_policy_admission';
      const event = (await agents.query(`SELECT launch_id,scenario_id,generation,
        original_platform_owner_id,original_platform_session_id,shop_user_id,shop_role,
        action,source_kind,source_id,params_json FROM secureshop_agents.bound_audit_events
        WHERE launch_id=$1 AND scenario_id=$2 AND generation=$3
          AND original_platform_owner_id=$4 AND original_platform_session_id=$5
          AND source_kind='bound_tool_policy' AND source_id=$6 AND action=$7`,
      [adminScope.launchId, adminScope.scenarioId, adminScope.generation,
        adminScope.platformOwnerId, adminScope.platformSessionId, id, action])).rows;
      assert.equal(event.length, 1);
      assert.equal(event[0].shop_user_id, actor.id);
      assert.equal(event[0].shop_role, 'admin');
      const detail = JSON.parse(event[0].params_json);
      assert.equal(detail.operationId || detail.admissionId, id);
      if (row.operation_id) assert.deepEqual(detail, row.receipt_json);
      else {
        assert.equal(detail.toolKey, row.tool_key);
        assert.equal(detail.policyVersion, String(row.policy_version));
        assert.equal(detail.allowed, row.allowed);
        assert.equal(detail.action, row.action);
      }
    }
    status.auditSourceBound = true;
    assert.equal(judgeCalls, 0);
    assert.equal(await queryCount(identity,
      'SELECT count(*)::int AS n FROM secureshop_auth.assessment_judgments WHERE principal_id=$1',
      [tenant.principalId]), beforeJudgments);
    assert.equal(await queryCount(identity,
      'SELECT count(*)::int AS n FROM secureshop_auth.assessment_completions WHERE principal_id=$1',
      [tenant.principalId]), beforeCredit);
    status.noObjectiveCredit = true;

    const resetReady = await protectedReset.readiness(current);
    assert.equal(resetReady.available, true);
    const resetResult = await protectedReset.reset(current, { launchId: resetReady.launchId,
      sceneId: resetReady.scene.id, expectedGeneration: adminScope.generation,
      idempotencyKey: randomUUID(), confirmation: 'RESET_SHARED_PRACTICE' });
    assert.equal(resetResult.status, 'committed');
    const afterReset = await fetch(`${origin}${operationPath}`, { headers });
    assert.equal(afterReset.status, 401);
    status.resetSessionDenied = true;
    assert.equal(status.roleTurns, 5);
    assert.ok(actorCalls >= 9 && actorCalls <= 15);
    assert.equal(pageErrors.length, 0);
    status.passed = true;
  } catch (error) {
    status.errors.push(String(error.code || error.name || 'Error'));
    t.diagnostic(JSON.stringify({ phase: 'q64-qualification', modelDecisions,
      earlyBrowser: earlyBrowserDiagnostic?.snapshot() || { stage: 'launch', attached: false },
      actorCalls, judgeCalls, errorCode: error.code || error.name || 'Error' }));
    throw error;
  } finally {
    earlyBrowserDiagnostic?.detach();
    status.actorCalls = actorCalls; status.judgeCalls = judgeCalls;
    for (const [label, close] of [
      ['browser', async () => browser?.close()],
      ['server', async () => closeServer(server)],
      ['audit-retirement', async () => {
        if (auditBackend) for (const scope of ownedScopes) await auditBackend.retire({ binding: scope });
      }],
      ['audit-http', async () => auditHttp?.close()],
      ['audit-service', async () => targetService?.close()],
      ['audit-control', async () => control.end()],
      ['lease', async () => leasePool.end()],
      ...Object.entries(pools).map(([name, pool]) => [name, async () => pool.end()]),
      ['browser-profile', async () => { if (profile) await fs.rm(profile, { recursive: true, force: true }); }],
    ]) try { await close(); } catch (error) { cleanupErrors.push(`${label}:${error.code || error.name}`); }
    status.fixtureCleaned = cleanupErrors.length === 0;
    if (!status.fixtureCleaned) status.passed = false;
    assert.ok(Buffer.byteLength(JSON.stringify(status), 'utf8') < 4096);
    await fs.writeFile(a.evidence, `${JSON.stringify(status)}\n`, { flag: 'wx', mode: 0o600 });
    if (cleanupErrors.length) throw Error(`Q64 cleanup failed: ${cleanupErrors.join(', ')}`);
  }
  validateQ64Receipt(status);
});

module.exports = { ASSERTION, _internals: { admission, frameFor, physical } };
