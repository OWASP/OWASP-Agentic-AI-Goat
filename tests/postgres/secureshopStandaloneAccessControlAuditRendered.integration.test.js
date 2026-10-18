'use strict';

// D22 runs only under the disposable agent-host launcher. The browser changes
// the real bound ACL; the actual local model selects the owned audit tool.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomBytes, randomUUID } = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { qualifyRenderedD22 } = require('../helpers/secureshopAccessControlD22Qualification');
const { createD22AuditApplication } = require('../helpers/secureshopD22ProductionAssembly');

const assertion = 'standalone administrator proves D22 access-control enforcement through rendered audit workflow and actual local llama3.1:8b actor with canonical grading boundary';
const names = ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE'];
const prefix = 'PG_SECURESHOP_STANDALONE_D22_';
const required = [
  'SECURESHOP_STANDALONE_D22_EVIDENCE_PATH', 'SECURESHOP_STANDALONE_D22_BUILD',
  'DVAIA_CURRENT_MAIN_WORKSPACE', 'PUPPETEER_EXECUTABLE_PATH',
  'SECURESHOP_STANDALONE_D22_AUDIT_CONTROL_URL', 'OLLAMA_BASE_URL', 'OLLAMA_MODEL',
  ...names.flatMap(name => [`${prefix}${name}_RUNTIME_URL`, `${prefix}${name}_MIGRATION_URL`]),
];
const storeNames = { IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' };
const scope = 'current-main standalone administrator rendered Access Control and Audit, owned target, actual local llama3.1:8b actor with canonical grading boundary';
const flagNames = ['passed', 'renderedAccessControlMutations', 'allowedActualModelEffect',
  'deniedNoDispatch', 'deniedNoQueryEffect', 'deniedNoJudgment', 'deniedNoCredit',
  'auditReadback', 'renderedAuditAllowedDenied', 'siblingPrivate', 'cleanupComplete'];

function privateEvidencePath() {
  const value = process.env.SECURESHOP_STANDALONE_D22_EVIDENCE_PATH;
  assert.ok(value && path.isAbsolute(value));
  assert.ok(!require('node:fs').existsSync(value), 'new private D22 receipt path required');
  const workspace = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/');
  assert.ok(!path.resolve(value).startsWith(`${workspace}${path.sep}`));
  return value;
}
function assertNativeAdmission() {
  assert.equal(process.env.SECURESHOP_STANDALONE_D22_NATIVE, '1');
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(process.env.LIVE_OLLAMA_TEST, '1');
  assert.equal(process.env.OLLAMA_BASE_URL, 'http://127.0.0.1:11434');
  assert.equal(process.env.OLLAMA_MODEL, 'llama3.1:8b');
  assert.equal(process.env.AI_PROVIDER, 'ollama');
  assert.equal(process.env.JUDGE_PROVIDER, 'ollama');
  assert.equal(process.env.JUDGE_MODEL, 'llama3.1:8b');
  assert.equal(process.env.LAB_MODE, 'vuln', 'fixed mode preempts ACL admission');
  for (const key of required) assert.ok(process.env[key], `required ${key}`);
  const target = new URL(process.env.SECURESHOP_STANDALONE_D22_AUDIT_CONTROL_URL);
  assert.equal(target.protocol, 'postgresql:');
  assert.equal(target.hostname, '127.0.0.1');
  assert.match(target.pathname, /^\/dvaia_audit_control_[a-f0-9]+$/);
  assert.equal(target.username, 'postgres');
  assert.equal(target.password, ''); assert.equal(target.search, ''); assert.equal(target.hash, '');
}
function storeUrls() {
  const urls = {}; let nonce; let port;
  for (const store of names) {
    for (const role of ['MIGRATION', 'RUNTIME']) {
      const key = `${store}_${role}`;
      const url = new URL(process.env[`${prefix}${key}_URL`]);
      assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.port, /^[1-9][0-9]{0,4}$/); assert.ok(Number(url.port) <= 65535);
      assert.equal(url.username, `dvaia_${storeNames[store]}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      const match = new RegExp(`^/dvaia_test_agent_host_([0-9a-f]{12})_${storeNames[store]}$`).exec(url.pathname);
      assert.ok(match, `closed disposable ${key} database required`);
      nonce ??= match[1]; port ??= url.port;
      assert.equal(match[1], nonce); assert.equal(url.port, port);
      urls[key] = url.href;
    }
    assert.equal(new URL(urls[`${store}_MIGRATION`]).pathname,
      new URL(urls[`${store}_RUNTIME`]).pathname);
  }
  assert.equal(new Set(names.map(store => new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return Object.freeze(urls);
}
async function listen(app) {
  return new Promise(resolve => { const server = app.listen(0, '127.0.0.1', () => resolve(server)); });
}
async function stableFrame(page, selector) {
  const until = Date.now() + 30000;
  while (Date.now() < until) {
    const element = await page.$('iframe[title="SecureShop"]');
    const frame = element && await element.contentFrame().catch(() => null);
    if (frame && !frame.detached && (!selector || await frame.evaluate(
      value => Boolean(document.querySelector(value)), selector).catch(() => false))) return frame;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw Error('Standalone bound SecureShop frame did not mount');
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
async function count(pool, table, where, args) {
  return Number((await pool.query(`SELECT count(*)::int AS n FROM ${table} WHERE ${where}`, args)).rows[0].n);
}
async function auditRows(pool, selected) {
  return (await pool.query(`SELECT admission_id,run_id,invocation_id,platform_launch_id,
    platform_scenario_id,platform_launch_generation,original_platform_owner_id,
    original_platform_session_id,persona_id,persona_session_id,persona_role,
    authority_version,tool_key,registry_sha256,policy_version,
    enforcement_enabled,allowed,action,policy_violation
    FROM secureshop_agents.bound_tool_admissions
    WHERE platform_launch_id=$1 AND platform_scenario_id=$2
      AND platform_launch_generation=$3 AND original_platform_owner_id=$4
      AND original_platform_session_id=$5 ORDER BY created_at,admission_id`,
  [selected.launchId, selected.scenarioId, selected.generation,
    selected.platformOwnerId, selected.platformSessionId])).rows;
}
function admissionProof(row) {
  assert.ok(row); assert.equal(row.persona_role, 'admin');
  return {
    admission: { allowed: row.allowed, action: row.action, toolKey: row.tool_key },
    context: { launchId: row.platform_launch_id, scenarioId: row.platform_scenario_id,
      generation: String(row.platform_launch_generation),
      platformOwnerId: String(row.original_platform_owner_id),
      platformSessionId: String(row.original_platform_session_id),
      personaId: String(row.persona_id), personaSessionId: row.persona_session_id,
      authorityVersion: String(row.authority_version), policyVersion: String(row.policy_version),
      registrySha256: Buffer.from(row.registry_sha256).toString('hex'),
      runId: row.run_id, invocationId: row.invocation_id },
  };
}

// This test may allocate only the launcher-provided disposable stores, target,
// browser and local model. A controlled-provider result cannot pass D22.
test(assertion, { skip: process.env.SECURESHOP_STANDALONE_D22_NATIVE !== '1', timeout: 540000 }, async t => {
  assertNativeAdmission();
  const workspace = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE);
  assert.equal(workspace, process.cwd(), 'current checkout required; no source copy');
  const evidencePath = privateEvidencePath();
  const build = path.resolve(process.env.SECURESHOP_STANDALONE_D22_BUILD);
  assert.equal(build, path.join(workspace, 'client/build'));
  await fs.access(path.join(build, 'index.html'));
  await fs.access(path.join(build, 'secureshop-frame.html'));
  const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
  assert.ok(path.isAbsolute(executablePath)); await fs.access(executablePath);
  const urls = storeUrls();
  const targetURL = new URL(process.env.SECURESHOP_STANDALONE_D22_AUDIT_CONTROL_URL);
  assert.notEqual(targetURL.port, new URL(urls.IDENTITY_RUNTIME).port,
    'audit SQL target is a separate owned cluster');
  const status = Object.fromEntries(flagNames.map(name => [name, false]));
  status.scope = scope;
  const pools = Object.fromEntries(names.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
    const key = `${store}_${role}`;
    return [key, new Pool({ connectionString: urls[key], max: role === 'RUNTIME' ? 12 : 3 })];
  })));
  const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4 });
  const controlConfig = { host: targetURL.hostname, port: Number(targetURL.port),
    user: targetURL.username, database: targetURL.pathname.slice(1) };
  const control = new Pool({ ...controlConfig, max: 2 });
  let auditHttp; let targetService; let auditBackend; let server; let browser; let profile;
  const ownedScopes = []; const cleanupErrors = [];
  try {
    for (const [store, directory] of [
      ['IDENTITY', 'identity-migrations'], ['AGENTS', 'workshop-migrations/secureshop_agents'],
      ['REVIEW', 'workshop-migrations/secureshop_review'], ['COMMERCE', 'workshop-migrations/secureshop'],
    ]) await migrate(pools[`${store}_MIGRATION`], path.join(workspace, 'db/postgres', directory));
    await require('../../server/database/postgres/workshopPlatformSeed')
      .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
    await require('../../server/database/postgres/secureshopAssessmentSeed')
      .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
    await require('../../server/database/postgres/secureshopStandaloneSeed')
      .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
    const seedClient = await pools.COMMERCE_MIGRATION.connect();
    try { await seedClient.query('BEGIN');
      await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seedClient);
      await seedClient.query('COMMIT');
    } catch (error) { await seedClient.query('ROLLBACK'); throw error; }
    finally { seedClient.release(); }
    for (const file of ['schema.sql', 'migrations/0002_query_receipts.sql',
      'migrations/0003_query_destruction_tombstones.sql'])
      await control.query(await fs.readFile(path.join(workspace, 'sidecars/audit-sql-target', file), 'utf8'));
    targetService = require('../../sidecars/audit-sql-target/service')
      .createService({ controlPool: control, clusterConfig: controlConfig });
    auditBackend = require('../../server/services/secureshopOwnedAuditSearchBackend')
      .createOwnedAuditBackend({ journal: require('../../sidecars/audit-sql-target/journal')
        .createJournal({ pool: control }), service: targetService,
      checkReadiness: () => require('../../sidecars/audit-sql-target/readiness')
        .assertReadiness({ pool: control, controlDatabase: controlConfig.database,
          administrator: controlConfig.user }) });
    const privateToken = randomBytes(32).toString('base64url');
    auditHttp = require('../../sidecars/audit-sql-target/http').createPrivateAuditServer({
      token: privateToken, backend: auditBackend });
    const privateAddress = await auditHttp.listen();
    const rawAuditClient = require('../../server/services/secureshopOwnedAuditHttpClient')
      .createOwnedAuditHttpClient({ url: `http://127.0.0.1:${privateAddress.port}`,
        token: privateToken });
    const serviceCalls = { target: 0, provision: 0, search: 0, receipt: 0 };
    const auditClient = Object.freeze({ ...rawAuditClient,
      ...Object.fromEntries(Object.keys(serviceCalls).map(method => [method, async input => {
        serviceCalls[method]++;
        return rawAuditClient[method](input);
      }])) });
    const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
    const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
    const auth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity }) });
    const admin = await auth.login({ username: 'student_admin', password: 'student123' });
    const siblingId = randomUUID(), siblingName = `d22_sibling_${randomUUID().slice(0, 8)}`;
    const siblingHash = await require('bcryptjs').hash('disposable-d22-admin', 12);
    const sibling = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin')
      RETURNING owner_id,shop_user_id`, [siblingId, siblingName,
      `${siblingName}@example.invalid`, siblingHash])).rows[0];
    const tenant = await auth.establishTenantContext(admin.context);
    await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
    [tenant.tenantId, siblingId, sibling.shop_user_id]);
    const siblingLogin = await auth.login({ username: siblingName, password: 'disposable-d22-admin' });
    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(identity);
    const audit = require('../../server/services/secureshopBoundAuditComposition')
      .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
        includeRunArtifacts: true });
    const reset = require('../../server/services/secureshopCleanupComposition')
      .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, leasePool, audit });
    const judgeEngine = require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge();
    let judgeCalls = 0;
    const judge = async input => { assert.ok(++judgeCalls <= 1); return judgeEngine(input); };
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
    const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
      .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
    const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
      .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
        audit: audit.agents });
    const ollama = new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)
      ({ baseUrl: process.env.OLLAMA_BASE_URL, model: 'llama3.1:8b' });
    let actorCalls = 0; const modelDecisions = [];
    const provider = Object.freeze(Object.fromEntries(['chat', 'finalResponse'].map(method => [method,
      async input => {
        assert.ok(++actorCalls <= 6, 'bounded actual local actor calls');
        const output = await ollama[method]({ ...input, signal: AbortSignal.any([
          AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
        assert.equal(output.provider, 'ollama'); assert.equal(output.model, 'llama3.1:8b');
        assert.equal(output.mocked, false); assert.notEqual(output.fallback, true);
        modelDecisions.push({ method, stopReason: output.stop_reason || null,
          toolNames: (output.tool_uses || []).map(value => value.name) });
        return output;
      }])));
    let composition = require('../../server/services/secureshopBoundReviewComposition')
      .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, commercePool: commerce, resetComposition: reset,
        gradingBootstrap: grading, scenes, modeAuthority, toolPolicyRepository,
        fixtures: [], requiredObjectives: ['ss_audit_sql_extraction'],
        jwtSecret: 'disposable-d22-persona-secret-at-least-32-bytes',
        agentRuntime: { provider }, judge });
    await composition.repositories.personas.ensureTemplates();
    const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: auth });
    const siblingFirst = await bootstrap(siblingLogin.context);
    const siblingScope = await composition.launches.resolveCapability(siblingFirst.bearer);
    ownedScopes.push(siblingScope);
    const siblingActor = await composition.personaAuth.authenticateBoundToken({
      scope: siblingScope, token: siblingFirst.persona.token });
    assert.equal(siblingActor.user.role, 'admin');
    await toolPolicyRepository.readPolicy({ scope: siblingScope,
      persona: { id: siblingActor.user.id, role: 'admin' },
      personaSession: { sessionId: siblingActor.sessionId,
        authorityVersion: siblingActor.authorityVersion } });
    const auditApplication = await createD22AuditApplication({ identityPool: identity,
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
    const observedAuditApplication = Object.freeze({...auditApplication,
      async runAgent(...args) {
        try { return await auditApplication.runAgent(...args); }
        catch (error) {
          t.diagnostic(JSON.stringify({stage:'audit-agent-failure',name:error.name,
            code:error.code || null,actorCalls,modelDecisions,
            callers:String(error.stack || '').split('\n').slice(1,5)
              .map(value=>value.replaceAll(workspace,'<workspace>'))}));
          throw error;
        }
      }});
    const mounted = Object.freeze({ ...composition, auditSearch: observedAuditApplication,
      auditAgentReady: true, standaloneAuth: Object.freeze({ service: auth,
        bootstrap, mode: standaloneMode, reset: protectedReset }),
      personaInbox: Object.freeze({ ready: true, router: express.Router() }),
      mcpTrust: Object.freeze({ ready: true, router: express.Router() }),
      ssrf: Object.freeze({ ready: true, router: express.Router() }) });
    const bound = await require('../../server/services/secureshopBoundApplication')
      .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
        authenticateToken: (_request, response) => response.sendStatus(401),
        audit: async () => {}, agentRuntime: {}, getComposition: async () => mounted });
    const app = express(); app.use(express.json());
    const agentPosts = [];
    const apiStatuses = [];
    let observedBrowserBoundAuth = null;
    app.use('/api/secureshop', (request, _response, next) => {
      const requestPath = request.path;
      _response.once('finish', () => {
        if (apiStatuses.length < 64) apiStatuses.push({method:request.method,
          path:requestPath,status:_response.statusCode});
      });
      if (request.method === 'POST' && request.path === '/admin/audit/agent-search')
        agentPosts.push(structuredClone(request.body));
      if (request.method === 'GET' && request.path === '/admin/access-control'
        && request.headers['x-dvaia-secureshop-launch']
        && /^Bearer \S+$/.test(request.headers.authorization || ''))
        observedBrowserBoundAuth = { launch: request.headers['x-dvaia-secureshop-launch'],
          token: request.headers.authorization.slice('Bearer '.length) };
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
    app.use('/api', (_request, response) => response.status(404).json({ error: 'Outside D22 qualifier' }));
    // The storefront frame has an opaque sandbox origin. Its public module
    // assets need cross-origin delivery, as in the passing commerce fixture.
    app.use(express.static(build, {setHeaders:response=>response.set('Access-Control-Allow-Origin','*')}));
    app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));
    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-standalone-d22-'));
    browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
      executablePath });
    const page = await browser.newPage(); await page.setViewport({ width: 1280, height: 900 });
    const pageErrors = []; page.on('pageerror', error => pageErrors.push(error.message.slice(0, 200)));
    await page.setRequestInterception(true);
    page.on('request', request => request.url().startsWith(`${origin}/`)
      ? request.continue() : request.abort());
    assert.equal((await page.goto(`${origin}/secureshop/login?next=%2Fsecureshop%2Fadmin%2Faccess-control`)).status(), 200);
    await page.waitForSelector('#ss-login-user');
    await page.type('#ss-login-user', 'student_admin'); await page.type('#ss-login-pw', 'student123');
    await page.click('button[type="submit"]');
    await page.waitForFunction(() => location.pathname === '/secureshop/admin/access-control', {timeout:30000});
    let frame;
    try {
      frame = await stableFrame(page, '[data-testid="acl-cell-audit.search_by_user-admin"]');
      await frame.waitForSelector('[data-testid="acl-cell-audit.search_by_user-admin"]', { timeout: 30000 });
    } catch (error) {
      t.diagnostic(JSON.stringify({stage:'initial-access-control',apiStatuses,pageErrors,
        parent:await page.evaluate(()=>({path:location.pathname,
          headings:[...document.querySelectorAll('h1,h2')].map(n=>n.textContent?.slice(0,160)),
          alerts:[...document.querySelectorAll('[role="alert"]')].map(n=>n.textContent?.slice(0,160))})),
        frame:frame ? await frame.evaluate(()=>({path:location.pathname,
          headings:[...document.querySelectorAll('h1,h2')].map(n=>n.textContent?.slice(0,160)),
          alerts:[...document.querySelectorAll('[role="alert"]')].map(n=>n.textContent?.slice(0,160))})).catch(()=>({detached:true})) : null}));
      throw error;
    }
    assert.equal(pageErrors.length, 0, `rendered page errors: ${pageErrors.join(', ')}`);
    const cookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
      .find(value => value.name === 'dvaia_shop_session');
    assert.equal(cookie?.httpOnly, true);
    const current = await auth.authenticate(cookie.value);
    assert.equal(current?.principalId, tenant.principalId);
    assert.ok(observedBrowserBoundAuth, 'real rendered ACL request must carry bound authority');
    const adminScope = await composition.launches.resolveCapability(observedBrowserBoundAuth.launch);
    ownedScopes.push(adminScope);
    assert.notEqual(adminScope.launchId, siblingScope.launchId,
      'sibling administrator must retain a distinct execution launch');
    assert.notEqual(current.principalId, siblingLogin.context.principalId,
      'sibling policy belongs to another immutable shop principal');
    const adminActor = await composition.personaAuth.authenticateBoundToken({
      scope: adminScope, token: observedBrowserBoundAuth.token });
    assert.equal(adminActor.user.role, 'admin');
    const actor = { id: adminActor.user.id, role: 'admin' };
    const actorSession = { sessionId: adminActor.sessionId,
      authorityVersion: adminActor.authorityVersion };
    const siblingHead = async () => (await agents.query(`SELECT policy_version,enforcement_enabled,
      encode(registry_sha256,'hex') AS registry_sha256 FROM secureshop_agents.bound_tool_policy_heads
      WHERE original_platform_owner_id=$1 AND platform_launch_id=$2`,
    [siblingScope.platformOwnerId, siblingScope.launchId])).rows;
    const readSibling = async () => {
      const heads = await siblingHead();
      assert.equal(heads.length, 1, 'sibling policy is actually admitted');
      const admissions = await auditRows(agents, siblingScope);
      assert.equal(admissions.length, 0);
      return { heads, admissions };
    };
    const auditResponses = [];
    const invokeActualAudit = async ({ phase }) => {
      assert.ok(['allowed', 'denied'].includes(phase));
      const beforeServiceCalls = { ...serviceCalls }, beforeJudge = judgeCalls;
      const beforeJudgments = await count(identity, 'secureshop_auth.assessment_judgments',
        'principal_id=$1', [tenant.principalId]);
      const beforeCredit = await count(identity, 'secureshop_auth.assessment_completions',
        'principal_id=$1', [tenant.principalId]);
      const beforeEffects = await count(identity, 'graph_runtime.effects',
        "effect_key LIKE '%:owned-audit-query:%'", []);
      await frame.click('a[href="/secureshop/admin/audit"]');
      await frame.waitForSelector('input[aria-label="Search by user"]', { timeout: 20000 });
      await frame.type('input[aria-label="Search by user"]', 'student_admin');
      await frame.waitForFunction(() => {
        const button = [...document.querySelectorAll('button')]
          .find(value => value.textContent?.trim() === 'Ask audit agent');
        return button && !button.disabled;
      }, { timeout: 30000 });
      const pending = page.waitForResponse(response => response.request().method() === 'POST'
        && new URL(response.url()).pathname === '/api/secureshop/admin/audit/agent-search',
      { timeout: 120000 });
      pending.catch(() => {});
      const buttons = await frame.$$('button');
      const ask = await (async () => {
        for (const button of buttons) if (await button.evaluate(node => node.textContent?.trim() === 'Ask audit agent')) return button;
        return null;
      })();
      assert.ok(ask, 'rendered Ask audit agent button required');
      await ask.evaluate(node => node.scrollIntoView({ block: 'center', inline: 'center' }));
      await ask.click();
      await Promise.all(buttons.map(button => button.dispose()));
      const response = await pending;
      assert.equal(response.status(), 200, `${phase} audit agent request must terminate`);
      const body = await response.json();
      assert.equal(typeof body?.result?.text, 'string');
      assert.equal(body.replayed, false);
      const submitted = agentPosts.at(-1);
      assert.ok(submitted && typeof submitted.message === 'string');
      assert.equal(body.result.provider, 'ollama');
      assert.equal(body.result.model, 'llama3.1:8b');
      const rows = await auditRows(agents, adminScope);
      assert.equal(rows.length, phase === 'allowed' ? 1 : 2,
        'one selected tool admission per real model request');
      const row = rows.at(-1);
      assert.equal(row.platform_launch_id, adminScope.launchId);
      assert.equal(row.platform_scenario_id, adminScope.scenarioId);
      assert.equal(String(row.platform_launch_generation), String(adminScope.generation));
      assert.equal(String(row.original_platform_session_id), String(adminScope.platformSessionId));
      assert.equal(row.persona_id, actor.id);
      assert.equal(row.persona_session_id, actorSession.sessionId);
      assert.equal(String(row.authority_version), String(actorSession.authorityVersion));
      assert.equal(row.tool_key, 'audit.search_by_user');
      assert.equal(row.allowed, phase === 'allowed');
      assert.equal(row.action, phase === 'allowed' ? 'dispatch' : 'block');
      const query = (await identity.query(`SELECT operation_id,run_id,request_json,receipt_json
        FROM identity.secureshop_audit_query_operations WHERE operation_id=$1`,
      [submitted.requestId])).rows[0];
      const effect = (await identity.query(`SELECT run_id,status FROM graph_runtime.effects
        WHERE effect_key=$1`, [`${submitted.requestId}:owned-audit-query:${submitted.requestId}`])).rows;
      if (phase === 'allowed') {
        assert.equal(query?.run_id, row.run_id);
        assert.ok(query.receipt_json, 'real owned SQL receipt persisted');
        assert.equal(query.receipt_json.result?.ok, true,
          'allowed audit tool must complete SQL successfully');
        assert.equal(query.receipt_json.result.count,
          query.receipt_json.result.events?.length);
        assert.deepEqual(body.result.query, query.receipt_json.result,
          'agent HTTP response must contain the exact persisted SQL result');
        await frame.waitForFunction((expected) => {
          const visible = node => node && node.getClientRects().length > 0
            && getComputedStyle(node).visibility !== 'hidden';
          const modelLabel = [...document.querySelectorAll('div')].find(node =>
            node.textContent === 'Model: ollama · llama3.1:8b · Judge: completion not established');
          const sql = [...document.querySelectorAll('code')].find(node =>
            node.textContent === expected.sql);
          const events = [...document.querySelectorAll('pre')].find(node =>
            node.textContent === expected.events);
          return visible(modelLabel) && visible(modelLabel.parentElement)
            && modelLabel.parentElement.textContent.startsWith(expected.text)
            && visible(sql) && visible(events);
        }, { timeout: 20000 }, {
          text: body.result.text,
          sql: query.receipt_json.result.sql,
          events: JSON.stringify(query.receipt_json.result.events, null, 2).slice(0, 4000),
        });
        assert.equal(effect.length, 1); assert.equal(effect[0].status, 'completed');
        assert.equal(effect[0].run_id, row.run_id);
        assert.equal(serviceCalls.search, beforeServiceCalls.search + 1);
      } else {
        assert.ok(body.result.text.trim(), 'denied audit response must be nonempty');
        await frame.waitForFunction(expected => {
          const visible = node => node && node.getClientRects().length > 0
            && getComputedStyle(node).visibility !== 'hidden';
          const modelLabel = [...document.querySelectorAll('div')].find(node =>
            node.textContent === 'Model: ollama · llama3.1:8b · Judge: completion not established');
          const output = modelLabel?.parentElement;
          const responseText = output && [...output.childNodes]
            .filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.textContent).join('');
          return visible(modelLabel) && visible(output) && responseText === expected;
        }, { timeout: 20000 }, body.result.text);
        assert.equal(query, undefined); assert.equal(effect.length, 0);
        assert.deepEqual(serviceCalls, beforeServiceCalls,
          'blocked admission must make no owned SQL target/query/receipt call');
        assert.equal(await count(identity, 'graph_runtime.effects',
          "effect_key LIKE '%:owned-audit-query:%'", []), beforeEffects);
        assert.equal(judgeCalls, beforeJudge);
        assert.equal(await count(identity, 'secureshop_auth.assessment_judgments',
          'principal_id=$1', [tenant.principalId]), beforeJudgments);
        assert.equal(await count(identity, 'secureshop_auth.assessment_completions',
          'principal_id=$1', [tenant.principalId]), beforeCredit);
      }
      const replayCalls = actorCalls, replayServiceCalls = { ...serviceCalls };
      const replay = await auditApplication.runAgent({ scope: adminScope, persona: actor,
        personaSession: actorSession, sessionId: submitted.sessionId,
        requestId: submitted.requestId, message: submitted.message });
      assert.equal(replay.replayed, true);
      assert.equal(actorCalls, replayCalls);
      assert.deepEqual(serviceCalls, replayServiceCalls, 'exact replay is read-only');
      assert.equal(serviceCalls.search, phase === 'allowed'
        ? beforeServiceCalls.search + 1 : beforeServiceCalls.search);
      auditResponses.push({ requestId: submitted.requestId, runId: row.run_id,
        policyVersion: String(row.policy_version), outcome: phase,
        queryReceipt: Boolean(query?.receipt_json) });
      await frame.click('a[href="/secureshop/admin/access-control"]');
      await frame.waitForSelector('[data-testid="acl-cell-audit.search_by_user-admin"]', { timeout: 30000 });
      return { provider: body.result.provider, model: body.result.model, replayed: replay.replayed,
        ...admissionProof(row),
        ...(phase === 'allowed' ? { effectPersisted: true, auditReadback: true }
          : { noServiceDispatch: true, noQueryEffect: true, noJudgment: true,
            noCredit: true, actorFinalResponse: Boolean(body.result.text.trim()) }) };
    };
    const readAudit = async ({ allowed, denied, deny, enforce }) => {
      assert.equal(deny.version, String(BigInt(allowed.context.policyVersion) + 1n));
      assert.equal(enforce.version, String(BigInt(allowed.context.policyVersion) + 2n));
      const allowedRef = auditResponses.find(value => value.outcome === 'allowed');
      const deniedRef = auditResponses.find(value => value.outcome === 'denied');
      assert.equal(allowedRef.runId, allowed.context.runId);
      assert.equal(deniedRef.runId, denied.context.runId);
      const saved = (await identity.query(`SELECT request_json,receipt_json FROM
        identity.secureshop_audit_query_operations WHERE operation_id=$1 AND run_id=$2`,
      [allowedRef.requestId, allowedRef.runId])).rows[0];
      assert.ok(saved?.receipt_json);
      for (const table of ['secureshop_audit_query_operations','secureshop_audit_target_admissions']) {
        const ownership = (await identity.query(`SELECT user_id,original_platform_owner_id
          FROM identity.${table} WHERE launch_id=$1`,[adminScope.launchId])).rows;
        assert.ok(ownership.length > 0, 'standalone audit preserves actual admitted evidence');
        assert.ok(ownership.every(row=>row.user_id===null
          && Number(row.original_platform_owner_id)===adminScope.platformOwnerId),
        'shop evidence has its canonical owner without a workshop-user surrogate');
      }
      const username = saved.request_json?.request?.username;
      assert.equal(typeof username, 'string');
      const privateReceipt = await rawAuditClient.receipt({ binding: adminScope,
        operationId: allowedRef.requestId, username });
      assert.deepEqual(privateReceipt, saved.receipt_json,
        'private owned SQL receipt must match the immutable central effect');
      assert.equal((await identity.query(`SELECT count(*)::int AS n FROM
        identity.secureshop_audit_query_operations WHERE operation_id=$1`,
      [deniedRef.requestId])).rows[0].n, 0);
      const foreign = await fetch(`${origin}/api/secureshop/admin/access-control/operations/${deny.operationId}`,
        { headers: { 'x-dvaia-secureshop-launch': siblingFirst.bearer,
          authorization: `Bearer ${siblingFirst.persona.token}` } });
      assert.equal(foreign.status, 404, 'sibling cannot read another policy operation');
      assert.equal((await auditRows(agents, siblingScope)).length, 0);
      const admissions = await auditRows(agents, adminScope);
      assert.equal(admissions.length, 2);
      for (const [row, expected] of [[admissions[0], 'completed'], [admissions[1], 'denied']]) {
        const events = (await agents.query(`SELECT launch_id,scenario_id,generation,
          original_platform_owner_id,original_platform_session_id,shop_user_id,shop_role,
          actor,action,target,params_json,outcome,source_kind,source_id
          FROM secureshop_agents.bound_audit_events
          WHERE launch_id=$1 AND scenario_id=$2 AND generation=$3
            AND original_platform_owner_id=$4 AND original_platform_session_id=$5
            AND source_kind='bound_tool_policy' AND source_id=$6
            AND action='tool_policy_admission'`,
        [adminScope.launchId, adminScope.scenarioId, adminScope.generation,
          adminScope.platformOwnerId, adminScope.platformSessionId, row.admission_id])).rows;
        assert.equal(events.length, 1, 'exact admitted tool has one immutable audit event');
        const event = events[0], receipt = JSON.parse(event.params_json);
        assert.equal(event.shop_user_id, actor.id);
        assert.equal(event.shop_role, 'admin'); assert.equal(event.actor, 'admin');
        assert.equal(event.target, 'bound-tool-policy');
        assert.equal(event.outcome, expected);
        assert.equal(receipt.admissionId, row.admission_id);
        assert.equal(receipt.runId, row.run_id);
        assert.equal(receipt.invocationId, row.invocation_id);
        assert.equal(receipt.toolKey, row.tool_key);
        assert.equal(receipt.policyVersion, String(row.policy_version));
        assert.equal(receipt.action, row.action);
        assert.equal(receipt.allowed, row.allowed);
      }
      assert.equal(judgeCalls, 0, 'benign allowed query and blocked query have no Judge call');
      return { allowedEffectReadback: true, deniedAdmissionReadback: true,
        deniedNoEffect: true };
    };
    const result = await qualifyRenderedD22({ page, frame, origin,
      invokeActualAudit, readSibling, readAudit });
    assert.equal(result.allowed.admission.action, 'dispatch');
    assert.equal(result.denied.admission.action, 'block');
    assert.equal(agentPosts.length, 2, 'two actual rendered audit requests only');
    assert.ok(actorCalls >= 4 && actorCalls <= 6);
    assert.equal(pageErrors.length, 0);
    t.diagnostic(JSON.stringify({ stage: 'D22-two-actual-model-admissions', actorCalls,
      judgeCalls, modelDecisions, auditResponses }));
    status.renderedAccessControlMutations = true;
    status.allowedActualModelEffect = true;
    status.deniedNoDispatch = true;
    status.deniedNoQueryEffect = true;
    status.deniedNoJudgment = true;
    status.deniedNoCredit = true;
    status.auditReadback = true;
    status.renderedAuditAllowedDenied = true;
    status.siblingPrivate = true;
    status.passed = true;
  } finally {
    for (const [label, close] of [
      ['browser', async () => browser?.close()],
      ['server', async () => closeServer(server)],
      ['target-retirement', async () => {
        if (auditBackend) for (const value of ownedScopes) await auditBackend.retire({ binding: value });
      }],
      ['target-http', async () => auditHttp?.close()],
      ['target-service', async () => targetService?.close()],
      ['target-control', async () => control.end()],
      ['lease', async () => leasePool.end()],
      ...Object.entries(pools).map(([key, pool]) => [key, async () => pool.end()]),
      ['browser-profile', async () => { if (profile) await fs.rm(profile, { recursive: true, force: true }); }],
    ]) try { await close(); } catch (error) { cleanupErrors.push(`${label}:${error.code || error.name}`); }
    status.cleanupComplete = cleanupErrors.length === 0;
    if (!status.cleanupComplete) status.passed = false;
    const contents = JSON.stringify(status);
    assert.ok(Buffer.byteLength(contents) <= 4096);
    await fs.writeFile(evidencePath, `${contents}\n`, { flag: 'wx', mode: 0o600 });
    if (cleanupErrors.length) throw Error(`D22 owned cleanup failed: ${cleanupErrors.join(', ')}`);
  }
  assert.ok(flagNames.every(name => status[name] === true));
});

module.exports = { assertion, _internals: { assertNativeAdmission, privateEvidencePath, storeUrls, admissionProof, required } };
