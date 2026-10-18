'use strict';

// Root-owned launcher supplies four disposable stores, the pinned production
// build/browser, and a genuine local model. This fixture owns only its bounded
// Express/composition process and browser profile.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomUUID, randomBytes, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { SEARCH_ECHO_SCOPE, SEARCH_ECHO_CANARY, SEARCH_ECHO_FLAGS, assertSearchEchoQualificationReceipt,
  assertSearchEchoActorWire, assertSearchEchoOutcome, captureSearchEchoAssessmentResponse,
  waitForOriginalSearchEchoAssessment, assertSearchEchoV9Proof } =
  require('../fixtures/secureshopSearchEchoQualification');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_SEARCH_ECHO_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const OBJECTIVE = 'ss_search_echo_browser';
const GATE = 'SECURESHOP_SEARCH_ECHO_BROWSER_NATIVE';
const ENABLED = process.env[GATE] === '1' && process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.LIVE_OLLAMA_TEST === '1' && Object.keys(STORES).every(store =>
    ['RUNTIME', 'MIGRATION'].every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const sha = value => createHash('sha256').update(value).digest('hex');

function urls() {
  const result = {}; let nonce, port;
  for (const [key, name] of Object.entries(STORES)) for (const role of ['RUNTIME', 'MIGRATION']) {
    const value = new URL(process.env[`${PREFIX}${key}_${role}_URL`]);
    assert.equal(value.protocol, 'postgresql:'); assert.equal(value.hostname, '127.0.0.1');
    assert.equal(value.username, `dvaia_${name}_${role.toLowerCase()}`);
    assert.equal(value.password, ''); assert.equal(value.search, ''); assert.equal(value.hash, '');
    const match = /^\/dvaia_test_agent_host_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(value.pathname);
    assert.ok(match && match[2] === name); nonce ??= match[1]; port ??= value.port;
    assert.equal(match[1], nonce); assert.equal(value.port, port);
    result[`${key}_${role}`] = value.href;
  }
  assert.equal(new Set(Object.keys(STORES).map(key =>
    new URL(result[`${key}_RUNTIME`]).pathname)).size, 4);
  return result;
}
const listen = app => new Promise(resolve => { const server = app.listen(0, '127.0.0.1', () => resolve(server)); });
const closeServer = server => server && new Promise((resolve, reject) =>
  server.close(error => error ? reject(error) : resolve()));
async function frameFor(page) {
  const element = await page.waitForSelector('iframe[title="SecureShop"]', { timeout: 20000 });
  const frame = await element.contentFrame(); assert.ok(frame); return frame;
}
const waitResponse = (page, method, pathname, timeout = 90000) => page.waitForResponse(response =>
  response.request().method() === method && new URL(response.url()).pathname === pathname, { timeout });
function headersFrom(request) {
  const headers = request.headers();
  assert.match(headers.authorization || '', /^Bearer [A-Za-z0-9_.-]+$/);
  assert.match(headers['x-dvaia-secureshop-launch'] || '', /^[A-Za-z0-9_-]{43}$/);
  return { authorization: headers.authorization,
    'x-dvaia-secureshop-launch': headers['x-dvaia-secureshop-launch'] };
}

test('genuine two-search turn executes only the dedicated vulnerable echo and earns one retained V60 award',
  { skip: !ENABLED, timeout: 300000 }, async t => {
    assert.equal(process.cwd(), ROOT);
    assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/'), ROOT);
    const evidencePath = process.env.SECURESHOP_SEARCH_ECHO_EVIDENCE_PATH || '';
    const build = path.resolve(process.env.SECURESHOP_SEARCH_ECHO_BROWSER_BUILD || '/');
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(evidencePath) && !path.resolve(evidencePath).startsWith(`${ROOT}${path.sep}`));
    assert.equal(build, path.join(ROOT, 'client/build')); assert.ok(path.isAbsolute(executablePath));
    for (const file of ['index.html', 'secureshop-frame.html',
      'secureshop-search-echo-renderer/manifest.json', 'secureshop-search-echo-renderer/renderer.js'])
      await fs.access(path.join(build, file));
    await fs.access(executablePath);
    assert.equal(process.env.LAB_MODE, 'vuln');
    assert.equal(process.env.JUDGE_PROVIDER || 'ollama', 'ollama');
    assert.equal(process.env.JUDGE_MODEL || MODEL, MODEL);
    const requestedPanels = Object.freeze({
      personaInboxFeature: require('../../server/services/secureshopPersonaInboxActivationPolicy')
        .activationPolicy(process.env).requested,
      mcpTrustFeature: require('../../server/services/secureshopMcpTrustActivationPolicy')
        .activationPolicy(process.env).requested,
      ssrfFeature: require('../../server/services/secureshopSsrfProduction')
        .activationPolicy(process.env).requested,
    });
    assert.equal(requestedPanels.personaInboxFeature, true);
    assert.equal(requestedPanels.mcpTrustFeature, false);
    assert.equal(requestedPanels.ssrfFeature, false);
    const modelOrigin = new URL(process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434').origin;
    const tags = await (await fetch(`${modelOrigin}/api/tags`, { signal: AbortSignal.timeout(5000) })).json();
    assert.equal(tags.models.find(row => row.name === MODEL)?.digest, MODEL_DIGEST);

    const databaseUrls = urls();
    const pools = Object.fromEntries(Object.entries(databaseUrls).map(([key, connectionString]) =>
      [key, new Pool({ connectionString, max: key.endsWith('RUNTIME') ? 12 : 3,
        connectionTimeoutMillis: 1500, statement_timeout: 8000 })]));
    const leasePool = new Pool({ connectionString: databaseUrls.IDENTITY_RUNTIME, max: 4 });
    const status = Object.fromEntries(SEARCH_ECHO_FLAGS.map(flag => [flag, false]));
    Object.assign(status, { passed: false, scope: SEARCH_ECHO_SCOPE, actorCalls: 0,
      judgeCalls: 0, roleTurns: 0, browserRuns: 0, attributedEffects: 0,
      genuineCredit: 0, cleanupErrors: [], errors: [] });
    const wirePath = path.join(path.dirname(evidencePath), 'search-echo-original-wire.json');
    const screenshotPath = path.join(path.dirname(evidencePath), 'search-echo-browser.png');
    let lifecycle, composition, transport, browser, fixedBrowser, page, profile, server, failure;
    let failureDiagnostic = null, failureScreenshot = null;
    let browserClosed = true;
    let stage = 'setup', originalModelUrl = process.env.OLLAMA_BASE_URL;
    const actorSpans = [], requests = [], pageErrors = [], judgePackets = [], httpStatuses = [];
    const assessmentHttpCaptures = [];
    const browserEvents = [];
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
      } catch (error) { await seed.query('ROLLBACK'); throw error; } finally { seed.release(); }
      status.isolatedStores = true;
      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
      const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
      const auth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const admin = await auth.login({ username: 'student_admin', password: 'student123' });
      const catalog = require('../../server/services/secureshopAssessmentCatalog')
        .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
      const objective = (await catalog.list(admin.context)).objectives
        .find(row => row.objectiveId === OBJECTIVE);
      assert.equal(objective?.qualification, 'native-browser-judge'); assert.equal(objective.enabled, false);
      assert.equal((await catalog.set(admin.context, { objectiveId: OBJECTIVE, enabled: true,
        expectedRevision: objective.revision })).enabled, true);
      status.canonicalObjectiveEnabled = true;

      const audit = require('../../server/services/secureshopBoundAuditComposition')
        .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
          includeRunArtifacts: true });
      lifecycle = require('../../server/services/secureshopCleanupComposition')
        .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, leasePool, audit });
      transport = await require('./secureshopMailActualTransport')
        .createMailActualTransport({ maxHttpCalls: 8, allowMetadata: true });
      process.env.OLLAMA_BASE_URL = transport.judgeUrl;
      const configuredJudge = require('../../server/agent-runtime/objectiveJudge')
        .createObjectiveJudge({ observeExecutionTranscript: packet => judgePackets.push(packet) });
      const judge = async input => {
        const result = await configuredJudge(input);
        status.judgeCalls = transport.calls.filter(call => call.kind === 'judge').length;
        assert.ok(status.judgeCalls >= 1 && status.judgeCalls <= 2); return result;
      };
      require('../../server/agent-runtime/judgeProviderConfiguration').registerConfiguredJudge(judge,
        () => require('../../server/agent-runtime/judgeProviderConfiguration')
          .readJudgeProviderConfig(configuredJudge));
      const progress = require('../../server/database/postgres/workshopProgressRepository')
        .createWorkshopProgressRepository(identity);
      const grading = await require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
          progress, resetComposition: lifecycle, judge,
          expectedIdentityDatabase: new URL(databaseUrls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(databaseUrls.AGENTS_RUNTIME).pathname.slice(1) });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository')
          .createSecureShopSceneRepository({ pool: identity, launches: lifecycle.launches }),
        reviewPool: review, launches: lifecycle.launches });
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
          actorSpans.push({ method, result, wires: transport.calls.slice(start) });
          status.actorCalls = transport.calls.filter(call => call.kind === 'actor').length;
          assert.ok(status.actorCalls <= 6); return result;
        };
      }
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identity);
      const couponDependencies = await require('../../server/services/secureshopCouponProduction')
        .prepareCommerceDependencies({ modeAuthority: lifecycle.modeAuthority, reviewPool: review,
          launches: lifecycle.launches, mode: 'vuln' });
      const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
        .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
          audit: audit.agents });
      await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness')
        .assertBoundToolPolicyReadiness(agents);
      composition = require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: lifecycle,
          gradingBootstrap: grading, scenes, modeAuthority: lifecycle.modeAuthority,
          couponDependencies, ...requestedPanels, searchEchoEvidenceVersion: 9,
          toolPolicyRepository, fixtures: [], requiredObjectives: [OBJECTIVE],
          judge, jwtSecret: randomBytes(32).toString('hex'), agentRuntime: { provider } });
      await composition.repositories.personas.ensureTemplates();
      assert.equal(composition.searchEcho?.ready, true);
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });
      const reset = require('../../server/services/secureshopStandaloneReset')
        .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
          launches: composition.launches, scenes, resetCoordinator: lifecycle.launchResetCoordinator,
          preflight: lifecycle.sceneResetPreflight });
      const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
        .createRegisteredAdminResetEnvelope({ activeKeyId: 'search-echo-owned',
          keys: new Map([['search-echo-owned', randomBytes(32)]]) });
      const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
        .createRegisteredAdminResetRepository({ pool: identity, envelope: resetEnvelope });
      await resetRepository.checkReadiness();
      const standalone = { service: auth, bootstrap, reset,
        registeredAdminReset: require('../../server/services/secureshopRegisteredAdminReset')
          .createRegisteredAdminResetService({ repository: resetRepository }),
        mode: require('../../server/services/secureshopStandaloneMode')
          .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository }),
        assessmentProgress: require('../../server/services/secureshopAssessmentProgress')
          .createSecureShopAssessmentProgress({ repository:
            require('../../server/database/postgres/secureshopAssessmentProgressRepository')
              .createSecureShopAssessmentProgressRepository({ pool: identity }) }),
        assessmentObjectives: catalog,
        assessmentRecovery: require('../../server/services/secureshopAssessmentRecovery')
          .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth,
            bootstrap, launches: composition.launches, personaAuth: composition.personaAuth,
            personaAuthority: grading.personaAuthority, modeAuthority: lifecycle.modeAuthority,
            scenes, judge, searchEchoAssessment: composition.searchEcho.assessment }),
        cartImport: require('../../server/services/secureshopStandaloneCartImport')
          .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
            personaAuth: composition.personaAuth, commerce: composition.commerce }),
        practices: require('../../server/services/secureshopPracticeAdmission')
          .createSecureShopPracticeAdmission({ catalog: composition.catalog,
            repository: require('../../server/database/postgres/secureshopPracticeAdmissionRepository')
              .createSecureShopPracticeAdmissionRepository({ pool: identity }) }) };
      const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
        .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
          reviewPool: review, commercePool: commerce });
      const bound = await require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          applicationMode: 'standalone', authenticateToken: (_q, response) => response.sendStatus(401),
          audit: async () => {}, agentRuntime: {}, getComposition: async () =>
            ({ ...composition, standaloneAuth: standalone, publicCatalog }) });
      assert.equal(bound.standaloneReadiness.ready, true);
      assert.equal(bound.standaloneReadiness.checks.requestedPanels, true);
      assert.ok(Object.values(bound.standaloneReadiness.checks).every(value => value === true));

      const app = express(); app.use(express.json());
      app.use('/api/secureshop', (request, response, next) => {
        if (request.path.startsWith('/agents/customer')) requests.push({ method: request.method,
          path: request.path, body: request.method === 'POST' ? structuredClone(request.body) : null });
        if (request.method === 'POST'
            && request.path === '/agents/customer/search-echo/assess')
          captureSearchEchoAssessmentResponse(request, response, value =>
            assessmentHttpCaptures.push(value));
        next();
      });
      server = await listen(app); const origin = `http://127.0.0.1:${server.address().port}`;
      app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthRouter({ ...standalone, allowedOrigins: [origin], secureCookies: false }));
      app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
        .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
      app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog')
        .createSecureShopPublicCatalogRouter({ getRepository: () => publicCatalog,
          isAvailable: async () => true }));
      app.use('/api', (_request, response) => response.status(404).json({ error: 'Outside V60 qualification' }));
      // Sandboxed shop ES modules load with an opaque Origin. Keep the owned
      // production bundle readable exactly as in the passing rendered cohorts.
      app.use(express.static(build, {
        setHeaders: response => response.set('Access-Control-Allow-Origin', '*'),
      }));
      app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));

      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-search-echo-browser-'));
      browser = await require('puppeteer').launch({ headless: true, userDataDir: profile, executablePath });
      browserClosed = false;
      page = await browser.newPage(); await page.setViewport({ width: 1280, height: 900 });
      page.on('pageerror', error => pageErrors.push(error.message.slice(0, 200)));
      const scrubBrowserMessage = value => String(value || '')
        .replace(/Bearer\s+\S+/gi, 'Bearer [redacted]')
        .replace(/\b[A-Za-z0-9_-]{24,}\b/g, '[redacted]').slice(0, 300);
      page.on('console', message => {
        if (browserEvents.length < 64 && ['error', 'warning'].includes(message.type())) {
          browserEvents.push({ kind: 'console', type: message.type(),
            message: scrubBrowserMessage(message.text()) });
        }
      });
      page.on('requestfailed', request => {
        try {
          const url = new URL(request.url());
          if (url.origin === origin && browserEvents.length < 64) browserEvents.push({
            kind: 'requestfailed', path: url.pathname, resourceType: request.resourceType(),
            message: scrubBrowserMessage(request.failure()?.errorText),
          });
        } catch {}
      });
      page.on('response', response => {
        try {
          const url = new URL(response.url());
          if (url.origin === origin && httpStatuses.length < 128) httpStatuses.push({
            method: response.request().method(), path: url.pathname,
            resourceType: response.request().resourceType(), status: response.status(),
          });
        } catch {}
      });
      const dialogs = [];
      page.on('dialog', dialog => { dialogs.push({ type: dialog.type(), message: dialog.message() });
        void dialog.dismiss(); });
      await page.setRequestInterception(true);
      page.on('request', request => request.url().startsWith(`${origin}/`)
        ? request.continue() : request.abort());
      stage = 'login';
      assert.equal((await page.goto(`${origin}/secureshop/login`)).status(), 200);
      await page.waitForSelector('#ss-login-user'); await page.type('#ss-login-user', 'student_customer');
      await page.type('#ss-login-pw', 'student123');
      const login = waitResponse(page, 'POST', '/api/secureshop/auth/login', 20000);
      const boot = waitResponse(page, 'POST', '/api/secureshop/auth/bootstrap', 20000);
      await page.click('button[type="submit"]'); assert.equal((await login).status(), 200);
      assert.equal((await boot).status(), 200);
      const frame = await frameFor(page);
      await frame.waitForSelector('select[id^="agent-lane-task-customer-"]');
      await frame.select('select[id^="agent-lane-task-customer-"]', 'chat');

      const canary = SEARCH_ECHO_CANARY;
      assert.ok(Buffer.byteLength(canary) <= 128);
      const prompt = `Use catalog.search for the exact text ${JSON.stringify(canary)}. Then use catalog.search a second time for the exact same text before answering.`;
      stage = 'genuine-two-search-turn';
      const chatRequest = page.waitForRequest(request => request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/secureshop/agents/customer/chat');
      const chatResponse = waitResponse(page, 'POST', '/api/secureshop/agents/customer/chat');
      await frame.type('textarea[id^="lane-general-help-"]', prompt);
      await frame.click('form.ss-lane__composer button[type="submit"]');
      const originalRequest = await chatRequest, customerHeaders = headersFrom(originalRequest);
      assert.equal((await chatResponse).status(), 200); status.roleTurns = 1;
      await frame.waitForFunction(() => [...document.querySelectorAll('[data-testid="agent-turn"]')]
        .some(node => /^CUSTOMER-SUPERVISOR\s+done$/.test(
          node.querySelector('.ss-turn__supervisor')?.textContent.trim() || '')),
      { timeout: 120000 });
      assert.equal(await frame.$$eval(
        '[aria-label^="Step "][aria-label*="catalog.search completed"]', nodes => nodes.length), 2);
      const submitted = requests.find(row => row.method === 'POST'
        && row.path === '/agents/customer/chat')?.body;
      assert.equal(submitted.message, prompt); status.exactOriginalEnvelope = true;
      let turn;
      const turnUntil = Date.now() + 10000;
      while (Date.now() < turnUntil) {
        const row = (await agents.query(`SELECT status,result_json FROM secureshop_agents.turn_requests
          WHERE session_id=$1 AND request_id=$2`, [submitted.sessionId, submitted.requestId])).rows[0];
        if (row?.status === 'completed') { turn = row.result_json; break; }
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      assert.equal(turn?.stopReason, 'end_turn');
      const searchHops = turn.hops.filter(hop => hop.tool === 'catalog.search');
      assert.equal(searchHops.length, 2); assert.deepEqual(searchHops.map(hop => hop.params.search), [canary, canary]);
      const traceIds = turn.taskMetadata?.searchEcho?.traceEventIds;
      assert.ok(Array.isArray(traceIds));
      const traces = (await agents.query(`SELECT id,event_id,kind,actor,step,agent_ns,tool_name,
        params_json::jsonb AS params_json,result_json::jsonb AS result_json
        FROM secureshop_agents.agent_trace WHERE session_id=$1 AND event_id=ANY($2::text[]) ORDER BY id`,
      [submitted.sessionId, traceIds])).rows;
      assert.deepEqual(traces.map(row => row.event_id), traceIds);
      const origins = searchHops.map(hop => {
        const decisions = traces.filter(row => row.kind === 'model_decision'
          && row.actor === 'supervisor' && row.step === hop.step
          && row.params_json?.decision === 'tool_use');
        assert.equal(decisions.length, 1);
        assert.equal(decisions[0].params_json.toolCalls.length, 1);
        assert.equal(decisions[0].params_json.toolCalls[0].name, 'catalog.search');
        assert.deepEqual(decisions[0].params_json.toolCalls[0].args, { search: canary });
        return { callId: decisions[0].params_json.toolCalls[0].id };
      });
      const selected = assertSearchEchoActorWire({ spans: actorSpans, turn: { text: turn.text }, origins,
        queries: [canary, canary], selectedStep: searchHops[1].step, model: MODEL });
      assert.equal(selected.echoHtml, `<p>Results for: <b>${canary}</b></p>`);
      status.genuineTwoSearchHops = status.selectedStepExact = status.savedEchoExact = true;
      for (const hop of searchHops) {
        const calls = traces.filter(row => row.kind === 'local_tool_call' && row.step === hop.step
          && row.agent_ns === 'catalog' && row.tool_name === 'search');
        const results = traces.filter(row => row.kind === 'local_tool_result' && row.step === hop.step
          && row.agent_ns === 'catalog' && row.tool_name === 'search');
        assert.equal(calls.length, 1); assert.equal(results.length, 1);
        assert.deepEqual(calls[0].params_json, { search: canary });
        const observation = JSON.parse(results[0].result_json.content[0].text);
        assert.equal(observation.echo_html, `<p>Results for: <b>${canary}</b></p>`);
        assert.deepEqual(hop.params, calls[0].params_json);
        assert.deepEqual(hop.result, results[0].result_json);
      }
      status.parameterizedQueryUnchanged = true;

      stage = 'physical-dedicated-echo';
      await frame.click('details[data-testid="agent-activity"] summary');
      const sandboxTokens = (await page.$eval('iframe[title="SecureShop"]', node =>
        (node.getAttribute('sandbox') || '').split(/\s+/).filter(Boolean))).sort();
      assert.ok(sandboxTokens.includes('allow-scripts'));
      assert.ok(sandboxTokens.includes('allow-forms'));
      assert.equal(sandboxTokens.includes('allow-modals'), false);
      const second = await frame.$(`[aria-label^="Step ${selected.step}:"][aria-label*="catalog.search completed"]`);
      assert.ok(second); await second.click();
      await frame.waitForSelector('[data-testid="hop-echo-html"][data-v60="1"] img');
      const physicalEcho = await frame.evaluate(() => {
        const images = [...document.querySelectorAll('.ss-sheet__body img[src="x"]')];
        const markers = [...document.querySelectorAll('[data-v60]')];
        return { imageCount: images.length,
          dedicatedImages: images.filter(node => node.closest('[data-testid="hop-echo-html"]')).length,
          genericImages: images.filter(node => !node.closest('[data-testid="hop-echo-html"]')).length,
          markerCount: markers.length,
          dedicatedMarkerCount: markers.filter(node => node.matches(
            '[data-testid="hop-echo-html"][data-v60="1"]')).length,
          outsideDedicatedMarkers: markers.filter(node => !node.closest(
            '[data-testid="hop-echo-html"]')).length };
      });
      assert.deepEqual(physicalEcho, { imageCount: 2, dedicatedImages: 1, genericImages: 1,
        markerCount: 1, dedicatedMarkerCount: 1, outsideDedicatedMarkers: 0 });
      // The production iframe intentionally omits allow-modals. The DOM marker
      // is the physical component effect; canonical grading separately requires
      // an attributed event effect from its isolated qualification browser.
      assert.deepEqual(dialogs, []);
      status.physicalDedicatedEcho = status.v27PreviewExcluded = status.vulnerableAttributedExecution = true;

      stage = 'fixed-contrast';
      const fixedRegistration = await auth.register({
        username: `search_echo_fixed_${randomUUID().slice(0, 8)}`,
        password: 'disposable-search-echo-fixed', email: `${randomUUID()}@owned.invalid`,
        role: 'customer' });
      const initialFixedMode = await standalone.mode.get(fixedRegistration.context);
      const currentFixedMode = initialFixedMode.mode === 'fixed' ? initialFixedMode
        : await standalone.mode.set(fixedRegistration.context,
          { mode: 'fixed', expectedRevision: initialFixedMode.revision });
      assert.equal(currentFixedMode.mode, 'fixed');
      assert.deepEqual(await standalone.mode.get(fixedRegistration.context), currentFixedMode);
      fixedBrowser = require('../../server/services/secureshopSearchEchoBrowserQualification')
        .createSecureShopSearchEchoBrowserQualification();
      const fixed = await fixedBrowser.qualifySearchEcho({ html: selected.echoHtml,
        captureDom: true,
        modeCapability: { version: 1, featureId: 'customer_chat',
          policyVersion: 'owned-catalog-and-cart-read-v1', effectiveMode: 'fixed',
          scope: { kind: 'launch_feature', id: 'customer_chat' } } });
      assert.equal(fixed.executed, false); assert.equal(fixed.targetEventExecuted, false);
      assert.equal(fixed.renderedSourceSha256, sha(selected.echoHtml));
      assert.equal(fixed.domCapture?.originalSourceSha256, sha(selected.echoHtml));
      assert.equal(fixed.domCapture?.snapshot?.mode, 'fixed');
      assert.equal(fixed.domCapture.snapshot.nodes.length, 2);
      assert.equal(fixed.domCapture.snapshot.nodes[0].name, 'pre');
      // The qualifier instruments the same original source, then serializes
      // the projected markup before mounting. Fixed mode renders those exact
      // mounted bytes as text; the original-source digest remains separate.
      assert.equal(fixed.domCapture.snapshot.nodes[1].type, 3);
      assert.equal(sha(fixed.domCapture.snapshot.nodes[1].text),
        fixed.domCapture.mountedSourceSha256);
      assert.equal((await identity.query(`SELECT count(*)::int AS n FROM
        secureshop_auth.assessment_completions WHERE objective_id=$1`, [OBJECTIVE])).rows[0].n, 0);
      status.browserRuns += 1; status.fixedSameSourceInert = status.fixedNoCredit = true;
      // Retire this separately owned qualifier before the long Judge call.
      // A failed close remains a strict fixture failure and is retried by finally.
      await fixedBrowser.close(); fixedBrowser = null;

      stage = 'assessment';
      const assessResponse = waitResponse(page, 'POST', '/api/secureshop/agents/customer/search-echo/assess');
      void assessResponse.catch(() => {});
      const assessButton = await frame.waitForFunction(() => [...document.querySelectorAll(
        '[role="dialog"] button')].find(button => button.textContent.trim() === 'Check search echo'
          && !button.disabled) || null, { timeout: 20000 });
      await assessButton.asElement().click();
      const assessed = await assessResponse; assert.equal(assessed.status(), 200);
      assert.equal(assessed.request().failure(), null);
      const originalAssessment = await waitForOriginalSearchEchoAssessment(assessmentHttpCaptures,
        '/agents/customer/search-echo/assess', submitted.requestId);
      assert.equal(originalAssessment.method, 'POST');
      assert.deepEqual(originalAssessment.requestBody, { sessionId: submitted.sessionId,
        requestId: submitted.requestId, step: selected.step });
      assert.equal(originalAssessment.status, assessed.status());
      assert.match(originalAssessment.contentType, /^application\/json\b/);
      assert.equal(originalAssessment.error, null);
      const outcome = assertSearchEchoOutcome(JSON.parse(originalAssessment.body), { replayed: false });
      const assessmentPosts = requests.filter(row => row.method === 'POST'
        && row.path === '/agents/customer/search-echo/assess');
      assert.deepEqual(assessmentPosts, [{ method: 'POST',
        path: '/agents/customer/search-echo/assess',
        body: { sessionId: submitted.sessionId, requestId: submitted.requestId,
          step: selected.step } }]);
      await frame.waitForFunction(() => [...document.querySelectorAll('[role=status]')]
        .some(node => node.textContent.includes('Saved assessment: pass')), { timeout: 90000 });
      const judgment = (await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
        WHERE evaluation_id=$1`, [outcome.judgment.evaluationId])).rows;
      assert.equal(judgment.length, 1); assert.equal(judgment[0].verdict, 'pass');
      assert.equal(judgment[0].objective_id, OBJECTIVE);
      const packet = JSON.parse(judgment[0].packet);
      const rawJudge = JSON.parse(judgment[0].judge_result_json);
      assertSearchEchoV9Proof(packet, rawJudge, selected,
        require('../../server/services/secureshopSearchEchoBrowserQualification')
          .validateSearchEchoDomCapture);
      const retainedProof = packet.evidence.find(item => item.id === 'search_echo_browser')?.content;
      const originalProof = retainedProof?.original;
      assert.deepEqual(originalProof?.source, { sessionId: submitted.sessionId,
        requestId: submitted.requestId, step: selected.step });
      assert.equal(retainedProof?.component?.id, 'SecureShop.SearchEcho');
      assert.equal(retainedProof?.browser?.renderingMode, 'client');
      assert.equal(retainedProof?.browser?.executed, true);
      assert.equal(retainedProof?.browser?.targetEventExecuted, true);
      assert.equal(retainedProof?.browser?.targetEffectObserved, true);
      assert.ok(retainedProof.browser.markers.length > 0);
      assert.equal(retainedProof?.effectReceipt?.status, 'completed');
      const packetDecision = originalProof.traces.filter(row => row.kind === 'model_decision'
        && row.actor === 'supervisor' && row.step === selected.step);
      assert.equal(packetDecision.length, 1);
      const packetCall = JSON.parse(packetDecision[0].params_json).toolCalls;
      assert.deepEqual(packetCall, [{ id: selected.callId, name: 'catalog.search',
        args: { search: selected.query } }]);
      const completions = (await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
        WHERE objective_id=$1 AND evaluation_id=$2`, [OBJECTIVE, outcome.judgment.evaluationId])).rows;
      assert.equal(completions.length, 1);
      status.browserRuns += 1; status.attributedEffects = 1;
      status.genuineJudge = status.canonicalCredit = true; status.genuineCredit = 1;

      stage = 'saved-replay';
      const savedPath = `/api/secureshop/agents/customer/sessions/${submitted.sessionId}/requests/${submitted.requestId}/search-echo/${selected.step}/assessment`;
      const beforeReplay = transport.calls.length;
      const replayResponse = await fetch(`${origin}${savedPath}`, { headers: customerHeaders,
        signal: AbortSignal.timeout(10000) });
      assert.equal(replayResponse.status, 200);
      assertSearchEchoOutcome(await replayResponse.json(), { replayed: true });
      assert.equal(transport.calls.length, beforeReplay); status.savedGetNoReplay = true;

      stage = 'sibling-and-reset';
      const siblingName = `search_echo_peer_${randomUUID().slice(0, 8)}`;
      const siblingPassword = 'disposable-search-echo-peer';
      const sibling = await auth.register({ username: siblingName, password: siblingPassword,
        email: `${randomUUID()}@owned.invalid`, role: 'customer' });
      const peerMerchant = await auth.register({ username: `search_echo_merchant_${randomUUID().slice(0, 8)}`,
        password: siblingPassword, email: `${randomUUID()}@owned.invalid`, role: 'merchant' });
      const peerTenantId = randomUUID(), peerSlug = `search_echo_peer_${randomUUID().slice(0, 8)}`;
      await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenants (tenant_id,slug)
        VALUES($1,$2)`, [peerTenantId, peerSlug]);
      for (const [registration, role] of [[sibling, 'customer'], [peerMerchant, 'merchant']])
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,$4)`,
        [peerTenantId, registration.context.principalId, registration.context.shopUserId, role]);
      await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants
        SET seed_merchant_id=$2 WHERE tenant_id=$1`,
      [peerTenantId, peerMerchant.context.shopUserId]);
      const peerAuth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity,
              executionTenantSlug: peerSlug }) });
      const peerLogin = await peerAuth.login({ username: siblingName, password: siblingPassword });
      const peerBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: peerAuth });
      const siblingBoot = await peerBootstrap(peerLogin.context);
      const siblingScope = await composition.launches.resolveCapability(siblingBoot.bearer);
      const siblingActor = await composition.personaAuth.authenticateBoundToken({ scope: siblingScope,
        token: siblingBoot.persona.token });
      await composition.catalog.prepareTarget({ scope: siblingScope, persona: siblingActor.user,
        personaSession: { sessionId: siblingActor.sessionId,
          authorityVersion: siblingActor.authorityVersion } });
      const siblingBefore = await scenes.readExisting(siblingScope); assert.ok(siblingBefore);
      const siblingTargetBefore = (await review.query(`SELECT * FROM secureshop_review.product_targets
        WHERE target_id=$1`, [siblingBefore.targetId])).rows;
      const siblingPrincipal = await peerAuth.establishTenantContext(peerLogin.context);
      const siblingProgressBefore = (await identity.query(`SELECT * FROM
        secureshop_auth.assessment_completions WHERE tenant_id=$1 AND principal_id=$2`,
      [siblingPrincipal.tenantId, siblingPrincipal.principalId])).rows;
      const callsBeforeForeign = transport.calls.length;
      const foreign = await fetch(`${origin}${savedPath}`, { headers: {
        authorization: `Bearer ${siblingBoot.persona.token}`,
        'x-dvaia-secureshop-launch': siblingBoot.bearer }, signal: AbortSignal.timeout(10000) });
      assert.equal(foreign.status, 401);
      assert.deepEqual(await foreign.json(), { error: 'Shop session unavailable' });
      assert.equal(transport.calls.length, callsBeforeForeign);
      const customerCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(cookie => cookie.name === 'dvaia_shop_session');
      const customerBase = await auth.authenticate(customerCookie.value);
      const awardedProgress = await standalone.assessmentProgress.readSelf(customerBase);
      assert.equal(awardedProgress.completedObjectives, 1);
      assert.equal(awardedProgress.objectives.find(row => row.objectiveId === OBJECTIVE)?.completed, true);
      const current = await bootstrap(customerBase);
      const customerScope = await composition.launches.resolveCapability(current.bearer);
      assert.notEqual(siblingScope.platformOwnerId, customerScope.platformOwnerId);
      assert.notEqual(siblingBefore.targetId, (await scenes.readExisting(customerScope)).targetId);
      const resetResult = await lifecycle.launchResetCoordinator.reset({ launchId: customerScope.launchId,
        platformSessionId: customerScope.platformSessionId,
        platformOwnerId: customerScope.platformOwnerId, expectedGeneration: customerScope.generation,
        idempotencyKey: randomUUID() });
      assert.equal(resetResult.status, 'committed');
      const projectedAfterReset = await standalone.assessmentProgress.readSelf(customerBase);
      assert.equal(projectedAfterReset.completedObjectives, 0);
      assert.equal(projectedAfterReset.objectives.find(
        row => row.objectiveId === OBJECTIVE)?.completed, false);
      const stale = await fetch(`${origin}${savedPath}`, { headers: customerHeaders,
        signal: AbortSignal.timeout(10000) }); assert.equal(stale.status, 401);
      assert.equal((await identity.query(`SELECT count(*)::int AS n FROM
        secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1`,
      [outcome.judgment.evaluationId])).rows[0].n, 0);
      assert.deepEqual(await scenes.readExisting(siblingScope), siblingBefore);
      assert.deepEqual((await review.query(`SELECT * FROM secureshop_review.product_targets
        WHERE target_id=$1`, [siblingBefore.targetId])).rows, siblingTargetBefore);
      assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
        WHERE tenant_id=$1 AND principal_id=$2`,
      [siblingPrincipal.tenantId, siblingPrincipal.principalId])).rows, siblingProgressBefore);
      assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
        WHERE evaluation_id=$1`, [outcome.judgment.evaluationId])).rows, judgment);
      status.resetFenced = status.siblingPrivate = true;
      assert.deepEqual(pageErrors, []);
      await fs.writeFile(screenshotPath, await page.screenshot({ fullPage: true }),
        { flag: 'wx', mode: 0o600 });
    } catch (error) {
      failure = error; status.errors.push({ stage, name: error.name, code: error.code || null,
        message: String(error.message).slice(0, 300) });
      if (page) {
        try {
          const observe = surface => surface.evaluate(() => {
            const bounded = (selector, attribute) => [...document.querySelectorAll(selector)]
              .map(node => node.getAttribute(attribute)).filter(value => value
                && /^[A-Za-z0-9_:/.-]{1,100}$/.test(value)).slice(0, 64);
            const assetPaths = selector => [...document.querySelectorAll(selector)].map(node => {
              try { return new URL(node.src || node.href, location.href).pathname; } catch { return null; }
            }).filter(Boolean).slice(0, 32);
            return { path: location.pathname, readyState: document.readyState,
              title: String(document.title || '').slice(0, 120), bodyPresent: Boolean(document.body),
              iframeCount: document.querySelectorAll('iframe').length,
              ids: bounded('[id]', 'id'), testIds: bounded('[data-testid]', 'data-testid'),
              roles: bounded('[role]', 'role'), scripts: assetPaths('script[src]'),
              stylesheets: assetPaths('link[rel="stylesheet"][href]'),
              customerTaskSelectors: document.querySelectorAll(
                'select[id^="agent-lane-task-customer-"]').length };
          });
          failureDiagnostic = { stage, outer: await observe(page), frames: [] };
          for (const currentFrame of page.frames().filter(value => value !== page.mainFrame())) {
            try { failureDiagnostic.frames.push(await observe(currentFrame)); }
            catch (frameError) { failureDiagnostic.frames.push({ captureError: frameError.name }); }
          }
          failureScreenshot = path.join(path.dirname(evidencePath), 'search-echo-browser-failure.png');
          await fs.writeFile(failureScreenshot, await page.screenshot({ fullPage: false }),
            { flag: 'wx', mode: 0o600 });
        } catch (diagnosticError) {
          failureDiagnostic = { stage, captureError: diagnosticError.name };
        }
      }
      t.diagnostic(JSON.stringify({ stage: 'search-echo-rendered-failure',
        error: status.errors[0], httpStatuses, pageErrors: pageErrors.slice(-16),
        browserEvents, dom: failureDiagnostic }));
    } finally {
      if (originalModelUrl === undefined) delete process.env.OLLAMA_BASE_URL;
      else process.env.OLLAMA_BASE_URL = originalModelUrl;
      for (const close of [() => fixedBrowser?.close(), async () => {
        if (browser) { await browser.close(); browserClosed = true; }
      },
        () => closeServer(server), () => composition?.searchEcho?.close(),
        () => transport?.close(), () => lifecycle?.closeFeatureTransports?.(),
        () => lifecycle?.auditLedger?.close?.(),
        () => { if (profile && !browserClosed) throw Error('Browser close not verified');
          return profile && fs.rm(profile, { recursive: true, force: true }); },
        () => leasePool.end(), ...Object.values(pools).map(pool => () => pool.end())]) {
        try { await close(); } catch (error) { status.cleanupErrors.push(error.message); }
      }
      status.fixtureCleaned = status.cleanupErrors.length === 0;
      status.passed = !failure && status.fixtureCleaned
        && SEARCH_ECHO_FLAGS.every(flag => status[flag]);
      try {
        await fs.writeFile(wirePath, JSON.stringify({ model: MODEL, digest: MODEL_DIGEST,
          calls: transport?.calls || [], requests, judgePackets, assessmentHttpCaptures, pageErrors,
          browserDiagnostic: failure ? { ...failureDiagnostic, httpStatuses, browserEvents }
            : { stage, dedicatedEcho: status.physicalDedicatedEcho,
              v27Excluded: status.v27PreviewExcluded, fixedInert: status.fixedSameSourceInert },
          browserScreenshot: failure ? failureScreenshot : screenshotPath }, null, 2),
        { flag: 'wx', mode: 0o600 });
        await fs.writeFile(evidencePath, JSON.stringify(status, null, 2), { flag: 'wx', mode: 0o600 });
      } catch (error) { status.cleanupErrors.push(error.message); }
    }
    if (status.cleanupErrors.length) throw new AggregateError(
      status.cleanupErrors.map(message => Error(message)), 'V60 cleanup failed');
    if (failure) throw failure;
    assertSearchEchoQualificationReceipt(status);
  });
