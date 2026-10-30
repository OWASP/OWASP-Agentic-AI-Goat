'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const path = require('node:path');
const fs = require('node:fs/promises');
const os = require('node:os');
const bcrypt = require('bcryptjs');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { seedSecureShop } = require('../../server/database/postgres/secureshopSeed');
const { createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopBoundReviewComposition } = require(
  '../../server/services/secureshopBoundReviewComposition');
const { createSecureShopBoundApplication } = require('../../server/services/secureshopBoundApplication');
const { createXssBrowserQualification } = require('../../server/services/xssBrowserQualification');
const { createObjectiveJudge } = require('../../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../../server/agent-runtime/providers/langchainProvider');
const { waitForObservedCount } = require('../helpers/waitForObservedCount');

const PREFIX = 'PG_SECURESHOP_STORED_BROWSER_';
const STORES = ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && STORES.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const WORKSHOP = 'secureshop_agent_security';
const OBJECTIVE = 'ss_stored_browser_execution';
const PAYLOAD = '<img src="invalid://owned-parent-frame" onerror="alert(\'owned-parent-frame\')">';

function checkedUrl(key) {
  const value = new URL(process.env[`${PREFIX}${key}_URL`]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return value.href;
}

async function listen(app) {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}

async function closeServer(server) {
  if (!server) return;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

test('built parent and opaque frame earn canonical stored-browser credit and reset fences a late effect', {
  skip: !enabled, timeout: 240000,
}, async t => {
  const workspace = path.resolve(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || '');
  assert.match(path.basename(path.dirname(workspace)), /^owasp-ai-goat-secureshop-stored-browser-/);
  const pools = Object.fromEntries(STORES.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
    const key = `${store}_${role}`;
    return [key, new Pool({ connectionString: checkedUrl(key), max: role === 'RUNTIME' ? 10 : 3 })];
  })));
  const leases = new Pool({ connectionString: checkedUrl('IDENTITY_RUNTIME'), max: 5,
    application_name: 'secureshop-rendered-browser-leases' });
  const browserVerifier = createXssBrowserQualification({ idleCloseMs: 1000 });
  let composition; let server; let uiBrowser; let profile;
  const cleanupErrors = [];
  try {
    await migrate(pools.IDENTITY_MIGRATION, path.join(workspace, 'db/postgres/identity-migrations'));
    await migrate(pools.AGENTS_MIGRATION,
      path.join(workspace, 'db/postgres/workshop-migrations/secureshop_agents'));
    await migrate(pools.REVIEW_MIGRATION,
      path.join(workspace, 'db/postgres/workshop-migrations/secureshop_review'));
    await migrate(pools.COMMERCE_MIGRATION,
      path.join(workspace, 'db/postgres/workshop-migrations/secureshop'));
    await pools.COMMERCE_MIGRATION.query('BEGIN');
    try {
      await seedSecureShop(pools.COMMERCE_MIGRATION);
      await pools.COMMERCE_MIGRATION.query('COMMIT');
    } catch (error) {
      await pools.COMMERCE_MIGRATION.query('ROLLBACK'); throw error;
    }
    await pools.IDENTITY_MIGRATION.query(`INSERT INTO workshop_platform.exercises
      (workshop_key,challenge_key,challenge_name,challenge_description,ordinal,catalog_active,is_visible)
      VALUES($1,'secureshop-agent-security','SecureShop Agent Security',
        'Owned full rendered stored-browser qualification',900,true,true)`, [WORKSHOP]);
    await pools.IDENTITY_MIGRATION.query(`INSERT INTO workshop_platform.objectives
      (workshop_key,objective_id,label,category,ordinal,catalog_active,is_enabled)
      VALUES($1,$2,'Execute a stored review in ReviewCard','browser-sink',1,true,true)`,
    [WORKSHOP, OBJECTIVE]);

    const identities = createIdentityRepository(pools.IDENTITY_RUNTIME);
    const passwordHash = await bcrypt.hash('owned-rendered-browser', 4);
    const user = await identities.createUser({ username: `rendered-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@rendered.invalid`, passwordHash });
    const platformSession = await identities.createSession({ userId: user.id, token: randomUUID(),
      expiresAt: new Date(Date.now() + 4 * 3600000).toISOString(),
      expectedPasswordHash: passwordHash });
    await pools.IDENTITY_RUNTIME.query(`INSERT INTO workshop_platform.user_modes
      (user_id,workshop_key,mode) VALUES($1,$2,'vuln')`, [user.id, WORKSHOP]);

    const baseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
    const model = 'llama3.1:8b';
    const actualJudge = createObjectiveJudge({ model: createLangChainProvider({
      provider: 'ollama', baseURL: baseUrl, model,
    }) });
    let judgeCalls = 0; let browserCalls = 0; let browserCompleted = 0; let browserSettled = 0;
    let browserResult = null; let browserFailure = null; let holdBrowser = false;
    const startedAt = Date.now();
    const routeLifecycle = [];
    let observedBrowser; let releaseBrowser;
    const countedJudge = async packet => { judgeCalls += 1; return actualJudge(packet); };
    const countedBrowser = {
      async qualify(...args) {
        browserCalls += 1;
        try {
          const result = await browserVerifier.qualify(...args);
          browserCompleted += 1;
          browserResult = { executed: result?.executed === true,
            targetEventExecuted: result?.targetEventExecuted === true,
            targetEffectObserved: result?.targetEffectObserved === true,
            reason: typeof result?.reason === 'string' ? result.reason : null };
          if (holdBrowser) {
            holdBrowser = false;
            observedBrowser?.();
            await new Promise(resolve => { releaseBrowser = resolve; });
          }
          return result;
        } catch (error) {
          browserFailure = { name: error?.name || null, code: error?.code || null,
            reason: typeof error?.message === 'string' ? error.message.slice(0, 160) : null };
          throw error;
        } finally {
          browserSettled += 1;
        }
      },
    };
    composition = createSecureShopBoundReviewComposition({
      identityPool: pools.IDENTITY_RUNTIME, agentsPool: pools.AGENTS_RUNTIME,
      reviewPool: pools.REVIEW_RUNTIME, commercePool: pools.COMMERCE_RUNTIME, leasePool: leases,
      agentRuntime: { provider: { async chat() { throw new Error('moderation model not requested'); } } },
      jwtSecret: 'owned-rendered-secureshop-secret-at-least-32-bytes', fixtures: [],
      requiredObjectives: [OBJECTIVE], judge: countedJudge, browserQualification: countedBrowser,
      browserLifecycleObserver: event => routeLifecycle.push({ elapsedMs: Date.now() - startedAt, ...event }),
    });
    const platformToken = 'owned-rendered-platform-token';
    const authenticateToken = (req, res, next) => {
      if (req.get('authorization') !== `Bearer ${platformToken}`) return res.sendStatus(401);
      req.user = { id: user.id, username: user.username, role: 'student', admin_level: 0 };
      req.identitySession = { id: platformSession.id }; return next();
    };
    // Full application readiness requires every installed panel. These inert
    // routers keep this qualification scoped to stored-browser behavior; they
    // do not qualify the unrelated persona, MCP trust, or SSRF objectives.
    const mountedComposition = Object.freeze({ ...composition,
      personaInbox: Object.freeze({ ready: true, router: express.Router() }),
      mcpTrust: Object.freeze({ ready: true, router: express.Router() }),
      ssrf: Object.freeze({ ready: true, router: express.Router() }),
    });
    const bound = await createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
      authenticateToken, audit: async () => {}, agentRuntime: {},
      getComposition: async () => mountedComposition });

    let dropBrowserResponse = true; let reviewPosts = 0; let authStatusResponses = 0;
    const droppedBrowserResponses = [];
    const browserRequestIds = []; const browserHttpEvents = []; const httpEvents = [];
    const app = express(); app.use(express.json());
    app.use((req, res, next) => {
      if (req.path.startsWith('/api/')) httpEvents.push({ phase: 'start', method: req.method,
        path: req.path });
      if (/\/browser-attempt$/.test(req.path)) {
        browserHttpEvents.push({ phase: 'start', method: req.method, path: req.path });
        req.once('aborted', () => browserHttpEvents.push({ phase: 'aborted' }));
        res.once('finish', () => browserHttpEvents.push({ phase: 'finish', status: res.statusCode }));
        res.once('close', () => browserHttpEvents.push({ phase: 'close', status: res.statusCode,
          writableEnded: res.writableEnded }));
      }
      res.once('finish', () => {
        if (req.path.startsWith('/api/')) httpEvents.push({ phase: 'finish', method: req.method,
          path: req.path, status: res.statusCode });
      });
      next();
    });
    app.get('/api/auth/status', (_req, res) => {
      authStatusResponses += 1;
      res.json({ authenticated: true,
        user: { id: user.id, username: user.username, role: 'student', admin_level: 0 } });
    });
    app.get('/api/workshop/config/snapshot', (_req, res) => res.json({ revision: 1, exercises: {
      [WORKSHOP]: { isVisible: true, showHints: false, showSolutions: false, objectives: {
        [OBJECTIVE]: { isVisible: true, hintVisible: false, solutionVisible: false },
      } },
    } }));
    app.get('/api/workshop/config/revision', (_req, res) => res.json({ revision: 1 }));
    app.get('/api/ctf/config', (_req, res) => res.json({ enabled: false, show_in_nav: false }));
    async function completionCount() {
      return Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::integer AS count
        FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 AND objective_id=$3`,
      [user.id, WORKSHOP, OBJECTIVE])).rows[0].count);
    }
    app.get('/api/changes/revisions', async (_req, res) => {
      const active = await composition.launches.readActiveMetadata({ platformOwnerId: user.id,
        platformSessionId: platformSession.id });
      res.json({ revisions: { workshop_progress: (active?.generation || 0) * 10 + await completionCount() } });
    });
    app.get('/api/workshop/challenges', async (_req, res) => {
      const completed = await completionCount() === 1;
      const objective = { id: OBJECTIVE, label: 'Execute a stored review in ReviewCard',
        text: 'Execute a stored review in ReviewCard', completed,
        hintVisible: false, solutionVisible: false };
      res.json({ success: true, challenges: [{ id: WORKSHOP, workshopKey: WORKSHOP,
        name: 'SecureShop Agent Security', title: 'SecureShop Agent Security',
        route: '/workshop/secureshop', showHints: false, showSolutions: false,
        objectives: [objective], exerciseGroups: [{ id: 'ss_browser_sink',
          title: 'Stored browser execution', objectives: [objective], objectiveCount: 1,
          completedObjectiveCount: Number(completed) }], totalObjectives: 1,
        completedObjectives: Number(completed) }] });
    });
    app.use('/api/auth/secureshop-launch', bound.launchRouter);
    app.use('/api/secureshop', (req, res, next) => {
      if (req.method === 'POST' && /^\/products\/\d+\/reviews$/.test(req.path)) reviewPosts += 1;
      if (req.method === 'POST' && /\/browser-attempt$/.test(req.path)) {
        browserRequestIds.push(req.body?.request_id);
        if (dropBrowserResponse) {
          dropBrowserResponse = false;
          res.json = body => {
            droppedBrowserResponses.push({ status: res.statusCode,
              completed: body?.completed === true, replayed: body?.replayed === true,
              verdict: typeof body?.judgment?.verdict === 'string' ? body.judgment.verdict : null,
              retryable: body?.judgment?.canRetry === true,
              error: typeof body?.error === 'string' ? body.error : null,
              errorCode: typeof body?.errorCode === 'string' ? body.errorCode : null });
            setImmediate(() => res.socket?.destroy());
            return res;
          };
        }
      }
      next();
    });
    app.use('/api/secureshop', bound.gateway);
    app.use('/api', (_req, res) => res.status(404).json({ error: 'Outside connected qualifier' }));
    const clientBuild = path.join(workspace, 'client/build');
    app.use(express.static(clientBuild, {
      // The sandboxed frame has an opaque origin and Vite emits crossorigin
      // module/preload requests. Match the application's reviewed CORS asset
      // boundary so the real frame entry can execute.
      setHeaders: res => res.set('Access-Control-Allow-Origin', '*'),
    }));
    app.get(/.*/, (_req, res) => res.sendFile('index.html', { root: clientBuild }));
    server = await listen(app);
    const origin = `http://127.0.0.1:${server.address().port}`;
    const launchProbe = await fetch(`${origin}/api/auth/secureshop-launch`, {
      headers: { authorization: `Bearer ${platformToken}` }, signal: AbortSignal.timeout(5000),
    });
    assert.equal(launchProbe.status, 200);
    assert.deepEqual(await launchProbe.json(), { preparationOnly: false, launch: null });
    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-stored-browser-parent-'));
    uiBrowser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
      ...(process.env.PUPPETEER_EXECUTABLE_PATH
        ? { executablePath: process.env.PUPPETEER_EXECUTABLE_PATH } : {}) });
    const page = await uiBrowser.newPage(); await page.setViewport({ width: 1280, height: 900 });
    const parentStartup = [{ milestone: 'page-created' }];
    const sanitizeDiagnostic = value => String(value || '')
      .replaceAll(platformToken, '<redacted-platform-token>')
      .replace(/Bearer\s+[^\s"']+/gi, 'Bearer <redacted>')
      .replace(/[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g, '<redacted-jwt>')
      .slice(0, 500);
    const uiDialogs = [];
    page.on('dialog', dialog => {
      uiDialogs.push(dialog.message());
      dialog.dismiss().catch(() => {});
    });
    await page.setRequestInterception(true); parentStartup.push({ milestone: 'request-interception-ready' });
    page.on('request', request => request.url().startsWith(`${origin}/`)
      ? request.continue() : request.abort());
    const pageErrors = []; page.on('pageerror', error => pageErrors.push(sanitizeDiagnostic(error.message)));
    const browserRequestFailures = []; const parentRequestFailures = []; const parentNetwork = [];
    page.on('requestfailed', request => {
      const requested = new URL(request.url());
      parentRequestFailures.push({ path: requested.origin === origin ? requested.pathname : '<blocked-external>',
        resourceType: request.resourceType(), errorText: request.failure()?.errorText || null });
      if (/\/browser-attempt$/.test(new URL(request.url()).pathname)) {
        browserRequestFailures.push({ elapsedMs: Date.now() - startedAt,
          errorText: request.failure()?.errorText || null });
      }
    });
    page.on('response', response => {
      const requested = new URL(response.url());
      if (requested.origin === origin && parentNetwork.length < 128) {
        parentNetwork.push({ path: requested.pathname, status: response.status(),
          resourceType: response.request().resourceType() });
      }
    });
    const pageConsoleErrors = [];
    page.on('console', message => {
      if (message.text().startsWith('ErrorBoundary caught')) pageErrors.push(message.text());
      if (['error', 'warn', 'warning'].includes(message.type())) {
        pageConsoleErrors.push({ type: message.type(), text: sanitizeDiagnostic(message.text()) });
      }
    });
    await page.evaluateOnNewDocument(() => {
      const originalAbort = AbortController.prototype.abort;
      const events = [];
      Object.defineProperty(globalThis, '__owasp-ai-goatAbortEvents', { value: events });
      AbortController.prototype.abort = function observedAbort(reason) {
        events.push({ elapsedMs: Math.round(performance.now()),
          reasonName: typeof reason?.name === 'string' ? reason.name : null,
          stack: String(new Error('AbortController.abort observed').stack || '')
            .split('\n').slice(0, 7).join('\n').slice(0, 1200) });
        return originalAbort.call(this, reason);
      };
    });
    await page.evaluateOnNewDocument(token => {
      try {
        if (window.parent === window) localStorage.setItem('token', token);
      } catch { /* opaque child frames never receive platform storage */ }
    }, platformToken);
    parentStartup.push({ milestone: 'token-bootstrap-installed' });
    const navigation = await page.goto(`${origin}/workshop/secureshop`);
    parentStartup.push({ milestone: 'navigation-complete', path: new URL(page.url()).pathname,
      status: navigation?.status() || null });
    async function stableShopFrame(previous = null) {
      const deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        const element = await page.$('iframe[title="SecureShop workshop"]');
        const isPrevious = element && previous
          ? await page.evaluate((left, right) => left === right, element, previous).catch(() => true)
          : false;
        if (element && !isPrevious) {
          const connected = await element.evaluate(node => new Promise(resolve => {
            requestAnimationFrame(() => requestAnimationFrame(() => resolve(node.isConnected)));
          })).catch(() => false);
          const candidate = connected ? await element.contentFrame().catch(() => null) : null;
          if (candidate && !candidate.detached) return { element, frame: candidate };
        }
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      throw new Error('Stable SecureShop frame unavailable');
    }
    const authDeadline = Date.now() + 15000;
    while (authStatusResponses < 1 && Date.now() < authDeadline) {
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    if (authStatusResponses < 1) {
      t.diagnostic(JSON.stringify({ stage: 'parent-auth-bootstrap', pagePath: new URL(page.url()).pathname,
        parentTokenPresent: await page.evaluate(() => Boolean(localStorage.getItem('token'))).catch(() => false),
        parentBody: sanitizeDiagnostic(await page.evaluate(() => document.body.textContent.slice(0, 1000))
          .catch(() => '<unavailable>')),
        parentStartup, parentNetwork, parentRequestFailures, pageErrors, pageConsoleErrors,
        httpEvents: httpEvents.slice(-40) }));
    }
    assert.ok(authStatusResponses >= 1, 'platform authentication must resolve before frame selection');
    await page.waitForFunction(() => document.body.textContent.includes('0 of 1 objectives completed'),
      { timeout: 15000 }).catch(async error => {
      const frames = await Promise.all(page.frames().map(async current => ({ url: current.url(),
        body: await current.evaluate(() => document.body.textContent).catch(() => '<detached>') })));
      t.diagnostic(JSON.stringify({ stage: 'parent-launch-ready', cause: error.message,
        parentBody: await page.evaluate(() => document.body.textContent), frames,
        parentTokenPresent: await page.evaluate(() => Boolean(localStorage.getItem('token'))),
        httpEvents: httpEvents.slice(-40), pageErrors }));
      throw error;
    });
    let mounted = await stableShopFrame();
    let frame = mounted.frame;
    async function loginCustomer(targetFrame) {
      await targetFrame.waitForSelector('a[href="/secureshop/login"]', { timeout: 15000 });
      await targetFrame.click('a[href="/secureshop/login"]');
      await targetFrame.waitForSelector('#ss-login-user');
      await targetFrame.type('#ss-login-user', 'student_customer');
      await targetFrame.type('#ss-login-pw', 'student123');
      await targetFrame.click('button[type="submit"]');
    }
    async function openCatalog(targetFrame) {
      await targetFrame.waitForSelector('button[aria-label="Account menu"]', { timeout: 15000 });
      await targetFrame.click('a[href="/secureshop/catalog"]');
      await targetFrame.waitForSelector('a[href^="/secureshop/product/"]');
    }
    await loginCustomer(frame).catch(async error => {
      const frames = await Promise.all(page.frames().map(async current => ({ url: current.url(),
        body: await current.evaluate(() => document.body.textContent).catch(() => '<detached>') })));
      t.diagnostic(JSON.stringify({ stage: 'initial-frame-login', cause: error.message,
        parentBody: await page.evaluate(() => document.body.textContent), frames, pageErrors }));
      throw error;
    });
    await openCatalog(frame);
    await frame.evaluate(() => document.querySelector('a[href^="/secureshop/product/"]').click());
    await frame.waitForSelector('textarea[aria-label="Review body"]');
    async function postReview(payload) {
      await frame.$eval('textarea[aria-label="Review body"]', (textarea, value) => {
        const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
        setter.call(textarea, value); textarea.dispatchEvent(new Event('input', { bubbles: true }));
      }, payload);
      await frame.waitForFunction(value => {
        const textarea = document.querySelector('textarea[aria-label="Review body"]');
        return textarea?.value === value
          && textarea.closest('form')?.querySelector('button[type="submit"]')?.disabled === false;
      }, {}, payload);
      await frame.$eval('textarea[aria-label="Review body"]', textarea =>
        textarea.closest('form').querySelector('button[type="submit"]').click());
    }
    await postReview(PAYLOAD);
    try {
      // The Judge alone has a 90-second bound. Wait for its response loss and
      // the terminal replay request, with separate transport allowance.
      await waitForObservedCount({ read: () => browserRequestIds.length,
        expected: 2, timeoutMs: 105000 });
    } catch (error) {
      const abortEvents = await Promise.all(page.frames().map(async current => ({ url: current.url(),
        events: await current.evaluate(() => globalThis.__owasp-ai-goatAbortEvents || []).catch(() => []) })));
      const databaseActivity = {};
      for (const store of ['IDENTITY', 'REVIEW', 'AGENTS']) {
        databaseActivity[store.toLowerCase()] = (await pools[`${store}_MIGRATION`].query(`SELECT
          usename,state,wait_event_type,wait_event,left(regexp_replace(query,'\\s+',' ','g'),160) AS query
          FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
          ORDER BY usename,pid`)).rows;
      }
      t.diagnostic(JSON.stringify({ stage: 'browser-response-replay', reviewPosts, browserCalls,
        browserCompleted, browserSettled, browserResult, browserFailure, droppedBrowserResponses,
        judgeCalls, browserRequestCount: browserRequestIds.length,
        routeLifecycle, browserRequestFailures,
        abortEvents,
        parentBody: await page.evaluate(() => document.body.textContent),
        frameBody: await frame.evaluate(() => document.body.textContent).catch(() => '<detached>'),
        browserHttpEvents, httpEvents: httpEvents.slice(-40), databaseActivity, pageErrors }));
      throw error;
    }
    assert.equal(browserRequestIds.length, 2,
      'the lost response must settle before the exact request is replayed');
    await frame.waitForFunction(() =>
      document.querySelector('textarea[aria-label="Review body"]')?.value === '', { timeout: 10000 });
    assert.equal(reviewPosts, 1); assert.equal(browserCalls, 1); assert.equal(judgeCalls, 1);
    assert.equal(browserRequestIds[0], browserRequestIds[1]);
    assert.deepEqual(uiDialogs, [], 'the opaque application frame must suppress native modal UI');
    await page.waitForFunction(() => document.body.textContent.includes('1 of 1 objectives completed'),
      { timeout: 15000 });
    assert.equal(await completionCount(), 1);

    const active = await composition.launches.readActiveMetadata({ platformOwnerId: user.id,
      platformSessionId: platformSession.id });
    const learnerRows = (await pools.REVIEW_RUNTIME.query(`SELECT r.id,r.body,r.body_sha256,
        r.submission_id,t.target_id,t.launch_id,t.generation,t.original_platform_owner_id
      FROM secureshop_review.reviews r JOIN secureshop_review.review_targets t USING(target_id)
      WHERE t.launch_id=$1 AND t.generation=$2 AND r.source_kind='learner'`,
    [active.launchId, active.generation])).rows;
    assert.equal(learnerRows.length, 1, 'the learner review business mutation must occur once');
    assert.equal(learnerRows[0].body, PAYLOAD);
    assert.equal(learnerRows[0].original_platform_owner_id, user.id);
    assert.equal(learnerRows[0].body_sha256.toString('hex'),
      createHash('sha256').update(PAYLOAD).digest('hex'));
    const judgment = (await pools.IDENTITY_RUNTIME.query(`SELECT *
      FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND workshop_key=$2 AND objective_id=$3`,
    [user.id, WORKSHOP, OBJECTIVE])).rows[0];
    assert.equal(judgment.verdict, 'pass');
    assert.equal(judgment.disposition, 'awarded');
    assert.equal(judgment.result_json.provider, 'ollama');
    assert.equal(judgment.platform_launch_id, active.launchId);
    assert.equal(String(judgment.platform_launch_generation), String(active.generation));
    const contribution = (await pools.IDENTITY_RUNTIME.query(`SELECT *
      FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND evaluation_id=$2`, [user.id, judgment.evaluation_id])).rows[0];
    assert.equal(contribution.platform_launch_id, active.launchId);
    assert.equal(String(contribution.platform_launch_generation), String(active.generation));
    const packetValue = (await pools.IDENTITY_RUNTIME.query(`SELECT packet
      FROM workshop_platform.grade_packets WHERE user_id=$1 AND evaluation_id=$2`,
    [user.id, judgment.evaluation_id])).rows[0].packet;
    const packet = typeof packetValue === 'string' ? JSON.parse(packetValue) : packetValue;
    const proof = packet.evidence.find(row => row.id === 'stored_browser_receipt').content;
    assert.equal(proof.source.reviewId, Number(learnerRows[0].id));
    assert.equal(proof.source.submissionId, learnerRows[0].submission_id);
    assert.equal(proof.source.bodySha256, learnerRows[0].body_sha256.toString('hex'));
    assert.equal(proof.component.id, 'SecureShop.ReviewCard');
    assert.equal(proof.browser.targetEventExecuted, true);
    assert.equal(proof.browser.targetEffectObserved, true);
    assert.equal(proof.execution.effectReceipt.status, 'completed');
    assert.equal(proof.execution.effectReceipt.runId, judgment.run_id);
    assert.match(proof.execution.effectReceipt.effectKey,
      new RegExp(`^${browserRequestIds[0]}:stored-browser:${learnerRows[0].id}$`));
    const effects = (await pools.IDENTITY_RUNTIME.query(`SELECT effect_key,status,run_id
      FROM graph_runtime.effects WHERE run_id=$1`, [judgment.run_id])).rows;
    assert.deepEqual(effects, [{ effect_key: proof.execution.effectReceipt.effectKey,
      status: 'completed', run_id: judgment.run_id }]);
    assert.equal(Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::integer AS count
      FROM graph_runtime.events WHERE run_id=$1 AND node='stored_browser_assessment'
        AND event_type='node_start'`, [judgment.run_id])).rows[0].count), 1);
    t.diagnostic(JSON.stringify({ stage: 'accepted-browser-credit',
      evaluationId: judgment.evaluation_id, runId: judgment.run_id,
      launchId: active.launchId, launchGeneration: active.generation,
      submissionId: learnerRows[0].submission_id,
      bodySha256: learnerRows[0].body_sha256.toString('hex'),
      effectKey: proof.execution.effectReceipt.effectKey,
      verdict: judgment.verdict, provider: judgment.result_json.provider }));

    const sibling = await identities.createUser({ username: `rendered-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@rendered.invalid`, passwordHash });
    const siblingSession = await identities.createSession({ userId: sibling.id, token: randomUUID(),
      expiresAt: new Date(Date.now() + 3600000).toISOString(), expectedPasswordHash: passwordHash });
    const siblingLaunch = await composition.launches.issueOrRenew({ platformOwnerId: sibling.id,
      platformSessionId: siblingSession.id, expiresAt: new Date(Date.now() + 30 * 60000).toISOString() });
    const siblingLogin = await composition.personaAuth.login({ scope: siblingLaunch.binding,
      username: 'student_customer', password: 'student123' });
    const siblingSubmission = await composition.runtime.application.submitReview({
      scope: siblingLaunch.binding, persona: siblingLogin.user, submissionId: randomUUID(),
      productId: 1, authorId: 999, body: 'Sibling owner factual usage feedback.', rating: 4 });
    const siblingTarget = await composition.runtime.application.resolveTarget(siblingLaunch.binding);

    const firstFrameElement = mounted.element;
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.includes('Reset launch')).click());
    await page.waitForFunction(() => document.body.textContent.includes('0 of 1 objectives completed'),
      { timeout: 20000 });
    assert.equal(await firstFrameElement.evaluate(node => node.isConnected), false);
    assert.equal((await composition.repositories.reviews.readSubmission(
      siblingTarget, siblingSubmission.id)).body, 'Sibling owner factual usage feedback.');
    assert.equal(Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::integer AS count
      FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2`,
    [sibling.id, WORKSHOP])).rows[0].count), 0);
    mounted = await stableShopFrame(firstFrameElement);
    frame = mounted.frame;
    const secondActive = await composition.launches.readActiveMetadata({ platformOwnerId: user.id,
      platformSessionId: platformSession.id });
    await loginCustomer(frame);
    await openCatalog(frame);
    await frame.evaluate(() => document.querySelector('a[href^="/secureshop/product/"]').click());
    await frame.waitForSelector('textarea[aria-label="Review body"]');
    const observed = new Promise(resolve => { observedBrowser = resolve; });
    holdBrowser = true;
    await postReview(PAYLOAD.replace('owned-parent-frame', 'owned-reset-race'));
    await observed;
    const raceFrameElement = mounted.element;
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.includes('Reset launch')).click());
    await page.waitForFunction(() => document.body.textContent.includes('Connecting to your isolated shop'));
    assert.equal(await raceFrameElement.evaluate(node => node.isConnected), false);
    releaseBrowser();
    const recovered = await stableShopFrame(raceFrameElement);
    const recoveredFrame = recovered.frame;
    await recoveredFrame.waitForSelector('a[href="/secureshop/login"]', { timeout: 15000 });
    await page.waitForFunction(() => document.body.textContent.includes('0 of 1 objectives completed'),
      { timeout: 30000 });
    assert.equal(await completionCount(), 0);
    assert.equal(judgeCalls, 1, 'reset-fenced effect must not reach Judge');
    const historical = (await pools.IDENTITY_RUNTIME.query(`SELECT evaluation_id,platform_launch_id,
        platform_launch_generation,workshop_generation
      FROM workshop_platform.objective_contributions WHERE user_id=$1 ORDER BY accepted_at`,
    [user.id])).rows;
    assert.equal(historical.length, 1, 'reset preserves exactly the immutable accepted contribution');
    assert.equal(historical[0].evaluation_id, judgment.evaluation_id);
    assert.equal(historical[0].platform_launch_id, active.launchId);
    assert.equal(String(historical[0].platform_launch_generation), String(active.generation));
    const retired = (await pools.IDENTITY_RUNTIME.query(`SELECT reset_id,launch_id,
        from_launch_generation,retired_objective_contribution_count,projected_completion_count
      FROM identity.secureshop_progress_cleanup_history
      WHERE original_platform_owner_id=$1 AND launch_id=$2 AND from_launch_generation=$3`,
    [user.id, active.launchId, active.generation])).rows;
    assert.equal(retired.length, 1, 'the initial accepted contribution needs an exact cleanup receipt');
    assert.equal(retired[0].retired_objective_contribution_count, 1);
    assert.equal(retired[0].projected_completion_count, 0);
    assert.equal(Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::integer AS count
      FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND platform_launch_id=$2 AND platform_launch_generation=$3`,
    [user.id, secondActive.launchId, secondActive.generation])).rows[0].count), 0,
    'the fenced new-generation effect must publish no contribution');
    assert.equal(Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::integer AS count
      FROM workshop_platform.objective_contributions c WHERE c.user_id=$1
        AND NOT EXISTS (SELECT 1 FROM identity.secureshop_progress_cleanup_history h
          WHERE h.launch_id=c.platform_launch_id
            AND h.from_launch_generation=c.platform_launch_generation)`,
    [user.id])).rows[0].count), 0, 'no accepted contribution remains in the active projection');
    assert.equal(Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::integer AS count
      FROM workshop_platform.objective_judgments WHERE user_id=$1 AND platform_launch_generation=$2
        AND verdict='pass' AND disposition IN ('awarded','already_complete')`,
    [user.id, secondActive.generation])).rows[0].count), 0,
    'the reset-generation browser effect must not create passing evidence');
    t.diagnostic(JSON.stringify({ stage: 'reset-retirement',
      historicalEvaluationId: historical[0].evaluation_id,
      retiredByResetId: retired[0].reset_id,
      retiredLaunchId: retired[0].launch_id,
      retiredLaunchGeneration: String(retired[0].from_launch_generation),
      newLaunchGeneration: secondActive.generation,
      canonicalCompletionCount: 0, newGenerationContributionCount: 0,
      totalImmutableContributionCount: historical.length }));
    assert.deepEqual(pageErrors, []);
    t.diagnostic(JSON.stringify({ scope: 'built parent + opaque frame + native four-store runtime + isolated browser + actual local 8B Judge',
      retry: { reviewPosts, browserCallsBeforeReset: 1, judgeCallsBeforeReset: 1,
        stableRequestId: browserRequestIds[0], verdict: judgment.verdict,
        provider: judgment.result_json.provider, effectKey: proof.execution.effectReceipt.effectKey },
      resetRace: { browserCalls, judgeCalls, completionCount: 0 },
      limitation: 'catalog visibility remains isolated-test-only; no live feature activation' }));
  } finally {
    for (const close of [() => uiBrowser?.close(), () => closeServer(server),
      () => composition?.closeBrowserAssessment(), () => browserVerifier.close(),
      () => profile && fs.rm(profile, { recursive: true, force: true }),
      () => leases.end(), ...Object.values(pools).map(pool => () => pool.end())]) {
      try { await close(); } catch (error) { cleanupErrors.push(error); }
    }
    if (cleanupErrors.length) throw new AggregateError(cleanupErrors,
      'Rendered stored-browser qualification cleanup failed');
  }
});
