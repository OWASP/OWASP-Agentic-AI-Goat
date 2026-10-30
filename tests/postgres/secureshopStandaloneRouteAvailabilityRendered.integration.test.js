'use strict';

// A11 intentionally has a small rendered qualification of its own.  The
// commerce browser qualification also visits this page, but it owns checkout
// and listing behaviour; keeping the availability proof here makes a timeout
// in those flows unable to hide a route-boundary regression.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

const PREFIX = 'PG_SECURESHOP_STANDALONE_ROUTE_AVAILABILITY_';
const STORES = ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE'];
const CLEANUP_STEP_TIMEOUT_MS = 10000;
const BROWSER_PROTOCOL_TIMEOUT_MS = 20000;
const QUALIFICATION_WORK_TIMEOUT_MS = 240000;
const BROWSER_STEP_TIMEOUT_MS = 30000;
let qualificationDeadline = 0;
let phaseCheckpointPath = '';
let phaseCheckpointWrite = Promise.resolve();
const ENABLED = process.env.SECURESHOP_STANDALONE_ROUTE_AVAILABILITY_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && STORES.every(store => ['MIGRATION', 'RUNTIME'].every(role =>
    process.env[`${PREFIX}${store}_${role}_URL`]));

function storeUrls() {
  const names = { IDENTITY: 'identity', AGENTS: 'secureshop_agents',
    REVIEW: 'secureshop_review', COMMERCE: 'secureshop' };
  const urls = {};
  let nonce; let port;
  for (const store of STORES) {
    for (const role of ['MIGRATION', 'RUNTIME']) {
      const key = `${store}_${role}`;
      const url = new URL(process.env[`${PREFIX}${key}_URL`]);
      assert.equal(url.protocol, 'postgresql:');
      assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.port, /^[1-9][0-9]{0,4}$/);
      assert.ok(Number(url.port) <= 65535);
      assert.equal(url.username, `dvaia_${names[store]}_${role.toLowerCase()}`);
      assert.equal(url.password, '');
      assert.equal(url.search, '');
      assert.equal(url.hash, '');
      const match = new RegExp(`^/owasp_ai_goat_test_agent_host_([0-9a-f]{12})_${names[store]}$`)
        .exec(url.pathname);
      assert.ok(match, `closed disposable database name required for ${key}`);
      nonce ??= match[1];
      port ??= url.port;
      assert.equal(match[1], nonce);
      assert.equal(url.port, port);
      urls[key] = url.href;
    }
    assert.equal(new URL(urls[`${store}_MIGRATION`]).pathname,
      new URL(urls[`${store}_RUNTIME`]).pathname);
  }
  assert.equal(new Set(STORES.map(store =>
    new URL(urls[`${store}_RUNTIME`]).pathname)).size, STORES.length);
  return Object.freeze(urls);
}

async function waitForServerListening(server) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (!error) return resolve(server);
      closeServer(server).then(
        () => reject(error),
        closeError => reject(new AggregateError([error, closeError],
          'Server listen failed and owned handle close failed')),
      );
    };
    timer = setTimeout(() => {
      const error = Object.assign(new Error('server listen timed out'),
        { code: 'SERVER_LISTEN_TIMEOUT' });
      finish(error);
    }, BROWSER_STEP_TIMEOUT_MS);
    timer.unref?.();
    server.once('listening', () => finish());
    server.once('error', finish);
    if (server.listening) finish();
  });
}

async function closeServer(server) {
  if (server) await new Promise((resolve, reject) =>
    server.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING'
      ? reject(error) : resolve()));
}

async function boundedCleanup(label, operation) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(operation),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(
          new Error(`${label} cleanup timed out`), { code: 'CLEANUP_TIMEOUT' })),
        CLEANUP_STEP_TIMEOUT_MS);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function phaseStep(label, operation) {
  const remaining = qualificationDeadline ? qualificationDeadline - Date.now() : Infinity;
  if (remaining <= 0) throw Object.assign(new Error(`${label} work deadline exceeded`), {
    code: 'QUALIFICATION_WORK_TIMEOUT',
  });
  persistPhaseCheckpoint(label, 'before');
  try {
    const result = await operation();
    persistPhaseCheckpoint(label, 'after');
    return result;
  } catch (error) {
    persistPhaseCheckpoint(label, 'failed', error);
    throw error;
  }
}

function persistPhaseCheckpoint(label, state, error) {
  if (!phaseCheckpointPath) return;
  const checkpoint = { phase: label, state, updatedAt: new Date().toISOString() };
  if (error) checkpoint.error = { name: error.name, code: error.code || null,
    message: String(error.message || '').slice(0, 512) };
  phaseCheckpointWrite = phaseCheckpointWrite
    .then(() => fs.writeFile(phaseCheckpointPath, JSON.stringify(checkpoint), { mode: 0o600 }))
    .catch(() => {});
}

function browserProcessExited(browser) {
  if (!browser) return true;
  const process = browser.process?.();
  if (!process) return browser.connected?.() === false;
  return process.exitCode !== null || process.signalCode !== null || !process.pid;
}

async function waitForBrowserExit(browser) {
  if (!browser) return true;
  const deadline = Date.now() + CLEANUP_STEP_TIMEOUT_MS;
  while (!browserProcessExited(browser) && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  return browserProcessExited(browser);
}

async function stableFrame(page) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const element = await phaseStep('frame:find-iframe',
      () => page.$('iframe[title="SecureShop"]'));
    const frame = element && await phaseStep('frame:content-frame',
      () => element.contentFrame(), 5000).catch(() => null);
    if (frame && !frame.detached) return frame;
    await new Promise(resolve => setTimeout(resolve, 40));
  }
  throw new Error('Standalone SecureShop frame did not mount');
}

async function browserLogin(page, origin, username, password) {
  const navigation = await phaseStep('login:document',
    () => page.goto(`${origin}/secureshop/login`, {
      waitUntil: 'domcontentloaded', timeout: BROWSER_STEP_TIMEOUT_MS,
    }));
  assert.ok([200, 304].includes(navigation.status()));
  await phaseStep('login:form', () => page.waitForSelector('#ss-login-user', { timeout: 20000 }));
  await phaseStep('login:user', () => page.type('#ss-login-user', username));
  await phaseStep('login:password', () => page.type('#ss-login-pw', password));
  const loginResponse = page.waitForResponse(response => {
    const url = new URL(response.url());
    return response.request().method() === 'POST'
      && url.pathname === '/api/secureshop/auth/login';
  }, { timeout: 20000 });
  try {
    await phaseStep('login:submit', () => page.click('button[type="submit"]'));
    assert.equal((await phaseStep('login:response', () => loginResponse)).status(), 200,
      'rendered standalone login must be admitted');
  } catch (error) {
    await loginResponse.catch(() => {});
    throw error;
  }
  return phaseStep('login:frame', () => stableFrame(page));
}

async function browserBoundRequest(page, authority, method, route, body) {
  return phaseStep(`bound-request:${method}:${route}`, () => page.evaluate(async ({ authority, method, route, body }) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch(route, {
        method,
        signal: controller.signal,
        credentials: 'include',
        headers: {
          Authorization: authority.authorization,
          'X-OWASP-AI-GOAT-SecureShop-Launch': authority.launch,
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const text = await response.text();
      let parsed;
      try { parsed = JSON.parse(text); } catch { parsed = { text }; }
      return { status: response.status, body: parsed };
    } finally { clearTimeout(timer); }
  }, { authority, method, route, body }));
}

function assertUnavailableReadiness(response) {
  assert.equal(response.status, 503);
  assert.deepEqual(response.body, { error: 'Bound SecureShop operation unavailable' });
}

function assertDistinctBrowserContexts(entries) {
  const contexts = entries.map(entry => entry.context);
  assert.equal(new Set(contexts).size, contexts.length,
    'each rendered identity must own a distinct browser context');
}

async function captureReadinessDiagnostics(page, frame, lifecycle) {
  const result = { pageUrl: null, frameUrl: null, frameDetached: null, dom: null,
    readinessRequests: lifecycle.map(entry => ({ ...entry })) };
  try { result.pageUrl = page.url(); } catch (error) { result.pageUrl = `unavailable: ${error.message}`; }
  try { result.frameUrl = frame.url(); result.frameDetached = frame.detached; } catch (error) {
    result.frameUrl = `unavailable: ${error.message}`;
  }
  try {
    result.dom = await frame.evaluate(() => {
      const visible = node => {
        const style = globalThis.getComputedStyle(node), box = node.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden'
          && box.width > 0 && box.height > 0;
      };
      const text = node => String(node.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 512);
      return {
        readyState: document.readyState,
        bodyText: String(document.body?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 3000),
        alerts: [...document.querySelectorAll('[role="alert"]')].filter(visible).map(text).slice(0, 20),
        statuses: [...document.querySelectorAll('[role="status"]')].filter(visible).map(text).slice(0, 20),
        retryButtons: [...document.querySelectorAll('button')].filter(node => visible(node)
          && /retry|availability|listing actions/i.test(text(node))).map(text).slice(0, 20),
      };
    });
  } catch (error) { result.dom = { error: String(error.message || error).slice(0, 512) }; }
  return result;
}

test('cleanup does not treat a signalled but still-running browser as exited', () => {
  const child = { pid: 4242, killed: true, exitCode: null, signalCode: null };
  const browser = { process: () => child, connected: () => false };
  assert.equal(browserProcessExited(browser), false);
  child.exitCode = 0;
  assert.equal(browserProcessExited(browser), true);
});

test('readiness body proof rejects an empty unavailable response', () => {
  assert.throws(() => assertUnavailableReadiness({ status: 503, body: {} }));
  assert.doesNotThrow(() => assertUnavailableReadiness({ status: 503,
    body: { error: 'Bound SecureShop operation unavailable' } }));
});

test('rendered identity sessions reject a shared browser context', () => {
  const owner = { context: {} }, sibling = { context: {} };
  assert.doesNotThrow(() => assertDistinctBrowserContexts([owner, sibling]));
  assert.throws(() => assertDistinctBrowserContexts([owner, { context: owner.context }]),
    /distinct browser context/);
});

test('standalone rendered listings boundary reports disabled 503 and unknown 404 without legacy fallthrough',
  { skip: !ENABLED, timeout: 300000 }, async () => {
    qualificationDeadline = Date.now() + QUALIFICATION_WORK_TIMEOUT_MS;
    const workspace = path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/');
    assert.equal(workspace, process.cwd(), 'qualification must use the current checkout');
    const build = path.resolve(process.env.SECURESHOP_STANDALONE_ROUTE_AVAILABILITY_BUILD
      || path.join(workspace, 'client/build'));
    assert.equal(build, path.join(workspace, 'client/build'));
    await phaseStep('preflight:build', () => Promise.all([
      fs.access(path.join(build, 'index.html')),
      fs.access(path.join(build, 'secureshop-frame.html')),
    ]));
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(executablePath));
    await phaseStep('preflight:browser', () => fs.access(executablePath));
    const receiptPath = process.env.SECURESHOP_STANDALONE_ROUTE_AVAILABILITY_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(receiptPath));
    assert.ok(!path.resolve(receiptPath).startsWith(`${workspace}${path.sep}`));
    phaseCheckpointPath = receiptPath.replace(/\.json$/i, '.phase.json');
    phaseCheckpointWrite = Promise.resolve();

    const urls = storeUrls();
    const pools = Object.fromEntries(STORES.flatMap(store =>
      ['MIGRATION', 'RUNTIME'].map(role => {
        const key = `${store}_${role}`;
        return [key, new Pool({ connectionString: urls[key], max: role === 'RUNTIME' ? 12 : 3,
          connectionTimeoutMillis: 15000, statement_timeout: 45000 })];
      })));
    const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4,
      connectionTimeoutMillis: 15000, statement_timeout: 45000 });
    let composition; let server; let browser; let profile; const contexts = new Set();
    let failure; let phase = 'setup'; const cleanupErrors = [];
    const setPhase = label => {
      phase = label;
      persistPhaseCheckpoint(phase, 'start');
    };
    const status = { scope: 'current-main rendered standalone listings availability boundary',
      passed: false, ownerRendered: false, siblingRendered: false,
      disabledListings503: false, unknownRoute404: false, ownerScopeStable: false,
      siblingScopeStable: false, legacyFallbackHits: 0, cleanupComplete: false,
      browserCloseVerified: false, profileRemoved: false, profilePreserved: false };
    let legacyFallbackHits = 0;

    try {
      for (const [store, directory] of [
        ['IDENTITY', 'identity-migrations'],
        ['AGENTS', 'workshop-migrations/secureshop_agents'],
        ['REVIEW', 'workshop-migrations/secureshop_review'],
        ['COMMERCE', 'workshop-migrations/secureshop'],
      ]) {
        setPhase(`migrate:${store.toLowerCase()}`);
        await phaseStep(phase, () => migrate(pools[`${store}_MIGRATION`],
          path.join(workspace, 'db/postgres', directory)));
      }
      setPhase('seed:workshop-platform');
      await phaseStep(phase, () => require('../../server/database/postgres/workshopPlatformSeed')
        .seedWorkshopPlatform(pools.IDENTITY_MIGRATION));
      setPhase('seed:assessment-defaults');
      await phaseStep(phase, () => require('../../server/database/postgres/secureshopAssessmentSeed')
        .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION));
      setPhase('seed:standalone-defaults');
      await phaseStep(phase, () => require('../../server/database/postgres/secureshopStandaloneSeed')
        .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION));
      setPhase('seed:commerce');
      const seedClient = await phaseStep(phase, () => pools.COMMERCE_MIGRATION.connect());
      try {
        await phaseStep('seed:commerce-begin', () => seedClient.query('BEGIN'));
        await phaseStep('seed:commerce-data', () => require('../../server/database/postgres/secureshopSeed')
          .seedSecureShop(seedClient));
        await phaseStep('seed:commerce-commit', () => seedClient.query('COMMIT'));
      } catch (error) {
        await phaseStep('seed:commerce-rollback', () => seedClient.query('ROLLBACK'))
          .catch(() => {});
        throw error;
      } finally { seedClient.release(); }

      const identity = pools.IDENTITY_RUNTIME;
      const agents = pools.AGENTS_RUNTIME;
      const review = pools.REVIEW_RUNTIME;
      const commerce = pools.COMMERCE_RUNTIME;
      const auth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const suffix = randomUUID().slice(0, 8);
      const password = 'disposable-route-availability';
      const ownerUsername = `route_owner_${suffix}`;
      const siblingUsername = `route_sibling_${suffix}`;
      setPhase('auth:owner-register');
      const ownerRegistration = await phaseStep(phase, () => auth.register({ username: ownerUsername,
        email: `${ownerUsername}@example.invalid`, password, role: 'merchant' }));
      setPhase('auth:sibling-register');
      const siblingRegistration = await phaseStep(phase, () => auth.register({ username: siblingUsername,
        email: `${siblingUsername}@example.invalid`, password, role: 'merchant' }));
      const audit = require('../../server/services/secureshopBoundAuditComposition')
        .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
          includeRunArtifacts: true });
      const reset = require('../../server/services/secureshopCleanupComposition')
        .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, leasePool, audit });
      assert.ok(reset.audit?.agents && reset.audit?.review,
        'prepared bound composition requires the shared audit bundle for ACL wiring');
      setPhase('composition:grading-bootstrap');
      const gradingBootstrap = await phaseStep(phase, () => require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
          progress: require('../../server/database/postgres/workshopProgressRepository')
            .createWorkshopProgressRepository(identity), resetComposition: reset,
          expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) }));
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository')
          .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
        reviewPool: review, launches: reset.launches });
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identity);
      const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
        .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
      const provider = {
        async chat() { throw new Error('route availability must not invoke a model'); },
        async finalResponse() { throw new Error('route availability must not invoke a model'); },
      };
      setPhase('composition:bound-review');
      composition = await phaseStep(phase, () => require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: reset,
          gradingBootstrap, scenes, modeAuthority, fixtures: [],
          requiredObjectives: ['ss_loop_observation'],
          jwtSecret: 'disposable-route-availability-secret-at-least-32-bytes',
          agentRuntime: { provider } }));
      setPhase('composition:persona-templates');
      await phaseStep(phase, () => composition.repositories.personas.ensureTemplates());
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });
      const standaloneMode = require('../../server/services/secureshopStandaloneMode')
        .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
      const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
        .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
          reviewPool: review, commercePool: commerce });

      // Reserve the canonical owner target before the UI session.  Sibling
      // sessions receive their own launch/capability and cannot inherit it.
      setPhase('target:bootstrap');
      const first = await phaseStep(phase, () => bootstrap(ownerRegistration.context));
      setPhase('target:resolve-capability');
      const firstScope = await phaseStep(phase, () => composition.launches.resolveCapability(first.bearer));
      setPhase('target:authenticate-persona');
      const firstActor = await phaseStep(phase, () => composition.personaAuth.authenticateBoundToken({
        scope: firstScope, token: first.persona.token }));
      setPhase('target:prepare');
      await phaseStep(phase, () => composition.catalog.prepareTarget({ scope: firstScope, persona: firstActor.user }));
      await phaseStep('auth:owner-logout', () => auth.logout(ownerRegistration.token));
      await phaseStep('auth:sibling-logout', () => auth.logout(siblingRegistration.token));

      const mounted = Object.freeze({ ...composition,
        standaloneAuth: Object.freeze({ service: auth, bootstrap, mode: standaloneMode }),
        publicCatalog,
        personaInbox: Object.freeze({ ready: true, router: express.Router() }),
        mcpTrust: Object.freeze({ ready: true, router: express.Router() }),
        ssrf: Object.freeze({ ready: true, router: express.Router() }),
      });
      setPhase('composition:bound-application');
      const bound = await phaseStep(phase, () => require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          authenticateToken: (_request, response) => response.sendStatus(401),
          audit: async () => {}, agentRuntime: {}, getComposition: async () => mounted }));

      const app = express();
      app.use(express.json());
      setPhase('server:listen');
      server = app.listen(0, '127.0.0.1');
      await phaseStep(phase, () => waitForServerListening(server));
      const origin = `http://127.0.0.1:${server.address().port}`;
      app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthRouter({ service: auth, bootstrap, mode: standaloneMode,
          allowedOrigins: [origin], secureCookies: false }));
      app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
        .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
      app.use('/api/secureshop', (request, response, next) => {
        if (request.headers['x-owasp-ai-goat-secureshop-launch']) {
          legacyFallbackHits++;
          return response.status(200).json({ legacy: true });
        }
        return next();
      });
      app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog')
        .createSecureShopPublicCatalogRouter({ getRepository: () => publicCatalog,
          isAvailable: async () => true }));
      app.use('/api', (_request, response) =>
        response.status(404).json({ error: 'Outside route availability qualification' }));
      app.use(express.static(build, { setHeaders: response =>
        response.set('Access-Control-Allow-Origin', '*') }));
      app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));

      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-secureshop-route-'));
      setPhase('browser-launch');
      browser = await phaseStep(phase, () => require('puppeteer').launch({ headless: true,
        userDataDir: profile, executablePath, timeout: BROWSER_STEP_TIMEOUT_MS,
        protocolTimeout: BROWSER_PROTOCOL_TIMEOUT_MS }));
      const openSession = async (label, username) => {
        setPhase(`${label}:new-page`);
        const context = await phaseStep(`${label}:browser-context`, () => browser.createBrowserContext());
        contexts.add(context);
        const page = await phaseStep(phase, () => context.newPage());
        page.setDefaultTimeout(BROWSER_STEP_TIMEOUT_MS);
        page.setDefaultNavigationTimeout(BROWSER_STEP_TIMEOUT_MS);
        setPhase(`${label}:viewport`);
        await phaseStep(phase, () => page.setViewport({ width: 1280, height: 900 }));
        setPhase(`${label}:request-listeners`);
        const readinessLifecycle = [];
        const readinessRecords = new WeakMap();
        page.on('request', request => {
          if (request.method() === 'GET'
            && new URL(request.url()).pathname === '/api/secureshop/merchant/listings/readiness') {
            const record = { method: request.method(), url: request.url(), startedAt: Date.now(),
              responseAt: null, status: null, finishedAt: null, failedAt: null, failureText: null };
            readinessLifecycle.push(record); readinessRecords.set(request, record);
            const headers = request.headers();
            if (headers.authorization && headers['x-owasp-ai-goat-secureshop-launch']) {
              page.__routeAuthority = Object.freeze({ authorization: headers.authorization,
                launch: headers['x-owasp-ai-goat-secureshop-launch'] });
            }
          }
        });
        page.on('response', response => {
          const record = readinessRecords.get(response.request());
          if (record) { record.responseAt = Date.now(); record.status = response.status(); }
        });
        page.on('requestfinished', request => {
          const record = readinessRecords.get(request);
          if (record) record.finishedAt = Date.now();
        });
        page.on('requestfailed', request => {
          const record = readinessRecords.get(request);
          if (record) { record.failedAt = Date.now(); record.failureText = request.failure()?.errorText || null; }
        });
        setPhase(`${label}:interception`);
        await phaseStep(phase, () => page.setRequestInterception(true));
        page.on('request', request => request.url().startsWith(`${origin}/`)
          ? request.continue() : request.abort());
        setPhase(`${label}:login`);
        const frame = await browserLogin(page, origin, username, password);
        setPhase(`${label}:merchant-navigation`);
        await phaseStep(phase, () => frame.waitForSelector(
          'a[href="/secureshop/merchant/listings"]', { timeout: 20000 }));
        const readinessResponse = page.waitForResponse(response => {
          const url = new URL(response.url());
          return response.request().method() === 'GET'
            && url.pathname === '/api/secureshop/merchant/listings/readiness';
        }, { timeout: 20000 });
        const navigation = await phaseStep(`${label}:listings-document`, () =>
          page.goto(`${origin}/secureshop/merchant/listings`, {
            waitUntil: 'domcontentloaded', timeout: BROWSER_STEP_TIMEOUT_MS,
          }));
        assert.ok([200, 304].includes(navigation.status()));
        setPhase(`${label}:listing-frame`);
        const listingsFrame = await phaseStep(`${label}:listing-frame`, () => stableFrame(page));
        let readiness;
        try {
          readiness = await readinessResponse;
        } catch (error) {
          await readinessResponse.catch(() => {});
          throw error;
        }
        assert.equal(readiness.status(), 503);
        setPhase(`${label}:readiness-render`);
        try {
          await phaseStep(`${label}:bulk-import-open`, async () => {
            await listingsFrame.waitForFunction(() => [...document.querySelectorAll('button')]
              .some(node => node.textContent.trim() === 'Bulk import'), { timeout: 20000 });
            const buttons = await listingsFrame.$$('button');
            try {
              for (const button of buttons) {
                const text = await button.evaluate(node => node.textContent.trim());
                if (text === 'Bulk import') { await button.click(); return; }
              }
            } finally { await Promise.all(buttons.map(button => button.dispose())); }
            throw new Error('Bulk import button was not actionable');
          });
          await phaseStep(`${label}:readiness-render`, () => listingsFrame.waitForFunction(() => [...document.querySelectorAll('[role="alert"]')]
            .some(node => node.textContent.includes('Listing actions could not be verified (HTTP 503).'))
            && [...document.querySelectorAll('[role="dialog"] button')]
              .some(node => node.textContent.trim() === 'Import' && node.disabled),
          { timeout: 20000 }));
        } catch (error) {
          let diagnostics;
          try {
            diagnostics = await phaseStep(`${label}:readiness-diagnostic`, () =>
              captureReadinessDiagnostics(page, listingsFrame, readinessLifecycle));
          } catch (diagnosticError) {
            diagnostics = { error: String(diagnosticError.message || diagnosticError).slice(0, 512),
              readinessRequests: readinessLifecycle.map(entry => ({ ...entry })) };
          }
          error.readinessDiagnostics = diagnostics;
          error.message = `${error.message}; readiness diagnostics ${JSON.stringify(diagnostics)}`;
          throw error;
        }
        assert.ok(page.__routeAuthority?.authorization && page.__routeAuthority?.launch,
          'rendered bound frame must supply authenticated launch metadata');
        const readinessBody = await phaseStep(`${label}:readiness-body`, () =>
          browserBoundRequest(page, page.__routeAuthority, 'GET',
            '/api/secureshop/merchant/listings/readiness'));
        assertUnavailableReadiness(readinessBody);
        return { context, page, frame: listingsFrame, authority: page.__routeAuthority };
      };

      const owner = await openSession('owner', ownerUsername);
      status.ownerRendered = true;
      const ownerWhoami = await browserBoundRequest(owner.page, owner.authority, 'GET',
        '/api/secureshop/v2/auth/whoami');
      assert.equal(ownerWhoami.status, 200);
      assert.equal(ownerWhoami.body.user.username, ownerUsername);
      status.ownerScopeStable = true;
      const unknown = await Promise.all([
        browserBoundRequest(owner.page, owner.authority, 'GET',
          '/api/secureshop/merchant/listings/not-registered'),
        browserBoundRequest(owner.page, owner.authority, 'POST',
          '/api/secureshop/merchant/listings/not-registered', {}),
      ]);
      for (const response of unknown) {
        assert.equal(response.status, 404);
        assert.deepEqual(response.body, { error: 'Bound SecureShop route not found' });
      }
      status.disabledListings503 = true;
      status.unknownRoute404 = true;
      await phaseStep('owner:close-page', () => owner.page.close());

      const sibling = await openSession('sibling', siblingUsername);
      status.siblingRendered = true;
      assertDistinctBrowserContexts([owner, sibling]);
      assert.notEqual(sibling.authority.launch, owner.authority.launch,
        'sibling must receive a distinct bound launch');
      const siblingWhoami = await browserBoundRequest(sibling.page, sibling.authority, 'GET',
        '/api/secureshop/v2/auth/whoami');
      assert.equal(siblingWhoami.status, 200);
      assert.equal(siblingWhoami.body.user.username, siblingUsername);
      status.siblingScopeStable = true;
      await phaseStep('sibling:close-page', () => sibling.page.close());
      assert.equal(legacyFallbackHits, 0,
        'disabled and unknown bound requests must not fall through to legacy mounts');
      status.legacyFallbackHits = legacyFallbackHits;
      status.passed = true;
    } catch (error) {
      failure = error;
    } finally {
      let browserCloseSucceeded = !browser;
      for (const context of contexts) {
        try { await boundedCleanup('browser context close', () => context.close()); }
        catch (error) { cleanupErrors.push(error); }
      }
      contexts.clear();
      try {
        if (browser) {
          await boundedCleanup('browser.close', () => browser.close());
          browserCloseSucceeded = true;
        }
      } catch (error) { cleanupErrors.push(error); }
      try {
        status.browserCloseVerified = browserCloseSucceeded
          && await boundedCleanup('browser exit', () => waitForBrowserExit(browser));
      } catch (error) { cleanupErrors.push(error); }
      if (status.browserCloseVerified || !browser) {
        try {
          await boundedCleanup('profile removal', () => profile
            && fs.rm(profile, { recursive: true, force: true }));
          status.profileRemoved = true;
        } catch (error) { cleanupErrors.push(error); }
      } else {
        status.profilePreserved = true;
        cleanupErrors.push(Object.assign(new Error(
          'Browser termination was not verified; preserving owned profile for outer cleanup'),
        { code: 'BROWSER_TERMINATION_UNVERIFIED' }));
      }
      for (const close of [
        () => closeServer(server),
        () => composition?.closeBrowserAssessment?.(),
        () => leasePool.end(),
        ...Object.values(pools).map(pool => () => pool.end()),
      ]) {
        try { await boundedCleanup('resource', close); } catch (error) { cleanupErrors.push(error); }
      }
      persistPhaseCheckpoint('cleanup', 'after', cleanupErrors[0]);
      await phaseCheckpointWrite;
      status.cleanupComplete = cleanupErrors.length === 0;
      try {
        await fs.writeFile(receiptPath, JSON.stringify({ ...status,
          ...(failure ? { failure: { name: failure.name, code: failure.code || null,
            message: String(failure.message || '').slice(0, 512),
            stack: String(failure.stack || '').slice(0, 2048), phase,
            ...(failure.readinessDiagnostics ? { readinessDiagnostics: failure.readinessDiagnostics } : {}) } } : {}) }, null, 2),
        { flag: 'wx', mode: 0o600 });
      } catch (error) { cleanupErrors.push(error); }
    }
    if (cleanupErrors.length) throw new AggregateError(
      failure ? [failure, ...cleanupErrors] : cleanupErrors,
      'Standalone route availability cleanup or evidence write failed');
    if (failure) throw failure;
    assert.equal(status.passed, true);
  });
