'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const KEYS = ['PG_XSS_EMAIL_ROUTE_IDENTITY_RUNTIME_URL', 'PG_XSS_EMAIL_ROUTE_IDENTITY_MIGRATION_URL',
  'PG_XSS_EMAIL_ROUTE_XSS_RUNTIME_URL', 'PG_XSS_EMAIL_ROUTE_XSS_MIGRATION_URL',
  'PG_XSS_EMAIL_ROUTE_CTF_RUNTIME_URL', 'PG_XSS_EMAIL_ROUTE_CTF_MIGRATION_URL'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.XSS_EMAIL_ROUTE_UI === 'yes'
  && KEYS.every(key => process.env[key]) && process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE;

function verifyInputs() {
  const current = require('./xssCurrentCheckoutAdmission').verifyCurrentCheckout({ keys: KEYS, cohort: 'email' });
  if (current) return current;
  const workspace = fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);
  assert.equal(fs.realpathSync(process.cwd()), workspace);
  assert.equal(path.basename(workspace), 'source');
  assert.match(path.basename(path.dirname(workspace)), /^owasp-ai-goat-xss-email-route-/);
  assert.ok(fs.existsSync(path.join(workspace, 'client', 'package.json')));
  assert.ok(fs.existsSync(path.join(workspace, 'client', 'node_modules')));
  for (const key of KEYS) {
    const url = new URL(process.env[key]);
    assert.equal(url.hostname, '127.0.0.1');
    assert.match(url.pathname, /^\/owasp_ai_goat_test_xss_email_route_(?:identity|xss|ctf)$/);
  }
  return workspace;
}

async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = () => child.exitCode !== null || child.signalCode !== null ? Promise.resolve()
    : new Promise(resolve => child.once('exit', resolve));
  let terminal = exited(); child.kill('SIGTERM');
  if ((await Promise.race([terminal.then(() => true), new Promise(resolve => setTimeout(() => resolve(false), 5000))]))) return;
  terminal = exited(); child.kill('SIGKILL');
  if (!(await Promise.race([terminal.then(() => true), new Promise(resolve => setTimeout(() => resolve(false), 5000))]))) {
    throw new Error('Vite did not exit after SIGKILL');
  }
}

async function waitForVite(url, child, output) {
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Vite exited early\n${output()}`);
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1500) });
      if (response.ok && (await response.text()).includes('<div id="root">')) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  throw new Error(`Vite readiness timed out\n${output()}`);
}

async function waitForOwnedMail(recipient) {
  const base = new URL(process.env.MAILPIT_API_URL);
  const query = new URLSearchParams({ query: `to:"${recipient}"`, limit: '20' });
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const response = await fetch(new URL(`api/v1/search?${query}`, base));
    const body = await response.json();
    if (response.ok && Array.isArray(body.messages) && body.messages.some(message =>
      Array.isArray(message.To) && message.To.length === 1
      && (message.To[0]?.Address ?? message.To[0]?.Email) === recipient)) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.fail('Owned message did not become visible before the single rendered retrieval request');
}

test('rendered XSS email tab performs real local-mail objectives and reset through mounted native routes', {
  skip: !enabled, timeout: process.env.XSS_EMAIL_ROUTE_LIVE === '1' ? 300000 : 180000,
}, async t => {
  const workspace = verifyInputs();
  const live = process.env.XSS_EMAIL_ROUTE_LIVE === '1';
  const Module = require('node:module'); const originalLoad = Module._load;
  Module._load = function guarded(request, ...args) {
    if (request === 'sqlite3' || request === 'better-sqlite3' || /(?:^|\/)authDb$/.test(request)) {
      throw new Error(`Legacy database import forbidden: ${request}`);
    }
    return originalLoad.call(this, request, ...args);
  };
  const { Pool } = require('pg');
  const pools = KEYS.map(key => new Pool({ connectionString: process.env[key], max: 6 }));
  const [identityRuntime, identityMigration, xssRuntime, xssMigration, ctfRuntime, ctfMigration] = pools;
  let backend; let vite; let browser; let page; let xssRoutes; let authRoutes; let sessionManager;
  let restoreAi; let restoreGrader; let viteOutput = ''; let runtimeRoot;
  const pageErrors = []; const unexpectedResponses = []; const blockedExternalRequests = []; const sendBodies = [];
  try {
    assert.ok(process.env.OWASP_AI_GOAT_XSS_RENDERED_RUNTIME_ROOT);
    runtimeRoot = fs.realpathSync(process.env.OWASP_AI_GOAT_XSS_RENDERED_RUNTIME_ROOT);
    for (const name of ['logs', 'artifacts', 'vite-cache']) {
      assert.equal(fs.realpathSync(path.join(runtimeRoot, name)), path.join(runtimeRoot, name));
    }
    assert.ok(!runtimeRoot.startsWith(`${workspace}${path.sep}`));
    Object.assign(process.env, {
      PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres', XSS_MAIL_PROVIDER: 'mailpit',
      IDENTITY_DATABASE_URL: process.env.PG_XSS_EMAIL_ROUTE_IDENTITY_RUNTIME_URL,
      XSS_WORKSHOP_DATABASE_URL: process.env.PG_XSS_EMAIL_ROUTE_XSS_RUNTIME_URL,
      XSS_WORKSHOP_MIGRATION_DATABASE_URL: process.env.PG_XSS_EMAIL_ROUTE_XSS_MIGRATION_URL,
      CTF_DATABASE_URL: process.env.PG_XSS_EMAIL_ROUTE_CTF_RUNTIME_URL,
      CTF_MIGRATION_DATABASE_URL: process.env.PG_XSS_EMAIL_ROUTE_CTF_MIGRATION_URL,
      AI_PROVIDER: live ? 'ollama' : 'mock', JUDGE_PROVIDER: live ? 'ollama' : 'mock',
      JWT_SECRET: 'owned-xss-email-route-fixture-secret-at-least-32-bytes', EVENT_GATE_ENABLED: 'false',
    });
    const identityApi = require('../../server/database/postgres/identityRepository');
    await identityApi.initializeIdentityRepository(identityRuntime, identityMigration);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
    await require('../../server/database/postgres/xssWorkshopDb').createXssWorkshopDb(xssRuntime)
      .initializeXssWorkshopDb(xssMigration);
    await require('../../server/database/postgres/ctfDb').createCtfDb(ctfRuntime).initialize(ctfMigration);
    const identity = identityApi.createIdentityRepository(identityRuntime);
    const password = 'RenderedXssEmail@123';
    const user = await identity.createUser({ username: 'xss-email-rendered-owner', email: 'xss-email-rendered@fixture.invalid',
      passwordHash: await require('bcryptjs').hash(password, 4) });

    if (!live) {
      const ai = require('../../server/services/multiProviderAIService');
      const originalChat = ai.chatWithMessages.bind(ai);
      ai.chatWithMessages = async messages => {
        const original = messages.find(message => message.role === 'user'
          && !String(message.content).startsWith('Tool observation'))?.content || '';
        if (messages.some(message => String(message.content).startsWith('Tool observation'))) {
          return { response: 'The requested workshop mailbox action is complete.', provider: 'fixture', model: 'deterministic-xss-email' };
        }
        return /show|list|check/i.test(original)
          ? { response: '{"tool":"listEmails","args":{}}', provider: 'fixture', model: 'deterministic-xss-email' }
          : { response: '{"tool":"getEmail","args":{}}', provider: 'fixture', model: 'deterministic-xss-email' };
      };
      restoreAi = () => { ai.chatWithMessages = originalChat; };
      const progress = require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityRuntime);
      const { prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');
      const judge = async packet => ({ family: packet.rubric.family, scenario: packet.rubric.scenario,
        objectiveId: packet.rubric.objectiveId, rubricVersion: packet.rubric.version,
        evidenceDigest: prepareJudgeInput(packet).evidenceDigest, runId: packet.execution.runId, mode: packet.rubric.mode,
        verdict: 'pass', criteria: packet.rubric.criteria.map(item => ({ id: item.id, satisfied: true,
          evidenceRefs: ['server_receipt'] })), explanation: 'Deterministic rendered UI fixture accepted native evidence.',
        provider: 'fixture', model: 'deterministic-xss-email-judge', usage: null });
      const completionService = require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({
        receipts: require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identityRuntime),
        progress, judge,
      });
      const graderModule = require('../../server/services/xssObjectiveGrader');
      const originalFactory = graderModule.createXssObjectiveGrader;
      const grader = originalFactory({ postgres: true, completionService });
      graderModule.createXssObjectiveGrader = () => grader;
      restoreGrader = () => { graderModule.createXssObjectiveGrader = originalFactory; };
    }

    const adapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    sessionManager = require('../../server/middleware/postgresSessionManager').createPostgresSessionManager(adapter);
    authRoutes = require('../../server/routes/auth'); xssRoutes = require('../../server/routes/xssWorkshop');
    restoreGrader?.(); restoreGrader = null;
    const express = require('express'); const app = express();
    app.use(express.json());
    app.use(require('express-session')({ secret: 'vulnerable-secret-key', resave: false, saveUninitialized: true,
      cookie: { secure: false, httpOnly: false, sameSite: 'lax', maxAge: 14400000 } }));
    app.use(sessionManager.middleware());
    const authenticateToken = require('../../server/middleware/adminAuth').authenticateToken;
    app.use('/api/auth', authRoutes);
    app.use('/api/ctf', require('../../server/routes/ctf').router);
    app.use('/api/workshop/config', require('../../server/routes/workshopConfig').createWorkshopConfigRouter());
    app.use('/api/changes', require('../../server/routes/changeRevisions').createChangeRevisionsRouter({
      store: require('../../server/services/changeRevisionService'), authenticateToken,
    }));
    app.use('/api/workshop', require('../../server/routes/workshop'));
    app.use('/api/workshop/xss', authenticateToken, xssRoutes);
    app.use('/api/solutions', require('../../server/routes/solutions'));
    app.use('/api/hints', require('../../server/routes/hints'));
    backend = await new Promise(resolve => { const server = app.listen(0, '127.0.0.1', () => resolve(server)); });

    const backendBase = `http://127.0.0.1:${backend.address().port}`;
    const vitePort = await availablePort(); const pageBase = `http://127.0.0.1:${vitePort}`;
    vite = spawn(process.execPath, [path.join(workspace, 'tests/postgres/xssRenderedViteServer.js'), '--workspace', workspace,
      '--port', String(vitePort), '--backend-port', String(backend.address().port), '--runtime-root', runtimeRoot],
    { cwd: workspace, env: { PATH: process.env.PATH, HOME: process.env.HOME,
      TMPDIR: process.env.TMPDIR || os.tmpdir(), NODE_ENV: 'test', BROWSER: 'none' },
      stdio: ['ignore', 'pipe', 'pipe'] });
    for (const stream of [vite.stdout, vite.stderr]) stream.on('data', chunk => { viteOutput = (viteOutput + chunk).slice(-100000); });
    await waitForVite(`${pageBase}/workshop-login`, vite, () => viteOutput);
    browser = await require('puppeteer').launch({ headless: true }); page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 1000 }); page.setDefaultTimeout(live ? 180000 : 30000);
    await page.setRequestInterception(true);
    page.on('request', request => {
      const url = request.url();
      if (url.startsWith(`${pageBase}/`) || url.startsWith(`${backendBase}/`) || /^(?:data|blob|about):/.test(url)) request.continue();
      else { blockedExternalRequests.push(url); request.abort('blockedbyclient'); }
      if (url.includes('/api/workshop/xss/emails/send-attack') && request.method() === 'POST') sendBodies.push(request.postData());
    });
    page.on('pageerror', error => pageErrors.push(error.message));
    page.on('response', response => {
      if (response.status() >= 400 && !response.url().includes('/api/workshop/xss/llm-status')) {
        unexpectedResponses.push({ status: response.status(), url: response.url() });
      }
    });

    await page.goto(`${pageBase}/workshop-login`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[placeholder="Enter your username"]');
    await page.type('input[placeholder="Enter your username"]', user.username);
    await page.type('input[placeholder="Enter your password"]', password);
    await Promise.all([page.waitForFunction(() => !location.pathname.includes('login')), page.click('button[type="submit"]')]);
    await page.goto(`${pageBase}/vulnerabilities/xss`, { waitUntil: 'domcontentloaded' });
    const expectedInbox = `xss-${user.id}@owasp-ai-goat.invalid`;
    await page.waitForSelector('[data-scenario-tab="email"]', { timeout: 15000 });
    // VisibilityProtectedRoute can replace its child once while reconciling the
    // first config snapshot. Click only after that initial render settles.
    await new Promise(resolve => setTimeout(resolve, 1000));
    // Five scenario tabs can overflow horizontally. Use an element click so
    // Puppeteer scrolls the actual tab into view before dispatching input.
    await page.click('[data-scenario-tab="email"]');
    await page.waitForSelector('[data-scenario-tab="email"][aria-selected="true"]');
    await page.waitForFunction(expected => document.querySelector('input[type="email"]')?.value === expected,
      { timeout: 15000 }, expectedInbox);
    t.diagnostic('Rendered XSS email tab selected with server-owned inbox.');

    const chat = async message => {
      const responsePromise = page.waitForResponse(response => response.url().includes('/api/workshop/xss/chat')
        && response.request().method() === 'POST');
      await page.$eval('textarea[placeholder^="Message the XSS assistant"]', (input, value) => {
        const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
        setter.call(input, value); input.dispatchEvent(new Event('input', { bubbles: true }));
      }, message);
      await page.$eval('textarea[placeholder^="Message the XSS assistant"]', input => input.closest('form').requestSubmit());
      const response = await responsePromise; const body = await response.json();
      assert.equal(response.status(), 200, JSON.stringify(body)); return body;
    };
    assert.equal((await chat('Show me my workshop emails')).completedObjectiveId, 'xss_e1');
    t.diagnostic('Rendered e1 completed.');
    const payload = '<img src=x onerror="globalThis.xssEmailUiEffect=733">';
    await page.evaluate(value => {
      const select = [...document.querySelectorAll('select')].find(item =>
        [...item.options].some(option => option.textContent === 'Custom Payload'));
      const option = [...select.options].find(item => item.textContent === 'Custom Payload');
      select.value = option.value; select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await page.waitForSelector('textarea[placeholder="<img src=x onerror=alert(1)>"]');
    await page.type('textarea[placeholder="<img src=x onerror=alert(1)>"]', payload);
    const sendResponse = page.waitForResponse(response => response.url().includes('/api/workshop/xss/emails/send-attack')
      && response.request().method() === 'POST');
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Send Email').click());
    const sent = await sendResponse; const sentBody = await sent.json();
    assert.equal(sent.status(), 200, JSON.stringify(sentBody)); assert.equal(sentBody.completedObjectiveId, 'xss_e2');
    t.diagnostic('Rendered e2 completed through SMTP.');
    assert.equal(sendBodies.length, 1); assert.deepEqual(JSON.parse(sendBodies[0]), {
      fromEmail: `xss-${user.id}@owasp-ai-goat.invalid`, payload,
    });
    await waitForOwnedMail(`xss-${user.id}@owasp-ai-goat.invalid`);
    assert.equal((await chat('Summarize my latest exercise attack email')).completedObjectiveId, 'xss_e3');
    t.diagnostic('Rendered e3 completed through retrieval and browser qualification.');
    await page.waitForFunction(() => document.body.innerText.includes('XSS Executed!')
      && globalThis.xssEmailUiEffect === 733
      && [...document.querySelectorAll('.status-badge')].filter(item => item.textContent === 'DONE').length === 3);

    const artifacts = path.join(runtimeRoot, 'artifacts'); await fsp.mkdir(artifacts, { recursive: true });
    const before = path.join(artifacts, 'xss-email-rendered-before-reset.png');
    await page.screenshot({ path: before, fullPage: true });
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND objective_id LIKE 'xss_e%'`, [user.id])).rows[0].n, 3);
    assert.equal((await xssRuntime.query(`SELECT count(*)::int n FROM xss.progress
      WHERE user_key=$1 AND objective_id LIKE 'xss_e%'`, [String(user.id)])).rows[0].n, 3);
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND objective_id LIKE 'xss_e%' AND verdict='pass'`,
    [user.id])).rows[0].n, 3);
    const judgments = (await identityRuntime.query(`SELECT j.objective_id,j.run_id,j.result_json,p.judge_version
      FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
      WHERE j.user_id=$1 AND j.workshop_key='xss_workshop' AND j.objective_id LIKE 'xss_e%'`, [user.id])).rows;
    assert.equal(judgments.length, 3);
    assert.ok(judgments.every(row => row.judge_version === require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION));
    if (live) {
      assert.ok(judgments.every(row => row.result_json?.provider === 'ollama'
        && row.result_json?.model === 'llama3.1:8b'), JSON.stringify(judgments));
      for (const [objectiveId, tool] of [['xss_e1', 'listEmails'], ['xss_e3', 'getEmail']]) {
        const judgment = judgments.find(row => row.objective_id === objectiveId);
        const events = (await identityRuntime.query(`SELECT node,event_type,metadata FROM graph_runtime.events
          WHERE run_id=$1 AND owner_key=$2 ORDER BY sequence`,
        [judgment.run_id, JSON.stringify(['XSS', String(user.id)])])).rows;
        assert.ok(events.some(event => event.node === 'decide' && event.event_type === 'decision'
          && event.metadata?.decisionSource === 'model' && event.metadata?.provider === 'ollama'
          && event.metadata?.model === 'llama3.1:8b' && event.metadata?.tool === tool),
        `${objectiveId} must retain its actual 8B ${tool} decision`);
      }
    }

    const resetResponse = page.waitForResponse(response => response.url().includes('/api/workshop/xss/progress/reset-tab')
      && response.request().method() === 'POST');
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.includes('Reset Above Objectives')).click());
    await page.waitForSelector('[role="alertdialog"]', { visible: true });
    await page.evaluate(() => [...document.querySelector('[role="alertdialog"]').querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Confirm reset' && !button.disabled).click());
    assert.equal((await resetResponse).status(), 200);
    await page.waitForFunction(() => !document.body.innerText.includes('XSS Executed!')
      && ![...document.querySelectorAll('.status-badge')].some(item => item.textContent === 'DONE'));
    await page.waitForFunction(() => [...document.querySelectorAll('button')]
      .some(button => button.textContent.trim() === 'Send Email' && !button.disabled));
    const after = path.join(artifacts, 'xss-email-rendered-after-reset.png');
    await page.screenshot({ path: after, fullPage: true });
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND objective_id LIKE 'xss_e%'`, [user.id])).rows[0].n, 0);
    assert.equal((await xssRuntime.query(`SELECT count(*)::int n FROM xss.progress
      WHERE user_key=$1 AND objective_id LIKE 'xss_e%'`, [String(user.id)])).rows[0].n, 0);
    assert.equal(sendBodies.length, 1, 'rendered reset never resends the attack email');
    assert.deepEqual(pageErrors, []); assert.deepEqual(unexpectedResponses, []);
    assert.deepEqual(blockedExternalRequests.filter(url => {
      try { return !['fonts.googleapis.com', 'fonts.gstatic.com'].includes(new URL(url).hostname); } catch { return true; }
    }), []);
    t.diagnostic(JSON.stringify({ mode: live ? 'live-ollama' : 'deterministic', screenshots: [before, after], blockedExternalRequests }));
  } catch (error) {
    if (page) {
      const artifacts = path.join(runtimeRoot, 'artifacts'); await fsp.mkdir(artifacts, { recursive: true }).catch(() => {});
      await fsp.writeFile(path.join(artifacts, 'xss-email-rendered-failure.json'), JSON.stringify({
        error: { name: error.name, message: error.message, stack: error.stack }, pageErrors, unexpectedResponses,
        blockedExternalRequests, sendBodies, viteOutput,
        dom: await page.evaluate(() => ({ url: location.href, text: document.body.innerText,
          scenarioTabs: [...document.querySelectorAll('[data-scenario-tab]')].map(item => item.outerHTML),
          emailInput: document.querySelector('input[type="email"]')?.outerHTML || null,
        })).catch(() => null),
      }, null, 2)).catch(() => {});
      await page.screenshot({ path: path.join(artifacts, 'xss-email-rendered-failure.png'), fullPage: true }).catch(() => {});
    }
    throw error;
  } finally {
    Module._load = originalLoad; const failures = [];
    const capture = async operation => { try { await operation(); } catch (error) { failures.push(error); } };
    if (restoreAi) restoreAi(); if (restoreGrader) restoreGrader();
    if (browser) await capture(() => browser.close()); if (vite) await capture(() => stopChild(vite));
    if (backend) await capture(() => new Promise((resolve, reject) => backend.close(error => error ? reject(error) : resolve())));
    if (xssRoutes?.closeBrowser) await capture(() => xssRoutes.closeBrowser());
    authRoutes?.close?.(); sessionManager?.stopCleanupTask?.();
    await capture(() => require('../../server/services/xssMailProvider').close());
    await capture(() => require('../../server/database/postgres').closePostgresPools());
    const closed = await Promise.allSettled(pools.map(pool => pool.end()));
    failures.push(...closed.filter(result => result.status === 'rejected').map(result => result.reason));
    if (failures.length) throw new AggregateError(failures, 'Rendered XSS email UI cleanup failed');
  }
});
