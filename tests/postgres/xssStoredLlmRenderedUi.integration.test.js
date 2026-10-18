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
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.XSS_STORED_LLM_ROUTE_UI === 'yes'
  && KEYS.every(key => process.env[key]) && process.env.DVAIA_ISOLATED_TEST_WORKSPACE;

function verifyInputs() {
  const current = require('./xssCurrentCheckoutAdmission').verifyCurrentCheckout({ keys: KEYS, cohort: 'stored_llm' });
  if (current) return current;
  const workspace = fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE);
  assert.equal(fs.realpathSync(process.cwd()), workspace);
  assert.equal(path.basename(workspace), 'source');
  assert.match(path.basename(path.dirname(workspace)), /^dvaia-xss-email-route-/);
  assert.ok(fs.existsSync(path.join(workspace, 'client', 'package.json')));
  assert.ok(fs.existsSync(path.join(workspace, 'client', 'node_modules')));
  for (const key of KEYS) {
    const url = new URL(process.env[key]);
    assert.equal(url.hostname, '127.0.0.1');
    assert.match(url.pathname, /^\/dvaia_test_xss_email_route_(?:identity|xss|ctf)$/);
  }
  return workspace;
}

function verifyRenderedRuntimeRoot(workspace) {
  const value = process.env.DVAIA_XSS_RENDERED_RUNTIME_ROOT;
  assert.ok(value && path.isAbsolute(value), 'owned rendered runtime root is required');
  const root = fs.realpathSync(value);
  assert.notEqual(root, workspace);
  assert.ok(!root.startsWith(`${workspace}${path.sep}`), 'rendered artifacts must not be written in source workspace');
  return root;
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

test('rendered stored-LLM XSS proves generation, model-origin save, provenance rejection, execution, and reset', {
  skip: !enabled, timeout: process.env.XSS_EMAIL_ROUTE_LIVE === '1' ? 300000 : 180000,
}, async t => {
  const workspace = verifyInputs();
  const runtimeRoot = verifyRenderedRuntimeRoot(workspace);
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
  let restoreAi; let restoreGrader; let viteOutput = '';
  const pageErrors = []; const unexpectedResponses = []; const blockedExternalRequests = []; let blockedExternalRequestCount = 0; const sendBodies = [];
  const dialogs = []; const chatResponses = [];
  let closing = false;
  try {
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
    const user = await identity.createUser({ username: 'xss-stored-llm-rendered-owner', email: 'xss-stored-llm-rendered@fixture.invalid',
      passwordHash: await require('bcryptjs').hash(password, 4) });
    const sibling = await identity.createUser({ username: 'xss-stored-llm-rendered-sibling', email: 'xss-stored-llm-sibling@fixture.invalid',
      passwordHash: await require('bcryptjs').hash(password, 4) });

    if (!live) {
      const ai = require('../../server/services/multiProviderAIService');
      const originalChat = ai.chatWithMessages.bind(ai);
      ai.chatWithMessages = async messages => {
        const system = messages.find(message => message.role === 'system')?.content || '';
        const original = messages.find(message => message.role === 'user' && !message.content.startsWith('Tool observation'))?.content || '';
        const observation = [...messages].reverse().find(message => message.role === 'user'
          && message.content.startsWith('Tool observation'))?.content || '';
        const generated = '<div>Generated QA card</div><img src=x onerror="alert(628)">';
        let response;
        if (observation.startsWith('Tool observation for getProfile:')) {
          const serialized = observation.split('\n')[1];
          const profile = JSON.parse(serialized).profile;
          response = `<div>${profile.name}</div>${profile.bio}<a href="${profile.website}">Website</a>`;
        } else if (observation.startsWith('Tool observation for updateProfile:')) {
          response = 'The exact profile value was saved.';
        } else if (/do not (?:save|store|update|apply|set|put|persist|commit)/i.test(original)) {
          response = generated;
        } else if (/show|view|retrieve/i.test(original)) {
          response = '{"tool":"getProfile"}';
        } else if (/save|store|update|apply|set|put|persist|commit/i.test(original)) {
          const supplied = require('../../server/services/xssProfileWriteContract').extractStoredUserArtifact(original);
          response = JSON.stringify({ tool: 'updateProfile', args: { field: 'bio',
            value: /profile management assistant/i.test(system) && supplied ? supplied.value : generated } });
        } else {
          response = generated;
        }
        return { response, provider: 'test-provider', model: 'deterministic-xss-stored-llm' };
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
      const grader = originalFactory({ postgres: true, completionService,
        readProfileOrigin: input => require('../../server/database/xssWorkshopDb').readCurrentProfileField(input) });
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
      '--port', String(vitePort), '--backend-port', String(backend.address().port), '--runtime-root', runtimeRoot], { cwd: workspace,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR || os.tmpdir(),
        NODE_ENV: 'test', BROWSER: 'none' },
      stdio: ['ignore', 'pipe', 'pipe'] });
    for (const stream of [vite.stdout, vite.stderr]) stream.on('data', chunk => { viteOutput = (viteOutput + chunk).slice(-100000); });
    await waitForVite(`${pageBase}/workshop-login`, vite, () => viteOutput);
    browser = await require('puppeteer').launch({ headless: true });
    await fsp.writeFile(path.join(runtimeRoot, 'rendered-browser-process.json'), JSON.stringify({
      pid: browser.process().pid, workerPid: process.pid, uid: process.getuid(),
    }), { flag: 'wx', mode: 0o600 });
    page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 1000 }); page.setDefaultTimeout(live ? 180000 : 30000);
    await page.setRequestInterception(true);
    page.on('request', request => {
      const url = request.url();
      if (url.startsWith(`${pageBase}/`) || url.startsWith(`${backendBase}/`) || /^(?:data|blob|about):/.test(url)) request.continue().catch(error => { if (!closing) recordPageError(`request-continue:${error.message}`); });
      else { let expectedFont = false; try { expectedFont = ['fonts.googleapis.com', 'fonts.gstatic.com'].includes(new URL(url).hostname); } catch {} if (!expectedFont) recordPageError('Unexpected external request: ' + url); blockedExternalRequestCount += 1; if (blockedExternalRequests.length < 100 && !blockedExternalRequests.includes(url)) blockedExternalRequests.push(url); request.abort('blockedbyclient').catch(error => { if (!closing) recordPageError(`request-abort:${error.message}`); }); }
      if (url.includes('/api/workshop/xss/emails/send-attack') && request.method() === 'POST') sendBodies.push(request.postData());
    });
    const recordPageError = message => { if (pageErrors.length < 100) pageErrors.push(String(message).slice(0, 2000)); };
    page.on('pageerror', error => recordPageError(error.message));
    page.on('dialog', async dialog => { if (dialogs.length < 100) dialogs.push(dialog.message().slice(0, 2000)); try { await dialog.dismiss(); } catch (error) { if (!closing) recordPageError(`dialog-dismiss:${error.message}`); } });
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
    await page.waitForSelector('[data-scenario-tab="stored_llm"]', { timeout: 15000 });
    await page.waitForFunction(() => document.body.innerText.includes('AI ready'));
    await new Promise(resolve => setTimeout(resolve, 1000));

    const selectTab = async tab => {
      await page.waitForFunction(selected => {
        const item = document.querySelector(`[data-scenario-tab="${selected}"]`);
        if (!item) return false; item.click(); return true;
      }, {}, tab);
      await page.waitForFunction(selected => document.querySelector(`[data-scenario-tab="${selected}"]`)
        ?.getAttribute('aria-selected') === 'true', {}, tab);
    };
    await selectTab('stored_llm');
    const chat = async message => {
      const responsePromise = page.waitForResponse(response => response.url().includes('/api/workshop/xss/chat')
        && response.request().method() === 'POST');
      await page.$eval('textarea[placeholder^="Message the XSS assistant"]', (input, value) => {
        const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
        setter.call(input, value); input.dispatchEvent(new Event('input', { bubbles: true }));
        input.closest('form').requestSubmit();
      }, message);
      const response = await responsePromise; const body = await response.json();
      chatResponses.push({ message, status: response.status(), body });
      assert.equal(response.status(), 200, JSON.stringify(body)); return body;
    };
    const profile = async () => (await xssRuntime.query('SELECT name,bio,website FROM xss.profiles WHERE user_key=$1',
      [String(user.id)])).rows[0] || null;
    const defaults = { name: 'Security Student', bio: 'Learning about web security.', website: 'https://example.com' };
    const assertNoCreditVerdict = judgment => {
      assert.ok(['fail', 'inconclusive'].includes(judgment?.verdict), 'Negative evidence requires a genuine non-passing Judge verdict');
      assert.equal(judgment.errorCode, null, 'Provider/schema failures do not qualify Judge participation');
      return judgment.verdict;
    };

    const runGeneration = async () => {
      const before = await profile();
      const g1 = await chat('Generate an event-handler HTML test value for my bio, but do not save it.');
      assert.equal(g1.completedObjectiveId, 'xss_g1');
      assert.match(g1.response, /\bon(?:error|load|click|mouseover|focus|input|toggle)\s*=|javascript\s*:/i);
      assert.deepEqual(await profile(), before, 'g1 generation must not persist profile content');
      const g2 = await chat('Generate a new event-handler HTML test value and save it to my bio.');
      if (g2.completedObjectiveId !== 'xss_g2') {
        const currentOrigin = await require('../../server/database/xssWorkshopDb').readCurrentProfileField({
          userKey: String(user.id), platformUserId: user.id, field: 'bio',
        });
        const latestPacket = (await identityRuntime.query(`SELECT p.packet FROM workshop_platform.grade_packets p
          JOIN workshop_platform.objective_judgments j USING(user_id,evaluation_id)
          WHERE p.user_id=$1 AND j.objective_id='xss_g2' ORDER BY j.evaluated_at DESC LIMIT 1`, [user.id])).rows[0]?.packet;
        assert.equal(g2.completedObjectiveId, 'xss_g2', JSON.stringify({ g2, currentOrigin, latestPacket }));
      }
      const stored = await profile();
      assert.match(stored.bio, /\bon(?:error|load|click|mouseover|focus|input|toggle)\s*=|javascript\s*:/i);
      return { g1, g2, storedValue: stored.bio };
    };

    const first = await runGeneration();
    const originBeforeCopy = await require('../../server/database/xssWorkshopDb').readCurrentProfileField({
      userKey: String(user.id), platformUserId: user.id, field: 'bio',
    });
    const copiedByModel = await chat(`Save this exact value as my bio: ${first.storedValue}`);
    assert.ok(copiedByModel.objectiveCandidate === null || copiedByModel.objectiveCandidate === 'xss_g3',
      `a copied stored-LLM write may be observed as g3, but cannot earn another objective: ${JSON.stringify(copiedByModel)}`);
    assert.equal(copiedByModel.completedObjectiveId, null);
    if (copiedByModel.objectiveCandidate === null) {
      assert.deepEqual(copiedByModel.judgments, []);
    } else {
      assert.equal(copiedByModel.judgments.length, 1);
      assertNoCreditVerdict(copiedByModel.judgments[0]);
    }
    assert.equal((await profile()).bio, first.storedValue,
      'the intentionally unsafe stored-LLM copy must preserve the requested bytes');
    const copiedOrigin = await require('../../server/database/xssWorkshopDb').readCurrentProfileField({
      userKey: String(user.id), platformUserId: user.id, field: 'bio',
    });
    const copyHadNoEffect = live && copiedOrigin.origin && originBeforeCopy.origin
      && JSON.stringify(copiedOrigin.origin) === JSON.stringify(originBeforeCopy.origin)
      && copiedOrigin.value === first.storedValue;
    if (copyHadNoEffect) {
      assert.deepEqual(copiedOrigin, originBeforeCopy, 'No-action copy must preserve the complete field receipt');
      t.diagnostic('Live model declined the copied stored-LLM write; original model-origin receipt and bytes remained unchanged.');
    } else {
      assert.equal(copiedOrigin.origin, null,
        'a value copied from the learner request must clear model-generation origin when the model selected the write');
    }
    let rejectedModelCopy = null;
    if (!copyHadNoEffect) {
      rejectedModelCopy = copiedByModel.objectiveCandidate === 'xss_g3'
        ? copiedByModel
        : await chat('Show me my current profile again.');
      assert.equal(rejectedModelCopy.objectiveCandidate, 'xss_g3');
      assert.equal(rejectedModelCopy.completedObjectiveId, null);
      assertNoCreditVerdict(rejectedModelCopy.judgments[0]);
    }

    const copyJudgmentOccurred = copiedByModel.objectiveCandidate === 'xss_g3' || rejectedModelCopy !== null;

    await selectTab('stored_user');
    const manual = await chat(`Save this exact value as my bio: ${first.storedValue}`);
    assert.equal((await profile()).bio, first.storedValue, 'manual identical-byte rewrite must persist the same bytes');
    assert.notEqual(manual.completedObjectiveId, 'xss_g3');
    await selectTab('stored_llm');
    const rejected = await chat('Show me my current profile again.');
    assert.equal(rejected.objectiveCandidate, 'xss_g3');
    assert.equal(rejected.completedObjectiveId, null);
    assertNoCreditVerdict(rejected.judgments[0]);
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND objective_id='xss_g3'`, [user.id])).rows[0].n, 0,
    'Neither copied nor manually rewritten content can earn canonical g3 credit');

    const firstRows = (await identityRuntime.query(`SELECT j.objective_id,j.verdict,j.evaluation_id,p.packet
      FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
      WHERE j.user_id=$1 AND j.objective_id LIKE 'xss_g%' ORDER BY j.evaluated_at,j.evaluation_id`, [user.id])).rows
      .map(row => ({ ...row, packet: typeof row.packet === 'string' ? JSON.parse(row.packet) : row.packet }));
    const rejectedG3Rows = firstRows.filter(row => row.objective_id === 'xss_g3' && ['fail', 'inconclusive'].includes(row.verdict));
    assert.equal(rejectedG3Rows.length, copyJudgmentOccurred ? 2 : 1,
      'the executed copied write and manual rewrite must create non-credit g3 evidence; a declined live copy creates no judgment');
    for (const rejectedG3 of rejectedG3Rows.filter(row => !copyHadNoEffect
      || row.evaluation_id === rejected.judgments[0].evaluationId)) {
      assert.equal(rejectedG3.packet.facts.model_profile_origin_current, false);
      assert.equal(rejectedG3.packet.facts.stored_payload_returned, false);
      assert.equal(rejectedG3.packet.facts.isolated_browser_executed, false);
      const rejectedToolReceipt = rejectedG3.packet.evidence.find(item => item.id === 'tool_receipt');
      assert.equal(rejectedToolReceipt.content.result.profile.bio, first.storedValue,
        'the negative must return the identical stored bytes without treating them as current model origin');
    }

    const resetFirst = page.waitForResponse(response => response.url().includes('/api/workshop/xss/progress/reset-tab')
      && response.request().method() === 'POST');
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.includes('Reset Above Objectives')).click());
    await page.waitForSelector('[role="alertdialog"]', { visible: true });
    await page.evaluate(() => [...document.querySelector('[role="alertdialog"]').querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Confirm reset' && !button.disabled).click());
    assert.equal((await resetFirst).status(), 200);
    const resetProfileFirst = page.waitForResponse(response => response.url().includes('/api/workshop/xss/profile/reset')
      && response.request().method() === 'POST');
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Reset Profile').click());
    await page.waitForSelector('[role="alertdialog"]', { visible: true });
    await page.evaluate(() => [...document.querySelector('[role="alertdialog"]').querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Confirm reset' && !button.disabled).click());
    assert.equal((await resetProfileFirst).status(), 200);
    assert.deepEqual(await profile(), defaults);

    const second = await runGeneration();
    const g3 = await chat('Show me my current profile again.');
    assert.equal(g3.completedObjectiveId, 'xss_g3'); assert.equal(g3.xssDetected, true);
    assert.ok(g3.response.includes(second.storedValue));
    await page.waitForFunction(() => [...document.querySelectorAll('.status-badge')]
      .filter(item => item.textContent === 'DONE').length === 3);

    const artifacts = path.join(runtimeRoot, 'artifacts'); await fsp.mkdir(artifacts, { recursive: true });
    const before = path.join(artifacts, 'xss-stored-llm-rendered-before-reset.png');
    await page.screenshot({ path: before, fullPage: true });
    const rows = (await identityRuntime.query(`SELECT j.objective_id,j.verdict,j.disposition,j.run_id,j.result_json,p.packet,p.judge_version
      FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
      WHERE j.user_id=$1 AND j.objective_id LIKE 'xss_g%' ORDER BY j.evaluated_at,j.evaluation_id`, [user.id])).rows
      .map(row => ({ ...row, packet: typeof row.packet === 'string' ? JSON.parse(row.packet) : row.packet,
        result_json: typeof row.result_json === 'string' ? JSON.parse(row.result_json) : row.result_json }));
    assert.deepEqual(rows.map(row => [row.objective_id,row.verdict]), [
      ['xss_g1','pass'],['xss_g2','pass'],
      ...(copyJudgmentOccurred ? [['xss_g3', (rejectedModelCopy || copiedByModel).judgments[0].verdict]] : []),
      ['xss_g3', rejected.judgments[0].verdict],
      ['xss_g1','pass'],['xss_g2','pass'],['xss_g3','pass'],
    ]);
    for (const row of rows.filter(row => row.verdict !== 'pass')) assert.notEqual(row.disposition, 'awarded');
    t.diagnostic(JSON.stringify({ negativeJudgeVerdicts: rows.filter(row => row.verdict !== 'pass').map(row => row.verdict),
      exactFailureCalibration: rows.filter(row => row.verdict !== 'pass').every(row => row.verdict === 'fail') }));
    const passedG3 = rows.filter(row => row.objective_id === 'xss_g3' && row.verdict === 'pass').at(-1);
    const passedG2 = rows.filter(row => row.objective_id === 'xss_g2' && row.verdict === 'pass').at(-1);
    assert.ok(rows.every(row => row.judge_version === require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION));
    assert.equal(passedG2.packet.facts.model_profile_origin_current, true);
    assert.equal(passedG2.packet.facts.actual_model_response, true);
    assert.equal(passedG3.packet.facts.model_profile_origin_current, true);
    assert.equal(passedG3.packet.facts.canonical_model_save_completed, true);
    assert.equal(passedG3.packet.facts.stored_payload_returned, true);
    assert.equal(passedG3.packet.facts.isolated_browser_executed, true);
    if (live) {
      assert.ok(rows.every(row => row.result_json?.provider === 'ollama'
        && row.result_json?.model === 'llama3.1:8b'), JSON.stringify(rows));
      for (const row of rows) {
        const events = (await identityRuntime.query(`SELECT metadata FROM graph_runtime.events
          WHERE run_id=$1 AND owner_key=$2 AND node='decide' AND event_type='decision' ORDER BY sequence`,
        [row.run_id, JSON.stringify(['XSS', String(user.id)])])).rows;
        assert.ok(events.some(event => event.metadata?.decisionSource === 'model'
          && event.metadata?.provider === 'ollama' && event.metadata?.model === 'llama3.1:8b'));
      }
    }
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND objective_id LIKE 'xss_g%'`, [user.id])).rows[0].n, 3);
    assert.equal((await xssRuntime.query(`SELECT count(*)::int n FROM xss.progress
      WHERE user_key=$1 AND objective_id LIKE 'xss_g%'`, [String(user.id)])).rows[0].n, 3);
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND objective_id LIKE 'xss_g%'`, [sibling.id])).rows[0].n, 0);

    const resetResponse = page.waitForResponse(response => response.url().includes('/api/workshop/xss/progress/reset-tab')
      && response.request().method() === 'POST');
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.includes('Reset Above Objectives')).click());
    await page.waitForSelector('[role="alertdialog"]', { visible: true });
    await page.evaluate(() => [...document.querySelector('[role="alertdialog"]').querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Confirm reset' && !button.disabled).click());
    assert.equal((await resetResponse).status(), 200);
    await page.waitForFunction(() => ![...document.querySelectorAll('.status-badge')]
      .some(item => item.textContent === 'DONE'));
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND objective_id LIKE 'xss_g%'`, [user.id])).rows[0].n, 0);
    assert.equal((await profile()).bio, second.storedValue);
    const profileReset = page.waitForResponse(response => response.url().includes('/api/workshop/xss/profile/reset')
      && response.request().method() === 'POST');
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Reset Profile').click());
    await page.waitForSelector('[role="alertdialog"]', { visible: true });
    await page.evaluate(() => [...document.querySelector('[role="alertdialog"]').querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Confirm reset' && !button.disabled).click());
    assert.equal((await profileReset).status(), 200);
    assert.deepEqual(await profile(), defaults);
    const after = path.join(artifacts, 'xss-stored-llm-rendered-after-reset.png');
    await page.screenshot({ path: after, fullPage: true });
    assert.deepEqual(pageErrors, []); assert.deepEqual(unexpectedResponses, []);
    assert.ok(blockedExternalRequests.length <= 100);
    t.diagnostic(JSON.stringify({ scenario: 'stored_llm', mode: live ? 'live-ollama' : 'deterministic', screenshots: [before, after], blockedExternalRequestCount, blockedExternalRequests }));
  } catch (error) {
    if (page) {
      const artifacts = path.join(runtimeRoot, 'artifacts'); await fsp.mkdir(artifacts, { recursive: true }).catch(() => {});
      await fsp.writeFile(path.join(artifacts, 'xss-stored-llm-rendered-failure.json'), JSON.stringify({
        error: { name: error.name, message: error.message, stack: error.stack }, pageErrors, unexpectedResponses,
        blockedExternalRequestCount, blockedExternalRequests, sendBodies, chatResponses, viteOutput,
        dom: await page.evaluate(() => ({ url: location.href, text: document.body.innerText,
          scenarioTabs: [...document.querySelectorAll('[data-scenario-tab]')].map(item => item.outerHTML),
          emailInput: document.querySelector('input[type="email"]')?.outerHTML || null,
        })).catch(() => null),
      }, null, 2)).catch(() => {});
      await page.screenshot({ path: path.join(artifacts, 'xss-stored-llm-rendered-failure.png'), fullPage: true }).catch(() => {});
    }
    throw error;
  } finally {
    closing = true; Module._load = originalLoad; const failures = [];
    const capture = async operation => { try { await operation(); } catch (error) { failures.push(error); } };
    if (restoreAi) restoreAi(); if (restoreGrader) restoreGrader();
    if (browser) await capture(async () => {
      const pid = browser.process().pid;
      await browser.close();
      assert.throws(() => process.kill(pid, 0), error => error.code === 'ESRCH', 'Rendered browser PID must be absent after close');
      await fsp.writeFile(path.join(runtimeRoot, 'rendered-browser-terminal.json'),
        JSON.stringify({ pid, absent: true }), { flag: 'wx', mode: 0o600 });
    }); if (vite) await capture(() => stopChild(vite));
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
