'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const apiPath = value => new URL(value).pathname;
function mountAuthRoutes({ app, adapter }) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  const pass = (_req, _res, next) => next();
  const router = require('../../server/routes/postgresAuth').createPostgresAuthRouter({
    adapter, limiters: {
      loginRateLimiter: pass, registerRateLimiter: pass, passwordResetRateLimiter: pass,
    },
  });
  app.use('/api/auth', router);
  return { close: () => router.close() };
}

function mountStaticRoutes({ app, buildDirectory }) {
  const build = fs.realpathSync(buildDirectory);
  assert.ok(path.isAbsolute(build) && fs.statSync(build).isDirectory());
  assert.ok(fs.statSync(path.join(build, 'index.html')).isFile());
  assert.equal(build, fs.realpathSync(process.env.CTF_STAGE6_BUILD_DIRECTORY),
    'private build must be admitted by the Stage 6 launcher');
  const express = require('express');
  app.use('/api', (_req, res) => res.status(404).json({ error: 'Unmapped Stage 6 API' }));
  app.use(express.static(build));
  app.get('/{*path}', (_req, res) => res.sendFile(path.join(build, 'index.html')));
}

async function retireStage6Browser({ page, browser, afterSubmit }) {
  const failures = [];
  if (afterSubmit) try { await afterSubmit(); } catch (error) { failures.push(error); }
  if (page) try { await page.close(); } catch (error) { failures.push(error); }
  try { await browser.close(); } catch (error) { failures.push(error); }
  return failures;
}

async function createIdentityPage(browser, contexts) {
  const context = await browser.createBrowserContext();
  contexts.push(context);
  return context.newPage();
}

async function retireStage6ReadbackBrowser({ pages, contexts, browser }) {
  const failures = [];
  for (const page of pages) try { await page.close(); } catch (error) { failures.push(error); }
  for (const context of contexts) try { await context.close(); } catch (error) { failures.push(error); }
  try { await browser.close(); } catch (error) { failures.push(error); }
  return failures;
}

function adminLeaderboardRowVisible({ name, completed }) {
  return [...document.querySelectorAll('tr')].some(row => {
    const cells = row.querySelectorAll('td');
    return cells.length === 9 && cells[1].textContent.trim() === name
      && cells[3].textContent.trim() === String(completed);
  });
}

function adminStage6AttemptVisible({ name, payload, stage }) {
  return [...document.querySelectorAll('tr')].some(row => {
    const cells = row.querySelectorAll('td');
    return cells.length === 7 && cells[1].textContent.trim() === name
      && cells[2].textContent.trim().split(/\s+/)[0] === `#${stage}`
      && cells[3].getAttribute('title') === payload;
  });
}

async function submitStage6CandidateInBrowser({ origin, owner, password, stage6, payload,
  evidence, beforeSubmit, afterSubmit }) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(process.env.CTF_STAGE6_EARNED_RENDERED, '1');
  assert.match(origin, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.equal(stage6?.stage_number, 6);
  assert.ok(typeof payload === 'string' && payload.trim() === payload && payload.length);
  assert.equal(typeof beforeSubmit, 'function');
  assert.equal(typeof afterSubmit, 'function');
  const root = fs.realpathSync(evidence);
  assert.equal(fs.statSync(root).mode & 0o077, 0, 'private browser evidence required');
  const browser = await require('./secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(root, 'ctfsubmit');
  const deadline = setTimeout(() => { browser.close().catch(() => {}); }, 300000);
  let page, primary, caseStarted = false;
  const blocked = [], errors = [], posts = [];
  const result = { version: 1, kind: 'ctf-stage6-one-real-browser-attempt',
    initialStatus: null, initialBody: null, publicationStatus: null, publicationBody: null,
    decisionId: null, sessionTokenSha256: null, postCount: 0,
    responseVisibleInLearnerChat: false, completionVisibleInLearnerUi: false,
    domVisible: false };
  const save = () => {
    const value = JSON.stringify(result, null, 2);
    assert.ok(Buffer.byteLength(value) <= 65536, 'bounded private browser result');
    fs.writeFileSync(path.join(root, 'ctf-stage6-candidate-browser.json'), value, { mode: 0o600 });
  };
  try {
    page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 900 });
    await require('./fullBackendRenderedSecureShop').configurePage(page, origin, blocked, errors);
    page.on('request', request => {
      if (request.method() === 'POST' && /^\/api\/ctf\/stage\/\d+\/attempt$/.test(apiPath(request.url()))) {
        posts.push(apiPath(request.url()));
        result.postCount = posts.length;
      }
    });
    await page.goto(origin + '/workshop-login', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[placeholder="Enter your username"]');
    await page.type('input[placeholder="Enter your username"]', owner.username);
    await page.type('input[placeholder="Enter your password"]', password);
    const login = page.waitForResponse(response => apiPath(response.url()) === '/api/auth/login'
      && response.request().method() === 'POST', { timeout: 20000 });
    await page.click('button[type="submit"]');
    assert.equal((await login).status(), 200);
    await page.waitForFunction(() => Boolean(localStorage.getItem('token'))
      && location.pathname !== '/workshop-login');
    const token = await page.evaluate(() => localStorage.getItem('token'));
    result.sessionTokenSha256 = createHash('sha256').update(token).digest('hex');
    await page.goto(origin + '/ctf', { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(name => [...document.querySelectorAll('[role="button"]')]
      .some(card => [...card.querySelectorAll('h3')].some(h => h.textContent.trim() === name)
        && card.tabIndex === 0), {}, stage6.stage_name);
    await page.evaluate(name => [...document.querySelectorAll('[role="button"]')]
      .find(card => [...card.querySelectorAll('h3')].some(h => h.textContent.trim() === name)).click(),
    stage6.stage_name);
    await page.waitForFunction(() => location.pathname === '/ctf/challenge'
      && Boolean(document.querySelector('textarea:not([disabled])')));
    await page.type('textarea:not([disabled])', payload);
    assert.equal(await page.$eval('textarea', element => element.value), payload,
      'exact fixed candidate must be visible before submit');
    const initial = page.waitForResponse(response => apiPath(response.url()) ===
      `/api/ctf/stage/${stage6.id}/attempt` && response.request().method() === 'POST',
    { timeout: 245000 });
    const publicationReady = page.waitForResponse(response =>
      /^\/api\/ctf\/publications\/[a-f0-9-]{36}$/.test(apiPath(response.url()))
      && response.status() !== 202, { timeout: 245000 });
    publicationReady.catch(() => {});
    await beforeSubmit();
    caseStarted = true;
    await page.click('form button[type="submit"]');
    const first = await initial;
    result.initialStatus = first.status();
    result.initialBody = await first.json();
    assert.equal(result.postCount, 1, 'browser must submit exactly one candidate attempt');
    result.decisionId = result.initialBody?.decisionId ?? null;
    if (result.decisionId) {
      assert.match(result.decisionId, /^[a-f0-9-]{36}$/);
      const publication = await publicationReady;
      assert.equal(apiPath(publication.url()), `/api/ctf/publications/${result.decisionId}`);
      result.publicationStatus = publication.status();
      result.publicationBody = await publication.json();
      if (typeof result.publicationBody?.aiResponse === 'string') {
        try {
          await page.waitForFunction(answer => document.body.textContent.includes(answer),
          { timeout: 2500 }, result.publicationBody.aiResponse);
          result.responseVisibleInLearnerChat = true;
        } catch {}
      }
      if (result.publicationBody?.success === true) {
        try {
          await page.waitForFunction(() => document.body.textContent.includes('Challenge Completed!'),
          { timeout: 2500 });
          result.completionVisibleInLearnerUi = true;
          await page.screenshot({ path: path.join(root, 'ctf-stage6-genuine-learner-response.png'),
            fullPage: true });
        } catch {}
      }
      result.domVisible = result.responseVisibleInLearnerChat
        && result.completionVisibleInLearnerUi;
    }
    save();
    assert.equal(result.publicationStatus, 200,
      'genuine learner publication must be authorized before earned UI qualification');
    assert.deepEqual(blocked, []);
    assert.deepEqual(errors, []);
    assert.equal(result.postCount, 1);
    if (result.publicationBody?.success === true) {
      assert.equal(result.responseVisibleInLearnerChat, true,
        'genuine published response must appear in learner chat DOM');
      assert.equal(result.completionVisibleInLearnerUi, true,
        'genuine completion must appear before redirect');
    }
    Object.defineProperty(result, 'browserToken', { value: token, enumerable: false });
    return result;
  } catch (error) {
    primary = error;
    result.failure = { name: error.name, message: String(error.message).slice(0, 300) };
    save();
    throw error;
  } finally {
    clearTimeout(deadline);
    const cleanup = await retireStage6Browser({ page, browser,
      afterSubmit: caseStarted ? afterSubmit : null });
    if (cleanup.length) {
      result.cleanupFailures = cleanup.map(error => ({ name: error?.name || 'Error',
        message: String(error?.message || error).slice(0, 200) }));
      try { save(); } catch {}
    }
    if (!primary && cleanup.length) throw new AggregateError(cleanup, 'Stage 6 browser cleanup failed');
  }
}

async function qualifyStage6EarnedRendered({ origin, owner, sibling, admin, password,
  stage6, stage7, ownerSession, siblingSession, adminSession, authorityApplication, participant,
  siblingParticipant, acceptedJudgment, evidence, resetOwner }) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(process.env.CTF_STAGE6_EARNED_RENDERED, '1');
  assert.match(origin, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.equal(stage6.stage_number, 6);
  assert.equal(stage7.stage_number, 7);
  assert.equal(typeof resetOwner, 'function');
  assert.equal((await authorityApplication?.runtime?.readiness())?.runtimeReady, true,
    'activated current CTF authority application required');
  assert.equal(acceptedJudgment?.verdict, 'pass', 'canonical genuine Judge pass required');
  assert.equal(Number(acceptedJudgment?.accepted), 1, 'accepted Stage 6 judgment required');
  assert.equal(Number(acceptedJudgment?.stage_id), Number(stage6.id));
  const provenance = JSON.parse(acceptedJudgment.metadata);
  assert.equal(provenance.guardian?.provider, 'ollama');
  assert.equal(provenance.guardian?.model, 'llama3.1:8b');
  assert.ok(typeof acceptedJudgment.ai_response === 'string' && acceptedJudgment.ai_response.length);
  assert.equal(provenance.guardian.visibleResponseSha256,
    createHash('sha256').update(acceptedJudgment.ai_response).digest('hex'));
  const root = fs.realpathSync(evidence);
  assert.equal(fs.statSync(root).mode & 0o077, 0, 'evidence directory must be private');
  const request = async (url, token) => {
    const response = await fetch(origin + url, { headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(20000) });
    assert.equal(response.status, 200, url);
    return response.json();
  };
  const before = await Promise.all([
    request('/api/ctf/status', ownerSession.token),
    request('/api/ctf/status', siblingSession.token),
    request('/api/ctf/leaderboard', ownerSession.token),
    request('/api/ctf/admin/participants', adminSession.token),
    request(`/api/ctf/admin/attempts?participantId=${participant.id}&stageId=${stage6.id}&wasSuccessful=true`,
      adminSession.token),
  ]);
  const [ownerStatus, siblingStatus, leaderboard, adminParticipants, adminAttempts] = before;
  const storedAttempt = adminAttempts.attempts?.find(row =>
    Number(row.id) === Number(acceptedJudgment.attempt_id));
  assert.equal(storedAttempt?.ai_response, acceptedJudgment.ai_response,
    'authenticated admin history must retain the exact post-defense visible response');
  assert.equal(storedAttempt?.judgment_verdict, 'pass');
  assert.equal(Number(storedAttempt?.judgment_accepted), 1);
  const ownerStage6 = ownerStatus.progress?.find(row => Number(row.stage_id) === Number(stage6.id));
  assert.equal(ownerStage6?.status, 'completed', 'real Stage 6 commit required before browser launch');
  assert.equal(siblingStatus.progress?.find(row => Number(row.stage_id) === Number(stage6.id))?.status,
    'in_progress', 'sibling must retain its distinct current Stage 6 state');
  const ownerEntry = leaderboard.leaderboard?.find(row => Number(row.participant_id) === Number(participant.id));
  const siblingEntry = leaderboard.leaderboard?.find(row => Number(row.participant_id) === Number(siblingParticipant.id));
  const adminOwner = adminParticipants.participants?.find(row => Number(row.user_id) === Number(owner.id));
  assert.equal(Number(ownerEntry?.total_stages_completed), 6);
  assert.equal(Number(siblingEntry?.total_stages_completed), 5);
  assert.equal(Number(adminOwner?.stages_completed), 6);
  const browser = await require('./secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(root, 'ctfearned');
  const deadline = setTimeout(() => { browser.close().catch(() => {}); }, 180000);
  let learner, siblingPage, adminPage, primary;
  const contexts = [], loginTokenHashes = new Map();
  const observed = { version: 1, scope: 'genuine-stage6-earned-rendered', stage6Completed: false,
    stage7Unlocked: false, challengeCompletedRedirect: false, adminHistoryResponse: true,
    leaderboardParity: false, adminParity: false,
    ownerReset: false, siblingPreserved: false, prerequisiteStages1To5Earned: false,
    actualModelCallsByBrowser: 0 };
  const save = () => fs.writeFileSync(path.join(root, 'ctf-stage6-earned-rendered.json'),
    JSON.stringify(observed, null, 2), { mode: 0o600 });
  const blocked = [], errors = [];
  async function page(user) {
    const p = await createIdentityPage(browser, contexts);
    p.setDefaultTimeout(20000);
    await p.setViewport({ width: 1280, height: 900 });
    await require('./fullBackendRenderedSecureShop').configurePage(p, origin, blocked, errors);
    p.on('request', request => {
      if (request.method() === 'POST' && /^\/api\/ctf\/stage\/\d+\/attempt$/.test(apiPath(request.url()))) {
        observed.actualModelCallsByBrowser += 1;
      }
    });
    await p.goto(origin + '/workshop-login', { waitUntil: 'domcontentloaded' });
    await p.waitForSelector('input[placeholder="Enter your username"]');
    await p.type('input[placeholder="Enter your username"]', user.username);
    await p.type('input[placeholder="Enter your password"]', password);
    const login = p.waitForResponse(r => apiPath(r.url()) === '/api/auth/login' && r.request().method() === 'POST');
    await p.click('button[type="submit"]');
    assert.equal((await login).status(), 200);
    await p.waitForFunction(() => Boolean(localStorage.getItem('token')) && location.pathname !== '/workshop-login');
    const token = await p.evaluate(() => localStorage.getItem('token'));
    loginTokenHashes.set(p, createHash('sha256').update(token).digest('hex'));
    return p;
  }
  try {
    learner = await page(owner);
    siblingPage = await page(sibling);
    adminPage = await page(admin);
    const currentHashes = await Promise.all([learner, siblingPage, adminPage].map(async current => {
      const token = await current.evaluate(() => localStorage.getItem('token'));
      assert.ok(token, 'identity browser context must retain a login token');
      return createHash('sha256').update(token).digest('hex');
    }));
    assert.deepEqual(currentHashes, [learner, siblingPage, adminPage]
      .map(current => loginTokenHashes.get(current)), 'identity storage must remain isolated after all logins');
    assert.equal(new Set(currentHashes).size, 3, 'each browser identity must have its own session');
    observed.identityStorageIsolated = true;
    await learner.goto(origin + '/ctf', { waitUntil: 'domcontentloaded' });
    await learner.waitForFunction(({ six, seven }) => {
      const card = name => [...document.querySelectorAll('[role="button"]')]
        .find(e => [...e.querySelectorAll('h3')].some(h => h.textContent.trim() === name));
      return card(six)?.innerText.includes('Completed') && card(seven)?.tabIndex === 0
        && card(seven)?.innerText.includes('Start challenge');
    }, {}, { six: stage6.stage_name, seven: stage7.stage_name });
    const cards = await learner.evaluate(({ six, seven }) => {
      const card = name => [...document.querySelectorAll('[role="button"]')]
        .find(e => [...e.querySelectorAll('h3')].some(h => h.textContent.trim() === name));
      return { six: card(six)?.innerText, seven: card(seven)?.innerText };
    }, { six: stage6.stage_name, seven: stage7.stage_name });
    assert.match(cards.six, /Completed/);
    assert.match(cards.seven, /Start challenge/);
    observed.stage6Completed = observed.stage7Unlocked = true;
    await learner.screenshot({ path: path.join(root, 'ctf-stage6-earned-dashboard.png'), fullPage: true });
    const completedStart = learner.waitForResponse(response =>
      apiPath(response.url()) === `/api/ctf/stage/${stage6.id}/start`
      && response.request().method() === 'POST');
    await learner.evaluate(name => [...document.querySelectorAll('[role="button"]')]
      .find(card => [...card.querySelectorAll('h3')].some(h => h.textContent.trim() === name)).click(),
    stage6.stage_name);
    const replay = await completedStart;
    assert.equal(replay.status(), 200);
    assert.equal((await replay.json()).alreadyCompleted, true);
    await learner.waitForFunction(() => location.pathname === '/ctf');
    observed.challengeCompletedRedirect = true;
    await learner.goto(origin + '/ctf/leaderboard', { waitUntil: 'domcontentloaded' });
    await learner.waitForFunction(({ name, completed }) => [...document.querySelectorAll('tr')]
      .some(row => row.innerText.includes(name) && row.innerText.includes(completed)), {},
    { name: participant.username, completed: '6/10' });
    observed.leaderboardParity = true;
    await learner.screenshot({ path: path.join(root, 'ctf-stage6-earned-leaderboard.png'), fullPage: true });
    await adminPage.goto(origin + '/admin/ctf-management', { waitUntil: 'domcontentloaded' });
    await adminPage.waitForFunction(() => [...document.querySelectorAll('nav[aria-label="CTF admin sections"] button')]
      .some(button => button.textContent.trim() === 'Leaderboard'));
    await adminPage.evaluate(() => [...document.querySelectorAll('nav[aria-label="CTF admin sections"] button')]
      .find(button => button.textContent.trim() === 'Leaderboard').click());
    await adminPage.waitForFunction(adminLeaderboardRowVisible, {},
      { name: participant.username, completed: 6 });
    observed.adminParity = true;
    await adminPage.screenshot({ path: path.join(root, 'ctf-stage6-earned-admin.png'), fullPage: true });
    await adminPage.evaluate(() => [...document.querySelectorAll('nav[aria-label="CTF admin sections"] button')]
      .find(button => button.textContent.trim() === 'Attempts').click());
    await adminPage.waitForFunction(adminStage6AttemptVisible, {},
      { name: participant.username, payload: storedAttempt.payload, stage: 6 });
    observed.adminAttemptsVisible = true;
    await siblingPage.goto(origin + '/ctf', { waitUntil: 'domcontentloaded' });
    await siblingPage.waitForFunction(name => [...document.querySelectorAll('h3')]
      .some(h => h.textContent.trim() === name), {}, stage6.stage_name);
    await resetOwner();
    const after = await Promise.all([
      request('/api/ctf/status', ownerSession.token),
      request('/api/ctf/status', siblingSession.token),
    ]);
    assert.equal(after[0].progress?.length, 0);
    assert.deepEqual(after[1].progress, siblingStatus.progress);
    observed.ownerReset = observed.siblingPreserved = true;
    await learner.goto(origin + '/ctf', { waitUntil: 'domcontentloaded' });
    await learner.waitForFunction(name => [...document.querySelectorAll('[role="button"]')]
      .some(card => card.innerText.includes(name) && card.innerText.includes('Complete previous stage')), {}, stage7.stage_name);
    await siblingPage.goto(origin + '/ctf', { waitUntil: 'domcontentloaded' });
    await siblingPage.waitForFunction(name => [...document.querySelectorAll('[role="button"]')]
      .some(card => card.innerText.includes(name) && card.innerText.includes('Continue challenge')), {}, stage6.stage_name);
    assert.deepEqual(blocked, []);
    assert.deepEqual(errors, []);
    assert.equal(observed.actualModelCallsByBrowser, 0, 'rendered readback must not resample model');
    save();
    return observed;
  } catch (error) {
    primary = error;
    observed.failure = { name: error.name, message: String(error.message).slice(0, 300) };
    const diagnostics = {};
    for (const [label, current] of [['owner', learner], ['sibling', siblingPage], ['admin', adminPage]]) {
      if (!current || current.isClosed()) continue;
      const entry = {};
      try { entry.pathname = new URL(current.url()).pathname; } catch {}
      try {
        const body = await Promise.race([
          current.evaluate(() => document.body?.innerText || ''),
          new Promise((_, reject) => setTimeout(() => reject(Error('DOM capture timed out')), 2000)),
        ]);
        entry.bodyText = body.slice(0, 4096);
        entry.bodyTruncated = body.length > 4096;
      } catch (captureError) { entry.bodyCaptureError = captureError.name; }
      try {
        const screenshot = await Promise.race([
          current.screenshot({ fullPage: false }),
          new Promise((_, reject) => setTimeout(() => reject(Error('Screenshot timed out')), 2000)),
        ]);
        assert.ok(screenshot.length <= 2 * 1024 * 1024, 'bounded private failure screenshot');
        fs.writeFileSync(path.join(root, `ctf-stage6-${label}-failure.png`), screenshot, { mode: 0o600 });
        entry.screenshot = `ctf-stage6-${label}-failure.png`;
      } catch (captureError) { entry.screenshotError = captureError.name; }
      diagnostics[label] = entry;
    }
    try {
      const value = JSON.stringify(diagnostics, null, 2);
      assert.ok(Buffer.byteLength(value) <= 16384, 'bounded private failure diagnostics');
      fs.writeFileSync(path.join(root, 'ctf-stage6-earned-failure-diagnostic.json'), value, { mode: 0o600 });
    } catch {}
    save();
    throw error;
  } finally {
    clearTimeout(deadline);
    const pages = [learner, siblingPage, adminPage].filter(Boolean);
    const failures = await retireStage6ReadbackBrowser({ pages, contexts, browser });
    if (failures.length) {
      observed.cleanupFailures = failures.map(error => ({ name: error?.name || 'Error',
        message: String(error?.message || error).slice(0, 200) }));
      try { save(); } catch {}
    }
    if (!primary && failures.length) throw new AggregateError(failures, 'Stage 6 readback cleanup failed');
  }
}

module.exports = { mountAuthRoutes, mountStaticRoutes, submitStage6CandidateInBrowser,
  qualifyStage6EarnedRendered, retireStage6Browser, createIdentityPage,
  retireStage6ReadbackBrowser, adminLeaderboardRowVisible, adminStage6AttemptVisible };
