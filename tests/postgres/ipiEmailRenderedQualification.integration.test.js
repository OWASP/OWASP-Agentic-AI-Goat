'use strict';

// Current assembled IPI email UI qualification.  The owned launcher supplies
// an already running application, Mailpit, and two disposable learner users.
// This file intentionally does not create containers or start a browser unless
// IPI_EMAIL_RENDERED_UI=1 is explicitly supplied by that launcher.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const puppeteer = require('puppeteer');

const enabled = process.env.IPI_EMAIL_RENDERED_UI === '1'
  && process.env.IPI_RENDERED_APP_URL
  && process.env.IPI_RENDERED_MAILPIT_API_URL
  && process.env.IPI_RENDERED_USER
  && process.env.IPI_RENDERED_PASSWORD
  && process.env.IPI_RENDERED_SIBLING_USER
  && process.env.IPI_RENDERED_SIBLING_PASSWORD
  && process.env.IPI_RENDERED_IDENTITY_RUNTIME_URL
  && process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE;

// Observe rejection immediately so cleanup cannot mask an earlier assertion.
// Awaiting the original promise still reports response failures normally.
function waitForResponse(page, ...args) {
  const pending = page.waitForResponse(...args);
  pending.catch(() => {});
  return pending;
}

function assertOwnedMailpit(value) {
  const url = new URL(value);
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname), 'Mailpit must be loopback-only');
  assert.equal(url.protocol, 'http:');
  assert.match(url.pathname, /^\/?$/);
  return url.origin;
}

function assertOwnedWorkspace(value) {
  const resolved = require('node:fs').realpathSync(value);
  assert.equal(require('node:path').basename(resolved), 'source');
  assert.match(require('node:path').basename(require('node:path').dirname(resolved)), /^owasp-ai-goat-ipi-email-rendered-/);
  return resolved;
}

function createPrivateDiagnosticWriter(root) {
  if (!root) return null;
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  fs.chmodSync(root, 0o700);
  return (name, value) => {
    const target = path.join(root, name);
    const payload = `${JSON.stringify(value, null, 2)}\n`;
    if (Buffer.byteLength(payload) > 2 * 1024 * 1024) throw new Error('Private diagnostic size limit exceeded');
    fs.writeFileSync(target, payload, { mode: 0o600 });
    fs.chmodSync(target, 0o600);
    return target;
  };
}

async function readObjectiveJudgments(identity, username, objectiveId = null) {
  const filter = objectiveId ? 'AND j.objective_id = $2' : '';
  const params = objectiveId ? [username, objectiveId] : [username];
  const result = await identity.query(`SELECT j.evaluation_id, j.objective_id, j.rubric_version,
      j.verdict, j.disposition, j.evidence_digest, j.result_json, j.result_digest,
      j.run_id, j.generation, j.created_at, j.evaluated_at
      FROM workshop_platform.objective_judgments j
      JOIN identity.users u ON u.id = j.user_id
      WHERE u.username = $1 AND j.workshop_key = 'indirect_prompt_injection' ${filter}
      ORDER BY j.created_at, j.objective_id`, params);
  return result.rows;
}

async function writeFailureDiagnostics(page, failedApi, error) {
  const root = process.env.IPI_RENDERED_FAILURE_DIAGNOSTICS || path.join(os.tmpdir(), `owasp-ai-goat-ipi-email-rendered-failure-${process.pid}`);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  let safeUrl = null;
  try { const url = new URL(page.url()); safeUrl = `${url.origin}${url.pathname}`; } catch {}
  const screenshot = path.join(root, 'page.png');
  try { await page.screenshot({ path: screenshot, captureBeyondViewport: false }); } catch {}
  const safeMessage = String(error?.message || error).slice(0, 1000).replace(/Bearer\s+\S+/gi, 'Bearer [redacted]');
  fs.writeFileSync(path.join(root, 'failure.json'), JSON.stringify({
    version: 1,
    error: { name: error?.name || 'Error', message: safeMessage },
    page: { url: safeUrl, screenshot: 'page.png' },
    failedApi,
  }, null, 2) + '\n', { mode: 0o600 });
}

async function login(page, base, username, password) {
  await page.goto(`${base}/workshop-login`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('input[placeholder="Enter your username"]');
  await page.type('input[placeholder="Enter your username"]', username);
  await page.type('input[placeholder="Enter your password"]', password);
  await Promise.all([
    page.waitForFunction(() => !location.pathname.includes('login')),
    page.click('button[type="submit"]'),
  ]);
}

async function api(page, route, body) {
  return page.evaluate(async ({ route, body }) => {
    const token = localStorage.getItem('token');
    const response = await fetch(route, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, data: await response.json() };
  }, { route, body });
}

test('assembled IPI email UI covers all five objectives, receipts, reset and sibling isolation', {
  skip: !enabled,
  timeout: 420000,
}, async t => {
  const base = new URL(process.env.IPI_RENDERED_APP_URL).origin;
  const mailpit = assertOwnedMailpit(process.env.IPI_RENDERED_MAILPIT_API_URL);
  const workspace = assertOwnedWorkspace(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);
  const writePrivateDiagnostic = createPrivateDiagnosticWriter(
    process.env.IPI_RENDERED_EMAIL_DIAGNOSTICS || path.join(workspace, 'private-email-diagnostics'),
  );
  const browser = await puppeteer.launch({ headless: true, executablePath: process.env.PUPPETEER_EXECUTABLE_PATH });
  const ownerContext = await browser.createBrowserContext();
  const siblingContext = await browser.createBrowserContext();
  const page = await ownerContext.newPage();
  const errors = [];
  const external = [];
  const failedApi = [];
  let identity;
  const guardPage = async target => {
  target.on('pageerror', error => errors.push(error.message));
  target.on('response', response => {
    if (response.status() < 400) return;
    try {
      const url = new URL(response.url());
      failedApi.push({ method: response.request().method(), origin: url.origin, pathname: url.pathname, status: response.status() });
    } catch {}
  });
  await target.setRequestInterception(true);
  target.on('request', request => {
    const url = request.url();
    let allowed = false;
    try { allowed = new URL(url).origin === base || new URL(url).origin === mailpit; } catch {}
    if (allowed || /^(?:data|blob|about):/.test(url)) request.continue();
    else { external.push(url); request.abort('blockedbyclient'); }
  });
  };
  await guardPage(page);
  let failure;
  try {
    await login(page, base, process.env.IPI_RENDERED_USER, process.env.IPI_RENDERED_PASSWORD);
    await page.goto(`${base}/vulnerabilities/indirect-prompt-injection`, { waitUntil: 'networkidle0' });
    await page.waitForSelector('[data-scenario-tab="email"]');
    await page.click('[data-scenario-tab="email"]');
    await page.waitForSelector('input[type="email"]');
    await page.waitForFunction(() => document.querySelector('input[type="email"]')?.value.endsWith('@owasp-ai-goat.invalid'));
    await page.waitForFunction(() => document.body.innerText.includes('0 of 5 objectives completed'));

    const address = await page.$eval('input[type="email"]', input => input.value);
    const save = waitForResponse(page, r => r.url().endsWith('/api/email-agent/save-email') && r.request().method() === 'POST');
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Save').click());
    assert.equal((await save).status(), 200);
    await page.waitForFunction(() => document.body.innerText.includes('1 of 5 objectives completed'));

    const send = waitForResponse(page, r => r.url().endsWith('/api/email-agent/send') && r.request().method() === 'POST');
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.includes('Send Attack Email to Me')).click());
    assert.equal((await send).status(), 200);
    await page.waitForFunction(() => document.body.innerText.includes('Email Sent!'), { timeout: 60000 });

    const fetchResponse = waitForResponse(page, r => r.url().endsWith('/api/email-agent/fetch-sharklasers') && r.request().method() === 'POST', { timeout: 120000 });
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.includes('Fetch My Emails')).click());
    const fetchedResponse = await fetchResponse;
    const fetchedPayload = await fetchedResponse.json();
    assert.equal(fetchedResponse.status(), 200);
    assert.equal(fetchedPayload.success, true, JSON.stringify({ error: fetchedPayload.error, message: fetchedPayload.message }));
    assert.ok(Array.isArray(fetchedPayload.emails) && fetchedPayload.emails.some(email => typeof email?.artifactId === 'string'), 'owned provider must return a persisted artifact');
    // Preserve the exact retrieval response and canonical retrieval judgment
    // before the later summary call changes the visible UI state. This file is
    // owner-only diagnostic evidence; raw bodies never go to console/TAP.
    const { Pool } = require('pg');
    identity = new Pool({ connectionString: process.env.IPI_RENDERED_IDENTITY_RUNTIME_URL, max: 2 });
    const retrievalJudgments = await readObjectiveJudgments(identity, process.env.IPI_RENDERED_USER, 'email_retrieve');
    writePrivateDiagnostic?.('email-retrieve-fetch.json', {
      version: 1,
      phase: 'after-fetch-before-summary',
      response: { status: fetchedResponse.status(), payload: fetchedPayload },
      judgments: retrievalJudgments,
    });
    assert.equal(fetchedPayload.objectiveCompleted, 3, 'retrieval must earn its own canonical Judge credit before actor qualification');
    await page.waitForSelector('text/Email Retrieved', { timeout: 120000 });
    assert.equal(await page.$('textarea[placeholder="Paste the email content here..."]'), null, 'manual fallback cannot qualify retrieval');

    const summarize = waitForResponse(page, r => r.url().endsWith('/api/email-agent/summarize') && r.request().method() === 'POST', { timeout: 240000 });
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.includes('Summarize Email')).click());
    const summaryResponse = await summarize;
    assert.equal(summaryResponse.status(), 200);
    const summaryBody = await summaryResponse.json();
    assert.equal(summaryBody.success, true);
    assert.ok(typeof summaryBody.vulnerableSummary === 'string' && summaryBody.vulnerableSummary.trim());
    assert.ok(typeof summaryBody.safeSummary === 'string' && summaryBody.safeSummary.trim(), 'objective 5 requires secure summary');
    assert.ok(Array.isArray(summaryBody.judgments) && summaryBody.judgments.some(j => j.objectiveId === 'email_understand_defense'));
    await page.waitForFunction(() => document.body.innerText.includes('4 of 5 objectives completed')
      || document.body.innerText.includes('5 of 5 objectives completed'), { timeout: 240000 });
    await page.waitForFunction(() => document.body.innerText.includes('Judge:'), { timeout: 120000 });
    await page.waitForFunction(() => document.body.innerText.includes('Secure AI Output'), { timeout: 30000 });

    const progress = await api(page, '/api/email-agent/progress');
    assert.equal(progress.status, 200);
    assert.equal(progress.data.totalObjectives, 5);
    assert.equal(progress.data.completedCount, 5, JSON.stringify(progress.data));
    assert.deepEqual(Object.values(progress.data.progress).map(row => row.completed), [true, true, true, true, true]);
    const ownerRows = await readObjectiveJudgments(identity, process.env.IPI_RENDERED_USER);
    writePrivateDiagnostic?.('objective-judgments-owner.json', { username: process.env.IPI_RENDERED_USER, rows: ownerRows });
    assert.deepEqual(ownerRows.map(row => row.objective_id).sort(), [
      'email_create_inbox', 'email_retrieve', 'email_send_attack',
      'email_trigger_injection', 'email_understand_defense',
    ]);
    assert.ok(ownerRows.every(row => row.verdict === 'pass' && row.disposition === 'awarded'));
    t.diagnostic(JSON.stringify({ scope: 'ipi-email-rendered', mailpit, progress: progress.data }));

    // Establish sibling isolation before mutating the owner. A second browser
    // context avoids relying on the owner's cookie/token state.
    const siblingPage = await siblingContext.newPage();
    await guardPage(siblingPage);
    await login(siblingPage, base, process.env.IPI_RENDERED_SIBLING_USER, process.env.IPI_RENDERED_SIBLING_PASSWORD);
    const siblingInitial = await api(siblingPage, '/api/email-agent/progress');
    assert.equal(siblingInitial.status, 200);
    assert.equal(siblingInitial.data.completedCount, 0, 'sibling must start with independent progress');
    const siblingInbox = await api(siblingPage, '/api/email-agent/owned-inbox');
    assert.equal(siblingInbox.status, 200);
    assert.match(siblingInbox.data.ownedInbox, /@owasp-ai-goat\.invalid$/);
    assert.notEqual(siblingInbox.data.ownedInbox, address);
    const foreignFetch = await api(siblingPage, '/api/email-agent/fetch-sharklasers', { tempEmail: address });
    assert.equal(foreignFetch.status, 403, 'sibling cannot retrieve the owner inbox');
    assert.notEqual(foreignFetch.data.fallbackAvailable, true);
    const foreignSave = await api(siblingPage, '/api/email-agent/save-email', { tempEmail: address });
    assert.equal(foreignSave.status, 403, 'sibling cannot configure the owner inbox');
    const siblingSaved = await api(siblingPage, '/api/email-agent/save-email', { tempEmail: siblingInbox.data.ownedInbox });
    assert.equal(siblingSaved.status, 200);
    const siblingBeforeReset = await api(siblingPage, '/api/email-agent/progress');
    assert.equal(siblingBeforeReset.status, 200);
    assert.equal(siblingBeforeReset.data.completedCount, 1, 'sibling must have real progress to preserve');
    const siblingRows = await readObjectiveJudgments(identity, process.env.IPI_RENDERED_SIBLING_USER);
    writePrivateDiagnostic?.('objective-judgments-sibling.json', { username: process.env.IPI_RENDERED_SIBLING_USER, rows: siblingRows });
    await siblingPage.close();

    // Both scenario panels keep their reset controls in the DOM.  Select the
    // active email workspace so a hidden document reset cannot leave the
    // browser waiting forever for /api/email-agent/progress/reset.
    await page.evaluate(() => {
      const workspace = document.querySelector('[data-scenario-workspace="email"]');
      const button = [...(workspace?.querySelectorAll('button') || [])]
        .find(candidate => candidate.textContent.trim() === 'Reset Progress');
      if (!button) throw new Error('email reset control not found in active workspace');
      button.click();
    });
    await page.waitForSelector('button', { visible: true });
    await page.waitForFunction(() => [...document.querySelectorAll('button')]
      .some(button => button.textContent.trim() === 'Confirm reset'));
    const reset = waitForResponse(page, r => r.url().endsWith('/api/email-agent/progress/reset') && r.request().method() === 'POST');
    await page.evaluate(() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Confirm reset').click());
    assert.equal((await reset).status(), 200);
    await page.waitForFunction(() => document.body.innerText.includes('0 of 5 objectives completed'));
    const afterReset = await api(page, '/api/email-agent/progress');
    assert.equal(afterReset.data.completedCount, 0);
    const rotatedInbox = await api(page, '/api/email-agent/owned-inbox');
    assert.equal(rotatedInbox.status, 200);
    assert.notEqual(rotatedInbox.data.ownedInbox, address, 'reset must rotate the owned local inbox');
    const staleFetch = await api(page, '/api/email-agent/fetch-sharklasers', { tempEmail: address });
    assert.equal(staleFetch.status, 403, 'stale inbox must be rejected without manual fallback');
    const resetRows = await identity.query(`SELECT count(*)::int AS count
      FROM workshop_platform.completions
      WHERE user_id = (SELECT id FROM identity.users WHERE username = $1)
        AND workshop_key = 'indirect_prompt_injection'
        AND objective_id LIKE 'email_%'`, [process.env.IPI_RENDERED_USER]);
    assert.equal(resetRows.rows[0].count, 0);

    const siblingPageAfterReset = await siblingContext.newPage();
    await guardPage(siblingPageAfterReset);
    await login(siblingPageAfterReset, base, process.env.IPI_RENDERED_SIBLING_USER, process.env.IPI_RENDERED_SIBLING_PASSWORD);
    const sibling = await api(siblingPageAfterReset, '/api/email-agent/progress');
    assert.equal(sibling.status, 200);
    assert.equal(sibling.data.completedCount, siblingBeforeReset.data.completedCount, 'reset must not leak progress across owners');
    assert.deepEqual(sibling.data.progress, siblingBeforeReset.data.progress, 'owner reset must preserve existing sibling progress');
    await siblingPageAfterReset.close();
    assert.deepEqual(errors, []);
    assert.deepEqual(external, [], `browser attempted non-owned destinations: ${external.join(', ')}`);
  } catch (error) {
    failure = error;
    if (identity) {
      try {
        for (const [label, username] of [['owner', process.env.IPI_RENDERED_USER],
          ['sibling', process.env.IPI_RENDERED_SIBLING_USER]]) {
          writePrivateDiagnostic(`objective-judgments-${label}-failure.json`, {
            username, rows: await readObjectiveJudgments(identity, username),
          });
        }
      } catch (diagnosticError) {
        failure.diagnosticCaptureError = { name: diagnosticError.name,
          message: String(diagnosticError.message).slice(0, 300) };
        try { writePrivateDiagnostic('judgment-capture-error.json', failure.diagnosticCaptureError); } catch {}
      }
    }
    await writeFailureDiagnostics(page, failedApi, error);
  } finally {
    try { await identity?.end(); } finally { await browser.close(); }
  }
  if (failure) throw failure;
});

module.exports = { assertOwnedMailpit, assertOwnedWorkspace };
