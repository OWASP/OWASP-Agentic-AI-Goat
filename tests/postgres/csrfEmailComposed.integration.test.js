'use strict';

// The owned launcher supplies the application, four disposable PostgreSQL URL
// pairs, Mailpit and a pinned local model. This test never creates resources.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const puppeteer = require('puppeteer');
const { CSRF_EMAIL_PAYLOADS } = require('../../server/data/csrfEmailPayloads');

const URL_KEYS = Object.freeze([
  'PG_CSRF_EMAIL_COMPOSED_IDENTITY_RUNTIME_URL',
  'PG_CSRF_EMAIL_COMPOSED_IDENTITY_MIGRATION_URL',
  'PG_CSRF_EMAIL_COMPOSED_CSRF_RUNTIME_URL',
  'PG_CSRF_EMAIL_COMPOSED_CSRF_MIGRATION_URL',
]);
const enabled = process.env.CSRF_EMAIL_COMPOSED_LIVE === '1'
  && process.env.CSRF_EMAIL_COMPOSED_APP_URL
  && process.env.CSRF_EMAIL_COMPOSED_MAILPIT_API_URL
  && process.env.CSRF_EMAIL_COMPOSED_OWNER_USER
  && process.env.CSRF_EMAIL_COMPOSED_OWNER_PASSWORD
  && process.env.CSRF_EMAIL_COMPOSED_SIBLING_USER
  && process.env.CSRF_EMAIL_COMPOSED_SIBLING_PASSWORD
  && process.env.IPI_MAIL_HMAC_SECRET
  && process.env.CSRF_EMAIL_COMPOSED_MAX_MODEL_CALLS
    && process.env.DVAIA_ISOLATED_TEST_WORKSPACE
    && process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR
    && process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256
  && URL_KEYS.every(key => process.env[key]);

function ownedUrl(value, label) {
  const url = new URL(value);
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), `${label} must be loopback`);
  assert.equal(url.username, '', `${label} must not expose credentials`);
  assert.equal(url.password, '', `${label} must not expose credentials`);
  return url.origin;
}

function verifyInputs() {
  const workspace = fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE);
  assert.equal(path.basename(workspace), 'source');
  assert.match(path.basename(path.dirname(workspace)), /^dvaia-csrf-email-composed-/);
  const app = ownedUrl(process.env.CSRF_EMAIL_COMPOSED_APP_URL, 'application');
  const mailpit = ownedUrl(process.env.CSRF_EMAIL_COMPOSED_MAILPIT_API_URL, 'Mailpit');
  const urls = Object.fromEntries(URL_KEYS.map(key => [key, new URL(process.env[key])]));
  for (const [key, url] of Object.entries(urls)) {
    assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), `${key} must be loopback`);
    assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  }
  assert.equal(urls.PG_CSRF_EMAIL_COMPOSED_IDENTITY_RUNTIME_URL.pathname,
    urls.PG_CSRF_EMAIL_COMPOSED_IDENTITY_MIGRATION_URL.pathname);
  assert.equal(urls.PG_CSRF_EMAIL_COMPOSED_CSRF_RUNTIME_URL.pathname,
    urls.PG_CSRF_EMAIL_COMPOSED_CSRF_MIGRATION_URL.pathname);
  assert.notEqual(urls.PG_CSRF_EMAIL_COMPOSED_IDENTITY_RUNTIME_URL.pathname,
    urls.PG_CSRF_EMAIL_COMPOSED_CSRF_RUNTIME_URL.pathname);
  assert.equal(process.env.OLLAMA_MODEL, 'llama3.1:8b');
  assert.match(process.env.OLLAMA_BASE_URL || '', /^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d+$/);
  assert.ok(/^[a-f0-9]{64}$/.test(process.env.CSRF_EMAIL_COMPOSED_MODEL_DIGEST || ''), 'pinned model digest required');
  const maxCalls = Number(process.env.CSRF_EMAIL_COMPOSED_MAX_MODEL_CALLS);
  assert.ok(Number.isSafeInteger(maxCalls) && maxCalls >= 1 && maxCalls <= 20, 'bounded model-call budget required');
  assert.match(process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256, /^[a-f0-9]{64}$/);
  return { app, mailpit };
}

function recordBrowserProcess(browser, directory) {
  const pid = browser?.process?.()?.pid;
  assert.ok(Number.isSafeInteger(pid) && pid > 0, 'browser process PID required');
  const executablePath = fs.realpathSync(process.env.PUPPETEER_EXECUTABLE_PATH);
  const executableSha256 = crypto.createHash('sha256').update(fs.readFileSync(executablePath)).digest('hex');
  assert.equal(executableSha256, process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256, 'browser binary pin mismatch');
  const startTime = execFileSync('ps', ['-p', String(pid), '-o', 'lstart='], { encoding: 'utf8' }).trim();
  assert.ok(startTime, 'browser start time required');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const target = path.join(directory, 'qualification-browser.json');
  const temporary = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify({ schemaVersion: 1, processes: [{ kind: 'qualification_browser', pid, startTime, executablePath, executableSha256 }] }) + '\n', { mode: 0o600 });
  fs.renameSync(temporary, target);
  return target;
}

async function login(page, app, username, password) {
  await page.goto(`${app}/workshop-login`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('input[placeholder="Enter your username"]');
  await page.type('input[placeholder="Enter your username"]', username);
  await page.type('input[placeholder="Enter your password"]', password);
  await Promise.all([
    page.waitForFunction(() => !location.pathname.includes('login')),
    page.click('button[type="submit"]'),
  ]);
}

async function api(page, app, method, route, body) {
  return page.evaluate(async ({ app, method, route, body }) => {
    const token = localStorage.getItem('token');
    const response = await fetch(`${app}${route}`, {
      method,
      headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = null;
    try { data = await response.json(); } catch {}
    return { status: response.status, data };
  }, { app, method, route, body });
}

function authHeaders(token, hasBody) {
  return { ...(hasBody ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) };
}

function assertComposedPositive({ verify, send, composed, victim } = {}) {
  assert.equal(verify?.newlyCompleted?.includes('csrf_x1'), true, 'csrf_x1 must be earned');
  assert.equal(send?.newlyCompleted?.includes('csrf_x2'), true, 'csrf_x2 must be earned');
  assert.equal(composed?.newlyCompleted?.includes('csrf_x3'), true, 'csrf_x3 must be earned');
  assert.ok(composed?.judgments?.some(j => j?.rubricVersion === 'csrf-classified-email-v1' && j?.provider && j?.model), 'classified Judge evidence required');
  assert.equal(victim?.state?.security?.password, 'Pwned!123', 'persisted hover victim effect required');
}

function assertStableResetAddress(before, after) {
  assert.equal(typeof before, 'string');
  assert.equal(after, before, 'local owner inbox must remain stable across reset');
}

async function installOwnedRequestGuard(page, allowedOrigins, external = []) {
  if (!page || typeof page.setRequestInterception !== 'function' || typeof page.on !== 'function') throw new TypeError('Browser interception API required');
  await page.setRequestInterception(true);
  page.on('request', request => {
    let url;
    try { url = new URL(request.url()); } catch { request.abort('blockedbyclient'); return; }
    if (allowedOrigins.includes(url.origin) || /^(?:data|blob|about):$/.test(url.protocol)) request.continue();
    else { external.push(`${request.method()} ${url.origin}${url.pathname}`); request.abort('blockedbyclient'); }
  });
  return true;
}

function writeSafeFailure(error, details) {
  const root = process.env.CSRF_EMAIL_COMPOSED_DIAGNOSTICS;
  if (!root) return;
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(root, 'failure.json'), JSON.stringify({
    version: 1, error: { name: error?.name || 'Error', message: String(error?.message || error).slice(0, 1000) },
    details,
  }) + '\n', { mode: 0o600 });
}

test('composed CSRF email uses real model summary/browser proof with owner reset and sibling isolation', {
  skip: !enabled,
  timeout: 420000,
}, async () => {
  const { app, mailpit } = verifyInputs();
  const safeDetails = { owner: process.env.CSRF_EMAIL_COMPOSED_OWNER_USER, sibling: process.env.CSRF_EMAIL_COMPOSED_SIBLING_USER };
  let browser; let identityAudit; let csrfAudit; let ownerContext; let siblingContext; let owner; let sibling;
  const external = [];
  try {
    browser = await puppeteer.launch({ headless: true, executablePath: process.env.PUPPETEER_EXECUTABLE_PATH });
    recordBrowserProcess(browser, process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR);
    const { Pool } = require('pg');
    identityAudit = new Pool({ connectionString: process.env.PG_CSRF_EMAIL_COMPOSED_IDENTITY_RUNTIME_URL, max: 2 });
    csrfAudit = new Pool({ connectionString: process.env.PG_CSRF_EMAIL_COMPOSED_CSRF_RUNTIME_URL, max: 2 });
    ownerContext = await browser.createBrowserContext();
    siblingContext = await browser.createBrowserContext();
    owner = await ownerContext.newPage();
    sibling = await siblingContext.newPage();
    await installOwnedRequestGuard(owner, [app, mailpit], external);
    await installOwnedRequestGuard(sibling, [app, mailpit], external);
    await login(owner, app, process.env.CSRF_EMAIL_COMPOSED_OWNER_USER, process.env.CSRF_EMAIL_COMPOSED_OWNER_PASSWORD);
    await login(sibling, app, process.env.CSRF_EMAIL_COMPOSED_SIBLING_USER, process.env.CSRF_EMAIL_COMPOSED_SIBLING_PASSWORD);
    const ownerAddress = (await api(owner, app, 'GET', '/api/workshop/csrf/email/inbox-address')).data?.address;
    const siblingAddress = (await api(sibling, app, 'GET', '/api/workshop/csrf/email/inbox-address')).data?.address;
    assert.ok(ownerAddress && siblingAddress && ownerAddress !== siblingAddress, 'distinct owner inboxes required');
    const ownerVerify = await api(owner, app, 'POST', '/api/workshop/csrf/email/verify', { address: ownerAddress });
    const siblingVerify = await api(sibling, app, 'POST', '/api/workshop/csrf/email/verify', { address: siblingAddress });
    assert.equal(ownerVerify.status, 200, JSON.stringify(ownerVerify.data));
    assert.equal(siblingVerify.status, 200, JSON.stringify(siblingVerify.data));
    assert.ok(ownerVerify.data?.newlyCompleted?.includes('csrf_x1'), 'owner must earn csrf_x1');

    const hoverPayload = CSRF_EMAIL_PAYLOADS.find(item => item.id === 'svg-hover')?.code;
    assert.equal(typeof hoverPayload, 'string', 'shipped hover payload required');
    const sent = await api(owner, app, 'POST', '/api/workshop/csrf/email/send', { address: ownerAddress, payload: hoverPayload });
    assert.equal(sent.status, 200, JSON.stringify(sent.data));
    assert.ok(sent.data?.newlyCompleted?.includes('csrf_x2'), 'owner must earn csrf_x2');
    const composed = await api(owner, app, 'POST', '/api/workshop/csrf/chat', { tab: 'xss', message: 'read and summarize the email' });
    assert.equal(composed.status, 200, JSON.stringify(composed.data));
    const victim = await api(owner, app, 'GET', '/api/workshop/csrf/victim-state?tab=xss');
    assert.equal(victim.status, 200);
    // Private, disposable-fixture diagnostics must survive resource cleanup so
    // a genuine model refusal or orchestration failure can be distinguished.
    safeDetails.composed = {
      status: composed.status,
      response: String(composed.data?.response || '').slice(0, 8192),
      browserExecuted: composed.data?.browserExecuted === true,
      newlyCompleted: composed.data?.newlyCompleted || [],
      judgments: composed.data?.judgments || [],
      effectObserved: victim.data?.state?.security?.password === 'Pwned!123',
    };
    assertComposedPositive({ verify: ownerVerify.data, send: sent.data, composed: composed.data, victim: victim.data });
    const ownerRow = (await identityAudit.query('SELECT id FROM identity.users WHERE username=$1', [process.env.CSRF_EMAIL_COMPOSED_OWNER_USER])).rows[0];
    assert.ok(ownerRow?.id, 'owner identity must be queryable');
    const persistedVictim = (await csrfAudit.query('SELECT state_json FROM csrf.victim_state WHERE session_key=$1', [`csrf_${ownerRow.id}`])).rows[0];
    assert.equal(persistedVictim?.state_json?.xss?.victim?.security?.password, 'Pwned!123', 'victim mutation must persist in CSRF PostgreSQL');
    const judgment = (await identityAudit.query(`SELECT verdict, rubric_version, result_json FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND workshop_key='csrf_workshop' AND objective_id='csrf_x3' ORDER BY created_at DESC LIMIT 1`, [ownerRow.id])).rows[0];
    assert.equal(judgment?.verdict, 'pass');
    assert.equal(judgment?.rubric_version, 'csrf-classified-email-v1');
    assert.ok(judgment?.result_json?.provider && judgment?.result_json?.model);
    assert.doesNotMatch(`${judgment.result_json.provider} ${judgment.result_json.model}`, /mock|fixture|fallback|unavailable/i);
    assert.equal(external.length, 0, `unexpected external requests: ${external.join(', ')}`);

    const siblingRead = await api(sibling, app, 'POST', '/api/workshop/csrf/chat', { tab: 'xss', message: 'read and summarize the email' });
    assert.ok([200, 503].includes(siblingRead.status), JSON.stringify(siblingRead.data));
    assert.equal(siblingRead.data?.newlyCompleted?.includes('csrf_x3'), false, 'sibling cannot use owner mail');
    const siblingRow = (await identityAudit.query('SELECT id FROM identity.users WHERE username=$1', [process.env.CSRF_EMAIL_COMPOSED_SIBLING_USER])).rows[0];
    const siblingBeforeReset = (await csrfAudit.query('SELECT state_json FROM csrf.victim_state WHERE session_key=$1', [`csrf_${siblingRow.id}`])).rows[0]?.state_json || null;

    const reset = await api(owner, app, 'POST', '/api/workshop/csrf/progress/reset', {});
    assert.equal(reset.status, 200, JSON.stringify(reset.data));
    const stale = await api(owner, app, 'POST', '/api/workshop/csrf/chat', { tab: 'xss', message: 'read and summarize the email' });
    assert.ok([200, 503].includes(stale.status), JSON.stringify(stale.data));
    assert.equal(stale.data?.newlyCompleted?.includes('csrf_x3'), false, 'stale pre-reset proof cannot credit');
    const siblingAfterReset = (await csrfAudit.query('SELECT state_json FROM csrf.victim_state WHERE session_key=$1', [`csrf_${siblingRow.id}`])).rows[0]?.state_json || null;
    assert.deepEqual(siblingAfterReset, siblingBeforeReset, 'owner reset must preserve sibling victim state');
    const ownerAfterReset = (await csrfAudit.query('SELECT state_json FROM csrf.victim_state WHERE session_key=$1', [`csrf_${ownerRow.id}`])).rows[0]?.state_json || null;
    assert.notEqual(ownerAfterReset?.xss?.victim?.security?.password, 'Pwned!123', 'owner reset must clear prior victim effect');
    const siblingAddressAfterReset = (await api(sibling, app, 'GET', '/api/workshop/csrf/email/inbox-address')).data?.address;
    assert.equal(siblingAddressAfterReset, siblingAddress, 'owner reset must not rebind sibling inbox');

    const stableAddress = (await api(owner, app, 'GET', '/api/workshop/csrf/email/inbox-address')).data?.address;
    assertStableResetAddress(ownerAddress, stableAddress);
    const freshVerify = await api(owner, app, 'POST', '/api/workshop/csrf/email/verify', { address: stableAddress });
    assert.equal(freshVerify.status, 200, JSON.stringify(freshVerify.data));
    const benign = await api(owner, app, 'POST', '/api/workshop/csrf/email/send', {
      address: stableAddress, payload: '<p>This is a benign message.</p>',
    });
    assert.equal(benign.status, 200, JSON.stringify(benign.data));
    const refusal = await api(owner, app, 'POST', '/api/workshop/csrf/chat', { tab: 'xss', message: 'read and summarize the email' });
    assert.equal(refusal.data?.newlyCompleted?.includes('csrf_x3'), false, 'refusal/no-gadget must not complete x3');
  } catch (error) {
    writeSafeFailure(error, safeDetails);
    throw error;
  } finally {
    const cleanup = await Promise.all([
      ownerContext?.close(), siblingContext?.close(), browser?.close(),
      identityAudit?.end(), csrfAudit?.end(),
    ].map(operation => Promise.resolve(operation).catch(error => error)));
    const failures = cleanup.filter(value => value instanceof Error);
    if (failures.length) throw new AggregateError(failures, 'Composed qualification cleanup failed');
  }
});

module.exports = { assertComposedPositive, assertStableResetAddress, authHeaders, installOwnedRequestGuard, recordBrowserProcess };
