'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const fs = require('node:fs/promises');
const jwt = require('jsonwebtoken');
const path = require('node:path');
const test = require('node:test');

const REPO = path.resolve(__dirname, '../..');
const CLIENT = path.join(REPO, 'client');
const RUNTIME_URL = 'PG_ADMIN_BROWSER_TEST_RUNTIME_URL';
const MIGRATION_URL = 'PG_ADMIN_BROWSER_TEST_MIGRATION_URL';
const RESOURCE_JOURNAL = 'PG_ADMIN_BROWSER_RESOURCE_JOURNAL';
const TEMP_ROOT = 'PG_ADMIN_BROWSER_TEMP_ROOT';
const q05CurrentHost = process.env.ADMIN_Q05_CURRENT_HOST === '1';
const studentResetCurrentHost = q05CurrentHost && process.env.ADMIN_STUDENT_RESET_ONLY === '1';
const enabled = process.env.RUN_ADMIN_PRODUCTION_BROWSER === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env[RUNTIME_URL])
  && Boolean(process.env[MIGRATION_URL])
  && Boolean(process.env[RESOURCE_JOURNAL])
  && Boolean(process.env[TEMP_ROOT])
  && Boolean(process.env.PUPPETEER_EXECUTABLE_PATH);

function assertDisposableUrl(value, name) {
  const parsed = new URL(value);
  assert.ok(['127.0.0.1', 'localhost'].includes(parsed.hostname), `${name} must use loopback PostgreSQL`);
  assert.match(parsed.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/, `${name} must name a disposable database`);
}

async function buildProductionClient(buildDirectory, trackChild) {
  const buildEnvironment = Object.fromEntries(['PATH', 'TMPDIR', 'TMP', 'TEMP']
    .filter(name => process.env[name] !== undefined).map(name => [name, process.env[name]]));
  let child;
  const completed = new Promise((resolve, reject) => {
    child = execFile(process.execPath, [
      path.join(CLIENT, 'node_modules/vite/bin/vite.js'),
      'build',
      '--config', path.join(CLIENT, 'vite.config.mjs'),
      '--configLoader', 'native',
      '--outDir', buildDirectory,
      '--emptyOutDir',
    ], {
      cwd: CLIENT,
      env: { ...buildEnvironment, BROWSERSLIST_IGNORE_OLD_DATA: '1', CI: 'false' },
      maxBuffer: 10 * 1024 * 1024,
      timeout: 120000,
      detached: true,
    }, error => error ? reject(error) : resolve());
  });
  await trackChild(child);
  await completed;
  assert.equal(await fs.stat(path.join(buildDirectory, 'index.html')).then(() => true, () => false), true,
    'production build must contain index.html');
}

function processExists(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

function processGroupExists(pgid) {
  if (!Number.isSafeInteger(pgid) || pgid <= 0 || process.platform === 'win32') return false;
  try { process.kill(-pgid, 0); return true; } catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

async function assertProcessGroupAbsent(pgid, label) {
  if (!Number.isSafeInteger(pgid) || pgid <= 0) return;
  const deadline = Date.now() + 5000;
  while (processExists(pgid) || processGroupExists(pgid)) {
    if (Date.now() >= deadline) throw new Error(`${label} process group ${pgid} remains alive`);
    await new Promise(resolve => setTimeout(resolve, 50));
  }
}

async function stopProcessGroup(child) {
  if (!child?.pid) return;
  if (processGroupExists(child.pid)) {
    try { process.kill(-child.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    const deadline = Date.now() + 5000;
    while (processGroupExists(child.pid) && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    if (processGroupExists(child.pid)) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    }
  }
  await assertProcessGroupAbsent(child.pid, 'owned build');
}

async function closeBrowserBounded(browser, browserPid) {
  if (!browser) return;
  const closed = await Promise.race([
    browser.close().then(() => true),
    new Promise(resolve => setTimeout(() => resolve(false), 5000)),
  ]);
  if (closed) return;
  if (processExists(browserPid)) {
    try { process.kill(browserPid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
  const deadline = Date.now() + 2000;
  while (processExists(browserPid) && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  if (processExists(browserPid)) {
    try { process.kill(browserPid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
}

async function writeJsonDurable(file, value) {
  const temporary = `${file}.tmp-${process.pid}`;
  const handle = await fs.open(temporary, 'w', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temporary, file);
  const directory = await fs.open(path.dirname(file), 'r');
  try { await directory.sync(); } finally { await directory.close(); }
}

function operationalUnavailable(_req, res) {
  res.status(503).json({ error: 'Not part of the bounded admin browser qualification' });
}

async function closeServer(server, { q05 = false } = {}) {
  if (!server?.listening) return;
  if (q05) return require('./adminQ05RenderedScenario').closeQ05OwnedServer(server);
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

async function bodyText(page) {
  return page.evaluate(() => document.body.innerText);
}

async function waitForText(page, expected, timeout = 15000) {
  await page.waitForFunction(value => document.body.innerText.includes(value), { timeout }, expected);
}

function responsePath(response, expected, method = 'GET') {
  return new URL(response.url()).pathname === expected && response.request().method() === method;
}

function assertConditionalBrowserRead(response, label) {
  assert.equal(response.request().method(), 'GET', `${label} must remain a browser GET`);
  assert.ok([200, 304].includes(response.status()),
    `${label} must return content or a valid conditional cache response`);
}

async function requestJson(base, pathname, token, { method = 'GET', body } = {}) {
  const response = await fetch(`${base}${pathname}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const value = await response.json();
  return { status: response.status, body: value };
}

function mcpCardMatches(expectedCompleted, expectedTotal, requiredTexts = [], forbiddenTexts = [], root = document) {
  const normalize = value => String(value || '').replace(/\s+/g, ' ').trim();
  const title = [...root.querySelectorAll('*')]
    .find(node => node.children.length === 0 && normalize(node.textContent) === 'MCP Server Lab');
  if (!title) return false;
  const card = title.parentElement?.parentElement?.parentElement;
  if (!card) return false;
  const expected = new RegExp(
    `(^|[^0-9])${expectedCompleted}\\s*\\/\\s*${expectedTotal}([^0-9]|$)`,
    'i',
  );
  const text = card.innerText || card.textContent || '';
  const exactTexts = [...card.querySelectorAll('*')].map(node => normalize(node.textContent));
  return expected.test(text)
    && requiredTexts.every(value => exactTexts.includes(normalize(value)))
    && forbiddenTexts.every(value => !exactTexts.includes(normalize(value)));
}

function mcpObjectiveStylesMatch(completedLabel, incompleteLabel, completedVisible = true, root = document) {
  const normalize = value => String(value || '').replace(/\s+/g, ' ').trim();
  const title = [...root.querySelectorAll('*')]
    .find(node => node.children.length === 0 && normalize(node.textContent) === 'MCP Server Lab');
  const card = title?.parentElement?.parentElement?.parentElement;
  if (!card) return false;
  const exactLeaf = value => [...card.querySelectorAll('*')]
    .find(node => node.children.length === 0 && normalize(node.textContent) === normalize(value));
  const completed = exactLeaf(completedLabel);
  if (!completedVisible) return !completed;
  const incomplete = exactLeaf(incompleteLabel);
  const completedRow = completed?.parentElement?.parentElement;
  const incompleteRow = incomplete?.parentElement?.parentElement;
  const completedIcon = completedRow?.querySelector('svg');
  const incompleteIcon = incompleteRow?.querySelector('svg');
  if (!completedRow || !incompleteRow || !completedIcon || !incompleteIcon) return false;
  const view = root.defaultView || window;
  return view.getComputedStyle(completedRow).color === 'rgb(45, 106, 79)'
    && view.getComputedStyle(completedIcon).color === 'rgb(40, 167, 69)'
    && view.getComputedStyle(incompleteRow).color === 'rgb(74, 85, 104)'
    && view.getComputedStyle(incompleteIcon).color === 'rgb(160, 174, 192)';
}

function mcpAdminModalMatches(expectedObjectiveIds, hintEnabled, solutionEnabled, root = document) {
  const normalize = value => String(value || '').replace(/\s+/g, ' ').trim();
  const heading = [...root.querySelectorAll('h3')]
    .find(node => normalize(node.textContent) === 'Objectives — MCP Server Lab');
  const modal = heading?.parentElement?.parentElement;
  if (!modal) return false;
  const ids = [...modal.querySelectorAll('*')]
    .filter(node => node.children.length === 0 && /^mcp_[a-z0-9_]+$/.test(normalize(node.textContent)))
    .map(node => normalize(node.textContent));
  if (ids.length !== expectedObjectiveIds.length
      || ids.some((value, index) => value !== expectedObjectiveIds[index])) return false;
  const reconId = [...modal.querySelectorAll('*')]
    .find(node => node.children.length === 0 && normalize(node.textContent) === 'mcp_recon');
  const row = reconId?.parentElement?.parentElement;
  if (!row || row.children.length !== 5) return false;
  const visibleToggle = row.children[1]?.firstElementChild;
  const hintToggle = row.children[2]?.firstElementChild;
  const solutionToggle = row.children[3]?.firstElementChild;
  if (!visibleToggle || !hintToggle || !solutionToggle) return false;
  const view = root.defaultView || window;
  return view.getComputedStyle(visibleToggle).backgroundColor === 'rgb(72, 187, 120)'
    && view.getComputedStyle(hintToggle).backgroundColor === (hintEnabled
      ? 'rgb(72, 187, 120)'
      : 'rgb(203, 213, 224)')
    && view.getComputedStyle(solutionToggle).backgroundColor === (solutionEnabled
      ? 'rgb(72, 187, 120)'
      : 'rgb(203, 213, 224)');
}

function clickMcpManageObjectives(root = document) {
  const normalize = value => String(value || '').replace(/\s+/g, ' ').trim();
  const title = [...root.querySelectorAll('h3')]
    .find(node => normalize(node.textContent) === 'MCP Server Lab');
  const card = title?.parentElement?.parentElement?.parentElement;
  const button = [...(card?.querySelectorAll('button') || [])]
    .find(node => normalize(node.textContent) === 'Manage Objectives');
  if (!button) return false;
  button.click();
  return true;
}

function mcpAdminCardControlsMatch(active, hints, solutions, root = document) {
  const card = root.querySelector('[data-exercise-key="mcp_server_rce"]');
  if (!card) return false;
  const view = root.defaultView || window;
  const enabledColor = 'rgb(72, 187, 120)';
  const disabledColor = 'rgb(203, 213, 224)';
  return [
    ['active', active],
    ['hints', hints],
    ['solutions', solutions],
  ].every(([control, enabled]) => {
    const toggle = card.querySelector(`[data-control="${control}"]`);
    return toggle && toggle.getAttribute('aria-disabled') !== 'true'
      && view.getComputedStyle(toggle).backgroundColor === (enabled ? enabledColor : disabledColor);
  });
}

function clickMcpCardControl(control, root = document) {
  const toggle = root.querySelector(
    `[data-exercise-key="mcp_server_rce"] [data-control="${control}"]`,
  );
  if (!toggle || toggle.getAttribute('aria-disabled') === 'true') return false;
  toggle.click();
  return true;
}

function clickMcpReconSolution(root = document) {
  const normalize = value => String(value || '').replace(/\s+/g, ' ').trim();
  const heading = [...root.querySelectorAll('h3')]
    .find(node => normalize(node.textContent) === 'Objectives — MCP Server Lab');
  const modal = heading?.parentElement?.parentElement;
  const reconId = [...(modal?.querySelectorAll('*') || [])]
    .find(node => node.children.length === 0 && normalize(node.textContent) === 'mcp_recon');
  const solutionToggle = reconId?.parentElement?.parentElement?.children[3]?.firstElementChild;
  if (!solutionToggle) return false;
  solutionToggle.click();
  return true;
}

function clickMcpReconHint(root = document) {
  const normalize = value => String(value || '').replace(/\s+/g, ' ').trim();
  const heading = [...root.querySelectorAll('h3')]
    .find(node => normalize(node.textContent) === 'Objectives — MCP Server Lab');
  const modal = heading?.parentElement?.parentElement;
  const reconId = [...(modal?.querySelectorAll('*') || [])]
    .find(node => node.children.length === 0 && normalize(node.textContent) === 'mcp_recon');
  const hintToggle = reconId?.parentElement?.parentElement?.children[2]?.firstElementChild;
  if (!hintToggle) return false;
  hintToggle.click();
  return true;
}

function mcpObjectiveHelpControlsMatch(objectiveLabel, hintVisible, solutionVisible, root = document) {
  const normalize = value => String(value || '').replace(/\s+/g, ' ').trim();
  const title = [...root.querySelectorAll('*')]
    .find(node => node.children.length === 0 && normalize(node.textContent) === 'MCP Server Lab');
  const card = title?.parentElement?.parentElement?.parentElement;
  const objective = [...(card?.querySelectorAll('*') || [])]
    .find(node => node.children.length === 0 && normalize(node.textContent) === normalize(objectiveLabel));
  const row = objective?.parentElement?.parentElement;
  if (!row) return false;
  const controls = [...row.querySelectorAll('button')].map(node => normalize(node.textContent));
  return controls.includes('Hint') === hintVisible && controls.includes('Solution') === solutionVisible;
}

async function waitForRenderedMcpCount(page, completed, total) {
  // All three current views render the title three levels below the exercise
  // card. The shared helper keeps counts/text inside that exact card.
  await page.waitForFunction(mcpCardMatches, {}, completed, total);
}

async function studentViewOptions(page) {
  return page.evaluate(() => {
    const heading = [...document.querySelectorAll('h2')]
      .find(node => node.textContent.includes('Student Workshop View'));
    const root = heading?.parentElement?.parentElement;
    return [...(root?.querySelectorAll('select option') || [])]
      .map(node => ({ value: node.value, text: node.textContent }));
  });
}

async function selectStudentInView(page, studentId) {
  await page.evaluate(value => {
    const heading = [...document.querySelectorAll('h2')]
      .find(node => node.textContent.includes('Student Workshop View'));
    const select = heading?.parentElement?.parentElement?.querySelector('select');
    if (!select) throw new Error('Student Workshop View selector unavailable');
    select.value = String(value);
    select.dispatchEvent(new Event('change', { bubbles: true }));
  }, studentId);
}

async function refreshStudentView(page) {
  await page.evaluate(() => {
    const heading = [...document.querySelectorAll('h2')]
      .find(node => node.textContent.includes('Student Workshop View'));
    const button = [...(heading?.parentElement?.querySelectorAll('button') || [])]
      .find(node => node.textContent.trim() === 'Refresh');
    if (!button) throw new Error('Student Workshop View refresh unavailable');
    button.click();
  });
}

test('production admin UI uses durable PostgreSQL auth and responds to delegated permission changes', {
  skip: !enabled,
  timeout: process.env.ADMIN_STUDENT_RESET_ONLY === '1' || q05CurrentHost ? 480000 : 240000,
}, async t => {
  assertDisposableUrl(process.env[RUNTIME_URL], RUNTIME_URL);
  assertDisposableUrl(process.env[MIGRATION_URL], MIGRATION_URL);
  const runtimeUrl = new URL(process.env[RUNTIME_URL]);
  const migrationUrl = new URL(process.env[MIGRATION_URL]);
  assert.equal(runtimeUrl.pathname, migrationUrl.pathname, 'runtime and migration roles must target one database');
  assert.notEqual(runtimeUrl.username, migrationUrl.username,
    'runtime and migration URLs must use distinct least-privilege roles');
  const journalPath = path.resolve(process.env[RESOURCE_JOURNAL]);
  const requestedTempRoot = path.resolve(process.env[TEMP_ROOT]);
  const q05 = q05CurrentHost
    ? require('./adminQ05RenderedScenario').admitQ05({ env: process.env, repo: REPO,
      journalPath, tempRoot: requestedTempRoot,
      expectedCohort: studentResetCurrentHost
        ? 'admin-student-reset-current-host' : 'admin-q05-current-host' }) : null;
  assert.equal(process.env[RESOURCE_JOURNAL], journalPath, `${RESOURCE_JOURNAL} must be absolute`);
  assert.equal(process.env[TEMP_ROOT], requestedTempRoot, `${TEMP_ROOT} must be absolute`);
  assert.equal(path.dirname(requestedTempRoot), path.dirname(journalPath),
    'owned runtime root and resource journal must share the launcher evidence directory');

  let tempRoot;
  let runtime;
  let migration;
  let browser;
  let browserPid;
  let server;
  let authRouter;
  let sessionManager;
  let resetSupport;
  let qualificationCompleted = false;
  const buildChildren = [];
  const journal = {
    version: 1,
    status: 'initializing',
    database: {
      name: runtimeUrl.pathname.slice(1),
      runtimeRole: decodeURIComponent(runtimeUrl.username),
      migrationRole: decodeURIComponent(migrationUrl.username),
    },
    resources: {},
    externalCleanupAuthority: 'launcher-owned-test-process-group-and-database',
    cleanup: [],
  };
  const persistJournal = () => writeJsonDurable(journalPath, journal);
  t.after(async () => {
    const errors = [];
    for (const [name, cleanup] of [
      ['browser-close', async () => {
        if (q05) {
          browser?.disconnect();
          browser?.process()?.unref();
        }
        else await closeBrowserBounded(browser, browserPid);
      }],
      ['browser-root-absence', async () => {
        if (q05) return;
        if (processExists(browserPid)) throw new Error(`owned browser root process ${browserPid} remains alive`);
      }],
      ['server-close', async () => closeServer(server, { q05 })],
      ['auth-router-close', async () => authRouter?.close()],
      ['session-cleanup-stop', async () => sessionManager?.stopCleanupTask()],
      ...buildChildren.map(child => [`build-process-group-${child.pid}`, async () => stopProcessGroup(child)]),
      ['reset-support-close', async () => resetSupport?.close()],
      ['runtime-pool-close', async () => runtime?.end()],
      ['migration-pool-close', async () => migration?.end()],
    ]) {
      try {
        await cleanup();
        journal.cleanup.push({ name, ok: true });
      } catch (error) {
        errors.push(error);
        journal.cleanup.push({ name, ok: false, error: error.message });
      }
    }
    if (errors.length) {
      journal.status = 'cleanup_failed';
      journal.testBody = qualificationCompleted ? 'passed' : 'failed';
      await persistJournal();
      t.diagnostic(`retained qualification artifacts after cleanup failure: ${tempRoot || 'not-created'}`);
      throw new AggregateError(errors, 'admin browser qualification cleanup failed');
    }
    if (tempRoot && !q05) {
      await fs.rm(tempRoot, { recursive: true, force: true });
      assert.equal(await fs.stat(tempRoot).then(() => true, error => error.code !== 'ENOENT'), false,
        'owned browser runtime root must be absent after cleanup');
    }
    journal.status = q05 ? 'browser_cleanup_delegated_to_current_host_launcher' : 'cleanup_complete';
    journal.testBody = qualificationCompleted ? 'passed' : 'failed';
    journal.tempRootAbsent = q05 ? false : true;
    await persistJournal();
  });

  assert.equal(await fs.stat(requestedTempRoot).then(() => true, error => error.code !== 'ENOENT'), false,
    `${TEMP_ROOT} must start absent`);
  tempRoot = requestedTempRoot;
  const buildDirectory = path.join(tempRoot, 'build');
  const profileDirectory = path.join(tempRoot, 'chromium-profile');
  journal.resources = { tempRoot, buildDirectory, profileDirectory };
  journal.status = 'paths_recorded';
  await persistJournal();
  await fs.mkdir(tempRoot, { recursive: false, mode: 0o700 });
  journal.status = 'runtime_root_created';
  await persistJournal();
  const { createPool } = require('../../server/database/postgres');
  runtime = createPool(process.env, RUNTIME_URL, process.env.ADMIN_STUDENT_RESET_ONLY === '1'
    ? { purpose: 'control' } : {});
  migration = createPool(process.env, MIGRATION_URL);

  const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
  const { createWorkshopProgressRepository } = require('../../server/database/postgres/workshopProgressRepository');
  const { createWorkshopConfigRepository } = require('../../server/database/postgres/workshopConfigRepository');
  assert.equal((await migration.query("SELECT to_regnamespace('identity') AS schema")).rows[0].schema, null,
    'admin browser qualification requires a fresh disposable identity database');
  await initializeIdentityRepository(runtime, migration);
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);

  const identity = createIdentityRepository(runtime);
  const progress = createWorkshopProgressRepository(runtime);
  const config = createWorkshopConfigRepository(runtime, { isSecureShopReady: () => false });
  const jwtSecret = 'owned-admin-browser-jwt-secret-at-least-32-bytes';
  const adminPassword = 'AdminBrowserFixture123!';
  const studentPassword = 'StudentBrowserFixture123!';
  const [adminHash, studentHash] = await Promise.all([
    require('bcryptjs').hash(adminPassword, 4),
    require('bcryptjs').hash(studentPassword, 4),
  ]);
  const admin = await identity.createUser({
    username: 'rendered-admin', email: 'rendered-admin@example.invalid', passwordHash: adminHash,
  });
  await migration.query("UPDATE identity.users SET role='admin',admin_level=$2,email_verified=1 WHERE id=$1",
    [admin.id, q05 && !studentResetCurrentHost ? 2 : 1]);
  const firstStudent = await identity.createUser({
    username: 'isolated-student-one', email: 'student-one@example.invalid', passwordHash: studentHash,
  });
  const secondStudent = await identity.createUser({
    username: 'isolated-student-two', email: 'student-two@example.invalid', passwordHash: studentHash,
  });
  for (const permission of ['manage_progress', 'user_management', 'view_analytics', 'challenge_management']) {
    await identity.grantPermission({ userId: admin.id, permission, grantedBy: admin.id });
  }

  // Controlled projection data distinguishes the two owners. Objective authenticity
  // and Judge behavior are outside this browser/authentication qualification.
  const mcpObjectives = require('../../server/config/workshopCatalog').WORKSHOP_OBJECTIVES.mcp_workshop;
  const mcpObjectiveIds = mcpObjectives.map(objective => objective.id);
  const mcpReconLabel = mcpObjectives.find(objective => objective.id === 'mcp_recon').text;
  const mcpIncompleteLabel = mcpObjectives.find(objective => objective.id === 'mcp_cmd_injection').text;
  assert.deepEqual(mcpObjectiveIds, [
    'mcp_recon', 'mcp_cmd_injection', 'mcp_ssrf', 'mcp_tool_poisoning',
    'mcp_indirect_injection', 'mcp_confused_deputy', 'mcp_broken_authz',
    'mcp_secret_exposure', 'mcp_supply_chain', 'mcp_audit_gap', 'mcp_shadow_server',
  ]);
  const firstProjection = await progress.getVisibleUserProgress(firstStudent.id);
  const secureShopWorkshopKey = require('../../server/config/secureshopCurriculum').WORKSHOP_KEY;
  const completedWorkshop = firstProjection.find(row => ![secureShopWorkshopKey, 'mcp_workshop', ...(process.env.ADMIN_STUDENT_RESET_ONLY === '1' ? ['sensitive_info_disclosure'] : [])].includes(row.workshopKey)
    && row.objectiveCount > 0);
  assert.ok(completedWorkshop, 'a visible non-SecureShop workshop is required for isolation proof');
  for (const objective of completedWorkshop.objectives) {
    await progress.syncObjectiveComplete(firstStudent.id, completedWorkshop.workshopKey, objective.id);
  }
  // Projection-only fixture: the native MCP SDK/actor/Judge cohort separately
  // proves the real mcp_recon award. This controlled write qualifies only the
  // canonical learner/instructor read paths and visibility behavior below.
  await progress.syncObjectiveComplete(firstStudent.id, 'mcp_workshop', 'mcp_recon');
  const heartbeatStart = Date.UTC(2026, 8, 15, 12, 0, 0);
  assert.deepEqual(await progress.recordHeartbeat({
    userId: firstStudent.id,
    workshopKey: 'mcp_workshop',
    now: heartbeatStart,
  }), { added: 0, newSession: true });
  assert.deepEqual(await progress.recordHeartbeat({
    userId: firstStudent.id,
    workshopKey: 'mcp_workshop',
    now: heartbeatStart + 37_000,
  }), { added: 37, newSession: false });
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count FROM workshop_platform.completions
    WHERE user_id=$1 AND workshop_key='mcp_workshop' AND objective_id='mcp_recon'`, [firstStudent.id])).rows[0].count, 1);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count FROM workshop_platform.completions
    WHERE user_id=$1 AND workshop_key='mcp_workshop' AND objective_id='mcp_recon'`, [secondStudent.id])).rows[0].count, 0);
  assert.equal((await runtime.query(`SELECT COALESCE(sum(duration_seconds),0)::integer AS seconds
    FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key='mcp_workshop'`, [firstStudent.id])).rows[0].seconds, 37);
  assert.equal((await runtime.query(`SELECT COALESCE(sum(duration_seconds),0)::integer AS seconds
    FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key='mcp_workshop'`, [secondStudent.id])).rows[0].seconds, 0);
  await identity.recordAudit({ userId: firstStudent.id, actionType: 'admin_browser_student_fixture', details: {} });

  const { ownerKey, createPostgresAgentRunReadRepository } = require('../../server/database/postgres/agentRunReadRepository');
  const runId = crypto.randomUUID();
  const siblingRunId = crypto.randomUUID();
  const runOwner = ownerKey('ARIA', firstStudent.id);
  const siblingRunOwner = ownerKey('ARIA', secondStudent.id);
  await runtime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1),($2)', [runOwner, siblingRunOwner]);
  await runtime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,last_node)
    VALUES($1,$2,0,'running','fixture_wait')`, [runId, runOwner]);
  await runtime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,last_node)
    VALUES($1,$2,0,'completed','sibling_complete')`, [siblingRunId, siblingRunOwner]);
  await runtime.query(`INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata)
    VALUES($1,$2,1,'fixture_start','node_end','{}')`, [runId, runOwner]);
  await runtime.query(`INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata)
    VALUES($1,$2,1,'sibling_start','node_end','{}')`, [siblingRunId, siblingRunOwner]);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count FROM graph_runtime.owners
    WHERE owner_key LIKE $1`, ['["SecureShopBoundConversation",%'])).rows[0].count, 0,
  'single-store browser fixture must contain no SecureShop conversation owners');

  // This record qualifies durable receipt projection only. An inconclusive verdict
  // and explicit fixture provider prevent it from representing objective or model proof.
  const evaluationId = crypto.randomUUID();
  const evidenceDigest = crypto.createHash('sha256').update('controlled-admin-browser-receipt').digest('hex');
  const controlledReceiptExplanation = 'Controlled persisted receipt; no model evaluation was performed.';
  await runtime.query(`INSERT INTO workshop_platform.objective_judgments
    (user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,
      run_id,generation,verdict,result_json,disposition,evaluated_at)
    VALUES($1,$2,$3,$4,'ARIA','browser_receipt_projection','controlled-browser-v1',$5,
      $6,0,'inconclusive',$7::jsonb,'not_pass',clock_timestamp())`, [
    firstStudent.id, evaluationId, completedWorkshop.workshopKey, completedWorkshop.objectives[0].id,
    evidenceDigest, runId, JSON.stringify({
      verdict: 'inconclusive',
      explanation: controlledReceiptExplanation,
      criteria: [{ id: 'projection_fixture', satisfied: false, evidenceRefs: [] }],
      provider: 'controlled-fixture',
      model: 'none',
      attempts: 0,
      durationMs: 0,
      usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
    }),
  ]);

  if (q05) {
    await q05.verifyBuild();
    journal.resources.build = { existingArtifact: q05.buildDirectory, sha256: q05.buildSha256,
      noBuildExecuted: true };
    journal.status = 'existing_build_verified';
    await persistJournal();
  } else {
    await buildProductionClient(buildDirectory, async child => {
      buildChildren.push(child);
      journal.resources.build = { pid: child.pid, pgid: child.pid };
      journal.status = 'build_started';
      await persistJournal();
    });
    journal.resources.build.exitCode = 0;
    journal.status = 'build_complete';
    await persistJournal();
  }
  const { createPostgresIdentityAdapter } = require('../../server/services/postgresIdentityAdapter');
  const { createPostgresAdminAuth } = require('../../server/middleware/postgresAdminAuth');
  const { createPostgresSessionManager } = require('../../server/middleware/postgresSessionManager');
  const { createPostgresAuthRouter } = require('../../server/routes/postgresAuth');
  const { createPostgresAdminRouter } = require('../../server/routes/postgresAdmin');
  const { createPostgresWorkshopRouter } = require('../../server/routes/postgresWorkshop');
  const { createPostgresAdminRepository } = require('../../server/database/postgres/adminRepository');
  const { createAgentRunsRouter } = require('../../server/routes/agentRuns');
  const { createWorkshopConfigRouter } = require('../../server/routes/workshopConfig');
  const { createChangeRevisionsRouter } = require('../../server/routes/changeRevisions');
  const { createWorkshopRevisionStore } = require('../../server/database/postgres/workshopRevisionRepository');
  const ownershipLookupOwners = [];
  const secureShopOwnership = require('../helpers/excludedSecureShopOwnership').createExcludedSecureShopOwnership({
    onListOwned: ownerId => ownershipLookupOwners.push(ownerId),
  });
  const agentRunRepository = createPostgresAgentRunReadRepository(runtime, { secureShopOwnership });
  const judgmentRepository = require('../../server/database/postgres/objectiveJudgmentRepository')
    .createObjectiveJudgmentRepository(runtime);
  const adapter = createPostgresIdentityAdapter({ repository: identity, progress, jwtSecret });
  const adminAuth = createPostgresAdminAuth(adapter);
  const adminRepository = createPostgresAdminRepository(runtime);
  sessionManager = createPostgresSessionManager(adapter);
  const pass = (_req, _res, next) => next();
  authRouter = createPostgresAuthRouter({
    adapter,
    limiters: { loginRateLimiter: pass, registerRateLimiter: pass, passwordResetRateLimiter: pass },
  });
  const operational = Object.fromEntries([
    'providerStatus', 'switchProvider', 'configureProvider', 'testProvider', 'testLlm',
    'appLogs', 'llmLogs', 'logStats', 'systemMonitoring',
  ].map(name => [name, operationalUnavailable]));
  let resetService = {
    resetAll: async () => { throw new Error('outside bounded qualification'); },
    resetStudent: async () => { throw new Error('outside bounded qualification'); },
    resetAdministrativeStudent: async () => { throw new Error('outside bounded qualification'); },
    resetWorkshop: async () => { throw new Error('outside bounded qualification'); },
  };
  if (process.env.ADMIN_STUDENT_RESET_ONLY === '1') {
    resetSupport = await require('./adminStudentResetRecoverySupport').createResetSupport({
      runtime, migration, progress, appDataRoot: path.join(tempRoot, 'reset-resources'),
    });
    resetService = resetSupport.resetService;
  }
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());
  const q05AckLoss = { armed: null, drops: [], invalidDrops: [] };
  const q05AccountAccessReceived = [];
  const q05DeactivationReceived = [];
  const armQ05AckLoss = (method, endpoint) => {
    assert(q05 && !q05AckLoss.armed);
    assert((method === 'PUT' && /^\/api\/admin\/administrators\/[1-9]\d*$/.test(endpoint))
      || (method === 'DELETE' && /^\/api\/admin\/administrators\/[1-9]\d*$/.test(endpoint))
      || (method === 'POST' && /^\/api\/admin\/users\/[1-9]\d*\/unlock$/.test(endpoint)),
    'Only the three exact Q05 acknowledgement-loss routes may be armed');
    q05AckLoss.armed = { method, endpoint };
    if (method === 'DELETE') return () => ({
      received: q05DeactivationReceived.filter(path => path === endpoint).length,
      armed: q05AckLoss.armed?.method === method && q05AckLoss.armed?.endpoint === endpoint,
      validDrops: q05AckLoss.drops.filter(drop => drop.method === method && drop.path === endpoint).length,
      invalidDrops: q05AckLoss.invalidDrops.filter(drop => drop.method === method && drop.path === endpoint).length,
      validStatus200: q05AckLoss.drops.some(drop => drop.method === method
        && drop.path === endpoint && drop.status === 200),
    });
  };
  if (q05) app.use((req, res, next) => {
    if (req.method === 'POST' && /^\/api\/admin\/users\/[1-9]\d*\/(lock|unlock)$/.test(req.originalUrl))
      q05AccountAccessReceived.push(req.originalUrl);
    if (req.method === 'DELETE' && /^\/api\/admin\/administrators\/[1-9]\d*$/.test(req.originalUrl))
      q05DeactivationReceived.push(req.originalUrl);
    const armed = q05AckLoss.armed;
    if (!armed || req.method !== armed.method || req.originalUrl !== armed.endpoint) return next();
    if (req.method === 'DELETE') {
      require('./adminQ05RenderedScenario').installQ05DeactivationAckObserver(
        req, res, req.originalUrl, result => {
          q05AckLoss.armed = null;
          if (result.valid) q05AckLoss.drops.push({ method: req.method, path: req.originalUrl,
            phase: 'after-real-http-200-before-browser-consumption', ...result.fact });
          else q05AckLoss.invalidDrops.push({ method: req.method, path: req.originalUrl,
            reason: result.reason });
        });
      return next();
    }
    // Test-only one-shot response discard at the final HTTP write. The mounted
    // repository/route has already returned; the browser cannot see an ACK.
    res.end = function discardOneAcknowledgement() {
      q05AckLoss.armed = null;
      const dropped = { method: req.method, path: req.originalUrl,
        phase: 'after-mounted-handler-before-response' };
      q05AckLoss.drops.push(dropped);
      req.socket.destroy();
      return this;
    };
    next();
  });
  app.use(session({ secret: 'owned-admin-browser-express-session-secret', resave: false, saveUninitialized: false }));
  app.use(sessionManager.middleware());
  app.use('/api/auth', authRouter);
  app.use('/api/workshop/config', createWorkshopConfigRouter(config));
  app.use('/api/workshop', createPostgresWorkshopRouter({
    stores: { pool: runtime, progress, config },
    authenticateToken: adminAuth.authenticateToken,
    requirePermission: adminAuth.requirePermission,
    accountRepository: adminRepository,
    resetService,
  }));
  app.use('/api/changes', createChangeRevisionsRouter({
    store: createWorkshopRevisionStore(runtime),
    authenticateToken: adminAuth.authenticateToken,
  }));
  let failAgentEventPolling = false;
  let failJudgmentRefresh = false;
  app.get('/api/admin/agent-runs/:runId/events', adminAuth.authenticateToken,
    adminAuth.requirePermission('view_analytics'), (req, res, next) => {
      if (!failAgentEventPolling) return next();
      return res.status(503).json({ error: 'Controlled polling outage' });
    });
  app.use('/api/admin/agent-runs', createAgentRunsRouter({
    repository: agentRunRepository,
    authenticateToken: adminAuth.authenticateToken,
    requirePermission: adminAuth.requirePermission,
    admin: true,
    receiptAdapters: {},
    getGraphDefinition: () => ({ nodes: [{ id: 'fixture_start' }], edges: [] }),
  }));
  app.get('/api/agent-runs/judgments', adminAuth.authenticateToken, (req, res, next) => {
    if (!failJudgmentRefresh) return next();
    return res.status(503).json({ error: 'Controlled judgment refresh outage' });
  });
  app.use('/api/agent-runs', createAgentRunsRouter({
    repository: agentRunRepository,
    authenticateToken: adminAuth.authenticateToken,
    receiptAdapters: {},
    listJudgments: userId => judgmentRepository.listRecoverable({
      userId,
      judgeVersion: 'controlled-browser-v1',
    }),
    getGraphDefinition: () => ({ nodes: [{ id: 'fixture_start' }], edges: [] }),
  }));
  app.use('/api/admin', createPostgresAdminRouter({
    adapter,
    stores: { pool: runtime, progress, config },
    auth: adminAuth,
    repository: adminRepository,
    resetService,
    operational,
    deletionService: { deleteStudent: async () => { throw new Error('outside bounded qualification'); } },
  }));
  const servedBuild = q05?.buildDirectory || buildDirectory;
  app.use(express.static(servedBuild, { index: false }));
  app.get(/.*/, (_req, res) => res.sendFile('index.html', { root: servedBuild }));
  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  journal.resources.server = { address: '127.0.0.1', port };
  journal.status = 'server_listening';
  await persistJournal();

  // A valid signature alone is not authentication: the mounted middleware must
  // also resolve the nonce-backed durable session row for both status and APIs.
  const unpersistedToken = jwt.sign({ userId: admin.id }, jwtSecret, { algorithm: 'HS256', expiresIn: '1h' });
  const forgedStatus = await fetch(`${base}/api/auth/status`, {
    headers: { authorization: `Bearer ${unpersistedToken}` },
  });
  assert.equal(forgedStatus.status, 200);
  assert.equal((await forgedStatus.json()).authenticated, false);
  assert.equal((await fetch(`${base}/api/admin/users`, {
    headers: { authorization: `Bearer ${unpersistedToken}` },
  })).status, 401, 'validly signed JWT without a persisted session must not authorize an admin API');

  if (q05) journal.q05LaunchGrant = await q05.consumeLaunchGrant(profileDirectory);
  browser = await require('puppeteer').launch({
    headless: true,
    userDataDir: profileDirectory,
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH,
    args: q05 ? [
      '--no-sandbox', '--disable-background-networking', '--disable-component-update',
      '--disable-domain-reliability', '--disable-quic',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--proxy-server=http://blocked.invalid:9',
      '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]',
    ] : ['--no-sandbox'],
    ...(q05 ? { handleSIGINT: false, handleSIGTERM: false, handleSIGHUP: false } : {}),
  });
  browserPid = browser.process()?.pid;
  assert.ok(Number.isSafeInteger(browserPid) && browserPid > 0, 'owned browser PID must be observable');
  journal.resources.browser = q05
    ? { pid: browserPid, profileDirectory,
      executablePath: process.env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE }
    : { pid: browserPid };
  journal.status = 'browser_launched';
  await persistJournal();
  if (q05) await q05.awaitBrowserAck(browserPid, profileDirectory);
  const q05UnexpectedTargets = [];
  const q05Targets = q05 ? require('./adminQ05RenderedScenario').q05PageTargets(target => {
    q05UnexpectedTargets.push(target.type());
    if (target.type() === 'page') void target.page().then(other => other?.close()).catch(() => {});
    else void browser.disconnect().catch(() => {});
  }) : null;
  if (q05) browser.on('targetcreated', target => q05Targets.observe(target));
  const page = await browser.newPage();
  if (q05) assert(q05Targets.mainIs(page.target()),
    'Only the owned rendered main page may precede request interception');
  const pageErrors = [];
  const requestedPaths = [];
  const blockedOrigins = [];
  // Retain only paths/status, never tokens, request bodies or passwords.
  page.on('response', response => {
    const url = new URL(response.url());
    if (url.origin === base && url.pathname.startsWith('/api/'))
      t.diagnostic(`HTTP ${response.status()} ${url.pathname}`);
  });
  page.on('pageerror', error => pageErrors.push(error.message));
  await page.setRequestInterception(true);
  page.on('request', request => {
    let target;
    try { target = new URL(request.url()); } catch {
      blockedOrigins.push(request.url());
      void request.abort('blockedbyclient');
      return;
    }
    if (target.protocol === 'data:') {
      void request.continue();
      return;
    }
    if (target.origin !== base) {
      blockedOrigins.push(target.origin);
      void request.abort('blockedbyclient');
      return;
    }
    requestedPaths.push(target.pathname);
    void request.continue();
  });
  const openQ05AuthorityTab = async () => {
    assert(q05 && !studentResetCurrentHost, 'Only the manual Q05 cohort may open an auxiliary authority tab');
    const { q05AuxiliaryRequestAllowed } = require('./adminQ05RenderedScenario');
    q05Targets.armAuxiliary();
    let other;
    try {
      other = await browser.newPage();
      assert(q05Targets.auxiliaryIs(other.target()), 'Armed auxiliary target must be the physical new page');
      assert(['about:blank', ''].includes(other.url()), 'Auxiliary tab must begin without external navigation');
      await other.setRequestInterception(true);
      other.on('request', request => {
        if (q05AuxiliaryRequestAllowed(request.url(), base))
          void request.continue();
        else { blockedOrigins.push('auxiliary-origin-denied'); void request.abort('blockedbyclient'); }
      });
      await other.goto(`${base}/api/auth/status`, { waitUntil: 'domcontentloaded' });
      assert.equal(new URL(other.url()).origin, base);
      const otherTarget = other.target();
      return Object.freeze({
        async swap(tokenA, tokenB) {
          assert.equal(new URL(other.url()).origin, base);
          await other.evaluate(([a, b]) => { localStorage.setItem('token', b); localStorage.setItem('token', a); }, [tokenA, tokenB]);
        },
        async close() { try { await other.close(); } finally { q05Targets.closeAuxiliary(otherTarget); } },
      });
    } catch (error) {
      q05Targets.disarmAuxiliary();
      if (other) { try { await other.close(); } finally { q05Targets.closeAuxiliary(other.target()); } }
      throw error;
    }
  };

  t.diagnostic('browser: opening workshop login');
  await page.goto(`${base}/workshop-login`, { waitUntil: 'networkidle0' });
  t.diagnostic('browser: login document settled');
  await page.type('input[placeholder="Enter your username"]', 'rendered-admin');
  await page.type('input[placeholder="Enter your password"]', adminPassword);
  const loginPromise = page.waitForResponse(response => responsePath(response, '/api/auth/login', 'POST'));
  await page.click('button[type="submit"]');
  const loginResponse = await loginPromise;
  const loginBody = await loginResponse.json();
  assert.equal(loginResponse.status(), 200);
  assert.equal(jwt.verify(loginBody.token, jwtSecret, { algorithms: ['HS256'] }).userId, admin.id,
    'browser token must carry a valid application signature and owner');
  const durableSession = await adapter.validateSession(loginBody.token);
  assert.equal(durableSession?.user?.id, admin.id, 'browser token must resolve through a persisted active session');
  const tokenDigest = crypto.createHash('sha256').update(loginBody.token).digest('hex');
  assert.equal((await migration.query(`SELECT count(*)::integer AS count FROM identity.user_sessions
    WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1`, [admin.id, tokenDigest])).rows[0].count, 1);
  await page.waitForFunction(() => location.pathname.startsWith('/admin'), { timeout: 15000 });

  t.diagnostic('browser: durable admin login verified');
  if (q05 && !studentResetCurrentHost) {
    journal.q05 = { status: 'running', modelCalls: 0, judgeCalls: 0 };
    await persistJournal();
    journal.q05 = await q05.run({ page, base, runtime, migration, admin, firstStudent,
      secondStudent, token: loginBody.token, adminPassword,
      armAcknowledgementLoss: armQ05AckLoss, openAuthorityTab: openQ05AuthorityTab,
      record: async facts => { journal.q05 = facts; await persistJournal(); } });
    assert.deepEqual(q05AckLoss.invalidDrops, [],
      'A malformed or incomplete deactivation acknowledgement cannot qualify');
    assert.equal(q05AckLoss.drops.length, 3);
    journal.q05.ackLoss = q05AckLoss.drops[0];
    journal.q05.administratorDeactivationAckLoss = q05AckLoss.drops[1];
    journal.q05.accountUnlockAckLoss = q05AckLoss.drops[2];
    assert(q05Targets.auxiliaryUsed(), 'Exactly one owned Q05 authority tab must have been observed');
    assert.deepEqual(q05UnexpectedTargets, [], 'Q05 rendered flow must not open unarmed browser targets');
    const studentId = journal.q05.actions.studentCreate.targetId;
    assert.deepEqual(q05AccountAccessReceived,
      [`/api/admin/users/${studentId}/lock`, `/api/admin/users/${studentId}/unlock`],
      'Mounted server must receive exactly one physical Lock and Unlock POST');
    journal.q05.accountAccessServerReceived = { lock: 1, unlock: 1 };
    assert.deepEqual(q05DeactivationReceived,
      [`/api/admin/administrators/${journal.q05.actions.administratorDeactivation.targetId}`],
      'Mounted server must receive exactly one physical administrator DELETE');
    journal.q05.administratorDeactivationServerReceived = { delete: 1 };
    await q05.verifyBuild();
    journal.status = 'test_body_passed';
    qualificationCompleted = true;
    await persistJournal();
    return;
  }
  if (process.env.ADMIN_STUDENT_RESET_ONLY === '1') {
    if (studentResetCurrentHost) {
      const result = await require('./adminStudentResetRecoveryBrowser').runStudentResetQ05Scenario({
        page, base, target: firstStudent.id, sibling: secondStudent.id, support: resetSupport,
        revoke: () => identity.revokePermission(admin.id, 'manage_progress'),
        restore: () => identity.grantPermission({ userId: admin.id,
          permission: 'manage_progress', grantedBy: admin.id }),
        record: async evidence => { journal.studentResetQ05 = evidence; await persistJournal(); },
      });
      journal.studentResetQ05 = result;
      assert.deepEqual(q05UnexpectedTargets, [], 'reset cohort must not open additional browser targets');
      await q05.verifyBuild();
      assert.deepEqual(blockedOrigins, []);
      assert.deepEqual(pageErrors, []);
      qualificationCompleted = true;
      journal.status = 'test_body_passed';
      await persistJournal();
      return;
    }
    const studentLogin = await fetch(`${base}/api/auth/login`, { method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: firstStudent.username, password: studentPassword }) });
    assert.equal(studentLogin.status, 200);
    const studentSession = await studentLogin.json();
    assert.equal((await adapter.validateSession(studentSession.token))?.user?.id, firstStudent.id);
    const result = await require('./adminStudentResetRecoveryBrowser').runRecoveryScenario({
      page, base, target: firstStudent.id, sibling: secondStudent.id, support: resetSupport,
      record: async evidence => { journal.resetRecovery = evidence; await persistJournal(); },
    });
    journal.resetRecovery = result;
    journal.studentAccessDenial = await require('./adminStudentResetRecoveryBrowser').runAccessDenialScenario({
      page, base, target: firstStudent.id, sibling: secondStudent.id, support: resetSupport,
      revoke: () => identity.revokePermission(admin.id, 'manage_progress'),
      restore: () => identity.grantPermission({ userId: admin.id, permission: 'manage_progress', grantedBy: admin.id }),
      announce: () => createWorkshopRevisionStore(runtime).bump({ scopeType: 'user', scopeKey: String(admin.id), category: 'admin_permission' }),
      record: async evidence => { journal.studentAccessDenial = evidence; await persistJournal(); },
    });
    journal.rosterAccessDenial = await require('./adminStudentResetRecoveryBrowser').runRosterDenialScenario({
      page, base, target: firstStudent.id, sibling: secondStudent.id, support: resetSupport,
      privateUsername: firstStudent.username,
      revoke: () => identity.revokePermission(admin.id, 'user_management'),
      restore: () => identity.grantPermission({ userId: admin.id, permission: 'user_management', grantedBy: admin.id }),
      record: async evidence => { journal.rosterAccessDenial = evidence; await persistJournal(); },
    });
    journal.inspectorAccessDenial = await require('./adminStudentResetRecoveryBrowser').runInspectorDenialScenario({
      page, base, target: firstStudent.id, runId, receiptText: controlledReceiptExplanation,
      revoke: () => identity.revokePermission(admin.id, 'view_analytics'),
      restore: () => identity.grantPermission({ userId: admin.id, permission: 'view_analytics', grantedBy: admin.id }),
      snapshot: async () => ({
        runs: (await migration.query('SELECT * FROM graph_runtime.runs WHERE run_id=ANY($1::uuid[]) ORDER BY run_id', [[runId, siblingRunId]])).rows,
        events: (await migration.query('SELECT * FROM graph_runtime.events WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,sequence', [[runId, siblingRunId]])).rows,
        judgments: (await migration.query('SELECT * FROM workshop_platform.objective_judgments WHERE evaluation_id=$1', [evaluationId])).rows,
      }),
      record: async evidence => { journal.inspectorAccessDenial = evidence; await persistJournal(); },
    });
    assert.deepEqual(blockedOrigins, []);
    assert.deepEqual(pageErrors, []);
    qualificationCompleted = true;
    journal.status = 'test_body_passed';
    await persistJournal();
    return;
  }

  const initialAdminObjectives = await requestJson(base, '/api/admin/workshops/mcp_workshop/objectives', loginBody.token);
  const initialAdminSolutions = await requestJson(base, '/api/admin/mcp-workshop/solutions', loginBody.token);
  const initialAdminHints = await requestJson(base, '/api/admin/workshops/mcp_workshop/hints', loginBody.token);
  const initialGenericSolutions = await requestJson(base, '/api/admin/solutions', loginBody.token);
  assert.equal(initialAdminObjectives.status, 200);
  assert.equal(initialAdminSolutions.status, 200);
  assert.equal(initialAdminHints.status, 200);
  assert.equal(initialGenericSolutions.status, 200);
  const auditSolutionId = 'secureshop_agent_security:ss_audit_instruction_followed';
  const auditSolution = initialGenericSolutions.body.solutions
    .find(solution => solution.id === auditSolutionId);
  assert.ok(auditSolution, 'generic admin solution ledger must expose the SecureShop audit objective');
  assert.equal(auditSolution.workshopKey, 'secureshop_agent_security');
  assert.equal(auditSolution.objective_id, 'ss_audit_instruction_followed');
  assert.equal(typeof auditSolution.difficultyLevel, 'string');
  assert.ok(Array.isArray(auditSolution.tags) && auditSolution.tags.length > 0);
  assert.ok(Array.isArray(auditSolution.examples) && auditSolution.examples.length > 0);
  const unchangedAuditPatch = {
    solution_title: auditSolution.title,
    solution_description: auditSolution.description,
    solution_steps: auditSolution.steps,
    explanation: auditSolution.explanation,
    difficulty_level: auditSolution.difficultyLevel,
    tags: auditSolution.tags,
  };
  const auditPut = await requestJson(base, `/api/admin/solutions/${encodeURIComponent(auditSolutionId)}`, loginBody.token, {
    method: 'PUT', body: unchangedAuditPatch,
  });
  assert.equal(auditPut.status, 200, 'unchanged canonical audit solution content must remain editable');
  const editedAuditPatch = { ...unchangedAuditPatch,
    solution_description: 'Instructor-authored audit learning context',
    solution_code: 'read_owned_audit_log()', reference_links: ['docs/modernization/secureshop-audit-agent-design.md'],
    estimated_time: '20 minutes', prerequisites: ['An owned SecureShop launch'], is_public: false };
  assert.equal((await requestJson(base, `/api/admin/solutions/${encodeURIComponent(auditSolutionId)}`, loginBody.token,
    { method: 'PUT', body: editedAuditPatch })).status, 200);
  const editedAudit = (await requestJson(base, '/api/admin/solutions', loginBody.token)).body.solutions
    .find(solution => solution.id === auditSolutionId);
  assert.equal(editedAudit.description, editedAuditPatch.solution_description);
  assert.equal(editedAudit.code, editedAuditPatch.solution_code);
  assert.deepEqual(editedAudit.references, editedAuditPatch.reference_links);
  assert.equal(editedAudit.estimatedTime, editedAuditPatch.estimated_time);
  assert.deepEqual(editedAudit.prerequisites, editedAuditPatch.prerequisites);
  const pendingSolutionId = 'secureshop_agent_security:ss_pricing_false_grounding';
  const pendingSolution = initialGenericSolutions.body.solutions
    .find(solution => solution.id === pendingSolutionId);
  assert.ok(pendingSolution, 'generic admin solution ledger must expose the pending pricing objective');
  const pendingEnablePatch = {
    solution_title: 'Must roll back',
    solution_description: pendingSolution.description,
    solution_steps: pendingSolution.steps,
    explanation: pendingSolution.explanation,
    difficulty_level: pendingSolution.difficultyLevel,
    tags: pendingSolution.tags,
    is_public: true,
  };
  assert.equal((await requestJson(base, `/api/admin/solutions/${encodeURIComponent(pendingSolutionId)}`, loginBody.token,
    { method: 'PUT', body: pendingEnablePatch })).status, 409);
  assert.deepEqual((await requestJson(base, '/api/admin/solutions', loginBody.token)).body.solutions
    .find(solution => solution.id === pendingSolutionId), pendingSolution,
    'rejected pending-objective enable must not partially save content');
  const auditEnable = await requestJson(base, `/api/admin/solutions/${encodeURIComponent(auditSolutionId)}/visibility`, loginBody.token, {
    method: 'PATCH', body: { isPublic: true },
  });
  assert.equal(auditEnable.status, 200, 'qualified audit objective must support instructor enablement');
  const auditRestore = await requestJson(base, `/api/admin/solutions/${encodeURIComponent(auditSolutionId)}/visibility`, loginBody.token, {
    method: 'PATCH', body: { isPublic: auditSolution.isPublic },
  });
  assert.equal(auditRestore.status, 200, 'qualified audit objective must restore its original visibility');
  const afterAuditMutationAttempt = await requestJson(base, '/api/admin/solutions', loginBody.token);
  const afterAudit = afterAuditMutationAttempt.body.solutions.find(solution => solution.id === auditSolutionId);
  assert.deepEqual(afterAudit, { ...editedAudit, isPublic: auditSolution.isPublic, is_public: auditSolution.isPublic },
    'qualified audit visibility round trip must preserve edited content and restore the original gate');
  assert.equal(initialAdminObjectives.body.workshopKey, 'mcp_workshop');
  assert.deepEqual(initialAdminObjectives.body.objectives.map(objective => objective.objective_id), mcpObjectiveIds);
  assert.deepEqual(initialAdminSolutions.body.objectives.map(objective => objective.objective_id), mcpObjectiveIds);
  const initialReconObjective = initialAdminObjectives.body.objectives
    .find(objective => objective.objective_id === 'mcp_recon');
  const initialReconSolution = initialAdminSolutions.body.objectives
    .find(objective => objective.objective_id === 'mcp_recon');
  assert.equal(initialReconObjective.is_enabled, true);
  assert.equal(typeof initialAdminHints.body.hints.mcp_recon, 'boolean');
  assert.equal(typeof initialReconSolution.solutions_enabled, 'boolean');
  assert.equal(initialReconObjective.solutions_enabled, initialReconSolution.solutions_enabled,
    'admin objective and solution projections must share the independent solution gate');
  const reconSolutionEnabled = initialReconSolution.solutions_enabled;
  const initialReconHintEnabled = initialAdminHints.body.hints.mcp_recon;
  const reconHintEnabled = true;

  t.diagnostic('browser: qualified audit edit/visibility and pending rejection verified');
  const exercisesChallenges = page.waitForResponse(response => responsePath(response, '/api/admin/challenges'));
  t.diagnostic('browser: opening unified exercise catalog');
  await page.goto(`${base}/admin/solutions`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => location.pathname === '/admin/exercises', { timeout: 15000 });
  assertConditionalBrowserRead(await exercisesChallenges, 'admin exercises catalog');
  t.diagnostic('browser: unified exercise catalog route and catalog response verified');
  await waitForText(page, 'MCP Server Lab');
  t.diagnostic('browser: MCP exercise card rendered from the unified catalog');
  const readMcpControlRows = async () => ({
    exercise: (await runtime.query(`SELECT is_visible,show_hints,show_solutions
      FROM workshop_platform.exercises WHERE workshop_key='mcp_workshop'`)).rows[0],
    objectives: (await runtime.query(`SELECT objective_id,is_enabled,hint_enabled,solution_enabled,
        hint_content IS NOT NULL AS has_hint_content,solution_content IS NOT NULL AS has_solution_content
      FROM workshop_platform.objectives WHERE workshop_key='mcp_workshop' AND catalog_active=true
      ORDER BY ordinal`)).rows,
  });
  const readMcpDurableEvidence = async () => ({
    completions: (await runtime.query(`SELECT user_id,objective_id,completed_at,updated_at
      FROM workshop_platform.completions WHERE workshop_key='mcp_workshop'
      ORDER BY user_id,objective_id`)).rows,
    time: (await runtime.query(`SELECT user_id,COALESCE(sum(duration_seconds),0)::integer AS seconds
      FROM workshop_platform.time_tracking WHERE workshop_key='mcp_workshop'
      GROUP BY user_id ORDER BY user_id`)).rows,
    judgments: (await runtime.query(`SELECT user_id,evaluation_id,evidence_digest,verdict,disposition
      FROM workshop_platform.objective_judgments ORDER BY user_id,evaluation_id`)).rows,
    runs: (await runtime.query(`SELECT run_id,owner_key,generation,status,last_node
      FROM graph_runtime.runs ORDER BY run_id`)).rows,
    events: (await runtime.query(`SELECT run_id,owner_key,sequence,node,event_type,metadata
      FROM graph_runtime.events ORDER BY run_id,sequence`)).rows,
  });
  const assertMcpControlSources = async expected => {
    const [catalog, snapshot, rows] = await Promise.all([
      requestJson(base, '/api/admin/challenges', loginBody.token),
      requestJson(base, '/api/workshop/config/snapshot'),
      readMcpControlRows(),
    ]);
    assert.equal(catalog.status, 200);
    assert.equal(snapshot.status, 200);
    const challenge = catalog.body.challenges.find(row => row.key === 'mcp_server_rce');
    assert.ok(challenge, 'admin catalog must retain the MCP exercise');
    assert.deepEqual({
      active: challenge.enabled,
      hints: challenge.showHints,
      solutions: challenge.showSolutions,
    }, expected, 'admin catalog must agree with the rendered MCP card');
    const exercise = snapshot.body.exercises.mcp_workshop;
    assert.deepEqual({
      active: exercise.isVisible,
      hints: exercise.showHints,
      solutions: exercise.showSolutions,
    }, expected, 'public canonical config must agree with the rendered MCP card');
    assert.deepEqual({
      active: rows.exercise.is_visible,
      hints: rows.exercise.show_hints,
      solutions: rows.exercise.show_solutions,
    }, expected, 'PostgreSQL must remain the authority for the rendered MCP card');
    await page.waitForFunction(mcpAdminCardControlsMatch, {},
      expected.active, expected.hints, expected.solutions);
    return rows;
  };
  const initialControlRows = await readMcpControlRows();
  const initialControls = {
    active: initialControlRows.exercise.is_visible,
    hints: initialControlRows.exercise.show_hints,
    solutions: initialControlRows.exercise.show_solutions,
  };
  assert.equal(initialControls.active, true, 'MCP must begin active for the rendered OFF/ON qualification');
  await assertMcpControlSources(initialControls);
  const initialFirstProjection = await progress.getVisibleUserProgress(firstStudent.id);
  const initialSecondProjection = await progress.getVisibleUserProgress(secondStudent.id);
  const projectionRevision = projection => {
    const revisions = [...new Set(projection.map(row => row.configRevision))];
    assert.equal(revisions.length, 1, 'one learner projection must use one canonical config revision');
    assert.equal(Number.isInteger(revisions[0]), true, 'learner projection config revision must be an integer');
    return revisions[0];
  };
  const withoutConfigRevision = projection => projection.map(({ configRevision: _revision, ...row }) => row);
  const withoutRowConfigRevision = ({ configRevision: _revision, ...row }) => row;
  const initialConfigRevision = projectionRevision(initialFirstProjection);
  assert.equal(projectionRevision(initialSecondProjection), initialConfigRevision,
    'owner and sibling projections must begin on the same canonical config revision');
  const initialDurableEvidence = await readMcpDurableEvidence();

  const activeOffResponse = page.waitForResponse(response => responsePath(response,
    '/api/admin/challenges/toggle', 'POST'));
  assert.equal(await page.evaluate(clickMcpCardControl, 'active'), true);
  assert.equal((await activeOffResponse).status(), 200);
  const activeOffRows = await assertMcpControlSources({ ...initialControls, active: false });
  assert.deepEqual(activeOffRows.objectives, initialControlRows.objectives,
    'exercise visibility must not rewrite objective, hint or solution gates');
  const [hiddenFirstProjection, hiddenSecondProjection] = await Promise.all([
    progress.getVisibleUserProgress(firstStudent.id),
    progress.getVisibleUserProgress(secondStudent.id),
  ]);
  assert.equal(hiddenFirstProjection.some(row => row.workshopKey === 'mcp_workshop'), false);
  assert.equal(hiddenSecondProjection.some(row => row.workshopKey === 'mcp_workshop'), false);
  assert.equal(hiddenFirstProjection.reduce((sum, row) => sum + row.objectiveCount, 0),
    initialFirstProjection.reduce((sum, row) => sum + row.objectiveCount, 0) - mcpObjectiveIds.length);
  assert.equal(hiddenSecondProjection.reduce((sum, row) => sum + row.objectiveCount, 0),
    initialSecondProjection.reduce((sum, row) => sum + row.objectiveCount, 0) - mcpObjectiveIds.length);
  assert.equal(projectionRevision(hiddenFirstProjection), initialConfigRevision + 1);
  assert.equal(projectionRevision(hiddenSecondProjection), initialConfigRevision + 1);

  const activeOnResponse = page.waitForResponse(response => responsePath(response,
    '/api/admin/challenges/toggle', 'POST'));
  assert.equal(await page.evaluate(clickMcpCardControl, 'active'), true);
  assert.equal((await activeOnResponse).status(), 200);
  await assertMcpControlSources(initialControls);
  const activeRestoredFirstProjection = await progress.getVisibleUserProgress(firstStudent.id);
  const activeRestoredSecondProjection = await progress.getVisibleUserProgress(secondStudent.id);
  assert.deepEqual(withoutConfigRevision(activeRestoredFirstProjection), withoutConfigRevision(initialFirstProjection),
    'Active restoration must restore the owner count, completion and time projection');
  assert.deepEqual(withoutConfigRevision(activeRestoredSecondProjection), withoutConfigRevision(initialSecondProjection),
    'Active restoration must restore the sibling count, completion and time projection');
  assert.equal(projectionRevision(activeRestoredFirstProjection), initialConfigRevision + 2,
    'Active OFF/ON must advance the canonical configuration revision twice');
  assert.equal(projectionRevision(activeRestoredSecondProjection), initialConfigRevision + 2,
    'the sibling projection must observe the restored canonical configuration revision');

  const toggleMasterControl = async (control, nextValue) => {
    const primaryPath = control === 'hints'
      ? '/api/admin/challenges/hints/toggle'
      : '/api/admin/challenges/solutions/toggle';
    const primaryResponse = page.waitForResponse(response => responsePath(response, primaryPath, 'POST'));
    const cascadeResponse = control === 'hints'
      ? page.waitForResponse(response => responsePath(response,
        '/api/admin/workshops/mcp_workshop/hints/bulk-toggle', 'POST'))
      : null;
    assert.equal(await page.evaluate(clickMcpCardControl, control), true);
    assert.equal((await primaryResponse).status(), 200);
    if (cascadeResponse) assert.equal((await cascadeResponse).status(), 200);
    const expected = { ...initialControls, [control]: nextValue };
    return assertMcpControlSources(expected);
  };

  const invertedHintRows = await toggleMasterControl('hints', !initialControls.hints);
  assert.deepEqual(invertedHintRows.objectives.map(row => ({
    objective_id: row.objective_id,
    is_enabled: row.is_enabled,
    solution_enabled: row.solution_enabled,
  })), initialControlRows.objectives.map(row => ({
    objective_id: row.objective_id,
    is_enabled: row.is_enabled,
    solution_enabled: row.solution_enabled,
  })), 'master Hint must not change objective availability or the independent Solution gate');
  const invertedHintProjection = (await progress.getVisibleUserProgress(firstStudent.id))
    .find(row => row.workshopKey === 'mcp_workshop');
  const initialMcpProjection = initialFirstProjection.find(row => row.workshopKey === 'mcp_workshop');
  assert.deepEqual(invertedHintProjection.objectives.map(objective => ({
    id: objective.id,
    completed: objective.completed,
    solutionVisible: objective.solutionVisible,
  })), initialMcpProjection.objectives.map(objective => ({
    id: objective.id,
    completed: objective.completed,
    solutionVisible: objective.solutionVisible,
  })), 'master Hint must preserve learner completion and independent Solution visibility');
  assert.deepEqual(invertedHintProjection.objectives.map(objective => objective.hintVisible),
    invertedHintRows.objectives.map(row => !initialControls.hints && row.has_hint_content),
    'learner Hint controls must follow the rendered master Hint and authored content');
  await toggleMasterControl('hints', initialControls.hints);
  assert.deepEqual(await readMcpControlRows(), initialControlRows,
    'rendered master Hint round trip must restore every original MCP gate');

  const invertedSolutionRows = await toggleMasterControl('solutions', !initialControls.solutions);
  assert.deepEqual(invertedSolutionRows.objectives.map(row => ({
    objective_id: row.objective_id,
    is_enabled: row.is_enabled,
    hint_enabled: row.hint_enabled,
  })), initialControlRows.objectives.map(row => ({
    objective_id: row.objective_id,
    is_enabled: row.is_enabled,
    hint_enabled: row.hint_enabled,
  })), 'master Solution must not change objective availability or the independent Hint gate');
  const invertedSolutionProjection = (await progress.getVisibleUserProgress(firstStudent.id))
    .find(row => row.workshopKey === 'mcp_workshop');
  assert.deepEqual(invertedSolutionProjection.objectives.map(objective => ({
    id: objective.id,
    completed: objective.completed,
    hintVisible: objective.hintVisible,
  })), initialMcpProjection.objectives.map(objective => ({
    id: objective.id,
    completed: objective.completed,
    hintVisible: objective.hintVisible,
  })), 'master Solution must preserve learner completion and independent Hint visibility');
  assert.deepEqual(invertedSolutionProjection.objectives.map(objective => objective.solutionVisible),
    invertedSolutionRows.objectives.map(row => !initialControls.solutions && row.has_solution_content),
    'learner Solution controls must follow the rendered master Solution and authored content');
  await toggleMasterControl('solutions', initialControls.solutions);
  assert.deepEqual(await readMcpControlRows(), initialControlRows,
    'rendered master Solution round trip must restore every original MCP gate');
  const finalFirstProjection = await progress.getVisibleUserProgress(firstStudent.id);
  const finalSecondProjection = await progress.getVisibleUserProgress(secondStudent.id);
  assert.deepEqual(withoutConfigRevision(finalFirstProjection), withoutConfigRevision(initialFirstProjection));
  assert.deepEqual(withoutConfigRevision(finalSecondProjection), withoutConfigRevision(initialSecondProjection));
  assert.equal(projectionRevision(finalFirstProjection), initialConfigRevision + 6,
    'Active, Hint and Solution round trips must each advance the canonical revision twice');
  assert.equal(projectionRevision(finalSecondProjection), initialConfigRevision + 6,
    'the sibling projection must observe every restored canonical gate revision');
  assert.deepEqual(await readMcpDurableEvidence(), initialDurableEvidence,
    'card-level configuration round trips must preserve completion, time, judgments, runs and events');
  t.diagnostic('browser: rendered Active and independent master Hint/Solution round trips verified');

  const modalObjectives = page.waitForResponse(response => responsePath(response,
    '/api/admin/workshops/mcp_workshop/objectives'));
  const modalHints = page.waitForResponse(response => responsePath(response,
    '/api/admin/workshops/mcp_workshop/hints'));
  const modalSolutions = page.waitForResponse(response => responsePath(response,
    '/api/admin/mcp-workshop/solutions'));
  t.diagnostic('browser: opening MCP objectives modal for lazy family hydration');
  assert.equal(await page.evaluate(clickMcpManageObjectives), true);
  assertConditionalBrowserRead(await modalObjectives, 'MCP objective modal');
  assertConditionalBrowserRead(await modalHints, 'MCP hint modal');
  assertConditionalBrowserRead(await modalSolutions, 'MCP solution modal');
  await page.waitForFunction(mcpAdminModalMatches, {}, mcpObjectiveIds, initialReconHintEnabled, reconSolutionEnabled);
  t.diagnostic('browser: MCP objectives, hints and solutions hydrated in the rendered modal');
  await page.evaluate(() => [...document.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Done')?.click());
  const auditObjectives = page.waitForResponse(response => responsePath(response,
    '/api/admin/workshops/secureshop_agent_security/objectives'));
  const auditHints = page.waitForResponse(response => responsePath(response,
    '/api/admin/workshops/secureshop_agent_security/hints'));
  const clickedAuditObjectives = await page.evaluate(() => {
    const heading = [...document.querySelectorAll('h3')]
      .find(node => node.textContent.trim() === 'SecureShop Agent Security');
    let card = heading;
    while (card && ![...card.querySelectorAll('button')]
      .some(button => button.textContent.includes('Manage Objectives'))) card = card.parentElement;
    const button = [...(card?.querySelectorAll('button') || [])]
      .find(candidate => candidate.textContent.includes('Manage Objectives'));
    button?.click();
    return Boolean(button);
  });
  assert.equal(clickedAuditObjectives, true, 'SecureShop Manage Objectives must be rendered');
  assertConditionalBrowserRead(await auditObjectives, 'SecureShop objective panel');
  assertConditionalBrowserRead(await auditHints, 'SecureShop hint panel');
  await waitForText(page, 'ss_audit_instruction_followed');
  assert.ok(await page.$('button[title="Preview Solution"]'),
    'SecureShop audit objective must expose solution preview');
  assert.ok(await page.$('button[title="Edit Solution"]'),
    'SecureShop audit objective must expose solution edit');
  await page.evaluate(() => [...document.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Done')?.click());
  // This panel was loaded above; reopening reuses its cached objective/hint data.
  assert.equal(await page.evaluate(clickMcpManageObjectives), true);
  await page.waitForFunction(mcpAdminModalMatches, {}, mcpObjectiveIds, initialReconHintEnabled, reconSolutionEnabled);
  // Fresh installations intentionally hide hints. Establish the enabled state
  // through the instructor's real control before testing hide and live restore.
  if (!initialReconHintEnabled) {
    const enabledHintResponse = page.waitForResponse(response => responsePath(response,
      '/api/admin/workshops/mcp_workshop/hints/mcp_recon/toggle', 'POST'));
    assert.equal(await page.evaluate(clickMcpReconHint), true);
    assert.equal((await enabledHintResponse).status(), 200);
    await page.waitForFunction(mcpAdminModalMatches, {}, mcpObjectiveIds, true, reconSolutionEnabled);
  }

  const disabledHintResponse = page.waitForResponse(response => responsePath(response,
    '/api/admin/workshops/mcp_workshop/hints/mcp_recon/toggle', 'POST'));
  assert.equal(await page.evaluate(clickMcpReconHint), true);
  assert.equal((await disabledHintResponse).status(), 200);
  await page.waitForFunction(mcpAdminModalMatches, {}, mcpObjectiveIds, false, reconSolutionEnabled);
  const [hintDisabledObjectives, hintDisabledSolutions, hintDisabledMap] = await Promise.all([
    requestJson(base, '/api/admin/workshops/mcp_workshop/objectives', loginBody.token),
    requestJson(base, '/api/admin/mcp-workshop/solutions', loginBody.token),
    requestJson(base, '/api/admin/workshops/mcp_workshop/hints', loginBody.token),
  ]);
  assert.equal(hintDisabledObjectives.body.objectives
    .find(objective => objective.objective_id === 'mcp_recon').is_enabled, true,
  'the rendered hint toggle must not change objective visibility');
  assert.equal(hintDisabledMap.body.hints.mcp_recon, false);
  assert.equal(hintDisabledSolutions.body.objectives
    .find(objective => objective.objective_id === 'mcp_recon').solutions_enabled, reconSolutionEnabled,
  'the rendered hint toggle must not change the independent solution gate');

  const invertedSolutionResponse = page.waitForResponse(response => responsePath(response,
    '/api/admin/mcp-workshop/solutions/toggle', 'POST'));
  assert.equal(await page.evaluate(clickMcpReconSolution), true);
  assert.equal((await invertedSolutionResponse).status(), 200);
  await page.waitForFunction(mcpAdminModalMatches, {}, mcpObjectiveIds, false, !reconSolutionEnabled);
  const [invertedObjectives, invertedSolutions] = await Promise.all([
    requestJson(base, '/api/admin/workshops/mcp_workshop/objectives', loginBody.token),
    requestJson(base, '/api/admin/mcp-workshop/solutions', loginBody.token),
  ]);
  assert.equal(invertedObjectives.status, 200);
  assert.equal(invertedSolutions.status, 200);
  const invertedReconObjective = invertedObjectives.body.objectives
    .find(objective => objective.objective_id === 'mcp_recon');
  const invertedReconSolution = invertedSolutions.body.objectives
    .find(objective => objective.objective_id === 'mcp_recon');
  assert.equal(invertedReconObjective.is_enabled, true,
  'the rendered solution toggle must not change objective visibility');
  assert.equal(invertedReconSolution.solutions_enabled, !reconSolutionEnabled);
  assert.equal(invertedReconObjective.solutions_enabled, invertedReconSolution.solutions_enabled,
    'admin objective and solution projections must share the inverted solution state');

  const restoredSolutionResponse = page.waitForResponse(response => responsePath(response,
    '/api/admin/mcp-workshop/solutions/toggle', 'POST'));
  assert.equal(await page.evaluate(clickMcpReconSolution), true);
  assert.equal((await restoredSolutionResponse).status(), 200);
  await page.waitForFunction(mcpAdminModalMatches, {}, mcpObjectiveIds, false, reconSolutionEnabled);
  const [restoredObjectives, restoredSolutions] = await Promise.all([
    requestJson(base, '/api/admin/workshops/mcp_workshop/objectives', loginBody.token),
    requestJson(base, '/api/admin/mcp-workshop/solutions', loginBody.token),
  ]);
  assert.equal(restoredObjectives.status, 200);
  assert.equal(restoredSolutions.status, 200);
  const restoredReconObjective = restoredObjectives.body.objectives
    .find(objective => objective.objective_id === 'mcp_recon');
  const restoredReconSolution = restoredSolutions.body.objectives
    .find(objective => objective.objective_id === 'mcp_recon');
  assert.equal(restoredReconObjective.is_enabled, true);
  assert.equal(restoredReconSolution.solutions_enabled, reconSolutionEnabled,
  'the rendered solution toggle must restore the independent baseline');
  assert.equal(restoredReconObjective.solutions_enabled, restoredReconSolution.solutions_enabled,
    'admin objective and solution projections must share the restored solution state');

  const firstViewPromise = page.waitForResponse(response => responsePath(response,
    `/api/admin/student-workshop-view/${firstStudent.id}`));
  await page.goto(`${base}/admin/student-workshop-view?studentId=${firstStudent.id}`, { waitUntil: 'domcontentloaded' });
  const firstViewResponse = await firstViewPromise;
  const firstView = await firstViewResponse.json();
  assert.equal(firstViewResponse.status(), 200);
  assert.equal(firstView.student.id, firstStudent.id);
  assert.equal(firstView.overview.completedChallenges, 1);
  const initialAdminMcp = firstView.challenges.find(challenge => challenge.workshopKey === 'mcp_workshop');
  assert.ok(initialAdminMcp);
  assert.equal(initialAdminMcp.challengeKey, 'mcp_server_rce');
  assert.equal(initialAdminMcp.objectiveCount, 11);
  assert.equal(initialAdminMcp.completedObjectiveCount, 1);
  assert.equal(initialAdminMcp.status, 'in_progress');
  assert.deepEqual(initialAdminMcp.objectives.map(objective => objective.id), mcpObjectiveIds);
  assert.equal(initialAdminMcp.objectives.find(objective => objective.id === 'mcp_recon').completed, true);
  await page.waitForFunction(expected => {
    const label = [...document.querySelectorAll('.label')].find(node => node.textContent.trim() === 'Completed');
    return label?.parentElement?.querySelector('.value')?.textContent.trim() === String(expected);
  }, {}, 1);
  await waitForRenderedMcpCount(page, 1, 11);
  await page.waitForFunction(mcpCardMatches, {}, 1, 11, ['37s']);
  const options = await studentViewOptions(page);
  assert.deepEqual(new Set(options.map(option => option.value)), new Set([String(firstStudent.id), String(secondStudent.id)]),
    'student selector must contain only the two persisted student identities');

  const secondViewPromise = page.waitForResponse(response => responsePath(response,
    `/api/admin/student-workshop-view/${secondStudent.id}`));
  await selectStudentInView(page, secondStudent.id);
  const secondViewResponse = await secondViewPromise;
  const secondView = await secondViewResponse.json();
  assert.equal(secondView.student.id, secondStudent.id);
  assert.equal(secondView.overview.completedChallenges, 0);
  const siblingInitialMcp = secondView.challenges.find(challenge => challenge.workshopKey === 'mcp_workshop');
  assert.ok(siblingInitialMcp);
  assert.equal(siblingInitialMcp.objectiveCount, 11);
  assert.equal(siblingInitialMcp.completedObjectiveCount, 0);
  assert.equal(siblingInitialMcp.status, 'unlocked');
  assert.deepEqual(siblingInitialMcp.objectives.map(objective => objective.id), mcpObjectiveIds);
  await page.waitForFunction(() => {
    const label = [...document.querySelectorAll('.label')].find(node => node.textContent.trim() === 'Completed');
    return label?.parentElement?.querySelector('.value')?.textContent.trim() === '0';
  });

  const returnToFirstPromise = page.waitForResponse(response => responsePath(response,
    `/api/admin/student-workshop-view/${firstStudent.id}`));
  await selectStudentInView(page, firstStudent.id);
  await returnToFirstPromise;
  await identity.revokePermission(admin.id, 'manage_progress');
  const deniedStudentRefresh = page.waitForResponse(response => responsePath(response,
    `/api/admin/student-workshop-view/${firstStudent.id}`));
  await refreshStudentView(page);
  assert.equal((await deniedStudentRefresh).status(), 403);
  await waitForText(page, 'Permission denied');
  assert.doesNotMatch(await bodyText(page), /Available Exercises \(/,
    'failed foreground refresh must not leave a stale student projection presented as current');
  await identity.grantPermission({ userId: admin.id, permission: 'manage_progress', grantedBy: admin.id });

  const activityRosterPromise = page.waitForResponse(response => responsePath(response, '/api/admin/users'));
  await page.goto(`${base}/admin/activity`, { waitUntil: 'domcontentloaded' });
  assert.equal((await activityRosterPromise).status(), 200);
  await waitForText(page, 'isolated-student-one');
  await waitForText(page, 'isolated-student-two');
  await identity.revokePermission(admin.id, 'user_management');
  const deniedRosterRefresh = page.waitForResponse(response => responsePath(response, '/api/admin/users'));
  await page.evaluate(() => {
    const heading = [...document.querySelectorAll('h3')]
      .find(node => node.textContent.includes('Active Users & Their Activity'));
    heading.parentElement.querySelector('button').click();
  });
  assert.equal((await deniedRosterRefresh).status(), 403);
  await waitForText(page, 'Active user data is no longer accessible.');
  assert.doesNotMatch(await page.evaluate(() => {
    const heading = [...document.querySelectorAll('h3')].find(node => node.textContent.includes('Active Users & Their Activity'));
    return heading.parentElement.parentElement.innerText;
  }), /isolated-student-one/, 'denied roster must clear private users; permitted audit logs are a separate projection');

  const rosterRequestsBeforeReload = requestedPaths.filter(value => value === '/api/admin/users').length;
  await page.reload({ waitUntil: 'networkidle0' });
  await waitForText(page, 'User activity details require user management permission.');
  assert.equal(requestedPaths.filter(value => value === '/api/admin/users').length, rosterRequestsBeforeReload,
    'a current revoked session must not issue a roster request');
  assert.match(await bodyText(page), /Successful Logins/,
    'admin-level audit activity remains available without user-management permission');
  await identity.grantPermission({ userId: admin.id, permission: 'user_management', grantedBy: admin.id });
  const delegatedRoster = page.waitForResponse(response => responsePath(response, '/api/admin/users'));
  await page.reload({ waitUntil: 'domcontentloaded' });
  assert.equal((await delegatedRoster).status(), 200);
  await waitForText(page, 'isolated-student-one');

  const agentRunsPromise = page.waitForResponse(response => responsePath(response, '/api/admin/agent-runs'));
  await page.goto(`${base}/admin/agent-runs`, { waitUntil: 'domcontentloaded' });
  assert.equal((await agentRunsPromise).status(), 200);
  await page.waitForSelector('[aria-label="Administrator agent run inspector"]');
  const ownerFilteredRuns = page.waitForResponse(response => {
    const target = new URL(response.url());
    return target.pathname === '/api/admin/agent-runs'
      && target.searchParams.get('ownerId') === String(firstStudent.id);
  });
  const adminRunDetail = page.waitForResponse(response => responsePath(response,
    `/api/admin/agent-runs/${runId}`));
  await page.type('[aria-label="Owner ID"]', String(firstStudent.id));
  assert.equal((await ownerFilteredRuns).status(), 200);
  assert.ok(ownershipLookupOwners.includes(String(firstStudent.id)),
    'admin all-family owner filter must consult the explicit SecureShop exclusion');
  const adminOwnershipLookupCount = ownershipLookupOwners.filter(owner => owner === String(firstStudent.id)).length;
  await waitForText(page, runId);
  const adminRunBody = await (await adminRunDetail).json();
  assert.equal(adminRunBody.run.ownerId, String(firstStudent.id));
  assert.equal(adminRunBody.judgments[0].evaluationId, evaluationId,
    'actual admin run API must project the controlled persisted receipt');
  await waitForText(page, controlledReceiptExplanation);
  await waitForText(page, `Evidence digest: ${evidenceDigest}`);
  failAgentEventPolling = true;
  const failedPollingResponse = page.waitForResponse(response => responsePath(response,
    `/api/admin/agent-runs/${runId}/events`));
  assert.equal((await failedPollingResponse).status(), 503);
  await waitForText(page, 'Live updates are temporarily unavailable. Showing the last recorded state; retrying automatically.');
  assert.match(await bodyText(page), new RegExp(runId), 'polling failure must retain the last stored run state');
  failAgentEventPolling = false;
  await page.waitForFunction(() => !document.body.innerText.includes('Live updates are temporarily unavailable.'),
    { timeout: 10000 });

  await identity.revokePermission(admin.id, 'view_analytics');
  const agentRequestsBeforeReload = requestedPaths.filter(value => value === '/api/admin/agent-runs').length;
  await page.reload({ waitUntil: 'networkidle0' });
  await waitForText(page, 'Permission denied: Agent Runs requires analytics access.');
  assert.equal(requestedPaths.filter(value => value === '/api/admin/agent-runs').length, agentRequestsBeforeReload,
    'revoked analytics permission must prevent the inspector list request');
  assert.equal(await page.$('[aria-label="Administrator agent run inspector"]'), null);

  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
  await page.goto(`${base}/workshop/login`, { waitUntil: 'networkidle0' });
  await page.type('input[placeholder="Enter your username"]', 'isolated-student-one');
  await page.type('input[placeholder="Enter your password"]', studentPassword);
  const studentLoginPromise = page.waitForResponse(response => responsePath(response, '/api/auth/login', 'POST'));
  await page.click('button[type="submit"]');
  const studentLoginResponse = await studentLoginPromise;
  const studentLoginBody = await studentLoginResponse.json();
  assert.equal(studentLoginResponse.status(), 200);
  assert.equal(jwt.verify(studentLoginBody.token, jwtSecret, { algorithms: ['HS256'] }).userId, firstStudent.id);
  assert.equal((await adapter.validateSession(studentLoginBody.token))?.user?.id, firstStudent.id,
    'student browser token must resolve through its persisted application session');
  const studentTokenDigest = crypto.createHash('sha256').update(studentLoginBody.token).digest('hex');
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count FROM identity.user_sessions
    WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1`, [firstStudent.id, studentTokenDigest])).rows[0].count, 1);
  await page.waitForFunction(() => location.pathname === '/workshop-dashboard', { timeout: 15000 });

  const xssWorkshopKeys = ['xss_workshop', 'xss_email_builder'];
  const readXssCatalogSettings = async () => ({
    exercises: (await runtime.query(`SELECT workshop_key,challenge_key,challenge_name,challenge_description,
        category,difficulty,route,is_visible,show_hints,show_solutions,catalog_active,ordinal
      FROM workshop_platform.exercises WHERE workshop_key=ANY($1::text[]) ORDER BY workshop_key`,
    [xssWorkshopKeys])).rows,
    objectives: (await runtime.query(`SELECT workshop_key,objective_id,label,category,ordinal,is_enabled,
        catalog_active,hint_enabled,solution_enabled,hint_content,solution_content
      FROM workshop_platform.objectives WHERE workshop_key=ANY($1::text[])
      ORDER BY workshop_key,ordinal`, [xssWorkshopKeys])).rows,
  });
  const readXssDurableLearnerState = async () => ({
    completions: (await runtime.query(`SELECT user_id,workshop_key,objective_id,completed_at,updated_at
      FROM workshop_platform.completions WHERE user_id=ANY($1::integer[])
        AND workshop_key=ANY($2::text[]) ORDER BY user_id,workshop_key,objective_id`,
    [[firstStudent.id, secondStudent.id], xssWorkshopKeys])).rows,
    time: (await runtime.query(`SELECT id,user_id,workshop_key,session_start,last_heartbeat,duration_seconds
      FROM workshop_platform.time_tracking WHERE user_id=ANY($1::integer[])
        AND workshop_key=ANY($2::text[]) ORDER BY id`,
    [[firstStudent.id, secondStudent.id], xssWorkshopKeys])).rows,
  });
  const initialXssCatalog = await readXssCatalogSettings();
  const initialXssDurableState = await readXssDurableLearnerState();
  assert.deepEqual(initialXssDurableState.time, [],
    'shared-route qualification requires no pre-existing XSS heartbeat rows');
  const initialXssOwnerProjection = await progress.getVisibleUserProgress(firstStudent.id);
  const initialXssSiblingProjection = await progress.getVisibleUserProgress(secondStudent.id);
  const initialXssVisibility = Object.fromEntries(initialXssCatalog.exercises
    .map(row => [row.workshop_key, row.is_visible]));
  const xssCardTitles = Object.fromEntries(initialXssCatalog.exercises
    .map(row => [row.workshop_key, row.challenge_name]));
  assert.deepEqual(Object.keys(initialXssVisibility).sort(), [...xssWorkshopKeys].sort(),
    'both XSS catalog exercises must exist before the shared-route qualification');

  const setXssVisibility = async (mainVisible, builderVisible) => {
    for (const [challengeKey, enabled] of [
      ['reflected_xss_llm', mainVisible],
      ['xss_email_builder', builderVisible],
    ]) {
      const response = await requestJson(base, '/api/admin/challenges/toggle', loginBody.token, {
        method: 'POST', body: { challengeKey, enabled },
      });
      assert.equal(response.status, 200);
      assert.equal(response.body.enabled, enabled,
        `administrator visibility response must confirm ${challengeKey}=${enabled}`);
    }
    const snapshot = await requestJson(base, '/api/workshop/config/snapshot');
    assert.equal(snapshot.status, 200);
    assert.equal(snapshot.body.exercises.xss_workshop.isVisible, mainVisible);
    assert.equal(snapshot.body.exercises.xss_email_builder.isVisible, builderVisible);
  };
  const openOnlyXssCard = async (expectedTitle, hiddenTitle, expectedRoute) => {
    const challengesResponse = page.waitForResponse(response => responsePath(response,
      '/api/workshop/challenges'));
    await page.goto(`${base}/workshop/challenges`, { waitUntil: 'domcontentloaded' });
    assert.ok([200, 304].includes((await challengesResponse).status()),
      'rendered challenge projection may use a valid conditional-cache response');
    await page.waitForFunction(({ visible, hidden }) => {
      const titles = [...document.querySelectorAll('h3')].map(node => node.textContent.trim());
      return titles.includes(visible) && !titles.includes(hidden);
    }, { timeout: 15000 }, { visible: expectedTitle, hidden: hiddenTitle });
    const heartbeatResponse = page.waitForResponse(response => responsePath(response,
      '/api/workshop/time/heartbeat', 'POST'));
    await page.evaluate(title => {
      const heading = [...document.querySelectorAll('h3')]
        .find(candidate => candidate.textContent.trim() === title);
      let card = heading;
      let button = null;
      while (card && !button) {
        button = [...card.querySelectorAll('button')]
          .find(candidate => /^(Start|Continue|Review) Exercise$/.test(candidate.textContent.trim()));
        if (!button) card = card.parentElement;
      }
      if (!button) throw new Error(`XSS challenge card unavailable for ${title}`);
      button.click();
    }, expectedTitle);
    await page.waitForFunction(route => `${location.pathname}${location.search}` === route,
      { timeout: 15000 }, expectedRoute);
    assert.equal((await heartbeatResponse).status(), 200,
      'the admitted XSS curriculum must start its canonical learner heartbeat');
  };

  try {
    await setXssVisibility(false, true);
    await openOnlyXssCard(xssCardTitles.xss_email_builder, xssCardTitles.xss_workshop,
      '/vulnerabilities/xss?tab=email_builder');
    await waitForText(page, 'XSS Email Template Builder');
    await page.waitForSelector('select[aria-label="Email builder objective"]');
    assert.equal(await page.$('[data-scenario-tab="reflected"]'), null,
      'builder-only admission must not render a hidden main-curriculum tab');

    await setXssVisibility(true, false);
    await openOnlyXssCard(xssCardTitles.xss_workshop, xssCardTitles.xss_email_builder,
      '/vulnerabilities/xss');
    await waitForText(page, 'XSS in AI Powered Chat System');
    await page.waitForSelector('[data-scenario-tab="reflected"]');
    assert.equal(await page.$('[data-scenario-tab="email_builder"]'), null,
      'main-only admission must not render a hidden builder tab');

    await setXssVisibility(false, false);
    const hiddenChallengesResponse = page.waitForResponse(response => responsePath(response,
      '/api/workshop/challenges'));
    await page.goto(`${base}/workshop/challenges`, { waitUntil: 'domcontentloaded' });
    assert.ok([200, 304].includes((await hiddenChallengesResponse).status()),
      'hidden-state challenge projection may use a valid conditional-cache response');
    await waitForRenderedMcpCount(page, 1, 11);
    assert.deepEqual(await page.evaluate(expectedTitles => [...document.querySelectorAll('h3')]
      .map(node => node.textContent.trim()).filter(title => expectedTitles.includes(title)),
    Object.values(xssCardTitles)), [], 'both-hidden catalog state must remove both XSS challenge cards');
    await page.goto(`${base}/vulnerabilities/xss`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => location.pathname === '/workshop-dashboard', { timeout: 15000 });
    assert.equal((await bodyText(page)).includes('XSS in AI Powered Chat System'), false);
    assert.equal((await bodyText(page)).includes('XSS Email Template Builder'), false);
  } finally {
    const navigatedXssDurableState = await readXssDurableLearnerState();
    await runtime.query(`DELETE FROM workshop_platform.time_tracking
      WHERE user_id=ANY($1::integer[]) AND workshop_key=ANY($2::text[])`,
    [[firstStudent.id, secondStudent.id], xssWorkshopKeys]);
    await config.setExerciseVisibility('xss_workshop', initialXssVisibility.xss_workshop, admin.id);
    await config.setExerciseVisibility('xss_email_builder', initialXssVisibility.xss_email_builder, admin.id);
    assert.deepEqual(navigatedXssDurableState.completions, initialXssDurableState.completions,
      'visiting either shared XSS curriculum must not award an objective completion');
    assert.deepEqual(await readXssCatalogSettings(), initialXssCatalog,
      'shared-route qualification must restore every substantive XSS catalog setting');
    assert.deepEqual(await readXssDurableLearnerState(), initialXssDurableState,
      'shared-route visibility changes must preserve owner and sibling durable XSS state');
    assert.deepEqual(withoutConfigRevision(await progress.getVisibleUserProgress(firstStudent.id)),
      withoutConfigRevision(initialXssOwnerProjection),
      'shared-route restoration must preserve the owner learner projection');
    assert.deepEqual(withoutConfigRevision(await progress.getVisibleUserProgress(secondStudent.id)),
      withoutConfigRevision(initialXssSiblingProjection),
      'shared-route restoration must preserve the sibling learner projection');
  }
  t.diagnostic('browser: shared XSS route admits either visible curriculum and denies both-hidden state');

  const learnerMcpProjection = async (expectedCompleted, expectedTotal, expectedSeconds) => {
    const [challenges, dashboard, stats, time] = await Promise.all([
      requestJson(base, '/api/workshop/challenges', studentLoginBody.token),
      requestJson(base, '/api/workshop/progress', studentLoginBody.token),
      requestJson(base, '/api/workshop/student/stats', studentLoginBody.token),
      requestJson(base, '/api/workshop/time/summary', studentLoginBody.token),
    ]);
    for (const response of [challenges, dashboard, stats, time]) assert.equal(response.status, 200);
    assert.deepEqual(challenges.body.challenges, dashboard.body.challenges,
      'learner challenge and dashboard APIs must project the same canonical rows');
    const rows = challenges.body.challenges;
    assert.equal(stats.body.totalObjectives, rows.reduce((sum, row) => sum + row.objectiveCount, 0));
    assert.equal(stats.body.completedObjectives, rows.reduce((sum, row) => sum + row.completedObjectiveCount, 0));
    assert.equal(stats.body.totalTime, rows.reduce((sum, row) => sum + row.timeSpentSeconds, 0));
    assert.equal(stats.body.completedChallenges, rows.filter(row => row.status === 'completed').length);
    const mcp = rows.find(row => row.workshopKey === 'mcp_workshop');
    assert.ok(mcp);
    assert.equal(mcp.objectiveCount, expectedTotal);
    assert.equal(mcp.completedObjectiveCount, expectedCompleted);
    assert.equal(mcp.timeSpentSeconds, expectedSeconds);
    assert.equal(time.body.summary.mcp_workshop, expectedSeconds);
    return mcp;
  };
  const adminMcpProjection = async (studentId, expectedCompleted, expectedTotal, expectedSeconds) => {
    const response = await requestJson(base, `/api/admin/student-workshop-view/${studentId}`, loginBody.token);
    assert.equal(response.status, 200);
    const mcp = response.body.challenges.find(row => row.workshopKey === 'mcp_workshop');
    assert.ok(mcp);
    assert.equal(mcp.objectiveCount, expectedTotal);
    assert.equal(mcp.completedObjectiveCount, expectedCompleted);
    assert.equal(mcp.timeSpentSeconds, expectedSeconds);
    return mcp;
  };
  const renderedMcpProjection = async (expectedCompleted, expectedTotal, reconVisible) => {
    for (const pathname of ['/workshop-dashboard', '/workshop/challenges', '/workshop/progress']) {
      await page.goto(`${base}${pathname}`, { waitUntil: 'domcontentloaded' });
      if (pathname === '/workshop/progress') {
        await page.waitForFunction(() => location.pathname === '/workshop-dashboard', { timeout: 15000 });
      }
      await waitForRenderedMcpCount(page, expectedCompleted, expectedTotal);
      const expectedTime = pathname === '/workshop/challenges' ? '< 1m' : '37s';
      await page.waitForFunction(mcpCardMatches, {}, expectedCompleted, expectedTotal,
        [expectedTime], reconVisible ? [] : [mcpReconLabel]);
      if (pathname === '/workshop/challenges') {
        await page.waitForFunction(mcpObjectiveStylesMatch, {}, mcpReconLabel, mcpIncompleteLabel, reconVisible);
      }
    }
  };

  const learnerInitialMcp = await learnerMcpProjection(1, 11, 37);
  const currentAdminMcp = await adminMcpProjection(firstStudent.id, 1, 11, 37);
  assert.deepEqual(learnerInitialMcp, currentAdminMcp,
    'genuine student session and fresh admin view must share the current MCP projection');
  assert.deepEqual(withoutRowConfigRevision(currentAdminMcp), withoutRowConfigRevision(initialAdminMcp),
    'unrelated XSS visibility changes must preserve every substantive MCP projection field');
  assert.ok(currentAdminMcp.configRevision > initialAdminMcp.configRevision,
    'fresh MCP projections must expose the revision advanced by the XSS visibility sequence');
  assert.deepEqual(learnerInitialMcp.objectives.map(objective => objective.id), mcpObjectiveIds);
  const initialLearnerRecon = learnerInitialMcp.objectives.find(objective => objective.id === 'mcp_recon');
  assert.equal(initialLearnerRecon.completed, true);
  assert.equal(initialLearnerRecon.hintVisible, false,
    'the rendered administrator hint toggle must propagate to the learner projection');
  assert.equal(initialLearnerRecon.solutionVisible, reconSolutionEnabled,
    'disabling the hint must preserve the independent learner solution control');
  const currentSiblingMcp = await adminMcpProjection(secondStudent.id, 0, 11, 0);
  assert.deepEqual(withoutRowConfigRevision(currentSiblingMcp), withoutRowConfigRevision(siblingInitialMcp),
    'unrelated XSS visibility changes must preserve every substantive sibling MCP field');
  assert.equal(currentSiblingMcp.configRevision, currentAdminMcp.configRevision,
    'owner and sibling MCP projections must expose the same current configuration revision');
  assert.ok(currentSiblingMcp.configRevision > siblingInitialMcp.configRevision,
    'fresh sibling MCP projection must advance beyond its pre-XSS snapshot revision');
  await renderedMcpProjection(1, 11, true);
  await page.goto(`${base}/workshop/challenges`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(mcpObjectiveHelpControlsMatch, {}, mcpReconLabel, false, reconSolutionEnabled);

  const hiddenToggle = await requestJson(base,
    '/api/admin/workshops/mcp_workshop/objectives/mcp_recon/toggle', loginBody.token,
    { method: 'POST', body: { enabled: false } });
  assert.equal(hiddenToggle.status, 200);
  const [hiddenObjectives, hiddenSolutions] = await Promise.all([
    requestJson(base, '/api/admin/workshops/mcp_workshop/objectives', loginBody.token),
    requestJson(base, '/api/admin/mcp-workshop/solutions', loginBody.token),
  ]);
  assert.deepEqual(hiddenObjectives.body.objectives.map(objective => objective.objective_id), mcpObjectiveIds,
    'admin objective configuration retains disabled catalog entries');
  assert.deepEqual(hiddenSolutions.body.objectives.map(objective => objective.objective_id), mcpObjectiveIds,
    'solution configuration remains catalog-complete while an objective is hidden');
  assert.equal(hiddenObjectives.body.objectives.find(objective => objective.objective_id === 'mcp_recon').is_enabled, false);
  assert.equal(hiddenSolutions.body.objectives.find(objective => objective.objective_id === 'mcp_recon').solutions_enabled,
    reconSolutionEnabled, 'objective visibility must not mutate the independent solution gate');
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count FROM workshop_platform.completions
    WHERE user_id=$1 AND workshop_key='mcp_workshop' AND objective_id='mcp_recon'`, [firstStudent.id])).rows[0].count, 1,
  'hiding an objective must retain its canonical completion');
  assert.equal((await runtime.query(`SELECT COALESCE(sum(duration_seconds),0)::integer AS seconds
    FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key='mcp_workshop'`, [firstStudent.id])).rows[0].seconds, 37,
  'hiding an objective must retain canonical workshop time');
  const learnerHiddenMcp = await learnerMcpProjection(0, 10, 37);
  const adminHiddenMcp = await adminMcpProjection(firstStudent.id, 0, 10, 37);
  assert.deepEqual(learnerHiddenMcp, adminHiddenMcp);
  assert.equal(learnerHiddenMcp.objectives.some(objective => objective.id === 'mcp_recon'), false);
  const siblingHiddenMcp = await adminMcpProjection(secondStudent.id, 0, 10, 0);
  assert.equal(siblingHiddenMcp.objectives.some(objective => objective.id === 'mcp_recon'), false);
  await renderedMcpProjection(0, 10, false);

  const restoredToggle = await requestJson(base,
    '/api/admin/workshops/mcp_workshop/objectives/mcp_recon/toggle', loginBody.token,
    { method: 'POST', body: { enabled: true } });
  assert.equal(restoredToggle.status, 200);
  const learnerRestoredMcp = await learnerMcpProjection(1, 11, 37);
  const adminRestoredMcp = await adminMcpProjection(firstStudent.id, 1, 11, 37);
  assert.deepEqual(learnerRestoredMcp, adminRestoredMcp);
  assert.deepEqual(learnerRestoredMcp.objectives.map(objective => objective.id), mcpObjectiveIds);
  assert.equal(learnerRestoredMcp.objectives.find(objective => objective.id === 'mcp_recon').completed, true);
  const siblingRestoredMcp = await adminMcpProjection(secondStudent.id, 0, 11, 0);
  assert.deepEqual(siblingRestoredMcp.objectives.map(objective => objective.id), mcpObjectiveIds);
  assert.equal(siblingRestoredMcp.objectives.some(objective => objective.completed), false);
  await renderedMcpProjection(1, 11, true);

  await page.goto(`${base}/workshop/challenges`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(mcpObjectiveHelpControlsMatch, {}, mcpReconLabel, false, reconSolutionEnabled);

  const restoreHint = await requestJson(base,
    '/api/admin/workshops/mcp_workshop/hints/mcp_recon/toggle', loginBody.token,
    { method: 'POST', body: { enabled: reconHintEnabled } });
  assert.equal(restoreHint.status, 200);
  const learnerHintRestoredMcp = await learnerMcpProjection(1, 11, 37);
  const restoredLearnerRecon = learnerHintRestoredMcp.objectives
    .find(objective => objective.id === 'mcp_recon');
  assert.equal(restoredLearnerRecon.hintVisible, true);
  assert.equal(restoredLearnerRecon.solutionVisible, reconSolutionEnabled);
  assert.deepEqual(await adminMcpProjection(firstStudent.id, 1, 11, 37), learnerHintRestoredMcp,
    'hint restoration must preserve admin/learner count, completion and time parity');
  const siblingHintRestoredMcp = await adminMcpProjection(secondStudent.id, 0, 11, 0);
  assert.deepEqual({
    completedObjectiveCount: siblingHintRestoredMcp.completedObjectiveCount,
    objectiveCount: siblingHintRestoredMcp.objectiveCount,
    timeSpentSeconds: siblingHintRestoredMcp.timeSpentSeconds,
    completedIds: siblingHintRestoredMcp.objectives.filter(objective => objective.completed)
      .map(objective => objective.id),
  }, {
    completedObjectiveCount: siblingRestoredMcp.completedObjectiveCount,
    objectiveCount: siblingRestoredMcp.objectiveCount,
    timeSpentSeconds: siblingRestoredMcp.timeSpentSeconds,
    completedIds: siblingRestoredMcp.objectives.filter(objective => objective.completed)
      .map(objective => objective.id),
  }, 'hint restoration must preserve the sibling learner count, time and completion projection');
  assert.equal(siblingHintRestoredMcp.objectives
    .find(objective => objective.id === 'mcp_recon').hintVisible, true,
  'the restored global hint gate must also reach the sibling projection');
  // The already mounted learner view must receive the revision; no reload masks stale state.
  await waitForRenderedMcpCount(page, 1, 11);
  await page.waitForFunction(mcpObjectiveHelpControlsMatch, {}, mcpReconLabel, true, reconSolutionEnabled);

  const studentRunsPromise = page.waitForResponse(response => responsePath(response, '/api/agent-runs'));
  const studentJudgmentsPromise = page.waitForResponse(response => responsePath(response, '/api/agent-runs/judgments'));
  const studentDetailPromise = page.waitForResponse(response => responsePath(response, `/api/agent-runs/${runId}`));
  await page.goto(`${base}/workshop/agent-runs`, { waitUntil: 'domcontentloaded' });
  const studentRunsResponse = await studentRunsPromise;
  const studentRunsBody = await studentRunsResponse.json();
  assert.equal(studentRunsResponse.status(), 200);
  assert.deepEqual(studentRunsBody.runs.map(run => run.runId), [runId],
    'student run list must contain the owned run and exclude the sibling run');
  assert.ok(ownershipLookupOwners.filter(owner => owner === String(firstStudent.id)).length > adminOwnershipLookupCount,
    'student all-family list must consult the explicit SecureShop exclusion');
  const studentJudgmentsResponse = await studentJudgmentsPromise;
  const studentJudgmentsBody = await studentJudgmentsResponse.json();
  assert.equal(studentJudgmentsResponse.status(), 200);
  assert.equal(studentJudgmentsBody.judgments[0].evaluationId, evaluationId,
    'actual student judgments API must project the persisted receipt');
  const studentDetailResponse = await studentDetailPromise;
  const studentDetailBody = await studentDetailResponse.json();
  assert.equal(studentDetailResponse.status(), 200, 'owned run detail must be allowed');
  assert.equal(studentDetailBody.run.runId, runId);
  assert.equal(studentDetailBody.judgments[0].evaluationId, evaluationId);
  await page.waitForSelector('[aria-label="Your agent run inspector"]');
  await waitForText(page, controlledReceiptExplanation);
  await waitForText(page, 'Recent evaluations');

  const siblingDetail = await page.evaluate(async sibling => {
    const response = await fetch(`/api/agent-runs/${encodeURIComponent(sibling)}`, {
      headers: { authorization: `Bearer ${localStorage.getItem('token')}` },
    });
    return { status: response.status, body: await response.json() };
  }, siblingRunId);
  assert.equal(siblingDetail.status, 404,
    'authenticated student must not learn whether a sibling-owned run exists');
  assert.equal(siblingDetail.body.error, 'Agent run not found');

  failJudgmentRefresh = true;
  const failedJudgments = page.waitForResponse(response => responsePath(response, '/api/agent-runs/judgments'));
  await page.evaluate(() => {
    const inspector = document.querySelector('[aria-label="Your agent run inspector"]');
    const refresh = [...inspector.querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Refresh');
    if (!refresh) throw new Error('Student inspector refresh unavailable');
    refresh.click();
  });
  assert.equal((await failedJudgments).status(), 503);
  await waitForText(page, 'Previously loaded results may be out of date. Use Refresh to retry.');
  assert.match(await bodyText(page), new RegExp(controlledReceiptExplanation),
    'failed judgment refresh must retain the previously loaded receipt');
  failJudgmentRefresh = false;
  const recoveredJudgments = page.waitForResponse(response => responsePath(response, '/api/agent-runs/judgments'));
  await page.evaluate(() => {
    const inspector = document.querySelector('[aria-label="Your agent run inspector"]');
    [...inspector.querySelectorAll('button')]
      .find(button => button.textContent.trim() === 'Refresh').click();
  });
  assert.equal((await recoveredJudgments).status(), 200);
  await page.waitForFunction(() => !document.body.innerText.includes('Previously loaded results may be out of date.'),
    { timeout: 10000 });
  assert.match(await bodyText(page), new RegExp(controlledReceiptExplanation));

  assert.deepEqual(blockedOrigins, [], `production bundle attempted external origins: ${blockedOrigins.join(', ')}`);
  assert.deepEqual(pageErrors, [], `production admin bundle emitted page errors: ${pageErrors.join('; ')}`);
  qualificationCompleted = true;
  journal.status = 'test_body_passed';
  await persistJournal();
});

module.exports = {
  assertConditionalBrowserRead,
  mcpCardMatches,
  mcpObjectiveStylesMatch,
  mcpAdminModalMatches,
  mcpObjectiveHelpControlsMatch,
  clickMcpManageObjectives,
  clickMcpReconHint,
  clickMcpReconSolution,
};
