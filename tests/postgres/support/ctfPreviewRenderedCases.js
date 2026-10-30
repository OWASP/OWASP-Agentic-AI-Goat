'use strict';
// Controlled, stage-one-only rendered Preview facet. No original CTF receipt or credit is amended.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const content = require('./ctfRecoveryRenderedCases');

const PROFILE = 'ctf-preview-q05';
const FACTS = Object.freeze(['cancelNoPostOrProvider', 'dialogAbaNoPostOrProvider',
  'singleFlightOnePostOneProvider', 'closeAbortsProviderWithoutPublication',
  'stage1NoLanguageOrOutputDefense', 'allDurableStateUnchanged',
  'noObjectiveJudgeOrCredit', 'providerDiagnosticsNotQualification']);
const EXCLUDED = Object.freeze(['model-qualification', 'objective-judge',
  'gameplay-credit', 'outbox-operation-recovery']);
const WITNESS = Object.freeze(['targetStageUnchanged', 'siblingStageUnchanged',
  'progressUnchanged', 'attemptsUnchanged', 'judgmentsUnchanged',
  'historyUnchanged', 'outboxUnchanged']);
const LIMITS = Object.freeze({ browserActions: 1200, apiRequests: 1200,
  deadlineMs: 360000, providerCalls: 2 });
const DECIMAL = /^[1-9][0-9]*$/;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function seedPreviewSiblingHistoryBeforeBootstrap(migration) {
  assert(migration && typeof migration.query === 'function');
  await migration.query("INSERT INTO ctf.ctf_progress(participant_id,stage_id,status,started_at,completed_at,completion_time,attempts_count) VALUES(1001,2,'completed',clock_timestamp()-interval '60 seconds',clock_timestamp(),60000,1)");
  await migration.query("INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,ai_response) VALUES(1001,2,1,'owned sibling preview history','owned sibling response')");
  await migration.query("INSERT INTO ctf.ctf_sessions(participant_id,session_token,is_active,total_active_time) VALUES(1001,'owned-preview-sibling',1,1000)");
}
async function assertPreviewSiblingHistory(migration) {
  assert.deepEqual((await migration.query("SELECT participant_id,stage_id,status,completion_time::text AS completion_time,attempts_count FROM ctf.ctf_progress WHERE participant_id=1001 AND stage_id=2")).rows,
    [{ participant_id: 1001, stage_id: 2, status: 'completed', completion_time: '60000', attempts_count: 1 }]);
  assert.deepEqual((await migration.query("SELECT participant_id,stage_id,attempt_number,payload,ai_response FROM ctf.ctf_attempts WHERE participant_id=1001 AND stage_id=2")).rows,
    [{ participant_id: 1001, stage_id: 2, attempt_number: 1, payload: 'owned sibling preview history', ai_response: 'owned sibling response' }]);
  assert.deepEqual((await migration.query("SELECT participant_id,session_token,is_active,total_active_time FROM ctf.ctf_sessions WHERE participant_id=1001 AND session_token='owned-preview-sibling'")).rows,
    [{ participant_id: 1001, session_token: 'owned-preview-sibling', is_active: 1, total_active_time: 1000 }]);
}
function exactKeys(value, keys) {
  assert(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
}
function assertPreviewDatabaseName(pathname, state, kind, nonce = null) {
  assert(['FRESH', 'POPULATED'].includes(state));
  assert(['IDENTITY', 'CTF'].includes(kind));
  const match = pathname.match(new RegExp(
    `^/owasp_ai_goat_test_ctf_preview_${state[0].toLowerCase()}_${kind[0].toLowerCase()}_([a-f0-9]{12})$`));
  assert(match, 'Exact disposable Preview database name required');
  if (nonce !== null) assert.equal(match[1], nonce);
  return match[1];
}
function assertPreviewProviderReservation(ledger) {
  assert(Array.isArray(ledger) && ledger.length < LIMITS.providerCalls,
    'Preview physical provider boundary exceeded');
}
function reservePreviewProvider(ledger, entry) {
  assertPreviewProviderReservation(ledger);
  assert(entry && typeof entry === 'object' && !Array.isArray(entry));
  ledger.push(entry);
  return entry;
}
const PREVIEW_READS = new Set(['/api/auth/status', '/api/auth/signup-config',
  '/api/workshop/challenges', '/api/workshop/time/summary', '/api/workshop/config',
  '/api/workshop/config/snapshot', '/api/workshop/config/revision',
  '/api/admin/challenges', '/api/admin/students', '/api/admin/config',
  '/api/admin/users/locked', '/api/admin/solutions', '/api/admin/activity-stats',
  '/api/admin/activity-logs', '/api/admin/pi-workshop/solutions',
  '/api/admin/xss-workshop/objective-solutions',
  '/api/admin/csrf-workshop/objective-solutions',
  '/api/admin/finflow-workshop/solutions',
  '/api/admin/supply-chain-workshop/solutions',
  '/api/admin/ea-workshop/solutions',
  '/api/admin/ipi-workshop/solutions',
  '/api/admin/mcp-workshop/solutions',
  '/api/admin/sql-injection-workshop/solutions',
  '/api/admin/nosql-injection-workshop/solutions',
  '/api/changes/revisions', '/api/ctf/config', '/api/ctf/stages',
  '/api/ctf/status', '/api/ctf/leaderboard', '/api/ctf/admin/stages',
  '/api/ctf/admin/solutions', '/api/ctf/admin/participants',
  '/api/ctf/admin/analytics', '/api/ctf/admin/attempts']);
function previewApiAllowed(method, pathname, auxiliary = false) {
  if (auxiliary) return method === 'GET' && pathname === '/api/ctf/config';
  return method === 'GET' && PREVIEW_READS.has(pathname) ||
    method === 'POST' && pathname === '/api/ctf/admin/stages/1/preview';
}
function previewReadinessSummary(view, roster) {
  assert(view && roster);
  return { activeTab: ['levels', 'other', 'unknown', 'unavailable'].includes(view.activeTab)
    ? view.activeTab : 'unknown',
  rowCount: Number.isSafeInteger(view.rowCount) && view.rowCount >= -1 && view.rowCount <= 1000
    ? view.rowCount : -1,
  rosterRequests: Math.min(1200, Math.max(0, Number.isSafeInteger(roster.requests) ? roster.requests : 0)),
  rosterStatuses: (Array.isArray(roster.statuses) ? roster.statuses : [])
    .filter(status => Number.isSafeInteger(status) && status >= 100 && status <= 599).slice(0, 8),
  rosterFailures: Math.min(1200, Math.max(0, Number.isSafeInteger(roster.failures) ? roster.failures : 0)) };
}
async function waitPreviewRow(page, waitHandle, action, receipt, roster, save) {
  try { return await waitHandle(page, previewRow); }
  catch (error) {
    const view = await action(() => page.evaluate(() => {
      const selected = [...document.querySelectorAll('nav[aria-label="CTF admin sections"] button')]
        .filter(button => button.getAttribute('aria-selected') === 'true');
      return { activeTab: selected.length !== 1 ? 'unknown'
        : selected[0].textContent.trim() === 'Levels' ? 'levels' : 'other',
      rowCount: Math.min(1000, document.querySelectorAll('table tbody tr').length) };
    })).catch(() => ({ activeTab: 'unavailable', rowCount: -1 }));
    receipt.readiness = previewReadinessSummary(view, roster);
    save();
    throw error;
  }
}
async function currentPreviewBearer(page, action, adapter, actorId, sessionId) {
  const token = await action(() => page.evaluate(() => localStorage.getItem('token')));
  assert(typeof token === 'string' && token.length > 0);
  const current = await adapter.validateSession(token);
  assert.equal(String(current?.user?.id), actorId);
  assert.equal(String(current?.session?.id), sessionId);
  return { token, bearer: `Bearer ${token}` };
}
async function heldPreviewDoubleClick(firstClick, providerStarted, secondClick, release) {
  let timeout;
  try {
    await firstClick();
    await Promise.race([providerStarted, new Promise((_, reject) => {
      timeout = setTimeout(() => reject(Error('Preview first provider-start deadline')), 15000);
    })]);
    await secondClick();
  } finally { clearTimeout(timeout); release(); }
}
function assertCtfPreviewReceipt(r) {
  exactKeys(r, ['version', 'profile', 'targetStageId', 'siblingStageId',
    'mountedActorId', 'mountedSessionId', 'cases', 'providerDiagnostics',
    'storeWitness', 'facts', 'excluded', 'unexpectedApiPaths',
    'browserActions', 'apiRequests', 'stage', 'judgeCalls', 'genuineCredit']);
  assert.equal(r.version, 1); assert.equal(r.profile, PROFILE);
  assert.equal(r.targetStageId, 1); assert.equal(r.siblingStageId, 2);
  assert.match(r.mountedActorId, DECIMAL); assert.match(r.mountedSessionId, DECIMAL);
  exactKeys(r.cases, ['cancel', 'dialogAba', 'singleFlight', 'postDispatchClose']);
  assert.deepEqual(r.cases.cancel, { browserPosts: 0, serverPosts: 0,
    providerStarts: 0, uiPublished: false, stateInvariant: true });
  assert.deepEqual(r.cases.dialogAba, { browserPosts: 0, serverPosts: 0,
    providerStarts: 0, uiPublished: false, stateInvariant: true, eventsObserved: 2 });
  assert.deepEqual(r.cases.singleFlight, { browserPosts: 1, serverPosts: 1,
    providerStarts: 1, uiPublished: true, stateInvariant: true, status: 200 });
  assert.deepEqual(r.cases.postDispatchClose, { browserPosts: 1, serverPosts: 1,
    providerStarts: 1, uiPublished: false, stateInvariant: true, clientAborted: true });
  assert.deepEqual(r.providerDiagnostics, { kind: 'controlled-synthetic-transport',
    physicalStarted: 2, completed: 1, clientAborted: 1, maxPhysicalCalls: 2 });
  exactKeys(r.storeWitness, WITNESS);
  for (const key of WITNESS) assert.equal(r.storeWitness[key], true);
  exactKeys(r.facts, FACTS); for (const key of FACTS) assert.equal(r.facts[key], true);
  assert.deepEqual(r.excluded, EXCLUDED); assert.deepEqual(r.unexpectedApiPaths, []);
  assert(Number.isSafeInteger(r.browserActions) && r.browserActions >= 1 && r.browserActions <= LIMITS.browserActions);
  assert(Number.isSafeInteger(r.apiRequests) && r.apiRequests >= 1 && r.apiRequests <= LIMITS.apiRequests);
  assert.equal(r.stage, 'complete'); assert.equal(r.judgeCalls, 0); assert.equal(r.genuineCredit, 0);
  return true;
}
function canonicalRows(rows) { return rows.map(row => row.encoded).sort(); }
async function snapshotPrivateStores(i, c) {
  const ctfTables = ['ctf_stages', 'ctf_config', 'ctf_participants', 'ctf_progress',
    'ctf_attempts', 'ctf_judgments', 'ctf_sessions', 'ctf_leaderboard',
    'ctf_events', 'ctf_bans', 'ctf_technique_blocklist', 'ctf_payload_blocklist',
    'ctf_stage_teaching_content', 'projection_receipts'];
  const identityTables = ['users', 'user_sessions', 'ctf_outbox', 'ctf_decisions',
    'ctf_adaptive_memory', 'ctf_participant_bindings', 'ctf_progress_bindings',
    'ctf_stage_bindings', 'ctf_config_binding', 'ctf_registration_reservations',
    'ctf_attempt_admissions', 'ctf_decision_proposals', 'ctf_decision_inputs'];
  const graphTables = ['owners', 'runs', 'effects', 'events'];
  const result = {};
  for (const [schema, pool, tables] of [['ctf', c.migration, ctfTables],
    ['identity', i.migration, identityTables], ['graph_runtime', i.migration, graphTables]]) {
    for (const table of tables) {
      const key = `${schema}.${table}`;
      const rows = (await pool.query(`SELECT to_jsonb(t)::text AS encoded FROM ${key} t`)).rows;
      result[key] = canonicalRows(rows);
    }
  }
  return result;
}
function assertExactStoreTransition(before, after) {
  assert.deepEqual(Object.keys(after).sort(), Object.keys(before).sort(),
    'Preview canonical store coverage changed');
  for (const table of Object.keys(before)) {
    // Compare every raw canonical row, but never put a policy, token, prompt or model value in TAP.
    assert.equal(JSON.stringify(after[table]) === JSON.stringify(before[table]), true,
      `Preview changed canonical ${table} rows`);
  }
  return true;
}
function immutableWitness(before, after) {
  assertExactStoreTransition(before, after);
  return Object.fromEntries(WITNESS.map(key => [key, true]));
}
function assertReceiptFile(file) {
  const stat = fs.lstatSync(file), parent = fs.lstatSync(path.dirname(file));
  assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && stat.uid === process.getuid()
    && (stat.mode & 0o777) === 0o600 && stat.size <= 65536);
  assert(parent.isDirectory() && !parent.isSymbolicLink() && parent.uid === process.getuid()
    && (parent.mode & 0o777) === 0o700);
  assert.equal(fs.realpathSync(file), file);
}

function previewRow() {
  const rows = [...document.querySelectorAll('table tbody tr')].filter(row =>
    row.cells?.[0]?.textContent.trim() === '1' &&
    row.cells?.[1]?.textContent.trim() === 'The Doorway' && row.getClientRects().length);
  return rows.length === 1 ? rows[0] : null;
}
function previewButton() {
  const buttons = [...document.querySelectorAll('button')].filter(button =>
    button.textContent.trim() === 'Preview' && button.getClientRects().length && !button.disabled);
  return buttons.length === 1 ? buttons[0] : null;
}
function previewDialog() {
  const dialogs = [...document.querySelectorAll('[role="dialog"]')].filter(dialog =>
    dialog.querySelector('h3')?.textContent.trim() === 'Disclosure Preview: The Doorway' &&
    dialog.getClientRects().length);
  if (dialogs.length !== 1) return null;
  const dialog = dialogs[0];
  const label = [...dialog.querySelectorAll('label')].find(x => x.textContent.trim() === 'Test Payload');
  const textarea = label?.parentElement?.querySelector('textarea');
  const runs = [...dialog.querySelectorAll('button')].filter(x => x.textContent.trim() === 'Run Preview' && !x.disabled);
  const closes = [...dialog.querySelectorAll('button')].filter(x => x.getAttribute('aria-label') === 'Close' && !x.disabled);
  return textarea?.getClientRects().length && runs.length === 1 && closes.length === 1 ? dialog : null;
}
async function runCtfPreviewRenderedCases({ state, i, c, request, admin, ledger, web,
  origin, jwtSecret, contentHttp, previewHttp, holdTransport }) {
  const runtimeDirectory = fs.realpathSync(process.env.CTF_CONTENT_RUNTIME_DIRECTORY);
  const receiptPath = path.resolve(process.env.CTF_PREVIEW_Q05_RECEIPT);
  assert.equal(receiptPath, path.join(runtimeDirectory, 'ctf-preview-q05-result.json'));
  if (state === 'POPULATED') {
    assertReceiptFile(receiptPath);
    assertCtfPreviewReceipt(JSON.parse(fs.readFileSync(receiptPath, 'utf8')));
    const stage = (await c.runtime.query('SELECT id,stage_number,defense_style,adaptive_mode FROM ctf.ctf_stages WHERE stage_number=1')).rows[0];
    assert.deepEqual([stage?.id, stage?.stage_number, stage?.defense_style, stage?.adaptive_mode],
      [1, 1, '[]', 'none']);
    assert.equal(ledger.length, LIMITS.providerCalls,
      'POPULATED Preview migration must not add physical provider calls');
    return;
  }
  assert.equal(state, 'FRESH');
  assert.equal(fs.existsSync(receiptPath), false, 'Preview receipt must be created fresh');
  const r = { version: 1, profile: PROFILE, targetStageId: 1, siblingStageId: 2,
    mountedActorId: null, mountedSessionId: null, cases: {}, providerDiagnostics: null,
    storeWitness: null, facts: {}, excluded: [...EXCLUDED], unexpectedApiPaths: [],
    browserActions: 0, apiRequests: 0, stage: 'setup', judgeCalls: 0, genuineCredit: 0 };
  const save = () => { fs.writeFileSync(receiptPath, JSON.stringify(r, null, 2), { mode: 0o600 }); assertReceiptFile(receiptPath); };
  const checkpoint = stage => { r.stage = stage; r.apiRequests = contentHttp.apiRequests; save(); };
  save();
  const evidence = fs.realpathSync(process.env.CTF_RENDERED_EVIDENCE);
  const originalEnv = {};
  for (const [key, value] of Object.entries({
    IDENTITY_DATABASE_URL: process.env.PG_CTF_AUTHORITY_APPLICATION_FRESH_IDENTITY_RUNTIME_URL,
    IDENTITY_MIGRATION_DATABASE_URL: process.env.PG_CTF_AUTHORITY_APPLICATION_FRESH_IDENTITY_MIGRATION_URL,
    JWT_SECRET: jwtSecret,
  })) { originalEnv[key] = process.env[key]; process.env[key] = value; }
  let mounted, browser, pages, instructor, other, work, timer, gate, cancelled = false, primary;
  const roster = { requests: 0, statuses: [], failures: 0 };
  const active = () => { assert(!cancelled, 'Preview deadline exceeded');
    assert(ledger.length <= LIMITS.providerCalls, 'Preview physical provider cap exceeded'); };
  const action = fn => { active(); assert(++r.browserActions <= LIMITS.browserActions); return fn(); };
  const pointer = (page, handle) => content.contentPointerClick(page, handle, action);
  const waitHandle = async (page, predicate) => {
    const handle = await action(() => page.waitForFunction(predicate, { polling: 100, timeout: 15000 }));
    assert(handle.asElement()); return handle;
  };
  const open = async () => {
    const existing = await action(() => instructor.evaluateHandle(previewButton));
    const expanded = Boolean(existing.asElement()); await existing.dispose();
    if (!expanded) {
      const row = await waitPreviewRow(instructor, waitHandle, action, r, roster, save);
      try { await pointer(instructor, row); } finally { await row.dispose(); }
    }
    const button = await waitHandle(instructor, previewButton);
    try { await pointer(instructor, button); } finally { await button.dispose(); }
    const dialog = await waitHandle(instructor, previewDialog); await dialog.dispose();
  };
  const close = async () => {
    const handle = await action(() => instructor.evaluateHandle(() =>
      [...document.querySelectorAll('[role="dialog"] button')].find(button =>
        button.getAttribute('aria-label') === 'Close' && button.getClientRects().length)));
    assert(handle.asElement());
    try { await pointer(instructor, handle); } finally { await handle.dispose(); }
    const gone = await action(() => instructor.waitForFunction(() =>
      ![...document.querySelectorAll('[role="dialog"]')].some(dialog =>
        dialog.querySelector('h3')?.textContent.startsWith('Disclosure Preview:')),
    { timeout: 15000 })); await gone.dispose();
  };
  const fill = async value => {
    const handle = await action(() => instructor.evaluateHandle(() => {
      const dialog = [...document.querySelectorAll('[role="dialog"]')].find(x =>
        x.querySelector('h3')?.textContent.trim() === 'Disclosure Preview: The Doorway');
      const label = [...(dialog?.querySelectorAll('label') || [])].find(x => x.textContent.trim() === 'Test Payload');
      return label?.parentElement?.querySelector('textarea') || null;
    }));
    assert(handle.asElement());
    try { await action(() => handle.type(value));
      assert.equal(await action(() => handle.evaluate(x => x.value)), value); }
    finally { await handle.dispose(); }
  };
  const runButton = async () => {
    const handle = await action(() => instructor.evaluateHandle(() => {
      const dialog = [...document.querySelectorAll('[role="dialog"]')].find(x =>
        x.querySelector('h3')?.textContent.trim() === 'Disclosure Preview: The Doorway');
      return [...(dialog?.querySelectorAll('button') || [])].find(x =>
        x.textContent.trim() === 'Run Preview' && !x.disabled) || null;
    })); assert(handle.asElement()); return handle;
  };
  const noDialog = async () => !await action(() => instructor.evaluate(() =>
    [...document.querySelectorAll('[role="dialog"]')].some(x =>
      x.querySelector('h3')?.textContent.startsWith('Disclosure Preview:'))));
  const pauseUntil = async predicate => {
    const until = Date.now() + 15000;
    while (!predicate() && Date.now() < until) await sleep(25);
    assert(predicate(), 'Preview bounded observation unavailable');
  };
  try {
    await require('../../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(i.migration);
    const adapter = require('../../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const stores = require('../../../server/services/postgresPlatformStores').getPostgresPlatformStores();
    mounted = await require('../../fixtures/legacyFileSsiFullAppParity').mountLegacyParityRoutes({ app: web,
      adapter, pool: i.runtime, migration: i.migration, progress: stores.progress,
      config: stores.config, identity: adapter.repository });
    const authority = await adapter.validateSession(mounted.adminToken);
    assert(authority?.user?.id > 0 && authority?.session?.id > 0);
    assert.notEqual(String(authority.user.id), String(admin.user.id));
    r.mountedActorId = String(authority.user.id);
    r.mountedSessionId = String(authority.session.id);
    const stages = (await c.runtime.query('SELECT id,stage_number,stage_name,defense_style,adaptive_mode FROM ctf.ctf_stages WHERE stage_number IN (1,2) ORDER BY stage_number')).rows;
    assert.equal(stages.length, 2);
    assert.deepEqual([stages[0].id, stages[0].stage_number, stages[0].stage_name,
      stages[0].defense_style, stages[0].adaptive_mode], [1, 1, 'The Doorway', '[]', 'none']);
    assert.deepEqual([stages[1].id, stages[1].stage_number], [2, 2]);
    // These exact rows entered the canonical bootstrap snapshot before activation.
    // Migration-role writes here would fence delivery and make the roster return 503.
    await assertPreviewSiblingHistory(c.migration);
    await require('../../../server/database/postgres/ctfDeliveryActivation')
      .createCtfDeliveryActivation({ identityPool: i.runtime, ctfPool: c.runtime }).loadCurrent();
    const baseline = await snapshotPrivateStores(i, c);
    assert(baseline['ctf.ctf_progress'].length > 0 && baseline['ctf.ctf_attempts'].length > 0
      && baseline['ctf.ctf_sessions'].length > 0);
    const report = JSON.parse(fs.readFileSync(process.env.CTF_CONTENT_BUILD_REPORT, 'utf8'));
    const root = path.resolve(__dirname, '../../..');
    const expectedBuild = report.inputMode === 'private-external-v1'
      ? fs.realpathSync(report.outputRoot) : path.join(root, 'client/build');
    const build = fs.realpathSync(process.env.CTF_CONTENT_BUILD_DIRECTORY);
    assert.equal(build, expectedBuild); assert(fs.existsSync(path.join(build, 'index.html')));
    web.use('/api', (_req, res) => res.status(404).json({ error: 'Unmapped Preview API' }));
    web.use(require('express').static(build));
    web.get('/{*path}', (_req, res) => res.sendFile(path.join(build, 'index.html')));
    browser = await require('../../fixtures/ctfTenContentBrowserAdmission').launchCtfPreviewBrowser(evidence, 'preview');
    pages = content.contentActorPages(browser);
    instructor = await action(() => pages.newPage());
    instructor.setDefaultTimeout(15000);
    await action(() => instructor.setViewport({ width: 1280, height: 900 }));
    await action(() => instructor.setRequestInterception(true));
    const route = '/api/ctf/admin/stages/1/preview';
    const seen = { posts: [], failed: [], responses: [] };
    instructor.on('request', req => {
      const url = new URL(req.url());
      if (url.origin === origin && req.method() === 'GET' && url.pathname === '/api/ctf/admin/stages')
        roster.requests++;
      if (url.origin === origin && req.method() === 'POST' && url.pathname === route) {
        let body; try { body = JSON.parse(req.postData() || ''); } catch { body = null; }
        seen.posts.push({ body, bearer: req.headers().authorization || null });
      }
      if (['about:', 'data:', 'blob:'].includes(url.protocol)) return req.continue();
      if (url.origin !== origin) return req.abort();
      if (req.method() !== 'GET' && !url.pathname.startsWith('/api/')) return req.abort();
      if (url.pathname.startsWith('/api/') && !previewApiAllowed(req.method(), url.pathname)) {
        if (r.unexpectedApiPaths.length < 32) r.unexpectedApiPaths.push({ method: req.method(), path: url.pathname });
        return req.abort();
      }
      return req.continue();
    });
    instructor.on('requestfailed', req => { const url = new URL(req.url());
      if (url.origin === origin && req.method() === 'GET' && url.pathname === '/api/ctf/admin/stages')
        roster.failures++;
      if (url.origin === origin && req.method() === 'POST' && url.pathname === route) seen.failed.push(url.pathname); });
    instructor.on('response', response => { const url = new URL(response.url());
      if (url.origin === origin && response.request().method() === 'GET' && url.pathname === '/api/ctf/admin/stages'
        && roster.statuses.length < 8) roster.statuses.push(response.status());
      if (url.origin === origin && response.request().method() === 'POST' && url.pathname === route)
        seen.responses.push(response); });
    await action(() => instructor.evaluateOnNewDocument(token => localStorage.setItem('token', token), mounted.adminToken));
    await action(() => instructor.goto(origin + '/admin/ctf-management', { waitUntil: 'domcontentloaded' }));
    const nav = await waitHandle(instructor, () => [...document.querySelectorAll('nav[aria-label="CTF admin sections"] button')]
      .find(button => button.textContent.trim() === 'Levels' && button.getClientRects().length));
    try { await pointer(instructor, nav); } finally { await nav.dispose(); }
    const tokenB = admin.headers.authorization.slice(7);
    const currentBearer = () => currentPreviewBearer(instructor, action, adapter,
      r.mountedActorId, r.mountedSessionId);
    work = (async () => {
      checkpoint('preview-cancel');
      await open(); await close();
      assert.equal(await noDialog(), true);
      assert.equal(seen.posts.length, 0); assert.equal(previewHttp.serverPosts, 0); assert.equal(ledger.length, 0);
      assertExactStoreTransition(baseline, await snapshotPrivateStores(i, c));
      r.cases.cancel = { browserPosts: 0, serverPosts: 0, providerStarts: 0,
        uiPublished: false, stateInvariant: true }; save();

      checkpoint('preview-dialog-aba');
      await open();
      const { token: tokenA } = await currentBearer();
      assert.notEqual(tokenA, tokenB);
      other = await action(() => instructor.browserContext().newPage());
      await action(() => other.setRequestInterception(true));
      other.on('request', req => { const url = new URL(req.url());
        if (['about:', 'data:', 'blob:'].includes(url.protocol)) return req.continue();
        return url.origin === origin && previewApiAllowed(req.method(), url.pathname, true)
          ? req.continue() : req.abort(); });
      await action(() => other.goto(origin + '/api/ctf/config', { waitUntil: 'domcontentloaded' }));
      await action(() => instructor.evaluate(() => { window.__ctfPreviewEvents = 0;
        window.addEventListener('storage', event => { if (event.key === 'token') window.__ctfPreviewEvents++; }); }));
      await action(() => other.evaluate(([b, a]) => {
        localStorage.setItem('token', b); localStorage.setItem('token', a);
      }, [tokenB, tokenA]));
      const events = await action(() => instructor.waitForFunction(() => window.__ctfPreviewEvents >= 2,
        { timeout: 15000 })); await events.dispose();
      const eventsObserved = await action(() => instructor.evaluate(() => window.__ctfPreviewEvents));
      assert.equal(eventsObserved, 2);
      const retired = await action(() => instructor.waitForFunction(() =>
        ![...document.querySelectorAll('[role="dialog"]')].some(x =>
          x.querySelector('h3')?.textContent.startsWith('Disclosure Preview:')),
      { timeout: 15000 })); await retired.dispose();
      await action(() => other.close()); other = null;
      assert.equal(seen.posts.length, 0); assert.equal(previewHttp.serverPosts, 0); assert.equal(ledger.length, 0);
      assertExactStoreTransition(baseline, await snapshotPrivateStores(i, c));
      r.cases.dialogAba = { browserPosts: 0, serverPosts: 0, providerStarts: 0,
        uiPublished: false, stateInvariant: true, eventsObserved }; save();

      checkpoint('preview-singleflight');
      await action(() => instructor.reload({ waitUntil: 'domcontentloaded' }));
      const navAgain = await waitHandle(instructor, () => [...document.querySelectorAll('nav[aria-label="CTF admin sections"] button')]
        .find(button => button.textContent.trim() === 'Levels' && button.getClientRects().length));
      try { await pointer(instructor, navAgain); } finally { await navAgain.dispose(); }
      await open(); await fill('A controlled, ordinary preview question.');
      const completedBearer = (await currentBearer()).bearer;
      gate = holdTransport(1);
      const run = await runButton();
      const box = await action(() => run.boundingBox()); assert(box && box.width > 0 && box.height > 0);
      const responseWait = action(() => instructor.waitForResponse(response =>
        new URL(response.url()).origin === origin && new URL(response.url()).pathname === route &&
        response.request().method() === 'POST', { timeout: 15000 }));
      try {
        await heldPreviewDoubleClick(() => pointer(instructor, run), gate.entered,
          () => action(() => instructor.mouse.click(box.x + box.width / 2, box.y + box.height / 2)),
          () => gate.release());
      } finally { gate = null; await run.dispose(); }
      const response = await responseWait;
      assert.equal(response.status(), 200);
      const body = await response.json();
      assert.equal(typeof body.defenseBlocked, 'boolean'); assert.equal(body.defenseBlocked, false);
      assert.equal(typeof body.wouldSucceed, 'boolean'); assert(body.classification?.tag);
      assert(Number.isFinite(body.classification.confidence)); assert(Array.isArray(body.previewTrace));
      const published = await action(() => instructor.waitForFunction(() => {
        const dialog = [...document.querySelectorAll('[role="dialog"]')].find(x =>
          x.querySelector('h3')?.textContent.trim() === 'Disclosure Preview: The Doorway');
        return !!dialog && [...dialog.querySelectorAll('h4')].some(x => x.textContent.trim() === 'Classification')
          && [...dialog.querySelectorAll('h4')].some(x => x.textContent.trim() === 'Defense Result');
      }, { timeout: 15000 })); await published.dispose();
      await pauseUntil(() => ledger[0]?.settlement === 'completed');
      assert.equal(seen.posts.length, 1); assert.equal(previewHttp.serverPosts, 1); assert.equal(ledger.length, 1);
      assert.deepEqual(seen.posts[0], { body: { payload: 'A controlled, ordinary preview question.' }, bearer: completedBearer });
      assertExactStoreTransition(baseline, await snapshotPrivateStores(i, c));
      r.cases.singleFlight = { browserPosts: 1, serverPosts: 1, providerStarts: 1,
        uiPublished: true, stateInvariant: true, status: 200 }; save();
      await close();

      checkpoint('preview-post-dispatch-close');
      await open(); await fill('A second controlled preview question.');
      const abortedBearer = (await currentBearer()).bearer;
      gate = holdTransport(1, { abortOnClose: true });
      const pending = await runButton();
      try { await pointer(instructor, pending); } finally { await pending.dispose(); }
      await Promise.race([gate.entered, sleep(15000).then(() => { throw Error('Preview provider-start deadline'); })]);
      assert.equal(ledger.length, 2); assert.equal(seen.posts.length, 2); assert.equal(previewHttp.serverPosts, 2);
      assert.deepEqual(seen.posts[1], { body: { payload: 'A second controlled preview question.' }, bearer: abortedBearer });
      await close();
      await pauseUntil(() => ledger[1]?.settlement === 'client-aborted');
      await pauseUntil(() => seen.failed.length === 1);
      assert.deepEqual(seen.failed, [route]);
      assert.equal(await noDialog(), true); assert.equal(seen.responses.length, 1);
      assertExactStoreTransition(baseline, await snapshotPrivateStores(i, c));
      r.cases.postDispatchClose = { browserPosts: 1, serverPosts: 1, providerStarts: 1,
        uiPublished: false, stateInvariant: true, clientAborted: true };
      r.providerDiagnostics = { kind: 'controlled-synthetic-transport', physicalStarted: ledger.length,
        completed: ledger.filter(x => x.settlement === 'completed').length,
        clientAborted: ledger.filter(x => x.settlement === 'client-aborted').length,
        maxPhysicalCalls: LIMITS.providerCalls };
      r.storeWitness = immutableWitness(baseline, await snapshotPrivateStores(i, c));
      r.facts = {
        cancelNoPostOrProvider: true, dialogAbaNoPostOrProvider: true,
        singleFlightOnePostOneProvider: true, closeAbortsProviderWithoutPublication: true,
        stage1NoLanguageOrOutputDefense: true, allDurableStateUnchanged: true,
        noObjectiveJudgeOrCredit: true, providerDiagnosticsNotQualification: true,
      };
      assert.deepEqual(r.unexpectedApiPaths, []);
      await pages.closePage(instructor); instructor = null;
      r.apiRequests = contentHttp.apiRequests; r.stage = 'postflight'; save();
    })();
    await Promise.race([work, new Promise((_, reject) => { timer = setTimeout(() => {
      cancelled = true; reject(Error('Preview 360-second deadline'));
    }, LIMITS.deadlineMs); })]);
  } catch (error) {
    primary = error; r.stage = 'failed'; r.apiRequests = contentHttp.apiRequests;
    save(); throw error;
  } finally {
    clearTimeout(timer); cancelled = true; gate?.release();
    const failures = [];
    for (const closeOwned of [() => other?.close(), () => pages?.close(), () => browser?.close()]) {
      try { await closeOwned(); } catch (error) { failures.push(error); }
    }
    if (work) {
      const drained = await Promise.race([work.then(() => true, () => true), sleep(4000).then(() => false)]);
      if (!drained) failures.push(Error('Preview work did not retire'));
    }
    if (mounted) try { await mounted.close(); } catch (error) { failures.push(error); }
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    r.apiRequests = contentHttp.apiRequests; save();
    if (failures.length) throw new AggregateError(primary ? [primary, ...failures] : failures,
      'Preview rendered browser cleanup failed', { cause: primary });
    if (!primary) {
      assert.equal(ledger.length, LIMITS.providerCalls);
      assert.deepEqual(ledger.map(row => row.settlement), ['completed', 'client-aborted']);
      assert.equal(previewHttp.serverPosts, 2);
      r.stage = 'complete'; assertCtfPreviewReceipt(r); save();
    }
  }
}

module.exports = { PROFILE, FACTS, EXCLUDED, WITNESS, LIMITS,
  seedPreviewSiblingHistoryBeforeBootstrap, assertPreviewSiblingHistory,
  assertPreviewDatabaseName, assertPreviewProviderReservation, reservePreviewProvider, previewApiAllowed,
  previewReadinessSummary, waitPreviewRow,
  currentPreviewBearer, heldPreviewDoubleClick, assertCtfPreviewReceipt, snapshotPrivateStores,
  assertExactStoreTransition, immutableWitness, assertReceiptFile,
  previewRow, previewButton, previewDialog, runCtfPreviewRenderedCases };
