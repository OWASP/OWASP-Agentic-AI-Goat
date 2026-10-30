'use strict';
// A separate, controlled rendered Config facet. It never amends the original 55-content receipt.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const content = require('./ctfRecoveryRenderedCases');

const PROFILE = 'ctf-config-q05';
const POST_PATH = '/api/ctf/admin/config';
const KEYS = Object.freeze(require('../../../server/data/ctfDefaults').configs.map(row => row.key));
const BOOLEAN = new Set(['ctf_enabled', 'ctf_visible_to_students', 'student_leaderboard_visible',
  'public_leaderboard_visible', 'ctf_registration_open', 'ctf_nav_visible',
  'ctf_show_technique_feedback', 'ctf_show_attempt_counter']);
const FACTS = Object.freeze(['cancelNoPost', 'dialogAbaNoPost', 'onePhysicalPostPerKey',
  'canonicalProjectionReadback', 'distinctRestoreOperations',
  'siblingStageProgressHistoryPreserved', 'noPreview', 'noMutationRetry', 'noModelJudgeOrCredit']);
const EXCLUDED = Object.freeze(['byte-identical-undo', 'provenance-rollback',
  'model-qualification', 'original-55-content']);
const LIMITS = Object.freeze({ browserActions: 1200, apiRequests: 1200, deadlineMs: 360000 });
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DECIMAL = /^[1-9][0-9]*$/;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const exactKeys = (value, keys) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort());

function assertConfigDatabaseName(pathname, state, kind, cohortNonce = null) {
  assert(['FRESH', 'POPULATED'].includes(state));
  assert(['IDENTITY', 'CTF'].includes(kind));
  const match = pathname.match(new RegExp(
    `^/owasp_ai_goat_test_ctf_config_${state[0].toLowerCase()}_${kind[0].toLowerCase()}_([a-f0-9]{12})$`));
  assert(match, 'Exact disposable Config database name required');
  if (cohortNonce !== null) assert.equal(match[1], cohortNonce);
  return match[1];
}

function assertOperation(value) {
  exactKeys(value, ['originalStatus', 'resolvedStatus', 'sameIdGets', 'operationId',
    'sequence', 'browserAckOperationId', 'ackMessage']);
  assert([200, 202].includes(value.originalStatus));
  assert.equal(value.resolvedStatus, 200);
  assert(Number.isSafeInteger(value.sameIdGets) && value.sameIdGets >= 0 && value.sameIdGets <= 32);
  assert.match(value.operationId, UUID); assert.match(value.sequence, DECIMAL);
  if (value.originalStatus === 202) {
    assert(value.sameIdGets >= 1); assert.equal(value.browserAckOperationId, value.operationId);
    assert.equal(value.ackMessage, null);
  } else {
    assert.equal(value.sameIdGets, 0); assert.equal(value.browserAckOperationId, null);
    assert.equal(value.ackMessage, 'Configuration updated successfully');
  }
}
function assertCtfConfigReceipt(r) {
  exactKeys(r, ['version', 'profile', 'mountedActorId', 'mountedSessionId', 'keys', 'cases',
    'facts', 'excluded', 'unexpectedApiPaths', 'browserActions', 'apiRequests',
    'stage', 'modelCalls', 'judgeCalls']);
  assert.equal(r.version, 1); assert.equal(r.profile, PROFILE);
  assert.match(r.mountedActorId, DECIMAL); assert.match(r.mountedSessionId, DECIMAL);
  assert.deepEqual(r.keys, KEYS); assert.equal(r.cases.length, KEYS.length);
  const ids = new Set(), sequences = new Set();
  let lastSequence = 0n;
  for (let index = 0; index < KEYS.length; index++) {
    const item = r.cases[index];
    exactKeys(item, ['key', 'previous', 'proposed', 'cancel', 'dialogTimeAba',
      'confirmed', 'durable', 'restore', 'siblingPreserved']);
    assert.equal(item.key, KEYS[index]); assert.equal(typeof item.previous, 'string');
    assert.equal(typeof item.proposed, 'string'); assert.notEqual(item.previous, item.proposed);
    assert.deepEqual(item.cancel, { noPost: true, unchanged: true });
    assert.deepEqual(item.dialogTimeAba, { eventsObserved: 2, noPost: true, unchanged: true });
    assertOperation(item.confirmed);
    exactKeys(item.durable, ['canonicalProjectionApplied', 'actorSessionBound', 'dbValueMatches',
      'adminGetMatches', 'publicGetMatches']);
    for (const value of Object.values(item.durable)) assert.equal(value, true);
    exactKeys(item.restore, ['scope', 'contentEquivalent', 'originalStatus', 'resolvedStatus',
      'sameIdGets', 'operationId', 'sequence', 'browserAckOperationId', 'ackMessage']);
    assert.equal(item.restore.scope, 'content-equivalence-only');
    assert.equal(item.restore.contentEquivalent, true);
    assertOperation(Object.fromEntries(Object.entries(item.restore).filter(([key]) =>
      !['scope', 'contentEquivalent'].includes(key))));
    assert(BigInt(item.restore.sequence) > BigInt(item.confirmed.sequence));
    for (const op of [item.confirmed, item.restore]) {
      assert(!ids.has(op.operationId)); assert(!sequences.has(op.sequence));
      assert(BigInt(op.sequence) > lastSequence); lastSequence = BigInt(op.sequence);
      ids.add(op.operationId); sequences.add(op.sequence);
    }
    assert.equal(item.siblingPreserved, true);
  }
  exactKeys(r.facts, FACTS); for (const name of FACTS) assert.equal(r.facts[name], true);
  assert.deepEqual(r.excluded, EXCLUDED); assert.deepEqual(r.unexpectedApiPaths, []);
  assert(Number.isSafeInteger(r.browserActions) && r.browserActions > 0 && r.browserActions <= LIMITS.browserActions);
  assert(Number.isSafeInteger(r.apiRequests) && r.apiRequests > 0 && r.apiRequests <= LIMITS.apiRequests);
  assert.equal(r.stage, 'complete'); assert.equal(r.modelCalls, 0); assert.equal(r.judgeCalls, 0);
  return true;
}

function proposedValue(key, previous) {
  if (BOOLEAN.has(key)) { assert(['true', 'false'].includes(previous)); return previous === 'true' ? 'false' : 'true'; }
  assert(/^(?:-1|0|[1-9][0-9]*)$/.test(previous));
  const next = BigInt(previous) + 1n;
  assert(next <= 2147483647n, 'Bounded numeric Config fixture value required');
  return String(next);
}
function assertConfigTransition(before, observed, key, value) {
  assert.deepEqual(Object.keys(before).sort(), [...KEYS].sort());
  assert.deepEqual(Object.keys(observed).sort(), [...KEYS].sort());
  assert(Object.hasOwn(before, key));
  assert.deepEqual(observed, { ...before, [key]: value });
  return true;
}
function configRow(key, isBoolean) {
  const labels = [...document.querySelectorAll('div')].filter(node =>
    node.children.length === 0 && node.textContent.trim() === key && node.getClientRects().length);
  if (labels.length !== 1) return null;
  const row = labels[0].parentElement?.parentElement;
  if (!row) return null;
  const controls = row.querySelectorAll(isBoolean ? 'button[role="switch"]' : 'input');
  if (controls.length !== 1 || !controls[0].getClientRects().length || controls[0].disabled) return null;
  return row;
}
async function waitConfigRow(page, key, isBoolean, action) {
  const row = await action(() => page.waitForFunction(configRow,
    { polling: 100, timeout: 15000 }, key, isBoolean));
  assert(row.asElement(), `Rendered Config row missing: ${key}`);
  return row;
}

async function runCtfConfigRenderedCases({ state, i, c, request, admin, ledger, web,
  origin, jwtSecret, contentHttp }) {
  const runtimeDirectory = fs.realpathSync(process.env.CTF_CONTENT_RUNTIME_DIRECTORY);
  const receiptPath = path.resolve(process.env.CTF_CONFIG_Q05_RECEIPT);
  assert.equal(receiptPath, path.join(runtimeDirectory, 'ctf-config-q05-result.json'));
  if (state === 'POPULATED') {
    assertCtfConfigReceipt(JSON.parse(fs.readFileSync(receiptPath, 'utf8')));
    const rows = (await c.runtime.query('SELECT key,value FROM ctf.ctf_config ORDER BY key')).rows;
    assert.deepEqual(Object.fromEntries(rows.map(({ key, value }) => [key, value])),
      Object.fromEntries(require('../../../server/data/ctfDefaults').configs
        .map(({ key, value }) => [key, value])));
    assert.equal(ledger.length, 0);
    return;
  }
  assert.equal(state, 'FRESH');
  const r = { version: 1, profile: PROFILE, mountedActorId: null, mountedSessionId: null,
    keys: [...KEYS], cases: [], facts: {}, excluded: [...EXCLUDED], unexpectedApiPaths: [],
    browserActions: 0, apiRequests: 0, stage: 'setup', modelCalls: 0, judgeCalls: 0 };
  const save = () => fs.writeFileSync(receiptPath, JSON.stringify(r, null, 2), { mode: 0o600 });
  const checkpoint = name => { r.stage = name; r.apiRequests = contentHttp.apiRequests; save(); };
  save();
  const evidence = fs.realpathSync(process.env.CTF_RENDERED_EVIDENCE);
  const originalEnv = {};
  for (const [key, value] of Object.entries({ IDENTITY_DATABASE_URL: process.env.PG_CTF_AUTHORITY_APPLICATION_FRESH_IDENTITY_RUNTIME_URL,
    IDENTITY_MIGRATION_DATABASE_URL: process.env.PG_CTF_AUTHORITY_APPLICATION_FRESH_IDENTITY_MIGRATION_URL,
    JWT_SECRET: jwtSecret })) { originalEnv[key] = process.env[key]; process.env[key] = value; }
  let mounted, browser, pages, instructor, other, work, timer, cancelled = false, primary;
  const active = () => { assert(!cancelled, 'Config deadline exceeded'); assert.equal(ledger.length, 0, 'Config facet invoked provider'); };
  const action = fn => { active(); assert(++r.browserActions <= LIMITS.browserActions); return fn(); };
  const pointer = (page, handle) => content.contentPointerClick(page, handle, action);
  const click = async (page, selector, text) => {
    await action(() => page.bringToFront());
    const ready = await action(() => page.waitForFunction(({ selector, text }) =>
      [...document.querySelectorAll(selector)].filter(node =>
        node.textContent.trim() === text && node.getClientRects().length && !node.disabled).length === 1,
    { timeout: 15000 }, { selector, text })); await ready.dispose();
    const handle = await action(() => page.evaluateHandle(({ selector, text }) =>
      [...document.querySelectorAll(selector)].find(node => node.textContent.trim() === text && node.getClientRects().length),
    { selector, text }));
    try { await pointer(page, handle); } finally { await handle.dispose(); }
  };
  const configValue = async key => {
    const row = (await c.runtime.query('SELECT value FROM ctf.ctf_config WHERE key=$1', [key])).rows[0];
    assert(row && typeof row.value === 'string'); return row.value;
  };
  const configValues = async () => Object.fromEntries(
    (await c.runtime.query('SELECT key,value FROM ctf.ctf_config')).rows.map(row => [row.key, row.value]));
  const rowsAfter = sequence => i.migration.query("SELECT sequence::text,operation_id::text,actor_id::text,session_id::text,kind,state,canonical_command,command_hash,canonical_result,result_hash FROM identity.ctf_outbox WHERE sequence>$1 AND kind='config_mutation' ORDER BY sequence", [sequence]);
  const maxSequence = async () => (await i.migration.query('SELECT COALESCE(max(sequence),0)::text AS value FROM identity.ctf_outbox')).rows[0].value;
  const stableTables = ['ctf_stages', 'ctf_participants', 'ctf_progress', 'ctf_attempts',
    'ctf_judgments', 'ctf_sessions', 'ctf_leaderboard'];
  const snapshot = async () => Object.fromEntries(await Promise.all(stableTables.map(async table =>
    [table, (await c.runtime.query(`SELECT to_jsonb(t)::text AS row FROM ctf.${table} t`)).rows.map(x => x.row).sort()])));
  const historyBefore = await snapshot();
  const configBefore = await configValues();
  assertConfigTransition(configBefore, configBefore, KEYS[0], configBefore[KEYS[0]]);
  const recovery = async (operationId, actor, browser) => {
    let count = 0; const until = Date.now() + 30000;
    while (count < 32 && Date.now() < until) {
      count++;
      if (browser) {
        const observed = browser.responses.find(row => row.path === `/api/ctf/operations/${operationId}` && row.status === 200);
        if (observed) { assert.deepEqual(await observed.response.json(), { message: 'Configuration updated successfully' }); return browser.gets.filter(x => x === observed.path).length; }
        if (count <= 3) {
          const visible = await action(() => instructor.evaluate(() =>
            [...document.querySelectorAll('[role="status"] button')].some(x => x.textContent.trim() === 'Check status' && !x.disabled)));
          if (visible) await click(instructor, '[role="status"] button', 'Check status');
        }
      } else {
        const result = await request('GET', `/operations/${operationId}`, actor);
        if (result.status === 200) { assert.deepEqual(result.body, { message: 'Configuration updated successfully' }); return count; }
        assert.equal(result.status, 202);
      }
      await sleep(100);
    }
    throw Error('Config same-ID recovery bounded deadline');
  };
  const verifyOutbox = async (after, key, value, actorId, sessionId) => {
    const until = Date.now() + 10000;
    let rows;
    do {
      rows = (await rowsAfter(after)).rows;
      if (rows.length === 1 && rows[0].state === 'applied') break;
      if (Date.now() >= until) throw Error('Config projection deadline');
      await sleep(50);
    } while (true);
    const row = rows[0];
    assert.equal(row.actor_id, String(actorId)); assert.equal(row.session_id, String(sessionId));
    assert.equal(crypto.createHash('sha256').update(row.canonical_command).digest('hex'), row.command_hash);
    const command = JSON.parse(row.canonical_command);
    assert.equal(command.operationId, row.operation_id); assert.equal(command.kind, 'config_mutation');
    assert.deepEqual(command.body, { key, value });
    const projection = (await c.runtime.query('SELECT sequence::text,operation_id::text,kind,command_hash,canonical_result,result_hash FROM ctf.projection_receipts WHERE operation_id=$1', [row.operation_id])).rows[0];
    assert.deepEqual(projection, { sequence: row.sequence, operation_id: row.operation_id,
      kind: row.kind, command_hash: row.command_hash, canonical_result: row.canonical_result,
      result_hash: row.result_hash });
    return row;
  };
  try {
    await require('../../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(i.migration);
    const adapter = require('../../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const stores = require('../../../server/services/postgresPlatformStores').getPostgresPlatformStores();
    mounted = await require('../../fixtures/legacyFileSsiFullAppParity').mountLegacyParityRoutes({ app: web,
      adapter, pool: i.runtime, migration: i.migration, progress: stores.progress,
      config: stores.config, identity: adapter.repository });
    const mountedAuthority = await adapter.validateSession(mounted.adminToken);
    assert(mountedAuthority?.user?.id > 0 && mountedAuthority?.session?.id > 0);
    assert.notEqual(String(mountedAuthority.user.id), String(admin.user.id));
    r.mountedActorId = String(mountedAuthority.user.id);
    r.mountedSessionId = String(mountedAuthority.session.id);
    const report = JSON.parse(fs.readFileSync(process.env.CTF_CONTENT_BUILD_REPORT, 'utf8'));
    const root = path.resolve(__dirname, '../../..');
    const expectedBuild = report.inputMode === 'private-external-v1'
      ? fs.realpathSync(report.outputRoot) : path.join(root, 'client/build');
    const build = fs.realpathSync(process.env.CTF_CONTENT_BUILD_DIRECTORY);
    assert.equal(build, expectedBuild); assert(fs.existsSync(path.join(build, 'index.html')));
    web.use('/api', (_req, res) => res.status(404).json({ error: 'Unmapped Config API' }));
    web.use(require('express').static(build));
    web.get('/{*path}', (_req, res) => res.sendFile(path.join(build, 'index.html')));
    const journal = entry => {
      const journalPath = path.join(evidence, 'CONFIG-processes.json');
      const before = fs.existsSync(journalPath) ? JSON.parse(fs.readFileSync(journalPath, 'utf8')) : [];
      before.push(entry); fs.writeFileSync(journalPath, JSON.stringify(before), { mode: 0o600 });
    };
    browser = await require('../../fixtures/ctfTenContentBrowserAdmission').launchCtfConfigBrowser(evidence, 'config');
    const browserIdentity = JSON.parse(fs.readFileSync(path.join(evidence, 'config-process.json'), 'utf8'));
    assert(Number.isSafeInteger(browserIdentity.pid) && browserIdentity.pid > 0);
    journal({ kind: 'browser', pid: browserIdentity.pid });
    pages = content.contentActorPages(browser);
    instructor = await action(() => pages.newPage());
    instructor.setDefaultTimeout(15000);
    await action(() => instructor.setViewport({ width: 1280, height: 900 }));
    await action(() => instructor.setRequestInterception(true));
    const seen = { posts: [], gets: [], responses: [], paths: [], previews: 0 };
    instructor.on('request', req => {
      const url = new URL(req.url());
      if (url.origin === origin && req.method() === 'POST' && /\/preview(?:\/|$)/.test(url.pathname)) seen.previews++;
      if (url.origin === origin && req.method() === 'POST' && url.pathname.startsWith('/api/ctf/admin/')) {
        seen.paths.push(url.pathname);
        if (url.pathname === POST_PATH) {
          let body = null; try { body = JSON.parse(req.postData() || ''); } catch { /* Strict comparison below rejects malformed input. */ }
          seen.posts.push({ body, bearer: req.headers().authorization || null });
        }
      }
      if (url.origin === origin && req.method() === 'GET' && /^\/api\/ctf\/operations\//.test(url.pathname)) seen.gets.push(url.pathname);
      if (['about:', 'data:', 'blob:'].includes(url.protocol)) return req.continue();
      if (url.origin !== origin) return req.abort();
      if (url.pathname.startsWith('/api/') &&
          !(content.contentApiAllowed(req.method(), url.pathname) ||
            (req.method() === 'POST' && url.pathname === POST_PATH))) {
        if (r.unexpectedApiPaths.length < 32) r.unexpectedApiPaths.push({ method: req.method(), path: url.pathname });
        return req.abort();
      }
      return req.continue();
    });
    instructor.on('response', response => {
      const url = new URL(response.url());
      if (url.origin === origin && response.request().method() === 'GET' && /^\/api\/ctf\/operations\//.test(url.pathname))
        seen.responses.push({ path: url.pathname, status: response.status(), response });
    });
    await action(() => instructor.evaluateOnNewDocument(token => localStorage.setItem('token', token), mounted.adminToken));
    await action(() => instructor.goto(origin + '/admin/ctf-management', { waitUntil: 'domcontentloaded' }));
    await click(instructor, 'nav[aria-label="CTF admin sections"] button', 'Config');
    const ready = await action(() => instructor.waitForFunction(() =>
      [...document.querySelectorAll('div')].filter(x => x.children.length === 0 && x.textContent.trim() === 'ctf_enabled').length === 1,
    { timeout: 15000 })); await ready.dispose();
    const tokenA = mounted.adminToken, tokenB = admin.headers.authorization.slice(7);
    assert.notEqual(tokenA, tokenB);
    const bearer = `Bearer ${tokenA}`;
    const open = async (key, proposed) => {
      const row = await waitConfigRow(instructor, key, BOOLEAN.has(key), action);
      try {
        if (BOOLEAN.has(key)) {
          const control = await action(() => row.$('button[role="switch"]'));
          assert(control); try { await pointer(instructor, control); } finally { await control.dispose(); }
        } else {
          const field = await action(() => row.$('input'));
          assert(field);
          try {
            const previous = await field.evaluate(x => x.value);
            await action(() => field.press('A', { commands: ['SelectAll'], text: '' }));
            assert.deepEqual(await field.evaluate(x => [x.selectionStart, x.selectionEnd]), [0, previous.length]);
            await action(() => field.press('Backspace'));
            await action(() => field.type(proposed));
            assert.equal(await field.evaluate(x => x.value), proposed);
          } finally { await field.dispose(); }
          const saveButton = await action(() => row.$('button'));
          assert(saveButton); try { await pointer(instructor, saveButton); } finally { await saveButton.dispose(); }
        }
      } finally { await row.dispose(); }
      const review = await action(() => instructor.waitForFunction(({ key, proposed }) => {
        const dialogs = [...document.querySelectorAll('[role="dialog"]')].filter(x =>
          x.querySelector('h3')?.textContent.trim() === 'Review CTF configuration change' &&
          x.textContent.includes(`(${key})`) && x.textContent.includes(`"${proposed}"`));
        return dialogs.length === 1 && [...dialogs[0].querySelectorAll('button')].filter(x =>
          x.textContent.trim() === 'Confirm Config Save' && !x.disabled).length === 1;
      }, { timeout: 15000 }, { key, proposed })); await review.dispose();
    };
    const noDialog = async () => {
      const gone = await action(() => instructor.waitForFunction(() =>
        ![...document.querySelectorAll('[role="dialog"]')].some(x =>
          x.querySelector('h3')?.textContent.trim() === 'Review CTF configuration change'),
      { timeout: 15000 })); await gone.dispose();
    };
    work = (async () => {
      for (const key of KEYS) {
        checkpoint(`config-${key}-cancel`);
        const previous = configBefore[key], proposed = proposedValue(key, previous);
        assert.equal(await configValue(key), previous);
        const baselineSequence = await maxSequence(), postsBefore = seen.posts.length;
        await open(key, proposed);
        await click(instructor, '[role="dialog"] button', 'Cancel'); await noDialog();
        const cancel = { noPost: seen.posts.length === postsBefore && (await rowsAfter(baselineSequence)).rows.length === 0,
          unchanged: await configValue(key) === previous };
        assert.deepEqual(cancel, { noPost: true, unchanged: true });
        checkpoint(`config-${key}-dialog-aba`);
        await open(key, proposed);
        other = await action(() => instructor.browserContext().newPage());
        await action(() => other.setRequestInterception(true));
        other.on('request', req => { const url = new URL(req.url());
          return url.origin === origin || ['about:', 'data:', 'blob:'].includes(url.protocol) ? req.continue() : req.abort(); });
        await action(() => other.goto(origin + '/api/ctf/config', { waitUntil: 'domcontentloaded' }));
        await action(() => instructor.evaluate(() => { window.__ctfConfigEvents = 0;
          window.addEventListener('storage', event => { if (event.key === 'token') window.__ctfConfigEvents++; }); }));
        await action(() => other.evaluate(([b, a]) => { localStorage.setItem('token', b); localStorage.setItem('token', a); }, [tokenB, tokenA]));
        const observed = await action(() => instructor.waitForFunction(() => window.__ctfConfigEvents >= 2,
          { timeout: 15000 })); await observed.dispose();
        const eventsObserved = await action(() => instructor.evaluate(() => window.__ctfConfigEvents));
        await noDialog(); await action(() => other.close()); other = null;
        const dialogTimeAba = { eventsObserved,
          noPost: seen.posts.length === postsBefore && (await rowsAfter(baselineSequence)).rows.length === 0,
          unchanged: await configValue(key) === previous };
        assert.deepEqual(dialogTimeAba, { eventsObserved: 2, noPost: true, unchanged: true });
        checkpoint(`config-${key}-confirm`);
        await action(() => instructor.reload({ waitUntil: 'domcontentloaded' }));
        await click(instructor, 'nav[aria-label="CTF admin sections"] button', 'Config');
        await open(key, proposed);
        const beforeConfirm = await maxSequence();
        const responseWait = action(() => instructor.waitForResponse(response =>
          new URL(response.url()).origin === origin && new URL(response.url()).pathname === POST_PATH &&
          response.request().method() === 'POST', { timeout: 15000 }));
        await click(instructor, '[role="dialog"] button', 'Confirm Config Save');
        const response = await responseWait;
        assert([200, 202].includes(response.status()));
        const ack = await response.json();
        const row = await verifyOutbox(beforeConfirm, key, proposed, r.mountedActorId, r.mountedSessionId);
        if (response.status() === 200) assert.deepEqual(ack, { message: 'Configuration updated successfully' });
        else { assert.equal(ack?.pending, true); assert.equal(ack.operationId, row.operation_id); }
        const browserGets = response.status() === 202 ? await recovery(row.operation_id, admin, seen) : 0;
        const confirmed = { originalStatus: response.status(), resolvedStatus: 200, sameIdGets: browserGets,
          operationId: row.operation_id, sequence: row.sequence,
          browserAckOperationId: response.status() === 202 ? ack.operationId : null,
          ackMessage: response.status() === 200 ? ack.message : null };
        const physical = seen.posts.slice(postsBefore), paths = seen.paths.slice(postsBefore);
        assert.deepEqual(paths, [POST_PATH]);
        assert.equal(physical.length, 1); assert.equal(physical[0].bearer, bearer);
        assert.deepEqual(physical[0].body, { key, value: proposed });
        const adminGet = await request('GET', '/config', admin);
        assert.equal(adminGet.status, 200); assert.equal(adminGet.body.config[key], proposed);
        const publicGet = await request('GET', '/config');
        const publicGetMatches = key === 'ctf_enabled' && proposed === 'false'
          ? publicGet.status === 403
          : publicGet.status === 200 && publicGet.body.config[key] === proposed;
        assert(publicGetMatches);
        const durable = { canonicalProjectionApplied: true, actorSessionBound: true,
          dbValueMatches: await configValue(key) === proposed, adminGetMatches: adminGet.body.config[key] === proposed,
          publicGetMatches };
        assert(Object.values(durable).every(Boolean));
        assertConfigTransition(configBefore, await configValues(), key, proposed);
        checkpoint(`config-${key}-restore`);
        const beforeRestore = await maxSequence();
        const restoreResponse = await request('POST', '/admin/config', admin, { key, value: previous });
        assert([200, 202].includes(restoreResponse.status));
        const restored = await verifyOutbox(beforeRestore, key, previous, admin.user.id, admin.identitySession.id);
        if (restoreResponse.status === 200) assert.deepEqual(restoreResponse.body, { message: 'Configuration updated successfully' });
        else { assert.equal(restoreResponse.body?.pending, true); assert.equal(restoreResponse.body.operationId, restored.operation_id); }
        const restoreGets = restoreResponse.status === 202 ? await recovery(restored.operation_id, admin, null) : 0;
        const contentEquivalent = await configValue(key) === previous;
        assertConfigTransition(configBefore, await configValues(), key, previous);
        assert(contentEquivalent); assert.deepEqual(await snapshot(), historyBefore);
        const restore = { scope: 'content-equivalence-only', originalStatus: restoreResponse.status,
          resolvedStatus: 200, sameIdGets: restoreGets, operationId: restored.operation_id,
          sequence: restored.sequence,
          browserAckOperationId: restoreResponse.status === 202 ? restoreResponse.body.operationId : null,
          ackMessage: restoreResponse.status === 200 ? restoreResponse.body.message : null,
          contentEquivalent };
        assert.notEqual(confirmed.operationId, restore.operationId);
        assert(BigInt(restore.sequence) > BigInt(confirmed.sequence));
        const siblingPreserved = JSON.stringify(await snapshot()) === JSON.stringify(historyBefore);
        assert(siblingPreserved);
        r.cases.push({ key, previous, proposed, cancel, dialogTimeAba, confirmed, durable,
          restore, siblingPreserved }); save();
      }
      assert.deepEqual(await snapshot(), historyBefore);
      assert.deepEqual(await configValues(), configBefore);
      assert.equal(ledger.length, 0); assert.deepEqual(r.unexpectedApiPaths, []);
      await pages.closePage(instructor); instructor = null;
      await sleep(300);
      r.facts = {
        cancelNoPost: r.cases.every(x => x.cancel.noPost && x.cancel.unchanged),
        dialogAbaNoPost: r.cases.every(x => x.dialogTimeAba.noPost && x.dialogTimeAba.unchanged),
        onePhysicalPostPerKey: seen.posts.length === KEYS.length && seen.paths.length === KEYS.length
          && seen.paths.every(pathname => pathname === POST_PATH),
        canonicalProjectionReadback: r.cases.every(x => Object.values(x.durable).every(Boolean)),
        distinctRestoreOperations: new Set(r.cases.flatMap(x => [x.confirmed.operationId,
          x.restore.operationId])).size === KEYS.length * 2,
        siblingStageProgressHistoryPreserved: JSON.stringify(await snapshot()) === JSON.stringify(historyBefore),
        noPreview: seen.previews === 0,
        noMutationRetry: seen.posts.length === KEYS.length && seen.paths.length === KEYS.length,
        noModelJudgeOrCredit: ledger.length === 0 && r.modelCalls === 0 && r.judgeCalls === 0,
      };
      assert(Object.values(r.facts).every(Boolean));
      r.apiRequests = contentHttp.apiRequests; r.stage = 'postflight'; save();
    })();
    await Promise.race([work, new Promise((_, reject) => { timer = setTimeout(() => { cancelled = true; reject(Error('Config 360-second deadline')); }, LIMITS.deadlineMs); })]);
  } catch (error) {
    primary = error; r.stage = 'failed'; r.apiRequests = contentHttp.apiRequests;
    save(); throw error;
  } finally {
    clearTimeout(timer); cancelled = true;
    const failures = [];
    for (const close of [() => other?.close(), () => pages?.close(), () => browser?.close()]) {
      try { await close(); } catch (error) { failures.push(error); }
    }
    if (work) {
      const drained = await Promise.race([work.then(() => true, () => true), sleep(4000).then(() => false)]);
      if (!drained) failures.push(Error('Config work did not retire'));
    }
    if (mounted) try { await mounted.close(); } catch (error) { failures.push(error); }
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    r.apiRequests = contentHttp.apiRequests; save();
    if (failures.length) throw new AggregateError(primary ? [primary, ...failures] : failures,
      'Config rendered browser cleanup failed', { cause: primary });
    if (!primary) { r.stage = 'complete'; assertCtfConfigReceipt(r); save(); }
  }
}

module.exports = { KEYS, FACTS, EXCLUDED, LIMITS, proposedValue, assertConfigDatabaseName,
  assertConfigTransition, configRow, waitConfigRow, assertOperation,
  assertCtfConfigReceipt, runCtfConfigRenderedCases };
