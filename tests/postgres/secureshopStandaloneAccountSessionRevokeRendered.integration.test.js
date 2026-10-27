'use strict';

// A focused Q05 consequence cohort. It reuses the whole-commerce disposable
// stores and owned browser protocol, but never runs or changes its 280s journey.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomUUID, randomBytes, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { admitCommerceBrowser, exactConsequenceDialogButton } =
  require('../fixtures/secureshopCommerceBrowserAdmission');
const cases = require('../fixtures/secureshopAccountSessionRevokeRenderedCases');

const PREFIX = 'PG_SECURESHOP_STANDALONE_COMMERCE_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const ENABLED = process.env.SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && Object.keys(STORES).every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const OTHER_ENABLED = process.env.SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && Object.keys(STORES).every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const AVATAR_ENABLED = process.env.SECURESHOP_ACCOUNT_AVATAR_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && Object.keys(STORES).every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

// The iframe has an opaque sandbox origin. Its built ES module and preload
// requests therefore require CORS even though the URL is on this HTTP server.
// Keep this limited to public built assets; the API routers stay unchanged.
function serveOpaqueFrameAssets(build) {
  return express.static(build, { setHeaders: response => response.set('Access-Control-Allow-Origin', '*') });
}
module.exports = { serveOpaqueFrameAssets };

function initialSessionsReady() {
  const heading = [...document.querySelectorAll('h3')]
    .some(node => node.textContent.trim() === 'Active sessions');
  const rows = [...document.querySelectorAll('tbody tr')];
  return heading && rows.length === 1
    && rows[0].textContent.includes('(current session)');
}
module.exports.initialSessionsReady = initialSessionsReady;

function storeUrls() {
  const urls = {}; const databases = new Set(); let nonce; let port;
  for (const [store, name] of Object.entries(STORES)) for (const role of ['MIGRATION', 'RUNTIME']) {
    const key = `${store}_${role}`, url = new URL(process.env[`${PREFIX}${key}_URL`]);
    assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
    assert.match(url.port, /^[1-9]\d{0,4}$/); assert(Number(url.port) <= 65535);
    assert.equal(url.username, `dvaia_${name}_${role.toLowerCase()}`);
    assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
    const match = new RegExp(`^/dvaia_test_agent_host_([a-f0-9]{12})_${name}$`).exec(url.pathname);
    assert(match); nonce ??= match[1]; port ??= url.port;
    assert.equal(match[1], nonce); assert.equal(url.port, port); urls[key] = url.href;
    if (role === 'RUNTIME') databases.add(url.pathname);
  }
  assert.equal(databases.size, 4, 'four distinct owned disposable stores required');
  return urls;
}

function accountFrameEntry(rawUrl) {
  let frameUrl;
  try { frameUrl = new URL(rawUrl); }
  catch (error) {
    if (!(error instanceof TypeError)) throw error;
    return false;
  }
  return frameUrl.pathname === '/secureshop-frame.html'
    && frameUrl.searchParams.get('entry') === '/secureshop/account';
}
module.exports.accountFrameEntry = accountFrameEntry;

async function frameFor(page, buyerName) {
  const until = Date.now() + 20000;
  let observed = { frame: false, frameEntryAccount: false, initialFrameStatus: false,
    bridgeError: false, loadingSession: false, loginForm: false,
    account: false, buyer: false, sessionsTab: false };
  while (Date.now() < until) {
    const handle = await page.$('iframe[title="SecureShop"]');
    const frame = handle && await handle.contentFrame().catch(() => null);
    if (frame && !frame.detached) {
      const frameEntryAccount = accountFrameEntry(frame.url());
      observed = await frame.evaluate(name => ({ frame: true,
        initialFrameStatus: document.querySelector('#root[role="status"]')?.textContent.trim()
          === 'Connecting to your workshop session…',
        bridgeError: document.querySelector('#root[role="alert"]')?.textContent.trim()
          === 'Your SecureShop connection is unavailable. Return to SecureShop and reconnect.',
        loadingSession: [...document.querySelectorAll('div')].some(node =>
          node.textContent.trim() === 'Loading session…'),
        loginForm: Boolean(document.querySelector('#ss-login-user')),
        account: document.querySelector('h1')?.textContent.trim() === 'Account',
        buyer: [...document.querySelectorAll('strong')].some(node => node.textContent.trim() === name),
        sessionsTab: Boolean(document.querySelector('#ss-tab-sessions')),
      }), buyerName).then(value => ({ ...value, frameEntryAccount })).catch(() => observed);
      if (observed.account && observed.buyer && observed.sessionsTab) return frame;
    }
    await new Promise(resolve => setTimeout(resolve, 40));
  }
  const pathname = new URL(page.url()).pathname;
  const route = ['/secureshop/login', '/secureshop/account', '/secureshop/home'].includes(pathname)
    ? pathname : 'other';
  throw Error(`Owned Account frame unavailable: ${JSON.stringify({ route, ...observed })}`);
}

async function clickPhysical(frame, lookup) {
  // Only fixture-owned static lookup expressions reach this helper. Puppeteer
  // requires a function locator for DOM-result selection, not a CSS string.
  const handle = await frame.locator(new Function(`return (${lookup})();`))
    .setTimeout(20000).setVisibility('visible').waitHandle();
  try {
    await handle.evaluate(node => node.scrollIntoView({ block: 'center', inline: 'center' }));
    await frame.waitForFunction(node => {
      if (!node?.isConnected || node.disabled) return false;
      const r = node.getBoundingClientRect();
      const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      return r.width > 0 && r.height > 0 && r.top >= 0 && r.bottom <= innerHeight
        && (hit === node || node.contains(hit));
    }, { timeout: 20000 }, handle);
    await handle.click();
  } finally { await handle.dispose(); }
}
async function openAvatarAccountMenu(frame, click = clickPhysical) {
  const selector = 'button[aria-label="Account menu"]';
  const expanded = await frame.$eval(selector, node => node.getAttribute('aria-expanded') === 'true');
  if (!expanded) await click(frame, `() => document.querySelector('button[aria-label="Account menu"]')`);
  await frame.waitForFunction(() => {
    const menu = document.querySelector('button[aria-label="Account menu"]');
    return menu?.getAttribute('aria-expanded') === 'true'
      && [...document.querySelectorAll('button')].some(button => button.textContent.trim() === 'Sign out');
  }, { timeout: 20000 });
}
module.exports.openAvatarAccountMenu = openAvatarAccountMenu;

async function chooseAvatarFile(page, frame, filePath, click = clickPhysical) {
  const chooserAbort = new AbortController();
  const chooserPromise = page.waitForFileChooser({ timeout: 20000,
    signal: chooserAbort.signal });
  chooserPromise.catch(() => {});
  let chooser;
  try {
    await click(frame, `() => document.querySelector('.ss-uploadzone button.ss-btn--ghost')`);
    chooser = await chooserPromise;
  } catch (error) {
    chooserAbort.abort(Error('Owned Account chooser cancelled after click failure'));
    await chooserPromise.catch(() => {});
    throw error;
  }
  await chooser.accept([filePath]);
}
module.exports.chooseAvatarFile = chooseAvatarFile;

const AVATAR_POST = '/api/secureshop/uploads/avatar';
const avatarGet = requestId => `/api/secureshop/uploads/avatar/operations/${requestId}`;
const avatarHash = bytes => createHash('sha256').update(bytes).digest('hex');
function loseAvatarAckAfterCommit(request, response, record) {
  assert.equal(request.method, 'POST');
  assert.equal(request.path, '/');
  assert.equal(typeof record, 'function');
  const originalEnd = response.end;
  let used = false;
  response.end = function(chunk, encoding, callback) {
    const bytes = Buffer.isBuffer(chunk) ? Buffer.from(chunk)
      : Buffer.from(chunk || '', typeof encoding === 'string' ? encoding : 'utf8');
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); } catch {}
    if (value?.kind !== 'avatar' || value?.status !== 'completed')
      return originalEnd.call(this, chunk, encoding, callback);
    assert.equal(used, false, 'only one owned avatar acknowledgement may be lost');
    used = true;
    assert.equal(response.statusCode, 200);
    assert.equal(Number(response.getHeader('content-length')), bytes.length,
      'the real completed reply must declare its full byte length');
    assert.match(value.requestId, /^[a-f0-9-]{36}$/);
    // Express has prepared the real HTTP 200 and full Content-Length. One
    // written byte followed by a closed socket is an incomplete browser reply.
    response.write('{');
    record({ requestId: value.requestId, responseSha256: avatarHash(bytes) });
    setImmediate(() => response.destroy());
    return this;
  };
}
module.exports.loseAvatarAckAfterCommit = loseAvatarAckAfterCommit;
async function avatarRecoveryStorageFacts(expectedRequestId, expectedOwnerId) {
  const result = { pendingReferencePresent: false, ownerMatches: null,
    snapshotFingerprintMatches: null, matchingSnapshots: 0, storageAvailable: true };
  try {
    const storage = globalThis.localStorage;
    const count = Math.min(storage.length, 64);
    if (storage.length > 64) result.storageAvailable = false;
    for (let index = 0; index < count; index++) {
      const key = storage.key(index);
      if (!key?.startsWith('dvaia:secureshop:')) continue;
      let snapshot, pending;
      try {
        snapshot = JSON.parse(storage.getItem(key));
        pending = JSON.parse(snapshot?.['secureshop.account-avatar.pending.v1']);
      } catch { continue; }
      if (pending?.requestId !== expectedRequestId) continue;
      result.pendingReferencePresent = true;
      result.matchingSnapshots = Math.min(result.matchingSnapshots + 1, 2);
      if (Number.isSafeInteger(expectedOwnerId) && expectedOwnerId > 0)
        result.ownerMatches = result.ownerMatches === true
          || pending.ownerId === String(expectedOwnerId);
      // The parent snapshot deliberately never stores the persona JWT, so a
      // token-fingerprint comparison here is unavailable across all versions.
    }
  } catch { result.storageAvailable = false; }
  return result;
}
module.exports.avatarRecoveryStorageFacts = avatarRecoveryStorageFacts;
function avatarRecoveryUiFacts() {
  const zone = document.querySelector('.ss-uploadzone');
  const status = [...(zone?.querySelectorAll('[role="status"]') || [])]
    .find(node => node.textContent.includes('saved avatar upload'));
  const button = status?.querySelector('button');
  const alert = [...(zone?.querySelectorAll('[role="alert"]') || [])]
    .map(node => node.textContent.trim()).find(Boolean) || '';
  const errorCategory = alert.includes('different Account session') ? 'session-mismatch'
    : alert.includes('No saved avatar upload') ? 'missing-reference'
    : alert.includes('Saved avatar state or Account authority') ? 'authority-unavailable'
    : alert.includes('Saved avatar could not be checked') ? 'saved-get-failed'
    : alert.includes('Avatar upload outcome is unresolved') ? 'unresolved'
    : alert ? 'other' : 'none';
  return { pendingShown: Boolean(status), checkButtonPresent: Boolean(button),
    checkButtonDisabled: button?.disabled === true, errorCategory };
}
module.exports.avatarRecoveryUiFacts = avatarRecoveryUiFacts;
function avatarRecoveryFailureDiagnostic({ avatarGets, avatarGetAttempts, avatarGetResponses,
  avatarGetFailures, avatarPosts, avatarPostFailures, avatarPostFinishes, avatarPostResponses,
  beforeGet, beforeGetAttempts, beforeGetResponses, beforeGetFailures, beforePost,
  selected, storage, ui }) {
  const status = row => Number.isInteger(row.status) && row.status >= 100 && row.status <= 599
    ? row.status : null;
  const count = value => Math.min(999, Math.max(0, value));
  return { exactGets: count(avatarGets.length - beforeGet),
    operationAttempts: count(avatarGetAttempts.length - beforeGetAttempts),
    operationStatuses: avatarGetResponses.slice(beforeGetResponses, beforeGetResponses + 4).map(status),
    operationFailures: count(avatarGetFailures.length - beforeGetFailures),
    postAttempts: count(avatarPosts.length - beforePost),
    selectedPostStatuses: avatarPostResponses.filter(row => row.request === selected.request)
      .slice(0, 4).map(status),
    selectedPostFailures: count(avatarPostFailures.filter(row => row.request === selected.request).length),
    selectedPostFinishes: count(avatarPostFinishes.filter(row => row.request === selected.request).length),
    storage, ui };
}
module.exports.avatarRecoveryFailureDiagnostic = avatarRecoveryFailureDiagnostic;
async function waitForAvatarCaptured(predicate, description, timeoutMs = 20000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const value = predicate();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw Error(`Owned Account avatar ${description} unavailable`);
}
async function waitForAvatarUiReceipt(frame, requestId) {
  await frame.waitForFunction(expected => {
    const pre = document.querySelector('.ss-uploadzone pre');
    if (!pre) return false;
    try { const value = JSON.parse(pre.textContent);
      return value.requestId === expected && ['completed', 'denied'].includes(value.status); }
    catch { return false; }
  }, { timeout: 20000 }, requestId);
  const reply = await frame.$eval('.ss-uploadzone pre', node => JSON.parse(node.textContent));
  assert.equal(reply.requestId, requestId);
  return reply;
}
module.exports.waitForAvatarCaptured = waitForAvatarCaptured;
module.exports.waitForAvatarUiReceipt = waitForAvatarUiReceipt;
async function enterAvatarFilename(page, frame, filename) {
  const name = await frame.$('.ss-uploadzone input[type="text"]');
  assert(name, 'actual editable Account filename required');
  try {
    await name.click();
    await page.keyboard.press('Home');
    await page.keyboard.down('Shift');
    try { await page.keyboard.press('End'); }
    finally { await page.keyboard.up('Shift'); }
    await page.keyboard.press('Backspace');
    await page.keyboard.type(filename);
    assert.equal(await name.evaluate(node => node.value), filename,
      'physical Account filename selection must be exact before Upload');
  } finally { await name.dispose(); }
}
module.exports.enterAvatarFilename = enterAvatarFilename;
async function admitAvatarRoleLogin({ page, origin, expected, role, username, auth }) {
  await page.waitForFunction(() => location.pathname === '/secureshop/account', { timeout: 20000 });
  const cookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
    .find(value => value.name === 'dvaia_shop_session');
  assert.equal(cookie?.httpOnly, true, 'physical login must establish the real shop cookie');
  const actual = await auth.authenticate(cookie.value);
  assert.equal(actual?.shopUserId, expected.user.id);
  assert.equal(actual?.username, username);
  assert.equal(actual?.role, role);
  return actual;
}
module.exports.admitAvatarRoleLogin = admitAvatarRoleLogin;
function assertAvatarReceipt(value) {
  assert.equal(value?.version, 1);
  assert.equal(value?.scope, 'Q05 Account avatar direct rendered action');
  assert.equal(value?.passed, true);
  assert.deepEqual(value.roles, ['customer', 'merchant', 'admin']);
  assert.equal(value.physical?.onePostPerSelectedUpload, true);
  assert.equal(value.physical?.accountBridgeReadback, true);
  assert.equal(value.vulnerable?.mimeAndFilenameHonored, true);
  assert.equal(value.vulnerable?.traversalConfined, true);
  assert.equal(value.fixed?.extensionDeniedBeforeWrite, true);
  assert.equal(value.fixed?.traversalDeniedBeforeWrite, true);
  assert.equal(value.recovery?.committedAckLost, true);
  assert.equal(value.recovery?.getOnlyAfterRemount, true);
  assert.equal(value.authority?.sessionFenced, true);
  assert.equal(value.authority?.resetFenced, true);
  assert.equal(value.authority?.siblingUnchanged, true);
  assert.deepEqual(value.calls, { model: 0, judge: 0, credit: 0 });
}
module.exports.assertAvatarReceipt = assertAvatarReceipt;

async function prepareAvatarSiblingScene(composition, scope, persona, session) {
  const target = await composition.catalog.prepareTarget({ scope, persona,
    personaSession: { sessionId: session.sessionId, authorityVersion: session.authorityVersion } });
  const retained = await composition.scenes.readRetained(scope);
  assert(retained?.scene, 'sibling avatar requires an existing scene grant');
  assert.equal(retained.targetId, target.targetId);
  assert.equal(retained.scene.sceneId, target.scene.sceneId);
  assert.equal(retained.scene.sceneGeneration, target.scene.sceneGeneration);
  assert.equal(retained.scene.grantId, target.scene.grantId);
  return retained;
}
module.exports.prepareAvatarSiblingScene = prepareAvatarSiblingScene;

async function provisionAvatarPeerTenant(migrationPool, siblingContext, tenantSlug) {
  const tenantId = randomUUID();
  const client = await migrationPool.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
      [tenantId, tenantSlug]);
    const merchant = (await client.query(`SELECT principal_id,shop_user_id
      FROM secureshop_auth.principals
      WHERE username='student_merchant' AND role='merchant'`)).rows;
    assert.equal(merchant.length, 1, 'one seeded merchant required for the peer tenant');
    for (const [context, role] of [[siblingContext, 'customer'], [merchant[0], 'merchant']]) {
      await client.query(`INSERT INTO secureshop_auth.tenant_memberships
        (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,$4)`,
      [tenantId, context.principalId ?? context.principal_id,
        context.shopUserId ?? context.shop_user_id, role]);
    }
    const seeded = await client.query(`UPDATE secureshop_auth.tenants
      SET seed_merchant_id=$2 WHERE tenant_id=$1 AND seed_merchant_id IS NULL`,
    [tenantId, merchant[0].shop_user_id]);
    assert.equal(seeded.rowCount, 1);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
  return { tenantId, tenantSlug };
}
module.exports.provisionAvatarPeerTenant = provisionAvatarPeerTenant;

function assertAvatarCleanupGeneration(actual, expected) {
  assert.equal(actual, String(expected), 'reset receipt retains the exact admitted bigint generation');
}
module.exports.assertAvatarCleanupGeneration = assertAvatarCleanupGeneration;

const AVATAR_STAGE_LABELS = Object.freeze([
  'peer-login', 'peer-bootstrap', 'browser-launch', 'browser-ack',
  'browser-page', 'browser-viewport', 'browser-guard',
  'initial-goto', 'initial-login-form', 'initial-username',
  'initial-password', 'initial-submit', 'initial-account',
  'avatar-choose-file', 'avatar-filename', 'avatar-upload-click',
  'avatar-reload', 'avatar-reloaded-frame', 'avatar-saved-button',
  'avatar-check-click', 'avatar-ui-receipt', 'avatar-transport-assertions',
  'first-effect-readback', 'first-authority', 'sibling-scene', 'sibling-upload',
  'sibling-private-get', 'current-before-reset-get', 'reset-commit',
  'stale-after-reset-get', 'reset-cleanup', 'role-account-menu', 'role-signout-click',
  'role-signout-route', 'merchant-revoked-get', 'role-effect-readback',
  'merchant-current-get', 'role-results', 'traversal-effect',
  'fixed-mode-read', 'fixed-mode-set', 'fixed-account-menu', 'fixed-signout-click',
  'fixed-signout-route', 'fixed-files-baseline', 'fixed-traversal-absence',
  'fixed-extension-absence', 'final-inventory', 'final-build',
  'final-browser-targets', 'final-credit',
  'role-goto', 'role-login-form', 'role-username', 'role-password',
  'role-submit', 'role-account', 'role-frame',
]);
const NATIVE_ERROR_STACK_GETTER = Object.getOwnPropertyDescriptor(Error(), 'stack')?.get;
function avatarOwnData(value, key) {
  try {
    let cursor = value;
    for (let depth = 0; cursor && depth < 4; depth += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(cursor, key);
      if (descriptor) {
        if (Object.hasOwn(descriptor, 'value')) return descriptor.value;
        if (key === 'stack' && descriptor.get === NATIVE_ERROR_STACK_GETTER)
          return descriptor.get.call(cursor);
        return undefined;
      }
      cursor = Object.getPrototypeOf(cursor);
    }
  } catch { /* Diagnostic metadata cannot replace the original failure. */ }
  return undefined;
}
const AVATAR_CAUSE_NAMES = Object.freeze(['Error', 'AssertionError', 'TimeoutError',
  'ProtocolError', 'AbortError', 'TypeError', 'RangeError']);
const AVATAR_CAUSE_CODES = Object.freeze(['ERR_ASSERTION', 'ENOENT', 'SHOP_AUTH_INVALID',
  'SHOP_SCENE_STALE', 'STALE_GENERATION', 'STALE_LAUNCH', 'LAUNCH_UNAVAILABLE',
  'PERSONA_EFFECT_OUTCOME_UNCERTAIN', 'COMMERCE_OPERATION_CONFLICT']);
function avatarSafeCause(error) {
  const name = avatarOwnData(error, 'name');
  const code = avatarOwnData(error, 'code');
  const stack = avatarOwnData(error, 'stack');
  const line = typeof stack === 'string' ? stack.slice(0, 8192).split('\n').slice(1).find(row =>
    /^\s+at /.test(row) && row.includes(`${__filename}:`)) : undefined;
  const source = line?.match(/:(\d{1,6}):(\d{1,4})\)?$/);
  return {
    name: AVATAR_CAUSE_NAMES.includes(name) ? name : 'Error',
    code: AVATAR_CAUSE_CODES.includes(code) ? code : null,
    fixture: source ? { line: Number(source[1]), column: Number(source[2]) } : null,
  };
}
module.exports.avatarSafeCause = avatarSafeCause;
function createAvatarStageTrace() {
  let entered = 'none', completed = 'none';
  return Object.freeze({
    enter(label) {
      assert(AVATAR_STAGE_LABELS.includes(label), 'closed avatar stage required');
      entered = label;
    },
    complete(label) {
      assert.equal(entered, label, 'only the entered avatar stage can complete');
      completed = label;
    },
    failure(error) {
      return Error('Owned Account avatar boundary entered=' + entered
        + ' completed=' + completed + ' cause=' + JSON.stringify(avatarSafeCause(error)),
      { cause: error });
    },
  });
}
module.exports.createAvatarStageTrace = createAvatarStageTrace;

async function runAvatarCase({ frame, page, origin, workspace, uploadRoot, buyer, sibling, auth,
  siblingReady, siblingScope, siblingSession,
  composition, pools, reset, standaloneMode, modelCalls, judgeCalls, admission, boundary,
  avatarPosts, avatarGets, avatarGetAttempts, avatarGetResponses, avatarGetFailures,
  avatarPostFailures, avatarPostFinishes, avatarPostResponses, avatarFault, avatarStage }) {
  const review = pools.REVIEW_RUNTIME, identity = pools.IDENTITY_RUNTIME;
  const credentials = [
    { role: 'customer', username: buyer.user.username, password: 'owned-session-revoke-password',
      registration: buyer, frame },
    { role: 'merchant', username: `avatar_merchant_${randomUUID().slice(0, 8)}`,
      password: 'owned-session-revoke-password' },
    { role: 'admin', username: 'student_admin', password: 'student123' },
  ];
  credentials[1].registration = await auth.register({ username: credentials[1].username,
    email: `${credentials[1].username}@example.invalid`, password: credentials[1].password,
    role: 'merchant' });
  const effects = [];
  const readEffect = async operationId => {
    const rows = (await review.query(`SELECT a.operation_id,a.upload_request_id,a.launch_id,
      a.scenario_id,a.generation,a.platform_owner_id,a.platform_session_id,a.shop_user_id,
      a.persona_session_id,a.original_filename,a.declared_mime,a.byte_count,
      encode(a.body_sha256,'hex') AS admission_sha,e.outcome,e.cleaned_filename,
      e.stored_virtual_path,e.is_traversal,e.denial_code,
      encode(e.body_sha256,'hex') AS effect_sha
      FROM secureshop_review.bound_upload_admissions a JOIN secureshop_review.bound_upload_effects e
      USING(operation_id) WHERE a.operation_id=$1`, [operationId])).rows;
    assert.equal(rows.length, 1);
    return rows[0];
  };
  const physicalLogin = async entry => {
    avatarStage.enter('role-goto');
    assert([200, 304].includes((await page.goto(
      `${origin}/secureshop/login?next=%2Fsecureshop%2Faccount`)).status()));
    avatarStage.complete('role-goto');
    avatarStage.enter('role-login-form');
    await page.waitForSelector('#ss-login-user');
    avatarStage.complete('role-login-form');
    avatarStage.enter('role-username');
    await page.type('#ss-login-user', entry.username);
    avatarStage.complete('role-username');
    avatarStage.enter('role-password');
    await page.type('#ss-login-pw', entry.password);
    avatarStage.complete('role-password');
    avatarStage.enter('role-submit');
    await page.click('button[type="submit"]');
    avatarStage.complete('role-submit');
    const expected = entry.registration || await auth.login({ username: entry.username,
      password: entry.password });
    avatarStage.enter('role-account');
    await admitAvatarRoleLogin({ page, origin, expected, role: entry.role,
      username: entry.username, auth });
    avatarStage.complete('role-account');
    avatarStage.enter('role-frame');
    const roleFrame = await frameFor(page, entry.username);
    avatarStage.complete('role-frame');
    return roleFrame;
  };
  const physicalUpload = async (selectedFrame, { filename, mime, bytes, dropAck = false }) => {
    const beforePost = avatarPosts.length, beforeGet = avatarGets.length;
    const beforeGetAttempts = avatarGetAttempts.length;
    const beforeGetResponses = avatarGetResponses.length;
    const beforeGetFailures = avatarGetFailures.length;
    const extension = path.extname(filename);
    assert(['.html', '.svg'].includes(extension), 'closed synthetic Account MIME fixture');
    const filePath = path.join(path.dirname(uploadRoot), `avatar-input-${randomUUID()}${extension}`);
    await fs.writeFile(filePath, bytes, { flag: 'wx', mode: 0o600 });
    try {
      avatarStage.enter('avatar-choose-file');
      await chooseAvatarFile(page, selectedFrame, filePath);
      avatarStage.complete('avatar-choose-file');
      avatarStage.enter('avatar-filename');
      await enterAvatarFilename(page, selectedFrame, filename);
      avatarStage.complete('avatar-filename');
      avatarFault.armed = dropAck;
      avatarStage.enter('avatar-upload-click');
      await clickPhysical(selectedFrame, `() => [...document.querySelectorAll('.ss-uploadzone button')]
        .find(button => button.textContent.trim()==='Upload')`);
      avatarStage.complete('avatar-upload-click');
      await waitForAvatarCaptured(() => avatarPosts.length === beforePost + 1,
        'new physical POST');
      assert.equal(avatarPosts.length - beforePost, 1, 'one physical selected upload POST');
      const selected = avatarPosts.at(-1);
      assert.equal(selected.path, AVATAR_POST);
      if (dropAck) {
        await waitForAvatarCaptured(() => avatarFault.lost, 'committed lost acknowledgement');
        try {
          await waitForAvatarCaptured(() => avatarPostFailures.find(row =>
            row.request === selected.request), 'browser-observed lost POST reply');
        } catch (error) {
          const finished = avatarPostFinishes.filter(row => row.request === selected.request).length;
          const failed = avatarPostFailures.filter(row => row.request === selected.request).length;
          const statuses = avatarPostResponses.filter(row => row.request === selected.request)
            .map(row => row.status);
          throw Error(`Owned Account avatar browser-observed lost POST reply unavailable `
            + `(selectedFinished=${finished}, selectedFailed=${failed}, `
            + `selectedStatuses=${statuses.join(',') || 'none'}, allPostFailures=${avatarPostFailures.length})`,
          { cause: error });
        }
        assert.equal(avatarFault.lost, true, 'committed actual reply was lost once');
        assert.equal(avatarGets.length - beforeGet, 0, 'lost ACK did not invent a GET before remount');
        avatarStage.enter('avatar-reload');
        await page.reload({ waitUntil: 'domcontentloaded' });
        avatarStage.complete('avatar-reload');
        avatarStage.enter('avatar-reloaded-frame');
        selectedFrame = await frameFor(page, credentials[0].username);
        avatarStage.complete('avatar-reloaded-frame');
        avatarStage.enter('avatar-saved-button');
        await selectedFrame.waitForSelector('.ss-uploadzone [role="status"] button');
        avatarStage.complete('avatar-saved-button');
        avatarStage.enter('avatar-check-click');
        await clickPhysical(selectedFrame, `() => [...document.querySelectorAll('.ss-uploadzone [role="status"] button')]
          .find(button => button.textContent.trim()==='Check saved upload')`);
        avatarStage.complete('avatar-check-click');
      }
      let operationGet;
      try {
        operationGet = await waitForAvatarCaptured(() => avatarGets.length === beforeGet + 1
          && avatarGets.at(-1), 'new durable operation GET');
      } catch (error) {
        const [storage, ui] = await Promise.all([
          dropAck ? page.evaluate(avatarRecoveryStorageFacts, avatarFault.requestId,
            buyer.user.id)
            .catch(() => null) : null,
          selectedFrame.evaluate(avatarRecoveryUiFacts).catch(() => null),
        ]);
        const diagnostic = avatarRecoveryFailureDiagnostic({ avatarGets, avatarGetAttempts,
          avatarGetResponses, avatarGetFailures, avatarPosts, avatarPostFailures,
          avatarPostFinishes, avatarPostResponses, beforeGet, beforeGetAttempts,
          beforeGetResponses, beforeGetFailures, beforePost, selected, storage, ui });
        throw Error(`Owned Account avatar new durable operation GET unavailable ${JSON.stringify(diagnostic)}`,
          { cause: error });
      }
      const expectedRequestId = operationGet.path.slice(avatarGet('').length);
      if (dropAck) assert.equal(expectedRequestId, avatarFault.requestId);
      avatarStage.enter('avatar-ui-receipt');
      const reply = await waitForAvatarUiReceipt(selectedFrame, expectedRequestId);
      avatarStage.complete('avatar-ui-receipt');
      avatarStage.enter('avatar-transport-assertions');
      assert.equal(reply.filename, filename); assert.equal(reply.mime, mime);
      assert.equal(reply.size_bytes, bytes.length);
      assert.equal(avatarGets.length - beforeGet, 1, 'one durable operation GET, no polling/repost');
      assert.equal(avatarGets.at(-1).path, avatarGet(reply.requestId));
      assert.equal(avatarPosts.length - beforePost, 1);
      if (reply.operationId) effects.push(await readEffect(reply.operationId));
      avatarStage.complete('avatar-transport-assertions');
      return { frame: selectedFrame, reply, effect: reply.operationId ? effects.at(-1) : null };
    } finally { await fs.rm(filePath); avatarFault.armed = false; }
  };
  let currentFrame = frame;
  const firstBytes = Buffer.from('<html><body>owned Q05 avatar payload</body></html>');
  const first = await physicalUpload(currentFrame, { filename: 'owned-avatar.html',
    mime: 'text/html', bytes: firstBytes, dropAck: true });
  currentFrame = first.frame;
  avatarStage.enter('first-effect-readback');
  assert.equal(first.reply.status, 'completed');
  assert.equal(first.effect.outcome, 'completed');
  assert.equal(first.effect.original_filename, 'owned-avatar.html');
  assert.equal(first.effect.declared_mime, 'text/html');
  assert.equal(first.effect.admission_sha, avatarHash(firstBytes));
  assert.equal(first.effect.effect_sha, avatarHash(firstBytes));
  assert.deepEqual(await fs.readFile(path.join(uploadRoot, first.effect.stored_virtual_path)), firstBytes);
  avatarStage.complete('first-effect-readback');
  avatarStage.enter('first-authority');
  const firstPost = avatarPosts[0];
  assert.match(firstPost.authorization, /^Bearer \S+$/);
  const firstScope = await composition.launches.resolveCapability(firstPost.launch);
  const firstSession = await composition.personaAuth.authenticateBoundToken({ scope: firstScope,
    token: firstPost.authorization.slice(7) });
  assert.equal(first.effect.launch_id, firstScope.launchId);
  assert.equal(first.effect.platform_owner_id, firstScope.platformOwnerId);
  assert.equal(first.effect.platform_session_id, firstScope.platformSessionId);
  assert.equal(first.effect.shop_user_id, buyer.user.id);
  assert.equal(first.effect.persona_session_id, firstSession.sessionId);
  avatarStage.complete('first-authority');
  const siblingRows = () => pools.AGENTS_RUNTIME.query(`SELECT session_id,revoked_at
    FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1
      AND original_platform_owner_id=$2 ORDER BY session_id`,
  [siblingScope.launchId, siblingScope.platformOwnerId]);
  const siblingBytes = Buffer.from('<svg>owned sibling avatar remains</svg>');
  avatarStage.enter('sibling-scene');
  const siblingTarget = await prepareAvatarSiblingScene(composition, siblingScope,
    sibling.user, siblingSession);
  const originalTarget = await composition.scenes.readRetained(firstScope);
  assert.notEqual(siblingScope.platformOwnerId, firstScope.platformOwnerId,
    'the preserved sibling avatar must belong to a different platform owner');
  assert.notEqual(siblingTarget.targetId, originalTarget.targetId,
    'the preserved sibling avatar must have a different reset target');
  avatarStage.complete('sibling-scene');
  avatarStage.enter('sibling-upload');
  const siblingUpload = await composition.accountAvatar.upload({ scope: siblingScope,
    persona: sibling.user, personaSession: siblingSession,
    requestId: randomUUID(), scopeId: sibling.user.id,
    filename: 'sibling-avatar.svg', mime: 'image/svg+xml', bytes: siblingBytes, public: false });
  assert.equal(siblingUpload.status, 'completed');
  const siblingEffect = await readEffect(siblingUpload.operationId);
  const siblingFile = path.join(uploadRoot, siblingEffect.stored_virtual_path);
  assert.deepEqual(await fs.readFile(siblingFile), siblingBytes);
  const siblingBefore = (await siblingRows()).rows;
  avatarStage.complete('sibling-upload');
  avatarStage.enter('sibling-private-get');
  const siblingReply = await fetch(`${origin}${avatarGet(first.reply.requestId)}`, {
    headers: { authorization: `Bearer ${siblingReady.persona.token}`,
      'x-dvaia-secureshop-launch': siblingReady.bearer }, signal: AbortSignal.timeout(10000) });
  assert.equal(siblingReply.status, 200);
  const siblingBody = await siblingReply.json();
  assert.equal(siblingBody.status, 'uncertain'); assert.equal(siblingBody.operationId, null);
  assert.deepEqual((await siblingRows()).rows, siblingBefore);
  avatarStage.complete('sibling-private-get');
  const oldBearer = firstPost.authorization, oldLaunch = firstPost.launch;
  avatarStage.enter('current-before-reset-get');
  const currentBeforeReset = await fetch(`${origin}${avatarGet(first.reply.requestId)}`, {
    headers: { authorization: oldBearer, 'x-dvaia-secureshop-launch': oldLaunch },
    signal: AbortSignal.timeout(10000) });
  assert.equal(currentBeforeReset.status, 200, 'actual current authority can read the saved upload');
  assert.equal((await currentBeforeReset.json()).operationId, first.reply.operationId);
  avatarStage.complete('current-before-reset-get');
  avatarStage.enter('reset-commit');
  const resetResult = await reset.launchResetCoordinator.reset({ ...firstScope,
    expectedGeneration: firstScope.generation, idempotencyKey: randomUUID() });
  assert.equal(resetResult.status, 'committed');
  avatarStage.complete('reset-commit');
  avatarStage.enter('stale-after-reset-get');
  const staleAfterReset = await fetch(`${origin}${avatarGet(first.reply.requestId)}`, {
    headers: { authorization: oldBearer, 'x-dvaia-secureshop-launch': oldLaunch },
    signal: AbortSignal.timeout(10000) });
  assert([401, 403, 409].includes(staleAfterReset.status));
  await staleAfterReset.arrayBuffer();
  avatarStage.complete('stale-after-reset-get');
  avatarStage.enter('reset-cleanup');
  const oldEffectPath = path.join(uploadRoot, first.effect.stored_virtual_path);
  await assert.rejects(fs.stat(oldEffectPath), error => error?.code === 'ENOENT');
  const cleanupRows = (await review.query(`SELECT target_id,launch_id,scenario_id,generation,
    platform_owner_id,platform_session_id,deleted_count,quarantined_count
    FROM secureshop_review.bound_upload_cleanup_receipts WHERE target_id=$1`,
  [originalTarget.targetId])).rows;
  assert.equal(cleanupRows.length, 1);
  assert.equal(cleanupRows[0].launch_id, firstScope.launchId);
  assertAvatarCleanupGeneration(cleanupRows[0].generation, firstScope.generation);
  assert(cleanupRows[0].deleted_count >= 1);
  assert.deepEqual(await fs.readFile(siblingFile), siblingBytes,
    'other owner upload remains after exact target reset');
  assert.deepEqual((await siblingRows()).rows, siblingBefore);
  avatarStage.complete('reset-cleanup');
  let merchantSessionProof;
  for (const entry of credentials.slice(1)) {
    avatarStage.enter('role-account-menu');
    await openAvatarAccountMenu(currentFrame);
    avatarStage.complete('role-account-menu');
    avatarStage.enter('role-signout-click');
    await clickPhysical(currentFrame, `() => [...document.querySelectorAll('button')]
      .find(button => button.textContent.trim()==='Sign out')`);
    avatarStage.complete('role-signout-click');
    avatarStage.enter('role-signout-route');
    await page.waitForFunction(() => location.pathname === '/secureshop', { timeout: 20000 });
    avatarStage.complete('role-signout-route');
    if (entry.role === 'admin') {
      avatarStage.enter('merchant-revoked-get');
      assert(merchantSessionProof, 'merchant current-session read must precede logout');
      const revokedSessionGet = await fetch(`${origin}${avatarGet(merchantSessionProof.requestId)}`, {
        headers: { authorization: merchantSessionProof.authorization,
          'x-dvaia-secureshop-launch': merchantSessionProof.launch },
        signal: AbortSignal.timeout(10000) });
      assert([401, 403, 409].includes(revokedSessionGet.status),
        'logged-out merchant session cannot read its saved avatar');
      await revokedSessionGet.arrayBuffer();
      avatarStage.complete('merchant-revoked-get');
    }
    currentFrame = await physicalLogin(entry);
    const bytes = Buffer.from(`owned Q05 ${entry.role} avatar`);
    const result = await physicalUpload(currentFrame, { filename: `owned-${entry.role}.svg`,
      mime: 'image/svg+xml', bytes });
    currentFrame = result.frame;
    avatarStage.enter('role-effect-readback');
    assert.equal(result.reply.status, 'completed');
    assert.equal(result.effect.original_filename, `owned-${entry.role}.svg`);
    assert.deepEqual(await fs.readFile(path.join(uploadRoot, result.effect.stored_virtual_path)), bytes);
    avatarStage.complete('role-effect-readback');
    if (entry.role === 'merchant') {
      avatarStage.enter('merchant-current-get');
      const selected = avatarPosts.at(-1);
      const currentGet = await fetch(`${origin}${avatarGet(result.reply.requestId)}`, {
        headers: { authorization: selected.authorization,
          'x-dvaia-secureshop-launch': selected.launch },
        signal: AbortSignal.timeout(10000) });
      assert.equal(currentGet.status, 200, 'merchant saved-avatar GET works before logout');
      assert.equal((await currentGet.json()).operationId, result.reply.operationId);
      merchantSessionProof = { requestId: result.reply.requestId,
        authorization: selected.authorization, launch: selected.launch };
      avatarStage.complete('merchant-current-get');
    }
  }
  avatarStage.enter('role-results');
  assert.deepEqual(effects.filter(row => row.outcome === 'completed').map(row => row.original_filename),
    ['owned-avatar.html', 'owned-merchant.svg', 'owned-admin.svg']);
  avatarStage.complete('role-results');
  const traversalBytes = Buffer.from('<svg>bounded owned Q05 traversal</svg>');
  const traversal = await physicalUpload(currentFrame, { filename: '....//owned-escape.svg',
    mime: 'image/svg+xml', bytes: traversalBytes });
  currentFrame = traversal.frame;
  avatarStage.enter('traversal-effect');
  assert.equal(traversal.reply.status, 'completed');
  assert.equal(traversal.reply.is_traversal, true);
  assert.equal(traversal.effect.is_traversal, true);
  assert(traversal.effect.stored_virtual_path.startsWith('operations/'));
  assert(!traversal.effect.stored_virtual_path.includes('..'));
  assert.deepEqual(await fs.readFile(path.join(uploadRoot, traversal.effect.stored_virtual_path)),
    traversalBytes);
  avatarStage.complete('traversal-effect');
  avatarStage.enter('fixed-mode-read');
  const adminLogin = await auth.login({ username: credentials[2].username,
    password: credentials[2].password });
  const fixedBefore = await standaloneMode.get(adminLogin.context);
  avatarStage.complete('fixed-mode-read');
  avatarStage.enter('fixed-mode-set');
  await standaloneMode.set(adminLogin.context, { mode: 'fixed', expectedRevision: fixedBefore.revision });
  avatarStage.complete('fixed-mode-set');
  avatarStage.enter('fixed-account-menu');
  await openAvatarAccountMenu(currentFrame);
  avatarStage.complete('fixed-account-menu');
  avatarStage.enter('fixed-signout-click');
  await clickPhysical(currentFrame, `() => [...document.querySelectorAll('button')]
    .find(button => button.textContent.trim()==='Sign out')`);
  avatarStage.complete('fixed-signout-click');
  avatarStage.enter('fixed-signout-route');
  await page.waitForFunction(() => location.pathname === '/secureshop', { timeout: 20000 });
  avatarStage.complete('fixed-signout-route');
  currentFrame = await physicalLogin(credentials[2]);
  const beforeFixed = avatarPosts.length;
  avatarStage.enter('fixed-files-baseline');
  const fixedFiles = (await fs.readdir(uploadRoot, { recursive: true })).sort();
  avatarStage.complete('fixed-files-baseline');
  const deniedTraversal = await physicalUpload(currentFrame, { filename: '....//fixed-escape.svg',
    mime: 'image/svg+xml', bytes: Buffer.from('<svg>fixed traversal denied</svg>') });
  currentFrame = deniedTraversal.frame;
  avatarStage.enter('fixed-traversal-absence');
  assert.equal(deniedTraversal.reply.status, 'denied');
  assert.equal(deniedTraversal.reply.denialCode, 'PATH_TRAVERSAL_DENIED');
  assert.equal(deniedTraversal.effect.outcome, 'denied');
  assert.equal(deniedTraversal.effect.stored_virtual_path, null);
  assert.deepEqual((await fs.readdir(uploadRoot, { recursive: true })).sort(), fixedFiles,
    'Fixed traversal denial did not write any owned upload file');
  avatarStage.complete('fixed-traversal-absence');
  const deniedExtension = await physicalUpload(currentFrame, { filename: 'fixed-avatar.html',
    mime: 'text/html', bytes: Buffer.from('<html>fixed extension denied</html>') });
  currentFrame = deniedExtension.frame;
  avatarStage.enter('fixed-extension-absence');
  assert.equal(deniedExtension.reply.status, 'denied');
  assert.equal(deniedExtension.reply.denialCode, 'EXTENSION_DENIED');
  assert.equal(deniedExtension.effect.outcome, 'denied');
  assert.equal(deniedExtension.effect.stored_virtual_path, null);
  assert.deepEqual((await fs.readdir(uploadRoot, { recursive: true })).sort(), fixedFiles,
    'Fixed denial did not write any owned upload file');
  avatarStage.complete('fixed-extension-absence');
  avatarStage.enter('final-inventory');
  assert.equal(avatarPosts.length - beforeFixed, 2);
  assert.deepEqual((await siblingRows()).rows, siblingBefore);
  assert.equal(modelCalls(), 0); assert.equal(judgeCalls(), 0);
  avatarStage.complete('final-inventory');
  avatarStage.enter('final-build');
  await admission.verifyBuild();
  avatarStage.complete('final-build');
  avatarStage.enter('final-browser-targets');
  boundary.assertNoUnexpectedTargets();
  avatarStage.complete('final-browser-targets');
  avatarStage.enter('final-credit');
  const credit = (await identity.query(`SELECT
    (SELECT count(*)::int FROM workshop_platform.objective_judgments) AS judgments,
    (SELECT count(*)::int FROM workshop_platform.objective_contributions) AS contributions`)).rows[0];
  assert.deepEqual(credit, { judgments: 0, contributions: 0 });
  avatarStage.complete('final-credit');
  return { version: 1, scope: 'Q05 Account avatar direct rendered action', passed: true,
    roles: credentials.map(row => row.role),
    physical: { onePostPerSelectedUpload: true, accountBridgeReadback: true },
    vulnerable: { mimeAndFilenameHonored: true, traversalConfined: true },
    fixed: { extensionDeniedBeforeWrite: true, traversalDeniedBeforeWrite: true },
    recovery: { committedAckLost: true, getOnlyAfterRemount: true },
    authority: { sessionFenced: true, resetFenced: true, siblingUnchanged: true },
    calls: { model: modelCalls(), judge: judgeCalls(), credit: 0 } };
}

async function runOtherSessionPhysical({ frame, page, origin, buyerName, password, auth, browserCookie,
  cases, clickPhysical, exactConsequenceDialogButton, composition, scope,
  browserSession, browserAuth, siblingSession, siblingRows, siblingBefore,
  posts, requests, sessionReplies, agents, identity, admission, boundary,
  modelCalls, judgeCalls }) {
  assert.equal(browserCookie?.httpOnly, true);
  assert.match(browserAuth.authorization, /^Bearer \S+$/);
  const otherLogin = await auth.withReauthenticatedExecution({ token: browserCookie.value,
    username: buyerName, password }, shopPrincipal =>
    composition.personaAuth.establishAdditionalSession({ scope, shopPrincipal,
      token: browserAuth.authorization.slice(7),
      ip: '127.0.0.2', userAgent: 'Q05 other owned session' }));
  const otherSession = await composition.personaAuth.authenticateBoundToken({
    scope, token: otherLogin.token });
  assert.equal(otherSession.user.id, browserSession.user.id);
  assert.notEqual(otherSession.sessionId, browserSession.sessionId);
  assert.equal((await composition.launches.resolveCapability(browserAuth.launch)).launchId,
    scope.launchId);

  // The first physical GET preceded creation of the second same-owner session.
  // Refresh through the rendered control; do not inject a row into React state.
  await clickPhysical(frame, `() => [...document.querySelectorAll('button')]
    .find(button => button.textContent.trim()==='Refresh')`);
  await frame.waitForFunction(() => {
    const rows = [...document.querySelectorAll('tbody tr')];
    return rows.length === 2 && rows.filter(row => row.textContent.includes('(current session)')).length === 1
      && rows.some(row => row.textContent.includes('Q05 other owned session'));
  }, { timeout: 20000 });
  assert.deepEqual(sessionReplies, [200, 200]);
  assert.equal(requests.length, 2);
  assert.equal(requests[1].authorization, browserAuth.authorization);
  assert.equal(requests[1].launch, browserAuth.launch);
  const inventory = await composition.personaAuth.listSessions({ scope,
    shopPersona: browserSession.user, currentSessionId: browserSession.sessionId,
    authorityVersion: browserSession.authorityVersion });
  assert.equal(inventory.length, 2);
  const selected = cases.selectedRow(inventory.find(row => row.id === otherSession.sessionId), {
    id: otherSession.sessionId, user_agent: 'Q05 other owned session', ip: '127.0.0.2' });
  const rowButton = `() => { const rows=[...document.querySelectorAll('tbody tr')]
    .filter(row => row.textContent.includes('Q05 other owned session')
      && !row.textContent.includes('(current session)'));
    return rows.length===1 ? [...rows[0].querySelectorAll('button')]
      .find(button=>button.textContent.trim()==='Revoke') : null; }`;
  const dialog = { title: 'Revoke session?',
    consequence: `${selected.userAgent} (${selected.ip}), session ${selected.id}. This other session will stop working. Your current session will remain signed in.`,
    confirm: 'Confirm revoke' };
  const dialogButton = label => `() => (${exactConsequenceDialogButton.toString()})(${JSON.stringify(dialog.title)},${JSON.stringify(dialog.consequence)},${JSON.stringify(dialog.confirm)},${JSON.stringify(label)})`;
  await clickPhysical(frame, rowButton);
  await frame.waitForFunction(exactConsequenceDialogButton, { timeout: 20000 },
    dialog.title, dialog.consequence, dialog.confirm, 'Cancel');
  assert.equal(posts.length, 0);
  await clickPhysical(frame, dialogButton('Cancel'));
  await frame.waitForFunction(title => ![...document.querySelectorAll('[role="dialog"]')]
    .some(node => node.querySelector('#ss-dialog-title')?.textContent.trim() === title),
  { timeout: 20000 }, dialog.title);
  assert.equal(posts.length, 0);

  // Keep the existing different-owner sibling as a foreign-denial control.
  const foreign = await fetch(`${origin}${cases.revokePath(siblingSession.sessionId)}`, {
    method: 'POST', headers: { authorization: browserAuth.authorization,
      'x-dvaia-secureshop-launch': browserAuth.launch }, signal: AbortSignal.timeout(10000) });
  assert.equal(foreign.status, 200);
  assert.deepEqual(await foreign.json(), { ok: false });
  assert.deepEqual((await siblingRows()).rows, siblingBefore);

  await clickPhysical(frame, rowButton);
  await frame.waitForFunction(exactConsequenceDialogButton, { timeout: 20000 },
    dialog.title, dialog.consequence, dialog.confirm, dialog.confirm);
  assert.equal(posts.length, 0);
  const selectedPath = cases.revokePath(selected.id);
  // The fault is armed on Response, after a genuine 200. No second POST may
  // be sent while the UI says unresolved; only a physical Refresh can reconcile.
  const loss = await cases.loseOneCompletedAck(page, `${origin}${selectedPath}`);
  let lost;
  try {
    await clickPhysical(frame, dialogButton(dialog.confirm));
    await frame.waitForFunction(() => [...document.querySelectorAll('[role="alert"]')]
      .some(node => node.textContent.includes('Session change is unresolved')),
    { timeout: 20000 });
    lost = loss.observed();
    assert(lost && lost.status === 200);
  } finally { await loss.close(); }
  assert.equal(posts.length, 1);
  assert.equal(posts[0].path, selectedPath);
  assert.equal(posts[0].authorization, browserAuth.authorization);
  assert.equal(posts[0].launch, browserAuth.launch);
  const blocked = await frame.evaluate(() => {
    const rows = [...document.querySelectorAll('tbody tr')]
      .filter(row => row.textContent.includes('Q05 other owned session'));
    if (rows.length !== 1) return false;
    const controls = [...rows[0].querySelectorAll('button')]
      .filter(button => button.textContent.trim() === 'Revoke');
    return controls.length === 1 && controls[0].disabled === true;
  });
  assert.equal(blocked, true, 'unresolved revoke must disable another row click');
  assert.equal(posts.length, 1);
  await clickPhysical(frame, `() => [...document.querySelectorAll('button')]
    .find(button => button.textContent.trim()==='Refresh')`);
  await frame.waitForFunction(() => {
    const rows = [...document.querySelectorAll('tbody tr')];
    return rows.length === 1 && rows[0].textContent.includes('(current session)');
  }, { timeout: 20000 });
  assert.deepEqual(sessionReplies, [200, 200, 200]);
  assert.equal(posts.length, 1, 'GET-only recovery must not resubmit revoke');
  const selectedRows = (await agents.query(`SELECT session_id,revoked_at FROM secureshop_agents.bound_persona_sessions
    WHERE platform_launch_id=$1 AND shop_user_id=$2 AND session_id=$3`,
  [scope.launchId, browserSession.user.id, selected.id])).rows;
  assert.equal(selectedRows.length, 1);
  assert(selectedRows[0].revoked_at);
  const auditRows = (await agents.query(`SELECT action,source_kind,source_id,shop_user_id,
    launch_id,original_platform_owner_id,original_platform_session_id
    FROM secureshop_agents.bound_audit_events WHERE action='session_revoke' AND source_id=$1`,
  [selected.id])).rows;
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].shop_user_id, browserSession.user.id);
  assert.equal(auditRows[0].launch_id, scope.launchId);
  assert.equal(auditRows[0].original_platform_owner_id, scope.platformOwnerId);
  assert.equal(auditRows[0].original_platform_session_id, scope.platformSessionId);
  await assert.rejects(composition.personaAuth.authenticateBoundToken({
    scope, token: otherLogin.token }));
  assert.equal((await composition.personaAuth.authenticateBoundToken({
    scope, token: browserAuth.authorization.slice(7) })).sessionId, browserSession.sessionId);
  assert.deepEqual((await siblingRows()).rows, siblingBefore);
  await admission.verifyBuild(); boundary.assertNoUnexpectedTargets();
  const credit = (await identity.query(`SELECT
    (SELECT count(*)::int FROM workshop_platform.objective_judgments) AS judgments,
    (SELECT count(*)::int FROM workshop_platform.objective_contributions) AS contributions`)).rows[0];
  assert.deepEqual(credit, { judgments: 0, contributions: 0 });
  const receipt = { version: 1, scope: cases.SCOPE, passed: true,
    physical: { cancelPosts: 0, preConfirmPosts: 0, confirmedPosts: 1,
      foreignDeniedPosts: 1, confirmedStatus: lost.status, selectedDialogExact: true,
      browserAckLost: true, serverReplySha256: lost.replySha256 },
    state: { twoSameLaunchSessions: true, selectedRevoked: true,
      currentRetained: true, selectedTokenDenied: true, currentTokenAccepted: true,
      auditBound: true },
    authority: { capturedBrowserBearer: true, sameLaunchOwnerSession: true,
      foreignSessionDenied: true, foreignHttpDenied: true },
    recovery: { operationIdAvailable: false, explicitSessionsGet: true, noSecondPost: true },
    sibling: { preexistingNonempty: true, unchanged: true },
    calls: { model: modelCalls(), judge: judgeCalls(), credit: 0 } };
  cases.assertReceipt(receipt);
  return receipt;
}


async function runRenderedCase(avatar = false, other = false) {
    const workspace = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/');
    assert.equal(workspace, process.cwd());
    const receiptPath = process.env[avatar
      ? 'SECURESHOP_ACCOUNT_AVATAR_EVIDENCE_PATH'
      : other ? 'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_EVIDENCE_PATH'
      : 'SECURESHOP_ACCOUNT_SESSION_REVOKE_EVIDENCE_PATH'];
    assert.equal(receiptPath, path.join(workspace, 'tasks/qualification',
      path.basename(path.dirname(receiptPath)), avatar
        ? 'account-avatar-browser-v1.json' : other
        ? 'account-other-session-revoke-browser-v1.json' : 'account-current-session-revoke-browser-v2.json'));
    const build = path.join(workspace, 'client/build');
    await fs.access(path.join(build, 'index.html')); await fs.access(path.join(build, 'secureshop-frame.html'));
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
    assert(path.isAbsolute(executablePath)); await fs.access(executablePath);
    const admission = await admitCommerceBrowser(process.env,
      { workspace, evidencePath: receiptPath, executablePath,
        variant: avatar ? 'account-avatar' : other
        ? 'account-session-revoke-other' : 'account-session-revoke' });
    assert(admission, 'independent current-host browser grant required');
    const urls = storeUrls();
    const pools = Object.fromEntries(Object.keys(STORES).flatMap(store => ['MIGRATION', 'RUNTIME']
      .map(role => [`${store}_${role}`, new Pool({ connectionString: urls[`${store}_${role}`],
        max: role === 'RUNTIME' ? 12 : 3 })])));
    const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4 });
    let server, browser, profile, page, composition, failure, resetKeyDirectory, uploadRoot;
    const avatarStage = avatar ? createAvatarStageTrace() : null;
    const originalUploadRoot = process.env.SECURESHOP_UPLOAD_ROOT;
    let modelCalls = 0, judgeCalls = 0;
    const posts = [], requests = [], sessionReplies = [];
    const avatarPosts = [], avatarGets = [], avatarGetAttempts = [], avatarGetResponses = [],
      avatarGetFailures = [], avatarPostFailures = [];
    const avatarPostFinishes = [], avatarPostResponses = [];
    const avatarFault = { armed: false, lost: false, requestId: null, responseSha256: null };
    let receipt;
    try {
      for (const [store, directory] of [
        ['IDENTITY', 'identity-migrations'], ['AGENTS', 'workshop-migrations/secureshop_agents'],
        ['REVIEW', 'workshop-migrations/secureshop_review'], ['COMMERCE', 'workshop-migrations/secureshop'],
      ]) await migrate(pools[`${store}_MIGRATION`], path.join(workspace, 'db/postgres', directory));
      await require('../../server/database/postgres/workshopPlatformSeed')
        .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopAssessmentSeed')
        .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopStandaloneSeed')
        .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
      const seedClient = await pools.COMMERCE_MIGRATION.connect();
      try { await seedClient.query('BEGIN');
        await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seedClient);
        await seedClient.query('COMMIT');
      } catch (error) { await seedClient.query('ROLLBACK'); throw error; }
      finally { seedClient.release(); }
      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
      const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
      if (avatar) {
        uploadRoot = await fs.mkdtemp(path.join(process.env.TMPDIR, 'dvaia-account-avatar-'));
        await fs.chmod(uploadRoot, 0o700);
        process.env.SECURESHOP_UPLOAD_ROOT = uploadRoot;
      }
      const auth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const suffix = randomUUID().slice(0, 8), password = 'owned-session-revoke-password';
      const buyerName = `session_owner_${suffix}`, siblingName = `session_peer_${suffix}`;
      const buyer = await auth.register({ username: buyerName, email: `${buyerName}@example.invalid`, password,
        role: 'customer' });
      const sibling = await auth.register({ username: siblingName,
        email: `${siblingName}@example.invalid`, password, role: 'customer' });
      const audit = require('../../server/services/secureshopBoundAuditComposition')
        .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
          includeRunArtifacts: true });
      const reset = require('../../server/services/secureshopCleanupComposition')
        .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, leasePool, audit });
      const progress = require('../../server/database/postgres/workshopProgressRepository')
        .createWorkshopProgressRepository(identity);
      const unavailableJudge = async () => { judgeCalls++; throw Error('Judge not admitted'); };
      const grading = await require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
          progress, resetComposition: reset, judge: unavailableJudge,
          expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository')
          .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
        reviewPool: review, launches: reset.launches });
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identity);
      const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
        .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
      const couponDependencies = await require('../../server/services/secureshopCouponProduction')
        .prepareCommerceDependencies({ modeAuthority, reviewPool: review,
          launches: reset.launches, mode: 'vuln' });
      const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
        .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
          audit: audit.agents });
      const unavailableProvider = Object.fromEntries(['chat', 'finalResponse'].map(method =>
        [method, async () => { modelCalls++; throw Error('Model not admitted'); }]));
      composition = require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: reset,
          gradingBootstrap: grading, scenes, modeAuthority, couponDependencies,
          toolPolicyRepository, fixtures: [], requiredObjectives: ['ss_stored_browser_execution'],
          jwtSecret: 'owned-session-revoke-persona-secret-at-least-32-bytes',
          agentRuntime: { provider: unavailableProvider } });
      await composition.repositories.personas.ensureTemplates();
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });
      let siblingReady;
      if (avatar) {
        await auth.logout(sibling.token);
        const peerTenantSlug = `avatar_peer_${suffix}`;
        await provisionAvatarPeerTenant(pools.IDENTITY_MIGRATION, sibling.context,
          peerTenantSlug);
        const peerAuth = require('../../server/services/secureshopStandaloneAuth')
          .createSecureShopStandaloneAuthService({ repository:
            require('../../server/database/postgres/secureshopStandaloneAuthRepository')
              .createSecureShopStandaloneAuthRepository({ pool: identity,
                executionTenantSlug: peerTenantSlug }) });
        avatarStage.enter('peer-login');
        const peerLogin = await peerAuth.login({ username: siblingName, password });
        avatarStage.complete('peer-login');
        const peerBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
          .createSecureShopStandaloneBootstrap({ launches: composition.launches,
            personaAuth: composition.personaAuth, authService: peerAuth });
        avatarStage.enter('peer-bootstrap');
        siblingReady = await peerBootstrap(peerLogin.context);
        avatarStage.complete('peer-bootstrap');
      } else siblingReady = await bootstrap(sibling.context);
      const siblingScope = await composition.launches.resolveCapability(siblingReady.bearer);
      const siblingSession = await composition.personaAuth.authenticateBoundToken({
        scope: siblingScope, token: siblingReady.persona.token });
      const siblingRows = () => agents.query(`SELECT session_id,revoked_at FROM secureshop_agents.bound_persona_sessions
        WHERE platform_launch_id=$1 AND original_platform_owner_id=$2 ORDER BY session_id`,
      [siblingScope.launchId, siblingScope.platformOwnerId]);
      const siblingBefore = (await siblingRows()).rows;
      assert.equal(siblingBefore.length, 1);
      assert.equal(siblingBefore[0].session_id, siblingSession.sessionId);
      const protectedReset = require('../../server/services/secureshopStandaloneReset')
        .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
          launches: composition.launches, scenes, resetCoordinator: reset.launchResetCoordinator,
          preflight: reset.sceneResetPreflight });
      resetKeyDirectory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'dvaia-session-reset-'));
      await fs.chmod(resetKeyDirectory, 0o700);
      const resetKeyFile = path.join(resetKeyDirectory, 'keys.json');
      await fs.writeFile(resetKeyFile, JSON.stringify({ version: 1, activeKeyId: 'owned',
        keys: { owned: randomBytes(32).toString('base64url') } }), { flag: 'wx', mode: 0o600 });
      const registeredAdminReset = await require('../../server/services/secureshopPasswordResetComposition')
        .prepareRegisteredAdminResetService({ filePath: resetKeyFile, pool: identity });
      const cartImport = require('../../server/services/secureshopStandaloneCartImport')
        .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
          personaAuth: composition.personaAuth, commerce: composition.commerce });
      const assessmentObjectives = require('../../server/services/secureshopAssessmentCatalog')
        .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
      const assessmentProgress = require('../../server/services/secureshopAssessmentProgress')
        .createSecureShopAssessmentProgress({ repository:
          require('../../server/database/postgres/secureshopAssessmentProgressRepository')
            .createSecureShopAssessmentProgressRepository({ pool: identity }) });
      const assessmentRecovery = require('../../server/services/secureshopAssessmentRecovery')
        .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth,
          bootstrap, launches: composition.launches, personaAuth: composition.personaAuth,
          personaAuthority: grading.personaAuthority, modeAuthority, scenes,
          judge: unavailableJudge });
      const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
        .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
          reviewPool: review, commercePool: commerce });
      const standaloneAuth = Object.freeze({ service: auth, bootstrap, cartImport,
        reset: protectedReset, registeredAdminReset, assessmentObjectives,
        assessmentProgress, assessmentRecovery,
        mode: require('../../server/services/secureshopStandaloneMode')
          .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository }) });
      const mounted = { ...composition, standaloneAuth, publicCatalog };
      const bound = await require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          applicationMode: 'standalone',
          authenticateToken: (_request, response) => response.sendStatus(401),
          audit: async () => {}, agentRuntime: {}, getComposition: async () => mounted });
      assert.equal(bound.standaloneReadiness?.ready, true);
      assert(Object.values(bound.standaloneReadiness.checks).every(value => value === true),
        'actual standalone core readiness required before browser launch');
      const app = express(); app.use(express.json());
      server = await new Promise(resolve => { const opened = app.listen(0, '127.0.0.1', () => resolve(opened)); });
      const origin = `http://127.0.0.1:${server.address().port}`;
      if (avatar) app.use('/api/secureshop/uploads/avatar', (request, response, next) => {
        if (request.method !== 'POST' || !avatarFault.armed) return next();
        loseAvatarAckAfterCommit(request, response, value => {
          avatarFault.armed = false;
          avatarFault.lost = true;
          avatarFault.requestId = value.requestId;
          avatarFault.responseSha256 = value.responseSha256;
        });
        next();
      });
      app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthRouter({ service: auth, bootstrap,
          cartImport, reset: protectedReset, registeredAdminReset,
          assessmentObjectives, assessmentProgress, assessmentRecovery,
          mode: standaloneAuth.mode, allowedOrigins: [origin], secureCookies: false }));
      app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
        .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
      app.use('/api', (_request, response) => response.status(404).json({ error: 'Outside Q05 account cohort' }));
      app.use(serveOpaqueFrameAssets(build));
      app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));
      profile = await fs.mkdtemp(path.join(process.env.TMPDIR || os.tmpdir(), avatar
        ? 'dvaia-account-avatar-' : 'dvaia-standalone-commerce-'));
      if (avatar) avatarStage.enter('browser-launch');
      browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
        executablePath, args: admission.browserArgs({ profile, origin }) });
      if (avatar) avatarStage.complete('browser-launch');
      if (avatar) avatarStage.enter('browser-ack');
      await admission.acknowledgeBrowser({ browser, profile });
      if (avatar) avatarStage.complete('browser-ack');
      const boundary = admission.watchBrowserTargets(browser);
      if (avatar) avatarStage.enter('browser-page');
      page = await boundary.newPage(browser);
      if (avatar) { avatarStage.complete('browser-page'); avatarStage.enter('browser-viewport'); }
      await page.setViewport({ width: 1280, height: 900 });
      if (avatar) { avatarStage.complete('browser-viewport'); avatarStage.enter('browser-guard'); }
      await admission.guardPageRequests(page, origin);
      if (avatar) avatarStage.complete('browser-guard');
      page.on('request', request => {
        const url = new URL(request.url());
        if (url.origin !== origin) return;
        if (avatar && request.method() === 'POST' && url.pathname === AVATAR_POST)
          avatarPosts.push({ request, path: url.pathname,
            authorization: request.headers().authorization || null,
            launch: request.headers()['x-dvaia-secureshop-launch'] || null });
        if (avatar && request.method() === 'GET' && url.origin === origin
          && url.pathname.startsWith('/api/secureshop/uploads/avatar/operations/')) {
          avatarGetAttempts.push({ request });
          if (/^\/api\/secureshop\/uploads\/avatar\/operations\/[a-f0-9-]{36}$/.test(url.pathname))
            avatarGets.push({ path: url.pathname });
        }
        if (request.method() === 'POST' && /^\/api\/secureshop\/v2\/auth\/users\/me\/sessions\/.+\/revoke$/.test(url.pathname))
          posts.push({ path: url.pathname, authorization: request.headers().authorization || null,
            launch: request.headers()['x-dvaia-secureshop-launch'] || null });
        if (request.method() === 'GET' && url.pathname === '/api/secureshop/v2/auth/users/me/sessions')
          requests.push({ authorization: request.headers().authorization || null,
            launch: request.headers()['x-dvaia-secureshop-launch'] || null });
      });
      page.on('requestfailed', request => {
        const url = new URL(request.url());
        if (avatar && request.method() === 'POST' && url.origin === origin
          && url.pathname === AVATAR_POST)
          avatarPostFailures.push({ request });
        if (avatar && request.method() === 'GET' && url.origin === origin
          && url.pathname.startsWith('/api/secureshop/uploads/avatar/operations/'))
          avatarGetFailures.push({ request });
      });
      page.on('requestfinished', request => {
        const url = new URL(request.url());
        if (avatar && request.method() === 'POST' && url.origin === origin
          && url.pathname === AVATAR_POST) avatarPostFinishes.push({ request });
      });
      page.on('response', response => {
        const request = response.request();
        const url = new URL(response.url());
        if (avatar && request.method() === 'POST' && url.origin === origin
          && url.pathname === AVATAR_POST)
          avatarPostResponses.push({ request, status: response.status() });
        if (avatar && request.method() === 'GET' && url.origin === origin
          && url.pathname.startsWith('/api/secureshop/uploads/avatar/operations/'))
          avatarGetResponses.push({ request, status: response.status() });
        if (url.origin === origin && request.method() === 'GET'
          && url.pathname === '/api/secureshop/v2/auth/users/me/sessions')
          sessionReplies.push(response.status());
      });
      if (avatar) avatarStage.enter('initial-goto');
      assert([200, 304].includes((await page.goto(
        `${origin}/secureshop/login?next=%2Fsecureshop%2Faccount`)).status()));
      if (avatar) { avatarStage.complete('initial-goto'); avatarStage.enter('initial-login-form'); }
      await page.waitForSelector('#ss-login-user');
      if (avatar) { avatarStage.complete('initial-login-form'); avatarStage.enter('initial-username'); }
      await page.type('#ss-login-user', buyerName);
      if (avatar) { avatarStage.complete('initial-username'); avatarStage.enter('initial-password'); }
      await page.type('#ss-login-pw', password);
      if (avatar) { avatarStage.complete('initial-password'); avatarStage.enter('initial-submit'); }
      await page.click('button[type="submit"]');
      if (avatar) { avatarStage.complete('initial-submit'); avatarStage.enter('initial-account'); }
      const frame = await cases.admitAccountAfterPhysicalLogin({ page, origin, buyerName,
        buyerId: buyer.user.id, authenticate: token => auth.authenticate(token), findAccountFrame: frameFor });
      if (avatar) avatarStage.complete('initial-account');
      const browserCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.equal(browserCookie?.httpOnly, true);
      assert.notEqual(browserCookie.value, buyer.token,
        'registration and physical browser login are separate owned sessions');
      assert.equal((await auth.authenticate(buyer.token))?.shopUserId, buyer.user.id);
      if (avatar) {
        receipt = await runAvatarCase({ frame, page, origin, workspace, uploadRoot,
          buyer, sibling, siblingReady, siblingScope, siblingSession,
          auth, composition, pools, reset, standaloneMode: standaloneAuth.mode,
          modelCalls: () => modelCalls, judgeCalls: () => judgeCalls, admission, boundary,
          avatarPosts, avatarGets, avatarGetAttempts, avatarGetResponses, avatarGetFailures,
          avatarPostFailures, avatarPostFinishes, avatarPostResponses,
          avatarFault, avatarStage });
      } else {
      await frame.click('#ss-tab-sessions');
      await frame.waitForFunction(initialSessionsReady, { timeout: 20000 });
      assert.equal(requests.length, 1);
      assert.deepEqual(sessionReplies, [200], 'initial physical sessions GET must complete before staging');
      let browserAuth = requests[0];
      assert.match(browserAuth.authorization, /^Bearer \S+$/);
      const scope = await composition.launches.resolveCapability(browserAuth.launch);
      const browserSession = await composition.personaAuth.authenticateBoundToken({
        scope, token: browserAuth.authorization.slice(7) });
      if (other) {
        receipt = await runOtherSessionPhysical({ frame, page, origin, buyerName, password, auth, browserCookie,
          cases, clickPhysical, exactConsequenceDialogButton, composition, scope,
          browserSession, browserAuth, siblingSession, siblingRows, siblingBefore,
          posts, requests, sessionReplies, agents, identity, admission, boundary,
          modelCalls: () => modelCalls, judgeCalls: () => judgeCalls });
      } else {
      const inventory = await composition.personaAuth.listSessions({ scope,
        shopPersona: browserSession.user, currentSessionId: browserSession.sessionId,
        authorityVersion: browserSession.authorityVersion });
      assert.equal(inventory.length, 1, 'registered bootstrap has one current bound session');
      const exact = cases.selectedCurrentRow(inventory[0], {
        id: browserSession.sessionId, user_agent: inventory[0].user_agent, ip: inventory[0].ip });
      const rowButton = `() => { const rows=[...document.querySelectorAll('tbody tr')].filter(row =>
        row.textContent.includes('(current session)'));
        return rows.length===1 ? [...rows[0].querySelectorAll('button')]
          .find(button=>button.textContent.trim()==='Revoke') : null; }`;
      const dialog = { title: 'Revoke session?',
        consequence: `${exact.userAgent} (${exact.ip}), session ${exact.id}. This is your current session. Revoking it will sign you out of SecureShop.`,
        confirm: 'Confirm revoke' };
      const dialogButton = label => `() => (${exactConsequenceDialogButton.toString()})(${JSON.stringify(dialog.title)},${JSON.stringify(dialog.consequence)},${JSON.stringify(dialog.confirm)},${JSON.stringify(label)})`;
      await clickPhysical(frame, rowButton);
      await frame.waitForFunction(exactConsequenceDialogButton, { timeout: 20000 },
        dialog.title, dialog.consequence, dialog.confirm, 'Cancel');
      assert.equal(posts.length, 0);
      await clickPhysical(frame, dialogButton('Cancel'));
      await frame.waitForFunction(title => ![...document.querySelectorAll('[role="dialog"]')]
        .some(node => node.querySelector('#ss-dialog-title')?.textContent.trim() === title),
      { timeout: 20000 }, dialog.title);
      assert.equal(posts.length, 0);
      const foreignController = new AbortController();
      const foreignDeadline = setTimeout(() => foreignController.abort(), 10000);
      let foreignStatus, foreignReply;
      try { const foreign = await fetch(`${origin}${cases.revokePath(siblingSession.sessionId)}`, {
        method: 'POST', headers: { authorization: browserAuth.authorization,
          'x-dvaia-secureshop-launch': browserAuth.launch }, signal: foreignController.signal });
        foreignStatus = foreign.status; foreignReply = await foreign.json(); }
      finally { clearTimeout(foreignDeadline); }
      assert.equal(foreignStatus, 200);
      assert.deepEqual(foreignReply, { ok: false });
      assert.deepEqual((await siblingRows()).rows, siblingBefore);
      await clickPhysical(frame, rowButton);
      await frame.waitForFunction(exactConsequenceDialogButton, { timeout: 20000 },
        dialog.title, dialog.consequence, dialog.confirm, dialog.confirm);
      assert.equal(posts.length, 0);
      const selectedPath = cases.revokePath(exact.id);
      const confirmed = await cases.capturePhysicalResponse(page,
        response => response.request().method() === 'POST'
          && new URL(response.url()).pathname === selectedPath,
        () => clickPhysical(frame, dialogButton(dialog.confirm)));
      assert.equal(confirmed.status(), 200);
      assert.deepEqual(await confirmed.json(), { ok: true });
      assert.equal(posts.length, 1); assert.equal(posts[0].path, selectedPath);
      assert.equal(posts[0].authorization, browserAuth.authorization);
      assert.equal(posts[0].launch, browserAuth.launch);
      await page.waitForFunction(() => location.pathname === '/secureshop', { timeout: 20000 });
      const oldCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.equal(oldCookie, undefined, 'confirmed self-revoke must sign out the parent');
      const rows = (await agents.query(`SELECT session_id,revoked_at FROM secureshop_agents.bound_persona_sessions
        WHERE platform_launch_id=$1 AND shop_user_id=$2 AND session_id=$3`,
      [scope.launchId, browserSession.user.id, browserSession.sessionId])).rows;
      assert.equal(rows.length, 1);
      assert(rows[0].revoked_at);
      const auditRows = (await agents.query(`SELECT action,source_kind,source_id,shop_user_id,
        launch_id,original_platform_owner_id,original_platform_session_id
        FROM secureshop_agents.bound_audit_events WHERE action='session_revoke' AND source_id=$1`,
      [browserSession.sessionId])).rows;
      assert.equal(auditRows.length, 1);
      assert.equal(auditRows[0].source_kind, 'persona_session');
      assert.equal(auditRows[0].shop_user_id, browserSession.user.id);
      assert.equal(auditRows[0].launch_id, scope.launchId);
      assert.equal(auditRows[0].original_platform_owner_id, scope.platformOwnerId);
      assert.equal(auditRows[0].original_platform_session_id, scope.platformSessionId);
      await assert.rejects(composition.personaAuth.authenticateBoundToken({ scope,
        token: browserAuth.authorization.slice(7) }));
      assert.equal(await auth.authenticate(browserCookie.value), null,
        'actual parent logout must revoke the original standalone cookie');
      assert.equal((await auth.authenticate(buyer.token))?.shopUserId, buyer.user.id,
        'self-revoke must not invalidate the separately registered setup session');
      assert.deepEqual((await siblingRows()).rows, siblingBefore);
      assert([200, 304].includes((await page.goto(
        `${origin}/secureshop/login?next=%2Fsecureshop%2Faccount`)).status()));
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', buyerName);
      await page.type('#ss-login-pw', password);
      await page.click('button[type="submit"]');
      const freshFrame = await cases.admitAccountAfterPhysicalLogin({ page, origin, buyerName,
        buyerId: buyer.user.id, authenticate: token => auth.authenticate(token), findAccountFrame: frameFor });
      await freshFrame.click('#ss-tab-sessions');
      await freshFrame.waitForFunction(initialSessionsReady, { timeout: 20000 });
      assert.equal(requests.length, 2, 'fresh physical sign-in must make one new sessions GET');
      assert.deepEqual(sessionReplies, [200, 200]);
      const freshAuth = requests[1];
      const freshScope = await composition.launches.resolveCapability(freshAuth.launch);
      const freshSession = await composition.personaAuth.authenticateBoundToken({
        scope: freshScope, token: freshAuth.authorization.slice(7) });
      assert.equal(freshSession.user.id, browserSession.user.id);
      assert.notEqual(freshSession.sessionId, browserSession.sessionId);
      assert.equal(posts.length, 1, 'fresh sign-in must not repeat the revoke POST');
      const credit = (await identity.query(`SELECT
        (SELECT count(*)::int FROM workshop_platform.objective_judgments) AS judgments,
        (SELECT count(*)::int FROM workshop_platform.objective_contributions) AS contributions`)).rows[0];
      assert.deepEqual(credit, { judgments: 0, contributions: 0 });
      assert.equal(modelCalls, 0); assert.equal(judgeCalls, 0);
      await admission.verifyBuild(); boundary.assertNoUnexpectedTargets();
      receipt = { version: 2, scope: cases.CURRENT_SCOPE, passed: true,
        physical: { cancelPosts: 0, preConfirmPosts: 0, confirmedPosts: 1,
          foreignDeniedPosts: 1,
          confirmedStatus: confirmed.status(), selectedDialogExact: true },
        state: { originalCurrentRevoked: true, originalTokenDenied: true,
          freshAuthAccepted: true, freshSessionDistinct: true, auditBound: true },
        authority: { capturedBrowserBearer: true, exactCurrentSession: true,
          sameOriginalLaunchOwnerSession: true,
          foreignSessionDenied: true, foreignHttpDenied: true },
        recovery: { operationIdAvailable: false, browserConfirmedReply: true, noSecondPost: true },
        sibling: { preexistingNonempty: true, unchanged: true },
        calls: { model: modelCalls, judge: judgeCalls, credit: credit.judgments + credit.contributions } };
      cases.assertCurrentReceipt(receipt);
      }
      }
    } catch (error) { failure = avatar ? avatarStage.failure(error) : error; }
    finally {
      const errors = [];
      for (const [label, close] of [
        ['browser', () => browser?.close()], ['http', () => server && new Promise((resolve, reject) =>
          server.close(error => error ? reject(error) : resolve()))],
        ['assessment', () => composition?.closeBrowserAssessment()],
        ['avatar-root', () => uploadRoot && fs.rm(uploadRoot, { recursive: true })],
        ['reset-key', () => resetKeyDirectory && fs.rm(resetKeyDirectory, { recursive: true })],
        ['profile', () => admission ? undefined : profile && fs.rm(profile, { recursive: true, force: true })],
        ['lease', () => leasePool.end()],
        ...Object.entries(pools).map(([key, pool]) => [key, () => pool.end()]),
      ]) try { await close(); } catch (error) { errors.push({ label, error }); }
      if (errors.length) failure = new AggregateError([failure, ...errors.map(row => row.error)].filter(Boolean),
        `Q05 session revoke cleanup failed: ${errors.map(row => row.label).join(',')}`);
      if (originalUploadRoot === undefined) delete process.env.SECURESHOP_UPLOAD_ROOT;
      else process.env.SECURESHOP_UPLOAD_ROOT = originalUploadRoot;
    }
    if (failure) throw failure;
    if (avatar) assertAvatarReceipt(receipt);
    else if (other) cases.assertReceipt(receipt);
    else cases.assertCurrentReceipt(receipt);
    await fs.writeFile(receiptPath, JSON.stringify(receipt) + '\n', { flag: 'wx', mode: 0o600 });
}

if (process.env.SECURESHOP_ACCOUNT_AVATAR_NATIVE === '1') {
  test('Account avatar physically writes and recovers an owned consequence',
    { skip: !AVATAR_ENABLED, timeout: 300000 }, () => runRenderedCase(true));
} else if (process.env.SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_NATIVE === '1') {
  test('registered shopper physically revokes OTHER owned session with GET-only recovery',
    { skip: !OTHER_ENABLED, timeout: 150000 }, () => runRenderedCase(false, true));
} else {
  test('registered shopper physically confirms current-session revoke and signs in afresh',
    { skip: !ENABLED, timeout: 150000 }, () => runRenderedCase(false));
}
