'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const express = require('express');
const { createHash } = require('node:crypto');
const avatar = require('./postgres/secureshopStandaloneAccountSessionRevokeRendered.integration.test');

const requestId = '123e4567-e89b-42d3-a456-426614174000';
const otherId = '123e4567-e89b-42d3-a456-426614174001';

test('avatar stage trace retains only closed entered/completed labels and original cause', async () => {
  const trace = avatar.createAvatarStageTrace();
  const original = Error('synthetic controlled failure');
  trace.enter('browser-page');
  assert.equal(trace.failure(original).message,
    'Owned Account avatar boundary entered=browser-page completed=none cause={"name":"Error","code":null,"fixture":null}');
  assert.equal(trace.failure(original).cause, original);
  trace.complete('browser-page');
  trace.enter('initial-goto');
  const diagnostic = trace.failure(original);
  assert.equal(diagnostic.message,
    'Owned Account avatar boundary entered=initial-goto completed=browser-page cause={"name":"Error","code":null,"fixture":null}');
  assert.equal(diagnostic.cause, original);
  assert.throws(() => trace.enter('Bearer secret'), /closed avatar stage required/);
  assert.throws(() => trace.complete('browser-ack'), /only the entered avatar stage can complete/);
});

test('avatar post-receipt stages and cause projection remain closed and secret-free', () => {
  const trace = avatar.createAvatarStageTrace();
  const stages = ['avatar-transport-assertions', 'first-effect-readback', 'first-authority',
    'sibling-scene', 'sibling-upload', 'sibling-private-get', 'current-before-reset-get',
    'reset-commit', 'stale-after-reset-get', 'reset-cleanup', 'role-signout-click',
    'role-signout-route', 'merchant-revoked-get', 'role-effect-readback',
    'merchant-current-get', 'role-results', 'traversal-effect', 'fixed-mode-read',
    'fixed-mode-set', 'fixed-signout-click', 'fixed-signout-route',
    'fixed-files-baseline', 'fixed-traversal-absence', 'fixed-extension-absence',
    'final-inventory', 'final-build', 'final-browser-targets', 'final-credit'];
  for (const stage of stages) { trace.enter(stage); trace.complete(stage); }
  const original = Error('secret-message-Bearer-private');
  original.name = 'SecretName123'; original.code = 'SECRET_CODE_123';
  original.stack = `Error: secret-stack\n at owned (${require.resolve('./postgres/secureshopStandaloneAccountSessionRevokeRendered.integration.test')}:512:16)\n at other (/private/token:4:2)`;
  const wrapped = trace.failure(original);
  assert.equal(wrapped.cause, original);
  assert.equal(wrapped.message,
    'Owned Account avatar boundary entered=final-credit completed=final-credit cause={"name":"Error","code":null,"fixture":{"line":512,"column":16}}');
  assert.doesNotMatch(wrapped.message, /secret|Bearer|private|token/i);
  let assertion;
  try { assert.equal(1, 2); } catch (error) { assertion = error; }
  assert.deepEqual(avatar.avatarSafeCause(assertion),
    { name: 'AssertionError', code: 'ERR_ASSERTION', fixture: null });
  const forged = Error('secret');
  forged.stack = `secret ${require.resolve('./postgres/secureshopStandaloneAccountSessionRevokeRendered.integration.test')}:777:3\n at other (/private/token:4:2)`;
  assert.equal(avatar.avatarSafeCause(forged).fixture, null);
  let invoked = 0;
  const accessors = {};
  for (const key of ['name', 'code', 'stack']) Object.defineProperty(accessors, key,
    { get() { invoked += 1; throw Error('secret getter'); } });
  assert.deepEqual(avatar.avatarSafeCause(accessors), { name: 'Error', code: null, fixture: null });
  assert.equal(invoked, 0);
  assert.throws(() => trace.enter('unapproved-secret-stage'), /closed avatar stage required/);
});

test('physical avatar sign-out opens the actual Account menu before seeking Sign out', async () => {
  let expanded = false;
  const calls = [];
  const frame = {
    async $eval(selector) {
      calls.push('read-menu');
      assert.equal(selector, 'button[aria-label="Account menu"]');
      return expanded;
    },
    async waitForFunction(predicate, options) {
      calls.push('wait-signout');
      assert.equal(options.timeout, 20000);
      assert.match(String(predicate), /aria-expanded/);
      assert.match(String(predicate), /Sign out/);
      assert.equal(expanded, true, 'Sign out cannot be awaited before physical menu click');
    },
  };
  const click = async (target, lookup) => {
    calls.push('click-menu');
    assert.equal(target, frame);
    assert.match(lookup, /Account menu/);
    expanded = true;
  };
  await avatar.openAvatarAccountMenu(frame, click);
  assert.deepEqual(calls, ['read-menu', 'click-menu', 'wait-signout']);
  calls.length = 0;
  await avatar.openAvatarAccountMenu(frame, click);
  assert.deepEqual(calls, ['read-menu', 'wait-signout'], 'already-open menu is not toggled shut');
});

test('sibling avatar obtains an exact retained scene grant through supported target preparation', async () => {
  const scope = { launchId: requestId }, persona = { id: 43, role: 'customer' };
  const session = { sessionId: otherId, authorityVersion: 2 };
  const target = { targetId: otherId, scene: { sceneId: requestId,
    sceneGeneration: 1, grantId: '123e4567-e89b-42d3-a456-426614174002' } };
  const calls = [];
  const composition = { catalog: { async prepareTarget(input) {
    calls.push('prepare');
    assert.deepEqual(input, { scope, persona, personaSession: session });
    return target;
  } }, scenes: { async readRetained(input) {
    calls.push('retained'); assert.equal(input, scope); return target;
  } } };
  assert.equal(await avatar.prepareAvatarSiblingScene(composition, scope, persona, session), target);
  assert.deepEqual(calls, ['prepare', 'retained']);
  composition.scenes.readRetained = async () => ({ ...target,
    scene: { ...target.scene, grantId: otherId } });
  await assert.rejects(avatar.prepareAvatarSiblingScene(composition, scope, persona, session),
    /Expected values to be strictly equal/);
});

test('avatar sibling peer tenant uses migration-role membership, not a fabricated scene grant', async () => {
  const queries = [];
  let released = false;
  const merchant = { principal_id: requestId, shop_user_id: 17 };
  const sibling = { principalId: otherId, shopUserId: 31 };
  const migration = { async connect() { return {
    async query(sql, args) {
      queries.push({ sql: sql.trim().replace(/\s+/g, ' '), args });
      if (sql.includes('FROM secureshop_auth.principals')) return { rows: [merchant] };
      if (sql.includes('UPDATE secureshop_auth.tenants')) return { rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }, release() { released = true; },
  }; } };
  const result = await avatar.provisionAvatarPeerTenant(migration, sibling, 'avatar_peer_test');
  assert.match(result.tenantId, /^[a-f0-9-]{36}$/);
  assert.equal(result.tenantSlug, 'avatar_peer_test');
  assert.deepEqual(queries.map(row => row.sql.split(' ')[0]),
    ['BEGIN', 'INSERT', 'SELECT', 'INSERT', 'INSERT', 'UPDATE', 'COMMIT']);
  assert.deepEqual(queries[3].args, [result.tenantId, sibling.principalId,
    sibling.shopUserId, 'customer']);
  assert.deepEqual(queries[4].args, [result.tenantId, merchant.principal_id,
    merchant.shop_user_id, 'merchant']);
  assert.deepEqual(queries[5].args, [result.tenantId, merchant.shop_user_id]);
  assert.equal(queries.some(row => /scene|grant/i.test(row.sql)), false);
  assert.equal(released, true);
});

test('reset cleanup receipt compares raw PostgreSQL bigint text to the exact admitted generation', () => {
  avatar.assertAvatarCleanupGeneration('1', 1);
  assert.throws(() => avatar.assertAvatarCleanupGeneration(1, 1));
  assert.throws(() => avatar.assertAvatarCleanupGeneration('01', 1));
  assert.throws(() => avatar.assertAvatarCleanupGeneration('2', 1));
});

async function committedLossServer() {
  const app = express();
  const records = [];
  app.use('/api/secureshop/uploads/avatar', (request, response, next) => {
    avatar.loseAvatarAckAfterCommit(request, response, record => records.push(record));
    next();
  });
  app.post('/api/secureshop/uploads/avatar', (_request, response) => response.status(200)
    .json({ kind: 'avatar', status: 'completed', requestId }));
  app.get('/', (_request, response) => response.type('html').send('<!doctype html><title>Owned avatar loss</title>'));
  const server = await new Promise(resolve => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  return { origin: `http://127.0.0.1:${server.address().port}`, records,
    async close() { server.closeAllConnections();
      await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); } };
}

test('real completed avatar reply is truncated after declared HTTP 200 and cannot be read as an ACK',
  { timeout: 15000 }, async () => {
    const owner = await committedLossServer();
    try {
      const response = await fetch(`${owner.origin}/api/secureshop/uploads/avatar`,
        { method: 'POST', body: 'owned avatar', signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, 200);
      await assert.rejects(response.text(), /terminated|fetch failed|aborted/i);
      assert.equal(owner.records.length, 1);
      assert.equal(owner.records[0].requestId, requestId);
      assert.match(owner.records[0].responseSha256, /^[a-f0-9]{64}$/);
    } finally { await owner.close(); }
  });

test('actual browser observes one selected failed POST after the committed truncated avatar reply',
  { timeout: 45000 }, async t => {
    if (process.env.SS_AVATAR_BROWSER_CONTROL !== '1') {
      t.skip('explicit bounded localhost Chrome control opt-in required'); return;
    }
    const chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
    if (process.platform !== 'darwin' || !(await fs.stat(chrome).catch(() => null))) {
      t.skip('Darwin Chrome required for the bounded localhost browser control'); return;
    }
    const owner = await committedLossServer();
    const tempParent = path.resolve(__dirname, '../tasks/tmp');
    await fs.mkdir(tempParent, { recursive: true });
    const profile = await fs.mkdtemp(path.join(tempParent, 'owasp-ai-goat-avatar-ack-control-'));
    const browserTmp = path.join(profile, 'tmp');
    await fs.mkdir(browserTmp, { mode: 0o700 });
    await fs.mkdir(path.join(profile, 'cache'), { mode: 0o700 });
    await fs.mkdir(path.join(profile, 'config'), { mode: 0o700 });
    let browser;
    try {
      browser = await require('puppeteer').launch({ headless: true, executablePath: chrome,
        userDataDir: profile, timeout: 15000, protocolTimeout: 15000,
        env: { ...process.env, TMPDIR: browserTmp, MAC_CHROMIUM_TMPDIR: browserTmp,
          XDG_CACHE_HOME: path.join(profile, 'cache'),
          XDG_CONFIG_HOME: path.join(profile, 'config') },
        args: ['--no-sandbox', '--disable-background-networking', '--disable-component-update',
          '--disable-domain-reliability', '--disable-quic',
          '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
          '--proxy-server=http://blocked.invalid:9',
          '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
          '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]'] });
      const page = await browser.newPage();
      const requests = [], failed = [], finished = [], statuses = [];
      const selected = request => request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/secureshop/uploads/avatar';
      page.on('request', request => { if (selected(request)) requests.push(request); });
      page.on('requestfailed', request => { if (selected(request)) failed.push(request); });
      page.on('requestfinished', request => { if (selected(request)) finished.push(request); });
      page.on('response', response => {
        if (selected(response.request())) statuses.push(response.status());
      });
      await page.goto(owner.origin, { timeout: 10000 });
      const outcome = await page.evaluate(async url => {
        try { const response = await fetch(url, { method: 'POST', body: 'owned avatar' });
          await response.text(); return 'completed'; }
        catch { return 'failed'; }
      }, `${owner.origin}/api/secureshop/uploads/avatar`);
      assert.equal(outcome, 'failed');
      await avatar.waitForAvatarCaptured(() => failed.length === 1, 'browser failed POST', 5000);
      assert.equal(requests.length, 1);
      assert.equal(failed[0], requests[0], 'the exact selected request failed');
      assert.equal(finished.length, 0);
      assert.deepEqual(statuses, [200]);
      assert.equal(owner.records.length, 1);
      await page.setContent('<div class="ss-uploadzone"><input type="text" '
        + 'value="avatar-input-6a6a41owned-avatar.html4-6163-4418-9847.html"></div>');
      await avatar.enterAvatarFilename(page, page, 'owned-avatar.html');
      assert.equal(await page.$eval('.ss-uploadzone input[type="text"]', node => node.value),
        'owned-avatar.html', 'real Chrome selected the entire generated filename');
    } finally {
      const cleanupErrors = [];
      let browserRetired = browser === undefined;
      try { if (browser) { await browser.close(); browserRetired = true; } }
      catch (error) { cleanupErrors.push(error); }
      try { await owner.close(); } catch (error) { cleanupErrors.push(error); }
      // A failed Chrome close is debt, not permission to erase its live profile.
      if (browserRetired) {
        try { await fs.rm(profile, { recursive: true }); }
        catch (error) { cleanupErrors.push(error); }
      }
      if (cleanupErrors.length) throw new AggregateError(cleanupErrors,
        'Owned avatar browser control cleanup incomplete');
    }
  });

test('physical Account filename entry rejects an inexact readback before upload', async () => {
  const actions = [];
  const input = { async click() { actions.push('click'); },
    async evaluate() { return 'avatar-input-owned-avatar.html'; },
    async dispose() { actions.push('dispose'); } };
  const frame = { async $(selector) {
    assert.equal(selector, '.ss-uploadzone input[type="text"]'); return input;
  } };
  const page = { keyboard: { async down(value) { actions.push(`down:${value}`); },
    async press(value) { actions.push(`press:${value}`); },
    async up(value) { actions.push(`up:${value}`); },
    async type(value) { actions.push(`type:${value}`); } } };
  await assert.rejects(avatar.enterAvatarFilename(page, frame, 'owned-avatar.html'),
    /physical Account filename selection must be exact/);
  assert.deepEqual(actions, ['click', 'press:Home', 'down:Shift', 'press:End',
    'up:Shift', 'press:Backspace', 'type:owned-avatar.html', 'dispose']);
});

test('new physical request capture waits through delayed POST, never accepts a prior count', async () => {
  const posts = [{ path: '/api/secureshop/uploads/avatar' }];
  const pending = avatar.waitForAvatarCaptured(() => posts.length === 2 && posts[1], 'new POST', 500);
  setTimeout(() => posts.push({ path: '/api/secureshop/uploads/avatar', requestId }), 35);
  assert.equal((await pending).requestId, requestId);
  await assert.rejects(avatar.waitForAvatarCaptured(() => posts.length === 3,
    'new POST', 50), /new POST unavailable/);
});

test('committed ACK loss requires the exact browser request failure before recovery', async () => {
  const selected = {}, unrelated = {};
  const failures = [{ request: unrelated }];
  const observed = avatar.waitForAvatarCaptured(() => failures.find(row =>
    row.request === selected), 'browser-observed lost POST reply', 500);
  setTimeout(() => failures.push({ request: selected }), 35);
  assert.equal((await observed).request, selected);
  await assert.rejects(avatar.waitForAvatarCaptured(() => failures.find(row =>
    row.request === {}), 'browser-observed lost POST reply', 50));
});

test('installed file chooser waiter is armed before click and aborts on failed click', async () => {
  assert.equal(typeof require('puppeteer-core').CdpPage.prototype.waitForFileChooser, 'function');
  const filePath = '/owned/repository/avatar.svg';
  const sequence = [];
  const page = { waitForFileChooser({ timeout, signal }) {
    assert.equal(timeout, 20000);
    sequence.push('armed');
    return new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => { sequence.push('aborted'); reject(signal.reason); },
        { once: true });
      page.resolveChooser = resolve;
    });
  } };
  await assert.rejects(avatar.chooseAvatarFile(page, {}, filePath, async () => {
    sequence.push('click'); throw Error('physical click failed');
  }), /physical click failed/);
  assert.deepEqual(sequence, ['armed', 'click', 'aborted']);
  sequence.length = 0;
  await avatar.chooseAvatarFile(page, {}, filePath, async () => {
    sequence.push('click');
    page.resolveChooser({ accept: async paths => { sequence.push('accepted');
      assert.deepEqual(paths, [filePath]); } });
  });
  assert.deepEqual(sequence, ['armed', 'click', 'accepted']);
});

test('UI receipt rejects stale completed pre and only accepts the exact new requestId', async () => {
  const prior = { requestId: otherId, status: 'completed' };
  const current = { requestId, status: 'completed' };
  const original = global.document;
  let rendered = prior;
  global.document = { querySelector: () => ({ textContent: JSON.stringify(rendered) }) };
  try {
    const frame = {
      async waitForFunction(predicate, options, expected) {
        assert.equal(options.timeout, 20000);
        assert.equal(predicate(expected), false, 'stale pre is not the selected operation');
        rendered = current;
        assert.equal(predicate(expected), true);
      },
      async $eval(selector, parse) {
        assert.equal(selector, '.ss-uploadzone pre');
        return parse({ textContent: JSON.stringify(rendered) });
      },
    };
    assert.deepEqual(await avatar.waitForAvatarUiReceipt(frame, requestId), current);
    rendered = prior;
    const forged = { ...frame, waitForFunction: async () => {} };
    await assert.rejects(avatar.waitForAvatarUiReceipt(forged, requestId));
  } finally { global.document = original; }
});

test('role-aware physical-cookie admission accepts only the exact authenticated role and buyer', async () => {
  const page = { waitForFunction: async (_, options) => assert.equal(options.timeout, 20000),
    cookies: async () => [{ name: 'owasp_ai_goat_shop_session', value: 'private', httpOnly: true }] };
  const auth = { authenticate: async token => {
    assert.equal(token, 'private');
    return { shopUserId: 41, username: 'avatar_merchant', role: 'merchant' };
  } };
  const input = { page, origin: 'http://127.0.0.1:39117', expected: { user: { id: 41 } },
    role: 'merchant', username: 'avatar_merchant', auth };
  assert.equal((await avatar.admitAvatarRoleLogin(input)).role, 'merchant');
  await assert.rejects(avatar.admitAvatarRoleLogin({ ...input, role: 'customer' }));
  await assert.rejects(avatar.admitAvatarRoleLogin({ ...input, expected: { user: { id: 42 } } }));
  await assert.rejects(avatar.admitAvatarRoleLogin({ ...input, page: { ...page,
    cookies: async () => [{ name: 'owasp_ai_goat_shop_session', value: 'private', httpOnly: false }] } }));
});

test('avatar receipt is closed on required observed flags and zero model/Judge/credit', () => {
  const valid = { version: 1, scope: 'Q05 Account avatar direct rendered action', passed: true,
    roles: ['customer', 'merchant', 'admin'],
    physical: { onePostPerSelectedUpload: true, accountBridgeReadback: true },
    vulnerable: { mimeAndFilenameHonored: true, traversalConfined: true },
    fixed: { extensionDeniedBeforeWrite: true, traversalDeniedBeforeWrite: true },
    recovery: { committedAckLost: true, getOnlyAfterRemount: true },
    authority: { sessionFenced: true, resetFenced: true, siblingUnchanged: true },
    calls: { model: 0, judge: 0, credit: 0 } };
  avatar.assertAvatarReceipt(valid);
  assert.throws(() => avatar.assertAvatarReceipt({ ...valid,
    calls: { ...valid.calls, model: 1 } }));
  assert.throws(() => avatar.assertAvatarReceipt({ ...valid,
    fixed: { ...valid.fixed, traversalDeniedBeforeWrite: false } }));
});

test('recovery diagnostics return only bounded counts, statuses, and safe UI categories', () => {
  const request = { authorization: 'private-bearer', body: 'private-body' };
  const previous = { request: {}, status: 418 };
  const value = avatar.avatarRecoveryFailureDiagnostic({
    avatarGets: [{ path: '/private/operation' }],
    avatarGetAttempts: [previous, { request, path: '/private/operation' }],
    avatarGetResponses: [previous, { request, status: 409, body: 'private-body' }],
    avatarGetFailures: [previous], avatarPosts: [previous, { request }],
    avatarPostFailures: [previous, { request }], avatarPostFinishes: [previous],
    avatarPostResponses: [previous, { request, status: 200, authorization: 'private-bearer' }],
    beforeGet: 0, beforeGetAttempts: 1, beforeGetResponses: 1,
    beforeGetFailures: 1, beforePost: 1, selected: { request },
    storage: { pendingReferencePresent: true, ownerMatches: true,
      snapshotFingerprintMatches: null,
      matchingSnapshots: 1, storageAvailable: true },
    ui: { pendingShown: true, checkButtonPresent: true,
      checkButtonDisabled: false, errorCategory: 'session-mismatch' },
  });
  assert.deepEqual(value, { exactGets: 1, operationAttempts: 1, operationStatuses: [409],
    operationFailures: 0, postAttempts: 1, selectedPostStatuses: [200],
    selectedPostFailures: 1, selectedPostFinishes: 0,
    storage: { pendingReferencePresent: true, ownerMatches: true,
      snapshotFingerprintMatches: null,
      matchingSnapshots: 1, storageAvailable: true },
    ui: { pendingShown: true, checkButtonPresent: true,
      checkButtonDisabled: false, errorCategory: 'session-mismatch' } });
  assert.doesNotMatch(JSON.stringify(value), /private-bearer|private-body|private\/operation/);
});

test('saved-reference and UI probes disclose booleans and closed categories, never stored values', async () => {
  const originalStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  const originalDocument = Object.getOwnPropertyDescriptor(globalThis, 'document');
  const secret = 'private-avatar-bearer';
  const fingerprint = createHash('sha256').update(secret).digest('hex');
  const raw = JSON.stringify({ secureshop_v2_token: null,
    'secureshop.account-avatar.pending.v1': JSON.stringify({ requestId,
      ownerId: '17', sessionFingerprint: fingerprint }) });
  const storage = { length: 2, key: index => index ? 'other' : 'owasp-ai-goat:secureshop:test:1',
    getItem: key => key === 'owasp-ai-goat:secureshop:test:1' ? raw : 'private-other' };
  const status = { textContent: 'A saved avatar upload has an unresolved outcome.',
    querySelector: () => ({ disabled: false }) };
  const zone = { querySelectorAll: selector => selector === '[role="status"]' ? [status]
    : [{ textContent: 'Saved avatar belongs to a different Account session. private-token' }] };
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: storage });
  Object.defineProperty(globalThis, 'document', { configurable: true,
    value: { querySelector: () => zone } });
  try {
    assert.deepEqual(await avatar.avatarRecoveryStorageFacts(requestId, 17), {
      pendingReferencePresent: true, ownerMatches: true,
      snapshotFingerprintMatches: null,
      matchingSnapshots: 1, storageAvailable: true });
    assert.deepEqual(await avatar.avatarRecoveryStorageFacts(requestId, 18), {
      pendingReferencePresent: true, ownerMatches: false,
      snapshotFingerprintMatches: null,
      matchingSnapshots: 1, storageAvailable: true });
    assert.deepEqual(await avatar.avatarRecoveryStorageFacts(otherId, 17), {
      pendingReferencePresent: false, ownerMatches: null, snapshotFingerprintMatches: null,
      matchingSnapshots: 0, storageAvailable: true });
    assert.deepEqual(avatar.avatarRecoveryUiFacts(), { pendingShown: true,
      checkButtonPresent: true, checkButtonDisabled: false,
      errorCategory: 'session-mismatch' });
    assert.doesNotMatch(JSON.stringify(avatar.avatarRecoveryUiFacts()), /private-token/);
  } finally {
    if (originalStorage) Object.defineProperty(globalThis, 'localStorage', originalStorage);
    else delete globalThis.localStorage;
    if (originalDocument) Object.defineProperty(globalThis, 'document', originalDocument);
    else delete globalThis.document;
  }
});
