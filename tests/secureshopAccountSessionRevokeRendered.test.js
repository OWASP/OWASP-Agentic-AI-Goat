'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createHash } = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs/promises');
const express = require('express');
const cases = require('./fixtures/secureshopAccountSessionRevokeRenderedCases');
const { serveOpaqueFrameAssets, initialSessionsReady } =
  require('./postgres/secureshopStandaloneAccountSessionRevokeRendered.integration.test');
const { mountedReadiness, standaloneReadiness } = require('../server/routes/secureshopRuntimeReadiness');

const id = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const complete = () => ({ version: 1, scope: cases.SCOPE, passed: true,
  physical: { cancelPosts: 0, preConfirmPosts: 0, confirmedPosts: 1, foreignDeniedPosts: 1,
    confirmedStatus: 200, selectedDialogExact: true, browserAckLost: true,
    serverReplySha256: 'a'.repeat(64) },
  state: { twoSameLaunchSessions: true, selectedRevoked: true, currentRetained: true,
    selectedTokenDenied: true, currentTokenAccepted: true, auditBound: true },
  authority: { capturedBrowserBearer: true, sameLaunchOwnerSession: true,
    foreignSessionDenied: true, foreignHttpDenied: true },
  recovery: { operationIdAvailable: false, explicitSessionsGet: true, noSecondPost: true },
  sibling: { preexistingNonempty: true, unchanged: true },
  calls: { model: 0, judge: 0, credit: 0 } });
const currentComplete = () => ({ version: 2, scope: cases.CURRENT_SCOPE, passed: true,
  physical: { cancelPosts: 0, preConfirmPosts: 0, confirmedPosts: 1,
    foreignDeniedPosts: 1, confirmedStatus: 200, selectedDialogExact: true },
  state: { originalCurrentRevoked: true, originalTokenDenied: true,
    freshAuthAccepted: true, freshSessionDistinct: true, auditBound: true },
  authority: { capturedBrowserBearer: true, exactCurrentSession: true,
    sameOriginalLaunchOwnerSession: true, foreignSessionDenied: true, foreignHttpDenied: true },
  recovery: { operationIdAvailable: false, browserConfirmedReply: true, noSecondPost: true },
  sibling: { preexistingNonempty: true, unchanged: true },
  calls: { model: 0, judge: 0, credit: 0 } });

async function withStaticServer(build, cors, exercise) {
  const app = express();
  app.get('/api/secureshop/auth/session', (_request, response) => response.json({ unavailable: true }));
  app.use(cors ? serveOpaqueFrameAssets(build) : express.static(build));
  const server = await new Promise(resolve => {
    const opened = app.listen(0, '127.0.0.1', () => resolve(opened));
  });
  try {
    await exercise(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

test('public module middleware fixes the missing opaque-origin header without changing API headers', async () => {
  const workspace = path.resolve(__dirname, '..');
  const tempRoot = path.join(workspace, 'tasks/tmp');
  await fs.mkdir(tempRoot, { recursive: true });
  const assets = await fs.mkdtemp(path.join(tempRoot, 'q05-opaque-assets-'));
  try {
    await fs.mkdir(path.join(assets, 'assets'));
    await fs.writeFile(path.join(assets, 'secureshop-frame.html'),
      '<script type="module" crossorigin src="/assets/fixture.js"></script>');
    await fs.writeFile(path.join(assets, 'assets/fixture.js'), 'export const fixture = true;');
    await withStaticServer(assets, false, async origin => {
      const prior = await fetch(`${origin}/assets/fixture.js`, {
        headers: { Origin: 'null' }, signal: AbortSignal.timeout(5000),
      });
      assert.equal(prior.status, 200);
      assert.equal(prior.headers.get('access-control-allow-origin'), null);
      await prior.arrayBuffer();
    });
    await withStaticServer(assets, true, async origin => {
      for (const asset of ['/secureshop-frame.html', '/assets/fixture.js']) {
        for (const method of ['GET', 'HEAD']) {
          const response = await fetch(`${origin}${asset}`, { method,
            headers: { Origin: 'null' }, signal: AbortSignal.timeout(5000) });
          assert.equal(response.status, 200);
          assert.equal(response.headers.get('access-control-allow-origin'), '*');
          await response.arrayBuffer();
        }
      }
      const api = await fetch(`${origin}/api/secureshop/auth/session`, {
        headers: { Origin: 'null' }, signal: AbortSignal.timeout(5000),
      });
      assert.equal(api.status, 200);
      assert.equal(api.headers.get('access-control-allow-origin'), null);
      await api.arrayBuffer();
    });
  } finally { await fs.rm(assets, { recursive: true }); }
});

test('current built frame and its actual module receive the opaque-origin header when build is present', async t => {
  const build = path.resolve(__dirname, '../client/build');
  try { await fs.lstat(build); }
  catch (error) { if (error.code === 'ENOENT') { t.skip('frontend build not present in this checkout'); return; }
    throw error; }
  const frameInfo = await fs.lstat(path.join(build, 'secureshop-frame.html'));
  assert(frameInfo.isFile() && !frameInfo.isSymbolicLink(), 'present built frame must be a regular file');
  await withStaticServer(build, true, async origin => {
    const frame = await fetch(`${origin}/secureshop-frame.html`, {
      headers: { Origin: 'null' }, signal: AbortSignal.timeout(5000),
    });
    assert.equal(frame.status, 200);
    assert.equal(frame.headers.get('access-control-allow-origin'), '*');
    const html = await frame.text();
    const asset = /<script type="module" crossorigin src="(\/assets\/[^"\s]+\.js)"/.exec(html)?.[1];
    assert.match(asset, /^\/assets\/[^/]+\.js$/);
    for (const method of ['GET', 'HEAD']) {
      const moduleResponse = await fetch(`${origin}${asset}`, { method,
        headers: { Origin: 'null' }, signal: AbortSignal.timeout(5000) });
      assert.equal(moduleResponse.status, 200);
      assert.equal(moduleResponse.headers.get('access-control-allow-origin'), '*');
      await moduleResponse.arrayBuffer();
    }
  });
});

test('enabled Refresh is not initial readiness until the one current-session row has rendered', () => {
  const prior = global.document;
  let rows = [];
  global.document = { querySelectorAll(selector) {
    if (selector === 'h3') return [{ textContent: 'Active sessions' }];
    if (selector === 'tbody tr') return rows;
    if (selector === 'button') return [{ textContent: 'Refresh', disabled: false }];
    throw Error('Unexpected selector in controlled readiness');
  } };
  try {
    assert.equal(global.document.querySelectorAll('button')[0].disabled, false);
    assert.equal(initialSessionsReady(), false, 'button is enabled before the GET readback');
    rows = [{ textContent: 'Other browser' }];
    assert.equal(initialSessionsReady(), false, 'a noncurrent row cannot establish current authority');
    rows = [{ textContent: 'Owned browser (current session)' }];
    assert.equal(initialSessionsReady(), true);
    rows.push({ textContent: 'Other browser' });
    assert.equal(initialSessionsReady(), false, 'initial readback must precede second-session creation');
  } finally { global.document = prior; }
});

test('actual standalone readiness admits its real core shape, not incomplete full panels', () => {
  const methods = names => Object.fromEntries(names.map(name => [name, () => {}]));
  const composition = {
    standaloneAuth: {
      service: methods(['authenticate', 'register', 'login', 'renew', 'logout',
        'changePassword', 'establishTenantContext']), bootstrap() {},
      reset: methods(['readiness', 'reset', 'readRecovery', 'recover']),
      registeredAdminReset: methods(['preview', 'reset', 'read', 'reveal', 'acknowledge']),
      mode: methods(['get', 'set']), assessmentObjectives: methods(['list', 'set']),
      assessmentRecovery: methods(['list', 'retry']), cartImport() {},
    },
    publicCatalog: methods(['browse', 'product', 'related', 'categories', 'reviews']),
    catalog: methods(['listProducts', 'getProduct', 'listMerchantProducts', 'categories',
      'createMerchantProduct', 'updateMerchantProduct', 'archiveMerchantProduct']),
    commerce: methods(['cart', 'add', 'update', 'remove', 'summary', 'checkout', 'orders', 'order']),
    account: methods(['profile', 'updateProfile', 'addresses', 'createAddress', 'updateAddress', 'deleteAddress']),
    admin: methods(['users', 'kpis']), personaAuth: { authenticatePersona() {} },
    router() {}, browserRouter() {},
  };
  const ready = standaloneReadiness(composition);
  assert.equal(ready.ready, true);
  assert(Object.values(ready.checks).every(value => value === true));
  assert.throws(() => mountedReadiness(composition), /panel readiness incomplete/);
  for (const missing of [
    { ...composition, standaloneAuth: { ...composition.standaloneAuth, registeredAdminReset: undefined } },
    { ...composition, standaloneAuth: { ...composition.standaloneAuth, reset: undefined } },
    { ...composition, standaloneAuth: { ...composition.standaloneAuth, cartImport: undefined } },
    { ...composition, publicCatalog: undefined },
  ]) assert.throws(() => standaloneReadiness(missing), /core readiness incomplete/);
});

test('closed receipt requires physical one-POST and durable no-credit consequences', () => {
  assert.equal(cases.assertReceipt(complete()), true);
  for (const [part, key, value] of [
    ['physical', 'cancelPosts', 1], ['physical', 'confirmedPosts', 2],
    ['physical', 'foreignDeniedPosts', 0],
    ['physical', 'confirmedStatus', 202], ['physical', 'browserAckLost', false],
    ['physical', 'serverReplySha256', 'bad'], ['state', 'selectedRevoked', false],
    ['state', 'currentRetained', false], ['state', 'auditBound', false],
    ['authority', 'sameLaunchOwnerSession', false],
    ['authority', 'foreignHttpDenied', false],
    ['recovery', 'operationIdAvailable', true], ['recovery', 'noSecondPost', false],
    ['sibling', 'unchanged', false], ['calls', 'model', 1], ['calls', 'credit', 1],
  ]) {
    const wrong = complete(); wrong[part][key] = value;
    assert.throws(() => cases.assertReceipt(wrong), `${part}.${key}`);
  }
  const extra = complete(); extra.unproved = true;
  assert.throws(() => cases.assertReceipt(extra));
});

test('registered current-session receipt is separate from the unqualified other-session receipt', () => {
  assert.equal(cases.assertReceipt(complete()), true);
  assert.equal(cases.assertCurrentReceipt(currentComplete()), true);
  assert.throws(() => cases.assertReceipt(currentComplete()));
  assert.throws(() => cases.assertCurrentReceipt(complete()));
  for (const [part, key, value] of [
    ['physical', 'cancelPosts', 1], ['physical', 'preConfirmPosts', 1],
    ['physical', 'confirmedPosts', 2], ['physical', 'foreignDeniedPosts', 0],
    ['physical', 'confirmedStatus', 202], ['state', 'originalCurrentRevoked', false],
    ['state', 'originalTokenDenied', false], ['state', 'freshAuthAccepted', false],
    ['state', 'freshSessionDistinct', false], ['authority', 'exactCurrentSession', false],
    ['authority', 'foreignHttpDenied', false], ['recovery', 'browserConfirmedReply', false],
    ['recovery', 'noSecondPost', false], ['sibling', 'unchanged', false],
    ['calls', 'model', 1], ['calls', 'judge', 1], ['calls', 'credit', 1],
  ]) {
    const wrong = currentComplete(); wrong[part][key] = value;
    assert.throws(() => cases.assertCurrentReceipt(wrong), `${part}.${key}`);
  }
  const extra = currentComplete(); extra.unproved = true;
  assert.throws(() => cases.assertCurrentReceipt(extra));
});

test('selected physical row is exact, noncurrent, and a UUID', () => {
  const selected = { id, user_agent: 'Other owned session', ip: '127.0.0.1', is_current: false };
  assert.deepEqual(cases.selectedRow(selected, selected),
    { id, userAgent: selected.user_agent, ip: selected.ip });
  assert.throws(() => cases.selectedRow({ ...selected, is_current: true }, selected));
  assert.throws(() => cases.selectedRow(selected, { ...selected, id: 'other' }));
  assert.throws(() => cases.selectedRow({ ...selected, id: 'not-uuid' }, { ...selected, id: 'not-uuid' }));
  assert.equal(cases.revokePath(id), `/api/secureshop/v2/auth/users/me/sessions/${id}/revoke`);
  assert.throws(() => cases.revokePath('../foreign'));
});

test('current physical row binds the authenticated session and exact consequence metadata', () => {
  const selected = { id, user_agent: null, ip: null, is_current: true };
  assert.deepEqual(cases.selectedCurrentRow(selected, selected),
    { id, userAgent: 'Unknown browser', ip: 'unknown IP' });
  assert.throws(() => cases.selectedCurrentRow({ ...selected, is_current: false }, selected));
  assert.throws(() => cases.selectedCurrentRow(selected, { ...selected, id: 'other' }));
  assert.throws(() => cases.selectedCurrentRow(selected, { ...selected, ip: '127.0.0.1' }));
  assert.throws(() => cases.selectedCurrentRow({ ...selected, id: 'bad' }, { ...selected, id: 'bad' }));
});

function responseHarness() {
  let resolve, reject, signal;
  let cancelled = 0;
  const page = { waitForResponse(predicate, options) {
    assert.equal(typeof predicate, 'function');
    assert.equal(options.timeout, 20000);
    signal = options.signal;
    return new Promise((yes, no) => {
      resolve = yes; reject = no;
      signal.addEventListener('abort', () => { cancelled++; no(Error('waiter aborted')); }, { once: true });
    });
  } };
  return { page, resolve: value => resolve(value), reject: error => reject(error),
    state: () => ({ cancelled, aborted: signal?.aborted }) };
}

test('physical response waiter observes timeout while click remains pending, then retires it', async () => {
  const h = responseHarness();
  let releaseClick;
  const click = new Promise(resolve => { releaseClick = resolve; });
  const unhandled = [];
  const onUnhandled = error => unhandled.push(error);
  process.on('unhandledRejection', onUnhandled);
  try {
    const operation = cases.capturePhysicalResponse(h.page, () => true, () => click);
    h.reject(Error('controlled response timeout'));
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(unhandled, [], 'early waiter rejection must be immediately observed');
    releaseClick();
    await assert.rejects(operation, /controlled response timeout/);
    assert.deepEqual(h.state(), { cancelled: 1, aborted: true });
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(unhandled, []);
  } finally { process.off('unhandledRejection', onUnhandled); releaseClick(); }
});

test('failed physical click aborts and joins its response waiter without replacing the failure', async () => {
  const h = responseHarness();
  await assert.rejects(cases.capturePhysicalResponse(h.page, () => true, async () => {
    throw Error('controlled physical click failed');
  }), /controlled physical click failed/);
  assert.deepEqual(h.state(), { cancelled: 1, aborted: true });
});

test('response rejection after click stays a failure; success returns the actual response', async () => {
  const failed = responseHarness();
  await assert.rejects(cases.capturePhysicalResponse(failed.page, () => true, async () => {
    failed.reject(Error('controlled server response unavailable'));
  }), /controlled server response unavailable/);
  assert.deepEqual(failed.state(), { cancelled: 1, aborted: true });
  const success = responseHarness();
  const real = { status: () => 200, json: async () => ({ ok: true }) };
  assert.equal(await cases.capturePhysicalResponse(success.page, () => true, async () => {
    success.resolve(real);
  }), real);
  assert.deepEqual(success.state(), { cancelled: 1, aborted: true });
});

test('physical login admits the exact account route, saved HttpOnly buyer, then current account frame', async () => {
  const { safeLoginDestination } = await import('../client/src/pages/secureshop/utils/loginDestination.mjs');
  assert.equal(safeLoginDestination('/secureshop/account', { role: 'customer' }), '/secureshop/account');
  const order = [], buyerName = 'session_owner_controlled', buyerId = 41;
  const page = {
    url: () => 'http://127.0.0.1:39117/secureshop/account',
    async waitForFunction(predicate, options) {
      assert.equal(options.timeout, 20000);
      const prior = global.location;
      try { global.location = { pathname: '/secureshop/account' }; assert.equal(predicate(), true); }
      finally { global.location = prior; }
      order.push('account-route');
    },
    async cookies(url) {
      assert.equal(url, 'http://127.0.0.1:39117/api/secureshop/auth/session');
      order.push('cookie'); return [{ name: 'dvaia_shop_session', httpOnly: true, value: 'synthetic-token' }];
    },
  };
  const frame = {};
  assert.equal(await cases.admitAccountAfterPhysicalLogin({ page,
    origin: 'http://127.0.0.1:39117', buyerName, buyerId,
    authenticate: async token => { assert.equal(token, 'synthetic-token'); order.push('authenticate');
      return { shopUserId: buyerId, username: buyerName, role: 'customer' }; },
    findAccountFrame: async (selected, name) => { assert.equal(selected, page);
      assert.equal(name, buyerName); order.push('account-frame'); return frame; },
  }), frame);
  assert.deepEqual(order, ['account-route', 'cookie', 'authenticate', 'account-frame']);
});

test('unfinished navigation or missing authenticated buyer never admits an account frame', async () => {
  const order = [];
  const input = { origin: 'http://127.0.0.1:39117', buyerName: 'owned', buyerId: 41,
    authenticate: async () => { order.push('authenticate'); return { shopUserId: 42, username: 'owned', role: 'customer' }; },
    findAccountFrame: async () => { order.push('frame'); return {}; } };
  const page = { url: () => 'http://127.0.0.1:39117/secureshop/login',
    waitForFunction: async () => { throw Error('timeout'); }, cookies: async () => [] };
  await assert.rejects(cases.admitAccountAfterPhysicalLogin({ ...input, page }),
    /Completed account navigation unavailable: \/secureshop\/login/);
  assert.deepEqual(order, []);
  page.waitForFunction = async () => {};
  await assert.rejects(cases.admitAccountAfterPhysicalLogin({ ...input, page }),
    /completed shop login cookie required/);
  assert.deepEqual(order, []);
  page.cookies = async () => [{ name: 'dvaia_shop_session', httpOnly: true, value: 'synthetic-token' }];
  await assert.rejects(cases.admitAccountAfterPhysicalLogin({ ...input, page }),
    /authenticated exact buyer required/);
  assert.deepEqual(order, ['authenticate']);
});

test('response-stage loss requires a real bounded 200 reply and retires its CDP session', async () => {
  const endpoint = `http://127.0.0.1:39117${cases.revokePath(id)}`;
  const cdp = new EventEmitter(), calls = [];
  cdp.send = async (method, payload) => {
    calls.push([method, payload]);
    if (method === 'Fetch.getResponseBody') return { body: Buffer.from('{"ok":true}').toString('base64'),
      base64Encoded: true };
    return {};
  };
  cdp.detach = async () => { calls.push(['detach']); };
  const loss = await cases.loseOneCompletedAck({ createCDPSession: async () => cdp }, endpoint);
  cdp.emit('Fetch.requestPaused', { requestId: 'controlled-one', request: { url: endpoint, method: 'POST' },
    responseStatusCode: 200 });
  await new Promise(resolve => setImmediate(resolve));
  const sha = createHash('sha256').update('{"ok":true}').digest('hex');
  assert.deepEqual(loss.observed(), { status: 200, replySha256: sha });
  await loss.close();
  assert.deepEqual(calls.map(row => row[0]), ['Fetch.enable', 'Fetch.getResponseBody',
    'Fetch.failRequest', 'Fetch.disable', 'detach']);
  assert.equal(cdp.listenerCount('Fetch.requestPaused'), 0);
});

test('wrong or malformed response cannot be represented as committed ACK loss', async () => {
  for (const [status, body] of [[202, '{"ok":true}'], [200, '{"ok":false}'],
    [200, 'x'.repeat(4097)]]) {
    const cdp = new EventEmitter(), calls = [];
    cdp.send = async (method) => {
      calls.push(method);
      return method === 'Fetch.getResponseBody' ? { body, base64Encoded: false } : {};
    };
    cdp.detach = async () => { calls.push('detach'); };
    const loss = await cases.loseOneCompletedAck({ createCDPSession: async () => cdp },
      'http://127.0.0.1:39117/selected');
    cdp.emit('Fetch.requestPaused', { requestId: 'bad', request: {
      url: 'http://127.0.0.1:39117/selected', method: 'POST' }, responseStatusCode: status });
    await new Promise(resolve => setImmediate(resolve));
    assert.throws(() => loss.observed());
    await assert.rejects(loss.close());
    assert(calls.includes('Fetch.failRequest'));
    assert(calls.includes('Fetch.disable'));
    assert(calls.includes('detach'));
    assert.equal(cdp.listenerCount('Fetch.requestPaused'), 0);
  }
});

test('CDP setup and terminal cleanup failures preserve owned-session retirement attempts', async () => {
  const endpoint = 'http://127.0.0.1:39117/selected';
  for (const broken of ['Fetch.enable', 'Fetch.disable']) {
    const cdp = new EventEmitter(), calls = [];
    cdp.send = async method => {
      calls.push(method);
      if (method === broken) throw Error('controlled CDP failure');
      return {};
    };
    cdp.detach = async () => { calls.push('detach'); };
    if (broken === 'Fetch.enable') {
      await assert.rejects(cases.loseOneCompletedAck({ createCDPSession: async () => cdp }, endpoint));
    } else {
      const loss = await cases.loseOneCompletedAck({ createCDPSession: async () => cdp }, endpoint);
      await assert.rejects(loss.close());
    }
    assert(calls.includes('detach'));
    assert.equal(cdp.listenerCount('Fetch.requestPaused'), 0);
  }
});
