'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { createPostgresAuthRouter } = require('../server/routes/postgresAuth');

async function fixture(t, { regenerationFailure = false, saveBarrier, saveFailure = false, auditFailure = false, credentialState = 'active', loginRuntime, sessionBarrier } = {}) {
  let created = 0, audited = 0, revoked = 0, failedSaveAttempts = 0, credentialReads = 0;
  const user = { id: 7, username: 'learner', is_active: true, role: 'student',
    password: await bcrypt.hash('test-password', 4) };
  if (credentialState === 'inactive') user.is_active = false;
  if (credentialState === 'locked') user.account_locked_until = new Date(Date.now() + 3600000);
  const adapter = {
    repository: {
      findCredentialByUsername: async username => {
        credentialReads++;
        require('../server/database/postgres/identityValidation').text(username, 'username', 50);
        return credentialState === 'absent' ? null : user;
      },
      recordFailedLogin: async () => ({ login_attempts: 1,
        ...(credentialState === 'locksOnFailure' ? { account_locked_until: new Date(Date.now() + 3600000) } : {}) }),
      getUserById: async () => user,
      getUserPermissions: async () => [],
      recordAudit: async () => { if (auditFailure) throw new Error("controlled audit failure"); audited++; },
    },
    createSession: async () => { created++; await sessionBarrier?.(); return { token: 'controlled-token', internalSessionId: 71, expiresAt: new Date(Date.now()+3600000).toISOString() }; },
    logout: async token => { assert.equal(token, 'controlled-token'); revoked++; },
    userDto: value => ({ id: value.id, username: value.username }),
  };
  const pass = (req, res, next) => next();
  const router = createPostgresAuthRouter({ adapter, ...(loginRuntime ? { loginRuntime } : {}), limiters: {
    loginRateLimiter: pass, registerRateLimiter: pass, passwordResetRateLimiter: pass,
  } });
  const app = express();
  app.use(express.json());
  const store = new session.MemoryStore();
  const originalSet = store.set.bind(store);
  if (saveBarrier) store.set = (sid, value, callback) => saveBarrier(() => originalSet(sid, value, callback), value);
  app.use(session({ store, secret: 'isolated-session-rotation-test', resave: false, saveUninitialized: false }));
  if (saveFailure) store.set = (sid, value, callback) => {
    if (value.platformSessionId === 71 && failedSaveAttempts++ === 0) return callback(new Error('controlled save failure'));
    originalSet(sid, value, callback);
  };
  let headersSent = () => false, didDisconnect;
  const disconnected = new Promise(resolve => { didDisconnect = resolve; });
  app.use((req, res, next) => {
    if (req.path.startsWith('/auth/')) {
      headersSent = () => res.headersSent;
      res.once('close', () => { if (!res.writableFinished) didDisconnect(); });
    }
    next();
  });
  app.get('/anonymous', (req, res) => { req.session.marker = 'pre-login'; res.json({ id: req.sessionID }); });
  app.get('/inspect', (req, res) => res.json({ id: req.sessionID, owner: req.session.platformOwnerId,
    platformSession: req.session.platformSessionId, userId: req.session.userId, username: req.session.username,
    role: req.session.role, adminLevel: req.session.adminLevel, sessionData: req.session.sessionData, marker: req.session.marker }));
  if (regenerationFailure) app.use((req, res, next) => {
    req.session.regenerate = callback => callback(new Error('controlled store failure')); next();
  });
  app.use('/auth', router);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { await router.close(); await new Promise(resolve => server.close(resolve)); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  async function request(path, cookie, password, username = 'learner') {
    const response = await fetch(origin + path, { method: password === undefined ? 'GET' : 'POST',
      headers: { ...(cookie ? { cookie } : {}), 'content-type': 'application/json' },
      body: password === undefined ? undefined : JSON.stringify({ username, password }) });
    return { status: response.status, cookie: response.headers.get('set-cookie')?.split(';')[0], body: await response.json() };
  }
  return { origin, request, disconnected, credentialReads: () => credentialReads, cleanupCounts: () => ({ revoked, failedSaveAttempts }), headersSent: () => headersSent(), counts: () => ({ created, audited }) };
}

for (const phase of ['comparison', 'session']) {
  test(`disconnect during ${phase} cannot publish or retain late platform authority`, { timeout: 5000 }, async t => {
    let enter, release, finish;
    const entered = new Promise(resolve => { enter = resolve; });
    const gate = new Promise(resolve => { release = resolve; });
    const completed = new Promise(resolve => { finish = resolve; });
    t.after(() => release());
    const barrier = async () => { enter(); await gate; };
    const loginRuntime = { run: async (signal, work) => { try { return await work({
      check: () => signal.throwIfAborted(),
      compare: async () => { if (phase === 'comparison') await barrier(); return true; },
    }); } finally { finish(); } }, close: async () => {}, snapshot: () => ({ controlled: true }) };
    const f = await fixture(t, { loginRuntime, ...(phase === 'session' ? { sessionBarrier: barrier } : {}) });
    const controller = new AbortController();
    const request = fetch(f.origin + '/auth/login', { method: 'POST', signal: controller.signal,
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'learner', password: 'test-password' }) });
    const rejected = assert.rejects(request, { name: 'AbortError' });
    await entered;
    controller.abort();
    await rejected;
    await f.disconnected;
    release();
    await completed;
    assert.equal(f.counts().audited, 0);
    assert.equal(f.counts().created, phase === 'session' ? 1 : 0);
    assert.equal(f.cleanupCounts().revoked, phase === 'session' ? 1 : 0);
    assert.equal(f.headersSent(), false);
  });
}

for (const endpoint of ['/auth/login', '/auth/secure-login']) {
  test(`${endpoint} does not disclose account existence, inactivity or lockout in failed responses`, async t => {
    for (const credentialState of ['absent', 'active', 'inactive', 'locked', 'locksOnFailure']) {
      const f = await fixture(t, { credentialState }), anonymous = await f.request('/anonymous');
      // Even a matching password cannot authenticate inactive or locked users.
      const password = ['inactive', 'locked'].includes(credentialState) ? 'test-password' : 'wrong';
      const rejected = await f.request(endpoint, anonymous.cookie, password);
      assert.equal(rejected.status, 401, credentialState);
      assert.deepEqual(rejected.body, { error: 'Invalid credentials' }, credentialState);
      assert.deepEqual(f.counts(), { created: 0, audited: 0 });
      const current = await f.request('/inspect', anonymous.cookie);
      assert.equal(current.body.id, anonymous.body.id);
      assert.equal(current.body.owner, undefined);
    }
  });
  test(`${endpoint} rejects oversized usernames before storage or session mutation`, async t => {
    const f = await fixture(t), anonymous = await f.request('/anonymous');
    const invalid = await f.request(endpoint, anonymous.cookie, 'test-password', 'x'.repeat(51));
    assert.equal(invalid.status, 400);
    assert.equal(f.credentialReads(), 0);
    assert.deepEqual(f.counts(), { created: 0, audited: 0 });
    assert.equal((await f.request('/inspect', anonymous.cookie)).body.id, anonymous.body.id);
    const boundary = await f.request(endpoint, anonymous.cookie, 'test-password', 'x'.repeat(50));
    assert.equal(boundary.status, 200);
    assert.equal(f.credentialReads(), 1);
  });
  test(`${endpoint} rotates anonymous cookie before assigning platform authority`, async t => {
    const f = await fixture(t), anonymous = await f.request('/anonymous');
    const login = await f.request(endpoint, anonymous.cookie, 'test-password');
    assert.equal(login.status, 200); assert.ok(login.cookie); assert.notEqual(login.cookie, anonymous.cookie);
    const current = await f.request('/inspect', login.cookie);
    assert.notEqual(current.body.id, anonymous.body.id);
    assert.equal(current.body.owner, 7); assert.equal(current.body.platformSession, 71);
    assert.equal(current.body.userId, 7); assert.equal(current.body.username, 'learner');
    assert.equal(current.body.role, undefined); assert.equal(current.body.adminLevel, undefined);
    assert.equal(current.body.sessionData, undefined);
    assert.equal(current.body.marker, undefined);
    const stale = await f.request('/inspect', anonymous.cookie);
    assert.equal(stale.body.owner, undefined); assert.equal(stale.body.platformSession, undefined);
    assert.deepEqual(f.counts(), { created: 1, audited: 1 });
  });
}

test('invalid credentials preserve anonymous session and mint no platform session', async t => {
  const f = await fixture(t), anonymous = await f.request('/anonymous');
  assert.equal((await f.request('/auth/login', anonymous.cookie, 'wrong')).status, 401);
  const current = await f.request('/inspect', anonymous.cookie);
  assert.equal(current.body.id, anonymous.body.id); assert.equal(current.body.marker, 'pre-login');
  assert.deepEqual(f.counts(), { created: 0, audited: 0 });
});

test('failed session rotation fails closed before durable session creation', async t => {
  const f = await fixture(t, { regenerationFailure: true }), anonymous = await f.request('/anonymous');
  assert.equal((await f.request('/auth/login', anonymous.cookie, 'test-password')).status, 503);
  assert.deepEqual(f.counts(), { created: 0, audited: 0 });
});

test('successful login headers wait for the durable teaching-cookie save', async t => {
  let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  const f = await fixture(t, { saveBarrier: (save, value) => {
    if (value.platformSessionId === 71 && !release) { release = save; entered(); }
    else save();
  } });
  const pending = f.request('/auth/login', null, 'test-password');
  try {
    await started;
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(f.headersSent(), false, 'success headers must not race persistence');
    assert.deepEqual(f.counts(), { created: 1, audited: 0 });
  } finally { release?.(); }
  assert.equal((await pending).status, 200);
  assert.deepEqual(f.counts(), { created: 1, audited: 1 });
});

for (const failure of ['saveFailure', 'auditFailure']) test(`${failure} retires unpublished login and suppresses automatic cookie resave`, async t => {
  const f = await fixture(t, { [failure]: true });
  const result = await f.request('/auth/login', null, 'test-password');
  assert.equal(result.status, 503);
  assert.equal(result.cookie, undefined);
  assert.equal(result.body.token, undefined);
  assert.deepEqual(f.counts(), { created: 1, audited: 0 });
  assert.equal(f.cleanupCounts().revoked, 1);
  if (failure === 'saveFailure') assert.equal(f.cleanupCounts().failedSaveAttempts, 1);
});
