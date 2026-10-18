'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createAuthSessionHandlers } = require('../server/routes/authSessionHandlers');

function response() {
  let resolve;
  const result = new Promise(done => { resolve = done; });
  return { result, statusCode: 200, cookies: [], status(code) { this.statusCode = code; return this; },
    json(body) { resolve({ status: this.statusCode, body }); }, clearCookie(name) { this.cookies.push(name); } };
}

test('logout waits for revocation and reports persistence failure without a false success', async () => {
  let complete;
  let destroyed = false;
  const handlers = createAuthSessionHandlers({ authDb: { run(_sql, _params, cb) { complete = cb; } } });
  const req = { headers: { authorization: 'Bearer example' }, session: { destroy(cb) { destroyed = true; cb(); } } };
  const res = response();
  handlers.logout(req, res);
  assert.equal(destroyed, false);
  assert.deepEqual(res.cookies, []);
  complete(new Error('store unavailable'));
  assert.equal((await res.result).status, 503);
  assert.equal(destroyed, false);
  const success = response();
  handlers.logout(req, success);
  complete(null);
  assert.equal((await success.result).body.success, true);
  assert.equal(destroyed, true);
  assert.deepEqual(success.cookies, ['connect.sid', 'token']);
});

test('status cannot authenticate from a stale Express cookie after token rejection', async () => {
  const handlers = createAuthSessionHandlers({ authDb: {}, authenticateToken(_req, res) {
    return res.status(401).json({ error: 'invalid token' });
  } });
  const res = response();
  handlers.status({ headers: {}, session: { userId: 7 } }, res);
  assert.equal((await res.result).body.authenticated, false);
});

test('status works with a verified bearer identity and no Express session', async () => {
  const handlers = createAuthSessionHandlers({
    authenticateToken(req, _res, next) { req.user = { id: 7, role: 'student', username: 'student' }; next(); },
    authDb: {
      get(_sql, params, cb) { assert.deepEqual(params, ['example', 7]); cb(null, { expires_at: 'future', last_activity: 'now' }); },
      all(_sql, _params, cb) { cb(null, []); },
    },
  });
  const res = response();
  handlers.status({ headers: { authorization: 'Bearer example' } }, res);
  const result = await res.result;
  assert.equal(result.body.authenticated, true);
  assert.equal(result.body.user.id, 7);
});

test('password rotation atomically revokes sessions and handles crypto failure', async () => {
  const { createPasswordChangeHandler } = require('../server/routes/authSessionHandlers');
  const queries = [];
  const authDb = {
    get(_sql, _params, cb) { cb(null, { password: 'oldhash' }); },
    run(sql, params, cb) { queries.push(sql); cb.call({ changes: 1 }, null); },
  };
  const config = { authDb, validatePassword: () => ({ valid: true }),
    bcrypt: { compare: async () => true, hash: async () => 'newhash' } };
  const req = { user: { id: 7 }, body: { currentPassword: 'old', newPassword: 'new' } };
  const res = response(); await createPasswordChangeHandler(config)(req, res);
  assert.equal((await res.result).body.success, true);
  assert.deepEqual(queries, ['BEGIN IMMEDIATE', 'UPDATE users SET password = ? WHERE id = ? AND password = ?',
    'UPDATE user_sessions SET is_active = 0 WHERE user_id = ?', 'COMMIT']);
  config.bcrypt.hash = async () => { throw new Error('crypto failed'); };
  const failed = response(); await createPasswordChangeHandler(config)(req, failed);
  assert.equal((await failed.result).status, 500);
});

test('password rotation rolls back when session revocation fails', async () => {
  const { createPasswordChangeHandler } = require('../server/routes/authSessionHandlers');
  const queries = [];
  const handler = createPasswordChangeHandler({
    authDb: { get(_sql, _params, cb) { cb(null, { password: 'oldhash' }); },
      run(sql, params, cb) { queries.push(sql); cb.call({ changes: 1 }, sql.includes('user_sessions') ? new Error('failed') : null); } },
    validatePassword: () => ({ valid: true }), bcrypt: { compare: async () => true, hash: async () => 'newhash' },
  });
  const res = response(); await handler({ user: { id: 7 }, body: { currentPassword: 'old', newPassword: 'new' } }, res);
  assert.equal((await res.result).status, 500);
  assert.equal(queries.at(-1), 'ROLLBACK'); assert.equal(queries.includes('COMMIT'), false);
});
