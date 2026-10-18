'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isSessionActive } = require('../server/middleware/sessionValidity');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');

test('session validity fails closed after revocation, cleanup, expiry or malformed expiry', () => {
  const now = Date.now();
  const active = { is_active: 1, expires_at: new Date(now + 60000).toISOString() };
  assert.equal(isSessionActive(active, now), true);
  for (const row of [undefined, { ...active, is_active: 0 }, { ...active, expires_at: null },
    { ...active, expires_at: 'bad' }, { ...active, expires_at: new Date(now).toISOString() }]) {
    assert.equal(isSessionActive(row, now), false);
  }
});

test('actual admin authentication rejects a token after its revoked session row is cleaned up', async () => {
  let session = { id: 1, session_active: true, expires_at: new Date(Date.now() + 60000).toISOString() };
  const user = {
    id: 7, username: 'admin', email: 'admin@example.invalid', role: 'admin', admin_level: 2,
    full_name: 'Controlled Admin', email_verified: true, last_login: null,
  };
  const adapter = {
    jwtSecret: 'controlled-postgres-secret', repository: {},
    async validateSession(token) {
      if (session.account_locked_until) {
        throw Object.assign(new Error('Account locked'), {
          name: 'AccountLocked', lockedUntil: session.account_locked_until,
        });
      }
      if (token !== 'token' || session.session_active !== true) return null;
      return { user, session };
    },
  };
  const middleware = createPostgresAdminAuth(adapter).authenticateToken;
  async function invoke(authorization = 'Bearer token') {
    let status = 200, nextCalled = false;
    await middleware({ headers: { authorization } }, {
      status(code) { status = code; return this; }, json() {},
    }, () => { nextCalled = true; });
    return { status, nextCalled };
  }
  for (const header of ['Basic token', 'Bearer token extra', 'Bearer token,Bearer second', ['Bearer token']]) {
    assert.deepEqual(await invoke(header), { status: 401, nextCalled: false });
  }
  assert.deepEqual(await invoke(), { status: 200, nextCalled: true });
  session.account_locked_until = '2099-01-01T00:00:00Z';
  assert.deepEqual(await invoke(), { status: 423, nextCalled: false });
  delete session.account_locked_until;
  session.session_active = false;
  assert.deepEqual(await invoke(), { status: 401, nextCalled: false });
  session = { session_active: false };
  assert.deepEqual(await invoke(), { status: 401, nextCalled: false });
});

test('PostgreSQL timestamp Date and ISO UTC expiry have identical fail-closed semantics', () => {
  const now = Date.parse('2030-01-01T12:01:00Z');
  assert.equal(isSessionActive({ is_active: true, expires_at: new Date('2030-01-01T12:00:00Z') }, now), false);
  assert.equal(isSessionActive({ is_active: true, expires_at: '2030-01-01T12:02:00Z' }, now), true);
});
