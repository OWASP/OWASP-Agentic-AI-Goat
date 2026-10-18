'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresSessionManager } = require('../server/middleware/postgresSessionManager');

function fixture() {
  const user = { id: 7, username: 'student', role: 'student', is_active: true };
  const session = {
    id: 1,
    is_active: true,
    expires_at: new Date(Date.now() + 60000).toISOString(),
    last_activity: new Date().toISOString(),
    ip_address: '127.0.0.1',
    device_info: { platform: 'controlled' },
  };
  const repository = {
    touches: [],
    async touchSession(token, ownerId) { this.touches.push([token, ownerId]); },
    async listActiveSessions(ownerId) { return ownerId === user.id ? [session] : []; },
    async cleanupExpiredSessions() { return 0; },
  };
  const adapter = {
    jwtSecret: 'controlled-postgres-secret',
    repository,
    userDto: value => ({ id: value.id, username: value.username, role: value.role }),
    async validateSession(token) {
      if (user.account_locked_until) {
        throw Object.assign(new Error('Account locked'), {
          name: 'AccountLocked', lockedUntil: user.account_locked_until,
        });
      }
      return token === 'persisted-token' ? { user, session, decoded: { userId: user.id } } : null;
    },
  };
  return { adapter, repository, user };
}

test('PostgreSQL session manager preserves a valid persisted session and rejects a locked owner', async t => {
  const { adapter, repository, user } = fixture();
  const first = createPostgresSessionManager(adapter);
  const restarted = createPostgresSessionManager(adapter);
  t.after(() => { first.stopCleanupTask(); restarted.stopCleanupTask(); });

  assert.notEqual(first.serverInstanceId, restarted.serverInstanceId);
  assert.equal((await restarted.validateSession('persisted-token', {})).user.id, 7);
  assert.deepEqual(repository.touches, [['persisted-token', 7]]);
  assert.equal((await restarted.getUserSessions(7)).length, 1);

  user.account_locked_until = '2099-01-01T00:00:00Z';
  assert.equal(await restarted.validateSession('persisted-token', {}), null);
  assert.equal(await restarted.validateSession('missing-token', {}), null);
});
