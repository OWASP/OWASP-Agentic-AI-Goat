'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresSessionManager } = require('../server/middleware/postgresSessionManager');

function fixture() {
  const validated = [];
  const adapter = {
    jwtSecret: 'controlled-release-secret',
    repository: {
      async cleanupExpiredSessions() {},
      async touchSession(token, userId) {
        assert.equal(token, 'valid-platform-token');
        assert.equal(userId, 7);
      },
    },
    async validateSession(token) {
      validated.push(token);
      if (token !== 'valid-platform-token') return null;
      return {
        user: { id: 7, username: 'owner', role: 'student', admin_level: 0 },
        session: {
          id: 71,
          expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000),
          last_activity: new Date(),
          ip_address: '127.0.0.1',
          device_info: {},
        },
        decoded: { userId: 7 },
      };
    },
    userDto(user) {
      return { id: user.id, username: user.username, role: user.role };
    },
  };
  const manager = createPostgresSessionManager(adapter);
  manager.stopCleanupTask();
  return { manager, validated };
}

async function invoke(manager, authorization, request = {}) {
  const req = {
    headers: authorization === undefined ? {} : { authorization },
    // This is deliberately non-authoritative teaching state.
    session: { platformOwnerId: 999, platformSessionId: 9999 },
    ...request,
  };
  let nextCalls = 0;
  let response;
  await manager.middleware()(req, {
    status(status) {
      response = { status };
      return this;
    },
    json(body) {
      response.body = body;
      return this;
    },
  }, () => { nextCalls += 1; });
  return { req, nextCalls, response };
}

test('global session enrichment accepts only one canonical Bearer credential', async () => {
  const { manager, validated } = fixture();
  const valid = await invoke(manager, 'Bearer valid-platform-token');
  assert.equal(valid.nextCalls, 1);
  assert.equal(valid.response, undefined);
  assert.deepEqual(valid.req.user, { id: 7, username: 'owner', role: 'student' });
  assert.equal(valid.req.sessionManager, manager);
  assert.deepEqual(validated, ['valid-platform-token']);
});

test('non-Bearer, malformed, and duplicate credentials cannot attach platform authority', async () => {
  const invalid = [
    'Basic valid-platform-token',
    'valid-platform-token',
    'Bearer',
    'Bearer  valid-platform-token',
    'Bearer valid-platform-token extra',
    'Bearer valid-platform-token,Bearer second-token',
  ];
  for (const authorization of invalid) {
    const { manager, validated } = fixture();
    const result = await invoke(manager, authorization);
    assert.equal(result.nextCalls, 1, authorization);
    assert.equal(result.response, undefined, authorization);
    assert.equal(result.req.user, undefined, authorization);
    assert.equal(result.req.sessionManager, undefined, authorization);
    assert.deepEqual(result.req.session, { platformOwnerId: 999, platformSessionId: 9999 });
    assert.deepEqual(validated, [], authorization);
  }

  const { manager, validated } = fixture();
  const duplicate = await invoke(manager, 'Bearer valid-platform-token', {
    rawHeaders: [
      'Authorization', 'Bearer valid-platform-token',
      'aUtHoRiZaTiOn', 'Bearer second-token',
    ],
  });
  assert.equal(duplicate.nextCalls, 1);
  assert.equal(duplicate.req.user, undefined);
  assert.deepEqual(validated, []);
});
