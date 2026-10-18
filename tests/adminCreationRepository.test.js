'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const { createPostgresAdminRepository } = require('../server/database/postgres/adminRepository');

function fixture({ authority = true, failGrant = false } = {}) {
  const calls = [];
  const client = {
    async query(sql, values = []) {
      calls.push({ sql, values });
      if (sql.includes('FROM identity.users actor')) return { rowCount: authority ? 1 : 0, rows: authority ? [{ '?column?': 1 }] : [] };
      if (sql.includes('INSERT INTO identity.users')) return { rowCount: 1, rows: [{ id: 41, username: 'new-admin', role: 'admin', admin_level: 1 }] };
      if (sql.includes('INSERT INTO identity.admin_permissions') && failGrant) throw new Error('grant unavailable');
      return { rowCount: 1, rows: [] };
    },
    release() {}
  };
  const repository = createPostgresAdminRepository({ query: client.query.bind(client), connect: async () => client });
  const input = { username: 'new-admin', email: 'new@example.test', passwordHash: bcrypt.hashSync('test-password', 4),
    adminLevel: 1, permissions: ['challenge_management', 'view_analytics'], actorId: 7, sessionId: 9 };
  return { repository, input, calls };
}

test('administrator creation rechecks current role, session and grant before atomic account, permissions and audit', async () => {
  const { repository, input, calls } = fixture();
  const user = await repository.createAdministrator(input);
  assert.equal(user.id, 41);
  assert.match(calls[1].sql, /actor\.admin_level >= \$3/);
  assert.match(calls[1].sql, /session\.is_active=1/);
  assert.match(calls[1].sql, /permission\.permission_name='user_management'/);
  assert.match(calls[1].sql, /FOR SHARE OF actor,session,permission/);
  assert.deepEqual(calls[1].values, [7, 9, 2]);
  assert.equal(calls.filter(call => call.sql.includes('INSERT INTO identity.admin_permissions')).length, 2);
  const audit = calls.find(call => call.sql.includes('admin_administrator_created'));
  assert.equal(audit.values[0], 7);
  assert.equal(JSON.parse(audit.values[1]).targetUserId, 41);
  assert.equal(calls.at(-1).sql, 'COMMIT');
});

test('revoked authority and failed grants never commit a partial administrator', async () => {
  const denied = fixture({ authority: false });
  await assert.rejects(denied.repository.createAdministrator(denied.input), error => error.statusCode === 403);
  assert.equal(denied.calls.some(call => call.sql.includes('INSERT INTO identity.users')), false);
  assert.equal(denied.calls.at(-1).sql, 'ROLLBACK');

  const failed = fixture({ failGrant: true });
  await assert.rejects(failed.repository.createAdministrator(failed.input), /grant unavailable/);
  assert.equal(failed.calls.at(-1).sql, 'ROLLBACK');
  assert.equal(failed.calls.some(call => call.sql === 'COMMIT'), false);
});
