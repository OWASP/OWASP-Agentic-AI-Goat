'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresAdminRepository } = require('../server/database/postgres/adminRepository');

function fixture({ admins = 1, managers = 1, authority = true } = {}) {
  const calls = [];
  const row = { id: 1, username: 'owner', email: 'owner@example.test', role: 'admin', admin_level: 2,
    full_name: null, is_active: 1, email_verified: 1, department: null, phone: null };
  const client = {
    release() {},
    async query(sql, values = []) {
      calls.push({ sql, values });
      if (sql.includes('FROM identity.users actor')) return {
        rowCount: authority ? 1 : 0, rows: authority ? [{ '?column?': 1 }] : [],
      };
      if (sql.includes('SELECT * FROM identity.users WHERE id=')) return { rowCount: 1, rows: [{ ...row }] };
      if (sql.includes('AS active_admins')) return { rows: [{ active_admins: admins, managers }] };
      if (sql.includes('SELECT 1 FROM identity.student_deletion_jobs')) return { rowCount: 0, rows: [] };
      if (sql.includes('SELECT id FROM identity.users WHERE id=')) return { rowCount: 1, rows: [{ id: 1 }] };
      if (sql.startsWith('UPDATE identity.users')) return { rowCount: 1, rows: [{ ...row, is_active: values[4] ?? values[7] }] };
      if (sql.includes('FROM identity.admin_permissions p JOIN identity.users u')) return {
        rows: [{ id: 10, admin_id: 1, permission_name: 'user_management', admin_level: 2 }], rowCount: 1,
      };
      if (sql.includes('RETURNING id')) return { rows: [{ id: 10 }], rowCount: 1 };
      if (sql.includes('SELECT id,admin_level FROM identity.users')) return { rows: [{ id: 1, admin_level: 2 }], rowCount: 1 };
      if (sql.includes('SELECT permission_name FROM identity.admin_permissions')) return { rows: [{ permission_name: 'user_management' }] };
      return { rows: [], rowCount: 1 };
    },
  };
  const repository = createPostgresAdminRepository({ query: client.query.bind(client), connect: async () => client });
  return { repository, calls };
}

test('sole manager removal rolls back through every administrative route', async () => {
  const actor = { id: 1, sessionId: 2, level: 2 };
  for (const [name, mutation] of [
    ['soft deactivate', repo => repo.deactivateAdministrator({ userId: 1, actorId: 1, sessionId: 2 })],
    ['demote', repo => repo.updateAdministrator({ userId: 1, input: { adminLevel: 1 }, actorId: 1, sessionId: 2 })],
    ['direct permission revoke', repo => repo.revokePermissionById(10, actor)],
    ['generic update', repo => repo.updateUser(1, { isActive: false }, actor)],
    ['lock', repo => repo.setUserLock({ userId: 1, locked: true, actorId: 1, sessionId: 2 })],
    ['expiring permission upsert', repo => repo.grantPermission({ userId: 1, permission: 'user_management',
      actorId: 1, sessionId: 2, expiresAt: '2099-01-01T00:00:00Z' })],
  ]) {
    const { repository, calls } = fixture({ managers: 0 });
    await assert.rejects(mutation(repository), { code: 'LAST_ADMIN', statusCode: 409 }, name);
    assert.equal(calls[1].sql, 'SELECT pg_advisory_xact_lock(1743921, 1)', name);
    assert.equal(calls.at(-1).sql, 'ROLLBACK', name);
    assert.equal(calls.some(call => call.sql === 'COMMIT'), false, name);
  }
});

test('administrative mutations revalidate a current session and level two authority', async () => {
  const { repository, calls } = fixture();
  await repository.updateAdministrator({ userId: 1, input: { fullName: 'Owner' }, actorId: 1, sessionId: 2 });
  const authority = calls.find(call => call.sql.includes('FROM identity.users actor'));
  assert.deepEqual(authority.values, [1, 2, 2]);
  assert.match(authority.sql, /FOR SHARE OF actor,session,permission/);
  assert.equal(calls.at(-1).sql, 'COMMIT');
});

test('revoked actor session prevents a new administrator mutation', async () => {
  const { repository, calls } = fixture({ authority: false });
  await assert.rejects(repository.deactivateAdministrator({ userId: 1, actorId: 1, sessionId: 2 }),
    { statusCode: 403 });
  assert.equal(calls.some(call => call.sql.startsWith('UPDATE identity.users')), false);
  assert.equal(calls.at(-1).sql, 'ROLLBACK');
});

test('successful deactivation revokes sessions and commits the audit and account change', async () => {
  const { repository, calls } = fixture({ admins: 1, managers: 1 });
  const result = await repository.deactivateAdministrator({ userId: 1, actorId: 1, sessionId: 2 });
  assert.equal(result.user.is_active, 0);
  assert.ok(calls.some(call => call.sql.includes('UPDATE identity.user_sessions SET is_active=0')));
  assert.ok(calls.some(call => call.sql.includes('INSERT INTO identity.activity_logs') &&
    call.values[1] === 'admin_administrator_deactivated'));
  assert.equal(calls.at(-1).sql, 'COMMIT');
});

test('level one actor cannot modify an administrator through generic user update', async () => {
  const { repository, calls } = fixture();
  await assert.rejects(repository.updateUser(1, { fullName: 'Changed' },
    { id: 2, sessionId: 3, level: 1 }), { statusCode: 403 });
  assert.ok(calls.some(call => call.sql.includes('FROM identity.users actor') && call.values[2] === 2));
  assert.equal(calls.some(call => call.sql.startsWith('UPDATE identity.users')), false);
  assert.equal(calls.at(-1).sql, 'ROLLBACK');
});
