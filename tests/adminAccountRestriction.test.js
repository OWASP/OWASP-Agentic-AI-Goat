'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresAdminRepository } = require('../server/database/postgres/adminRepository');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');
const { createPostgresWorkshopRouter } = require('../server/routes/postgresWorkshop');

function repositoryFixture({ deletionAdmitted = false } = {}) {
  const statements = [];
  const users = new Map([
    [7, { id: 7, username: 'student', email: 'student@example.invalid', full_name: 'Student',
      role: 'student', admin_level: 0, is_active: 1, email_verified: 1 }],
  ]);
  const client = {
    release() {},
    async query(sql, values = []) {
      const normalized = sql.replace(/\s+/g, ' ').trim();
      statements.push({ sql: normalized, values: [...values] });
      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(normalized)) return { rows: [], rowCount: 0 };
      if (normalized === 'SELECT pg_advisory_xact_lock(1743921, 1)') return { rows: [], rowCount: 1 };
      if (normalized.startsWith('SELECT * FROM identity.users')) {
        return { rows: users.has(values[0]) ? [{ ...users.get(values[0]) }] : [] };
      }
      if (normalized.startsWith('SELECT id,admin_level FROM identity.users')) {
        const user = users.get(values[0]);
        return { rows: user ? [{ id: user.id, admin_level: user.admin_level }] : [] };
      }
      if (normalized.startsWith("SELECT count(*) FILTER (WHERE role IN ('admin','super_admin')")) {
        return { rows: [{ active_admins: 1, managers: 1 }] };
      }
      if (normalized.startsWith('SELECT 1 FROM identity.student_deletion_jobs')) {
        return { rows: deletionAdmitted ? [{ '?column?': 1 }] : [], rowCount: deletionAdmitted ? 1 : 0 };
      }
      if (normalized.startsWith('SELECT id FROM identity.users')) {
        const user = users.get(values[0]);
        return { rows: user?.role === 'student' && user.admin_level === 0 ? [{ id: user.id }] : [] };
      }
      if (normalized.startsWith('UPDATE identity.users SET username=')) {
        const user = users.get(values[9]);
        Object.assign(user, { username: values[0], email: values[1], full_name: values[2],
          role: values[3], admin_level: values[4], is_active: values[7], email_verified: values[8] });
        return { rows: [{ ...user }], rowCount: 1 };
      }
      if (normalized.startsWith('UPDATE identity.users SET is_active=')) {
        const user = users.get(values[1]);
        user.is_active = values[0];
        return { rows: [{ ...user }], rowCount: 1 };
      }
      if (normalized.startsWith('UPDATE identity.users SET account_locked_until=')) {
        return { rows: [{ ...users.get(values[1]) }], rowCount: 1 };
      }
      if (normalized.startsWith('UPDATE identity.user_sessions SET is_active=0')) {
        return { rows: [], rowCount: values[0] === 7 ? 2 : 0 };
      }
      if (normalized.startsWith('INSERT INTO identity.activity_logs')) return { rows: [], rowCount: 1 };
      throw new Error(`Unexpected SQL: ${normalized}`);
    },
  };
  return { repository: createPostgresAdminRepository({ query: client.query, connect: async () => client }), statements, users };
}

function assertRevokedBeforeCommit(statements, reason) {
  const revoke = statements.findIndex(row => row.sql.startsWith('UPDATE identity.user_sessions') && row.values[1] === reason);
  const commit = statements.findIndex(row => row.sql === 'COMMIT');
  assert.ok(revoke >= 0, `missing ${reason} session revocation`);
  assert.ok(commit > revoke, 'session revocation must commit in the account-state transaction');
}

test('lock and deactivation revoke sessions in their account transaction while reversal never revives them', async () => {
  let fixture = repositoryFixture();
  await fixture.repository.setUserLock({ userId: 7, locked: true, actorId: 1, actorUsername: 'admin' });
  assertRevokedBeforeCommit(fixture.statements, 'account_locked');

  fixture = repositoryFixture();
  await fixture.repository.setUserLock({ userId: 7, locked: false, actorId: 1, actorUsername: 'admin' });
  assert.equal(fixture.statements.some(row => row.sql.startsWith('UPDATE identity.user_sessions')), false,
    'unlock must not reactivate or rewrite prior sessions');

  fixture = repositoryFixture();
  await fixture.repository.updateUser(7, { isActive: false }, 2);
  assertRevokedBeforeCommit(fixture.statements, 'account_deactivated');
  fixture.statements.length = 0;
  await fixture.repository.updateUser(7, { isActive: true }, 2);
  assert.equal(fixture.statements.some(row => row.sql.startsWith('UPDATE identity.user_sessions')), false,
    'reactivation must require a fresh login rather than reviving a bearer');

  fixture = repositoryFixture();
  await fixture.repository.updateUser(7, { role: 'admin', adminLevel: 1 }, 2);
  assertRevokedBeforeCommit(fixture.statements, 'account_authority_changed');

  fixture = repositoryFixture();
  await fixture.repository.setStudentActive({ userId: 7, enabled: false });
  assertRevokedBeforeCommit(fixture.statements, 'account_deactivated');
  fixture.statements.length = 0;
  await fixture.repository.setStudentActive({ userId: 7, enabled: true });
  assert.equal(fixture.statements.some(row => row.sql.startsWith('UPDATE identity.user_sessions')), false);

  fixture = repositoryFixture();
  fixture.users.get(7).role = 'admin';
  fixture.users.get(7).admin_level = 1;
  assert.equal(await fixture.repository.updateStudent(7, { fullName: 'Must not change' }, 2), null);
  assert.equal(fixture.statements.some(row => row.sql.startsWith('UPDATE identity.users SET username=')), false,
    'student update must recheck role while holding the mutation row lock');
});

test('an admitted deletion makes every administrative learner mutation unavailable', async () => {
  const fixture = repositoryFixture({ deletionAdmitted: true });
  assert.equal(await fixture.repository.updateStudent(7, { fullName: 'Must remain deleted' }, 2), null);
  assert.equal(await fixture.repository.updateUser(7, { isActive: true }, 2), null);
  assert.equal(await fixture.repository.setStudentActive({ userId: 7, enabled: true }), null);
  assert.equal(await fixture.repository.setUserLock({ userId: 7, locked: true,
    actorId: 1, actorUsername: 'admin' }), null);
  assert.equal(fixture.statements.some(row => row.sql.startsWith('UPDATE identity.users')), false);
  assert.equal(fixture.statements.some(row => row.sql.startsWith('UPDATE identity.user_sessions')), false);
});

function authFixture(grants) {
  return {
    authenticateToken(req, _res, next) {
      req.user = { id: 1, username: 'admin', role: 'admin', admin_level: 1 };
      next();
    },
    requireAdminLevel: () => (_req, _res, next) => next(),
    requirePermission: name => (_req, res, next) => grants.has(name)
      ? next() : res.status(403).json({ error: 'Permission denied', requiredPermission: name }),
    logActivity: () => (_req, _res, next) => next(),
  };
}

async function listen(app, t) {
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}

test('both student reset aliases validate live permissions and student role before reset', async t => {
  const grants = new Set();
  const resetCalls = [], progressCalls = [], toggleCalls = [], challengeCalls = [];
  let rosterProgressCalls = 0;
  const accountRepository = {
    async getStudent(id) { return Number(id) === 7 ? { id: 7, role: 'student', admin_level: 0 } : null; },
    async getMutableStudent(id) { return Number(id) === 7 ? { id: 7, role: 'student', admin_level: 0 } : null; },
    async setStudentActive(input) { toggleCalls.push(input); return Number(input.userId) === 7 ? { id: 7 } : null; },
  };
  const resetService = {
    assertSupported() {},
    async resetStudent(input) { resetCalls.push(['student', input]); return { generation: 2 }; },
    async resetAdministrativeStudent(input) { resetCalls.push(['administrative', input]); return { generation: 2 }; },
  };
  const progress = {
    async getUserProgress(id) { progressCalls.push(id); return [{ workshopKey: 'sql_injection_workshop' }]; },
    async getVisibleUsersProgress() { rosterProgressCalls++; return new Map(); },
    async recordHeartbeat() {},
  };
  const config = { async setExerciseVisibility(...args) { challengeCalls.push(args); } };
  const auth = authFixture(grants);
  const adminRepository = new Proxy(accountRepository, { get(target, name) {
    if (name in target) return target[name];
    return async () => ({ rows: [], logs: [] });
  } });
  const operational = new Proxy({}, { get: () => (_req, res) => res.status(503).json({ error: 'unused' }) });
  const app = express();
  app.use(express.json());
  app.use('/api/admin', createPostgresAdminRouter({ adapter: { repository: {} }, stores: { progress, config },
    auth, repository: adminRepository, resetService, operational, xssLegacyRepository: {},
    deletionService: { async deleteStudent() { throw new Error('unused'); } } }));
  app.use('/api/workshop', createPostgresWorkshopRouter({ stores: { pool: { async query() { return { rows: [] }; } }, progress, config },
    authenticateToken: auth.authenticateToken, requirePermission: auth.requirePermission,
    accountRepository, resetService }));
  const base = await listen(app, t);
  const request = async (path, method = 'POST', body) => {
    const response = await fetch(base + path, { method, headers: body ? { 'content-type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined });
    return { status: response.status, body: await response.json() };
  };

  assert.equal((await request('/api/admin/students/7/workshops/sql_injection_workshop/reset')).status, 403);
  assert.equal((await request('/api/workshop/instructor/reset-progress/7')).status, 403);
  assert.equal((await request('/api/workshop/instructor/students', 'GET')).status, 403);
  assert.deepEqual(resetCalls, []);
  assert.equal(rosterProgressCalls, 0);
  grants.add('manage_progress');
  for (const path of ['/api/admin/students/1/workshops/sql_injection_workshop/reset',
    '/api/admin/students/999/workshops/sql_injection_workshop/reset',
    '/api/workshop/instructor/reset-progress/1', '/api/workshop/instructor/reset-progress/999']) {
    assert.equal((await request(path)).status, 404, path);
  }
  assert.deepEqual(resetCalls, []);
  assert.deepEqual(progressCalls, []);
  assert.equal((await request('/api/admin/students/7/workshops/sql_injection_workshop/reset')).status, 200);
  assert.equal((await request('/api/workshop/instructor/reset-progress/7')).status, 200);
  assert.equal(resetCalls.length, 2);
  assert.deepEqual(resetCalls.map(([kind]) => kind), ['administrative', 'student']);

  assert.equal((await request('/api/workshop/instructor/students/7/toggle', 'PUT', { enabled: false })).status, 403);
  grants.add('user_management');
  assert.equal((await request('/api/workshop/instructor/students/1/toggle', 'PUT', { enabled: false })).status, 404);
  assert.equal((await request('/api/workshop/instructor/students/7/toggle', 'PUT', { enabled: false })).status, 200);
  assert.deepEqual(toggleCalls, [{ userId: 7, enabled: false }]);

  assert.equal((await request('/api/workshop/instructor/challenges/sql_injection_workshop/toggle', 'PUT', { enabled: false })).status, 403);
  grants.add('challenge_management');
  assert.equal((await request('/api/workshop/instructor/challenges/sql_injection_workshop/toggle', 'PUT', { enabled: false })).status, 200);
  assert.equal(challengeCalls.length, 1);
  grants.delete('manage_progress');
  assert.equal((await request('/api/workshop/instructor/reset-progress/7')).status, 403,
    'revoked permission must be checked on each alias request');
  assert.equal((await request('/api/workshop/instructor/students', 'GET')).status, 403);
  assert.equal(resetCalls.length, 2);
  assert.equal(rosterProgressCalls, 0);
});

test('instructor aliases fail closed when their permission factory is omitted', async t => {
  let progressCalls = 0;
  const app = express();
  app.use(createPostgresWorkshopRouter({
    stores: { pool: { async query() { throw new Error('query must not run'); } },
      progress: { async getVisibleUsersProgress() { progressCalls++; return new Map(); }, async recordHeartbeat() {} } },
    authenticateToken(req, _res, next) { req.user = { id: 1, role: 'admin', admin_level: 1 }; next(); },
    accountRepository: {}, resetService: {},
  }));
  const base = await listen(app, t);
  const response = await fetch(`${base}/instructor/students`);
  assert.equal(response.status, 503);
  assert.equal(progressCalls, 0);
});

test('student administration aliases require user management and reject non-students before mutation', async t => {
  const grants = new Set();
  const calls = { create: 0, update: 0, lock: 0, studentLookup: 0, credential: 0, rotate: 0 };
  const repository = new Proxy({
    async createUser() { calls.create++; return { id: 7, role: 'student', admin_level: 0 }; },
    async updateStudent(id) { calls.update++; return Number(id) === 7 ? { id: 7 } : null; },
    async setUserLock() { calls.lock++; return { id: 7 }; },
    async getStudent(id) { calls.studentLookup++; return Number(id) === 7 ? { id: 7 } : null; },
    async getMutableStudent(id) { calls.studentLookup++; return Number(id) === 7 ? { id: 7 } : null; },
  }, { get(target, name) { return name in target ? target[name] : async () => []; } });
  const adapter = { repository: {
    async findCredentialById(id) {
      calls.credential++;
      return Number(id) === 7
        ? { id: 7, role: 'student', admin_level: 0, password: '$2b$04$123456789012345678901u6a7Yv9Ja5SxuTsJ.Oq8iK7jzRpkNq2W' }
        : Number(id) === 1 ? { id: 1, role: 'super_admin', admin_level: 2, password: 'unused' } : null;
    },
    async rotateStudentPasswordAndRevoke() { calls.rotate++; return { sessionsRevoked: 1 }; },
  } };
  const auth = authFixture(grants);
  const operational = new Proxy({}, { get: () => (_req, res) => res.status(503).json({ error: 'unused' }) });
  const app = express(); app.use(express.json());
  app.use('/api/admin', createPostgresAdminRouter({ adapter, stores: { progress: {}, config: {} }, auth,
    repository, resetService: {}, operational, xssLegacyRepository: {},
    deletionService: { async deleteStudent() { throw new Error('unused'); } } }));
  const base = await listen(app, t);
  const request = async (path, method, body) => {
    const response = await fetch(base + path, { method, headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body || {}) });
    return response.status;
  };
  assert.equal(await request('/api/admin/students', 'POST', { username: 'new', email: 'new@example.invalid', password: 'Password@123' }), 403);
  assert.equal(await request('/api/admin/students/7', 'PUT', { fullName: 'New' }), 403);
  assert.equal(await request('/api/admin/students/7/change-password', 'POST', { password: 'Password@123' }), 403);
  assert.equal(await request('/api/admin/users/7/lock', 'POST'), 403);
  assert.deepEqual(calls, { create: 0, update: 0, lock: 0, studentLookup: 0, credential: 0, rotate: 0 });
  grants.add('user_management');
  assert.equal(await request('/api/admin/students/1', 'PUT', { fullName: 'No' }), 404);
  assert.equal(await request('/api/admin/students/1/change-password', 'POST', { password: 'Password@123' }), 404);
  assert.equal(await request('/api/admin/students/999/change-password', 'POST', { password: 'Password@123' }), 404);
  assert.equal(calls.rotate, 0, 'admin and missing targets must not reach password mutation');
  assert.equal(calls.credential, 0, 'student aliases must not load credential hashes for invalid targets');
});
