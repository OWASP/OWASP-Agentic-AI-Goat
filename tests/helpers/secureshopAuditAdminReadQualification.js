'use strict';

const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const express = require('express');

// Proves the persisted audit judgment is visible through the real platform
// admin read path.  Authentication and permission checks use PostgreSQL
// identity sessions/JWTs; unused mutating handlers are fail-closed stubs.
async function qualifyAuditAdminRead({ identity, progress, identityMigration, studentId,
  expectedCompleted, expectedVerdict } = {}) {
  if (!identity?.query || !progress || !identityMigration?.query || !Number.isSafeInteger(studentId)
      || typeof expectedCompleted !== 'boolean' || !['pass','fail'].includes(expectedVerdict)) {
    throw new TypeError('Admin audit read qualification dependencies are required');
  }
  const password = await bcrypt.hash('bounded-admin-read-qualification', 4);
  const admin = await require('../../server/database/postgres/identityRepository')
    .createIdentityRepository(identity).createUser({
      username: `audit-read-admin-${require('node:crypto').randomUUID().slice(0, 8)}`,
      email: `${require('node:crypto').randomUUID()}@audit-read.invalid`, passwordHash: password,
    });
  await identityMigration.query("UPDATE identity.users SET role='super_admin',admin_level=2,email_verified=1 WHERE id=$1", [admin.id]);
  const identities = require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
  await identities.grantPermission({ userId: admin.id, permission: 'manage_progress', grantedBy: admin.id });
  const credential = await identities.findCredentialById(admin.id);
  const adapter = require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({
    repository: identities, progress, jwtSecret: `audit-read-${require('node:crypto').randomUUID()}`,
  });
  const adminSession = await adapter.createSession(credential, { get: () => null, ip: '127.0.0.1' });
  const studentCredential = await identities.findCredentialById(studentId);
  const studentSession = await adapter.createSession(studentCredential, { get: () => null, ip: '127.0.0.1' });
  const auth = require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter);
  const repository = require('../../server/database/postgres/adminRepository').createPostgresAdminRepository(identity);
  const app = express(); app.use(express.json());
  const unavailable = async () => { throw new Error('outside bounded admin read qualification'); };
  app.use('/api/admin', require('../../server/routes/postgresAdmin').createPostgresAdminRouter({
    adapter, stores: { pool: identity, progress }, auth, repository,
    operational: Object.fromEntries(['providerStatus','switchProvider','configureProvider','testProvider','testLlm','appLogs','llmLogs','logStats','systemMonitoring'].map(key => [key, unavailable])),
    resetService: { resetAll: unavailable, resetStudent: unavailable, resetAdministrativeStudent: unavailable, resetWorkshop: unavailable },
    deletionService: { deleteStudent: unavailable },
  }));
  let server;
  try {
    server = await new Promise((resolve, reject) => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); value.once('error', reject); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const request = token => fetch(`${base}/api/admin/student-workshop-view/${studentId}`, {
      headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(15000),
    });
    const adminResponse = await request(adminSession.token);
    assert.equal(adminResponse.status, 200);
    const view = await adminResponse.json();
    const challenge = view.challenges.find(row => row.workshopKey === 'secureshop_agent_security');
    assert.ok(challenge, 'admin view must include SecureShop');
    assert.equal(challenge.completedObjectiveCount, expectedCompleted ? 1 : 0);
    const judgment = (await identity.query("SELECT verdict,disposition FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id='ss_audit_instruction_followed' ORDER BY evaluated_at DESC LIMIT 1", [studentId])).rows[0];
    assert.equal(judgment?.verdict, expectedVerdict);
    assert.equal(judgment?.disposition, expectedCompleted ? 'awarded' : 'not_pass');
    assert.equal((await request(studentSession.token)).status, 403);
    assert.equal((await request('invalid-admin-token')).status, 401);
    return Object.freeze({ status: adminResponse.status, completed: challenge.completedObjectiveCount, verdict: judgment.verdict });
  } finally { if (server) await new Promise(resolve => server.close(resolve)); }
}

module.exports = { qualifyAuditAdminRead };
