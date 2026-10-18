'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const bcrypt = require('bcryptjs');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');

test('admin log cleanup never resets workshops and reset requests require the current password', async t => {
  let resetCalls = 0, logCalls = 0;
  const password = 'Disposable-Admin-Password';
  const hash = await bcrypt.hash(password, 4);
  const adapter = { repository: {
    recordAudit: async () => {},
    findCredentialById: async () => ({ password: hash }),
    // This test isolates reset dispatch/password behavior. Supply the current
    // permission repository contract so a permitted challenge reset reaches it.
    hasPermission: async () => true,
  },
    validateSession: async token => ({ user: { id: 1, username: 'fixture', role: token === 'student' ? 'student' : 'super_admin', admin_level: token === 'student' ? 0 : 2 }, session: {} }) };
  const noop = (_req, res) => res.sendStatus(501);
  const operational = Object.fromEntries(['providerStatus', 'switchProvider', 'configureProvider', 'testProvider', 'testLlm', 'appLogs', 'llmLogs', 'logStats', 'systemMonitoring'].map(key => [key, noop]));
  const app = express(); app.use(express.json());
  app.use('/admin', createPostgresAdminRouter({ adapter, auth: createPostgresAdminAuth(adapter), stores: { config: {}, progress: {} },
    repository: { clearOldActivityLogs: async () => { logCalls++; return 4; } },
    resetService: { resetAll: async () => { resetCalls++; } }, xssLegacyRepository: {}, operational }));
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const request = async (body, token = 'admin', endpoint = '/database/reset') => {
    const res = await fetch(`http://127.0.0.1:${server.address().port}/admin${endpoint}`, { method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: res.status, body: await res.json() };
  };
  for (const resetType of ['full', 'unknown', undefined]) assert.equal((await request({ resetType, confirmPassword: password })).status, 400);
  assert.equal((await request({ resetType: 'logs' })).status, 400);
  assert.equal((await request({ resetType: 'challenges', confirmPassword: 'wrong' })).status, 403);
  assert.equal((await request({ resetType: 'logs', confirmPassword: password }, 'student')).status, 403);
  for (const endpoint of ['/system/reset', '/workshops/reset-all-progress']) {
    assert.equal((await request({}, 'admin', endpoint)).status, 409);
    assert.equal((await request({ confirmPassword: password }, 'admin', endpoint)).status, 409);
  }
  assert.equal(resetCalls, 0); assert.equal(logCalls, 0);
  const logs = await request({ resetType: 'logs', confirmPassword: password });
  assert.equal(logs.status, 200); assert.equal(logs.body.results.deletedActivityLogs, 4);
  assert.equal(resetCalls, 0); assert.equal(logCalls, 1);
  const reset = await request({ resetType: 'challenges', confirmPassword: password });
  assert.equal(reset.status, 200); assert.equal(resetCalls, 1); assert.equal(logCalls, 1);
  assert.match(reset.body.message, /No backup was created/);
});
