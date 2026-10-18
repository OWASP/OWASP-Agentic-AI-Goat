'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');

function auth() {
  const allow = (_value) => (_req, _res, next) => next();
  return {
    authenticateToken(req, _res, next) { req.user = { id: 91, admin_level: 2 }; next(); },
    requireAdminLevel: allow,
    requirePermission: allow,
    logActivity: () => (_req, _res, next) => next(),
  };
}

test('authenticated admin reset forwards exact owner and durable operation ID', async (t) => {
  const calls = [];
  const studentLookups = [];
  const unusedHandler = (_req, res) => res.status(501).json({ error: 'unused fixture route' });
  const operational = Object.fromEntries([
    'providerStatus', 'switchProvider', 'configureProvider', 'testProvider', 'testLlm',
    'appLogs', 'llmLogs', 'logStats', 'systemMonitoring',
  ].map(name => [name, unusedHandler]));
  const app = express();
  app.use(express.json());
  app.use('/api/admin', createPostgresAdminRouter({
    adapter: {}, stores: { config: {}, progress: {} }, auth: auth(), repository: {
      async getMutableStudent(id) {
        studentLookups.push(id);
        return [73, 74].includes(Number(id)) ? { id: Number(id), role: 'student', admin_level: 0 } : null;
      },
    },
    resetService: {
      async resetAdministrativeStudent(input) {
        calls.push(input);
        return { operationId: input.operationId, status: 'completed' };
      },
    },
    operational, xssLegacyRepository: {}, deletionService: {},
  }));
  const server = await new Promise(resolve => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const operationId = '39c590ef-85ab-4dc3-8bf6-45e35ca19029';
  const response = await fetch(`http://127.0.0.1:${server.address().port}`
    + '/api/admin/students/73/workshops/sensitive_info_disclosure/reset', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-reset-operation-id': operationId },
    body: '{}',
  });
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  const {actorRequest, ...resetInput} = calls[0];
  assert.deepEqual(resetInput, { userId: '73', workshopKey: 'sensitive_info_disclosure', operationId });
  assert.equal(actorRequest.user.id, 91);
  assert.ok(Object.isFrozen(actorRequest));
  assert.deepEqual((await response.json()).result, { operationId, status: 'completed' });

  const withoutOperation = await fetch(`http://127.0.0.1:${server.address().port}`
    + '/api/admin/students/74/workshops/sensitive_info_disclosure/reset', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(withoutOperation.status, 200);
  assert.equal(calls[1].userId, '74');
  assert.equal(calls[1].workshopKey, 'sensitive_info_disclosure');
  assert.match(calls[1].operationId, /^[0-9a-f-]{36}$/);
  assert.equal(withoutOperation.headers.get('x-reset-operation-id'), calls[1].operationId);
  assert.equal(calls[1].actorRequest.user.id, 91);
  assert.deepEqual(studentLookups, ['73', '74'], 'both resets must validate their student target');
});
