'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');

function fixture(deletionService) {
  let directDeletes = 0;
  const pass = (_req, _res, next) => next();
  const auth = { authenticateToken(req, _res, next) { req.user = { id: 2, admin_level: 2 }; next(); },
    requireAdminLevel: () => pass, requirePermission: () => pass, logActivity: () => pass };
  const repository = new Proxy({ deleteUser: async () => { directDeletes += 1; } }, {
    get(target, key) { return key in target ? target[key] : async () => []; },
  });
  const stores = { config: {}, progress: {} };
  const handler = (_req, res) => res.json({});
  const operational = Object.fromEntries(['providerStatus', 'switchProvider', 'configureProvider',
    'testProvider', 'testLlm', 'appLogs', 'llmLogs', 'logStats', 'systemMonitoring']
    .map(name => [name, handler]));
  const router = createPostgresAdminRouter({ adapter: {}, stores, auth, repository,
    resetService: {}, operational, xssLegacyRepository: {}, deletionService });
  const app = express(); app.use(express.json()); app.use('/api/admin', router);
  return { app, directDeletes: () => directDeletes };
}
async function listen(app, t) {
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

test('PostgreSQL admin deletion uses the journal service and preserves the terminal success response', async t => {
  const calls = [];
  const f = fixture({ async deleteStudent(input) { calls.push(input); return {
    completed: true, jobId: '11111111-1111-4111-8111-111111111111',
  }; } });
  const response = await fetch(`${await listen(f.app, t)}/api/admin/students/7`, { method: 'DELETE' });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { success: true, message: 'Student deleted successfully',
    jobId: '11111111-1111-4111-8111-111111111111' });
  assert.deepEqual(calls, [{ requesterId: 2, subjectId: '7' }]);
  assert.equal(f.directDeletes(), 0);
});

test('pending cleanup returns an error and cannot fall back to direct identity deletion', async t => {
  const f = fixture({ async deleteStudent() { throw Object.assign(new Error('Student deletion is pending cleanup'), {
    code: 'DELETION_UNAVAILABLE', statusCode: 503,
  }); } });
  const response = await fetch(`${await listen(f.app, t)}/api/admin/students/7`, { method: 'DELETE' });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Student deletion is pending cleanup',
    code: 'DELETION_UNAVAILABLE' });
  assert.equal(f.directDeletes(), 0);
});

test('both PostgreSQL initialization aliases remain fail-closed without legacy imports or writes', async t => {
  const Module=require('node:module'),original=Module._load;
  const f=fixture({deleteStudent:async()=>{throw Error('Unexpected mutation');}});
  const base=await listen(f.app,t);
  Module._load=function(request,...rest){
    if(request.includes('initialize-db')||request.includes('initialize-application'))throw Error('Initializer import forbidden');
    return original.call(this,request,...rest);
  };
  try {
    for(const endpoint of ['initialize','initilize']) {
      const response=await fetch(`${base}/api/admin/database/${endpoint}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({confirmPassword:'controlled-not-used'})});
      assert.equal(response.status,409);
      assert.deepEqual(await response.json(),{success:false,error:'PostgreSQL schema migrations must run through the migration command'});
    }
    assert.equal(f.directDeletes(),0);
  } finally {Module._load=original;}
});
