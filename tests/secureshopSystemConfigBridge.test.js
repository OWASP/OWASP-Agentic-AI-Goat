'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

test('bound config bridge preserves traversal and operation identity without accepting authority', async () => {
  const { compileOperation } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  const operationId = '11111111-1111-4111-8111-111111111111';
  const body = { operationId, path: '....//.env' };
  const request = compileOperation('admin.system.configRead', { body });
  assert.equal(request.path, '/api/secureshop/admin/system/config-read');
  assert.deepEqual(request.body, body);
  assert.throws(() => compileOperation('admin.system.configRead', { body: { ...body, scope: { owner: 7 } } }));
  const recovery = compileOperation('admin.system.configReadOperation', { params: { operationId } });
  assert.equal(compileOperation('admin.system.configReadAdministration', {}).method, 'GET');
  assert.throws(() => compileOperation('admin.system.configReadAdministration', { query: { scope: 'forged' } }));
  assert.equal(recovery.method, 'GET');
  assert.equal(recovery.path, `/api/secureshop/admin/system/config-operations/${operationId}`);
  assert.throws(() => compileOperation('admin.system.configReadOperation', { params: { operationId }, query: { owner: 7 } }));
  assert.deepEqual(compileOperation('admin.system.readConfig', { body: { path: '.env' } }).body, { path: '.env' });
  assert.throws(() => compileOperation('admin.system.readConfig', { body }));
});
