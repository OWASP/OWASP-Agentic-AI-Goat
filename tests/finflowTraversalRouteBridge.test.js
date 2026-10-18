'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');

const previous = { exportInternals: process.env.EXPORT_INTERNALS,
  platformEngine: process.env.PLATFORM_DATABASE_ENGINE,
  workshopEngine: process.env.WORKSHOP_DATABASE_ENGINE,
  identityUrl: process.env.IDENTITY_DATABASE_URL,
  jwtSecret: process.env.JWT_SECRET };
Object.assign(process.env, { EXPORT_INTERNALS: '1', PLATFORM_DATABASE_ENGINE: 'postgres',
  WORKSHOP_DATABASE_ENGINE: 'postgres',
  IDENTITY_DATABASE_URL: 'postgresql://preflight@127.0.0.1:1/preflight',
  JWT_SECRET: 'finflow-route-bridge-test-secret-over-32-bytes' });
const route = require('../server/routes/sensitiveInfoWorkshop');
for (const [name, value] of Object.entries({ EXPORT_INTERNALS: previous.exportInternals,
  PLATFORM_DATABASE_ENGINE: previous.platformEngine,
  WORKSHOP_DATABASE_ENGINE: previous.workshopEngine,
  IDENTITY_DATABASE_URL: previous.identityUrl, JWT_SECRET: previous.jwtSecret })) {
  if (value === undefined) delete process.env[name]; else process.env[name] = value;
}

test('route-configured traversal bridge exposes and delegates every agent traversal method', async () => {
  const calls = [];
  const manager = {
    read: async input => { calls.push(['read', input]); return 'traversal'; },
    readAdminConfig: async input => { calls.push(['readAdminConfig', input]); return 'config'; },
    listAdminDirectory: async input => { calls.push(['listAdminDirectory', input]); return 'listing'; },
  };
  const bridge = route.createRouteTraversalManager(async () => ({ traversalManager: manager }));
  const inputs = [{ tool: 'traversal' }, { tool: 'admin_view_config' },
    { tool: 'admin_list_directory_or_admin_system_info' }];
  assert.equal(await bridge.read(inputs[0]), 'traversal');
  assert.equal(await bridge.readAdminConfig(inputs[1]), 'config');
  assert.equal(await bridge.listAdminDirectory(inputs[2]), 'listing');
  assert.deepEqual(calls, [
    ['read', inputs[0]], ['readAdminConfig', inputs[1]], ['listAdminDirectory', inputs[2]],
  ]);
  assert.deepEqual(Object.keys(route.configuredTraversalManager).sort(),
    ['listAdminDirectory', 'read', 'readAdminConfig']);
});

test('route traversal bridge preserves typed readiness failure for every method', async () => {
  const bridge = route.createRouteTraversalManager(async () => ({ traversalManager: {
    read: async () => null,
  } }));
  for (const method of ['read', 'readAdminConfig', 'listAdminDirectory']) {
    await assert.rejects(bridge[method]({}), {
      code: 'TRAVERSAL_TARGET_STORAGE_NOT_READY', statusCode: 503,
    });
  }
});
