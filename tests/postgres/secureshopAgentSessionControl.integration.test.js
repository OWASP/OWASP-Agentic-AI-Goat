'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createPool } = require('../../server/database/postgres');
const { migrate } = require('../../db/postgres/migrate');
const { createSecureShopAgentsDb } = require('../../server/database/postgres/secureshopAgentsDb');
const { agentSessionControl } = require('../../server/routes/secureshop/_agentSessionControl');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_SECURESHOP_AGENT_CONTROL_TEST_MIGRATION_URL
  && process.env.PG_SECURESHOP_AGENT_CONTROL_TEST_RUNTIME_URL;

test('native PostgreSQL session metadata enforces owner and role', { skip: !enabled }, async () => {
  for (const key of ['PG_SECURESHOP_AGENT_CONTROL_TEST_MIGRATION_URL', 'PG_SECURESHOP_AGENT_CONTROL_TEST_RUNTIME_URL']) {
    assert.match(new URL(process.env[key]).pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  }
  const migrationPool = createPool(process.env, 'PG_SECURESHOP_AGENT_CONTROL_TEST_MIGRATION_URL');
  const runtimePool = createPool(process.env, 'PG_SECURESHOP_AGENT_CONTROL_TEST_RUNTIME_URL');
  try {
    await migrate(migrationPool, path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_agents'));
    const db = createSecureShopAgentsDb(runtimePool);
    await db.createSession('native-owner-session', 41, 'customer');
    assert.deepEqual(await db.getSession('native-owner-session'), {
      id: 'native-owner-session', userId: 41, role: 'customer',
    });

    const control = agentSessionControl('customer', db);
    const authorize = async (ssUser) => {
      const req = { ssUser, params: { sessionId: 'native-owner-session' }, body: {} };
      const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json() { return this; } };
      let allowed = false;
      await control.requireOwned(req, res, () => { allowed = true; });
      return { allowed, status: res.statusCode };
    };
    assert.deepEqual(await authorize({ id: 41, role: 'customer' }), { allowed: true, status: 200 });
    assert.deepEqual(await authorize({ id: 42, role: 'customer' }), { allowed: false, status: 404 });
    assert.deepEqual(await authorize({ id: 41, role: 'merchant' }), { allowed: false, status: 404 });
  } finally {
    await Promise.all([runtimePool.end(), migrationPool.end()]);
  }
});
