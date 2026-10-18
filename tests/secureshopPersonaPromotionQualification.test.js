'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EXPECTED_NAMES, assertPersonaReadiness } = require('../scripts/qualify-secureshop-persona-promotion');

test('persona promotion uses the complete normal initializer manifest', () => {
  const configured = require('../db/postgres/initialize-application').requiredStoreManifest.map(row => row.schema);
  assert.deepEqual(EXPECTED_NAMES, configured);
  assert.equal(EXPECTED_NAMES.length, 16);
  assert.ok(EXPECTED_NAMES.includes('identity'));
  assert.ok(EXPECTED_NAMES.includes('secureshop_agents'));
});

test('persona promotion readiness requires structure and preserves hidden defaults', async () => {
  const pools = [];
  const result = await assertPersonaReadiness({
    createPool(_env, selector) {
      const pool = { selector, async end() { pool.closed = true; } };
      pools.push(pool);
      return pool;
    },
    async closePostgresPools() {},
    async assertPersonaInboxReadiness({ identityPool, agentsPool }) {
      assert.equal(identityPool.selector, 'IDENTITY_DATABASE_URL');
      assert.equal(agentsPool.selector, 'SECURESHOP_AGENTS_DATABASE_URL');
    },
    createSecureShopPersonaInboxAvailability(identityPool) {
      assert.equal(identityPool.selector, 'IDENTITY_DATABASE_URL');
      return { async read() { return { registered: true, visible: false, enabled: new Set() }; } };
    },
  });
  assert.deepEqual(result, { ready: true, registered: true, visible: false, enabledObjectives: [] });
  assert.ok(pools.every(pool => pool.closed));
});

test('persona promotion readiness rejects visible or enabled catalog state and still closes pools', async () => {
  const pools = [];
  await assert.rejects(assertPersonaReadiness({
    createPool() {
      const pool = { async end() { pool.closed = true; } };
      pools.push(pool);
      return pool;
    },
    async closePostgresPools() {},
    async assertPersonaInboxReadiness() {},
    createSecureShopPersonaInboxAvailability() {
      return { async read() { return { registered: true, visible: true, enabled: new Set(['ss_cross_persona_effect']) }; } };
    },
  }), { code: 'PERSONA_INBOX_DEFAULTS_CHANGED' });
  assert.ok(pools.every(pool => pool.closed));
});
