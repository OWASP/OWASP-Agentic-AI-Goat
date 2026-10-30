'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const verifier = require('../scripts/qualify-secureshop-owned-prefix-promotion');

test('reserved promotion heads bind the exact ordered prefix tips', () => {
  assert.deepEqual(verifier.EXPECTED_HEADS, {
    identity: { name: '0053_codebot_request_journal.sql', checksum: '25958c7c062ea915134000eef60202fc6ec7cb187e8f93064e900c0074cfa712' },
    secureshop_agents: { name: '0013_secureshop_conversation_purpose.sql', checksum: '4446bed59d6734d19066f5ef8486e3c254dbb90681c2a155edecf57949682b9d' },
  });
});

test('private configuration digest is mandatory and byte exact', () => {
  const bytes = Buffer.from('private qualification configuration');
  const expected = crypto.createHash('sha256').update(bytes).digest('hex');
  assert.doesNotThrow(() => verifier.assertPrivateConfigBytes({
    OWASP_AI_GOAT_EXPECTED_PRIVATE_CONFIG_SHA256: expected,
  }, { readFile: () => bytes }));
  assert.throws(() => verifier.assertPrivateConfigBytes({}, { readFile: () => bytes }),
    error => error.code === 'PRIVATE_CONFIG_DIGEST_REQUIRED');
  assert.throws(() => verifier.assertPrivateConfigBytes({
    OWASP_AI_GOAT_EXPECTED_PRIVATE_CONFIG_SHA256: '0'.repeat(64),
  }, { readFile: () => bytes }), error => error.code === 'PRIVATE_CONFIG_CHANGED');
});

test('normal owned-store initializers close all pools and report real results', async () => {
  const pools = [];
  const createPool = (_env, variable) => {
    const pool = { variable, ended: false, end: async () => { pool.ended = true; } };
    pools.push(pool); return pool;
  };
  const result = await verifier.initializeOwnedStores({
    createPool,
    initializeIdentityRepository: async (runtime, migration) => {
      assert.equal(runtime.variable, 'IDENTITY_DATABASE_URL');
      assert.equal(migration.variable, 'IDENTITY_MIGRATION_DATABASE_URL');
      return ['0051_secureshop_mcp_trust.sql', '0052_secureshop_controlled_ssrf.sql', '0053_codebot_request_journal.sql'];
    },
    initializeSecureShopAgentsDb: async ({ runtimePool, migrationPool }) => {
      assert.equal(runtimePool.variable, 'SECURESHOP_AGENTS_DATABASE_URL');
      assert.equal(migrationPool.variable, 'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL');
    },
  });
  assert.deepEqual(result, {
    identity: ['0051_secureshop_mcp_trust.sql', '0052_secureshop_controlled_ssrf.sql', '0053_codebot_request_journal.sql'],
    secureshop_agents: null,
  });
  assert.ok(pools.every(pool => pool.ended));
});

test('readiness queries every relation through its owning runtime database', async () => {
  const calls = [];
  const pools = new Map();
  const createPool = (_env, variable) => {
    const pool = {
      variable,
      query: async (_sql, [relation]) => {
        calls.push([variable, relation]);
        return { rows: [{ name: relation, can_select: true }] };
      },
      end: async () => {},
    };
    pools.set(variable, pool); return pool;
  };
  const result = await verifier.schemaReadiness({ createPool });
  assert.equal(result.ready, true);
  assert.deepEqual(calls, [
    ['IDENTITY_DATABASE_URL', 'identity.secureshop_target_reservations'],
    ['IDENTITY_DATABASE_URL', 'graph_runtime.codebot_requests'],
    ['SECURESHOP_AGENTS_DATABASE_URL', 'secureshop_agents.bound_mcp_targets'],
    ['SECURESHOP_AGENTS_DATABASE_URL', 'secureshop_agents.bound_mcp_invocations'],
    ['SECURESHOP_AGENTS_DATABASE_URL', 'secureshop_agents.bound_ssrf_targets'],
    ['SECURESHOP_AGENTS_DATABASE_URL', 'secureshop_agents.agent_sessions'],
  ]);
});
