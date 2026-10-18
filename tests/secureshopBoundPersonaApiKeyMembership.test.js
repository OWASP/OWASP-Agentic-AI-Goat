'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundPersonaRepository } = require('../server/database/postgres/secureshopBoundPersonaRepository');

const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000083',
  scenarioId: '20000000-0000-4000-8000-000000000083', generation: 6,
  platformOwnerId: 83, platformSessionId: 803 });
const key = 'sk_ss_live_11111111111111111111111111111111';

function repositoryForMembership(admitted) {
  const queries = [];
  const client = {
    async query(text, values = []) {
      queries.push({ text, values });
      if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(text) || text.includes('pg_advisory_xact_lock')) {
        return { rows: [], rowCount: 0 };
      }
      if (text.includes('SELECT base_role AS role FROM secureshop_agents.bound_actor_identities')) {
        assert.match(text, /bound_actor_in_owner\(shop_user_id,\$2\)/);
        assert.deepEqual(values, [1000000083, scope.platformOwnerId]);
        return { rows: admitted ? [{ role: 'customer' }] : [], rowCount: admitted ? 1 : 0 };
      }
      if (text.includes('SELECT api_key_version')) return { rows: [], rowCount: 0 };
      if (text.includes('INSERT INTO secureshop_agents.bound_persona_api_keys')) {
        return { rows: [{ api_key_plaintext: key, api_key_version: 1,
          created_at: '2026-10-10T00:00:00.000Z', rotated_at: '2026-10-10T00:00:00.000Z' }], rowCount: 1 };
      }
      if (text.includes('FROM secureshop_agents.bound_persona_api_keys k')) {
        assert.match(text, /k\.original_platform_owner_id=\$4/);
        assert.match(text, /k\.original_platform_session_id=\$5/);
        assert.match(text, /k\.api_key_sha256=\$6/);
        assert.match(text, /bound_actor_in_owner\(t\.shop_user_id,\$7\)/);
        assert.equal(values.at(-1), scope.platformOwnerId);
        return { rows: admitted ? [{ id: 1000000083, username: 'registered_customer',
          email: 'registered@example.invalid', role: 'customer', original_platform_owner_id: 17,
          api_key_version: 1 }] : [], rowCount: admitted ? 1 : 0 };
      }
      throw new Error(`Unexpected query: ${text}`);
    },
    release() {},
  };
  return { queries, repository: createSecureShopBoundPersonaRepository({
    commercePool: { async query() { return { rows: [] }; } },
    agentsPool: { async query() { return { rows: [] }; }, async connect() { return client; } },
  }) };
}

test('registered tenant member can rotate and authenticate a key through canonical owner admission', async () => {
  const { repository } = repositoryForMembership(true);
  const rotated = await repository.rotateApiKey({ scope, shopUserId: 1000000083, nextKey: key });
  assert.equal(rotated.apiKey, key);
  assert.equal(rotated.version, 1);
  assert.deepEqual(await repository.authenticateApiKey({ scope, presentedKey: key }), {
    id: 1000000083, username: 'registered_customer', email: 'registered@example.invalid',
    role: 'customer', full_name: null, phone: null, apiKeyVersion: 1,
  });
});

test('unrelated or revoked tenant membership cannot rotate or authenticate a scoped API key', async () => {
  const { repository } = repositoryForMembership(false);
  await assert.rejects(repository.rotateApiKey({ scope, shopUserId: 1000000083, nextKey: key }),
    { code: 'SHOP_PERSONA_UNAVAILABLE' });
  assert.equal(await repository.authenticateApiKey({ scope, presentedKey: key }), null);
});
