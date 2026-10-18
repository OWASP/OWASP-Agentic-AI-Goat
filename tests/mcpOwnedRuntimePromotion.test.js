'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const promotion = require('../scripts/qualify-mcp-owned-runtime-promotion');

test('promotion helper requires and rechecks the exact private config bytes', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-mcp-promotion-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const configPath = path.join(directory, '.env'); const bytes = Buffer.from(`JWT_SECRET=${'s'.repeat(48)}\n`);
  await fs.writeFile(configPath, bytes, { mode: 0o600 });
  const expected = crypto.createHash('sha256').update(bytes).digest('hex');
  assert.doesNotThrow(() => promotion.assertPrivateConfigBytes(
    { DVAIA_EXPECTED_PRIVATE_CONFIG_SHA256: expected }, { configPath }));
  assert.throws(() => promotion.assertPrivateConfigBytes({}, { configPath }),
    { code: 'PRIVATE_CONFIG_DIGEST_REQUIRED' });
  await fs.appendFile(configPath, 'changed=true\n');
  assert.throws(() => promotion.assertPrivateConfigBytes(
    { DVAIA_EXPECTED_PRIVATE_CONFIG_SHA256: expected }, { configPath }), { code: 'PRIVATE_CONFIG_CHANGED' });
});

test('identity and MCP normal initializers run without the application seed or unrelated stores', async () => {
  const opened = []; const closed = [];
  const pools = new Map();
  const createPool = (_env, variable) => {
    opened.push(variable);
    const pool = { variable, async end() { closed.push(variable); } }; pools.set(variable, pool); return pool;
  };
  const result = await promotion.initializeOwnedStores({ createPool,
    async initializeIdentityRepository(runtime, migration) {
      assert.equal(runtime.variable, 'IDENTITY_DATABASE_URL');
      assert.equal(migration.variable, 'IDENTITY_MIGRATION_DATABASE_URL');
      return ['0050_mcp_conversation_history.sql'];
    },
    createMcpWorkshopDb(runtime) {
      assert.equal(runtime.variable, 'MCP_WORKSHOP_DATABASE_URL');
      return { async initialize(migration) {
        assert.equal(migration.variable, 'MCP_WORKSHOP_MIGRATION_DATABASE_URL'); return undefined;
      } };
    },
  });
  assert.deepEqual(result, { identity: ['0050_mcp_conversation_history.sql'], mcp: [] });
  assert.deepEqual(opened, ['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL',
    'MCP_WORKSHOP_DATABASE_URL','MCP_WORKSHOP_MIGRATION_DATABASE_URL']);
  assert.deepEqual([...closed].sort(), [...opened].sort());
  const source = await fs.readFile(require.resolve('../scripts/qualify-mcp-owned-runtime-promotion'), 'utf8');
  assert.doesNotMatch(source, /seedWorkshopPlatform|initializeApplication\s*\(/);
});

test('schema readiness requires exact conversation and all four runtime-owned relations', async () => {
  const ended = []; const relations = new Set(['mcp.runner_targets','mcp.runner_target_cleanups','mcp.mail_intents','mcp.mail_cleanups']);
  const createPool = (_env, variable) => ({
    async query(_sql, params) {
      const relation = params[0];
      if (!relations.has(relation)) throw new Error('unexpected relation');
      return { rows: [{ name: relation, can_select: true, can_insert: true, can_update: true }] };
    }, async end() { ended.push(variable); },
  });
  const result = await promotion.schemaReadiness({ createPool, conversationReadiness: async () => true });
  assert.equal(result.ready, true); assert.deepEqual(result.resourceRelations, [...relations]);
  assert.deepEqual(ended.sort(), ['IDENTITY_DATABASE_URL','MCP_WORKSHOP_DATABASE_URL']);

  relations.delete('mcp.mail_cleanups');
  await assert.rejects(promotion.schemaReadiness({ createPool, conversationReadiness: async () => true }),
    /unexpected relation|READINESS_FAILED/);
});

test('promotion pins the already-qualified forward migration heads', () => {
  assert.deepEqual(promotion.EXPECTED_HEADS, {
    identity: { name: '0050_mcp_conversation_history.sql',
      checksum: 'fde6cc519c887b481668d02d44bacad7976bbc8b604cf2a65e3fd5ac7dbd0d1f' },
    mcp: { name: '0004_mcp_owned_resources.sql',
      checksum: '30b9980f2ad0e37be8134a9868c00190b2590f4ce8e0e11c1d2d4fbc3c86ae6d' },
  });
});

test('prerequisite ledger inspection verifies all stores without pretending draft heads are installed', async () => {
  const dependencies = {
    createPool() { return { async query() { return { rows: [{ name: 'existing.sql', checksum: 'a'.repeat(64) }] }; }, async end() {} }; },
    async readMigrations() { return [{ name: 'existing.sql', checksum: 'a'.repeat(64) }]; },
    async migrate() { throw new Error('prerequisite inspection must be read-only'); },
  };
  const result = await promotion.inspectStores({ requireOwnedHeads: false, dependencies });
  assert.equal(Object.keys(result).length, 16);
  assert.deepEqual(result.identity.ledger, [{ name: 'existing.sql', checksum: 'a'.repeat(64) }]);
  await assert.rejects(promotion.inspectStores({ dependencies }), { code: 'LEDGER_HEAD_MISMATCH' });
});
