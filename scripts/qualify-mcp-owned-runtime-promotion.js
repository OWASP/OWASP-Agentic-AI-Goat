'use strict';

// Identity/MCP-only promotion verifier. Unlike initialize-application, this
// never invokes workshop catalog seeding and never initializes unrelated
// stores. The outer one-use launcher owns quiescence and backup/restore.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { repositories, requiredStoreManifest } = require('../db/postgres/initialize-application');

const ROOT = path.resolve(__dirname, '..');
const PRIVATE_CONFIG_DIGEST_VARIABLE = 'OWASP_AI_GOAT_EXPECTED_PRIVATE_CONFIG_SHA256';
const EXPECTED_HEADS = Object.freeze({
  identity: Object.freeze({ name: '0050_mcp_conversation_history.sql',
    checksum: 'fde6cc519c887b481668d02d44bacad7976bbc8b604cf2a65e3fd5ac7dbd0d1f' }),
  mcp: Object.freeze({ name: '0004_mcp_owned_resources.sql',
    checksum: '30b9980f2ad0e37be8134a9868c00190b2590f4ce8e0e11c1d2d4fbc3c86ae6d' }),
});

function assertPrivateConfigBytes(env = process.env, dependencies = {}) {
  const expected = env[PRIVATE_CONFIG_DIGEST_VARIABLE];
  if (!/^[a-f0-9]{64}$/.test(expected || '')) {
    throw Object.assign(new Error('private configuration digest is required'), { code: 'PRIVATE_CONFIG_DIGEST_REQUIRED' });
  }
  const bytes = (dependencies.readFile || fs.readFileSync)(dependencies.configPath || path.join(ROOT, '.env'));
  if (crypto.createHash('sha256').update(bytes).digest('hex') !== expected) {
    throw Object.assign(new Error('private configuration changed during qualification'), { code: 'PRIVATE_CONFIG_CHANGED' });
  }
}
function migrationDirectory(store) {
  return store === 'identity' ? path.join(ROOT, 'db/postgres/identity-migrations')
    : path.join(ROOT, `db/postgres/workshop-migrations/${store}`);
}
async function initializeOwnedStores(dependencies = {}) {
  const createPool = dependencies.createPool || require('../server/database/postgres').createPool;
  const identityRuntime = createPool(process.env, 'IDENTITY_DATABASE_URL');
  const identityMigration = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
  const mcpRuntime = createPool(process.env, 'MCP_WORKSHOP_DATABASE_URL');
  const mcpMigration = createPool(process.env, 'MCP_WORKSHOP_MIGRATION_DATABASE_URL');
  try {
    const identity = await (dependencies.initializeIdentityRepository
      || require('../server/database/postgres/identityRepository').initializeIdentityRepository)(identityRuntime, identityMigration);
    const database = (dependencies.createMcpWorkshopDb
      || require('../server/database/postgres/mcpWorkshopDb').createMcpWorkshopDb)(mcpRuntime);
    const mcp = await database.initialize(mcpMigration);
    return Object.freeze({ identity, mcp: mcp ?? [] });
  } finally { await Promise.allSettled([identityRuntime.end(), identityMigration.end(), mcpRuntime.end(), mcpMigration.end()]); }
}
async function inspectStores({ replay = false, requireOwnedHeads = true, dependencies = {} } = {}) {
  const createPool = dependencies.createPool || require('../server/database/postgres').createPool;
  const migration = dependencies.migrate && dependencies.readMigrations ? dependencies : require('../db/postgres/migrate');
  const result = {};
  for (const row of requiredStoreManifest) {
    const pool = createPool(process.env, row.migrationVariable);
    try {
      const directory = migrationDirectory(row.schema);
      const applied = replay ? await migration.migrate(pool, directory) : [];
      const actual = (await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
      const expected = (await migration.readMigrations(directory)).map(({ name, checksum }) => ({ name, checksum }));
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        throw Object.assign(new Error(`migration ledger differs for ${row.schema}`), { code: 'LEDGER_MISMATCH' });
      }
      result[row.schema] = Object.freeze({ applied, count: actual.length,
        head: actual.at(-1) || null, ledger: Object.freeze(actual) });
    } finally { await pool.end(); }
  }
  for (const [store, head] of Object.entries(requireOwnedHeads ? EXPECTED_HEADS : {})) {
    if (JSON.stringify(result[store]?.head) !== JSON.stringify(head)) {
      throw Object.assign(new Error(`${store} migration head differs`), { code: 'LEDGER_HEAD_MISMATCH' });
    }
  }
  return Object.freeze(result);
}
async function schemaReadiness(dependencies = {}) {
  const createPool = dependencies.createPool || require('../server/database/postgres').createPool;
  const identity = createPool(process.env, 'IDENTITY_DATABASE_URL');
  const mcp = createPool(process.env, 'MCP_WORKSHOP_DATABASE_URL');
  try {
    const conversationsReady = await (dependencies.conversationReadiness
      || require('../server/services/mcp/ownedResourceProduction').conversationReadiness)(identity);
    const relations = ['mcp.runner_targets','mcp.runner_target_cleanups','mcp.mail_intents','mcp.mail_cleanups'];
    const found = [];
    for (const relation of relations) {
      const row = (await mcp.query(`SELECT to_regclass($1)::text AS name,
        has_table_privilege(current_user,$1,'SELECT') AS can_select,
        has_table_privilege(current_user,$1,'INSERT') AS can_insert,
        has_table_privilege(current_user,$1,'UPDATE') AS can_update`, [relation])).rows[0];
      if (row?.name !== relation || row.can_select !== true || row.can_insert !== true || row.can_update !== true) {
        throw Object.assign(new Error('owned MCP schema or runtime privilege is unavailable'), { code: 'READINESS_FAILED' });
      }
      found.push(relation);
    }
    if (conversationsReady !== true) throw Object.assign(new Error('MCP conversation schema is unavailable'), { code: 'READINESS_FAILED' });
    return Object.freeze({ ready: true, conversationsReady, resourceRelations: Object.freeze(found) });
  } finally { await Promise.allSettled([identity.end(), mcp.end()]); }
}
async function main(argument) {
  assertPrivateConfigBytes(); require('dotenv').config({ quiet: true }); assertPrivateConfigBytes();
  let result;
  if (argument === '--initialize') result = await initializeOwnedStores();
  else if (argument === '--prerequisites') result = await inspectStores({ requireOwnedHeads: false });
  else if (argument === '--ledger') result = await inspectStores();
  else if (argument === '--replay') result = await inspectStores({ replay: true });
  else if (argument === '--readiness') result = await schemaReadiness();
  else throw Object.assign(new Error('Use --prerequisites, --initialize, --ledger, --replay or --readiness'), { code: 'INVALID_ARGUMENT' });
  assertPrivateConfigBytes(); return result;
}

if (require.main === module) main(process.argv[2]).then(result => {
  process.stdout.write(`MCP_OWNED_RUNTIME_PROMOTION=${JSON.stringify(result)}\n`);
}).catch(error => {
  process.stderr.write(`MCP owned runtime promotion check failed: ${error.code || error.name}\n`); process.exitCode = 1;
});

module.exports = { PRIVATE_CONFIG_DIGEST_VARIABLE, EXPECTED_HEADS, assertPrivateConfigBytes,
  migrationDirectory, initializeOwnedStores, inspectStores, schemaReadiness, main };
