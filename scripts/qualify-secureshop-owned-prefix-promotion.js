'use strict';

// Identity/SecureShop-agents-only verifier for the reserved owned-effect
// migration prefix. The outer launcher owns quiescence and backup/restore.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { requiredStoreManifest } = require('../db/postgres/initialize-application');

const ROOT = path.resolve(__dirname, '..');
const PRIVATE_CONFIG_DIGEST_VARIABLE = 'DVAIA_EXPECTED_PRIVATE_CONFIG_SHA256';
const EXPECTED_HEADS = Object.freeze({
  identity: Object.freeze({ name: '0053_codebot_request_journal.sql',
    checksum: '25958c7c062ea915134000eef60202fc6ec7cb187e8f93064e900c0074cfa712' }),
  secureshop_agents: Object.freeze({ name: '0013_secureshop_conversation_purpose.sql',
    checksum: '4446bed59d6734d19066f5ef8486e3c254dbb90681c2a155edecf57949682b9d' }),
});

function assertPrivateConfigBytes(env = process.env, dependencies = {}) {
  const expected = env[PRIVATE_CONFIG_DIGEST_VARIABLE];
  if (!/^[a-f0-9]{64}$/.test(expected || '')) throw Object.assign(new Error('private configuration digest is required'), { code: 'PRIVATE_CONFIG_DIGEST_REQUIRED' });
  const bytes = (dependencies.readFile || fs.readFileSync)(dependencies.configPath || path.join(ROOT, '.env'));
  if (crypto.createHash('sha256').update(bytes).digest('hex') !== expected) throw Object.assign(new Error('private configuration changed during qualification'), { code: 'PRIVATE_CONFIG_CHANGED' });
}
function migrationDirectory(store) {
  return store === 'identity' ? path.join(ROOT, 'db/postgres/identity-migrations')
    : path.join(ROOT, `db/postgres/workshop-migrations/${store}`);
}
async function initializeOwnedStores(dependencies = {}) {
  const createPool = dependencies.createPool || require('../server/database/postgres').createPool;
  const identityRuntime = createPool(process.env, 'IDENTITY_DATABASE_URL');
  const identityMigration = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
  const agentsRuntime = createPool(process.env, 'SECURESHOP_AGENTS_DATABASE_URL');
  const agentsMigration = createPool(process.env, 'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL');
  try {
    const identity = await (dependencies.initializeIdentityRepository
      || require('../server/database/postgres/identityRepository').initializeIdentityRepository)(identityRuntime, identityMigration);
    const agents = await (dependencies.initializeSecureShopAgentsDb
      || require('../server/database/postgres/secureshopAgentsDb').initializeSecureShopAgentsDb)({ runtimePool: agentsRuntime, migrationPool: agentsMigration });
    return Object.freeze({ identity, secureshop_agents: agents ?? null });
  } finally { await Promise.allSettled([identityRuntime.end(), identityMigration.end(), agentsRuntime.end(), agentsMigration.end()]); }
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
      if (JSON.stringify(actual) !== JSON.stringify(expected)) throw Object.assign(new Error(`migration ledger differs for ${row.schema}`), { code: 'LEDGER_MISMATCH' });
      result[row.schema] = Object.freeze({ applied, count: actual.length, head: actual.at(-1) || null, ledger: Object.freeze(actual) });
    } finally { await pool.end(); }
  }
  for (const [store, head] of Object.entries(requireOwnedHeads ? EXPECTED_HEADS : {})) {
    if (JSON.stringify(result[store]?.head) !== JSON.stringify(head)) throw Object.assign(new Error(`${store} migration head differs`), { code: 'LEDGER_HEAD_MISMATCH' });
  }
  return Object.freeze(result);
}
async function schemaReadiness(dependencies = {}) {
  const createPool = dependencies.createPool || require('../server/database/postgres').createPool;
  const identity = createPool(process.env, 'IDENTITY_DATABASE_URL');
  const agents = createPool(process.env, 'SECURESHOP_AGENTS_DATABASE_URL');
  try {
    const relations = [
      ['identity', 'identity.secureshop_target_reservations'],
      ['identity', 'graph_runtime.codebot_requests'],
      ['secureshop_agents', 'secureshop_agents.bound_mcp_targets'],
      ['secureshop_agents', 'secureshop_agents.bound_mcp_invocations'],
      ['secureshop_agents', 'secureshop_agents.bound_ssrf_targets'],
      ['secureshop_agents', 'secureshop_agents.agent_sessions'],
    ];
    const found = [];
    for (const [store, relation] of relations) {
      const pool = store === 'identity' ? identity : agents;
      const row = (await pool.query(`SELECT to_regclass($1)::text AS name,
        has_table_privilege(current_user,$1,'SELECT') AS can_select`, [relation])).rows[0];
      if (row?.name !== relation || row.can_select !== true) throw Object.assign(new Error('owned SecureShop prefix schema or runtime privilege is unavailable'), { code: 'READINESS_FAILED' });
      found.push(Object.freeze({ store, relation }));
    }
    return Object.freeze({ ready: true, relations: Object.freeze(found) });
  } finally { await Promise.allSettled([identity.end(), agents.end()]); }
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
if (require.main === module) main(process.argv[2]).then(result => process.stdout.write(`SECURESHOP_OWNED_PREFIX_PROMOTION=${JSON.stringify(result)}\n`)).catch(error => {
  process.stderr.write(`SecureShop owned prefix promotion check failed: ${error.code || error.name}\n`); process.exitCode = 1;
});
module.exports = { PRIVATE_CONFIG_DIGEST_VARIABLE, EXPECTED_HEADS, assertPrivateConfigBytes,
  migrationDirectory, initializeOwnedStores, inspectStores, schemaReadiness, main };
