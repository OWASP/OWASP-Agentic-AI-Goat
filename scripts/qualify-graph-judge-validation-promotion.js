'use strict';

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { repositories, requiredStoreManifest } = require('../db/postgres/initialize-application');

const ROOT = path.resolve(__dirname, '..');
const EXPECTED_NAMES = Object.freeze(repositories.map(([name]) => name));
const PRIVATE_CONFIG_DIGEST_VARIABLE = 'DVAIA_EXPECTED_PRIVATE_CONFIG_SHA256';

function assertPrivateConfigBytes(env = process.env, dependencies = {}) {
  const expected = env[PRIVATE_CONFIG_DIGEST_VARIABLE];
  if (!expected) return;
  const bytes = (dependencies.readFile || fs.readFileSync)(dependencies.configPath || path.join(ROOT, '.env'));
  if (crypto.createHash('sha256').update(bytes).digest('hex') !== expected) {
    throw Object.assign(new Error('private configuration changed during qualification'),
      { code: 'PRIVATE_CONFIG_CHANGED' });
  }
}

function migrationDirectory(store) {
  return store === 'identity' ? path.join(ROOT, 'db/postgres/identity-migrations')
    : path.join(ROOT, `db/postgres/workshop-migrations/${store}`);
}

async function inspectStores({ replay = false, dependencies = {} } = {}) {
  const createPool = dependencies.createPool || require('../server/database/postgres').createPool;
  const { migrate, readMigrations } = dependencies.migrate && dependencies.readMigrations
    ? dependencies : require('../db/postgres/migrate');
  const result = {};
  for (const row of requiredStoreManifest) {
    const pool = createPool(process.env, row.migrationVariable);
    try {
      const directory = migrationDirectory(row.schema);
      const applied = replay ? await migrate(pool, directory) : [];
      const actual = (await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
      const expected = (await readMigrations(directory)).map(({ name, checksum }) => ({ name, checksum }));
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        throw Object.assign(new Error('migration ledger does not match source'), { code: 'LEDGER_MISMATCH' });
      }
      result[row.schema] = { applied, count: actual.length,
        head: actual.length ? actual.at(-1) : null, ledger: actual };
    } finally { await pool.end(); }
  }
  return result;
}

async function readiness(dependencies = {}) {
  const createPool = dependencies.createPool || require('../server/database/postgres').createPool;
  const pool = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
  try {
    const rows = (await pool.query(`SELECT conname,pg_get_constraintdef(oid) AS definition
      FROM pg_constraint WHERE connamespace='graph_runtime'::regnamespace
      AND conname IN ('events_metadata_keys_check','events_validation_code_check') ORDER BY conname`)).rows;
    if (rows.length !== 2 || !rows.every(row => row.definition.includes('validationCode'))
        || !rows.find(row => row.conname === 'events_validation_code_check')?.definition.includes('CITATION_NOT_GROUNDED')) {
      throw Object.assign(new Error('Judge validationCode constraints are unavailable'), { code: 'READINESS_FAILED' });
    }
    const { traceData } = require('../server/agent-runtime/runTraceStore');
    if (traceData({ validationCode: 'JSON_SYNTAX' }).validationCode !== 'JSON_SYNTAX'
        || Object.hasOwn(traceData({ validationCode: 'UNRECOGNIZED' }), 'validationCode')) {
      throw Object.assign(new Error('trace sanitizer differs from the database contract'), { code: 'READINESS_FAILED' });
    }
    return { ready: true, constraints: rows.map(row => row.conname) };
  } finally { await pool.end(); }
}

async function initializeIdentity(dependencies = {}) {
  const createPool = dependencies.createPool || require('../server/database/postgres').createPool;
  const initialize = dependencies.initializeIdentityRepository
    || require('../server/database/postgres/identityRepository').initializeIdentityRepository;
  const runtime = createPool(process.env, 'IDENTITY_DATABASE_URL');
  const migration = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
  try { return { initialized: ['identity'], applied: await initialize(runtime, migration) }; }
  finally { await Promise.allSettled([runtime.end(), migration.end()]); }
}

async function main(argument) {
  assertPrivateConfigBytes(); require('dotenv').config({ quiet: true }); assertPrivateConfigBytes();
  let result;
  if (argument === '--initialize') result = await initializeIdentity();
  else if (argument === '--ledger') result = await inspectStores();
  else if (argument === '--replay') result = await inspectStores({ replay: true });
  else if (argument === '--readiness') result = await readiness();
  else throw Object.assign(new Error('Use --initialize, --ledger, --replay or --readiness'), { code: 'INVALID_ARGUMENT' });
  assertPrivateConfigBytes(); return result;
}

if (require.main === module) main(process.argv[2]).then(result => {
  process.stdout.write(`GRAPH_JUDGE_VALIDATION_QUALIFICATION=${JSON.stringify(result)}\n`);
}).catch(error => {
  console.error('Graph Judge validation qualification failed:', error.code || error.name);
  process.exitCode = 1;
});

module.exports = { EXPECTED_NAMES, PRIVATE_CONFIG_DIGEST_VARIABLE, migrationDirectory,
  assertPrivateConfigBytes, inspectStores, readiness, initializeIdentity, main };
