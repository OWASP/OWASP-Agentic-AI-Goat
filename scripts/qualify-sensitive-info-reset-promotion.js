'use strict';

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { repositories, requiredStoreManifest, initializeApplication } = require('../db/postgres/initialize-application');

const ROOT = path.resolve(__dirname, '..');
const EXPECTED_NAMES = Object.freeze(repositories.map(([name]) => name));
const PRIVATE_CONFIG_DIGEST_VARIABLE = 'OWASP_AI_GOAT_EXPECTED_PRIVATE_CONFIG_SHA256';

function assertPrivateConfigBytes(env = process.env, dependencies = {}) {
  const expected = env[PRIVATE_CONFIG_DIGEST_VARIABLE];
  if (!expected) return;
  const configPath = dependencies.configPath || path.join(ROOT, '.env');
  const readFile = dependencies.readFile || fs.readFileSync;
  let bytes;
  try {
    bytes = readFile(configPath);
  } catch (cause) {
    throw Object.assign(new Error('private configuration is unavailable during qualification'),
      { code: 'PRIVATE_CONFIG_UNAVAILABLE', cause });
  }
  const actual = crypto.createHash('sha256').update(bytes).digest('hex');
  if (actual !== expected) {
    throw Object.assign(new Error('private configuration changed during qualification'),
      { code: 'PRIVATE_CONFIG_CHANGED' });
  }
}

function migrationDirectory(store) {
  return store === 'identity'
    ? path.join(ROOT, 'db/postgres/identity-migrations')
    : path.join(ROOT, `db/postgres/workshop-migrations/${store}`);
}

async function inspectStores({ replay = false, dependencies = {} } = {}) {
  const createPool = dependencies.createPool || require('../server/database/postgres').createPool;
  const migrate = dependencies.migrate || require('../db/postgres/migrate').migrate;
  const readMigrations = dependencies.readMigrations || require('../db/postgres/migrate').readMigrations;
  const result = {};
  for (const row of requiredStoreManifest) {
    const pool = createPool(process.env, row.migrationVariable);
    try {
      const directory = migrationDirectory(row.schema);
      const applied = replay ? await migrate(pool, directory) : [];
      const actual = (await pool.query(
        'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
      const expected = (await readMigrations(directory)).map(({ name, checksum }) => ({ name, checksum }));
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        throw Object.assign(new Error('migration ledger does not match source'), { code: 'LEDGER_MISMATCH' });
      }
      result[row.schema] = { applied, count: actual.length,
        head: actual.length ? actual[actual.length - 1] : null, ledger: actual };
    } finally { await pool.end(); }
  }
  return result;
}

async function assertResetReadiness() {
  process.env.SENSITIVE_INFO_AGGREGATE_RESET_ENABLED = 'true';
  const composition = require('../server/services/sensitiveInfoResetComposition');
  try {
    const ready = await composition.getSensitiveInfoResetComposition();
    if (!ready || typeof ready.reset?.reset !== 'function') throw new Error('reset composition is incomplete');
    return { ready: true };
  } finally {
    await composition.closeSensitiveInfoResetComposition();
    await require('../server/database/postgres').closePostgresPools();
  }
}

async function main(argument) {
  assertPrivateConfigBytes();
  require('dotenv').config({ quiet: true });
  assertPrivateConfigBytes();
  let result;
  if (argument === '--initialize') {
    await initializeApplication();
    result = { initialized: EXPECTED_NAMES };
  } else if (argument === '--ledger') {
    result = await inspectStores();
  } else if (argument === '--replay') {
    result = await inspectStores({ replay: true });
  } else if (argument === '--readiness') {
    result = await assertResetReadiness();
  } else {
    throw Object.assign(new Error('Usage: node scripts/qualify-sensitive-info-reset-promotion.js --initialize|--ledger|--replay|--readiness'),
      { code: 'INVALID_ARGUMENT' });
  }
  assertPrivateConfigBytes();
  return result;
}

if (require.main === module) main(process.argv[2]).then(result => {
  process.stdout.write(`SENSITIVE_RESET_QUALIFICATION=${JSON.stringify(result)}\n`);
}).catch(error => {
  console.error('Sensitive Information reset qualification failed:', error.code || error.name);
  process.exitCode = 1;
});

module.exports = { EXPECTED_NAMES, PRIVATE_CONFIG_DIGEST_VARIABLE, migrationDirectory,
  assertPrivateConfigBytes, inspectStores, assertResetReadiness, main };
