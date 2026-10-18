'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { createPool, withTransaction, verifyServer } = require('../../server/database/postgres');

function executionSql(migration) {
  // Preserve immutable history/checksums while keeping this historical wrapper
  // inside the loader's transaction (including its advisory lock and ledger).
  // This is deliberately an exact exception, not a SQL/PLpgSQL parser.
  if (migration.name === '0004_system_prompt_default_provenance.sql' &&
      createHash('sha256').update(migration.sql).digest('hex') ===
        'a41d0235686dd7e40189ec47c5f65cf06578c9663b3b33751075dd32d5d1112c') {
    return migration.sql.slice('BEGIN;\n'.length).replace(/COMMIT;\n$/, '');
  }
  // 0091 accidentally omitted the IDOR purpose already admitted by 0086.
  // Preserve populated sessions while executing that exact historical file;
  // 0093 repairs stores which have already recorded 0091. The ledger continues
  // to record the original file checksum, never a rewritten migration file.
  if (migration.name === '0091_mail_summary_conversation_purpose.sql' &&
      createHash('sha256').update(migration.sql).digest('hex') ===
        'b84aaa3f7af2a58480bbd4dd057911d62571a55129a161d2322cd7999355a27b') {
    return migration.sql.replace("'secureshop_admin_assistant'",
      "'secureshop_admin_assistant','secureshop_idor_lesson'");
  }
  return migration.sql;
}

async function readMigrations(directory) {
  const files = (await fs.readdir(directory)).filter(name => name.endsWith('.sql')).sort();
  if (files.some(name => !/^\d{4}_[a-z0-9_]+\.sql$/.test(name))) throw new Error('Migration names must use NNNN_name.sql');
  const versions = new Set();
  return Promise.all(files.map(async name => {
    const version = name.slice(0, 4);
    if (versions.has(version)) throw new Error(`Duplicate migration version ${version}`);
    versions.add(version);
    const sql = await fs.readFile(path.join(directory, name), 'utf8');
    return { name, sql, checksum: createHash('sha256').update(sql).digest('hex') };
  }));
}

async function migrate(pool, directory = path.join(__dirname, 'migrations')) {
  const migrations = await readMigrations(directory);
  return withTransaction(pool, async client => {
    await verifyServer(client);
    // Transaction-scoped lock releases on success, failure, disconnect, or process exit.
    await client.query('SELECT pg_advisory_xact_lock(1886610804, 1)');
    await client.query('CREATE SCHEMA IF NOT EXISTS dvaia_migrations');
    await client.query(`CREATE TABLE IF NOT EXISTS dvaia_migrations.ledger (
      name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now()
    )`);
    const { rows } = await client.query('SELECT name, checksum FROM dvaia_migrations.ledger ORDER BY name');
    for (let i = 0; i < rows.length; i++) {
      if (!migrations[i] || migrations[i].name !== rows[i].name || migrations[i].checksum !== rows[i].checksum) {
        const error = new Error('Applied migration history differs from local migration files');
        error.code = 'MIGRATION_HISTORY_MISMATCH';
        error.migration = rows[i].name;
        throw error;
      }
    }
    const applied = [];
    for (const migration of migrations.slice(rows.length)) {
      await client.query(executionSql(migration));
      await client.query('INSERT INTO dvaia_migrations.ledger (name, checksum) VALUES ($1, $2)', [migration.name, migration.checksum]);
      applied.push(migration.name);
    }
    return applied;
  });
}

if (require.main === module) {
  (async () => {
    const pool = createPool(process.env, 'PG_MIGRATION_DATABASE_URL');
    try { console.log(JSON.stringify({ applied: await migrate(pool) })); }
    finally { await pool.end(); }
  })().catch(error => {
    console.error('PostgreSQL migration failed:', error.code || error.message);
    process.exitCode = 1;
  });
}
module.exports = { readMigrations, migrate, executionSql };
