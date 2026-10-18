'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { createPool, withTransaction, verifyServer } = require('../../server/database/postgres');

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
      await client.query(migration.sql);
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
module.exports = { readMigrations, migrate };
