'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createPool } = require('../../server/database/postgres');
const { migrate } = require('../../db/postgres/migrate');

// Explicit opt-in and a disposable database name: never use the application's URL.
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && Boolean(process.env.PG_TEST_DATABASE_URL);
test('real PostgreSQL: repeatable migrations, rollback, history integrity and concurrent boot', { skip: !enabled }, async () => {
  const url = new URL(process.env.PG_TEST_DATABASE_URL);
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  const pool = createPool(process.env, 'PG_TEST_DATABASE_URL');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-pg-migrations-'));
  try {
    const existing = await pool.query("SELECT to_regnamespace('dvaia_migrations') AS schema");
    assert.equal(existing.rows[0].schema, null, 'Test requires a fresh disposable database');
    await fs.writeFile(path.join(directory, '0001_probe.sql'), 'CREATE TABLE public.migration_probe (id integer PRIMARY KEY);');
    const results = await Promise.all([migrate(pool, directory), migrate(pool, directory)]);
    assert.equal(results.flat().length, 1);
    assert.deepEqual(await migrate(pool, directory), []);
    await fs.writeFile(path.join(directory, '0002_abort.sql'), 'INSERT INTO public.migration_probe VALUES (1); SELECT * FROM nonexistent_test_table;');
    await assert.rejects(migrate(pool, directory));
    assert.equal((await pool.query('SELECT * FROM public.migration_probe')).rowCount, 0);
    assert.equal((await pool.query('SELECT * FROM dvaia_migrations.ledger')).rowCount, 1);
    await fs.writeFile(path.join(directory, '0001_probe.sql'), 'SELECT 1;');
    await assert.rejects(migrate(pool, directory), /history differs/);
  } finally {
    // Leave database lifecycle to the caller; no DROP DATABASE or application-data cleanup.
    await pool.end();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
