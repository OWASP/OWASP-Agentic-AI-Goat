'use strict';

// Native-only proof that the one immutable, already-applied migration with an
// outer transaction wrapper remains ledger/checksum compatible while the
// production loader retains atomic rollback authority.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

const root = path.resolve(__dirname, '../..');
const connectionString = process.env.PG_CTF_WRAPPER_MIGRATION_URL;
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!connectionString;

test('historical CTF wrapper keeps its original ledger checksum and rolls back with the loader', {
  skip: !enabled,
  timeout: 60_000,
}, async () => {
  const url = new URL(connectionString);
  const database = decodeURIComponent(url.pathname.slice(1));
  assert.match(database, /^owasp_ai_goat_ctf_wrapper_[a-f0-9]{12}$/,
    'owned disposable database required');
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname), 'loopback PostgreSQL required');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  const pool = new Pool({ connectionString, max: 1 });
  const stagedRoot = await fs.mkdtemp(path.join(
    process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || os.tmpdir(), 'ctf-wrapper-loader-'));
  const baselineDir = path.join(stagedRoot, 'baseline');
  const fullDir = path.join(stagedRoot, 'full');
  const failingDir = path.join(stagedRoot, 'failing');
  await Promise.all([baselineDir, fullDir, failingDir].map(directory => fs.mkdir(directory)));
  try {
    assert.equal((await pool.query('SELECT current_database() AS name')).rows[0].name, database);
    const migrationRoot = path.join(root, 'db/postgres/workshop-migrations/ctf');
    const baseNames = [
      '0001_schema.sql',
      '0002_import_provenance.sql',
      '0003_stage_default_provenance.sql',
    ];
    for (const name of baseNames) {
      const sql = await fs.readFile(path.join(migrationRoot, name), 'utf8');
      for (const directory of [baselineDir, fullDir, failingDir]) {
        await fs.writeFile(path.join(directory, name), sql);
      }
    }
    const wrapperName = '0004_system_prompt_default_provenance.sql';
    const wrapper = await fs.readFile(path.join(migrationRoot, wrapperName), 'utf8');
    assert.equal(createHash('sha256').update(wrapper).digest('hex'),
      'a41d0235686dd7e40189ec47c5f65cf06578c9663b3b33751075dd32d5d1112c');
    assert.match(wrapper, /^BEGIN;\n/);
    assert.match(wrapper, /COMMIT;\n$/);
    await fs.writeFile(path.join(fullDir, wrapperName), wrapper);
    await fs.writeFile(path.join(failingDir, wrapperName), wrapper);
    await fs.writeFile(path.join(failingDir, '0005_loader_rollback_sentinel.sql'),
      "DO $rollback$ BEGIN RAISE EXCEPTION 'loader rollback sentinel'; END $rollback$;\n");

    assert.deepEqual(await migrate(pool, baselineDir), baseNames);
    const constraint = async () => (await pool.query(`SELECT pg_get_constraintdef(oid) AS value
      FROM pg_constraint WHERE conrelid='ctf.stage_default_fields'::regclass
      AND conname='stage_default_fields_field_name_check'`)).rows[0].value;
    const functionDefinition = async () => (await pool.query(`SELECT pg_get_functiondef(
      'ctf.mark_stage_default_fields_custom(integer,text[])'::regprocedure) AS value`)).rows[0].value;
    const before = {
      constraint: await constraint(),
      functionDefinition: await functionDefinition(),
    };
    assert.doesNotMatch(before.constraint, /system_prompt/);
    assert.doesNotMatch(before.functionDefinition, /system_prompt/);

    await assert.rejects(migrate(pool, failingDir), /loader rollback sentinel/);
    assert.equal(await constraint(), before.constraint,
      'later migration failure must roll back the normalized wrapper DDL');
    assert.equal(await functionDefinition(), before.functionDefinition,
      'later migration failure must roll back the normalized wrapper function');
    assert.deepEqual((await pool.query(`SELECT name FROM dvaia_migrations.ledger
      WHERE name IN ($1,$2) ORDER BY name`, [wrapperName, '0005_loader_rollback_sentinel.sql'])).rows, [],
    'later migration failure must roll back the wrapper and sentinel ledger entries');

    assert.deepEqual(await migrate(pool, fullDir), [wrapperName]);
    assert.match(await constraint(), /system_prompt/);
    assert.match(await functionDefinition(), /system_prompt/);
    assert.deepEqual((await pool.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger WHERE name=$1', [wrapperName])).rows,
    [{ name: wrapperName, checksum: createHash('sha256').update(wrapper).digest('hex') }],
    'ledger must retain the checksum of the immutable wrapped source bytes');
    assert.deepEqual(await migrate(pool, fullDir), []);
  } finally {
    await pool.end();
    await fs.rm(stagedRoot, { recursive: true, force: true });
  }
});
