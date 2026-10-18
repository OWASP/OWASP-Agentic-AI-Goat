'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const vm = require('node:vm');
const { createHash } = require('node:crypto');
const { Pool } = require('pg');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.CTF_PROVENANCE_NATIVE === '1';
const migrationDirectory = path.join(__dirname, '../../db/postgres/workshop-migrations/ctf');
const current = require('../../server/data/ctfDefaults').stages;
const previous = require('../fixtures/ctfDefaults.previous').stages;
const { hashValue, adoptExactPriorDefault } = require('../../server/database/postgres/ctfStageDefaultProvenance');
const { createCtfDb } = require('../helpers/loadCtfDbForProvenance');

function pool(url, max = 3) {
  const parsed = new URL(url);
  assert.equal(parsed.hostname, '127.0.0.1');
  assert.match(parsed.pathname, /^\/dvaia_ctf_provenance_(fresh|populated)_[a-f0-9]{12}$/);
  assert.ok(['dvaia_ctf_migration', 'dvaia_ctf_runtime'].includes(parsed.username));
  assert.equal(parsed.search, '');
  assert.equal(parsed.hash, '');
  return new Pool({ connectionString: parsed.href, max, statement_timeout: 30000,
    lock_timeout: 5000, idle_in_transaction_session_timeout: 30000 });
}
async function one(db, sql, args = []) { return (await db.query(sql, args)).rows[0]; }
async function close(...pools) { await Promise.allSettled(pools.map(item => item.end())); }

// The migration loader only needs readdir/readFile.  Keep the historical
// populated fixture's 0001/0002 prefix as an in-memory view over the real
// canonical bytes instead of copying SQL files into a temporary directory.
async function migrationNames() {
  return (await fs.readdir(migrationDirectory)).filter(name => name.endsWith('.sql')).sort();
}
function loadMigrationView(names) {
  const filename = require.resolve('../../db/postgres/migrate');
  const nativeRequire = Module.createRequire(filename);
  const nativeFs = require('node:fs/promises');
  const virtualDirectory = path.join(os.tmpdir(), `ctf-provenance-prefix-${process.pid}-${names.join(',').length}`);
  const viewFs = {
    ...nativeFs,
    readdir: async directory => directory === virtualDirectory ? [...names] : nativeFs.readdir(directory),
    readFile: async (file, ...args) => {
      if (path.dirname(file) === virtualDirectory) {
        const name = path.basename(file);
        assert.ok(names.includes(name), `Unadmitted migration read: ${name}`);
        return nativeFs.readFile(path.join(migrationDirectory, name), ...args);
      }
      return nativeFs.readFile(file, ...args);
    },
  };
  const localRequire = request => ['node:fs/promises', 'fs/promises'].includes(request)
    ? viewFs : nativeRequire(request);
  const loaded = { exports: {} };
  vm.runInThisContext(`(function(require,module,exports,__dirname){${require('node:fs').readFileSync(filename, 'utf8')}\n})`,
    { filename })(localRequire, loaded, loaded.exports, path.dirname(filename));
  return { ...loaded.exports, virtualDirectory };
}

test('managed text hashing distinguishes SQL null, literal null, and unsupported types', () => {
  assert.notEqual(hashValue(null), hashValue('null'));
  assert.notEqual(hashValue(''), hashValue(null));
  assert.throws(() => hashValue(undefined), /text or null/);
  assert.throws(() => hashValue(1), /text or null/);
});

test('explicit adoption API requires a transaction-owning PostgreSQL pool', async () => {
  await assert.rejects(adoptExactPriorDefault({ query: async () => ({ rows: [] }) }, {
    stageNumber: 8, fieldName: 'hints', priorValue: 'reviewed',
  }), /PostgreSQL pool required/);
});

test('normal CTF loader seeds fresh managed defaults twice without drift', { skip: !enabled }, async () => {
  const runtime = pool(process.env.CTF_PROVENANCE_FRESH_RUNTIME_URL);
  const migration = pool(process.env.CTF_PROVENANCE_FRESH_MIGRATION_URL, 1);
  try {
    const store = createCtfDb(runtime);
    await store.initialize(migration);
    const first = await migration.query(`SELECT s.stage_number,s.stage_description,s.ai_guardian_personality,s.hints,
      s.system_prompt,s.defense_style,
      p.field_name,p.provenance_state,p.applied_default_sha256,p.source_default_sha256
      FROM ctf.ctf_stages s JOIN ctf.stage_default_fields p USING(stage_number)
      ORDER BY s.stage_number,p.field_name`);
    assert.equal(first.rows.length, 50);
    assert.ok(first.rows.every(row => row.provenance_state === 'managed'));
    for (const row of first.rows) {
      const value = row[row.field_name];
      assert.equal(row.applied_default_sha256, hashValue(value));
      assert.equal(row.source_default_sha256, hashValue(value));
    }
    await store.initialize(migration);
    const second = await migration.query(`SELECT s.stage_number,s.stage_description,s.ai_guardian_personality,s.hints,
      s.system_prompt,s.defense_style,
      p.field_name,p.provenance_state,p.applied_default_sha256,p.source_default_sha256
      FROM ctf.ctf_stages s JOIN ctf.stage_default_fields p USING(stage_number)
      ORDER BY s.stage_number,p.field_name`);
    assert.deepEqual(second.rows, first.rows);
    const ledger = await migration.query('SELECT name FROM dvaia_migrations.ledger ORDER BY name');
    assert.deepEqual(ledger.rows.map(row => row.name), await migrationNames());
  } finally { await close(runtime, migration); }
});

test('populated migration preserves unknown/custom values and upgrades only matching managed values',
  { skip: !enabled }, async t => {
    const runtime = pool(process.env.CTF_PROVENANCE_POPULATED_RUNTIME_URL);
    const migration = pool(process.env.CTF_PROVENANCE_POPULATED_MIGRATION_URL, 2);
    try {
      const canonicalNames = await migrationNames();
      const prefixNames = canonicalNames.slice(0, 2);
      assert.deepEqual(prefixNames, ['0001_schema.sql', '0002_import_provenance.sql']);
      const prefixLoader = loadMigrationView(prefixNames);
      const prefixMigrations = await prefixLoader.readMigrations(prefixLoader.virtualDirectory);
      for (const migration of prefixMigrations) {
        assert.equal(migration.name, prefixNames[prefixMigrations.indexOf(migration)]);
        assert.equal(migration.checksum,
          createHash('sha256').update(await fs.readFile(path.join(migrationDirectory, migration.name))).digest('hex'),
          `prefix must expose canonical ${migration.name} bytes`);
      }
      await prefixLoader.migrate(migration, prefixLoader.virtualDirectory);
      const old8 = previous[7], old9 = previous[8], old10 = previous[9];
      const insert = async row => (await migration.query(`INSERT INTO ctf.ctf_stages
        (stage_number,stage_name,stage_description,ai_guardian_personality,hints,stage_order)
        VALUES($1,$2,$3,$4,$5,$6) RETURNING id`, row)).rows[0].id;
      const id8 = await insert([8, old8.stage_name, old8.stage_description,
        old8.ai_guardian_personality, old8.hints, 8]);
      const id9 = await insert([9, old9.stage_name, 'Instructor description', null, null, 9]);
      const id10 = await insert([10, old10.stage_name, null, 'null', old10.hints, 10]);
      const { migrate } = require('../../db/postgres/migrate');
      await migrate(migration, migrationDirectory);
      const provenance = async (stage, field, state, applied = null, source = null) => migration.query(`INSERT INTO ctf.stage_default_fields
        (stage_number,field_name,provenance_state,applied_default_sha256,source_default_sha256)
        VALUES($1,$2,$3,$4,$5)`, [stage, field, state, applied, source]);
      await provenance(8, 'stage_description', 'managed', hashValue(old8.stage_description), hashValue(old8.stage_description));
      await provenance(8, 'ai_guardian_personality', 'custom');
      await provenance(9, 'stage_description', 'managed', hashValue(old9.stage_description), hashValue(old9.stage_description));
      await provenance(9, 'ai_guardian_personality', 'custom');
      await provenance(9, 'hints', 'legacy_unknown', null, hashValue(current[8].hints));
      await provenance(10, 'stage_description', 'managed', hashValue(null), hashValue(null));
      await provenance(10, 'ai_guardian_personality', 'managed', hashValue(null), hashValue(null));
      const store = createCtfDb(runtime);
      await store.initialize(migration);

      const stage8 = await store.getStage(id8), stage9 = await store.getStage(id9), stage10 = await store.getStage(id10);
      assert.equal(stage8.stage_description, current[7].stage_description);
      assert.equal(stage8.ai_guardian_personality, old8.ai_guardian_personality, 'same-value custom preserved');
      assert.equal(stage8.hints, old8.hints, 'absent provenance preserved as unknown');
      assert.equal((await one(migration, `SELECT provenance_state FROM ctf.stage_default_fields
        WHERE stage_number=8 AND field_name='hints'`)).provenance_state, 'legacy_unknown');
      const adopted = await adoptExactPriorDefault(migration, { stageNumber: 8, fieldName: 'hints',
        priorValue: old8.hints });
      assert.equal(adopted.appliedDefaultSha256, hashValue(old8.hints));
      assert.equal((await one(migration, `SELECT provenance_state FROM ctf.stage_default_fields
        WHERE stage_number=8 AND field_name='hints'`)).provenance_state, 'managed',
      'explicit reviewed adoption is transactionally persisted');
      assert.equal(stage9.stage_description, 'Instructor description');
      assert.equal((await one(migration, `SELECT provenance_state FROM ctf.stage_default_fields
        WHERE stage_number=9 AND field_name='stage_description'`)).provenance_state, 'custom');
      assert.equal(stage9.ai_guardian_personality, null); assert.equal(stage9.hints, null);
      assert.equal(stage10.stage_description, current[9].stage_description, 'managed null upgrades');
      assert.equal(stage10.ai_guardian_personality, 'null', 'literal null mismatches null hash and becomes custom');
      assert.equal((await one(migration, `SELECT provenance_state FROM ctf.stage_default_fields
        WHERE stage_number=10 AND field_name='ai_guardian_personality'`)).provenance_state, 'custom');

      await assert.rejects(runtime.query(`UPDATE ctf.stage_default_fields SET provenance_state='managed'
        WHERE stage_number=8 AND field_name='hints'`), error => error.code === '42501');
      await assert.rejects(runtime.query(`INSERT INTO ctf.stage_default_fields(stage_number,field_name,provenance_state)
        VALUES(8,'hints','custom')`), error => error.code === '42501');
      await assert.rejects(runtime.query(`DELETE FROM ctf.stage_default_fields WHERE stage_number=8`),
        error => error.code === '42501');

      await store.updateStage(id8, { hints: 'Instructor hints' });
      assert.equal((await store.getStage(id8)).hints, 'Instructor hints');
      assert.equal((await one(migration, `SELECT provenance_state FROM ctf.stage_default_fields
        WHERE stage_number=8 AND field_name='hints'`)).provenance_state, 'custom');

      const before = await store.getStage(id10);
      const beforeProvenance = await one(migration, `SELECT * FROM ctf.stage_default_fields
        WHERE stage_number=10 AND field_name='hints'`);
      await assert.rejects(store.updateStage(id10, { hints: 'must roll back', stage_name: null }), /not-null|null value/i);
      assert.deepEqual(await store.getStage(id10), before);
      assert.deepEqual(await one(migration, `SELECT * FROM ctf.stage_default_fields
        WHERE stage_number=10 AND field_name='hints'`), beforeProvenance);

      await migration.query(`UPDATE ctf.ctf_stages SET stage_description=$1 WHERE stage_number=8`, [old8.stage_description]);
      await migration.query(`UPDATE ctf.stage_default_fields SET provenance_state='managed',
        applied_default_sha256=$1,source_default_sha256=$1 WHERE stage_number=8 AND field_name='stage_description'`,
      [hashValue(old8.stage_description)]);
      await Promise.all([
        store.initialize(migration),
        store.updateStage(id8, { stage_description: 'Concurrent instructor edit' }),
      ]);
      assert.equal((await store.getStage(id8)).stage_description, 'Concurrent instructor edit');
      assert.equal((await one(migration, `SELECT provenance_state FROM ctf.stage_default_fields
        WHERE stage_number=8 AND field_name='stage_description'`)).provenance_state, 'custom');

      // Hold the provenance row so adoption blocks after locking the stage row. The
      // concurrent admin edit must then run after adoption commits and remain custom.
      await migration.query('UPDATE ctf.ctf_stages SET hints=$1 WHERE stage_number=8', [old8.hints]);
      await migration.query(`UPDATE ctf.stage_default_fields SET provenance_state='legacy_unknown',
        applied_default_sha256=NULL WHERE stage_number=8 AND field_name='hints'`);
      const blocker = await migration.connect();
      const adoptionPool = new Pool({ connectionString: new URL(process.env.CTF_PROVENANCE_POPULATED_MIGRATION_URL).href,
        max: 1, application_name: 'ctf-adoption-qualification', statement_timeout: 30000, lock_timeout: 5000 });
      try {
        await blocker.query('BEGIN');
        await blocker.query(`SELECT provenance_state FROM ctf.stage_default_fields
          WHERE stage_number=8 AND field_name='hints' FOR UPDATE`);
        const adopting = adoptExactPriorDefault(adoptionPool, { stageNumber: 8, fieldName: 'hints', priorValue: old8.hints });
        let waiting = false;
        for (let attempt = 0; attempt < 100; attempt += 1) {
          const activity = await migration.query(`SELECT wait_event_type FROM pg_stat_activity
            WHERE datname=current_database() AND application_name='ctf-adoption-qualification'`);
          if (activity.rows.some(row => row.wait_event_type === 'Lock')) { waiting = true; break; }
          await new Promise(resolve => setTimeout(resolve, 20));
        }
        assert.equal(waiting, true, 'adoption transaction must hold the stage row while awaiting provenance');
        const editing = store.updateStage(id8, { hints: 'Concurrent adopted-field edit' });
        await blocker.query('COMMIT');
        await adopting;
        await editing;
      } finally {
        try { await blocker.query('ROLLBACK'); } catch {}
        blocker.release();
        await adoptionPool.end();
      }
      assert.equal((await store.getStage(id8)).hints, 'Concurrent adopted-field edit');
      assert.equal((await one(migration, `SELECT provenance_state FROM ctf.stage_default_fields
        WHERE stage_number=8 AND field_name='hints'`)).provenance_state, 'custom',
      'concurrent admin edit wins after explicit adoption and retains custom provenance');

      const unknownBefore = await one(migration, `SELECT * FROM ctf.stage_default_fields
        WHERE stage_number=9 AND field_name='hints'`);
      await store.initialize(migration);
      assert.deepEqual(await one(migration, `SELECT * FROM ctf.stage_default_fields
        WHERE stage_number=9 AND field_name='hints'`), unknownBefore,
      'normal seed never implicitly adopts unknown content');
      await assert.rejects(adoptExactPriorDefault(migration, { stageNumber: 9, fieldName: 'hints',
        priorValue: old9.hints }), /does not equal/);
      assert.equal((await store.getStage(id9)).hints, null);
    } finally { await close(runtime, migration); }
  });

test('in-memory migration view reads canonical prefix and full manifest with second-run no-op', async () => {
  const canonicalNames = await migrationNames();
  const prefixNames = canonicalNames.slice(0, 2);
  const prefixLoader = loadMigrationView(prefixNames);
  const prefix = await prefixLoader.readMigrations(prefixLoader.virtualDirectory);
  assert.deepEqual(prefix.map(row => row.name), prefixNames);
  for (const row of prefix) {
    assert.equal(row.checksum,
      createHash('sha256').update(await fs.readFile(path.join(migrationDirectory, row.name))).digest('hex'));
  }
  const canonical = await require('../../db/postgres/migrate').readMigrations(migrationDirectory);
  assert.deepEqual(canonical.map(row => row.name), canonicalNames);

  const ledger = [];
  const queries = [];
  const client = {
    async query(sql, args = []) {
      queries.push(sql);
      if (sql.includes('current_setting')) return { rows: [{ version: 180000, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false }] };
      if (/SELECT name, checksum FROM dvaia_migrations\.ledger/.test(sql)) return { rows: ledger.map(row => ({ ...row })) };
      if (/INSERT INTO dvaia_migrations\.ledger/.test(sql)) { ledger.push({ name: args[0], checksum: args[1] }); return { rows: [], rowCount: 1 }; }
      return { rows: [], rowCount: 0 };
    },
    release() {},
  };
  const pool = { async connect() { return client; } };
  assert.deepEqual(await prefixLoader.migrate(pool, prefixLoader.virtualDirectory), prefixNames);
  assert.deepEqual(await require('../../db/postgres/migrate').migrate(pool, migrationDirectory), canonicalNames.slice(2));
  assert.deepEqual(await require('../../db/postgres/migrate').migrate(pool, migrationDirectory), []);
  assert.equal(ledger.length, canonicalNames.length);
  assert.ok(queries.some(sql => sql.includes('CREATE TABLE IF NOT EXISTS dvaia_migrations.ledger')));
});
