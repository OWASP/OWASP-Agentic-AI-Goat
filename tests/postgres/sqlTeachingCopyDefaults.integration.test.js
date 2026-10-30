'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const syncFs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { Pool } = require('pg');
const provenance = require('../../server/database/postgres/catalogDefaultProvenance');
function historicalBase() {
  const filename = require.resolve('../../server/data/sqlInjectionWorkshopSolutions');
  const module = { exports:{} };
  vm.runInNewContext(syncFs.readFileSync(filename, 'utf8'), {
    module, exports:module.exports, require:createRequire(filename), __filename:filename,
    __dirname:path.dirname(filename), process:{ env:{ ...process.env, WORKSHOP_DATABASE_ENGINE:'legacy' } },
  }, { filename });
  return JSON.parse(JSON.stringify(module.exports));
}
const base = historicalBase();
const current = require('../../server/data/postgres/sqlInjectionWorkshopSolutions')(base);

const root = path.resolve(__dirname, '../..');
const migrationDirectory = path.join(root, 'db/postgres/identity-migrations');
const candidateName = '0069_sql_injection_postgres_copy_defaults.sql';
const virtualDirectories = new Map();
const virtualFs = {
  async readdir(directory, ...args) {
    const entries = virtualDirectories.get(directory);
    return entries ? [...entries.keys()] : fs.readdir(directory, ...args);
  },
  async readFile(file, encoding) {
    const entries = virtualDirectories.get(path.dirname(file));
    if (!entries) return fs.readFile(file, encoding);
    assert.equal(encoding, 'utf8');
    if (!entries.has(path.basename(file))) throw Object.assign(Error('Missing virtual migration'), { code: 'ENOENT' });
    return entries.get(path.basename(file));
  },
};
function loadMigrationWithVirtualDirectories() {
  const filename = require.resolve('../../db/postgres/migrate');
  const localRequire = createRequire(filename);
  const { Module } = require('node:module');
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? virtualFs : localRequire(name);
  loaded._compile(syncFs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports;
}
const { migrate, readMigrations } = loadMigrationWithVirtualDirectories();
async function stageCanonicalPrefix(rows, label) {
  const directory = path.join('/virtual-sql-copy-migrations', label);
  virtualDirectories.set(directory, new Map(rows.map(row => [row.name, row.sql])));
  return directory;
}
function disposeVirtualDirectory(directory) {
  assert.equal(virtualDirectories.delete(directory), true);
}
const connectionString = process.env.PG_SQL_TEACHING_COPY_TEST_URL;
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && Boolean(connectionString);
const version = 'workshop-defaults-2026-09-18-v5-postgres-sql-copy';

async function putRows(client, rows) {
  await client.query(`DELETE FROM workshop_platform.catalog_field_defaults
    WHERE entity_kind='objective' AND workshop_key='sql_injection_workshop';
    DELETE FROM workshop_platform.objectives WHERE workshop_key='sql_injection_workshop';
    INSERT INTO workshop_platform.exercises
      (workshop_key,challenge_key,challenge_name,ordinal)
    VALUES('sql_injection_workshop','sql_injection_workshop','SQL Injection Workshop',0)
    ON CONFLICT(workshop_key) DO NOTHING`);
  for (const [ordinal, row] of rows.entries()) {
    const document = provenance.document(row.value);
    const hash = provenance.hashDocument(document);
    await client.query(`INSERT INTO workshop_platform.objectives
      (workshop_key,objective_id,label,ordinal,solution_content,updated_by)
      VALUES('sql_injection_workshop',$1,$1,$2,$3::jsonb,$4)`,
    [row.id, ordinal, JSON.stringify(row.value), row.updatedBy ?? null]);
    await client.query(`INSERT INTO workshop_platform.catalog_field_defaults
      (entity_kind,workshop_key,objective_id,field_name,provenance_state,
       source_version,source_hash,source_document,applied_default_version,applied_default_hash,
       applied_default_document,observed_document)
      VALUES('objective','sql_injection_workshop',$1,'solution_content',$2,
       'prior',$3,$4::jsonb,CASE WHEN $2='managed' THEN 'prior' END,
       CASE WHEN $2='managed' THEN $3 END,CASE WHEN $2='managed' THEN $4::jsonb END,$4::jsonb)`,
    [row.id, row.state, hash, JSON.stringify(document)]);
  }
}

async function snapshot(client) {
  return {
    objectives: (await client.query(`SELECT objective_id,solution_content,updated_by
      FROM workshop_platform.objectives WHERE workshop_key='sql_injection_workshop'
      ORDER BY objective_id`)).rows,
    defaults: (await client.query(`SELECT objective_id,provenance_state,source_version,source_hash,
      source_document,applied_default_version,applied_default_hash,applied_default_document,observed_document
      FROM workshop_platform.catalog_field_defaults WHERE entity_kind='objective'
        AND workshop_key='sql_injection_workshop' AND field_name='solution_content'
      ORDER BY objective_id`)).rows,
    revision: Number((await client.query(
      'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision),
  };
}

async function removeCandidateLedger(client) {
  const deleted = await client.query('DELETE FROM dvaia_migrations.ledger WHERE name=$1', [candidateName]);
  assert.equal(deleted.rowCount, 1, 'candidate must be the applied migration tail');
}

async function actualLedger(client) {
  return (await client.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
}

test('production identity chain and 0069 preserve fresh, exact-old, edited, rollback, and replay paths',
  { skip: !enabled ? 'requires owned disposable PostgreSQL URL' : false, timeout: 90000 }, async () => {
    const database = decodeURIComponent(new URL(connectionString).pathname.slice(1));
    assert.match(database, /^owasp_ai_goat_sql_copy_[a-f0-9]{12}$/, 'owned disposable database required');
    const pool = new Pool({ connectionString, max: 2 });
    const client = await pool.connect();
    const canonical = await readMigrations(migrationDirectory);
    const candidateIndex = canonical.findIndex(row => row.name === candidateName);
    assert.notEqual(candidateIndex, -1, '0069 must remain in the canonical migration manifest');
    const candidateRows = canonical.slice(0, candidateIndex + 1);
    const expected = candidateRows.map(({ name, checksum }) => ({ name, checksum }));
    assert.equal(expected.at(-1).name, candidateName);
    const migrationView = await stageCanonicalPrefix(candidateRows, 'candidate');
    try {
      for (const id of ['sqli_1', 'sqli_3']) assert.notDeepEqual(base[id], current[id],
        `${id} historical fixture must differ from the PostgreSQL default`);
      assert.deepEqual(await migrate(pool, migrationView), expected.map(row => row.name));
      assert.deepEqual(await actualLedger(client), expected, 'fresh chain records exact production checksums');
      assert.deepEqual(await migrate(pool, migrationView), [], 'second canonical-prefix run is a no-op');

      await client.query("INSERT INTO identity.users(id,username,email,password,role,admin_level) VALUES(77,'sql-copy-instructor','sql-copy-instructor@fixture.invalid',$1,'admin',1) ON CONFLICT(id) DO NOTHING", ['$2b$04$'+'a'.repeat(53)]);
      assert.equal((await client.query('SELECT id FROM identity.users WHERE id=77')).rows[0].id, 77,
        'owned disposable instructor principal required for updated_by=77 preservation checks');

      await putRows(client, ['sqli_1', 'sqli_3'].map(id => ({ id, value:current[id], state:'managed' })));
      await removeCandidateLedger(client);
      const freshBefore = await snapshot(client);
      assert.deepEqual(await migrate(pool, migrationView), [candidateName]);
      assert.deepEqual(await snapshot(client), freshBefore, 'fresh corrected source defaults remain unchanged');

      await putRows(client, [
        { id:'sqli_1', value:base.sqli_1, state:'managed' },
        { id:'sqli_3', value:base.sqli_3, state:'legacy_unknown' },
      ]);
      await removeCandidateLedger(client);
      const oldBefore = await snapshot(client);
      const failingRows = candidateRows.map(row => row.name === candidateName
        ? { ...row, sql: `${row.sql}\nDO $rollback$ BEGIN RAISE EXCEPTION '0069 rollback sentinel'; END $rollback$;\n` }
        : row);
      const failingDirectory = await stageCanonicalPrefix(failingRows, 'failing');
      try {
        await assert.rejects(migrate(pool, failingDirectory), /0069 rollback sentinel/);
      } finally {
        disposeVirtualDirectory(failingDirectory);
      }
      assert.deepEqual(await snapshot(client), oldBefore, 'failed production-shaped migration rolls back content and revision');
      assert.equal((await client.query('SELECT count(*)::integer AS count FROM dvaia_migrations.ledger WHERE name=$1',
        [candidateName])).rows[0].count, 0, 'failed migration does not enter the ledger');

      assert.deepEqual(await migrate(pool, migrationView), [candidateName]);
      const changed = await snapshot(client);
      assert.equal(changed.revision, oldBefore.revision + 1);
      for (const row of changed.objectives) assert.deepEqual(row.solution_content, current[row.objective_id]);
      for (const row of changed.defaults) {
        const expectedDocument = provenance.document(current[row.objective_id]);
        const expectedHash = provenance.hashDocument(expectedDocument);
        assert.equal(row.provenance_state, 'managed');
        assert.equal(row.source_version, version); assert.equal(row.applied_default_version, version);
        assert.equal(row.source_hash, expectedHash); assert.equal(row.applied_default_hash, expectedHash);
        assert.deepEqual(row.source_document, expectedDocument);
        assert.deepEqual(row.applied_default_document, expectedDocument);
        assert.deepEqual(row.observed_document, expectedDocument);
      }
      assert.deepEqual(await migrate(pool, migrationView), [], 'qualified chain replay is a no-op');
      assert.deepEqual(await snapshot(client), changed);

      await putRows(client, [
        { id:'sqli_1', value:current.sqli_1, state:'managed' },
        { id:'sqli_3', value:base.sqli_3, state:'managed', updatedBy:77 },
      ]);
      await removeCandidateLedger(client);
      const instructorBefore = await snapshot(client);
      assert.deepEqual(await migrate(pool, migrationView), [candidateName]);
      assert.deepEqual(await snapshot(client), instructorBefore,
        'updated_by instructor content survives the default migration unchanged');

      for (const state of ['managed', 'legacy_unknown']) {
        await putRows(client, [
          { id:'sqli_1', value:base.sqli_1, state },
          { id:'sqli_3', value:base.sqli_3, state },
        ]);
        await removeCandidateLedger(client);
        const adoptionBefore = await snapshot(client);
        assert.deepEqual(await migrate(pool, migrationView), [candidateName]);
        const adoptionAfter = await snapshot(client);
        assert.equal(adoptionAfter.revision, adoptionBefore.revision + 1);
        for (const row of adoptionAfter.objectives) {
          assert.deepEqual(row.solution_content, current[row.objective_id]);
          assert.equal(row.updated_by, null);
        }
        for (const row of adoptionAfter.defaults) {
          const expectedDocument = provenance.document(current[row.objective_id]);
          const expectedHash = provenance.hashDocument(expectedDocument);
          assert.equal(row.provenance_state, 'managed');
          assert.equal(row.source_version, version);
          assert.equal(row.applied_default_version, version);
          assert.equal(row.source_hash, expectedHash);
          assert.equal(row.applied_default_hash, expectedHash);
          assert.deepEqual(row.source_document, expectedDocument);
          assert.deepEqual(row.applied_default_document, expectedDocument);
          assert.deepEqual(row.observed_document, expectedDocument);
        }
        const adoptionChanged = await snapshot(client);
        assert.deepEqual(await migrate(pool, migrationView), [], 'adoption replay is a no-op');
        assert.deepEqual(await snapshot(client), adoptionChanged);
      }

      const edited = [
        { id:'sqli_1', value:{ ...base.sqli_1, approach:'Instructor-authored approach' }, state:'custom' },
        { id:'sqli_3', value:{ ...base.sqli_3, tips:['Instructor-authored tip'] }, state:'managed', updatedBy:77 },
      ];
      await putRows(client, edited); await removeCandidateLedger(client);
      const editedBefore = await snapshot(client);
      assert.deepEqual(await migrate(pool, migrationView), [candidateName]);
      assert.deepEqual((await snapshot(client)).objectives.map(row => ({ id:row.objective_id, value:row.solution_content, updatedBy:row.updated_by })),
        editedBefore.objectives.map(row => ({ id:row.objective_id, value:row.solution_content, updatedBy:row.updated_by })));
      assert.deepEqual(await snapshot(client), editedBefore, 'custom and drifted legacy content survive');
      assert.deepEqual(await actualLedger(client), expected);

      await putRows(client, [
        { id:'sqli_1', value:{ ...base.sqli_1, approach:'Instructor-authored approach' }, state:'custom' },
        { id:'sqli_3', value:{ ...base.sqli_3, tips:['Legacy drifted tip'] }, state:'legacy_unknown' },
      ]);
      await removeCandidateLedger(client);
      const legacyDriftBefore = await snapshot(client);
      assert.deepEqual(await migrate(pool, migrationView), [candidateName]);
      assert.deepEqual(await snapshot(client), legacyDriftBefore,
        'legacy unknown content drift survives without updated_by');
      assert.deepEqual(await migrate(pool, migrationView), []);
    } finally {
      disposeVirtualDirectory(migrationView);
      client.release(); await pool.end();
    }
  });
