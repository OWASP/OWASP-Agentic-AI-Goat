'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createPool } = require('../../server/database/postgres');
const { migrate } = require('../../db/postgres/migrate');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env.PG_LEGACY_SENSITIVE_MOVE_TEST_MIGRATION_URL);

test('0007 moves only exact legacy sensitive audit rows and restores both immutable stores', {
  skip: !enabled,
}, async () => {
  assert.match(new URL(process.env.PG_LEGACY_SENSITIVE_MOVE_TEST_MIGRATION_URL).pathname,
    /^\/dvaia_test_[a-z0-9_]+$/);
  const pool = createPool(process.env, 'PG_LEGACY_SENSITIVE_MOVE_TEST_MIGRATION_URL');
  const partial = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-finflow-pre-0007-'));
  const migrations = path.join(__dirname, '../../db/postgres/workshop-migrations/finflow');
  try {
    for (const name of (await fs.readdir(migrations)).filter(name => /^000[1-6]_/.test(name))) {
      await fs.copyFile(path.join(migrations, name), path.join(partial, name));
    }
    await migrate(pool, partial);
    const digest = 'a'.repeat(64);
    await pool.query(`INSERT INTO finflow.import_provenance(archive_sha256,source_table,source_id,source_row)
      VALUES($1,'sensitive_info.db:documents','101','{"legacy":true}'),
            ($1,'finflow_progress','17','{"agent":true}'),
            ($1,'sensitiveXinfo.db:documents','102','{"other":true}')`, [digest]);
    await pool.query(`INSERT INTO finflow.import_batches
      (archive_sha256,importer_version,timestamp_policy,counts,retained_decisions,identity_map_sha256)
      VALUES($1,'legacy-sensitive-v1','UTC','{"documents":1}','[]',NULL)`, [digest]);

    await migrate(pool, migrations);
    assert.deepEqual((await pool.query(`SELECT source_table,source_id,source_row
      FROM legacy_sensitive.import_provenance ORDER BY source_table`)).rows, [
      { source_table: 'sensitive_info.db:documents', source_id: '101', source_row: { legacy: true } },
    ]);
    assert.deepEqual((await pool.query('SELECT source_table FROM finflow.import_provenance ORDER BY source_table')).rows,
      [{ source_table: 'finflow_progress' }, { source_table: 'sensitiveXinfo.db:documents' }]);
    assert.deepEqual((await pool.query(`SELECT importer_version,identity_map_sha256
      FROM legacy_sensitive.import_batches`)).rows,
      [{ importer_version: 'legacy-sensitive-v1', identity_map_sha256: null }]);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM finflow.import_batches')).rows[0].n, 0);
    await pool.query(`INSERT INTO finflow.import_batches
      (archive_sha256,importer_version,timestamp_policy,counts,retained_decisions,identity_map_sha256)
      VALUES($1,'agent-workshop-v1','UTC','{}','[]',$2)`, ['b'.repeat(64), 'c'.repeat(64)]);
    assert.deepEqual((await pool.query('SELECT importer_version,identity_map_sha256 FROM finflow.import_batches')).rows,
      [{ importer_version: 'agent-workshop-v1', identity_map_sha256: 'c'.repeat(64) }]);
    await assert.rejects(pool.query('DELETE FROM legacy_sensitive.import_provenance'), { code: '55000' });
    await assert.rejects(pool.query('DELETE FROM legacy_sensitive.import_batches'), { code: '55000' });
    await assert.rejects(pool.query('DELETE FROM finflow.import_provenance'), { code: '55000' });
    await assert.rejects(pool.query('DELETE FROM finflow.import_batches'), { code: '55000' });
  } finally {
    await pool.end();
    await fs.rm(partial, { recursive: true, force: true });
  }
});
