'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_FINFLOW_COPY_MIGRATION_URL
  && process.env.PG_FINFLOW_COPY_RUNTIME_URL;
const root = path.resolve(__dirname, '../..');
const ids = ['tool_enum', 'llm_identify', 'tool_version', 'admin_enum'];

function parseChanges(sql) {
  const pattern = /SET (hint_content|solution_content)=\$finflow\$([\s\S]*?)\$finflow\$::jsonb,updated_at=now\(\)[\s\S]*?objective_id='([^']+)'[\s\S]*?AND \1=\$finflow\$([\s\S]*?)\$finflow\$::jsonb/g;
  const changes = new Map();
  for (const match of sql.matchAll(pattern)) {
    const [, column, after, id, before] = match;
    changes.set(`${id}:${column}`, { id, column, before: JSON.parse(before), after: JSON.parse(after) });
  }
  return changes;
}

test('0041 real loader updates exact FinFlow defaults, preserves instructor copy, and replays', {
  skip: !enabled, timeout: 60000,
}, async () => {
  const migration = new Pool({ connectionString: process.env.PG_FINFLOW_COPY_MIGRATION_URL, max: 2 });
  const runtime = new Pool({ connectionString: process.env.PG_FINFLOW_COPY_RUNTIME_URL, max: 2 });
  const staged = await fs.mkdtemp(path.join(process.env.DVAIA_ISOLATED_TEST_WORKSPACE || os.tmpdir(), 'finflow-copy-'));
  try {
    const candidateName = '0041_finflow_response_repair_copy.sql';
    const priorMigrations = (await readMigrations(path.join(root, 'db/postgres/identity-migrations')))
      .filter(row => row.name < candidateName);
    assert.ok(priorMigrations.at(-1).name.startsWith('0040_'));
    for (const row of priorMigrations) {
      await fs.writeFile(path.join(staged, row.name), row.sql);
    }
    const draft = await fs.readFile(path.join(root, 'docs/modernization/drafts/0041_finflow_response_repair_copy.sql'), 'utf8');
    await fs.writeFile(path.join(staged, '0041_finflow_response_repair_copy.sql'), draft);
    const baseline = priorMigrations.map(row => row.name);
    assert.deepEqual(await migrate(migration, staged), [...baseline, '0041_finflow_response_repair_copy.sql']);
    // The draft ran before initial teaching content existed. Seed, then recreate
    // the exact prior defaults to exercise the populated-upgrade path.
    await seedWorkshopPlatform(migration);
    const changes = parseChanges(draft);
    assert.equal(changes.size, 8);
    for (const change of changes.values()) {
      await migration.query(`UPDATE workshop_platform.objectives SET ${change.column}=$1::jsonb
        WHERE workshop_key='sensitive_info_disclosure' AND objective_id=$2`,
      [JSON.stringify(change.before), change.id]);
    }
    const custom = { title: 'Instructor custom reconnaissance copy', hints: ['retain exactly'] };
    await migration.query(`UPDATE workshop_platform.objectives SET hint_content=$1::jsonb
      WHERE workshop_key='sensitive_info_disclosure' AND objective_id='admin_enum'`, [JSON.stringify(custom)]);
    const before = await runtime.query(`SELECT objective_id FROM workshop_platform.objectives
      WHERE workshop_key='sensitive_info_disclosure' ORDER BY objective_id`);
    assert.equal(before.rowCount, 18);
    const revision = Number((await runtime.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);

    // Remove only the staged draft ledger row, reproducing a populated store at
    // 0040 while retaining the exact loader-created schema and data.
    await migration.query("DELETE FROM dvaia_migrations.ledger WHERE name='0041_finflow_response_repair_copy.sql'");
    assert.deepEqual(await migrate(migration, staged), ['0041_finflow_response_repair_copy.sql']);
    assert.deepEqual(await migrate(migration, staged), []);
    const after = await runtime.query(`SELECT objective_id,hint_content,solution_content
      FROM workshop_platform.objectives WHERE workshop_key='sensitive_info_disclosure'
      ORDER BY objective_id`);
    assert.deepEqual(after.rows.map(row => row.objective_id), before.rows.map(row => row.objective_id));
    for (const id of ids) {
      const row = after.rows.find(value => value.objective_id === id);
      assert.deepEqual(row.solution_content, changes.get(`${id}:solution_content`).after);
      assert.deepEqual(row.hint_content, id === 'admin_enum' ? custom : changes.get(`${id}:hint_content`).after);
    }
    assert.equal(Number((await runtime.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision), revision + 1);
  } finally {
    await Promise.allSettled([runtime.end(), migration.end()]);
    await fs.rm(staged, { recursive: true, force: true });
  }
});
