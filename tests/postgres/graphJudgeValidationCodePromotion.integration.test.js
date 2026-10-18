'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { Pool } = require('pg');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_GRAPH_VALIDATION_PROMOTION_RUNTIME_URL
  && process.env.PG_GRAPH_VALIDATION_PROMOTION_MIGRATION_URL;

test('reserved 0046 loads after the exact 0045 ledger, preserves events and replays empty', {
  skip: !enabled,
}, async t => {
  for (const name of ['PG_GRAPH_VALIDATION_PROMOTION_RUNTIME_URL', 'PG_GRAPH_VALIDATION_PROMOTION_MIGRATION_URL']) {
    assert.match(new URL(process.env[name]).pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  }
  const runtime = new Pool({ connectionString: process.env.PG_GRAPH_VALIDATION_PROMOTION_RUNTIME_URL, max: 2 });
  const migration = new Pool({ connectionString: process.env.PG_GRAPH_VALIDATION_PROMOTION_MIGRATION_URL, max: 1 });
  const staged = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-identity-0046-'));
  t.after(() => fs.rm(staged, { recursive: true, force: true }));
  try {
    const applied = await require('../../server/database/postgres/identityRepository')
      .initializeIdentityRepository(runtime, migration);
    assert.ok(Array.isArray(applied));
    const sourceMigrations = path.resolve(__dirname, '../../db/postgres/identity-migrations');
    const names = (await fs.readdir(sourceMigrations)).filter(name => name.endsWith('.sql')).sort();
    assert.equal(names.at(-1)?.slice(0, 4), '0045');
    const currentLedger = (await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.equal(currentLedger.at(-1)?.name, names.at(-1));
    assert.equal(currentLedger.length, names.length);
    for (const name of names) await fs.copyFile(path.join(sourceMigrations, name), path.join(staged, name));
    const draft = await fs.readFile(path.resolve(__dirname,
      '../../docs/modernization/drafts/graph-judge-validation-code.sql'));
    const expectedChecksum = crypto.createHash('sha256').update(draft).digest('hex');
    assert.equal(expectedChecksum, 'd5b40afc1d3c43c2371ec30fd9d1cc119a935cbc1840ef3b11c8bc4cfa6be936');
    const registeredName = '0046_graph_judge_validation_code.sql';
    await fs.writeFile(path.join(staged, registeredName), draft, { flag: 'wx', mode: 0o600 });

    const runId = crypto.randomUUID();
    const ownerKey = JSON.stringify(['MCP', 'preexisting-0046-event']);
    await migration.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)', [ownerKey]);
    await migration.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'completed')", [runId, ownerKey]);
    const legacyMetadata = { errorCode: 'INVALID_JUDGE_OUTPUT', objectiveId: 'historic_objective' };
    await migration.query(`INSERT INTO graph_runtime.events
      (run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,1,'judge_validate','error',$3::jsonb)`,
    [runId, ownerKey, JSON.stringify(legacyMetadata)]);
    const existingEvent = (await runtime.query(`SELECT run_id,owner_key,sequence,node,event_type,metadata,created_at
      FROM graph_runtime.events WHERE run_id=$1 AND owner_key=$2 AND sequence=1`, [runId, ownerKey])).rows[0];

    const { migrate } = require('../../db/postgres/migrate');
    assert.deepEqual(await migrate(migration, staged), [registeredName]);
    const completeLedger = (await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(completeLedger.slice(0, currentLedger.length), currentLedger);
    const ledger = completeLedger.at(-1);
    assert.deepEqual(ledger, { name: registeredName, checksum: expectedChecksum });
    const preserved = (await runtime.query(`SELECT run_id,owner_key,sequence,node,event_type,metadata,created_at
      FROM graph_runtime.events WHERE run_id=$1 AND owner_key=$2 AND sequence=1`, [runId, ownerKey])).rows[0];
    assert.deepEqual(preserved, existingEvent);
    await runtime.query(`INSERT INTO graph_runtime.events
      (run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,2,'judge_validate','error',$3::jsonb)`,
    [runId, ownerKey, JSON.stringify({ errorCode: 'INVALID_JUDGE_OUTPUT', validationCode: 'JSON_SYNTAX' })]);
    assert.deepEqual(await migrate(migration, staged), []);
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM graph_runtime.events WHERE run_id=$1', [runId])).rows[0].n, 2);
    assert.equal((await migration.query('SELECT count(*)::int AS n FROM dvaia_migrations.ledger WHERE name=$1', [registeredName])).rows[0].n, 1);
  } finally {
    await Promise.all([runtime.end(), migration.end()]);
  }
});
