'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && ['FRESH', 'POPULATED', 'CUSTOM'].every(kind => (
    process.env[`PG_RAG_GUIDANCE_${kind}_MIGRATION_URL`]
    && process.env[`PG_RAG_GUIDANCE_${kind}_RUNTIME_URL`]
  ));
const root = path.resolve(__dirname, '../..');
const candidateName = '0042_rag_upload_guidance.sql';
const workshopKey = 'indirect_prompt_injection';
const objectiveId = 'rag_upload';

function parseChange(sql) {
  const match = sql.match(/SET solution_content=\$rag\$([\s\S]*?)\$rag\$::jsonb,updated_at=now\(\)[\s\S]*?objective_id='rag_upload'[\s\S]*?AND solution_content=\$rag\$([\s\S]*?)\$rag\$::jsonb/);
  assert.ok(match, 'draft contains one exact-default-only RAG solution update');
  return { after: JSON.parse(match[1]), before: JSON.parse(match[2]) };
}

async function copyMigrations(destination) {
  // Reconstruct the pre-0042 store even after the verified migration has been
  // promoted. Never duplicate the candidate or include later migrations here.
  const rows = (await readMigrations(path.join(root, 'db/postgres/identity-migrations')))
    .filter(row => row.name < candidateName);
  for (const row of rows) await fs.writeFile(path.join(destination, row.name), row.sql);
  return rows;
}

async function objective(pool) {
  const result = await pool.query(`SELECT objective_id,label,ordinal,hint_content,solution_content,
      is_enabled,catalog_active FROM workshop_platform.objectives
    WHERE workshop_key=$1 AND objective_id=$2`, [workshopKey, objectiveId]);
  assert.equal(result.rowCount, 1);
  return result.rows[0];
}

async function objectiveIds(pool) {
  return (await pool.query(`SELECT objective_id FROM workshop_platform.objectives
    WHERE workshop_key=$1 ORDER BY objective_id`, [workshopKey])).rows.map(row => row.objective_id);
}

async function revision(pool) {
  return Number((await pool.query(
    'SELECT revision FROM workshop_platform.config_revision WHERE id=1',
  )).rows[0].revision);
}

async function assertLedger(pool, draftSql) {
  const ledger = await pool.query(
    'SELECT checksum FROM dvaia_migrations.ledger WHERE name=$1', [candidateName],
  );
  assert.equal(ledger.rowCount, 1);
  assert.equal(ledger.rows[0].checksum, createHash('sha256').update(draftSql).digest('hex'));
}

test('0042 production loader handles fresh and populated RAG guidance without overwriting instructor edits', {
  skip: !enabled,
  timeout: 60000,
}, async () => {
  const pools = Object.fromEntries(['FRESH', 'POPULATED', 'CUSTOM'].map(kind => [kind, {
    migration: new Pool({ connectionString: process.env[`PG_RAG_GUIDANCE_${kind}_MIGRATION_URL`], max: 2 }),
    runtime: new Pool({ connectionString: process.env[`PG_RAG_GUIDANCE_${kind}_RUNTIME_URL`], max: 2 }),
  }]));
  const baselineDir = await fs.mkdtemp(path.join(
    process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || os.tmpdir(), 'rag-guidance-baseline-',
  ));
  const fullDir = await fs.mkdtemp(path.join(
    process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || os.tmpdir(), 'rag-guidance-full-',
  ));
  try {
    const baseline = await copyMigrations(baselineDir);
    await copyMigrations(fullDir);
    const draftSql = await fs.readFile(
      path.join(root, 'docs/modernization/drafts/rag-upload-guidance.sql'), 'utf8',
    );
    const change = parseChange(draftSql);
    await fs.writeFile(path.join(fullDir, candidateName), draftSql);
    const baselineNames = baseline.map(row => row.name);
    assert.equal(baselineNames.at(-1), '0041_finflow_response_repair_copy.sql');

    assert.deepEqual(await migrate(pools.FRESH.migration, fullDir), [...baselineNames, candidateName]);
    await seedWorkshopPlatform(pools.FRESH.migration);
    assert.deepEqual((await objective(pools.FRESH.runtime)).solution_content, change.after);
    await assert.rejects(
      pools.FRESH.runtime.query('SELECT checksum FROM dvaia_migrations.ledger'),
      { code: '42501' },
      'runtime role cannot inspect the private migration ledger',
    );
    await assertLedger(pools.FRESH.migration, draftSql);
    assert.deepEqual(await migrate(pools.FRESH.migration, fullDir), []);

    for (const kind of ['POPULATED', 'CUSTOM']) {
      assert.deepEqual(await migrate(pools[kind].migration, baselineDir), baselineNames);
      await seedWorkshopPlatform(pools[kind].migration);
    }

    await pools.POPULATED.migration.query(`UPDATE workshop_platform.objectives
      SET solution_content=$1::jsonb,is_enabled=false
      WHERE workshop_key=$2 AND objective_id=$3`, [JSON.stringify(change.before), workshopKey, objectiveId]);
    const populatedBefore = await objective(pools.POPULATED.runtime);
    const populatedIds = await objectiveIds(pools.POPULATED.runtime);
    const populatedRevision = await revision(pools.POPULATED.runtime);
    assert.deepEqual(await migrate(pools.POPULATED.migration, fullDir), [candidateName]);
    assert.deepEqual(await migrate(pools.POPULATED.migration, fullDir), []);
    const populatedAfter = await objective(pools.POPULATED.runtime);
    assert.deepEqual(populatedAfter.solution_content, change.after);
    assert.deepEqual(
      { ...populatedAfter, solution_content: change.before },
      populatedBefore,
      'only the exact shipped solution JSON changes; label, hint and toggles remain intact',
    );
    assert.deepEqual(await objectiveIds(pools.POPULATED.runtime), populatedIds);
    assert.equal(await revision(pools.POPULATED.runtime), populatedRevision + 1);
    await assertLedger(pools.POPULATED.migration, draftSql);

    const custom = {
      title: 'Instructor-authored upload workflow',
      hints: ['Use the cohort-specific document prepared in class.'],
      examples: [],
      approach: 'Retain this content exactly.',
      tips: [],
    };
    await pools.CUSTOM.migration.query(`UPDATE workshop_platform.objectives
      SET solution_content=$1::jsonb,is_enabled=false
      WHERE workshop_key=$2 AND objective_id=$3`, [JSON.stringify(custom), workshopKey, objectiveId]);
    const customBefore = await objective(pools.CUSTOM.runtime);
    const customIds = await objectiveIds(pools.CUSTOM.runtime);
    const customRevision = await revision(pools.CUSTOM.runtime);
    assert.deepEqual(await migrate(pools.CUSTOM.migration, fullDir), [candidateName]);
    assert.deepEqual(await migrate(pools.CUSTOM.migration, fullDir), []);
    assert.deepEqual(await objective(pools.CUSTOM.runtime), customBefore);
    assert.deepEqual(await objectiveIds(pools.CUSTOM.runtime), customIds);
    assert.equal(await revision(pools.CUSTOM.runtime), customRevision);
    await assertLedger(pools.CUSTOM.migration, draftSql);
  } finally {
    await Promise.allSettled(Object.values(pools).flatMap(pair => [pair.runtime.end(), pair.migration.end()]));
    await Promise.all([
      fs.rm(baselineDir, { recursive: true, force: true }),
      fs.rm(fullDir, { recursive: true, force: true }),
    ]);
  }
});
