'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createPool } = require('../../server/database/postgres');
const { migrate } = require('../../db/postgres/migrate');
const { FAMILIES } = require('../../db/postgres/map-platform-solutions');
const { applyPlatformSolutions } = require('../../db/postgres/apply-platform-solutions');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');

function fixture() {
  const tables = {};
  for (const config of Object.values(FAMILIES)) {
    tables[config.contentTable] = config.objectiveIds.map((id, index) => ({
      ...(config.contentHasId ? { id: index + 1 } : {}), [config.idColumn]: id,
      title: `Edited ${id}`, difficulty: 'Intermediate', hints: '["preserved solution hint"]',
      examples: '[{"prompt":"example","explanation":"why"}]', approach: 'Instructor edited approach', tips: '[]',
      ...(config.contentHasTimestamp ? { updated_at: '2026-01-01 00:00:00' } : {}),
    }));
    tables[config.visibilityTable] = config.objectiveIds.map((id, index) => ({
      ...(config.visibilityHasId ? { id: index + 1 } : {}), [config.idColumn]: id,
      solutions_enabled: index % 2, updated_at: '2026-01-01 00:00:00',
      ...(config.visibilityTracksActor ? { enabled_by: null, enabled_at: null } : {}),
    }));
  }
  return { sources: { 'users_auth.db': { tables } }, archiveDigest: 'b'.repeat(64) };
}

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!process.env.PG_SOLUTIONS_IMPORT_TEST_MIGRATION_URL;
test('52 solution mappings apply atomically without changing hints, masters or historical progress', { skip: !enabled }, async () => {
  const pool = createPool(process.env, 'PG_SOLUTIONS_IMPORT_TEST_MIGRATION_URL');
  let client;
  try {
    await migrate(pool, path.join(__dirname, '../../db/postgres/identity-migrations'));
    await seedWorkshopPlatform(pool);
    client = await pool.connect();
    const before = (await client.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows;
    const exercises = (await client.query('SELECT * FROM workshop_platform.exercises ORDER BY workshop_key')).rows;
    await assert.rejects(applyPlatformSolutions(client, fixture()), { code: '25P01' });
    const missing = fixture();
    missing.sources['users_auth.db'].tables.ipi_solutions.pop();
    await assert.rejects(applyPlatformSolutions(client, missing), { code: 'SOLUTION_IMPORT_REQUIRES_REVIEW' });
    await assert.rejects(applyPlatformSolutions(client, { ...fixture(), archiveDigest: 'invalid' }), { code: 'ARCHIVE_DIGEST_REQUIRED' });
    const conflict = fixture();
    const nova = FAMILIES.nosql_injection_workshop;
    conflict.sources['nosql_workshop.db'] = { tables: {
      [nova.contentTable]: structuredClone(conflict.sources['users_auth.db'].tables[nova.contentTable]),
      [nova.visibilityTable]: structuredClone(conflict.sources['users_auth.db'].tables[nova.visibilityTable]),
    } };
    conflict.sources['nosql_workshop.db'].tables[nova.contentTable][0].title = 'Other origin';
    await assert.rejects(applyPlatformSolutions(client, conflict), { code: 'SOLUTION_IMPORT_REQUIRES_REVIEW' });
    conflict.resolutions = { 'nosql_injection_workshop:nosqli_1:content': { archiveDigest: conflict.archiveDigest, source: 'nosql_workshop.db' } };
    await client.query('BEGIN');
    await client.query("DELETE FROM workshop_platform.objectives WHERE workshop_key='sql_injection_workshop' AND objective_id='sqli_10'");
    await assert.rejects(applyPlatformSolutions(client, fixture()), { code: 'SOLUTION_IMPORT_TARGET_MISSING' });
    await client.query('ROLLBACK');
    await client.query('BEGIN');
    await applyPlatformSolutions(client, fixture());
    await client.query('ROLLBACK');
    assert.deepEqual((await client.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows, before);
    await client.query('BEGIN');
    const report = await applyPlatformSolutions(client, conflict);
    await client.query('COMMIT');
    assert.deepEqual(report.counts, { solutions: 52, solutionVisibility: 52 });
    assert.equal(report.chosenOrigins.length, 104);
    assert.equal(report.decisions[0].selectedSource, 'nosql_workshop.db');
    assert.deepEqual(report.unmappedFamilies.sort(), Object.keys(require('../../server/config/workshopCatalog').WORKSHOP_OBJECTIVES).filter(key => !Object.hasOwn(FAMILIES, key)).sort());
    const after = (await client.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows;
    for (let index = 0; index < after.length; index++) {
      assert.equal(after[index].hint_enabled, before[index].hint_enabled);
      assert.deepEqual(after[index].hint_content, before[index].hint_content);
      const config = FAMILIES[after[index].workshop_key];
      const mappedIndex = config?.objectiveIds.indexOf(after[index].objective_id) ?? -1;
      if (mappedIndex >= 0) {
        assert.equal(after[index].solution_enabled, mappedIndex % 2 === 1);
        assert.equal(after[index].solution_content.approach, 'Instructor edited approach');
      } else assert.deepEqual(after[index], before[index]);
    }
    assert.deepEqual((await client.query('SELECT * FROM workshop_platform.exercises ORDER BY workshop_key')).rows, exercises);
    for (const table of ['completions', 'objective_judgments', 'time_tracking']) {
      assert.equal((await client.query(`SELECT count(*)::int AS n FROM workshop_platform.${table}`)).rows[0].n, 0);
    }
    client.release();
    client = null;
    await seedWorkshopPlatform(pool);
    client = await pool.connect();
    assert.deepEqual((await client.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows, after);
  } finally {
    if (client) client.release();
    await pool.end();
  }
});
