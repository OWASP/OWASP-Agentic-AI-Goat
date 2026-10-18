'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createPool } = require('../../server/database/postgres');
const { migrate } = require('../../db/postgres/migrate');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { applyAdditionalPlatformSolutions } = require('../../db/postgres/apply-platform-additional-solutions');
const { fixture, legacyXssContent, legacyXssVisibility } = require('../fixtures/platformAdditionalSolutions');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!process.env.PG_ADDITIONAL_SOLUTIONS_IMPORT_TEST_MIGRATION_URL;
function input() {
  const raw = fixture();
  raw.identityMap = {42:71}; raw.naiveTimestamps = 'UTC';
  raw.sources['users_auth.db'].tables.xss_workshop_solutions = ['reflected','stored_user','stored_llm','email'].map(tab => legacyXssContent(tab));
  raw.sources['users_auth.db'].tables.xss_workshop_solution_visibility = ['reflected','stored_user','stored_llm','email'].map(tab => legacyXssVisibility(tab));
  raw.sources['users_auth.db'].tables.xss_workshop_solutions[0].examples = '[  {"payload":"<script>fixture()</script>", "explanation":"raw spacing retained"} ]';
  raw.sources['users_auth.db'].tables.xss_workshop_solutions[0].hints = 'raw malformed JSON { preserved';
  return raw;
}
test('48 canonical solutions and independent legacy XSS rows preserve values atomically', {skip:!enabled}, async () => {
  const pool = createPool(process.env, 'PG_ADDITIONAL_SOLUTIONS_IMPORT_TEST_MIGRATION_URL');
  let client;
  try {
    await migrate(pool, path.join(__dirname, '../../db/postgres/identity-migrations'));
    await seedWorkshopPlatform(pool);
    client = await pool.connect();
    // Catalog fixture only: remove generated legacy defaults in this disposable database
    // to model the schema-only legacy destination required by the import coordinator.
    await client.query('DELETE FROM workshop_platform.xss_legacy_solutions');
    await client.query('DELETE FROM workshop_platform.xss_legacy_solution_visibility');
    await client.query("INSERT INTO identity.users(id,username,email,password) VALUES(71,'fixture','fixture@example.test',$1)", [require('bcryptjs').hashSync('synthetic-password',4)]);
    const before = (await client.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows;
    const masters = (await client.query('SELECT * FROM workshop_platform.exercises ORDER BY workshop_key')).rows;
    await assert.rejects(applyAdditionalPlatformSolutions(client, input()), {code:'25P01'});
    await client.query('BEGIN');
    const absent = input(); absent.identityMap = {42:99};
    await assert.rejects(applyAdditionalPlatformSolutions(client, absent), {code:'TARGET_IDENTITY_MISSING'});
    await client.query('ROLLBACK');
    await client.query('BEGIN');
    await applyAdditionalPlatformSolutions(client,input());
    await client.query('ROLLBACK');
    assert.deepEqual((await client.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows,before);
    assert.equal((await client.query('SELECT count(*)::int n FROM workshop_platform.xss_legacy_solutions')).rows[0].n,0);
    await client.query('BEGIN');
    const report = await applyAdditionalPlatformSolutions(client,input());
    await client.query('COMMIT');
    assert.equal(report.counts.solutions,48); assert.equal(report.counts.legacySolutions,4); assert.equal(report.chosenOrigins.length,104);
    const legacy = (await client.query("SELECT *,updated_at::text AS stamp FROM workshop_platform.xss_legacy_solutions WHERE challenge_id='reflected'")).rows[0];
    assert.equal(legacy.examples,input().sources['users_auth.db'].tables.xss_workshop_solutions[0].examples);
    assert.equal(legacy.title,'Legacy tab content');
    assert.equal(legacy.hints,'raw malformed JSON { preserved');
    assert.match(legacy.stamp,/2025-01-02 03:04:05/);
    const visibility = (await client.query("SELECT * FROM workshop_platform.xss_legacy_solution_visibility WHERE challenge_id='reflected'")).rows[0];
    assert.equal(visibility.enabled_by,71); assert.equal(visibility.solutions_enabled,false);
    const after = (await client.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows;
    const canonical = after.find(row=>row.objective_id==='xss_r1');
    assert.equal(canonical.solution_content.title,'Title xss_r1');
    for(let i=0;i<after.length;i++) {
      assert.deepEqual(after[i].hint_content,before[i].hint_content);
      assert.equal(after[i].hint_enabled,before[i].hint_enabled);
    }
    assert.deepEqual((await client.query('SELECT * FROM workshop_platform.exercises ORDER BY workshop_key')).rows,masters);
    for(const table of ['completions','objective_judgments','time_tracking']) assert.equal((await client.query(`SELECT count(*)::int n FROM workshop_platform.${table}`)).rows[0].n,0);
    await client.query('BEGIN');
    await assert.rejects(applyAdditionalPlatformSolutions(client,input()),{code:'LEGACY_SOLUTION_IMPORT_REQUIRES_EMPTY_TARGET'});
    await client.query('ROLLBACK');
    client.release(); client=null;
    await seedWorkshopPlatform(pool);
    client=await pool.connect();
    assert.deepEqual((await client.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows,after);
    assert.equal((await client.query("SELECT examples FROM workshop_platform.xss_legacy_solutions WHERE challenge_id='reflected'")).rows[0].examples,legacy.examples);
  } finally { if(client) client.release(); await pool.end(); }
});
