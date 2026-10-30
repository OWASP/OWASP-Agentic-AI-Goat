'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const Module = require('node:module');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { initializeIdentityRepository, createIdentityRepository } = require(
  '../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const activation = require('../../docs/modernization/drafts/secureshopPersonaInboxActivationCandidate');
const catalogCurriculum = require(
  '../../docs/modernization/drafts/secureshopPersonaCatalogCurriculumCandidate');

const PREFIX = 'PG_SECURESHOP_PERSONA_CATALOG_';
const VARIANTS = ['FRESH', 'POPULATED'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && VARIANTS.every(variant =>
  ['MIGRATION', 'RUNTIME'].every(role => process.env[`${PREFIX}${variant}_${role}_URL`]));
const ROOT = path.join(__dirname, '../..');
const WORKSHOP = 'secureshop_agent_security';
const IDS = activation.QUALIFIED;

function ownedUrl(key) {
  const value = new URL(process.env[key]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return value.href;
}
function compile(source, filename) {
  const value = new Module(filename, module);
  value.filename = filename;
  value.paths = Module._nodeModulePaths(path.dirname(filename));
  value._compile(source, filename);
  return value.exports;
}
function curriculumPair() {
  const source = fs.readFileSync(path.join(ROOT, 'server/config/secureshopCurriculum.js'), 'utf8');
  const oldValue = require('../../server/config/secureshopCurriculum');
  const activated = activation.buildCandidates({
    application: fs.readFileSync(path.join(ROOT, 'server/services/secureshopBoundApplication.js'), 'utf8'),
    composition: fs.readFileSync(path.join(ROOT, 'server/services/secureshopBoundReviewComposition.js'), 'utf8'),
    curriculum: source,
  }).curriculum;
  const generated = catalogCurriculum.buildCandidate(activated);
  return { oldValue, newValue: compile(generated, path.join(ROOT, 'server/config/.candidateCurriculum.js')) };
}
async function seed(pool, curriculum) {
  return seedWorkshopPlatform(pool, { catalog: { [WORKSHOP]: curriculum.OBJECTIVES },
    hints: { [WORKSHOP]: curriculum.HINTS }, solutions: { [WORKSHOP]: curriculum.SOLUTIONS },
    challenges: [curriculum.CHALLENGE] });
}
async function snapshot(pool, userId) {
  const [exercise, objectives, progress, activity, time, configRevision, scopedRevision] = await Promise.all([
    pool.query(`SELECT challenge_description,route,is_visible,show_hints,show_solutions
      FROM workshop_platform.exercises WHERE workshop_key=$1`, [WORKSHOP]),
    pool.query(`SELECT objective_id,label,is_enabled,hint_enabled,solution_enabled,hint_content,solution_content
      FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=ANY($2::text[])
      ORDER BY objective_id`, [WORKSHOP, IDS]),
    pool.query(`SELECT objective_id,completed_at,updated_at FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id`, [userId, WORKSHOP]),
    pool.query(`SELECT activity_key,activity_count,updated_at
      FROM workshop_platform.activity_counters WHERE user_id=$1 AND workshop_key=$2 ORDER BY activity_key`,
    [userId, WORKSHOP]),
    pool.query(`SELECT duration_seconds,session_start,last_heartbeat
      FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key=$2`, [userId, WORKSHOP]),
    pool.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1'),
    pool.query(`SELECT revision FROM workshop_platform.revisions
      WHERE scope_type='workshop' AND scope_key=$1 AND category='workshop_config'`, [WORKSHOP]),
  ]);
  return { exercise: exercise.rows[0], objectives: objectives.rows,
    progress: progress.rows, activity: activity.rows, time: time.rows,
    configRevision: Number(configRevision.rows[0].revision),
    scopedRevision: scopedRevision.rowCount ? Number(scopedRevision.rows[0].revision) : 0 };
}

test('persona catalog transition is fresh-safe and preserves populated instructor and learner state', {
  skip: !enabled, timeout: 60000,
}, async t => {
  const curricula = curriculumPair();
  const stores = [];
  const currentDir = path.join(ROOT, 'db/postgres/identity-migrations');
  try {
    for (const variant of VARIANTS) {
      const migration = new Pool({ connectionString: ownedUrl(`${PREFIX}${variant}_MIGRATION_URL`), max: 4 });
      const runtime = new Pool({ connectionString: ownedUrl(`${PREFIX}${variant}_RUNTIME_URL`), max: 4 });
      stores.push({ variant, migration, runtime });
      if (variant === 'FRESH') {
        assert.ok((await initializeIdentityRepository(runtime, migration))
          .includes('0047_secureshop_persona_inbox_catalog.sql'));
        await seed(migration, curricula.newValue);
      } else {
        const priorDir = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-persona-catalog-prior-'));
        t.after(() => fs.rmSync(priorDir, { recursive: true, force: true }));
        for (const name of fs.readdirSync(currentDir).filter(name => name.endsWith('.sql')
          && name !== '0047_secureshop_persona_inbox_catalog.sql')) {
          fs.copyFileSync(path.join(currentDir, name), path.join(priorDir, name));
        }
        await migrate(migration, priorDir);
        await seed(migration, curricula.oldValue);
        const user = await createIdentityRepository(runtime).createUser({ username: 'catalog-populated-owner',
          email: 'catalog-populated-owner@example.invalid', passwordHash: await bcrypt.hash('OwnedCatalog#2026', 4) });
        stores.at(-1).userId = user.id;
        await migration.query(`UPDATE workshop_platform.exercises SET route='',is_visible=true,
          show_hints=true,show_solutions=true,challenge_description='Instructor custom SecureShop description'
          WHERE workshop_key=$1`, [WORKSHOP]);
        await migration.query(`UPDATE workshop_platform.objectives SET label='Instructor custom advisory label',
          hint_content='{"title":"Instructor hint","hints":["Retain this"]}'::jsonb,
          solution_content='{"title":"Instructor solution","approach":"Retain this"}'::jsonb,
          hint_enabled=false,solution_enabled=true WHERE workshop_key=$1 AND objective_id=$2`,
        [WORKSHOP, 'ss_acl_advisory_effect']);
        await migration.query(`UPDATE workshop_platform.objectives
          SET hint_content='{"title":"Instructor enforced hint","hints":["Retain only hint"]}'::jsonb
          WHERE workshop_key=$1 AND objective_id=$2`, [WORKSHOP, 'ss_acl_enforced_block']);
        await migration.query(`INSERT INTO workshop_platform.user_state
          (user_id,workshop_key,generation) VALUES($1,$2,4)`, [user.id, WORKSHOP]);
        await migration.query(`INSERT INTO workshop_platform.completions
          (user_id,workshop_key,objective_id) VALUES($1,$2,$3)`, [user.id, WORKSHOP, IDS[0]]);
        await migration.query(`INSERT INTO workshop_platform.activity_counters
          (user_id,workshop_key,activity_key,activity_count)
          VALUES($1,$2,'catalog-before',2)`, [user.id, WORKSHOP]);
        await migration.query(`INSERT INTO workshop_platform.time_tracking
          (user_id,workshop_key,session_start,last_heartbeat,duration_seconds)
          VALUES($1,$2,clock_timestamp()-interval '10 minutes',clock_timestamp(),321)`, [user.id, WORKSHOP]);
        stores.at(-1).before = await snapshot(migration, user.id);
        assert.deepEqual(await initializeIdentityRepository(runtime, migration),
          ['0047_secureshop_persona_inbox_catalog.sql']);
        await seed(migration, curricula.newValue);
      }
    }

    for (const store of stores) {
      assert.deepEqual(await initializeIdentityRepository(store.runtime, store.migration), []);
      const ledger = (await store.migration.query(`SELECT name,checksum FROM dvaia_migrations.ledger
        ORDER BY name`)).rows;
      assert.equal(ledger.at(-1).name, '0047_secureshop_persona_inbox_catalog.sql');
      assert.equal(ledger.at(-1).checksum,
        'e12496c0ebf7c3927ab2d967afa286b3e5774d88f4223527444c222c19ed3e64');
      const userId = store.userId || 0;
      const after = await snapshot(store.migration, userId);
      assert.equal(after.exercise.route, '/workshop/secureshop');
      assert.equal(after.objectives.length, 3);
      assert.ok(after.objectives.every(row => row.is_enabled === false));
      if (store.variant === 'FRESH') {
        assert.equal(after.exercise.is_visible, false);
        assert.equal(after.exercise.challenge_description, curricula.newValue.CHALLENGE.description);
        for (const row of after.objectives) {
          assert.equal(row.label, curricula.newValue.OBJECTIVES.find(value => value.id === row.objective_id).text);
          assert.deepEqual(row.hint_content, curricula.newValue.HINTS[row.objective_id]);
          assert.deepEqual(row.solution_content, curricula.newValue.SOLUTIONS[row.objective_id]);
        }
      } else {
        assert.equal(after.exercise.is_visible, true);
        assert.equal(after.exercise.show_hints, true);
        assert.equal(after.exercise.show_solutions, true);
        assert.equal(after.exercise.challenge_description, 'Instructor custom SecureShop description');
        const advisory = after.objectives.find(row => row.objective_id === 'ss_acl_advisory_effect');
        assert.equal(advisory.label, 'Instructor custom advisory label');
        assert.deepEqual(advisory.hint_content, { title: 'Instructor hint', hints: ['Retain this'] });
        assert.deepEqual(advisory.solution_content, { title: 'Instructor solution', approach: 'Retain this' });
        assert.equal(advisory.hint_enabled, false); assert.equal(advisory.solution_enabled, true);
        const enforced = after.objectives.find(row => row.objective_id === 'ss_acl_enforced_block');
        assert.deepEqual(enforced.hint_content,
          { title: 'Instructor enforced hint', hints: ['Retain only hint'] });
        assert.deepEqual(enforced.solution_content, curricula.newValue.SOLUTIONS.ss_acl_enforced_block);
        const cross = after.objectives.find(row => row.objective_id === 'ss_cross_persona_effect');
        assert.deepEqual(cross.hint_content, curricula.newValue.HINTS.ss_cross_persona_effect);
        assert.deepEqual(cross.solution_content, curricula.newValue.SOLUTIONS.ss_cross_persona_effect);
        assert.deepEqual(after.progress, store.before.progress);
        assert.deepEqual(after.activity, store.before.activity);
        assert.deepEqual(after.time, store.before.time);
        assert.ok(after.configRevision > store.before.configRevision);
        assert.ok(after.scopedRevision > store.before.scopedRevision);
      }
      const beforeNoop = { configRevision: after.configRevision, scopedRevision: after.scopedRevision };
      await store.migration.query(fs.readFileSync(path.join(currentDir,
        '0047_secureshop_persona_inbox_catalog.sql'), 'utf8'));
      const afterNoop = await snapshot(store.migration, userId);
      assert.deepEqual({ configRevision: afterNoop.configRevision, scopedRevision: afterNoop.scopedRevision },
        beforeNoop, 'reapplying an already-satisfied transition emits no revision');
      assert.equal((await store.runtime.query('SELECT current_user AS role')).rows[0].role,
        'dvaia_identity_runtime');
    }
  } finally {
    await Promise.allSettled(stores.flatMap(store => [store.runtime.end(), store.migration.end()]));
  }
});
