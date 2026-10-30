'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { initializeIdentityRepository, createIdentityRepository } = require(
  '../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require(
  '../../server/database/postgres/workshopPlatformSeed');
const { WORKSHOP_OBJECTIVES } = require('../../server/config/workshopCatalog');
const { createWorkshopConfigRepository } = require(
  '../../server/database/postgres/workshopConfigRepository');
const provenancePath=path.join(__dirname,'../../server/database/postgres/catalogDefaultProvenance.js');
const provenance = fs.existsSync(provenancePath)
  ? require('../../server/database/postgres/catalogDefaultProvenance')
  : require('../../docs/modernization/drafts/catalogDefaultProvenance.candidate');
const { fixture: historical116, seedRelease116, arrangePrior116 } = require(
  '../helpers/workshopCatalogRelease116');
const { createXssBoundedMigrationView } = require('../helpers/xssBoundedMigrationView');
const historicalView = createXssBoundedMigrationView({ identity: 49 });
const initializeRelease = historicalView.initializeIdentityRepository;
const PREFIX = 'PG_WORKSHOP_CATALOG_RELEASE_';
const VARIANTS = ['FRESH', 'POPULATED'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && VARIANTS.every(variant =>
  ['MIGRATION', 'RUNTIME'].every(role => process.env[`${PREFIX}${variant}_${role}_URL`]));
const ROOT = path.join(__dirname, '../..');
const WORKSHOP = 'secureshop_agent_security';
const IDS = ['ss_cross_persona_effect','ss_acl_advisory_effect','ss_acl_enforced_block'];

function ownedUrl(key) {
  const value = new URL(process.env[key]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return value.href;
}
async function seed(pool, curriculum) {
  return seedRelease116(pool, curriculum);
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
    pool.query(`SELECT duration_seconds,session_start,last_heartbeat,platform_launch_id,
      platform_scenario_id,platform_launch_generation,workshop_generation
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

test('historical release fixture retains the root-bound116 catalog and Persona predecessor', () => {
  assert.equal(historical116.provenance.root, 'owasp-ai-goat-workshop-catalog-release-0i69aob9/source');
  assert.equal(historical116.provenance.sourceHashes['server/config/workshopCatalog.js'],
    '54be1234e42d524e8090fe334bfb24538b8f0442b04b25d326169d75b0ceaa32');
  assert.equal(historical116.provenance.sourceHashes['server/database/postgres/workshopPlatformSeed.js'],
    '6c26c5333633891593fb56597751fc0a9e877d6086fdf88171cb3c78b35e66db');
  assert.equal(Object.values(historical116.catalog).flat().length, 116);
  assert.deepEqual(historical116.oldCurriculum.OBJECTIVES.map(row => row.id),
    historical116.newCurriculum.OBJECTIVES.map(row => row.id));
  assert.notDeepEqual(historical116.oldCurriculum.HINTS, historical116.newCurriculum.HINTS,
    'a prior curriculum fallback must not erase the historical adoption transition');
});

test('catalog provenance release integrates actual seed and admin paths after the Persona transition', {
  skip: !enabled, timeout: 60000,
}, async () => {
  const curricula = { oldValue:historical116.oldCurriculum, newValue:historical116.newCurriculum };
  const stores = [];
  const currentDir = path.join(ROOT, 'db/postgres/identity-migrations');
  try {
    for (const variant of VARIANTS) {
      const migration = new Pool({ connectionString: ownedUrl(`${PREFIX}${variant}_MIGRATION_URL`), max: 4 });
      const runtime = new Pool({ connectionString: ownedUrl(`${PREFIX}${variant}_RUNTIME_URL`), max: 4 });
      stores.push({ variant, migration, runtime });
      if (variant === 'FRESH') {
        assert.deepEqual((await initializeRelease(runtime, migration)).slice(-3), [
          '0047_secureshop_persona_inbox_catalog.sql',
          '0048_workshop_catalog_field_provenance.sql',
          '0049_workshop_catalog_persona_adoption.sql']);
        const sortObjectives=rows=>rows.sort((left,right)=>{
          const a=`${left.workshop_key}\0${left.objective_id}`;
          const b=`${right.workshop_key}\0${right.objective_id}`;
          return a<b?-1:a>b?1:0;
        });
        const expectedObjectives=sortObjectives(Object.entries(historical116.catalog)
          .flatMap(([workshopKey,objectives])=>objectives
            .map(objective=>({workshop_key:workshopKey,objective_id:objective.id}))));
        assert.equal(expectedObjectives.length,116,'reviewed release has 116 canonical objectives');
        assert.equal((await seedRelease116(migration)).changed,true);
        assert.equal((await seedRelease116(migration)).changed,false,
          'complete default fixture replay is a no-op');
        const actualObjectives=sortObjectives((await migration.query(`SELECT workshop_key,objective_id
          FROM workshop_platform.objectives WHERE catalog_active=true`)).rows);
        assert.deepEqual(actualObjectives,expectedObjectives);
        assert.deepEqual((await migration.query(`SELECT workshop_key FROM workshop_platform.exercises
          WHERE catalog_active=true ORDER BY workshop_key`)).rows.map(row=>row.workshop_key),
        Object.keys(historical116.catalog).sort());
        const fixtureSolutions=historical116.solutions;
        for(const workshopKey of ['sql_injection_workshop','nosql_injection_workshop']){
          const objectiveId=historical116.catalog[workshopKey][0].id;
          const actual=(await migration.query(`SELECT hint_content FROM workshop_platform.objectives
            WHERE workshop_key=$1 AND objective_id=$2`,[workshopKey,objectiveId])).rows[0].hint_content;
          const source=fixtureSolutions[workshopKey][objectiveId];
          assert.deepEqual(actual,{title:source.title,hints:source.hints||[]},
            `${workshopKey} retains solution-derived hint fallback`);
        }
        assert.equal((await migration.query(`SELECT count(*)::integer AS count
          FROM workshop_platform.xss_legacy_solution_visibility`)).rows[0].count,4);
        assert.equal((await migration.query(`SELECT count(*)::integer AS count
          FROM workshop_platform.xss_legacy_solutions`)).rows[0].count,4);
        const secureShopState=(await migration.query(`SELECT e.is_visible,bool_or(o.is_enabled) AS any_enabled
          FROM workshop_platform.exercises e JOIN workshop_platform.objectives o USING(workshop_key)
          WHERE e.workshop_key=$1 GROUP BY e.is_visible`,[WORKSHOP])).rows[0];
        assert.deepEqual(secureShopState,{is_visible:false,any_enabled:false});
      } else {
        historicalView.setCeiling('identity', 46);
        await historicalView.migrate(migration, currentDir);
        await arrangePrior116(migration);
        historicalView.setCeiling('identity', 49);
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
        const platformSession=(await migration.query(`INSERT INTO identity.user_sessions
          (user_id,session_token_hash,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour')
          RETURNING id`,[user.id,'ab'.repeat(32)])).rows[0];
        const launchId=randomUUID(),scenarioId=randomUUID(),activityContributionId=randomUUID();
        await migration.query(`INSERT INTO identity.secureshop_launches
          (launch_id,platform_session_id,original_platform_session_id,original_platform_owner_id,
           handle_hash,scenario_id,expires_at) VALUES($1,$2,$2,$3,decode($4,'hex'),$5,
           clock_timestamp()+interval '1 hour')`,
        [launchId,platformSession.id,user.id,'cd'.repeat(32),scenarioId]);
        await migration.query(`INSERT INTO workshop_platform.completions
          (user_id,workshop_key,objective_id) VALUES($1,$2,$3)`, [user.id, WORKSHOP, IDS[0]]);
        assert.deepEqual((await runtime.query(`SELECT * FROM
          workshop_platform.record_secureshop_activity_contribution($1,$2,$3,$4,$5,$6,$7,$8)`,
        [user.id,activityContributionId,'catalog-before',2,launchId,scenarioId,1,4])).rows,
        [{changed:true,activity_count:2}]);
        assert.deepEqual((await runtime.query(`SELECT * FROM
          workshop_platform.record_secureshop_heartbeat($1,$2,$3,$4,$5)`,
        [user.id,launchId,scenarioId,1,4])).rows,[{added:0,new_session:true}]);
        // Arrange an elapsed interval in this disposable fixture without sleeping or
        // writing duration credit. The runtime API still checks session/launch scope
        // and calculates the amount credited from its own database clock.
        const priorHeartbeat = await migration.query(`UPDATE workshop_platform.time_tracking
          SET last_heartbeat=clock_timestamp()-interval '60 seconds'
          WHERE user_id=$1 AND workshop_key=$2 AND platform_launch_id=$3
            AND platform_scenario_id=$4 AND platform_launch_generation=1
            AND workshop_generation=4 AND duration_seconds=0`,
        [user.id,WORKSHOP,launchId,scenarioId]);
        assert.equal(priorHeartbeat.rowCount,1,'exact owned initial heartbeat arranged');
        const accumulated = (await runtime.query(`SELECT * FROM
          workshop_platform.record_secureshop_heartbeat($1,$2,$3,$4,$5)`,
        [user.id,launchId,scenarioId,1,4])).rows;
        assert.equal(accumulated.length,1);
        assert.equal(accumulated[0].new_session,false);
        assert.ok(Number.isInteger(accumulated[0].added)
          && accumulated[0].added>0 && accumulated[0].added<120,
        'canonical heartbeat must accumulate nonzero time in the same session');
        stores.at(-1).before = await snapshot(migration, user.id);
        assert.equal(stores.at(-1).before.time[0].duration_seconds,accumulated[0].added,
          'preservation baseline contains the canonical nonzero duration');
        assert.deepEqual(stores.at(-1).before.activity.map(row=>({
          activity_key:row.activity_key,activity_count:row.activity_count,
        })),[{activity_key:'catalog-before',activity_count:2}]);
        assert.equal(stores.at(-1).before.time.length,1,
          'canonical heartbeat created launch-bound learner time state');
        assert.deepEqual(await initializeRelease(runtime, migration), [
          '0047_secureshop_persona_inbox_catalog.sql',
          '0048_workshop_catalog_field_provenance.sql',
          '0049_workshop_catalog_persona_adoption.sql']);
        await seed(migration, curricula.newValue);
      }
    }

    for (const store of stores) {
      assert.deepEqual(await initializeRelease(store.runtime, store.migration), []);
      const historicalIdentities = Object.entries(historical116.catalog)
        .flatMap(([workshopKey, objectives]) => objectives
          .map(objective => `${workshopKey}\0${objective.id}`)).sort();
      assert.equal(historicalIdentities.length, 116);
      assert.deepEqual((await store.migration.query(`SELECT workshop_key,objective_id
        FROM workshop_platform.objectives WHERE catalog_active=true`)).rows
        .map(row => `${row.workshop_key}\0${row.objective_id}`).sort(), historicalIdentities,
      `${store.variant} preserves exact historical116 identities before the current tail`);
      const ledger = (await store.migration.query(`SELECT name,checksum FROM dvaia_migrations.ledger
        ORDER BY name`)).rows;
      assert.equal(ledger.at(-1).name, '0049_workshop_catalog_persona_adoption.sql');
      assert.equal(ledger.at(-3).checksum,
        'e12496c0ebf7c3927ab2d967afa286b3e5774d88f4223527444c222c19ed3e64');
      assert.equal(ledger.at(-2).checksum,
        '96ea10297e339cc277a0c76db8dad7028f5683b1dbc1db46a3d913889fe24de2');
      assert.equal(ledger.at(-1).checksum,
        'aa22efe7d731bbb378f6cc9d7954f109af34573773f2f0f6ade10098b02abccb');
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
      for (const name of ['0047_secureshop_persona_inbox_catalog.sql',
        '0049_workshop_catalog_persona_adoption.sql']) {
        await store.migration.query(fs.readFileSync(path.join(currentDir,name), 'utf8'));
      }
      const afterNoop = await snapshot(store.migration, userId);
      assert.deepEqual({ configRevision: afterNoop.configRevision, scopedRevision: afterNoop.scopedRevision },
        beforeNoop, 'reapplying an already-satisfied transition emits no revision');
      assert.equal((await store.runtime.query('SELECT current_user AS role')).rows[0].role,
        'dvaia_identity_runtime');
      const managed = (await store.migration.query(`SELECT objective_id,field_name,provenance_state
        FROM workshop_platform.catalog_field_defaults WHERE workshop_key=$1
        ORDER BY objective_id,field_name`,[WORKSHOP])).rows;
      assert.ok(managed.length > 0);
      if (store.variant === 'FRESH') assert.ok(managed.every(row=>row.provenance_state==='managed'));
      else {
        assert.equal(managed.find(row=>row.objective_id===''&&row.field_name==='route').provenance_state,'managed');
        assert.equal(managed.find(row=>row.objective_id==='ss_acl_advisory_effect'
          &&row.field_name==='hint_content').provenance_state,'legacy_unknown');
      }
      if (store.variant === 'FRESH') {
        const admin=createWorkshopConfigRepository(store.runtime,{isSecureShopReady:()=>true});
        const beforeVisibilityStates=(await store.migration.query(`SELECT field_name,provenance_state
          FROM workshop_platform.catalog_field_defaults WHERE workshop_key=$1
          ORDER BY entity_kind,objective_id,field_name`,[WORKSHOP])).rows;
        await admin.setExerciseVisibility(WORKSHOP,true);
        await admin.setExerciseVisibility(WORKSHOP,false);
        assert.deepEqual((await store.migration.query(`SELECT field_name,provenance_state
          FROM workshop_platform.catalog_field_defaults WHERE workshop_key=$1
          ORDER BY entity_kind,objective_id,field_name`,[WORKSHOP])).rows,beforeVisibilityStates,
        'visibility-only writes do not change content provenance');
        await admin.updateExercise({key:WORKSHOP,challengeName:'Instructor Persona title',category:'ai',
          difficulty:'advanced',isVisible:false,showSolutions:false,
          description:'Instructor Persona description',route:'/instructor-persona'});
        await admin.updateHintContent(WORKSHOP,'ss_cross_persona_effect',{title:'Instructor Persona hint'});
        const customBeforeVisibility=(await store.migration.query(`SELECT field_name,provenance_state
          FROM workshop_platform.catalog_field_defaults WHERE workshop_key=$1
          AND ((entity_kind='exercise' AND field_name IN ('challenge_name','challenge_description','route'))
            OR (entity_kind='objective' AND objective_id='ss_cross_persona_effect'
              AND field_name='hint_content')) ORDER BY entity_kind,field_name`,[WORKSHOP])).rows;
        assert.ok(customBeforeVisibility.every(row=>row.provenance_state==='custom'));
        const beforeRejectedVisibility=await snapshot(store.migration,userId);
        await assert.rejects(admin.setExerciseVisibility(WORKSHOP,true),
          {code:'EXERCISE_NOT_READY'},
          'an instructor-custom route cannot publish the bound SecureShop application');
        assert.deepEqual(await snapshot(store.migration,userId),beforeRejectedVisibility,
          'rejected publication preserves content, progress and revisions');
        await admin.setExerciseVisibility(WORKSHOP,false);
        assert.deepEqual((await store.migration.query(`SELECT field_name,provenance_state
          FROM workshop_platform.catalog_field_defaults WHERE workshop_key=$1
          AND ((entity_kind='exercise' AND field_name IN ('challenge_name','challenge_description','route'))
            OR (entity_kind='objective' AND objective_id='ss_cross_persona_effect'
              AND field_name='hint_content')) ORDER BY entity_kind,field_name`,[WORKSHOP])).rows,
        customBeforeVisibility,'visibility-only writes preserve already-custom content provenance');
        await seedRelease116(store.migration);
        const preserved=(await store.migration.query(`SELECT challenge_name,challenge_description,route,is_visible
          FROM workshop_platform.exercises WHERE workshop_key=$1`,[WORKSHOP])).rows[0];
        assert.deepEqual(preserved,{challenge_name:'Instructor Persona title',
          challenge_description:'Instructor Persona description',route:'/instructor-persona',is_visible:false});
        assert.equal((await store.migration.query(`SELECT hint_content->>'title' AS title
          FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2`,
        [WORKSHOP,'ss_cross_persona_effect'])).rows[0].title,'Instructor Persona hint');
        assert.equal((await store.migration.query(`SELECT count(*)::integer AS count
          FROM workshop_platform.objectives WHERE catalog_active=true`)).rows[0].count,116,
        'full-catalog reseed preserves every unrelated objective');
      }
      // The historical release assertions above always run against ceiling49
      // and the recovered116 identities. Qualify the current tail separately.
      const beforeTail = await snapshot(store.migration, userId);
      const historicalLedger = ledger;
      await initializeIdentityRepository(store.runtime, store.migration);
      const currentLedger = (await store.migration.query(`SELECT name,checksum
        FROM dvaia_migrations.ledger ORDER BY name`)).rows;
      assert.deepEqual(currentLedger.slice(0, historicalLedger.length), historicalLedger,
        'current tail preserves the exact historical migration prefix');
      await seedWorkshopPlatform(store.migration);
      const currentIdentities = Object.entries(WORKSHOP_OBJECTIVES).flatMap(([workshopKey, objectives]) =>
        objectives.map(objective => `${workshopKey}\0${objective.id}`)).sort();
      assert.deepEqual((await store.migration.query(`SELECT workshop_key,objective_id
        FROM workshop_platform.objectives WHERE catalog_active=true`)).rows
        .map(row => `${row.workshop_key}\0${row.objective_id}`).sort(), currentIdentities);
      const afterTail = await snapshot(store.migration, userId);
      assert.deepEqual(afterTail.progress, beforeTail.progress);
      assert.deepEqual(afterTail.activity, beforeTail.activity);
      assert.deepEqual(afterTail.time, beforeTail.time);
      assert.equal(afterTail.exercise.is_visible, beforeTail.exercise.is_visible);
      assert.equal(afterTail.exercise.show_hints, beforeTail.exercise.show_hints);
      assert.equal(afterTail.exercise.show_solutions, beforeTail.exercise.show_solutions);
      if (store.variant === 'POPULATED') {
        assert.equal(afterTail.exercise.challenge_description, beforeTail.exercise.challenge_description);
        assert.deepEqual(afterTail.objectives.find(row => row.objective_id === 'ss_acl_advisory_effect'),
          beforeTail.objectives.find(row => row.objective_id === 'ss_acl_advisory_effect'));
      } else {
        assert.equal(afterTail.exercise.route, '/instructor-persona');
        assert.equal(afterTail.exercise.challenge_description, 'Instructor Persona description');
      }
      assert.deepEqual(await initializeIdentityRepository(store.runtime, store.migration), []);
      assert.equal((await seedWorkshopPlatform(store.migration)).changed, false);
    }
  } finally {
    await Promise.allSettled(stores.flatMap(store => [store.runtime.end(), store.migration.end()]));
  }
});
