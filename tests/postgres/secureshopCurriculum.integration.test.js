'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Pool } = require('pg');
const { initializeIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { createWorkshopConfigRepository } = require('../../server/database/postgres/workshopConfigRepository');
const { createWorkshopProgressRepository } = require('../../server/database/postgres/workshopProgressRepository');
const curriculum = require('../../server/config/secureshopCurriculum');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_SECURESHOP_CURRICULUM_RUNTIME_URL
  && process.env.PG_SECURESHOP_CURRICULUM_MIGRATION_URL;

test('native catalog remains hidden, preserves choices and blocks pending enablement',
  { skip: !enabled, timeout: 60000 }, async () => {
    const runtime = new Pool({ connectionString: process.env.PG_SECURESHOP_CURRICULUM_RUNTIME_URL, max: 4 });
    const migration = new Pool({ connectionString: process.env.PG_SECURESHOP_CURRICULUM_MIGRATION_URL, max: 2 });
    try {
      await initializeIdentityRepository(runtime, migration);
      await seedWorkshopPlatform(migration);
      const config = createWorkshopConfigRepository(runtime);
      const exercise = (await migration.query(`SELECT is_visible,show_hints,show_solutions,route
        FROM workshop_platform.exercises WHERE workshop_key=$1`, [curriculum.WORKSHOP_KEY])).rows[0];
      assert.deepEqual(exercise, { is_visible: false, show_hints: false, show_solutions: false, route: curriculum.CHALLENGE.route });
      const objectives = (await migration.query(`SELECT objective_id,is_enabled,hint_enabled,solution_enabled,
        hint_content IS NOT NULL AS has_hint,solution_content IS NOT NULL AS has_solution
        FROM workshop_platform.objectives WHERE workshop_key=$1 ORDER BY ordinal`, [curriculum.WORKSHOP_KEY])).rows;
      assert.deepEqual(objectives.map(row => row.objective_id), curriculum.OBJECTIVES.map(row => row.id));
      assert.ok(objectives.every(row => !row.is_enabled && !row.hint_enabled && !row.solution_enabled
        && row.has_hint && row.has_solution));

      const revision = await config.getRevision();
      for (const mutate of [
        () => config.setExerciseVisibility(curriculum.WORKSHOP_KEY, true),
        () => config.toggleExerciseVisibility(curriculum.WORKSHOP_KEY),
        () => config.setAllExerciseVisibility(true),
        () => config.updateExercise({ key: curriculum.WORKSHOP_KEY,
          challengeName: 'SecureShop', category: 'ai', difficulty: 'advanced',
          isVisible: true, showSolutions: false, description: 'fixture', route: '/secureshop' }),
      ]) await assert.rejects(mutate(), { code: 'EXERCISE_NOT_READY', statusCode: 409 });
      for (const id of curriculum.PENDING_OBJECTIVE_IDS) {
        await assert.rejects(config.setObjectiveVisibility(curriculum.WORKSHOP_KEY, id, true),
          { code: 'OBJECTIVE_UNQUALIFIED', statusCode: 409 });
        await assert.rejects(config.setObjectiveHintVisibility(curriculum.WORKSHOP_KEY, id, true),
          { code: 'OBJECTIVE_UNQUALIFIED', statusCode: 409 });
        await assert.rejects(config.setObjectiveSolutionVisibility(curriculum.WORKSHOP_KEY, id, true),
          { code: 'OBJECTIVE_UNQUALIFIED', statusCode: 409 });
      }
      assert.equal(await config.getRevision(), revision, 'rejected mutations do not bump configuration');
      assert.equal((await config.setAllObjectiveVisibility(curriculum.WORKSHOP_KEY,true)).affectedCount,curriculum.QUALIFIED_OBJECTIVE_IDS.length);
      const enabledIds = (await migration.query(`SELECT objective_id FROM workshop_platform.objectives
        WHERE workshop_key=$1 AND catalog_active AND is_enabled ORDER BY objective_id`, [curriculum.WORKSHOP_KEY])).rows.map(row => row.objective_id);
      assert.deepEqual(enabledIds, [...curriculum.QUALIFIED_OBJECTIVE_IDS].sort(), 'Bulk enablement selects the exact canonical qualified set');
      await config.setMasterHintVisibility(curriculum.WORKSHOP_KEY,true);
      await config.setMasterSolutionVisibility(curriculum.WORKSHOP_KEY,true);
      await config.setAllObjectiveVisibility(curriculum.WORKSHOP_KEY,false);
      await config.setMasterHintVisibility(curriculum.WORKSHOP_KEY,false);
      await config.setMasterSolutionVisibility(curriculum.WORKSHOP_KEY,false);

      const qualified = curriculum.QUALIFIED_OBJECTIVE_IDS[0];
      await config.setObjectiveVisibility(curriculum.WORKSHOP_KEY, qualified, true);
      await config.setObjectiveHintVisibility(curriculum.WORKSHOP_KEY, qualified, true);
      await config.setObjectiveSolutionVisibility(curriculum.WORKSHOP_KEY, qualified, true);
      await seedWorkshopPlatform(migration);
      const preserved = (await migration.query(`SELECT is_enabled,hint_enabled,solution_enabled
        FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2`,
      [curriculum.WORKSHOP_KEY, qualified])).rows[0];
      assert.deepEqual(preserved, { is_enabled: true, hint_enabled: true, solution_enabled: true });
      assert.equal((await config.getSnapshot()).exercises[curriculum.WORKSHOP_KEY].isVisible, false,
        'objective choices do not expose the hidden exercise');
      const readyConfig = createWorkshopConfigRepository(runtime, { isSecureShopReady: () => true });
      // Independently exercise missing-route denial after canonical seeding.
      await migration.query('UPDATE workshop_platform.exercises SET route=$2 WHERE workshop_key=$1',
        [curriculum.WORKSHOP_KEY, '']);
      await assert.rejects(readyConfig.setExerciseVisibility(curriculum.WORKSHOP_KEY, true),
        { code: 'EXERCISE_NOT_READY' }, 'runtime readiness cannot bypass the missing bound route');
      await migration.query('UPDATE workshop_platform.exercises SET route=$2 WHERE workshop_key=$1',
        [curriculum.WORKSHOP_KEY, curriculum.CHALLENGE.route]);
      await assert.rejects(config.setExerciseVisibility(curriculum.WORKSHOP_KEY, true),
        { code: 'EXERCISE_NOT_READY' }, 'a route alone is not runtime readiness');
      await readyConfig.setExerciseVisibility(curriculum.WORKSHOP_KEY, true);
      assert.equal((await readyConfig.getSnapshot()).exercises[curriculum.WORKSHOP_KEY].isVisible, true);
      await migration.query(`UPDATE workshop_platform.objectives SET label='Instructor loop label'
        WHERE workshop_key=$1 AND objective_id=$2`, [curriculum.WORKSHOP_KEY, qualified]);
      const progress = createWorkshopProgressRepository(runtime);
      const learner = (await progress.getVisibleUserProgress(17)).find(row => row.workshopKey === curriculum.WORKSHOP_KEY);
      const instructor = (await progress.getUserProgress(17)).find(row => row.workshopKey === curriculum.WORKSHOP_KEY);
      assert.equal(learner.exerciseGroups.length, 1);
      assert.equal(learner.exerciseGroups[0].objectiveCount, learner.objectiveCount);
      assert.equal(learner.exerciseGroups[0].objectives[0].text, 'Instructor loop label');
      assert.equal(learner.exerciseGroups[0].objectives[0].hintVisible, true);
      assert.equal(instructor.exerciseGroups[0].objectives[0].label, 'Instructor loop label');
      await config.setObjectiveVisibility(curriculum.WORKSHOP_KEY, qualified, false);
      const disabled = (await progress.getVisibleUserProgress(17)).find(row => row.workshopKey === curriculum.WORKSHOP_KEY);
      assert.deepEqual(disabled.exerciseGroups, []);
      assert.equal(disabled.objectiveCount, 0);
      await readyConfig.resetAllChallengeVisibility();
      assert.equal((await readyConfig.getSnapshot()).exercises[curriculum.WORKSHOP_KEY].isVisible, false,
        'reset defaults retains the staged curriculum default instead of enabling every exercise');

      await migration.query(`INSERT INTO workshop_platform.objectives
        (workshop_key,objective_id,label,ordinal,is_enabled) VALUES($1,'retired_fixture','Retired',999,true)`,
      [curriculum.WORKSHOP_KEY]);
      await seedWorkshopPlatform(migration);
      assert.deepEqual((await migration.query(`SELECT catalog_active,is_enabled FROM workshop_platform.objectives
        WHERE workshop_key=$1 AND objective_id='retired_fixture'`, [curriculum.WORKSHOP_KEY])).rows[0],
      { catalog_active: false, is_enabled: false });

      const draft = await fs.readFile(path.join(__dirname, '../../docs/modernization/drafts/dpi-teaching-scope.sql'), 'utf8');
      const replacements = [...draft.matchAll(/SET solution_content=\$json\$([\s\S]*?)\$json\$::jsonb[\s\S]*?objective_id='([^']+)'[\s\S]*?AND solution_content=\$json\$([\s\S]*?)\$json\$::jsonb/g)];
      assert.equal(replacements.length, 7);
      for (const [, , id, oldValue] of replacements) await migration.query(`UPDATE workshop_platform.objectives
        SET solution_content=$1::jsonb WHERE workshop_key='direct_prompt_injection' AND objective_id=$2`, [oldValue, id]);
      const customizedId = replacements[0][2];
      const custom = { title: 'Instructor content', difficulty: 'Custom', hints: ['retain'], examples: [{ action: 'retain', explanation: 'retain' }], approach: 'retain', tips: ['retain'] };
      await migration.query(`UPDATE workshop_platform.objectives SET solution_content=$1::jsonb,
        solution_enabled=true WHERE workshop_key='direct_prompt_injection' AND objective_id=$2`, [JSON.stringify(custom), customizedId]);
      const beforeDraftRevision = Number((await migration.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
      await migration.query(draft);
      assert.deepEqual((await migration.query(`SELECT solution_content,solution_enabled FROM workshop_platform.objectives
        WHERE workshop_key='direct_prompt_injection' AND objective_id=$1`, [customizedId])).rows[0],
      { solution_content: custom, solution_enabled: true });
      assert.equal(Number((await migration.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision), beforeDraftRevision + 1);
      await migration.query(draft);
      assert.equal(Number((await migration.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision), beforeDraftRevision + 1,
        'draft replay does not bump configuration revision');
    } finally {
      await Promise.allSettled([runtime.end(), migration.end()]);
    }
  });
