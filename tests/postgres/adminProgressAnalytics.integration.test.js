'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { initializeIdentityRepository, createIdentityRepository } = require(
  '../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { createAdminProgressAnalyticsRepository } = require(
  '../../server/database/postgres/adminProgressAnalyticsRepository');
const { createSecureShopLaunchRepository } = require(
  '../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopProgressCleanupCheckpointRepository, WORKSHOP_KEY } = require(
  '../../server/database/postgres/secureshopProgressCleanupCheckpointRepository');

const PREFIX = 'PG_ADMIN_ANALYTICS_TEST';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env[`${PREFIX}_MIGRATION_URL`] && process.env[`${PREFIX}_RUNTIME_URL`];

function disposableUrl(name) {
  const url = new URL(process.env[`${PREFIX}_${name}_URL`]);
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
  assert.match(url.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return url;
}

test('native analytics derives active-student catalog metrics and excludes retired launch time', {
  skip: !enabled, timeout: 30000,
}, async () => {
  const migrationUrl = disposableUrl('MIGRATION');
  const runtimeUrl = disposableUrl('RUNTIME');
  assert.equal(migrationUrl.pathname, runtimeUrl.pathname);
  assert.notEqual(migrationUrl.username, runtimeUrl.username, 'runtime and migration roles must differ');
  const migration = new Pool({ connectionString:migrationUrl.href, max:1 });
  const runtime = new Pool({ connectionString:runtimeUrl.href, max:4 });
  try {
    await initializeIdentityRepository(runtime, migration);
    await seedWorkshopPlatform(migration);
    await migration.query(`UPDATE workshop_platform.exercises SET is_visible=true
      WHERE workshop_key=$1`, [WORKSHOP_KEY]);
    const analytics = createAdminProgressAnalyticsRepository(runtime);
    const empty = await analytics.getSnapshot();
    assert.equal(empty.overview.totalStudents, 0);
    assert.ok(empty.overview.totalEnabledObjectives > 0);
    assert.ok(empty.challengeStats.some(row => row.challengeKey === WORKSHOP_KEY));
    const baselineObjectives = empty.overview.totalEnabledObjectives;

    const passwordHash = await bcrypt.hash('analytics-owned-fixture', 4);
    const identities = createIdentityRepository(runtime);
    const makeUser = async label => identities.createUser({
      username:`analytics-${label}-${randomUUID().slice(0, 8)}`,
      email:`${randomUUID()}@analytics.invalid`, passwordHash,
    });
    const [alice, bob, inactive, administrator] = await Promise.all([
      makeUser('alice'), makeUser('bob'), makeUser('inactive'), makeUser('admin'),
    ]);
    const now = new Date();
    const oldCompletion = new Date(now.getTime() - 8 * 86400000);
    const bobHeartbeat = new Date(now.getTime() - 10 * 60000);
    const bobActivity = now;
    await migration.query(`UPDATE identity.users SET last_login=$2 WHERE id=$1`, [alice.id, now]);
    await migration.query(`UPDATE identity.users SET last_login=$2 WHERE id=$1`, [bob.id, now]);
    await migration.query(`UPDATE identity.users SET is_active=0,last_login=$2 WHERE id=$1`, [inactive.id, now]);
    await migration.query(`UPDATE identity.users SET role='admin',admin_level=1,last_login=$2 WHERE id=$1`,
      [administrator.id, now]);

    const exercises = [
      ['analytics_visible','analytics-visible','Analytics visible','Easy',true],
      ['analytics_time_only','analytics-time-only','Analytics time only','Medium',true],
      ['analytics_activity_only','analytics-activity-only','Analytics activity only','Medium',true],
      ['analytics_zero_activity','analytics-zero-activity','Analytics zero activity','Hard',true],
      ['analytics_zero_objective','analytics-zero-objective','Analytics zero objective','Hard',true],
      ['analytics_hidden','analytics-hidden','Analytics hidden','Easy',false],
    ];
    for (const [workshopKey, challengeKey, name, difficulty, visible] of exercises) {
      await migration.query(`INSERT INTO workshop_platform.exercises
        (workshop_key,challenge_key,challenge_name,difficulty,is_visible,catalog_active,ordinal)
        VALUES($1,$2,$3,$4,$5,true,9000+(SELECT count(*) FROM workshop_platform.exercises))`,
      [workshopKey, challengeKey, name, difficulty, visible]);
    }
    const objectives = [
      ['analytics_visible','one',true], ['analytics_visible','two',true],
      ['analytics_visible','disabled',false], ['analytics_time_only','one',true],
      ['analytics_activity_only','one',true], ['analytics_zero_activity','one',true],
      ['analytics_hidden','one',true],
    ];
    for (const [workshopKey, objectiveId, objectiveEnabled] of objectives) {
      await migration.query(`INSERT INTO workshop_platform.objectives
        (workshop_key,objective_id,label,ordinal,is_enabled,catalog_active)
        VALUES($1,$2,$2,1,$3,true)`, [workshopKey, objectiveId, objectiveEnabled]);
    }

    const completion = async (user, workshopKey, objectiveId, completedAt) => migration.query(
      `INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id,completed_at)
       VALUES($1,$2,$3,$4)`, [user.id, workshopKey, objectiveId, completedAt]);
    await completion(alice, 'analytics_visible', 'one', now);
    await completion(alice, 'analytics_visible', 'two', now);
    await completion(bob, 'analytics_visible', 'one', oldCompletion);
    await completion(alice, 'analytics_visible', 'disabled', now);
    await completion(alice, 'analytics_hidden', 'one', now);
    await completion(inactive, 'analytics_visible', 'one', now);
    await completion(administrator, 'analytics_visible', 'one', now);

    for (const user of [alice, bob, inactive, administrator]) {
      for (const workshopKey of ['analytics_visible','analytics_time_only','analytics_activity_only','analytics_zero_activity']) {
        await migration.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key)
          VALUES($1,$2) ON CONFLICT DO NOTHING`, [user.id, workshopKey]);
      }
    }
    const time = async (user, workshopKey, seconds, heartbeat) => migration.query(
      `INSERT INTO workshop_platform.time_tracking
       (user_id,workshop_key,session_start,last_heartbeat,duration_seconds)
       VALUES($1,$2,$3,$3,$4)`, [user.id, workshopKey, heartbeat, seconds]);
    await time(alice, 'analytics_visible', 600, new Date(now.getTime() - 3600000));
    await time(bob, 'analytics_visible', 120, new Date(now.getTime() - 1800000));
    await time(bob, 'analytics_time_only', 0, bobHeartbeat);
    await time(inactive, 'analytics_visible', 9000, now);
    await time(administrator, 'analytics_visible', 9000, now);
    await migration.query(`INSERT INTO workshop_platform.activity_counters
      (user_id,workshop_key,activity_key,activity_count,updated_at)
      VALUES($1,'analytics_activity_only','turn',1,$2),
            ($1,'analytics_zero_activity','turn',0,$2)`, [bob.id, bobActivity]);

    await migration.query(`INSERT INTO identity.activity_logs(user_id,action_type,action_details,timestamp)
      VALUES($1,'challenge_complete','{"action_description":"Alice completed analytics"}', $4),
            ($2,'challenge_complete','{}',$4),($3,'challenge_complete','{}',$4),
            ($1,'unrelated_action','{}',$4)`, [alice.id, inactive.id, administrator.id, now]);

    const launches = createSecureShopLaunchRepository(runtime);
    const session = await identities.createSession({ userId:alice.id, token:randomUUID(),
      expiresAt:new Date(now.getTime() + 3600000).toISOString(), expectedPasswordHash:passwordHash });
    const launch = await launches.issueOrRenew({ platformOwnerId:alice.id, platformSessionId:session.id,
      expiresAt:new Date(now.getTime() + 3600000).toISOString() });
    await migration.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key)
      VALUES($1,$2) ON CONFLICT DO NOTHING`, [alice.id, WORKSHOP_KEY]);
    await migration.query(`INSERT INTO workshop_platform.time_tracking
      (user_id,workshop_key,session_start,last_heartbeat,duration_seconds,platform_launch_id,
       platform_scenario_id,platform_launch_generation,workshop_generation)
      VALUES($1,$2,$3,$3,100,$4,$5,$6,0)`, [alice.id, WORKSHOP_KEY, now,
      launch.binding.launchId, launch.binding.scenarioId, launch.binding.generation]);

    const beforeRetirement = await analytics.getSnapshot();
    assert.equal(beforeRetirement.overview.avgSessionMinutes, 6.8);
    assert.equal(beforeRetirement.challengeStats.find(row => row.challengeKey === WORKSHOP_KEY).studentsStarted, 1);
    const reset = await launches.beginReset({ launchId:launch.binding.launchId,
      platformSessionId:session.id, platformOwnerId:alice.id, expectedGeneration:1,
      idempotencyKey:'analytics-retired-time' });
    await createSecureShopProgressCleanupCheckpointRepository(runtime).finalize(reset.resetId);

    const result = await analytics.getSnapshot();
    assert.deepEqual(result.overview, {
      totalStudents:2, activeStudents:2, totalEnabledObjectives:baselineObjectives + 5,
      totalObjectiveCompletions:3, completionsThisWeek:2, avgSessionMinutes:6,
      platformCompletionRate:Math.round(300 / (2 * (baselineObjectives + 5))),
    });
    const byKey = Object.fromEntries(result.challengeStats.map(row => [row.challengeKey, row]));
    assert.equal(byKey['analytics-visible'].enabledObjectives, 2);
    assert.deepEqual({ started:byKey['analytics-visible'].studentsStarted,
      completed:byKey['analytics-visible'].studentsCompleted,
      rate:byKey['analytics-visible'].completionRate,
      average:byKey['analytics-visible'].avgTimeMinutes },
    { started:2, completed:1, rate:50, average:6 });
    assert.equal(byKey['analytics-time-only'].studentsStarted, 1);
    assert.equal(byKey['analytics-time-only'].avgTimeMinutes, 0);
    assert.equal(byKey['analytics-activity-only'].studentsStarted, 1);
    assert.equal(byKey['analytics-zero-activity'].studentsStarted, 0);
    assert.equal(byKey['analytics-zero-objective'].enabledObjectives, 0);
    assert.equal(byKey['analytics-hidden'], undefined);
    assert.equal(byKey[WORKSHOP_KEY].studentsStarted, 0);

    const aliceRow = result.studentProgress.find(row => row.id === alice.id);
    const bobRow = result.studentProgress.find(row => row.id === bob.id);
    assert.equal(aliceRow.workshopsInProgress, 0, 'completed workshop is not in progress');
    assert.equal(bobRow.workshopsInProgress, 3,
      'partial completion, zero-duration heartbeat, and positive activity each start an incomplete workshop');
    assert.equal(bobRow.totalTimeMinutes, 2);
    assert.equal(new Date(bobRow.lastActivity).toISOString(), bobActivity.toISOString());
    assert.deepEqual(result.topStudents.map(row => row.id), [alice.id, bob.id]);
    assert.equal(result.progressOverTime.reduce((sum, row) => sum + row.completions, 0), 3);
    assert.deepEqual(result.recentActivity.map(row => row.username), [alice.username]);
    assert.equal(result.difficultyBreakdown.Easy.completed, 3);

    // Synthetic SQL analytics fixtures, not objective credit qualification.
    const edges=(await migration.query("SELECT date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS day, date_trunc('week',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS week")).rows[0];
    await migration.query('UPDATE identity.users SET created_at=$2 WHERE id=$1',[alice.id,edges.day]);
    await migration.query("UPDATE identity.users SET created_at=$2::timestamptz-interval '1 millisecond' WHERE id=$1",[bob.id,edges.week]);
    let stats=(await analytics.getSnapshot()).platformStatistics;
    assert.equal(stats.registeredToday,1);assert.equal(stats.registeredThisWeek,1);
    await migration.query('UPDATE identity.users SET created_at=$2 WHERE id=$1',[bob.id,edges.week]);
    stats=(await analytics.getSnapshot()).platformStatistics;assert.equal(stats.registeredThisWeek,2);
    await migration.query("UPDATE workshop_platform.completions SET completed_at=$1::timestamptz-interval '1 millisecond' WHERE user_id=ANY($2::integer[]) AND workshop_key='analytics_visible'",[edges.week,[alice.id,bob.id]]);
    await migration.query("UPDATE workshop_platform.completions SET completed_at=$1 WHERE user_id=$2 AND workshop_key='analytics_visible' AND objective_id='one'",[edges.day,alice.id]);
    stats=(await analytics.getSnapshot()).platformStatistics;assert.equal(stats.completionsToday,1);assert.equal(stats.completionsThisWeek,1);
    await migration.query("UPDATE workshop_platform.completions SET completed_at=$1 WHERE user_id=$2 AND workshop_key='analytics_visible' AND objective_id='one'",[edges.week,bob.id]);
    stats=(await analytics.getSnapshot()).platformStatistics;assert.equal(stats.completionsThisWeek,2);
    const evaluation=async(user,workshop,objective)=>{const id=randomUUID();await migration.query(`INSERT INTO workshop_platform.objective_judgments(user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,generation)
      VALUES($1,$2,$3,$4,'ControlledAnalytics','analytics','controlled-v1',$5,0)`,[user.id,id,workshop,objective,'a'.repeat(64)]);return id;};
    const pending=await evaluation(alice,'analytics_visible','one');
    await evaluation(bob,'analytics_visible','one');await evaluation(inactive,'analytics_visible','one');await evaluation(administrator,'analytics_visible','one');await evaluation(alice,'analytics_visible','disabled');await evaluation(alice,'analytics_hidden','one');
    stats=(await analytics.getSnapshot()).platformStatistics;assert.equal(stats.totalAttempts,2);
    await migration.query("UPDATE workshop_platform.objective_judgments SET verdict='unavailable',evaluated_at=now(),result_json='{}',disposition='not_pass' WHERE user_id=$1 AND evaluation_id=$2",[alice.id,pending]);
    await migration.query("INSERT INTO identity.activity_logs(user_id,action_type,action_details) VALUES($1,'challenge_complete','{}'),($1,'unrelated_action','{}')",[alice.id]);
    stats=(await analytics.getSnapshot()).platformStatistics;assert.equal(stats.totalAttempts,2,'same evaluation update and audit noise cannot create attempts');assert.equal(stats.completionsThisWeek,2);assert.equal(stats.averageCompletionTime,null);assert.equal(stats.averageCompletionTimeStatus,'unavailable_no_objective_duration_measurement');
    const nonUtc=new Pool({connectionString:runtimeUrl.href,max:1,options:'-c timezone=Pacific/Honolulu'});try{assert.deepEqual((await createAdminProgressAnalyticsRepository(nonUtc).getSnapshot()).platformStatistics,stats,'UTC calendar metrics ignore database session timezone');}finally{await nonUtc.end();}

  } finally {
    await Promise.allSettled([runtime.end(), migration.end()]);
  }
});
