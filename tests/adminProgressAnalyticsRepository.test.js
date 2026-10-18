'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createAdminProgressAnalyticsRepository, projectSnapshot, _internals } = require(
  '../server/database/postgres/adminProgressAnalyticsRepository');
const { liveWorkshopTimeCondition } = require('../server/database/postgres/workshopProgressTimePredicate');

function fixturePool(rowsByMarker, failAt) {
  const calls = [];
  const client = {
    async query(sql) {
      const text = String(sql);
      calls.push(text);
      if (failAt && text.includes(failAt)) throw new Error('controlled query failure');
      const marker = Object.keys(rowsByMarker).find(key => text.includes(key));
      return { rows: marker ? rowsByMarker[marker] : [] };
    },
    release(error) { calls.push(error ? 'RELEASE:discard' : 'RELEASE'); },
  };
  return { calls, connect: async () => client, query: async () => ({ rows: [] }) };
}

test('repository reads one repeatable snapshot and projects every rendered analytics collection', async () => {
  const pool = fixturePool({
    'admin-progress-analytics:instance-readiness': [{ history:true, launch_scope:true, generation_scope:true }],
    'admin-progress-analytics:overview': [{ total_students:'6', active_students:'4',
      total_enabled_objectives:'5', total_objective_completions:'8', completions_this_week:'3',
      // Six active students share the denominator; two have zero tracked time.
      avg_session_minutes:'3.25' }],
    'admin-progress-analytics:challenges': [
      { challenge_key:'alpha', challenge_name:'Alpha', difficulty:'Easy', enabled_objectives:'2',
        students_started:'3', students_completed:'1', total_completions:'4', avg_time_minutes:'7.25' },
      { challenge_key:'empty', challenge_name:'Empty', difficulty:'Easy', enabled_objectives:'0',
        students_started:'0', students_completed:'0', total_completions:'0', avg_time_minutes:null },
      { challenge_key:'hard', challenge_name:'Hard', difficulty:'Hard', enabled_objectives:'2',
        students_started:'2', students_completed:'2', total_completions:'4', avg_time_minutes:'9' },
      { challenge_key:'time-only', challenge_name:'Time only', difficulty:'Medium', enabled_objectives:'1',
        students_started:'1', students_completed:'0', total_completions:'0', avg_time_minutes:'0' },
    ],
    'admin-progress-analytics:students': [
      { id:'2', username:'bravo', last_login:null, objectives_completed:'3', workshops_in_progress:'1',
        last_activity:'2026-09-14T12:00:00Z', total_time_seconds:'510' },
      { id:'1', username:'alpha', last_login:'2026-09-15T00:00:00Z', objectives_completed:'3',
        workshops_in_progress:'0', last_activity:'2026-09-14T12:00:00Z', total_time_seconds:'600' },
      { id:'3', username:'charlie', objectives_completed:'2', workshops_in_progress:'2',
        last_activity:'2026-09-15T12:00:00Z', total_time_seconds:'60' },
      { id:'4', username:'delta', objectives_completed:'1', workshops_in_progress:'1',
        last_activity:null, total_time_seconds:'0' },
      { id:'5', username:'echo', objectives_completed:'1', workshops_in_progress:'1',
        last_activity:'invalid', total_time_seconds:'0' },
      // A later heartbeat, without a completion, starts one incomplete workshop
      // and supplies the rendered Last Activity timestamp.
      { id:'6', username:'time-only', objectives_completed:'0', workshops_in_progress:'1',
        last_activity:'2026-09-15T13:00:00Z', total_time_seconds:'0' },
    ],
    'admin-progress-analytics:timeline': [
      { date:'2026-09-15', completions:'2', active_students:'2' },
      { date:'2026-09-14', completions:'1', active_students:'1' },
    ],
    'admin-progress-analytics:recent-activity': [
      { username:'alpha', action_type:'challenge_complete',
        action_details:{ action_description:'Completed Alpha' }, timestamp:'2026-09-15T12:00:00Z', success:true },
    ],
  });

  const result = await createAdminProgressAnalyticsRepository(pool).getSnapshot();
  assert.deepEqual(pool.calls.slice(0, 4), ['BEGIN', 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY',
    _internals.INSTANCE_READINESS_SQL, _internals.SQL.overview]);
  assert.deepEqual(pool.calls.slice(-2), ['COMMIT', 'RELEASE']);
  assert.deepEqual(result.overview, { totalStudents:6, activeStudents:4, totalEnabledObjectives:5,
    totalObjectiveCompletions:8, completionsThisWeek:3, avgSessionMinutes:3.3,
    platformCompletionRate:27 });
  assert.deepEqual(result.challengeStats[1], { challengeKey:'empty', challengeName:'Empty',
    difficulty:'Easy', enabledObjectives:0, studentsStarted:0, studentsCompleted:0,
    completionRate:0, avgTimeMinutes:0 });
  assert.equal(result.challengeStats[0].completionRate, 33);
  assert.deepEqual(result.topStudents.map(row => row.id), [1, 2, 3, 4, 5]);
  assert.equal(result.studentProgress[0].totalTimeMinutes, 8.5);
  assert.equal(result.studentProgress[1].lastLogin, '2026-09-15T00:00:00Z');
  assert.deepEqual(result.studentProgress[5], { id:6, username:'time-only', lastLogin:null,
    objectivesCompleted:0, totalEnabledObjectives:5, completionPercentage:0,
    workshopsInProgress:1, lastActivity:'2026-09-15T13:00:00Z', totalTimeMinutes:0 });
  assert.deepEqual(result.challengeStats[3], { challengeKey:'time-only', challengeName:'Time only',
    difficulty:'Medium', enabledObjectives:1, studentsStarted:1, studentsCompleted:0,
    completionRate:0, avgTimeMinutes:0 });
  assert.deepEqual(result.progressOverTime[0], { date:'2026-09-15', completions:2, activeStudents:2 });
  assert.deepEqual(result.difficultyBreakdown, {
    Easy:{ totalChallenges:2, totalObjectives:2, completed:4, completionRate:33 },
    Hard:{ totalChallenges:1, totalObjectives:2, completed:4, completionRate:33 },
    Medium:{ totalChallenges:1, totalObjectives:1, completed:0, completionRate:0 },
  });
  assert.deepEqual(result.recentActivity[0], { username:'alpha', actionType:'challenge_complete',
    description:'Completed Alpha', timestamp:'2026-09-15T12:00:00Z', success:true });
});

test('empty active-student population retains visible catalog rows and zero-safe denominators', () => {
  const result = projectSnapshot({
    overview:{ total_students:0, active_students:0, total_enabled_objectives:3 },
    challenges:[{ challenge_key:'catalog-only', challenge_name:'Catalog only', difficulty:'__proto__',
      enabled_objectives:3, students_started:0, students_completed:0, total_completions:0 }],
  });
  assert.deepEqual(result.overview, { totalStudents:0, activeStudents:0, totalEnabledObjectives:3,
    totalObjectiveCompletions:0, completionsThisWeek:0, avgSessionMinutes:0, platformCompletionRate:0 });
  assert.equal(result.challengeStats.length, 1);
  assert.deepEqual(result.difficultyBreakdown.__proto__, {
    totalChallenges:1, totalObjectives:3, completed:0, completionRate:0 });
  assert.deepEqual(result.studentProgress, []);
  assert.deepEqual(result.topStudents, []);
  assert.deepEqual(result.progressOverTime, []);
  assert.deepEqual(result.recentActivity, []);
});

test('SQL applies one student population, visible catalog, calendar boundaries and exact live-time rule', () => {
  const combined = Object.values(_internals.SQL).join('\n');
  assert.equal(_internals.LIVE_TIME, liveWorkshopTimeCondition('t'));
  assert.equal((combined.match(/u\.role='student' AND u\.is_active=1/g) || []).length, 5);
  assert.match(_internals.SQL.overview, /date_trunc\('week',transaction_timestamp\(\) AT TIME ZONE 'UTC'\)/);
  assert.doesNotMatch(_internals.SQL.overview, /interval '7 days'/);
  assert.match(_internals.SQL.timeline, /::date-29/);
  assert.doesNotMatch(combined, /clock_timestamp\(\)/);
  assert.match(_internals.SQL.overview, /avg\(COALESCE\(t\.seconds,0\)\).*FROM population p LEFT JOIN time_by_student/s);
  assert.match(_internals.SQL.challenges, /COALESCE\(spent\.time_count,0\)>0/);
  assert.match(_internals.SQL.challenges, /COALESCE\(activity\.activity_count,0\)>0/);
  assert.match(_internals.SQL.challenges, /a\.activity_count>0/);
  assert.match(_internals.SQL.students, /COALESCE\(done\.completed,0\)<c\.enabled_objectives/);
  assert.match(_internals.SQL.students, /COALESCE\(spent\.time_count,0\)>0/);
  assert.match(_internals.SQL.students, /GREATEST\([\s\S]*max\(done\.completed_at\)[\s\S]*max\(spent\.last_activity\)[\s\S]*max\(activity\.last_activity\)/);
  assert.match(combined, /e\.catalog_active=true AND e\.is_visible=true/);
  assert.match(combined, /o\.catalog_active=true AND o\.is_enabled=true/);
  assert.match(_internals.LIVE_TIME, /platform_launch_id IS NOT NULL/);
  assert.match(_internals.LIVE_TIME, /secureshop_progress_cleanup_history/);
  assert.match(_internals.LIVE_TIME, /from_launch_generation=t\.platform_launch_generation/);
  const progressSource = fs.readFileSync(path.resolve(__dirname,
    '../server/database/postgres/workshopProgressRepository.js'), 'utf8');
  assert.match(progressSource, /liveWorkshopTimeCondition\('t'\)/);
});

test('base schema without launch-scope readiness keeps legacy time readable without naming absent relations', async () => {
  const pool = fixturePool({
    'admin-progress-analytics:instance-readiness': [{ history:false, launch_scope:false, generation_scope:false }],
    'admin-progress-analytics:overview': [{ total_students:0, total_enabled_objectives:0 }],
    'admin-progress-analytics:challenges': [],
    'admin-progress-analytics:students': [],
    'admin-progress-analytics:timeline': [],
    'admin-progress-analytics:recent-activity': [],
  });
  await createAdminProgressAnalyticsRepository(pool).getSnapshot();
  const selected = pool.calls.filter(sql => sql.includes('admin-progress-analytics:overview'))[0];
  assert.match(selected, /e\.catalog_active=true AND e\.is_visible=true AND e\.workshop_key<>'secureshop_agent_security' AND true/);
  assert.doesNotMatch(selected, /secureshop_progress_cleanup_history/);
});

test('query failure rolls back and discards no healthy client', async () => {
  const pool = fixturePool({ 'admin-progress-analytics:overview':[{}] },
    'admin-progress-analytics:challenges');
  await assert.rejects(createAdminProgressAnalyticsRepository(pool).getSnapshot(), /controlled query failure/);
  assert.deepEqual(pool.calls.slice(-2), ['ROLLBACK', 'RELEASE']);
});

test('repository requires a PostgreSQL pool', () => {
  assert.throws(() => createAdminProgressAnalyticsRepository({}), /PostgreSQL pool is required/);
});


test('platform statistics projects canonical measurements without inventing objective duration',()=>{
 const value=projectSnapshot({overview:{registered_today:'2',registered_this_week:'5',completions_today:'3',completions_this_week:'7',total_evaluation_attempts:'11'}}).platformStatistics;
 assert.equal(value.registeredToday,2);assert.equal(value.registeredThisWeek,5);assert.equal(value.completionsToday,3);assert.equal(value.completionsThisWeek,7);assert.equal(value.totalAttempts,11);assert.equal(value.calendarTimeZone,'UTC');assert.equal(value.averageCompletionTime,null);assert.match(value.attemptDefinition,/one per evaluation ID/);
 const sql=_internals.SQL.overview;assert.match(sql,/date_trunc\('day',transaction_timestamp\(\) AT TIME ZONE 'UTC'\)/);assert.match(sql,/date_trunc\('week',transaction_timestamp\(\) AT TIME ZONE 'UTC'\)/);
 assert.match(sql,/objective_judgments j\s+JOIN population p ON p.id=j.user_id\s+JOIN visible_objectives o USING\(workshop_key,objective_id\)/);assert.doesNotMatch(sql,/activity_logs/);
 assert.equal(projectSnapshot().platformStatistics.totalAttempts,0);assert.equal(projectSnapshot().platformStatistics.averageCompletionTime,null);
});

test('every catalog-backed workshop analytics aggregate excludes standalone app participation',()=>{
 for(const variant of [_internals.SQL,_internals.buildSql('true')])for(const name of ['overview','challenges','students','timeline']){
  const sql=variant[name],catalogChecks=sql.match(/e\.catalog_active=true AND e\.is_visible=true/g)||[],exclusions=sql.match(/e\.workshop_key<>'secureshop_agent_security'/g)||[];
  assert(catalogChecks.length>0);assert.equal(exclusions.length,catalogChecks.length,name+' excludes app completions, time, activity and evaluations');
 }
});
