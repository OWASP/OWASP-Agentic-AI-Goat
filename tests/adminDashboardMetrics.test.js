'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresAdminRepository } = require('../server/database/postgres/adminRepository');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');
const { createAdminOperationalHandlers } = require('../server/routes/adminOperationalHandlers');

function compact(sql) {
  return String(sql).replace(/\s+/g, ' ').trim();
}

test('dashboard repository metrics use active students, a fixed 24-hour window, and canonical visible objectives', async () => {
  const expected = {
    total_users: 8,
    total_students: 6,
    total_admins: 2,
    active_students_24h: 3,
    new_students_24h: 1,
    students_with_completions: 2,
    activity_window_hours: 24,
  };
  let sql;
  const repository = createPostgresAdminRepository({
    query: async statement => {
      sql = compact(statement);
      return { rows: [expected] };
    },
  });

  assert.deepEqual(await repository.dashboardStats(), expected);
  assert.match(sql, /u\.role='student' AND u\.is_active=1/);
  assert.match(sql, /u\.last_login>CURRENT_TIMESTAMP-interval '24 hours'/);
  assert.match(sql, /u\.created_at>CURRENT_TIMESTAMP-interval '24 hours'/);
  assert.match(sql, /count\(\*\) FILTER\(WHERE u\.role='student' AND u\.is_active=1 AND EXISTS\(/);
  assert.match(sql, /JOIN workshop_platform\.objectives o ON o\.workshop_key=c\.workshop_key AND o\.objective_id=c\.objective_id/);
  assert.match(sql, /JOIN workshop_platform\.exercises e ON e\.workshop_key=c\.workshop_key/);
  assert.match(sql, /e\.catalog_active=true AND e\.is_visible=true/);
  assert.match(sql, /o\.catalog_active=true AND o\.is_enabled=true/);
  assert.match(sql, /24::integer AS activity_window_hours/);
});

test('exercise statistics retain hidden catalog rows and count canonical completions without requiring user state', async () => {
  let sql;
  const expected = [
    { workshop_key: 'visible', is_visible: true, students_attempted: 2, students_completed: 1 },
    { workshop_key: 'hidden', is_visible: false, students_attempted: 1, students_completed: 1 },
    { workshop_key: 'no-enabled-objectives', is_visible: true, students_attempted: 1, students_completed: 0 },
  ];
  const repository = createPostgresAdminRepository({ query: async statement => {
    sql = compact(statement);
    return { rows: expected };
  } });

  assert.deepEqual(await repository.listExercisesWithStats(), expected);
  assert.equal((sql.match(/JOIN identity\.users u ON u\.id=s\.user_id/g) || []).length, 1);
  assert.match(sql, /SELECT count\(\*\)::integer FROM identity\.users u WHERE u\.role='student' AND u\.is_active=1/);
  assert.equal((sql.match(/u\.role='student' AND u\.is_active=1/g) || []).length, 2);
  assert.match(sql, /EXISTS\(SELECT 1 FROM workshop_platform\.objectives o WHERE o\.workshop_key=e\.workshop_key AND o\.catalog_active=true AND o\.is_enabled=true\)/);
  assert.match(sql, /NOT EXISTS\(SELECT 1 FROM workshop_platform\.objectives o WHERE o\.workshop_key=e\.workshop_key AND o\.catalog_active=true AND o\.is_enabled=true/);
  assert.match(sql, /FROM workshop_platform\.exercises e WHERE e\.catalog_active=true AND e\.workshop_key<>'secureshop_agent_security' ORDER BY e\.ordinal$/);
  assert.doesNotMatch(sql, /FROM workshop_platform\.exercises e WHERE e\.catalog_active=true AND e\.is_visible=true/);
  assert.doesNotMatch(sql, /FROM workshop_platform\.user_state s[^)]*AS students_completed/);
});

test('dashboard exercise statistics group XSS display rows while checking every visible member objective', async () => {
  let sql;
  const rows = [{ workshop_key: 'xss_workshop', is_visible: true, students_attempted: 2, students_completed: 1 }];
  const repository = createPostgresAdminRepository({ query: async statement => {
    sql = compact(statement);
    return { rows };
  } });

  assert.deepEqual(await repository.listExercisesWithStats({ groupDisplay: true }), rows);
  assert.match(sql, /PARTITION BY CASE WHEN e\.workshop_key='xss_email_builder' THEN 'xss_workshop'/);
  assert.match(sql, /ORDER BY e\.is_visible DESC,\(e\.workshop_key='xss_workshop'\) DESC/);
  assert.match(sql, /WHERE representative\.display_rank=1/);
  assert.match(sql, /member\.display_key=representative\.display_key AND member_ex\.is_visible=true/);
  assert.match(sql, /c\.user_id=u\.id AND c\.workshop_key=o\.workshop_key AND c\.objective_id=o\.objective_id/);
  assert.match(sql, /o\.catalog_active=true AND o\.is_enabled=true/);
  assert.match(sql, /AND NOT EXISTS \(SELECT 1 FROM workshop_platform\.objectives o/);
});

test('distinct completion semantics reject disabled, hidden, inactive, and nonstudent rows without double-counting', () => {
  const users = [
    { id: 1, role: 'student', is_active: 1 },
    { id: 2, role: 'student', is_active: 1 },
    { id: 3, role: 'student', is_active: 0 },
    { id: 4, role: 'admin', is_active: 1 },
    { id: 5, role: 'student', is_active: 1 },
    { id: 6, role: 'student', is_active: 1 },
  ];
  const exercises = new Map([
    ['visible', { catalog_active: true, is_visible: true }],
    ['hidden', { catalog_active: true, is_visible: false }],
  ]);
  const objectives = new Map([
    ['visible:enabled-a', { catalog_active: true, is_enabled: true }],
    ['visible:enabled-b', { catalog_active: true, is_enabled: true }],
    ['visible:disabled', { catalog_active: true, is_enabled: false }],
    ['hidden:enabled', { catalog_active: true, is_enabled: true }],
  ]);
  const completions = [
    { user_id: 1, workshop_key: 'visible', objective_id: 'enabled-a' },
    { user_id: 1, workshop_key: 'visible', objective_id: 'enabled-b' },
    { user_id: 2, workshop_key: 'visible', objective_id: 'disabled' },
    { user_id: 3, workshop_key: 'visible', objective_id: 'enabled-a' },
    { user_id: 4, workshop_key: 'visible', objective_id: 'enabled-a' },
    { user_id: 5, workshop_key: 'hidden', objective_id: 'enabled' },
  ];
  const qualifying = new Set(completions.filter(completion => {
    const user = users.find(item => item.id === completion.user_id);
    const exercise = exercises.get(completion.workshop_key);
    const objective = objectives.get(`${completion.workshop_key}:${completion.objective_id}`);
    return user?.role === 'student' && user.is_active === 1
      && exercise?.catalog_active && exercise.is_visible
      && objective?.catalog_active && objective.is_enabled;
  }).map(completion => completion.user_id));

  assert.deepEqual([...qualifying], [1], 'two enabled completions count one student; all negative rows count zero');
  assert.equal(qualifying.has(2), false, 'disabled objective does not count');
  assert.equal(qualifying.has(3), false, 'inactive student does not count');
  assert.equal(qualifying.has(4), false, 'administrator completion does not count');
  assert.equal(qualifying.has(5), false, 'hidden exercise completion does not count');
  assert.equal(qualifying.has(6), false, 'student with no completion does not count');
});

test('mounted dashboard compatibility endpoints expose repository metrics and exclude hidden exercise totals', async t => {
  const pass = (_req, _res, next) => next();
  const handler = (_req, res) => res.sendStatus(501);
  const operational = Object.fromEntries([
    'providerStatus', 'switchProvider', 'configureProvider', 'testProvider', 'testLlm',
    'appLogs', 'llmLogs', 'logStats', 'systemMonitoring',
  ].map(key => [key, handler]));
  operational.systemMonitoring = createAdminOperationalHandlers().systemMonitoring;
  let activeStudents = 4;
  const repository = {
    dashboardStats: async () => ({
      total_users: 9,
      total_students: 7,
      total_admins: 2,
      active_students_24h: activeStudents,
      new_students_24h: 2,
      students_with_completions: 3,
      activity_window_hours: 24,
    }),
    listExercisesWithStats: async () => [
      { workshop_key: 'visible-one', is_visible: true, students_completed: 2 },
      { workshop_key: 'visible-two', is_visible: true, students_completed: 1 },
      { workshop_key: 'hidden', is_visible: false, students_completed: 50 },
    ],
    listActivity: async () => ({ logs: [{ id: 1 }, { id: 2 }], pagination: {} }),
    activityStats: async () => ({ total_activity: 12, failed_logins: 2 }),
  };
  const auth = {
    authenticateToken: pass,
    requireAdminLevel: () => pass,
    requirePermission: () => pass,
    logActivity: () => pass,
  };
  const app = express();
  app.use('/api/admin', createPostgresAdminRouter({
    adapter: {},
    stores: { pool: {}, config: {}, progress: {} },
    auth,
    repository,
    analytics: { async getSnapshot(){return {platformStatistics:{registeredToday:2,registeredThisWeek:5,totalAttempts:7,completionsToday:1,completionsThisWeek:3,calendarTimeZone:'UTC',attemptDefinition:'canonical evaluations',averageCompletionTime:null,averageCompletionTimeStatus:'unavailable_no_objective_duration_measurement'}};} },
    resetService: {},
    operational,
    xssLegacyRepository: {},
    deletionService: {},
  }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api/admin`;

  const dashboardResponse = await fetch(`${base}/dashboard`);
  assert.equal(dashboardResponse.status, 200);
  const dashboard = await dashboardResponse.json();
  assert.deepEqual(dashboard.stats, {
    totalUsers: 9,
    totalStudents: 7,
    totalAdmins: 2,
    activeChallenges: 2,
    recentActivities: 2,
    challengeCompletions: 3,
    studentsWithCompletions: 3,
    activityWindowHours: 24,
  });

  const statsResponse = await fetch(`${base}/dashboard/stats`);
  assert.equal(statsResponse.status, 200);
  const stats = (await statsResponse.json()).stats;
  assert.deepEqual(stats.users, { total: 7, active: 4, new: 2, activityWindowHours: 24 });
  assert.deepEqual(stats.challenges, { total: 3, enabled: 2, completed: 3 });
  assert.deepEqual(stats.activity, { total: 12, successful: 10, failed: 2 });

  // Compatibility endpoints must agree on student activity without changing
  // monitoring's historical all-account total into a student-only total.
  for (const active of [4, 0]) {
    activeStudents = active;
    const monitoringResponse = await fetch(`${base}/system/monitoring`);
    assert.equal(monitoringResponse.status, 200);
    assert.deepEqual((await monitoringResponse.json()).metrics.users, {
      total: 9, active, activePopulation: 'students', activityWindowHours: 24,
    });
    const platformResponse = await fetch(`${base}/analytics/platform-stats`);
    assert.equal(platformResponse.status, 200);
    assert.deepEqual((await platformResponse.json()).stats.students, {
      total: 7, active, activityWindowHours: 24, registeredToday: 2, registeredThisWeek: 5, registrationCalendarTimeZone: 'UTC',
    });
  }
});

test('all workshop admin counts and lists exclude separate apps while configuration opts in',async()=>{
 const statements=[];const repository=createPostgresAdminRepository({query:async sql=>{statements.push(compact(sql));return{rows:[]};}});
 await repository.listUsers();await repository.dashboardStats();await repository.listAllSolutions();await repository.listExercisesWithStats();await repository.listExercisesWithStats({groupDisplay:true});
 for(const sql of statements)assert.match(sql,/e\.workshop_key<>'secureshop_agent_security'/);
 statements.length=0;await repository.listExercisesWithStats({includeStandaloneApps:true});await repository.listAllSolutions({includeStandaloneApps:true});
 for(const sql of statements)assert.doesNotMatch(sql,/e\.workshop_key<>'secureshop_agent_security'/);
});
