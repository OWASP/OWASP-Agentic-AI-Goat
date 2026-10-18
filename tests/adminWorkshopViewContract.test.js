'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');
const { projectAdminWorkshopView } = require('../server/services/adminWorkshopView');
const { projectWorkshopChallenges } = require('../server/services/workshopChallengeProjection');

test('admin student views preserve the rendered contract and canonical objective/time totals', async t => {
  const student = { id: 7, username: 'fixture-student', full_name: 'Fixture Student', role: 'student',
    admin_level: 0, email: 'student@example.invalid', last_login_ip: '192.0.2.7', created_at: '2026-09-01T00:00:00Z' };
  const administrator = { id: 8, username: 'fixture-admin', full_name: 'Fixture Admin', role: 'admin',
    admin_level: 2, email: 'admin@example.invalid', last_login_ip: '192.0.2.8', created_at: '2026-09-01T00:00:00Z' };
  const challenges = [
    { id: 'one', workshopKey: 'xss_workshop', name: 'XSS Workshop', category: 'Web', difficulty: 'easy', status: 'completed', objectiveCount: 2, completedObjectiveCount: 2, timeSpentSeconds: 30, objectives: [{ id: 'xss_r1', label: 'Canonical XSS label', completed: true, solutionVisible: true }] },
    { id: 'two', workshopKey: 'excessive_agency', difficulty: 'intermediate', status: 'in_progress', objectiveCount: 3, completedObjectiveCount: 1, timeSpentSeconds: 0, objectives: [] },
  ];
  const pass = (_req, _res, next) => next();
  const auth = { authenticateToken: pass, requireAdminLevel: () => pass, requirePermission: () => pass, logActivity: () => pass };
  const pool = { query: async (_sql, [ids]) => {
    assert.deepEqual(ids, [7]);
    return { rows: [{ user_id: 7, active_days: 2, last_activity: '2026-09-12T00:00:00Z' }] };
  } };
  const handler = (_req, res) => res.sendStatus(501);
  const operational = Object.fromEntries(['providerStatus', 'switchProvider', 'configureProvider', 'testProvider', 'testLlm', 'appLogs', 'llmLogs', 'logStats', 'systemMonitoring'].map(key => [key, handler]));
  const app = express();
  app.use('/api/admin', createPostgresAdminRouter({ adapter: {}, auth, stores: { pool, config: {}, progress: {
    getVisibleUserProgress: async id => { assert.equal(id, '7'); return challenges; },
    getVisibleUsersProgress: async ids => { assert.deepEqual(ids, [7]); return new Map([[7, challenges]]); },
  } }, repository: {
    getUser: async id => id === '7' ? { user: student } : id === '8' ? { user: administrator } : null,
    getStudent: async id => id === '7' ? student : null,
    listStudents: async () => [student],
  },
  resetService: {}, xssLegacyRepository: {}, operational }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api/admin`;
  const singleResponse = await fetch(`${base}/student-workshop-view/7`);
  assert.equal(singleResponse.status, 200);
  const single = await singleResponse.json();
  assert.deepEqual(single.challenges, projectWorkshopChallenges(challenges));
  assert.equal(single.overview.totalObjectives, 5);
  assert.equal(single.overview.completedObjectives, 3);
  assert.equal(single.overview.totalTimeSeconds, 30);
  assert.equal(single.overview.completedChallenges, 1);
  assert.equal(single.overview.completionPercentage, 50);
  assert.equal(single.overview.streak, 2);
  assert.equal(single.overview.totalPoints, null, 'absence of a points ledger must not fabricate a score');
  assert.deepEqual(single.student, { id: 7, username: 'fixture-student', fullName: 'Fixture Student',
    joined: '2026-09-01T00:00:00Z' });
  assert.equal(single.student.email, undefined);
  assert.equal(single.student.last_login_ip, undefined);
  const all = await (await fetch(`${base}/all-students-workshop-view`)).json();
  assert.equal(all.totalStudents, 1);
  assert.equal(all.totalChallenges, 2);
  for (const [key, value] of Object.entries(single.overview)) assert.deepEqual(all.students[0][key], value);
  assert.deepEqual(all.students[0].challenges, single.challenges);
  assert.equal((await fetch(`${base}/student-workshop-view/99`)).status, 404);
  assert.equal((await fetch(`${base}/student-workshop-view/8`)).status, 404,
    'progress permission must not expose a non-student identity through the student view');
  const detailResponse = await fetch(`${base}/students/7/progress`);
  assert.equal(detailResponse.status, 200);
  const detail = await detailResponse.json();
  assert.equal(detail.student.id, 7);
  assert.equal(detail.student.username, 'fixture-student');
  assert.equal(detail.student.password, undefined);
  assert.equal(detail.pointsAvailable, false);
  assert.deepEqual(detail.stats, {
    totalChallenges: 2, completedChallenges: 1, inProgressChallenges: 1,
    totalTimeSpent: 30, totalObjectivesCompleted: 3,
    totalScore: null, averageScore: null, pointsAvailable: false,
  });
  assert.deepEqual(detail.progress.map(row => [row.id, row.challenge_name, row.score, row.challenge_max_score]), [
    ['one', 'XSS Workshop', null, null], ['two', 'two', null, null],
  ]);
  assert.deepEqual(detail.workshopObjectives.xss_workshop[0], {
    workshop_key: 'xss_workshop', objective_id: 'xss_r1', objective_label: 'Canonical XSS label',
    objective_category: null, completed: true, completed_at: null,
  });
  assert.equal((await fetch(`${base}/students/8/progress`)).status, 404,
    'student details must not project an administrator account');
});

test('empty/disabled canonical projection does not invent exercises or divide by zero', () => {
  const result = projectAdminWorkshopView({ id: 7 }, []);
  assert.equal(result.overview.completionPercentage, 0);
  assert.equal(result.overview.totalObjectives, 0);
  assert.equal(result.overview.totalTimeSeconds, 0);
  assert.deepEqual(result.challenges, []);
});
