'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');

async function fixture(t, analytics, repository = {}) {
  const grants = new Set();
  const pass = (_req, _res, next) => next();
  const auth = {
    authenticateToken(req, res, next) {
      if (req.get('authorization') !== 'Bearer controlled-admin') return res.sendStatus(401);
      req.user = { id: 7, role: 'admin', admin_level: 1 };
      next();
    },
    requireAdminLevel: () => pass,
    requirePermission: permission => (_req, res, next) => grants.has(permission)
      ? next() : res.status(403).json({ error: 'Permission denied' }),
    logActivity: () => pass,
  };
  const unavailable = (_req, res) => res.sendStatus(501);
  const operational = Object.fromEntries(['providerStatus', 'switchProvider', 'configureProvider',
    'testProvider', 'testLlm', 'appLogs', 'llmLogs', 'logStats', 'systemMonitoring']
    .map(name => [name, unavailable]));
  const app = express();
  app.use('/api/admin', createPostgresAdminRouter({ adapter: {}, stores: { config: {}, progress: {} },
    auth, repository, resetService: {}, operational, xssLegacyRepository: {}, deletionService: {}, analytics }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { grants, request: (path = '/analytics/progress', authenticated = true) => fetch(
    `http://127.0.0.1:${server.address().port}/api/admin${path}`,
    { redirect: 'manual', headers: authenticated ? { authorization: 'Bearer controlled-admin' } : {} }) };
}

test('analytics route forwards the read snapshot only after current permission checks', async t => {
  const snapshot = { overview: { totalStudents: 2, totalObjectiveCompletions: 3, avgSessionMinutes: 5 },
    challengeStats: [{ challengeKey: 'sql', studentsStarted: 2 }],
    studentProgress: [{ id: 1, lastActivity: '2026-09-15T12:00:00.000Z' }],
    topStudents: [{ id: 1, objectivesCompleted: 2 }],
    progressOverTime: [{ date: '2026-09-15', completions: 3 }], difficultyBreakdown: {}, recentActivity: [] };
  let reads = 0;
  const { grants, request } = await fixture(t, { async getSnapshot() { reads += 1; return snapshot; } });
  assert.equal((await request('/analytics/progress', false)).status, 401);
  assert.equal((await request()).status, 403);
  assert.equal(reads, 0);
  grants.add('manage_progress');
  const response = await request();
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), snapshot);
  assert.equal(reads, 1);
  const alias = await request('/analytics/student-progress');
  assert.equal(alias.status, 307);
  assert.equal(alias.headers.get('location'), '/api/admin/analytics/progress');
  grants.delete('manage_progress');
  assert.equal((await request()).status, 403);
  assert.equal((await request('/analytics/student-progress')).status, 403);
  assert.equal(reads, 1, 'revoked access must not execute another analytics query');
});

test('analytics storage failure is an error rather than fabricated empty statistics', async t => {
  t.mock.method(console, 'error', () => {});
  const { grants, request } = await fixture(t, { async getSnapshot() { throw new Error('internal analytics query failed'); } });
  grants.add('manage_progress');
  const response = await request();
  assert.equal(response.status, 500);
  assert.deepEqual(await response.json(), { error: 'Failed to fetch analytics' });
});


test('platform stats uses canonical metrics, preserves active24h and exposes unavailable duration',async t=>{
 const metrics={registeredToday:2,registeredThisWeek:5,completionsToday:3,completionsThisWeek:7,totalAttempts:11,calendarTimeZone:'UTC',attemptDefinition:'canonical evaluations',averageCompletionTime:null,averageCompletionTimeStatus:'unavailable_no_objective_duration_measurement'};
 let reads=0;const {request}=await fixture(t,{async getSnapshot(){reads++;return{platformStatistics:metrics};}},{async dashboardStats(){return{total_students:8,active_students_24h:4,activity_window_hours:24};},async listExercisesWithStats(){return[];},async listActivity(){return{logs:[]};},async activityStats(){throw Error('Audit events are not objective attempts');}});
 assert.equal((await request('/analytics/platform-stats',false)).status,401);assert.equal(reads,0);
 const response=await request('/analytics/platform-stats');assert.equal(response.status,200);const{stats}=await response.json();
 assert.deepEqual(stats.students,{total:8,active:4,activityWindowHours:24,registeredToday:2,registeredThisWeek:5,registrationCalendarTimeZone:'UTC'});
 assert.equal(stats.activity.totalAttempts,11);assert.equal(stats.activity.completionsToday,3);assert.equal(stats.activity.completionsThisWeek,7);assert.equal(stats.activity.averageCompletionTime,null);assert.equal(stats.activity.averageCompletionTimeStatus,metrics.averageCompletionTimeStatus);assert.equal(reads,1);
});
