'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresWorkshopRouter } = require('../server/routes/postgresWorkshop');

test('student time summary and dashboard totals use the same visible canonical workshops', async t => {
  const visible = [{ workshopKey: 'direct_prompt_injection', challengeKey: 'direct_prompt_injection',
    timeSpentSeconds: 45,
    objectives: [{ id: 'interact', completed: true }, { id: 'jailbreak', completed: false }],
    objectiveCount: 2, completedObjectiveCount: 1,
    status: 'in_progress', enabled: true }];
  const calls = [];
  const app = express();
  app.use(createPostgresWorkshopRouter({
    authenticateToken(req, _res, next) { req.user = { id: 37 }; next(); },
    stores: {
      progress: {
        async recordHeartbeat() { throw new Error('Unexpected heartbeat'); },
        async getVisibleUserProgress(id) { calls.push(id); return visible; },
        async getUserProgress() { return [...visible, { workshopKey: 'hidden', timeSpentSeconds: 900 }]; },
      },
      pool: { async query() { return { rows: [{ count: 1 }] }; } },
    },
  }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  const summaryResponse = await fetch(`${base}/time/summary`);
  const statsResponse = await fetch(`${base}/student/stats`);
  assert.equal(summaryResponse.status, 200);
  assert.equal(statsResponse.status, 200);
  const { summary } = await summaryResponse.json();
  const stats = await statsResponse.json();
  const progressResponse = await fetch(`${base}/progress`);
  const challengesResponse = await fetch(`${base}/challenges`);
  assert.equal(progressResponse.status, 200);
  assert.equal(challengesResponse.status, 200);
  const progress = await progressResponse.json();
  const challenges = await challengesResponse.json();
  assert.deepEqual(summary, { direct_prompt_injection: 45 });
  assert.equal(stats.totalTime, Object.values(summary).reduce((sum, seconds) => sum + seconds, 0));
  assert.deepEqual(progress.challenges, challenges.challenges);
  assert.equal(progress.challenges.length, 1);
  assert.equal(stats.totalObjectives, progress.challenges.reduce((sum, row) => sum + row.objectiveCount, 0));
  assert.equal(stats.completedObjectives, progress.challenges.reduce((sum, row) => sum + row.completedObjectiveCount, 0));
  assert.equal(stats.totalTime, progress.challenges.reduce((sum, row) => sum + row.timeSpentSeconds, 0));
  assert.deepEqual(progress.challenges[0].objectives.map(row => row.completed), [true, false]);
  assert.deepEqual(calls, [37, 37, 37, 37]);
});
