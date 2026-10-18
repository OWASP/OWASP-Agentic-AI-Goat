'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');
const { readConfig } = require('../server/database/postgres/workshopConfigRepository');

async function fixture() {
  const grants = new Map([
    [1, new Map([['manage_progress', { active: true }], ['challenge_management', { active: true }]])],
    [2, new Map([['manage_progress', { active: false }], ['challenge_management', { active: false }]])],
    [3, new Map([['manage_progress', { active: true, expiresAt: Date.now() - 1 }], ['challenge_management', { active: true, expiresAt: Date.now() - 1 }]])],
  ]);
  const calls = [];
  const identityRepository = {
    recordAudit: async () => {},
    hasPermission: async (userId, permission) => {
      const grant = grants.get(Number(userId))?.get(permission);
      return Boolean(grant?.active && (!grant.expiresAt || grant.expiresAt > Date.now()));
    },
  };
  const adapter = {
    repository: identityRepository,
    validateSession: async token => {
      const id = Number(token);
      return Number.isInteger(id) && id > 0 ? { user: { id, username: `admin-${id}`, role: 'admin', admin_level: 2 }, session: {} } : null;
    },
  };
  const auth = createPostgresAdminAuth(adapter);
  const objective = {
    workshopKey: 'direct_prompt_injection', label: 'Instructor-edited canonical label',
    raw: { objectiveEnabled: true, hintEnabled: false, solutionEnabled: true }, hasHintContent: true,
  };
  const config = {
    getSnapshot: async () => ({ exercises: { direct_prompt_injection: {
      workshopKey: 'direct_prompt_injection', objectives: { jailbreak: objective },
    } } }),
    setObjectiveVisibility: async (...args) => { calls.push(['objective', ...args]); return { changed: true }; },
  };
  const challenges = [{ id: 'direct_prompt_injection', workshopKey: 'direct_prompt_injection', objectiveCount: 1,
    completedObjectiveCount: 0, timeSpentSeconds: 0, status: 'not_started', objectives: [] }];
  const progress = {
    getVisibleUserProgress: async () => challenges,
    getVisibleUsersProgress: async ids => new Map(ids.map(id => [id, challenges])),
  };
  const repository = {
    getStudent: async id => ({ id: Number(id), username: `student-${id}`, role: 'student' }),
    getUser: async id => ({ user: { id: Number(id), username: `student-${id}`, role: 'student' } }),
    listStudents: async () => [{ id: 9, username: 'student-9' }],
  };
  const handler = (_req, res) => res.sendStatus(501);
  const operational = Object.fromEntries(['providerStatus', 'switchProvider', 'configureProvider', 'testProvider', 'testLlm', 'appLogs', 'llmLogs', 'logStats', 'systemMonitoring'].map(key => [key, handler]));
  const app = express(); app.use(express.json());
  app.use('/api/admin', createPostgresAdminRouter({ adapter, auth, stores: {
    pool: { query: async () => ({ rows: [] }) }, config, progress,
  }, repository, resetService: {}, xssLegacyRepository: {}, operational }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  return { server, calls, request: async (path, { token = 1, method = 'GET', body } = {}) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/admin${path}`, {
      method, headers: { authorization: `Bearer ${token}`, ...(body ? { 'content-type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, body: await response.json() };
  } };
}

test('progress reads reject revoked and expired grants while a current grant retains admin access', async t => {
  const f = await fixture(); t.after(() => new Promise(resolve => f.server.close(resolve)));
  assert.equal((await f.request('/student-workshop-view/9', { token: 2 })).status, 403);
  assert.equal((await f.request('/student-workshop-view/9', { token: 3 })).status, 403);
  assert.equal((await f.request('/students', { token: 2 })).status, 403);
  assert.equal((await f.request('/database/reset', { token: 3, method: 'POST', body: { resetType: 'challenges', confirmPassword: 'unused' } })).status, 403);
  const allowed = await f.request('/student-workshop-view/9');
  assert.equal(allowed.status, 200);
  assert.equal(allowed.body.challenges[0].workshopKey, 'direct_prompt_injection');
});

test('configuration writes reject revoked and expired grants and preserve a current grant', async t => {
  const f = await fixture(); t.after(() => new Promise(resolve => f.server.close(resolve)));
  const path = '/workshops/direct_prompt_injection/objectives/jailbreak/toggle';
  for (const token of [2, 3]) assert.equal((await f.request(path, { token, method: 'POST', body: { enabled: false } })).status, 403);
  assert.equal(f.calls.length, 0);
  assert.equal((await f.request(path, { method: 'POST', body: { enabled: false } })).status, 200);
  assert.deepEqual(f.calls, [['objective', 'direct_prompt_injection', 'jailbreak', false, 1]]);
});

test('objective DTO uses persisted canonical label and workshop key without changing independent gates', async t => {
  const f = await fixture(); t.after(() => new Promise(resolve => f.server.close(resolve)));
  const response = await f.request('/workshops/direct_prompt_injection/objectives');
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { success: true, workshopKey: 'direct_prompt_injection', objectives: [{
    workshopKey: 'direct_prompt_injection', objective_id: 'jailbreak', label: 'Instructor-edited canonical label',
    is_enabled: true, hint_enabled: false, solutions_enabled: true, has_hint_content: true,
  }] });
});

test('configuration snapshot carries the persisted instructor label and canonical workshop key', async () => {
  const client = { query: async sql => sql.includes('SELECT revision')
    ? { rows: [{ revision: 4 }] }
    : { rows: [{ workshop_key: 'xss_workshop', is_visible: true, show_hints: true, show_solutions: true,
      objective_id: 'xss_r1', label: 'Persisted instructor label', is_enabled: true, hint_enabled: false,
      solution_enabled: true, hint_content: { title: 'Hint' }, solution_content: { title: 'Solution' } }] } };
  const snapshot = await readConfig(client, { includeRaw: true });
  const objective = snapshot.exercises.xss_workshop.objectives.xss_r1;
  assert.equal(snapshot.exercises.xss_workshop.workshopKey, 'xss_workshop');
  assert.equal(objective.workshopKey, 'xss_workshop');
  assert.equal(objective.label, 'Persisted instructor label');
  assert.equal(objective.raw.hintEnabled, false);
  assert.equal(objective.raw.solutionEnabled, true);
});
