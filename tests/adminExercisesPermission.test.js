'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');
const { createAdminExercisesRouter } = require('../server/routes/adminExercises');

test('exercise configuration writes require a current challenge-management grant', async t => {
  let granted = false;
  const calls = [];
  const repository = { hasPermission: async (_id, permission) => {
    assert.equal(permission, 'challenge_management');
    return granted;
  } };
  const auth = createPostgresAdminAuth({ repository, validateSession: async token => ({
    user: { id: 1, role: token === 'student' ? 'student' : 'admin', admin_level: 1 }, session: {},
  }) });
  const methods = ['setAllHintAndSolutionVisibility', 'setExerciseVisibility', 'setObjectiveVisibility', 'setMasterHintVisibility',
    'setObjectiveHintVisibility', 'setMasterSolutionVisibility', 'setObjectiveSolutionVisibility',
    'updateObjectiveMetadata', 'updateHintContent', 'updateSolutionContent', 'setXssGroupControls'];
  const service = {
    getHintContent: async () => ({ title: 'Instructor hint', hints: ['Owned'] }),
    getSolutionContent: async () => ({ title: 'Instructor solution' }),
    getObjectiveMetadata: async () => ({ label: 'Instructor objective', category: 'AI' }),
  };
  for (const method of methods) service[method] = async () => {
    calls.push(method);
    return { changed: true, revision: calls.length, exercise: { objectives: {} } };
  };
  const app = express();
  app.use(express.json());
  app.use('/api/admin/exercises', createAdminExercisesRouter({
    service, auth, onCommitted: () => {}, onContentCommitted: async () => {},
  }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const root = `http://127.0.0.1:${server.address().port}/api/admin/exercises`;
  const base = `${root}/workshop`;
  const requests = [
    ['PATCH', `${root}/content-visibility`, { enabled: true }],
    ['PATCH', base, { enabled: true }],
    ['PATCH', `${base}/objectives/objective`, { enabled: true }],
    ['PATCH', `${base}/hints`, { enabled: true }],
    ['PATCH', `${base}/objectives/objective/hint`, { enabled: true }],
    ['PATCH', `${base}/solutions`, { enabled: true }],
    ['PATCH', `${base}/objectives/objective/solution`, { enabled: true }],
    ['PUT', `${base}/objectives/objective`, { label: 'Updated objective' }],
    ['PUT', `${base}/objectives/objective/hint`, { title: 'Owned hint' }],
    ['PUT', `${base}/objectives/objective/solution`, { title: 'Owned solution' }],
    ['POST', `${root}/reflected_xss_llm/group-controls`, { dimension: 'solutions', enabled: true }],
  ];
  const request = ([method, url, body], token = 'admin') => fetch(url, {
    method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

  // Reading authored content remains available to an authenticated instructor.
  assert.equal((await fetch(`${base}/objectives/objective/hint`, {
    headers: { authorization: 'Bearer admin' },
  })).status, 200);
  assert.equal((await fetch(`${base}/objectives/objective/solution`, {
    headers: { authorization: 'Bearer admin' },
  })).status, 200);
  assert.equal((await fetch(`${base}/objectives/objective`, {
    headers: { authorization: 'Bearer admin' },
  })).status, 200);
  for (const entry of requests) assert.equal((await request(entry)).status, 403);
  assert.deepEqual(calls, []);
  granted = true;
  for (const entry of requests) assert.equal((await request(entry, 'student')).status, 403);
  assert.deepEqual(calls, []);
  for (const entry of requests) assert.equal((await request(entry)).status, 200);
  assert.deepEqual(calls, methods);
  for (const body of [{}, { dimension: 'other', enabled: true },
    { dimension: 'hints', enabled: 'true' }, { dimension: 'hints', enabled: true, workshopKey: 'csrf_workshop' }]) {
    assert.equal((await request(['POST', `${root}/reflected_xss_llm/group-controls`, body])).status, 400);
  }
  assert.equal(calls.length, methods.length, 'malformed group controls never reach the service');
  assert.equal((await request(['POST', `${root}/csrf_workshop/group-controls`, { dimension: 'active', enabled: false }])).status, 404);
  granted = false;
  assert.equal((await request(requests[0])).status, 403, 'revocation applies to the next request');
  assert.equal(calls.length, methods.length);
});
