'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');

test('PostgreSQL admin router preserves the legacy four-tab XSS contract', async t => {
  const calls = [], audits = [];
  let preview = {
    title: 'Reflected', difficulty: 'Easy', hints: '["hint"]',
    examples: '[{"payload":"<b>x</b>"}]', approach: 'approach', tips: '["tip"]',
  };
  const xssLegacyRepository = {
    listSolutions: async () => [{ challenge_id: 'email', solutions_enabled: false, enabled_by: null,
      enabled_at: null, updated_at: '2026-09-11 12:00:00', title: 'Email', difficulty: 'Hard' }],
    setVisibility: async (...args) => { calls.push(['one', ...args]); return 1; },
    setAllVisibility: async (...args) => { calls.push(['all', ...args]); return 4; },
    getSolution: async id => id === 'missing' ? null : { ...preview },
    updateSolution: async (...args) => { calls.push(['content', ...args]); return args[0] === 'missing' ? 0 : 1; },
    setCanonicalAndLegacyMasterVisibility: async (...args) => {
      calls.push(['master', ...args]);
      return { changed: true, revision: 7, exercise: { showSolutions: args[0] } };
    },
  };
  const config = {
    setMasterSolutionVisibility: async (...args) => { calls.push(['canonical-master', ...args]); return { changed: true }; },
    setMasterHintVisibility: async () => ({ changed: false }),
    setObjectiveSolutionVisibility: async (...args) => { calls.push(['objective', ...args]); return { changed: true }; },
  };
  const auth = {
    authenticateToken(req, res, next) {
      const token = req.headers.authorization;
      if (!token) return res.status(401).json({ error: 'Authentication required' });
      req.user = token === 'Bearer student'
        ? { id: 2, admin_level: 0, username: 'student' }
        : { id: 17, admin_level: 1, username: 'admin' };
      next();
    },
    requireAdminLevel(level) {
      return (req, res, next) => req.user.admin_level < level
        ? res.status(403).json({ error: 'Insufficient privileges', userLevel: req.user.admin_level }) : next();
    },
    requirePermission() { return (_req, _res, next) => next(); },
    logActivity(action) { return (_req, _res, next) => { audits.push(action); next(); }; },
  };
  const unusedHandler = (_req, res) => res.status(501).json({ error: 'unused fixture handler' });
  const operational = Object.fromEntries(['providerStatus', 'switchProvider', 'configureProvider', 'testProvider',
    'testLlm', 'appLogs', 'llmLogs', 'logStats', 'systemMonitoring'].map(name => [name, unusedHandler]));
  const app = express();
  app.use(express.json());
  app.use('/api/admin', createPostgresAdminRouter({ adapter: {}, stores: { pool: {}, progress: {}, config }, auth,
    repository: {}, resetService: {}, operational, xssLegacyRepository }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  async function request(path, { method = 'GET', body, token = 'admin' } = {}) {
    const response = await fetch(base + path, { method, headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  }

  assert.equal((await request('/api/admin/xss-workshop/solutions', { token: null })).status, 401);
  assert.equal((await request('/api/admin/xss-workshop/solutions', { token: 'student' })).status, 403);
  const list = await request('/api/admin/xss-workshop/solutions');
  assert.deepEqual(list, { status: 200, body: { success: true, challenges: [{ challengeId: 'email',
    solutionsEnabled: false, enabledBy: null, enabledAt: null, updatedAt: '2026-09-11 12:00:00',
    title: 'Email', difficulty: 'Hard' }] } });

  assert.deepEqual(await request('/api/admin/xss-workshop/solutions/toggle', { method: 'POST', body: { challengeId: 'bad', enabled: true } }),
    { status: 400, body: { error: 'Valid challengeId is required' } });
  const toggle = await request('/api/admin/xss-workshop/solutions/toggle', { method: 'POST', body: { challengeId: 'reflected', enabled: 'yes' } });
  assert.deepEqual(toggle.body, { success: true, challengeId: 'reflected', enabled: true });
  assert.deepEqual(calls.at(-1), ['one', 'reflected', true, 17]);

  const bulk = await request('/api/admin/xss-workshop/solutions/bulk', { method: 'POST', body: { enabled: 0 } });
  assert.deepEqual(bulk.body, { success: true, enabled: false, updated: 4 });
  assert.deepEqual(calls.at(-1), ['all', false, 17]);

  const validPreview = await request('/api/admin/xss-workshop/solutions/preview/reflected');
  assert.deepEqual(validPreview.body.solution.hints, ['hint']);
  assert.deepEqual(validPreview.body.solution.examples, [{ payload: '<b>x</b>' }]);
  assert.deepEqual(validPreview.body.solution.tips, ['tip']);
  assert.equal((await request('/api/admin/xss-workshop/solutions/preview/missing')).status, 404);
  preview = { ...preview, examples: '{bad', tips: '["still raw"]' };
  const malformed = await request('/api/admin/xss-workshop/solutions/preview/reflected');
  assert.deepEqual(malformed.body.solution.hints, ['hint']);
  assert.equal(malformed.body.solution.examples, '{bad');
  assert.equal(malformed.body.solution.tips, '["still raw"]');

  assert.equal((await request('/api/admin/xss-workshop/solutions/reflected', { method: 'POST', body: {} })).status, 400);
  const update = await request('/api/admin/xss-workshop/solutions/missing', { method: 'POST', body: {
    title: 'Edited', hints: ['one'], examples: [{ payload: '<b>x</b>' }], tips: ['two'],
  } });
  assert.deepEqual(update.body, { success: true, message: 'Solution updated successfully' });
  assert.deepEqual(calls.at(-1), ['content', 'missing', { title: 'Edited', difficulty: undefined,
    hints: '["one"]', examples: '[{"payload":"<b>x</b>"}]', approach: undefined, tips: '["two"]' }]);

  const master = await request('/api/admin/challenges/solutions/toggle', { method: 'POST', body: {
    challengeKey: 'reflected_xss_llm', showSolutions: true,
  } });
  assert.equal(master.body.revision, 7);
  assert.deepEqual(calls.at(-1), ['master', true, 17]);
  assert.equal(calls.some(call => call[0] === 'canonical-master'), false);

  await request('/api/admin/xss-workshop/objective-solutions/xss_r1/toggle', { method: 'POST', body: { enabled: true } });
  assert.deepEqual(calls.at(-1), ['objective', 'xss_workshop', 'xss_r1', true, 17]);
  assert.deepEqual(audits, ['admin_xss_solution_toggle', 'admin_xss_solution_toggle',
    'admin_xss_solution_bulk', 'admin_xss_solution_update', 'admin_xss_solution_update']);
});
