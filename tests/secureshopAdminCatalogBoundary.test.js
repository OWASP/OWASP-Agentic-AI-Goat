'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');
const { createWorkshopConfigRepository } = require('../server/database/postgres/workshopConfigRepository');
const key = 'secureshop_agent_security';
const objectiveId = 'ss_audit_instruction_followed';

test('SecureShop catalog reads require admin authority and qualified visibility mutates storage', async t => {
  // Controlled identity/storage adapters: HTTP policy proof, not real-login/native database proof.
  const queries = [];
  const unqualifiedId = 'ss_controlled_unqualified_objective';
  assert.equal(require('../server/config/secureshopCurriculum').isQualifiedObjective(unqualifiedId), false);
  const client = { release() {}, async query(sql, params) {
    queries.push(sql);
    if (sql.startsWith('SELECT * FROM workshop_platform.exercises')) return { rows: [{ workshop_key: key }] };
    if (sql.startsWith('SELECT * FROM workshop_platform.objectives')) return { rows: [{ workshop_key: key,
      objective_id: params[1] === unqualifiedId ? unqualifiedId : objectiveId,
      solution_content: { title: 'Audit source instruction' } }] };
    if (sql.includes('SELECT EXISTS(SELECT 1 FROM workshop_platform.objectives')) return { rows: [{ enabled: true }] };
    if (sql.includes('SELECT revision FROM workshop_platform.config_revision')) return { rows: [{ revision: 1 }] };
    if (sql.includes('SELECT w.*,o.objective_id')) return { rows: [{ workshop_key: key, objective_id: objectiveId,
      is_visible: true, show_hints: false, show_solutions: true, is_enabled: true, hint_enabled: false,
      solution_enabled: true, hint_content: null, solution_content: { title: 'Audit source instruction' } }] };
    if (/^UPDATE/.test(sql)) return { rows: [], rowCount: 1 };
    if (/^INSERT INTO workshop_platform.revisions/.test(sql)) return { rows: [{ revision: 1 }], rowCount: 1 };
    if (/^(BEGIN|ROLLBACK|COMMIT)/.test(sql)) return { rows: [] };
    throw new Error(`Unexpected query: ${sql}`);
  } };
  const pool = { connect: async () => client };
  const adapter = { repository: { recordAudit: async () => {}, hasPermission: async id => id === 1 },
    validateSession: async token => token === 'admin' ? { user: { id: 1, role: 'admin', admin_level: 1 }, session: {} }
      : token === 'student' ? { user: { id: 2, role: 'student', admin_level: 0 }, session: {} } : null };
  let reads = 0;
  const repository = { listAllSolutions: async () => {
    reads++;
    return [{ workshop_key: key, objective_id: objectiveId, label: 'Audit source instruction',
      solution_enabled: false, solution_content: { description: 'Instructor description', code: 'read_owned_log()', references: ['docs/audit.md'], estimatedTime: '20 minutes', prerequisites: ['Owned launch'], title: 'Audit source instruction', hints: ['Inspect owned events'], tips: ['Use the owned log'], difficulty: 'advanced', examples: [{ action: 'Inspect', explanation: 'Owned source only' }] } }];
  } };
  const app = express(); app.use(express.json());
  app.use('/api/admin', createPostgresAdminRouter({ adapter, auth: createPostgresAdminAuth(adapter),
    stores: { pool, config: createWorkshopConfigRepository(pool), progress: {} }, repository,
    resetService: {}, operational: new Proxy({}, { get: () => (_req, res) => res.sendStatus(503) }), deletionService: {}, xssLegacyRepository: {} }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const request = (path, token, method = 'GET', body) => fetch(`http://127.0.0.1:${server.address().port}/api/admin${path}`, {
    method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), 'content-type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}) });
  assert.equal((await request('/solutions')).status, 401);
  assert.equal((await request('/solutions', 'student')).status, 403);
  assert.equal(reads, 0);
  const response = await request('/solutions', 'admin');
  assert.equal(response.status, 200);
  const solution = (await response.json()).solutions[0];
  assert.equal(solution.id, `${key}:${objectiveId}`);
  assert.equal(solution.objective_id, objectiveId);
  assert.equal(solution.workshopKey, key);
  assert.equal(solution.description, 'Instructor description');
  assert.equal(solution.code, 'read_owned_log()');
  assert.deepEqual(solution.references, ['docs/audit.md']);
  assert.equal(solution.estimatedTime, '20 minutes');
  assert.deepEqual(solution.prerequisites, ['Owned launch']);
  assert.deepEqual(solution.tags, ['Use the owned log']);
  assert.equal(solution.difficultyLevel, 'advanced');
  assert.deepEqual(solution.examples, [{ action: 'Inspect', explanation: 'Owned source only' }]);
  const path = `/solutions/${key}:${objectiveId}/visibility`;
  assert.equal((await request(path, 'student', 'PATCH', { isPublic: true })).status, 403);
  assert.equal(queries.length, 0);
  assert.equal((await request(path, 'admin', 'PATCH', { isPublic: 'true' })).status, 400);
  assert.equal(queries.length, 0);
  assert.equal((await request(path, 'admin', 'PATCH', { isPublic: true })).status, 200);
  assert.ok(queries.includes('COMMIT'));
  assert.equal(queries.some(sql => /^UPDATE/.test(sql)), true);

  queries.length = 0;
  const denied = await request(`/solutions/${key}:${unqualifiedId}/visibility`, 'admin', 'PATCH', { isPublic: true });
  assert.equal(denied.status, 409);
  assert.equal(queries.some(sql => sql.startsWith('SELECT * FROM workshop_platform.objectives')), false,
    'visibility qualification rejects before objective lookup or mutation');
  assert.ok(queries.includes('ROLLBACK'));
  assert.equal(queries.includes('COMMIT'), false);
  assert.equal(queries.some(sql => /^\s*(UPDATE|INSERT|DELETE)\b/.test(sql)), false);
});
