'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');
const { Pool } = require('pg');
const { createCtfDb } = require('../helpers/loadCtfDbForProvenance');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.CTF_REGISTRATION_CAPACITY_NATIVE === '1';
function pool(url, max = 4) {
  const parsed = new URL(url); assert.equal(parsed.hostname, '127.0.0.1');
  return new Pool({ connectionString: parsed.href, max, statement_timeout: 30000,
    lock_timeout: 5000, idle_in_transaction_session_timeout: 30000 });
}
function loadRoute(store) {
  const routePath = path.resolve(__dirname, '../../server/routes/ctf.js');
  const original = Module._load;
  Module._load = function(request, parent, isMain) {
    if (parent?.filename === routePath) {
      if (request === '../agent-runtime/ctfStageJudge') return { stageDigest: () => 'unused', judgeCtfStage: async () => { throw new Error('judge forbidden'); } };
      if (request === '../agent-runtime/ctfAttemptCommit') return { commitCtfAttempt: async () => { throw new Error('commit forbidden'); } };
      if (request === '../agent-runtime/ownerWorkflowRoutes') return { ownerWorkflowRoute: (_c, _o, handler) => handler, getOwnerExecution: () => null };
      if (request === '../agent-runtime/runCoordinator') return { createRunCoordinator: () => ({ reset: async (_owner, work) => work(), cancel() {} }) };
      if (request === '../database/ctfDb') return { ctfDb: {}, CTFHelpers: store, ctfDbPath: ':forbidden:', engine: 'postgres' };
      if (request === '../services/promptInjectionCTF') return { classifyTechnique() {}, hashPayload() {}, isNearDuplicate() {}, TECHNIQUE_TAGS: { OTHER: 'other' } };
      if (request === '../services/ctfDefenseLayers') return { runDefenseLayers() {}, runOutputDefenses() {}, normalizedContains() {} };
      if (request === '../agent-runtime/ctfGuardianResult') return { requireCtfGuardianResult() {} };
      if (request === '../middleware/ctfAttemptInput') return { ctfAttemptInput: () => (_q, _s, next) => next(), ctfStageIdInput: () => (_q, _s, next) => next(), ctfStageSecretInput: () => (_q, _s, next) => next() };
      if (request === '../services/multiProviderAIService') return {};
      if (request === '../utils/contextLogger') return { error() {} };
      if (request === '../data/ctfSolutions') return { levels: [] };
      if (request === '../services/ctfLeaderboardRefreshCoordinator') return { createLeaderboardRefreshCoordinator: () => ({ requestRefresh() {}, flush: async () => {} }) };
    }
    return original.call(this, request, parent, isMain);
  };
  try { delete require.cache[routePath]; return { router: require(routePath).router, routePath }; }
  finally { Module._load = original; }
}
async function activeCount(db) { return Number((await db.query('SELECT COUNT(*) AS count FROM ctf.ctf_participants WHERE is_active=1')).rows[0].count); }

test('atomic PostgreSQL registration admits recovery and never oversubscribes concurrent new/reactivated learners',
  { skip: !enabled }, async t => {
    const runtime = pool(process.env.CTF_PROVENANCE_REGISTRATION_RUNTIME_URL);
    const migration = pool(process.env.CTF_PROVENANCE_REGISTRATION_MIGRATION_URL, 3);
    let server;
    try {
      const store = createCtfDb(runtime);
      await store.initialize(migration);
      await store.updateConfig('ctf_registration_open', 'true');
      await store.updateConfig('ctf_max_participants', '1');
      const existingId = await store.registerParticipant(202, 'existing', 'existing@fixture.invalid');

      const recovered = await store.admitParticipant(202, 'recovered', 'recovered@fixture.invalid');
      assert.deepEqual(recovered, { admitted: true, participantId: existingId, recovered: true });
      assert.equal(await activeCount(migration), 1);

      const express = require('express');
      const { router, routePath } = loadRoute(store);
      const app = express(); app.use(express.json());
      app.use((req, _res, next) => { req.user = { id: 202, username: 'existing', email: 'existing@fixture.invalid', role: 'student' }; next(); });
      app.use(router);
      server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
      t.after(() => { delete require.cache[routePath]; });
      const mounted = await fetch(`http://127.0.0.1:${server.address().port}/register`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ displayName: 'mounted recovery' }),
      });
      assert.equal(mounted.status, 200, JSON.stringify(await mounted.json()));
      assert.equal(await activeCount(migration), 1);

      await store.updateConfig('ctf_registration_open', 'false');
      const closed = await store.admitParticipant(202, 'closed overwrite', 'closed@fixture.invalid');
      assert.deepEqual(closed, { admitted: false, reason: 'registration_closed' });
      assert.equal((await store.findParticipant(202)).username, 'mounted recovery');
      await store.updateConfig('ctf_registration_open', 'true');

      await store.updateConfig('ctf_max_participants', '2');
      await store.registerParticipant(303, 'inactive', 'inactive@fixture.invalid');
      await migration.query('UPDATE ctf.ctf_participants SET is_active=0 WHERE user_id=303');
      const mixed = await Promise.all([
        store.admitParticipant(303, 'reactivated', 'reactivated@fixture.invalid'),
        createCtfDb(runtime).admitParticipant(304, 'new', 'new@fixture.invalid'),
      ]);
      assert.equal(mixed.filter(result => result.admitted).length, 1);
      assert.equal(mixed.filter(result => result.reason === 'capacity_reached').length, 1);
      assert.equal(await activeCount(migration), 2);

      await migration.query('UPDATE ctf.ctf_participants SET is_active=0 WHERE user_id IN (303,304)');
      assert.equal(await activeCount(migration), 1);
      const newcomers = await Promise.all([
        store.admitParticipant(305, 'new-a', 'new-a@fixture.invalid'),
        createCtfDb(runtime).admitParticipant(306, 'new-b', 'new-b@fixture.invalid'),
      ]);
      assert.equal(newcomers.filter(result => result.admitted).length, 1);
      assert.equal(newcomers.filter(result => result.reason === 'capacity_reached').length, 1);
      assert.equal(await activeCount(migration), 2);
    } finally {
      if (server) await new Promise(resolve => server.close(resolve));
      await Promise.allSettled([runtime.end(), migration.end()]);
    }
  });

test('packaged route uses the atomic PostgreSQL admission result', () => {
  const fs = require('node:fs');
  const route = fs.readFileSync(path.resolve(__dirname, '../../server/routes/ctf.js'), 'utf8');
  assert.match(route, /CTFHelpers\.admitParticipant\(req\.user\.id, chosenName, req\.user\.email, null\)/);
  assert.match(route, /admission\.reason === 'registration_closed'/);
});
