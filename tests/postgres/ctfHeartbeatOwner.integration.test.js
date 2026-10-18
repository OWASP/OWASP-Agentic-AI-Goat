'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');
const { Pool } = require('pg');
const { createCtfDb } = require('../helpers/loadCtfDbForProvenance');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.CTF_PROVENANCE_HEARTBEAT_NATIVE === '1';
function pool(url, max = 3) {
  const parsed = new URL(url);
  assert.equal(parsed.hostname, '127.0.0.1');
  return new Pool({ connectionString: parsed.href, max, statement_timeout: 30000,
    lock_timeout: 5000, idle_in_transaction_session_timeout: 30000 });
}
async function sessionRow(db, token) {
  return (await db.query(`SELECT session_token,last_heartbeat,total_active_time,is_active
    FROM ctf.ctf_sessions WHERE session_token=$1`, [token])).rows[0];
}
function loadMountedRoute(store) {
  const routePath = path.resolve(__dirname, '../../server/routes/ctf.js');
  const originalLoad = Module._load;
  Module._load = function(request, parent, isMain) {
    if (parent?.filename === routePath) {
      if (request === '../agent-runtime/ctfStageJudge') return { stageDigest: () => 'unused', judgeCtfStage: async () => { throw new Error('judge forbidden'); } };
      if (request === '../agent-runtime/ctfAttemptCommit') return { commitCtfAttempt: async () => { throw new Error('attempt commit forbidden'); } };
      if (request === '../agent-runtime/ownerWorkflowRoutes') return { ownerWorkflowRoute: (_coordinator, _ownerFor, handler) => handler, getOwnerExecution: () => null };
      if (request === '../agent-runtime/runCoordinator') return { createRunCoordinator: () => ({ reset: async (_owner, work) => work(), cancel() {} }) };
      if (request === '../database/ctfDb') return { ctfDb: {}, CTFHelpers: store, ctfDbPath: ':forbidden:', engine: 'postgres' };
      if (request === '../services/promptInjectionCTF') return { classifyTechnique() {}, hashPayload() {}, isNearDuplicate() {}, TECHNIQUE_TAGS: { OTHER: 'other' } };
      if (request === '../services/ctfDefenseLayers') return { runDefenseLayers() {}, runOutputDefenses() {}, normalizedContains() {} };
      if (request === '../agent-runtime/ctfGuardianResult') return { requireCtfGuardianResult() {} };
      if (request === '../middleware/ctfAttemptInput') return { ctfAttemptInput: () => (_req, _res, next) => next(), ctfStageIdInput: () => (_req, _res, next) => next(), ctfStageSecretInput: () => (_req, _res, next) => next() };
      if (request === '../services/multiProviderAIService') return {};
      if (request === '../utils/contextLogger') return { error() {} };
      if (request === '../data/ctfSolutions') return { levels: [] };
      if (request === '../services/ctfLeaderboardRefreshCoordinator') return { createLeaderboardRefreshCoordinator: () => ({ requestRefresh() {}, flush: async () => {} }) };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try { delete require.cache[routePath]; return { router: require(routePath).router, routePath }; }
  finally { Module._load = originalLoad; }
}
async function request(base, token, body) {
  const response = await fetch(base + '/heartbeat', { method: 'POST', headers: {
    'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() };
}

test('mounted heartbeat and PostgreSQL mutation preserve owner isolation', { skip: !enabled }, async t => {
  const runtime = pool(process.env.CTF_PROVENANCE_HEARTBEAT_RUNTIME_URL);
  const migration = pool(process.env.CTF_PROVENANCE_HEARTBEAT_MIGRATION_URL, 2);
  let server;
  try {
    const store = createCtfDb(runtime);
    await store.initialize(migration);
    const ownerId = 101, siblingId = 202;
    const ownerParticipant = await store.registerParticipant(ownerId, 'heartbeat-owner', 'owner@fixture.invalid');
    await store.registerParticipant(siblingId, 'heartbeat-sibling', 'sibling@fixture.invalid');
    await store.createSession(ownerParticipant, 'victim-session', '127.0.0.1', 'qualification');
    await store.createSession(ownerParticipant, 'inactive-session', '127.0.0.1', 'qualification');
    await store.createSession(ownerParticipant, 'direct-owner-session', '127.0.0.1', 'qualification');
    await migration.query(`UPDATE ctf.ctf_sessions SET last_heartbeat='2026-01-01T00:00:00Z',
      total_active_time=4000 WHERE session_token='victim-session'`);
    await migration.query(`UPDATE ctf.ctf_sessions SET last_heartbeat='2026-01-02T00:00:00Z',
      total_active_time=7000,is_active=0 WHERE session_token='inactive-session'`);
    await migration.query(`UPDATE ctf.ctf_sessions SET last_heartbeat='2026-01-03T00:00:00Z',
      total_active_time=9000 WHERE session_token='direct-owner-session'`);

    const express = require('express');
    const { router, routePath } = loadMountedRoute(store);
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      const token = req.get('authorization');
      if (token === 'Bearer owner-auth') req.user = { id: ownerId, role: 'student', adminLevel: 0 };
      if (token === 'Bearer sibling-auth') req.user = { id: siblingId, role: 'student', adminLevel: 0 };
      next();
    });
    app.use(router);
    server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
    t.after(() => { delete require.cache[routePath]; });
    const base = `http://127.0.0.1:${server.address().port}`;
    const original = await sessionRow(migration, 'victim-session');

    assert.equal((await request(base, null, { sessionToken: 'victim-session', userId: ownerId })).status, 401);
    assert.deepEqual(await sessionRow(migration, 'victim-session'), original, 'unauthenticated request cannot mutate session');

    const sibling = await request(base, 'sibling-auth', {
      sessionToken: 'victim-session', userId: ownerId, ownerId,
    });
    assert.deepEqual(sibling, { status: 200, body: { status: 'ok' } });
    assert.deepEqual(await sessionRow(migration, 'victim-session'), original,
      'authenticated sibling cannot override owner through request body');
    assert.equal(await store.heartbeat('victim-session', siblingId), 0);
    assert.deepEqual(await sessionRow(migration, 'victim-session'), original,
      'direct sibling mutation returns zero and preserves victim state');

    const directOwnerBefore = await sessionRow(migration, 'direct-owner-session');
    assert.equal(await store.heartbeat('direct-owner-session', ownerId), 1);
    const directOwnerAfter = await sessionRow(migration, 'direct-owner-session');
    assert.equal(directOwnerAfter.total_active_time, 10000);
    assert.ok(new Date(directOwnerAfter.last_heartbeat) > new Date(directOwnerBefore.last_heartbeat));

    assert.equal(await store.heartbeat('missing-session', ownerId), 0);
    const inactiveBefore = await sessionRow(migration, 'inactive-session');
    assert.equal(await store.heartbeat('inactive-session', ownerId), 0);
    assert.deepEqual(await sessionRow(migration, 'inactive-session'), inactiveBefore);

    const owner = await request(base, 'owner-auth', {
      sessionToken: 'victim-session', userId: siblingId, ownerId: siblingId,
    });
    assert.deepEqual(owner, { status: 200, body: { status: 'ok' } });
    const updated = await sessionRow(migration, 'victim-session');
    assert.equal(updated.total_active_time, 5000);
    assert.equal(updated.is_active, 1);
    assert.ok(new Date(updated.last_heartbeat) > new Date(original.last_heartbeat));
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await Promise.allSettled([runtime.end(), migration.end()]);
  }
});

test('packaged heartbeat source forwards and enforces authenticated owner identity', () => {
  const fs = require('node:fs');
  const route = fs.readFileSync(path.resolve(__dirname, '../../server/routes/ctf.js'), 'utf8');
  const pgStore = fs.readFileSync(path.resolve(__dirname, '../../server/database/postgres/ctfDb.js'), 'utf8');
  assert.match(route, /CTFHelpers\.heartbeat\(sessionToken,\s*req\.user\.id\)/);
  assert.match(pgStore, /p\.id\s*=\s*s\.participant_id AND p\.user_id\s*=\s*\$2/);
});
