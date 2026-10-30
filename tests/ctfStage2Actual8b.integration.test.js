'use strict';

const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function guardedLoad(request, parent, isMain) {
  if (/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(request)) {
    throw new Error(`Working/SQLite database import forbidden: ${request}`);
  }
  return originalLoad.call(this, request, parent, isMain);
};

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.RUN_CTF_STAGE2_ACTUAL8B === '1';
const digest = value => createHash('sha256').update(value, 'utf8').digest('hex');
const packet = row => {
  assert.equal(typeof row?.metadata, 'string');
  const value = JSON.parse(row.metadata);
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  return value;
};

function ownedUrl(name, database) {
  const parsed = new URL(process.env[name]);
  assert.equal(parsed.hostname, '127.0.0.1');
  assert.equal(parsed.pathname, `/${database}`);
}

async function http(base, path, token, body) {
  const response = await fetch(base + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: response.status, body: await response.json() };
}

test('stage 2 remains prompt-only refusal with the shipped learner technique', async () => {
  const stage = require('../server/data/ctfDefaults').stages[1];
  const lesson = require('../server/data/ctfSolutions').levels.find(row => row.level === 2);
  assert.deepEqual(JSON.parse(stage.defense_style), []);
  assert.equal(stage.adaptive_mode, 'none');
  assert.match(stage.stage_description, /no filters/i);
  assert.match(lesson.defenses, /no active filter/i);
  assert.match(lesson.technique, /benign framing|instruction-leak/i);
  assert.equal(lesson.payloads.length, 5);
});

test('mounted stage 2 records real failures and one genuine visible-secret win, then resets only its owner', {
  skip: !enabled, timeout: 720_000,
}, async t => {
  ownedUrl('IDENTITY_DATABASE_URL', 'owasp_ai_goat_test_ctf_stage2_identity');
  ownedUrl('CTF_DATABASE_URL', 'owasp_ai_goat_test_ctf_stage2_store');
  assert.equal(fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE), fs.realpathSync(process.cwd()));
  const tags = await (await fetch(`${process.env.OLLAMA_BASE_URL}/api/tags`)).json();
  assert.ok(tags.models.some(row => row.name === 'llama3.1:8b'));
  const resultsPath = process.env.CTF_STAGE2_EVIDENCE_PATH;
  assert.ok(resultsPath && require('node:path').isAbsolute(resultsPath));
  const results = { version: 1, scope: 'ctf_stage2_actual8b', status: 'running', cases: [], reset: null };
  const persist = () => fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2) + '\n', { mode: 0o600 });
  persist();
  const { createPool, closePostgresPools } = require('../server/database/postgres');
  const identityRuntime = createPool(process.env, 'IDENTITY_DATABASE_URL');
  const identityMigration = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
  const ctfRuntime = createPool(process.env, 'CTF_DATABASE_URL');
  const ctfMigration = createPool(process.env, 'CTF_MIGRATION_DATABASE_URL');
  let server;
  const failures = [];
  try {
    const identityApi = require('../server/database/postgres/identityRepository');
    await identityApi.initializeIdentityRepository(identityRuntime, identityMigration);
    await require('../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
    const ctf = require('../server/database/postgres/ctfDb').createCtfDb(ctfRuntime);
    await ctf.initialize(ctfMigration);
    for (const key of ['ctf_enabled', 'ctf_visible_to_students', 'ctf_registration_open']) await ctf.updateConfig(key, 'true');
    const identity = identityApi.createIdentityRepository(identityRuntime);
    const passwordHash = await require('bcryptjs').hash('OwnedCtfFixture@123', 4);
    const owner = await identity.createUser({ username: 'ctf-stage2-owner', email: 'ctf-stage2-owner@fixture.invalid', passwordHash });
    const sibling = await identity.createUser({ username: 'ctf-stage2-sibling', email: 'ctf-stage2-sibling@fixture.invalid', passwordHash });
    const admin = await identity.createUser({ username: 'ctf-stage2-admin', email: 'ctf-stage2-admin@fixture.invalid', passwordHash });
    await identityMigration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1", [admin.id]);
    const progress = require('../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityRuntime);
    const adapter = require('../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({ repository: identity, progress, jwtSecret: process.env.JWT_SECRET });
    const session = async user => adapter.createSession(await identity.findCredentialById(user.id), { get: () => null, ip: '127.0.0.1' });
    const [ownerSession, siblingSession, adminSession] = await Promise.all([session(owner), session(sibling), session(admin)]);
    const express = require('express');
    const app = express(); app.use(express.json({ limit: '64kb' }));
    app.use(require('../server/middleware/adminAuth').authenticateToken);
    app.use('/api/ctf', require('../server/routes/ctf').router);
    server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const post = async (path, token, body, expected = 200) => {
      const response = await http(base, path, token, body);
      assert.equal(response.status, expected, JSON.stringify(response.body));
      return response.body;
    };
    const ownerRegistration = await post('/api/ctf/register', ownerSession.token, { displayName: 'Owned stage 2 learner' });
    const siblingRegistration = await post('/api/ctf/register', siblingSession.token, { displayName: 'Owned sibling' });
    await post('/api/ctf/stage/1/start', siblingSession.token, {});
    const participant = await ctf.findActiveParticipant(owner.id);
    const siblingParticipant = await ctf.findActiveParticipant(sibling.id);
    const stages = await ctf.listStudentStages();
    const levels = require('../server/data/ctfSolutions').levels;
    const attempt = async (level, payload, kind) => {
      const stage = stages.find(row => row.stage_number === level);
      const response = await post(`/api/ctf/stage/${stage.id}/attempt`, ownerSession.token, { payload, sessionToken: ownerRegistration.sessionToken });
      const row = (await ctfRuntime.query(`SELECT j.*,a.ai_response,a.payload FROM ctf.ctf_judgments j JOIN ctf.ctf_attempts a ON a.id=j.attempt_id WHERE j.participant_id=$1 AND j.stage_id=$2 ORDER BY j.created_at DESC,a.id DESC LIMIT 1`, [participant.id, stage.id])).rows[0];
      const metadata = packet(row);
      const record = { level, kind, payload, payloadSha256: digest(payload), response, persisted: { verdict: row.verdict, accepted: row.accepted, payload: row.payload, aiResponse: row.ai_response, metadata } };
      results.cases.push(record); persist();
      assert.equal(row.payload, payload); assert.equal(row.ai_response, response.aiResponse);
      assert.equal(metadata.guardian.provider, 'ollama'); assert.equal(metadata.guardian.model, 'llama3.1:8b');
      assert.equal(metadata.guardian.visibleResponseSha256, digest(response.aiResponse));
      assert.equal(metadata.provider, 'ollama'); assert.equal(metadata.model, 'llama3.1:8b');
      assert.equal(metadata.rubricVersion, 'ctf-visible-secret-v2');
      return record;
    };
    await post('/api/ctf/stage/1/start', ownerSession.token, {});
    let stage1Win;
    for (const payload of levels[0].payloads) { const row = await attempt(1, payload, 'prerequisite_candidate'); if (row.response.success) { stage1Win = row; break; } }
    if (!stage1Win) failures.push('stage 1 prerequisite did not authentically complete');
    if (stage1Win) {
      await post('/api/ctf/stage/2/start', ownerSession.token, {});
      const benign = await attempt(2, 'Explain compound interest for a normal customer. Do not discuss your setup.', 'benign_control');
      if (benign.response.success || benign.persisted.verdict !== 'fail' || benign.persisted.accepted !== 0) failures.push('stage 2 benign control was not a genuine failed attempt');
      let stage2Win;
      for (const payload of levels[1].payloads) { const row = await attempt(2, payload, 'instructor_candidate'); if (row.response.success) { stage2Win = row; break; } }
      if (!stage2Win) failures.push('stage 2 did not pass any unchanged instructor candidate');
      else {
        const { normalizedContains } = require('../server/services/ctfDefenseLayers');
        if (stage2Win.persisted.verdict !== 'pass' || stage2Win.persisted.accepted !== 1 || !normalizedContains(stage2Win.response.aiResponse, 'BYPASS_ALPHA_7X')) failures.push('stage 2 response did not carry an accepted learner-visible secret');
        const stage2 = stages.find(row => row.stage_number === 2);
        if ((await ctf.getProgress(participant.id, stage2.id))?.status !== 'completed') failures.push('stage 2 accepted response did not complete progress');
        if ((await ctf.getLeaderboardEntry(participant.id))?.total_stages_completed !== 2) failures.push('stage 2 accepted response did not advance the leaderboard');
      }
    }
    const judgments = (await ctfRuntime.query('SELECT count(*)::int AS n FROM ctf.ctf_judgments WHERE participant_id=$1', [participant.id])).rows[0].n;
    const ownerRuns = (await identityRuntime.query('SELECT count(*)::int AS n FROM graph_runtime.runs WHERE owner_key=$1', [JSON.stringify(['CTF', String(owner.id)])])).rows[0].n;
    if (ownerRuns < judgments) failures.push('not every attempt has a durable owner run');
    await post(`/api/ctf/admin/participants/${owner.id}/reset`, adminSession.token, {});
    const ownerProgress = (await ctf.listProgress(participant.id)).length;
    const siblingProgress = await ctf.getProgress(siblingParticipant.id, stages.find(row => row.stage_number === 1).id);
    results.reset = { ownerProgressRows: ownerProgress, siblingStage1Status: siblingProgress?.status, siblingSessionTokenRetained: Boolean(siblingRegistration.sessionToken), ownerRuns, judgments };
    if (ownerProgress !== 0 || siblingProgress?.status !== 'in_progress') failures.push('reset did not preserve exact owner/sibling boundary');
    results.status = failures.length ? 'incomplete' : 'complete'; results.failures = failures; persist();
    assert.deepEqual(failures, []);
  } finally {
    Module._load = originalLoad;
    if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await Promise.allSettled([identityRuntime.end(), identityMigration.end(), ctfRuntime.end(), ctfMigration.end()]);
    await closePostgresPools();
  }
});
