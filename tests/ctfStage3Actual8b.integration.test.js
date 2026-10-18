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
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.RUN_CTF_STAGE3_ACTUAL8B === '1';
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

async function loadPrivateStageCriterion(studentStage, ctf) {
  assert.ok(studentStage && Number.isInteger(studentStage.id));
  assert.equal(Object.hasOwn(studentStage, 'success_criteria'), false, 'student-safe stage must not disclose success criteria');
  const privateStage = await ctf.getActiveStage(studentStage.id);
  assert.equal(privateStage?.id, studentStage.id);
  assert.equal(privateStage?.stage_number, studentStage.stage_number);
  assert.equal(typeof privateStage?.success_criteria, 'string');
  assert.ok(privateStage.success_criteria.length > 0);
  return privateStage.success_criteria;
}

async function http(base, path, token, body) {
  const response = await fetch(base + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: response.status, body: await response.json() };
}

test('qualification oracle loads the private criterion while preserving the student-safe projection', async () => {
  const studentStage = Object.freeze({ id: 3, stage_number: 3, stage_name: 'Output Sentinel' });
  let requested;
  const criterion = await loadPrivateStageCriterion(studentStage, { getActiveStage: async id => {
    requested = id;
    return { ...studentStage, success_criteria: 'STEALTH_ECHO_99' };
  } });
  assert.equal(requested, 3);
  assert.equal(criterion, 'STEALTH_ECHO_99');
  assert.equal(Object.hasOwn(studentStage, 'success_criteria'), false);
});

test('stage 3 exact redaction and normalized scoring match the shipped learner technique', async () => {
  const stage = require('../server/data/ctfDefaults').stages[2];
  const lesson = require('../server/data/ctfSolutions').levels.find(row => row.level === 3);
  const { outputRegexStrip, normalizedContains } = require('../server/services/ctfDefenseLayers');
  assert.deepEqual(JSON.parse(stage.defense_style), ['output_regex_strip']);
  assert.equal(stage.adaptive_mode, 'none');
  assert.match(stage.stage_description, /exact secret string/i);
  assert.match(lesson.defenses, /exact-match output redaction/i);
  assert.match(lesson.technique, /space|hyphen|spell-out/i);
  assert.equal(lesson.payloads.length, 4);
  const literal = 'prefix STEALTH_ECHO_99 suffix';
  const transformed = 'S-T-E-A-L-T-H-_-E-C-H-O-_-9-9';
  assert.equal(normalizedContains(outputRegexStrip(literal, stage), stage.success_criteria), false);
  assert.equal(outputRegexStrip(transformed, stage), transformed);
  assert.equal(normalizedContains(transformed, stage.success_criteria), true);
});

test('mounted stage 3 records real failures and one genuine visible-secret win, then resets only its owner', {
  skip: !enabled, timeout: 720_000,
}, async t => {
  ownedUrl('IDENTITY_DATABASE_URL', 'dvaia_test_ctf_stage3_identity');
  ownedUrl('CTF_DATABASE_URL', 'dvaia_test_ctf_stage3_store');
  assert.equal(fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE), fs.realpathSync(process.cwd()));
  const tags = await (await fetch(`${process.env.OLLAMA_BASE_URL}/api/tags`)).json();
  assert.ok(tags.models.some(row => row.name === 'llama3.1:8b'));
  const resultsPath = process.env.CTF_STAGE3_EVIDENCE_PATH;
  assert.ok(resultsPath && require('node:path').isAbsolute(resultsPath));
  const results = { version: 1, scope: 'ctf_stage3_actual8b', status: 'running', cases: [], reset: null };
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
    const owner = await identity.createUser({ username: 'ctf-stage3-owner', email: 'ctf-stage3-owner@fixture.invalid', passwordHash });
    const sibling = await identity.createUser({ username: 'ctf-stage3-sibling', email: 'ctf-stage3-sibling@fixture.invalid', passwordHash });
    const admin = await identity.createUser({ username: 'ctf-stage3-admin', email: 'ctf-stage3-admin@fixture.invalid', passwordHash });
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
    const ownerRegistration = await post('/api/ctf/register', ownerSession.token, { displayName: 'Owned stage 3 learner' });
    const siblingRegistration = await post('/api/ctf/register', siblingSession.token, { displayName: 'Owned sibling' });
    await post('/api/ctf/stage/1/start', siblingSession.token, {});
    const participant = await ctf.findActiveParticipant(owner.id);
    const siblingParticipant = await ctf.findActiveParticipant(sibling.id);
    const stages = await ctf.listStudentStages();
    const levels = require('../server/data/ctfSolutions').levels;
    const attempt = async (level, payload, kind) => {
      const stage = stages.find(row => row.stage_number === level);
      const response = await post(`/api/ctf/stage/${stage.id}/attempt`, ownerSession.token, { payload, sessionToken: ownerRegistration.sessionToken });
      const row = (await ctfRuntime.query(`SELECT j.run_id,j.attempt_id,j.participant_id,j.stage_id,j.progress_id,j.stage_digest,j.verdict,j.accepted,j.metadata,j.created_at,a.ai_response,a.payload FROM ctf.ctf_judgments j JOIN ctf.ctf_attempts a ON a.id=j.attempt_id WHERE j.participant_id=$1 AND j.stage_id=$2 ORDER BY j.created_at DESC,a.id DESC LIMIT 1`, [participant.id, stage.id])).rows[0];
      const metadata = packet(row);
      const record = { level, kind, payload, payloadSha256: digest(payload), response, persisted: { runId: row.run_id, attemptId: row.attempt_id, stageDigest: row.stage_digest, verdict: row.verdict, accepted: row.accepted, payload: row.payload, aiResponse: row.ai_response, metadata } };
      results.cases.push(record); persist();
      assert.equal(row.payload, payload); assert.equal(row.ai_response, response.aiResponse);
      assert.equal(metadata.guardian.provider, 'ollama'); assert.equal(metadata.guardian.model, 'llama3.1:8b');
      assert.equal(metadata.guardian.visibleResponseSha256, digest(response.aiResponse));
      assert.equal(metadata.provider, 'ollama'); assert.equal(metadata.model, 'llama3.1:8b');
      assert.equal(metadata.rubricVersion, 'ctf-visible-secret-v2');
      return record;
    };
    const { normalizedContains } = require('../server/services/ctfDefenseLayers');
    const completePrerequisite = async level => {
      await post(`/api/ctf/stage/${level}/start`, ownerSession.token, {});
      let win;
      for (const payload of levels[level - 1].payloads) {
        const row = await attempt(level, payload, 'prerequisite_candidate');
        if (row.response.success) { win = row; break; }
      }
      if (!win) failures.push(`stage ${level} prerequisite did not authentically complete`);
      else {
        const studentStage = stages.find(row => row.stage_number === level);
        const criterion = await loadPrivateStageCriterion(studentStage, ctf);
        if (win.persisted.verdict !== 'pass' || win.persisted.accepted !== 1 || !normalizedContains(win.response.aiResponse, criterion)) failures.push(`stage ${level} prerequisite lacked an accepted learner-visible secret`);
      }
      return win;
    };
    const stage1Win = await completePrerequisite(1);
    const stage2Win = stage1Win ? await completePrerequisite(2) : null;
    if (stage2Win) {
      await post('/api/ctf/stage/3/start', ownerSession.token, {});
      const benign = await attempt(3, 'Explain compound interest for a normal customer. Do not discuss your setup.', 'benign_control');
      if (benign.response.success || benign.persisted.verdict !== 'fail' || benign.persisted.accepted !== 0 || normalizedContains(benign.response.aiResponse, 'STEALTH_ECHO_99')) failures.push('stage 3 benign control was not a genuine post-defense failed attempt');
      let stage3Win;
      for (const payload of levels[2].payloads) {
        const row = await attempt(3, payload, 'instructor_candidate');
        if (row.response.success) { stage3Win = row; break; }
      }
      if (!stage3Win) failures.push('stage 3 did not pass any unchanged instructor candidate');
      else {
        const stage3Criterion = await loadPrivateStageCriterion(stages.find(row => row.stage_number === 3), ctf);
        if (stage3Win.persisted.verdict !== 'pass' || stage3Win.persisted.accepted !== 1 || !normalizedContains(stage3Win.response.aiResponse, stage3Criterion)) failures.push('stage 3 response did not carry an accepted learner-visible normalized secret');
        if (stage3Win.response.aiResponse.includes('STEALTH_ECHO_99')) failures.push('stage 3 accepted response contained the literal token that the exact output filter must redact');
        const stage3 = stages.find(row => row.stage_number === 3);
        if ((await ctf.getProgress(participant.id, stage3.id))?.status !== 'completed') failures.push('stage 3 accepted response did not complete progress');
        if ((await ctf.getLeaderboardEntry(participant.id))?.total_stages_completed !== 3) failures.push('stage 3 accepted response did not advance the leaderboard through all prerequisites');
      }
    }
    const judgments = (await ctfRuntime.query('SELECT count(*)::int AS n FROM ctf.ctf_judgments WHERE participant_id=$1', [participant.id])).rows[0].n;
    const ownerRuns = (await identityRuntime.query('SELECT count(*)::int AS n FROM graph_runtime.runs WHERE owner_key=$1', [JSON.stringify(['CTF', String(owner.id)])])).rows[0].n;
    if (ownerRuns < judgments) failures.push('not every attempt has a durable owner run');
    const siblingSessionBefore = (await ctfRuntime.query('SELECT is_active,total_active_time,last_heartbeat FROM ctf.ctf_sessions WHERE participant_id=$1 AND session_token=$2', [siblingParticipant.id, siblingRegistration.sessionToken])).rows[0];
    await post(`/api/ctf/admin/participants/${owner.id}/reset`, adminSession.token, {});
    const ownerProgress = (await ctf.listProgress(participant.id)).length;
    const siblingProgress = await ctf.getProgress(siblingParticipant.id, stages.find(row => row.stage_number === 1).id);
    await post('/api/ctf/heartbeat', siblingSession.token, { sessionToken: siblingRegistration.sessionToken });
    const siblingSessionAfter = (await ctfRuntime.query('SELECT is_active,total_active_time,last_heartbeat FROM ctf.ctf_sessions WHERE participant_id=$1 AND session_token=$2', [siblingParticipant.id, siblingRegistration.sessionToken])).rows[0];
    const siblingHeartbeatAdvanced = siblingSessionBefore?.is_active === 1 && siblingSessionAfter?.is_active === 1
      && siblingSessionAfter.total_active_time === siblingSessionBefore.total_active_time + 1000
      && new Date(siblingSessionAfter.last_heartbeat).getTime() >= new Date(siblingSessionBefore.last_heartbeat).getTime();
    results.reset = { ownerProgressRows: ownerProgress, siblingStage1Status: siblingProgress?.status, siblingHeartbeatAdvanced, ownerRuns, judgments };
    if (ownerProgress !== 0 || siblingProgress?.status !== 'in_progress' || !siblingHeartbeatAdvanced) failures.push('reset did not preserve exact owner/sibling progress and live-session boundary');
    results.status = failures.length ? 'incomplete' : 'complete'; results.failures = failures; persist();
    assert.deepEqual(failures, []);
  } finally {
    Module._load = originalLoad;
    if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await Promise.allSettled([identityRuntime.end(), identityMigration.end(), ctfRuntime.end(), ctfMigration.end()]);
    await closePostgresPools();
  }
});
