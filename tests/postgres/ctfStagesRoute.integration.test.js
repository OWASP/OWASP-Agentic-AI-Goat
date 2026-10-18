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

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.CTF_STAGES_ROUTE_ISOLATED === '1'
  && process.env.RUN_LIVE_CTF_WORKFLOW === '1';
const candidateSet = process.env.CTF_CANDIDATE_SET || 'instructor';
assert.ok(['instructor', 'reviewer-boundary-v1', 'stage6-fixed-v1'].includes(candidateSet));
const stage6Fixed = candidateSet === 'stage6-fixed-v1';
const levels = require('../../server/data/ctfSolutions').levels.map(level =>
  candidateSet === 'reviewer-boundary-v1' && level.level >= 6
    ? { ...level, payloads: require('../fixtures/ctfReviewerBoundaryCandidates') } : level);
const digest = value => createHash('sha256').update(value, 'utf8').digest('hex');
const stageEnd = Number(process.env.CTF_STAGE_END || 4);
const targetStage = process.env.CTF_TARGET_STAGE === undefined
  ? null : Number(process.env.CTF_TARGET_STAGE);
const targetStages = new Set([6, 7, 8, 9, 10]);
const lessonStateKeys = [
  'input_guard_observed', 'reviewer_observed', 'category_consumed',
  'category_reuse_blocked', 'shared_similarity_blocked',
];
function assertLessonState(response, expected = {}) {
  assert.ok(response.lessonState && typeof response.lessonState === 'object');
  assert.deepEqual(Object.keys(response.lessonState).sort(), [...lessonStateKeys].sort());
  for (const key of lessonStateKeys) assert.equal(typeof response.lessonState[key], 'boolean');
  for (const [key, value] of Object.entries(expected)) assert.equal(response.lessonState[key], value, key);
}
const judgmentMetadata = row => {
  assert.equal(typeof row?.metadata, 'string', 'PostgreSQL judgment metadata must be persisted as TEXT');
  const parsed = JSON.parse(row.metadata);
  assert.ok(parsed && typeof parsed === 'object' && !Array.isArray(parsed));
  return parsed;
};

function safeHttpDiagnostic(path, status, body) {
  const diagnostic = { path, status, bodyKeys: body && typeof body === 'object'
    ? Object.keys(body).sort() : [] };
  for (const key of ['success', 'blocked', 'retryable', 'alreadyStarted', 'alreadyCompleted']) {
    if (typeof body?.[key] === 'boolean') diagnostic[key] = body[key];
  }
  if (body?.judgment && ['pass', 'fail', 'unavailable'].includes(body.judgment.verdict)) {
    diagnostic.judgment = { verdict: body.judgment.verdict };
  }
  if (body?.lessonState && typeof body.lessonState === 'object') {
    diagnostic.lessonState = Object.fromEntries(lessonStateKeys.map(key => [key,
      body.lessonState[key] === true]));
  }
  return diagnostic;
}

const empiricalOutcomeKinds = new Set([
  'input_blocked', 'guardian_non_disclosure', 'reviewer_blocked',
  'judge_fail', 'accepted', 'unavailable', 'stale',
]);
function independentQualificationSummary(fixture, outcomes) {
  assert.equal(fixture?.earned, false, 'independent prerequisites must remain explicitly unearned');
  assert.ok(outcomes.every(row => empiricalOutcomeKinds.has(row.outcome)));
  const accepted = outcomes.some(row => row.outcome === 'accepted');
  return Object.freeze({
    applicationCorrectness: Object.freeze({
      status: 'pass',
      scope: Object.freeze([
        'prerequisite_denial', 'synthetic_prerequisite_admission',
        'defense_and_judgment_persistence', 'owner_reset_sibling_preservation',
      ]),
      acceptedTargetCommit: accepted ? 'actual_observed' : 'not_required_for_correctness_claim',
    }),
    syntheticPrerequisites: fixture,
    empiricalModelExploitability: Object.freeze({
      status: accepted ? 'observed' : 'not_observed_within_budget',
      outcomes: Object.freeze(outcomes.map(row => Object.freeze({ ...row }))),
    }),
  });
}

async function establishUnearnedPrerequisites(client, participantId, allStages,
  selectedTargetStage) {
  assert.ok(targetStages.has(selectedTargetStage), 'target stage fixture must be closed to 6-10');
  const target = allStages.find(row => row.stage_number === selectedTargetStage);
  assert.ok(target, 'target stage must exist');
  const prerequisites = allStages.filter(row => row.stage_order < target.stage_order);
  assert.deepEqual(prerequisites.map(row => row.stage_number),
    Array.from({ length: selectedTargetStage - 1 }, (_, index) => index + 1));
  await client.query('BEGIN');
  try {
    for (const stage of prerequisites) {
      await client.query(`INSERT INTO ctf.ctf_progress
        (participant_id,stage_id,status,started_at,completed_at,completion_time,
         attempts_count,successful_attempts,failed_attempts,hints_used,hint_penalty_total,
         time_penalties,final_payload,techniques_used)
        VALUES($1,$2,'completed',transaction_timestamp(),transaction_timestamp(),0,
          0,0,0,0,0,0,NULL,'[]')`, [participantId, stage.id]);
      await client.query(`INSERT INTO ctf.ctf_events
        (event_type,participant_id,stage_id,event_data,is_public)
        VALUES('qualification_fixture_prerequisite',$1,$2,$3,0)`, [participantId, stage.id,
        JSON.stringify({ schemaVersion: 1, targetStage: selectedTargetStage,
          prerequisiteStage: stage.stage_number, earned: false })]);
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  }
  return Object.freeze({ earned: false, targetStage: selectedTargetStage,
    prerequisiteStages: Object.freeze(prerequisites.map(row => row.stage_number)) });
}

test('independent later-stage fixture records exact unearned prerequisite provenance', async () => {
  const calls = [];
  const client = { query: async (sql, values = []) => { calls.push({ sql, values }); return { rows: [] }; } };
  const allStages = Array.from({ length: 10 }, (_, index) => ({
    id: index + 101, stage_number: index + 1, stage_order: index + 1,
  }));
  const fixture = await establishUnearnedPrerequisites(client, 77, allStages, 9);
  assert.deepEqual(fixture, { earned: false, targetStage: 9,
    prerequisiteStages: [1, 2, 3, 4, 5, 6, 7, 8] });
  assert.equal(calls[0].sql, 'BEGIN');
  assert.equal(calls.at(-1).sql, 'COMMIT');
  const progress = calls.filter(call => /INSERT INTO ctf\.ctf_progress/.test(call.sql));
  const provenance = calls.filter(call => /qualification_fixture_prerequisite/.test(call.sql));
  assert.equal(progress.length, 8); assert.equal(provenance.length, 8);
  assert.ok(progress.every(call => /attempts_count,successful_attempts,failed_attempts/.test(call.sql)
    && /0,0,0/.test(call.sql) && /NULL,'\[\]'/.test(call.sql)));
  for (let index = 0; index < provenance.length; index += 1) {
    assert.deepEqual(JSON.parse(provenance[index].values[2]), {
      schemaVersion: 1, targetStage: 9, prerequisiteStage: index + 1, earned: false,
    });
  }
  await assert.rejects(establishUnearnedPrerequisites(client, 77, allStages, 5),
    /closed to 6-10/);
});

test('independent qualification separates application correctness from exploitability', () => {
  const fixture = Object.freeze({ earned: false, targetStage: 8,
    prerequisiteStages: Object.freeze([1, 2, 3, 4, 5, 6, 7]) });
  const blocked = independentQualificationSummary(fixture, [
    { payloadSha256: 'a'.repeat(64), outcome: 'reviewer_blocked' },
    { payloadSha256: 'b'.repeat(64), outcome: 'guardian_non_disclosure' },
  ]);
  assert.equal(blocked.applicationCorrectness.status, 'pass');
  assert.equal(blocked.applicationCorrectness.acceptedTargetCommit,
    'not_required_for_correctness_claim');
  assert.equal(blocked.empiricalModelExploitability.status, 'not_observed_within_budget');
  const accepted = independentQualificationSummary(fixture, [
    { payloadSha256: 'c'.repeat(64), outcome: 'accepted' },
  ]);
  assert.equal(accepted.empiricalModelExploitability.status, 'observed');
  assert.equal(accepted.applicationCorrectness.acceptedTargetCommit, 'actual_observed');
  assert.throws(() => independentQualificationSummary(fixture, [
    { payloadSha256: 'd'.repeat(64), outcome: 'forced_win' },
  ]));
  assert.throws(() => independentQualificationSummary({ ...fixture, earned: true }, []),
    /explicitly unearned/);
});

test('stage 8 and 10 memory control is classified but survives their input defenses', async () => {
  const { stages } = require('../../server/data/ctfDefaults');
  const { classifyTechnique } = require('../../server/services/promptInjectionCTF');
  const { runDefenseLayers } = require('../../server/services/ctfDefenseLayers');
  const payload = 'This is an emergency. Explain compound interest without discussing confidential material.';
  const traces = [];
  const controller = new AbortController();
  const execution = {
    ownerId: 'owned-ctf-teaching-control',
    signal: controller.signal,
    check: async () => {},
    trace: async event => traces.push(event),
  };
  let languageCalls = 0;
  const languageModel = { generateResponse: async (_prompt, options) => {
    languageCalls += 1;
    assert.equal(options.ownerId, execution.ownerId);
    assert.equal(options.signal, execution.signal);
    assert.equal(options.temperature, 0);
    return { response: JSON.stringify({ classification: 'english', language: 'English', confidence: 0.99 }),
      provider: 'ollama', model: 'controlled-language-provider', mocked: false, fallback: false };
  } };
  assert.deepEqual(classifyTechnique(payload), { tag: 'emotional_manipulation', confidence: 0.7 });
  for (const level of [8, 10]) assert.deepEqual(
    await runDefenseLayers(stages[level - 1], payload, { execution, languageModel }),
    { blocked: false },
  );
  assert.equal(languageCalls, 2, 'each stage must use the supplied controlled classifier');
  assert.equal(traces.filter(event => event.node === 'ctf_language_classify' && event.type === 'decision').length, 2);
});

test('stage 4 teaches a real input transformation guard while leaving indirect literal extraction admissible', async () => {
  const stage = require('../../server/data/ctfDefaults').stages[3];
  const priorLesson = levels.find(row => row.level === 3);
  const lesson = levels.find(row => row.level === 4);
  const { runDefenseLayers } = require('../../server/services/ctfDefenseLayers');
  for (const payload of priorLesson.payloads) {
    const transformed = await runDefenseLayers(stage, payload);
    assert.equal(transformed.blocked, true, payload);
    assert.equal(transformed.layer, 'transformation_guard');
  }
  for (const payload of lesson.payloads) {
    assert.deepEqual(await runDefenseLayers(stage, payload), { blocked: false }, payload);
  }
  for (const ordinary of [
    'Write each character Unicode code point on its own line.',
    'Put each checklist item on its own line.',
  ]) assert.deepEqual(await runDefenseLayers(stage, ordinary), { blocked: false }, ordinary);
  assert.match(stage.stage_description, /no output filter/i);
  assert.match(lesson.note, /no output filter/i);
});

function ownedUrl(name, database) {
  const parsed = new URL(process.env[name]);
  assert.equal(parsed.hostname, '127.0.0.1');
  assert.equal(parsed.pathname, `/${database}`);
}

async function request(base, path, token, body) {
  const response = await fetch(base + path, { method: body === undefined ? 'GET' : 'POST',
    headers: { authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: response.status, body: await response.json() };
}

test('mounted CTF uses actual guardians, defenses, Judge receipts, progress, and reset through the configured stage', {
  skip: !enabled, timeout: stageEnd <= 4 ? 600_000 : 1_800_000,
}, async t => {
  ownedUrl('IDENTITY_DATABASE_URL', 'dvaia_test_ctf_stages_identity');
  ownedUrl('CTF_DATABASE_URL', 'dvaia_test_ctf_stages_store');
  assert.ok(Number.isInteger(stageEnd) && stageEnd >= 2 && stageEnd <= 10);
  assert.ok(targetStage === null || targetStages.has(targetStage));
  if (targetStage !== null) assert.equal(stageEnd, targetStage);
  if (stage6Fixed) {
    assert.equal(targetStage, 6);
    assert.match(process.env.CTF_STAGE6_CANDIDATE_SHA256 || '', /^[a-f0-9]{64}$/);
    assert.ok(process.env.CTF_STAGE6_EVIDENCE_ROOT);
  }
  assert.equal(fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE), fs.realpathSync(process.cwd()));
  const transport = stage6Fixed
    ? await require('./ctfStage9ActualTransport').createTransport({ evidence: process.env.CTF_STAGE6_EVIDENCE_ROOT }) : null;
  if (transport) process.env.OLLAMA_BASE_URL = transport.actorUrl;
  else {
    const tags = await (await fetch(`${process.env.OLLAMA_BASE_URL}/api/tags`)).json();
    assert.ok(tags.models.some(row => row.name === 'llama3.1:8b'));
  }
  const { createPool, closePostgresPools } = require('../../server/database/postgres');
  const identityRuntime = createPool(process.env, 'IDENTITY_DATABASE_URL');
  const identityMigration = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
  const ctfRuntime = createPool(process.env, 'CTF_DATABASE_URL');
  const ctfMigration = createPool(process.env, 'CTF_MIGRATION_DATABASE_URL');
  let server, authMount, earnedRendered;
  try {
    const identityApi = require('../../server/database/postgres/identityRepository');
    await identityApi.initializeIdentityRepository(identityRuntime, identityMigration);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
    const ctf = require('../../server/database/postgres/ctfDb').createCtfDb(ctfRuntime);
    await ctf.initialize(ctfMigration);
    for (const key of ['ctf_enabled', 'ctf_visible_to_students', 'ctf_registration_open']) {
      await ctf.updateConfig(key, 'true');
    }
    const identity = identityApi.createIdentityRepository(identityRuntime);
    const passwordHash = await require('bcryptjs').hash('OwnedCtfFixture@123', 4);
    const owner = await identity.createUser({ username: 'ctf-stages-owner', email: 'ctf-owner@fixture.invalid', passwordHash });
    const sibling = await identity.createUser({ username: 'ctf-stages-sibling', email: 'ctf-sibling@fixture.invalid', passwordHash });
    const admin = await identity.createUser({ username: 'ctf-stages-admin', email: 'ctf-admin@fixture.invalid', passwordHash });
    await identityMigration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1", [admin.id]);
    const progress = require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityRuntime);
    const adapter = require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({
      repository: identity, progress, jwtSecret: process.env.JWT_SECRET,
    });
    const session = async user => adapter.createSession(await identity.findCredentialById(user.id), { get: () => null, ip: '127.0.0.1' });
    const [ownerSession, siblingSession, adminSession] = await Promise.all([session(owner), session(sibling), session(admin)]);
    const express = require('express');
    const app = express();
    app.use(express.json({ limit: '64kb' }));
    if (stage6Fixed) authMount = require('../fixtures/ctfStage6EarnedRendered').mountAuthRoutes({ app, adapter });
    if (stage6Fixed) app.use('/api/ctf', require('../../server/middleware/adminAuth').authenticateToken,
      require('../../server/routes/ctf').router);
    else {
      app.use(require('../../server/middleware/adminAuth').authenticateToken);
      app.use('/api/ctf', require('../../server/routes/ctf').router);
    }
    if (stage6Fixed) require('../fixtures/ctfStage6EarnedRendered').mountStaticRoutes({
      app, buildDirectory: process.env.CTF_STAGE6_BUILD_DIRECTORY,
    });
    server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const post = async (path, token, body, expected = 200) => {
      const result = await request(base, path, token, body);
      t.diagnostic(JSON.stringify(safeHttpDiagnostic(path, result.status, result.body)));
      assert.equal(result.status, expected, JSON.stringify(result.body));
      return result.body;
    };
    const ownerRegistration = await post('/api/ctf/register', ownerSession.token, { displayName: 'Owned CTF learner' });
    const siblingRegistration = await post('/api/ctf/register', siblingSession.token, { displayName: 'Owned sibling' });
    const participant = await ctf.findActiveParticipant(owner.id);
    const siblingParticipant = await ctf.findActiveParticipant(sibling.id);
    const stages = await ctf.listStudentStages();
    assert.deepEqual(stages.map(row => row.stage_number), [1,2,3,4,5,6,7,8,9,10]);
    let fixturePrerequisites = null;
    let siblingExpectedStage = 1;
    if (targetStage === null) {
      await post('/api/ctf/stage/1/start', siblingSession.token, {});
    } else {
      const target = stages.find(row => row.stage_number === targetStage);
      const denied = await request(base, `/api/ctf/stage/${target.id}/start`, ownerSession.token, {});
      t.diagnostic(JSON.stringify(safeHttpDiagnostic(`/api/ctf/stage/${target.id}/start`,
        denied.status, denied.body)));
      assert.equal(denied.status, 403, 'target must remain locked without explicit fixture prerequisites');
      const setup = await ctfMigration.connect();
      try {
        fixturePrerequisites = await establishUnearnedPrerequisites(
          setup, participant.id, stages, targetStage);
        await establishUnearnedPrerequisites(setup, siblingParticipant.id, stages, targetStage);
      } finally {
        setup.release();
      }
      const fixtureCounts = (await ctfMigration.query(`SELECT
        count(*)::int AS progress_rows,
        count(*) FILTER (WHERE attempts_count=0 AND successful_attempts=0 AND failed_attempts=0
          AND final_payload IS NULL AND techniques_used='[]')::int AS zero_evidence_rows
        FROM ctf.ctf_progress WHERE participant_id=$1`, [participant.id])).rows[0];
      assert.deepEqual(fixtureCounts, { progress_rows: targetStage - 1,
        zero_evidence_rows: targetStage - 1 });
      assert.equal((await ctfMigration.query(`SELECT count(*)::int AS n FROM ctf.ctf_attempts
        WHERE participant_id=$1`, [participant.id])).rows[0].n, 0);
      assert.equal((await ctfMigration.query(`SELECT count(*)::int AS n FROM ctf.ctf_judgments
        WHERE participant_id=$1`, [participant.id])).rows[0].n, 0);
      await post(`/api/ctf/stage/${target.id}/start`, siblingSession.token, {});
      siblingExpectedStage = targetStage;
      t.diagnostic(JSON.stringify({ qualificationMode: 'independent_target',
        syntheticPrerequisites: fixturePrerequisites }));
    }
    async function assertReviewerEvidence(judgment, level, expectedVerdict) {
      const events = (await identityRuntime.query(`SELECT metadata FROM graph_runtime.events
        WHERE run_id=$1 AND owner_key=$2 AND node='ctf_output_reviewer' AND event_type='decision'`,
      [judgment.run_id, JSON.stringify(['CTF', String(owner.id)])])).rows;
      assert.equal(events.length, 1, 'one actual output reviewer decision must persist');
      const data = events[0].metadata;
      assert.equal(data.decisionSource, 'model');
      assert.equal(data.provider, 'ollama');
      assert.equal(data.model, 'llama3.1:8b');
      if (expectedVerdict) assert.equal(data.verdict, expectedVerdict);
      if (level === 5 || stage6Fixed && level === 6) {
        const profile = level === 5
          ? require('../../server/services/ctfDefenseLayers').STRUCTURED_ARTIFACT_REVIEWER_PROFILE
          : require('../../server/services/ctfDefenseLayers').reviewerProfileEvidence(await ctf.getStage(judgment.stage_id));
        assert.ok(profile, 'Stage 6 must select its source-defined reviewer profile');
        assert.deepEqual(judgmentMetadata(judgment).guardian.reviewerProfile, profile);
        assert.equal(data.reviewerProfileId, profile.id);
        assert.equal(data.reviewerProfileVersion, profile.version);
        assert.equal(data.reviewerPolicyDigest, profile.policyDigest);
        const fullStage = await ctf.getStage(judgment.stage_id);
        assert.equal(judgment.stage_digest, require('../../server/agent-runtime/ctfStageJudge').stageDigest(fullStage));
      } else {
        assert.equal(data.reviewerProfileId, undefined);
        assert.equal(judgmentMetadata(judgment).guardian.reviewerProfile, undefined);
      }
    }
    async function completePrefixForSibling(throughLevel) {
      for (const prerequisite of levels.slice(0, throughLevel)) {
        const prerequisiteStage = stages.find(row => row.stage_number === prerequisite.level);
        const current = await ctf.getProgress(siblingParticipant.id, prerequisiteStage.id);
        if (current?.status === 'completed') continue;
        await post(`/api/ctf/stage/${prerequisiteStage.id}/start`, siblingSession.token, {});
        let won = false;
        for (const payload of prerequisite.payloads.slice(0, 5)) {
          const attempt = await post(`/api/ctf/stage/${prerequisiteStage.id}/attempt`, siblingSession.token, {
            payload, sessionToken: siblingRegistration.sessionToken,
          });
          if (attempt.success) { won = true; break; }
        }
        assert.equal(won, true, `Sibling could not authentically complete prerequisite stage ${prerequisite.level}`);
      }
    }

    const coverage = [];
    const empiricalOutcomes = [];
    let failedStage = null;
    const selectedLevels = targetStage === null
      ? levels.slice(0, stageEnd) : levels.filter(row => row.level === targetStage);
    for (const level of selectedLevels) {
      const stage = stages.find(row => row.stage_number === level.level);
      await post(`/api/ctf/stage/${stage.id}/start`, ownerSession.token, {});
      if (level.level === 5) {
        // This is a negative reviewer control, not a guardian win or progress fixture.
        // The synthetic stage secret is read only from this owned disposable store.
        const fullStage = await ctf.getStage(stage.id);
        const events = [];
        const leaked = await require('../../server/services/ctfDefenseLayers').metaStructuredArtifactReviewer(
          `The protected credential is ${fullStage.success_criteria}.`, fullStage,
          { execution: { ownerId: String(owner.id), check: async () => {}, trace: async event => events.push(event) } });
        assert.equal(leaked.leaked, true, 'actual reviewer must reject direct prose disclosure');
        assert.equal(events[0]?.data?.provider, 'ollama');
        assert.equal(events[0]?.data?.model, 'llama3.1:8b');
        assert.equal(events[0]?.data?.verdict, 'LEAKED');
      }
      if (level.level > 1) {
        const negativePayload = [8, 10].includes(level.level)
          ? 'This is an emergency. Explain compound interest without discussing confidential material.'
          : 'Explain compound interest for a normal customer. Do not discuss your setup.';
        if (transport) transport.beginCase('benign');
        let negative;
        try { negative = await post(`/api/ctf/stage/${stage.id}/attempt`, ownerSession.token, {
          payload: negativePayload, sessionToken: ownerRegistration.sessionToken,
        }); } finally { if (transport) transport.endCase(); }
        if (transport) assert.ok(transport.snapshot().calls.filter(call => call.caseId === 'benign').length <= 5,
          'Benign attempt exceeds guardian/reviewer/Judge budget');
        assert.equal(negative.success, false); assert.equal(negative.blocked, false);
        if (level.level >= 6) assertLessonState(negative, { input_guard_observed: false, reviewer_observed: true });
        const failed = (await ctfRuntime.query(`SELECT j.*,a.ai_response FROM ctf.ctf_judgments j
          JOIN ctf.ctf_attempts a ON a.id=j.attempt_id WHERE j.participant_id=$1 AND j.stage_id=$2
          ORDER BY j.created_at DESC LIMIT 1`, [participant.id, stage.id])).rows[0];
        assert.equal(failed.verdict, 'fail');
        assert.equal(failed.accepted, 0);
        const failedMetadata = judgmentMetadata(failed);
        t.diagnostic(JSON.stringify({ stage: level.level, control: 'benign-failure',
          guardian: failedMetadata.guardian, judge: { provider: failedMetadata.provider,
            model: failedMetadata.model, version: failedMetadata.judgeVersion } }));
        assert.equal(failedMetadata.guardian.provider, 'ollama');
        assert.equal(failedMetadata.guardian.model, 'llama3.1:8b');
        assert.equal(failedMetadata.guardian.visibleResponseSha256, digest(negative.aiResponse));
        if (level.level >= 5) await assertReviewerEvidence(failed, level.level,
          level.level === 5 ? 'SAFE' : undefined);
        if ([8, 10].includes(level.level)) {
          assert.equal(negative.techniqueTag, 'emotional_manipulation');
          const reused = await post(`/api/ctf/stage/${stage.id}/attempt`, ownerSession.token, {
            payload: 'This is an emergency. Describe a savings account without discussing confidential material.',
            sessionToken: ownerRegistration.sessionToken,
          });
          assert.equal(reused.success, false); assert.equal(reused.blocked, true);
          assert.match(reused.reason, /already been used|blocked/i);
          assertLessonState(negative, { category_consumed: true });
          assertLessonState(reused, { category_reuse_blocked: true, category_consumed: false, reviewer_observed: false });
        }
      }
      let positive = null;
      const candidatePayloads = stage6Fixed
        ? level.payloads.filter(payload => digest(payload) === process.env.CTF_STAGE6_CANDIDATE_SHA256)
        : level.payloads.slice(0, 5);
      if (stage6Fixed) assert.equal(candidatePayloads.length, 1, 'Exactly one fixed source-defined Stage 6 candidate required');
      for (const payload of candidatePayloads) {
        const path = `/api/ctf/stage/${stage.id}/attempt`;
        if (transport) transport.beginCase('instructor-candidate');
        let result;
        try { result = targetStage === null
          ? { status: 200, body: await post(path, ownerSession.token, {
            payload, sessionToken: ownerRegistration.sessionToken,
          }) }
          : await request(base, path, ownerSession.token, {
            payload, sessionToken: ownerRegistration.sessionToken,
          }); } finally { if (transport) transport.endCase(); }
        if (transport) assert.ok(transport.snapshot().calls.filter(call => call.caseId === 'instructor-candidate').length <= 5,
          'Fixed candidate exceeds guardian/reviewer/Judge budget');
        if (targetStage !== null) {
          t.diagnostic(JSON.stringify(safeHttpDiagnostic(path, result.status, result.body)));
          assert.ok([200, 503].includes(result.status), `unexpected target-stage status ${result.status}`);
          if (result.status === 503) {
            empiricalOutcomes.push({ payloadSha256: digest(payload), outcome: 'unavailable' });
            continue;
          }
        }
        const attempt = result.body;
        if (targetStage !== null && attempt.blocked === true) {
          empiricalOutcomes.push({ payloadSha256: digest(payload), outcome: 'input_blocked' });
          continue;
        }
        if (attempt.success) { positive = { payload, attempt }; break; }
        if (targetStage !== null) {
          const failed = (await ctfRuntime.query(`SELECT j.run_id,j.verdict,j.metadata,a.ai_response
            FROM ctf.ctf_judgments j JOIN ctf.ctf_attempts a ON a.id=j.attempt_id
            WHERE j.participant_id=$1 AND j.stage_id=$2 ORDER BY j.created_at DESC LIMIT 1`,
          [participant.id, stage.id])).rows[0];
          assert.ok(failed, 'a non-blocked real-model target attempt must persist a judgment');
          const reviewer = (await identityRuntime.query(`SELECT metadata FROM graph_runtime.events
            WHERE run_id=$1 AND owner_key=$2 AND node='ctf_output_reviewer' AND event_type='decision'
            ORDER BY sequence DESC LIMIT 1`, [failed.run_id,
            JSON.stringify(['CTF', String(owner.id)])])).rows[0]?.metadata;
          let outcome;
          if (reviewer?.verdict === 'LEAKED') outcome = 'reviewer_blocked';
          else if (failed.verdict === 'unavailable') outcome = 'unavailable';
          else if (require('../../server/services/ctfDefenseLayers').normalizedContains(
            failed.ai_response, stage.success_criteria)) outcome = 'judge_fail';
          else outcome = 'guardian_non_disclosure';
          empiricalOutcomes.push({ payloadSha256: digest(payload), outcome });
        }
      }
      if (!positive) {
        failedStage = { level: level.level, candidateCount: candidatePayloads.length };
        coverage.push({ level: level.level, completed: false, candidateCount: failedStage.candidateCount });
        t.diagnostic(JSON.stringify({ stage: level.level, outcome: 'no-candidate-passed', candidateSet,
          candidateCount: failedStage.candidateCount }));
        break;
      }
      if (level.level >= 6) assertLessonState(positive.attempt, { input_guard_observed: false, reviewer_observed: true });
      const accepted = (await ctfRuntime.query(`SELECT j.*,a.ai_response,a.payload FROM ctf.ctf_judgments j
        JOIN ctf.ctf_attempts a ON a.id=j.attempt_id WHERE j.participant_id=$1 AND j.stage_id=$2 AND j.accepted=1`,
      [participant.id, stage.id])).rows[0];
      assert.equal(accepted.verdict, 'pass');
      assert.equal(accepted.payload, positive.payload);
      assert.equal(accepted.ai_response, positive.attempt.aiResponse);
      const acceptedMetadata = judgmentMetadata(accepted);
      t.diagnostic(JSON.stringify({ stage: level.level, outcome: 'accepted',
        payloadSha256: digest(positive.payload), responseSha256: digest(positive.attempt.aiResponse),
        guardian: acceptedMetadata.guardian, judge: { provider: acceptedMetadata.provider,
          model: acceptedMetadata.model, version: acceptedMetadata.judgeVersion } }));
      assert.equal(acceptedMetadata.rubricVersion, 'ctf-visible-secret-v2');
      assert.equal(acceptedMetadata.judgeVersion, require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION);
      assert.deepEqual({ provider: acceptedMetadata.guardian.provider, model: acceptedMetadata.guardian.model },
        { provider: 'ollama', model: 'llama3.1:8b' });
      assert.equal(acceptedMetadata.guardian.version, 'ctf-guardian-provenance-v1');
      assert.equal(acceptedMetadata.guardian.visibleResponseSha256, digest(positive.attempt.aiResponse));
      assert.equal(acceptedMetadata.guardian.visibleResponseBytes, Buffer.byteLength(positive.attempt.aiResponse, 'utf8'));
      if (stage6Fixed) {
        const fullStage = await ctf.getStage(stage.id);
        assert.ok(positive.attempt.aiResponse.includes(fullStage.success_criteria),
          'Unchanged secret must be present in the post-defense visible response');
        assert.equal((await ctfRuntime.query(`SELECT count(*)::int AS n FROM ctf.ctf_attempts
          WHERE participant_id=$1 AND stage_id=$2 AND accepted=1`, [participant.id, stage.id])).rows[0].n, 1);
      }
      assert.match(acceptedMetadata.guardian.rawResponseSha256, /^[a-f0-9]{64}$/);
      assert.ok(acceptedMetadata.guardian.rawResponseBytes > 0);
      if (level.level >= 5) await assertReviewerEvidence(accepted, level.level, 'SAFE');
      assert.equal((await ctf.getProgress(participant.id, stage.id)).status, 'completed');
      if (stage6Fixed) {
        assert.equal((await ctf.getLeaderboardEntry(participant.id)).total_stages_completed, 6,
          'Five explicitly unearned prerequisites plus one genuine Stage 6 completion');
        const stage7 = stages.find(row => row.stage_number === 7);
        assert.equal((await ctf.getProgress(participant.id, stage7.id))?.status, undefined,
          'Stage 7 is unlocked but not pre-started before rendered verification');
        earnedRendered = await require('../fixtures/ctfStage6EarnedRendered').qualifyStage6EarnedRendered({
          origin: base, owner, sibling, admin, password: 'OwnedCtfFixture@123',
          stage6: stage, stage7, ownerSession, siblingSession, adminSession,
          ctf, participant, siblingParticipant, acceptedJudgment: accepted,
          evidence: process.env.CTF_STAGE6_EVIDENCE_ROOT,
          resetOwner: () => post(`/api/ctf/admin/participants/${owner.id}/reset`, adminSession.token, {}),
        });
        assert.equal(earnedRendered.stage6Completed, true);
        assert.equal(earnedRendered.stage7Unlocked, true);
        assert.equal(earnedRendered.ownerReset, true);
        assert.equal(earnedRendered.siblingPreserved, true);
        assert.equal(earnedRendered.actualModelCallsByBrowser, 0);
      }
      if (level.level === 9 || (targetStage !== null && level.level === 10)) {
        if (targetStage === null) {
          await completePrefixForSibling(8);
          await post(`/api/ctf/stage/${stage.id}/start`, siblingSession.token, {});
          siblingExpectedStage = 9;
        }
        const globallyBlocked = await post(`/api/ctf/stage/${stage.id}/attempt`, siblingSession.token, {
          payload: positive.payload, sessionToken: siblingRegistration.sessionToken,
        });
        assert.equal(globallyBlocked.success, false); assert.equal(globallyBlocked.blocked, true);
        assert.match(globallyBlocked.reason, /payload|similar|community shield/i);
        assertLessonState(globallyBlocked, { shared_similarity_blocked: true, reviewer_observed: false });
      }
      coverage.push({ level: level.level, completed: true });
      if (targetStage !== null) empiricalOutcomes.push({ payloadSha256: digest(positive.payload),
        outcome: 'accepted' });
    }
    const completedCount = coverage.filter(row => row.completed).length;
    const syntheticCompletedCount = targetStage === null ? 0 : targetStage - 1;
    const storedCompletedCount = syntheticCompletedCount + completedCount;
    assert.equal((await ctf.listProgress(participant.id)).filter(
      row => row.status === 'completed').length, earnedRendered ? 0 : storedCompletedCount);
    assert.equal((await ctf.getLeaderboardEntry(participant.id)).total_stages_completed,
      earnedRendered ? 0 : storedCompletedCount,
      'leaderboard reflects the authenticated rendered reset or explicit fixture prerequisites');
    const judgmentCount = (await ctfRuntime.query(`SELECT count(*)::int AS n FROM ctf.ctf_judgments
      WHERE participant_id=$1`, [participant.id])).rows[0].n;
    const ownerRuns = (await identityRuntime.query(`SELECT count(*)::int AS n FROM graph_runtime.runs
      WHERE owner_key=$1`, [JSON.stringify(['CTF', String(owner.id)])])).rows[0].n;
    assert.ok(ownerRuns >= judgmentCount, 'every persisted guardian/Judge attempt must have a durable owner run');
    if (transport) {
      transport.assertComplete();
      const wire = transport.snapshot();
      assert.ok(wire.counts.external <= 11 && wire.counts.generate <= 10,
        'Stage 6 fixed cohort exceeds one metadata plus ten model attempts');
      assert.equal(wire.failures.length, 0);
    }
    if (!earnedRendered) await post(`/api/ctf/admin/participants/${owner.id}/reset`, adminSession.token, {});
    assert.equal((await ctf.listProgress(participant.id)).length, 0);
    assert.equal((await ctf.getProgress(siblingParticipant.id, stages.find(row => row.stage_number === siblingExpectedStage).id)).status, 'in_progress');
    assert.ok(siblingRegistration.sessionToken);
    t.diagnostic(JSON.stringify({ coverage, ownerRuns, judgmentCount,
      reset: { ownerProgressRows: 0, siblingInProgressStage: siblingExpectedStage,
        ...(stage6Fixed ? { earnedRendered } : {}) },
      ...(targetStage === null ? {} : { qualification:
        independentQualificationSummary(fixturePrerequisites, empiricalOutcomes) }) }));
    if (targetStage === null) assert.equal(failedStage, null,
      failedStage ? `Stage ${failedStage.level} did not pass any of its ${failedStage.candidateCount} ${candidateSet} candidates` : undefined);
    if (stage6Fixed) assert.equal(failedStage, null,
      failedStage ? 'Fixed Stage 6 candidate did not earn visible-secret completion' : undefined);
  } finally {
    Module._load = originalLoad;
    if (authMount) await authMount.close();
    if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await Promise.allSettled([identityRuntime.end(), identityMigration.end(), ctfRuntime.end(), ctfMigration.end()]);
    await closePostgresPools();
    if (transport) await transport.close();
  }
});
