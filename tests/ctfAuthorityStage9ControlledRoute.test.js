'use strict';

// Controlled HTTP composition coverage only. Prerequisite eligibility and the
// failed attempt below are fixture facts, never PostgreSQL/Judge/model proof.
process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
process.env.WORKSHOP_DATABASE_ENGINE = 'postgres';
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const express = require('express');

// Keep the guard installed during requests, including lazy coordinator imports.
const originalLoad = Module._load;
const forbiddenImports = [];
Module._load = function (name, ...args) {
  if (/sqlite|(?:^|\/)ctfDb(?:\.js)?$|(?:^|\/)(?:authDb|postgresRunLedger|ollamaService|multiProviderAIService)(?:\.js)?$/.test(name)) {
    forbiddenImports.push(name);
    throw new Error('Controlled authority seam cannot import database/provider services');
  }
  return originalLoad.call(this, name, ...args);
};
const { createCtfAuthorityRouter } = require('../server/routes/ctfAuthorityRouter');
const { createCtfAuthorityAttemptRoute } = require('../server/services/ctfAuthorityAttemptRoute');
const { createCtfAuthorityPrepare } = require('../server/services/ctfAuthorityPrepare');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
const { readBearerAuthorization } = require('../server/middleware/bearerToken');
const traces = require('../server/agent-runtime/runTraceStore');

test('mounted authority Stage9 seam preserves canonical scope and explicitly unearned failed flow', async t => {
  t.after(() => { Module._load = originalLoad; });
  const sessions = new Map([
    ['owner-bearer', { user: { id: 7, role: 'student' }, session: { id: 8, user_id: 7 } }],
    ['sibling-bearer', { user: { id: 9, role: 'student' }, session: { id: 10, user_id: 9 } }],
    ['mismatched-bearer', { user: { id: 7 }, session: { id: 11, user_id: 9 } }]
  ]);
  const owners = new Map(['7', '9'].map(ownerId => [ownerId, {
    generation: '0', participantId: ownerId === '7' ? '70' : '90',
    prerequisites: [], progress: null, attempts: [], completions: [], decisions: []
  }]));
  const reads = [], prepared = [], executions = [], attemptRequests = [];
  const coordinator = createRunCoordinator({ family: 'CTF', ledger: null });
  const authenticate = async token => structuredClone(sessions.get(token) ?? null);
  function sessionFor(req) {
    const rawToken = readBearerAuthorization(req).token;
    const current = sessions.get(rawToken);
    assert.equal(String(current?.user.id), String(req.user.id));
    assert.equal(String(current?.session.id), String(req.identitySession.id));
    return { actorId: String(req.user.id), sessionId: String(req.identitySession.id), rawToken };
  }
  const repository = {
    async read(query) {
      reads.push(structuredClone(query));
      assert.equal(query.admin, false);
      assert.equal(query.ownerId, query.session.actorId);
      assert.equal(query.stageId, '9');
      const owner = owners.get(query.ownerId);
      return {
        actor: { username: 'controlled learner', email: null },
        global: { revision: '1' }, config: {}, owner: { generation: owner.generation },
        participant: { participant_id: owner.participantId },
        stage: { authority_revision: '2', stage_number: 9 }, progress: owner.progress
      };
    }
  };
  const prepare = createCtfAuthorityPrepare({ repository });
  // These predicates stand in for repository decisions; they do not test SQL.
  const eligible = owner => owner.prerequisites.length === 8 && owner.prerequisites.every(
    (row, index) => row.stageNumber === index + 1 && row.status === 'completed' && row.earned === false
      && row.source === 'controlled-prerequisite-fixture');
  const denied = () => { throw Object.assign(new Error('Controlled prerequisite denial'), { statusCode: 403 }); };
  const runtime = {
    async read() { return { controlled: true }; },
    async heartbeat() { return { status: 200, body: { success: false } }; },
    async adminSolutions() { assert.fail('No administrator operation in this fixture'); },
    async mutate({ req, kind, input }) {
      assert.equal(kind, 'start');
      const session = sessionFor(req);
      const command = await prepare({ kind, input, session });
      prepared.push(command);
      const owner = owners.get(command.scope.ownerId);
      if (!eligible(owner)) denied();
      owner.progress = { participant_id: owner.participantId, progress_id: '79', stage_id: '9',
        status: 'in_progress', attempts: 0, earned: false };
      return { status: 200, body: { success: false, started: true, stageId: '9' } };
    },
    async attempt({ req, runId, execution, signal, request }) {
      const session = sessionFor(req), owner = owners.get(session.actorId);
      attemptRequests.push(structuredClone(request));
      assert.equal(execution.ownerKey, JSON.stringify(['CTF', session.actorId]));
      assert.equal(runId, execution.runId);
      assert.equal(request.runId, runId);
      assert.equal(signal, execution.signal);
      assert.equal(request.stageId, '9');
      await execution.check();
      if (!eligible(owner) || owner.progress?.status !== 'in_progress') denied();
      executions.push(execution);
      const number = owner.progress.attempts + 1;
      await execution.effect('controlled_failed_attempt', async () => {
        owner.progress.attempts = number;
        owner.attempts.push({ ownerId: session.actorId, sessionId: session.sessionId,
          runId, stageId: request.stageId, payload: request.payload, wasSuccessful: false,
          earned: false, source: 'controlled-failed-attempt-fixture' });
        owner.decisions.push({ runId, verdict: 'fail', currentCompletion: false,
          source: 'controlled-decision-fixture', modelObserved: false });
      });
      await execution.trace({ node: 'controlled_stage9_attempt', type: 'verdict',
        data: { verdict: 'fail', responseSource: 'fixture' } });
      return { status: 200, body: { success: false, attemptNumber: number,
        judgment: { verdict: 'fail' }, currentCompletion: false } };
    }
  };
  for (const method of ['recoverOperation', 'recoverDecision', 'publishDecision', 'publishBlocked',
    'recoverPredefense', 'resumePredefense']) runtime[method] = async () => {
    assert.fail('No recovery/publication service is qualified by this test');
  };
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => {
    // Deliberately forged upstream state must be replaced by canonical bearer auth.
    req.user = { id: 999, role: 'admin', admin_level: 3 };
    req.identitySession = { id: 999, user_id: 999 };
    next();
  });
  app.use('/api/ctf', createCtfAuthorityRouter({ runtime, authenticate,
    attemptHandlers: createCtfAuthorityAttemptRoute({ runtime, coordinator }),
    previewHandler: () => assert.fail('No preview in this fixture'),
    practiceHandler: () => assert.fail('No practice in this fixture') }));
  const server = await new Promise(resolve => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const post = async (suffix, body = {}, authorization = 'Bearer owner-bearer') => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/ctf${suffix}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json',
        ...(authorization === null ? {} : { Authorization: authorization }) },
      body: JSON.stringify(body), signal: AbortSignal.timeout(5000)
    });
    return { status: response.status, body: await response.json() };
  };
  const start = '/stage/9/start', attempt = '/stage/9/attempt';
  for (const bearer of [null, 'Basic owner-bearer', 'Bearer unknown', 'Bearer mismatched-bearer']) {
    assert.equal((await post(start, {}, bearer)).status, 401);
    assert.equal((await post(attempt, { payload: 'controlled failure' }, bearer)).status, 401);
  }
  assert.equal(reads.length, 0);
  assert.equal(attemptRequests.length, 0);
  assert.equal((await post(start, { ownerId: '9' })).status, 400);
  assert.equal((await post(attempt, { payload: 'x', runId: 'forged', judge: { pass: true } })).status, 400);
  assert.equal((await post(start)).status, 403);
  assert.equal((await post(attempt, { payload: 'locked target' })).status, 403);
  assert.equal(owners.get('7').attempts.length, 0);
  const siblingBefore = structuredClone(owners.get('9'));
  const owner = owners.get('7');
  owner.prerequisites = Array.from({ length: 8 }, (_, index) => ({ stageNumber: index + 1,
    status: 'completed', earned: false, source: 'controlled-prerequisite-fixture' }));
  assert.equal(owner.completions.length, 0, 'fixture prerequisites grant no earned credit');
  assert.equal((await post(start)).status, 200);
  assert.deepEqual(prepared.at(-1).scope, { ownerId: '7', participantId: '70', stageId: '9',
    progressId: null, ownerGeneration: '0', globalRevision: '1', stageRevision: '2' });
  assert.deepEqual(reads.at(-1).session, { actorId: '7', sessionId: '8', rawToken: 'owner-bearer' });
  assert.equal((await post(start, {}, 'Bearer sibling-bearer')).status, 403);
  const payload = '  Controlled Stage9 failure\n🌍  ';
  const failed = await post(attempt, { payload, sessionToken: 'synthetic-teaching-locator' });
  assert.deepEqual(failed, { status: 200, body: { success: false, attemptNumber: 1,
    judgment: { verdict: 'fail' }, currentCompletion: false } });
  assert.equal(owner.attempts.length, 1);
  assert.equal(owner.attempts[0].payload, payload);
  assert.equal(owner.attempts[0].ownerId, '7');
  assert.equal(owner.attempts[0].sessionId, '8');
  assert.equal(owner.attempts[0].earned, false);
  assert.equal(owner.progress.status, 'in_progress');
  assert.equal(owner.completions.length, 0);
  assert.equal(owner.decisions[0].modelObserved, false);
  assert.equal(owner.decisions[0].currentCompletion, false);
  assert.deepEqual(attemptRequests.at(-1), { runId: owner.attempts[0].runId, stageId: '9',
    payload, registrationToken: 'synthetic-teaching-locator' });
  const trace = traces.getRun(owner.attempts[0].runId, '["CTF","7"]');
  assert.equal(trace.status, 'completed', 'coordinator completion is not objective completion');
  assert.deepEqual(trace.events.map(event => [event.node, event.type, event.data.verdict]),
    [['controlled_stage9_attempt', 'decision', 'fail']]);
  assert.equal(traces.getRun(owner.attempts[0].runId, '["CTF","9"]'), null);
  const failedEvidence = structuredClone({ attempts: owner.attempts, decisions: owner.decisions });
  await coordinator.reset('7', async execution => {
    assert.equal(execution.ownerKey, '["CTF","7"]');
    owner.generation = String(execution.generation);
    owner.prerequisites = [];
    owner.progress = null;
  });
  await assert.rejects(executions[0].check(), { name: 'AbortError' });
  assert.equal((await post(attempt, { payload: 'after reset' })).status, 403);
  assert.equal((await post(start)).status, 403);
  assert.equal(prepared.at(-1).scope.ownerGeneration, '1');
  sessions.delete('owner-bearer');
  const readsBeforeRevocation = reads.length, attemptsBeforeRevocation = attemptRequests.length;
  assert.equal((await post(start)).status, 401);
  assert.equal((await post(attempt, { payload: 'after revocation' })).status, 401);
  assert.equal(reads.length, readsBeforeRevocation);
  assert.equal(attemptRequests.length, attemptsBeforeRevocation);
  assert.deepEqual({ attempts: owner.attempts, decisions: owner.decisions }, failedEvidence);
  assert.deepEqual(owners.get('9'), siblingBefore);
  assert.deepEqual(forbiddenImports, []);
});
