'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createCtfAuthorityRouter } = require('../server/routes/ctfAuthorityRouter');
const { createCtfAuthorityAttemptRoute } = require('../server/services/ctfAuthorityAttemptRoute');
const { createCtfAuthorityPrepare } = require('../server/services/ctfAuthorityPrepare');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');

test('supported Stage 9 authority path scopes unearned fixture admission and keeps failed attempts uncredited', async t => {
  // This repository stands in for owned disposable-store snapshots. Its eight
  // prerequisite rows are fixture data, never earned learner progress.
  const owners = new Map([
    ['7', { participantId: '70', completed: new Set(), attempts: [], credit: new Set() }],
    ['9', { participantId: '90', completed: new Set(), attempts: [], credit: new Set() }],
  ]);
  const sessions = new Map([
    ['owner-token', { user: { id: 7, role: 'student' }, session: { id: 71, user_id: 7 } }],
    ['sibling-token', { user: { id: 9, role: 'student' }, session: { id: 91, user_id: 9 } }],
  ]);
  const reads = [];
  const repository = {
    async read({ session, ownerId, stageId, admin }) {
      assert.equal(admin, false);
      assert.equal(ownerId, session.actorId);
      assert.equal(stageId, '9');
      assert(sessions.has(session.rawToken));
      const owner = owners.get(ownerId);
      assert(owner);
      reads.push({ actorId: session.actorId, sessionId: session.sessionId, ownerId, stageId });
      return {
        actor: { id: ownerId, username: 'controlled-' + ownerId, email: null },
        global: { revision: '1' }, config: {}, owner: { generation: '0' },
        participant: { participant_id: owner.participantId },
        stage: { authority_revision: '1' }, progress: null,
      };
    },
  };
  const prepare = createCtfAuthorityPrepare({ repository });
  const prerequisiteCount = owner => [...Array(8)].filter((_, index) => owner.completed.has(index + 1)).length;
  const current = req => {
    const token = req.headers.authorization?.replace(/^Bearer /, '');
    const identity = sessions.get(token);
    if (!identity || identity.user.id !== req.user?.id || identity.session.id !== req.identitySession?.id) {
      throw Object.assign(Error('Session revoked'), { statusCode: 401, code: 'SESSION_REVOKED' });
    }
    return { token, owner: owners.get(String(identity.user.id)) };
  };
  const runtime = {
    async mutate({ req, kind, input }) {
      assert.equal(kind, 'start');
      const { token, owner } = current(req);
      const command = await prepare({ kind, input, session: {
        actorId: String(req.user.id), sessionId: String(req.identitySession.id), rawToken: token,
      } });
      assert.equal(command.scope.ownerId, String(req.user.id));
      assert.equal(command.scope.participantId, owner.participantId);
      assert.equal(command.scope.stageId, '9');
      if (prerequisiteCount(owner) !== 8) return { status: 403, body: { error: 'Stage locked' } };
      return { status: 200, body: { stage: { id: 9 }, fixturePrerequisitesEarned: false } };
    },
    async attempt({ req, request, execution }) {
      const { owner } = current(req);
      assert.equal(request.stageId, '9');
      assert.equal(request.runId, execution.runId);
      assert.equal(execution.ownerKey, `["CTF","${req.user.id}"]`);
      if (prerequisiteCount(owner) !== 8) return { status: 403, body: { error: 'Stage locked' } };
      owner.attempts.push({ stageId: 9, payload: request.payload, verdict: 'fail', awarded: false });
      return { status: 200, body: { success: false, judgment: { verdict: 'fail' }, attemptNumber: owner.attempts.length } };
    },
    async read() { return { stages: [] }; },
    async heartbeat() { return { status: 200, body: { success: true } }; },
    async adminSolutions() { return {}; },
  };
  for (const name of ['recoverOperation', 'recoverDecision', 'publishDecision', 'publishBlocked', 'recoverPredefense', 'resumePredefense']) {
    runtime[name] = async () => { throw Error('No recovery expected'); };
  }
  const attempts = createCtfAuthorityAttemptRoute({ runtime, coordinator: createRunCoordinator({ family: 'CTF', ledger: null }) });
  const router = createCtfAuthorityRouter({
    runtime, attemptHandlers: attempts,
    authenticate: async token => sessions.get(token) ?? (() => { throw Object.assign(Error('Invalid session'), { statusCode: 401 }); })(),
    previewHandler: (_req, res) => res.status(503).json({ error: 'No preview' }),
    practiceHandler: (_req, res) => res.status(503).json({ error: 'No practice' }),
  });
  const app = express();
  app.use(express.json());
  app.use('/api/ctf', router);
  const server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const post = async (path, token, body) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/ctf${path}`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  };

  assert.equal((await post('/stage/9/start', null, {})).status, 401);
  assert.equal((await post('/stage/9/start', 'owner-token', { ownerId: '9' })).status, 400);
  assert.equal((await post('/stage/9/start', 'owner-token', {})).status, 403);
  assert.equal((await post('/stage/9/attempt', 'owner-token', { payload: 'ordinary attempt' })).status, 403);
  assert.equal(owners.get('7').attempts.length, 0);

  for (let stage = 1; stage <= 8; stage++) owners.get('7').completed.add(stage);
  const started = await post('/stage/9/start', 'owner-token', {});
  assert.equal(started.status, 200);
  assert.equal(started.body.fixturePrerequisitesEarned, false);
  assert.equal((await post('/stage/9/start', 'sibling-token', {})).status, 403);
  assert.equal((await post('/stage/9/attempt', 'sibling-token', { payload: 'ordinary attempt' })).status, 403);
  const failed = await post('/stage/9/attempt', 'owner-token', { payload: 'ordinary attempt' });
  assert.equal(failed.status, 200);
  assert.deepEqual(failed.body, { success: false, judgment: { verdict: 'fail' }, attemptNumber: 1 });
  assert.deepEqual(owners.get('7').attempts, [{ stageId: 9, payload: 'ordinary attempt', verdict: 'fail', awarded: false }]);
  assert.equal(owners.get('7').credit.size, 0);
  assert.equal(owners.get('9').attempts.length, 0);
  assert.equal(owners.get('9').credit.size, 0);
  assert(reads.every(row => row.actorId === row.ownerId && row.stageId === '9'));

  sessions.delete('owner-token');
  assert.equal((await post('/stage/9/start', 'owner-token', {})).status, 401);
  assert.equal((await post('/stage/9/attempt', 'owner-token', { payload: 'another attempt' })).status, 401);
  assert.equal(owners.get('7').attempts.length, 1);
});
