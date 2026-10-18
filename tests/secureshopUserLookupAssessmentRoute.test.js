'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const express = require('express');
const { createBoundRoleChatRouter } = require('../server/routes/secureshop/boundRoleChat');

const bearer = 'm'.repeat(43);
const scope = Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 2,
  platformOwnerId: 71, platformSessionId: 72 });
const personaSession = Object.freeze({ sessionId: randomUUID(), authorityVersion: '2' });
const ids = Object.freeze({ sessionId: randomUUID(), requestId: randomUUID() });

async function fixture(t, assessment) {
  const calls = [], reads = [];
  let role = 'admin', available = true;
  const saved = Object.freeze({ status: 'completed', privateTrace: 'must stay on server' });
  const runtime = Object.fromEntries(['createSession', 'run', 'confirmUserAdministration',
    'confirmPolicy', 'confirmMcpRegistry', 'confirmSystemRestart', 'confirmAcl',
    'runAuditJob', 'readAuditJob', 'readAuditOperation', 'readSystemConfigOperation']
    .map(name => [name, async () => assert.fail(`Assessment route called ${name}`)]));
  runtime.readRequest = async (...args) => { reads.push(args); return saved; };
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', createBoundRoleChatRouter({ role: 'admin', runtime,
    userLookupAssessment: assessment && {
      async runAttempt(input) { calls.push(['runAttempt', input]); return assessment.runAttempt(input); },
      async readOutcome(input) { calls.push(['readOutcome', input]); return assessment.readOutcome(input); },
    },
    launches: { async resolveCapability(value) { return available && value === bearer ? scope : null; } },
    authenticatePersona(request, response, next) {
      if (request.get('authorization') !== 'Bearer admin-71')
        return response.status(401).json({ error: 'Authentication required' });
      request.ssUser = { id: 71, role }; request.ssPersonaSession = personaSession; next();
    },
  }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { base: `http://127.0.0.1:${server.address().port}/api/secureshop/agents/admin/assistant`,
    calls, reads, saved, setRole(value) { role = value; }, setAvailable(value) { available = value; } };
}

const headers = () => ({ authorization: 'Bearer admin-71',
  'x-dvaia-secureshop-launch': bearer, 'content-type': 'application/json' });
const post = (base, body, suffix = '', supplied = headers()) =>
  fetch(`${base}/user-lookup/assess${suffix}`, { method: 'POST', headers: supplied,
    body: JSON.stringify(body) });
const get = (base, value = ids, suffix = '') => fetch(`${base}/sessions/${value.sessionId}`
  + `/requests/${value.requestId}/user-lookup/assessment${suffix}`,
{ headers: headers() });

test('User lookup assessment uses current admin authority, protected original read and closed output', async t => {
  const evaluationId = randomUUID();
  const f = await fixture(t, {
    async runAttempt(input) {
      assert.deepEqual(await input.verifyOriginal(), f.saved);
      return { completed: true, judgment: { evaluationId, verdict: 'pass', canRetry: false,
        privateEvidence: 'must not cross' }, replayed: false };
    },
    async readOutcome(input) {
      assert.deepEqual(await input.verifyOriginal(), f.saved);
      return { completed: true, judgment: { evaluationId, verdict: 'pass', canRetry: false,
        privateEvidence: 'must not cross' }, replayed: true };
    },
  });
  const upper = Object.fromEntries(Object.entries(ids).map(([key, value]) => [key, value.toUpperCase()]));
  const response = await post(f.base, upper);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await response.json(), { completed: true, judgment: {
    evaluationId, verdict: 'pass', canRetry: false }, replayed: false });
  const read = await get(f.base, upper);
  assert.equal(read.status, 200);
  assert.deepEqual(await read.json(), { completed: true, judgment: {
    evaluationId, verdict: 'pass', canRetry: false }, replayed: true });
  assert.deepEqual(f.calls.map(([method]) => method), ['runAttempt', 'readOutcome']);
  for (const [, input] of f.calls) {
    assert.deepEqual(input.scope, scope);
    assert.deepEqual(input.persona, { id: 71, role: 'admin' });
    assert.deepEqual(input.personaSession, personaSession);
    assert.deepEqual([input.sessionId, input.requestId],
      [ids.sessionId, ids.requestId]);
    assert.ok(input.signal instanceof AbortSignal);
  }
  assert.equal(f.reads.length, 2);
  for (const args of f.reads) assert.deepEqual(args,
    [scope, { id: 71, role: 'admin' }, personaSession, ids.sessionId, ids.requestId]);
});

test('User lookup assessment rejects client scope and unavailable or malformed results', async t => {
  const f = await fixture(t, {
    async runAttempt() { return { completed: false, status: 'unconfirmed', modelEvaluated: false }; },
    async readOutcome() { return { completed: false, status: 'pending', modelEvaluated: false }; },
  });
  assert.deepEqual(await (await post(f.base, ids)).json(),
    { completed: false, status: 'unconfirmed', modelEvaluated: false });
  assert.deepEqual(await (await get(f.base)).json(),
    { completed: false, status: 'pending', modelEvaluated: false });
  const prior = f.calls.length;
  for (const body of [{ ...ids, role: 'admin' }, { ...ids, requestId: 'bad' },
    { sessionId: ids.sessionId }])
    assert.equal((await post(f.base, body)).status, 400);
  assert.equal((await post(f.base, ids, '?mode=vuln')).status, 400);
  assert.equal((await get(f.base, ids, '?private=1')).status, 400);
  assert.equal(f.calls.length, prior);
  f.setRole('merchant'); assert.equal((await post(f.base, ids)).status, 403);
  f.setRole('admin'); f.setAvailable(false); assert.equal((await post(f.base, ids)).status, 401);
  assert.equal(f.calls.length, prior);

  const absent = await fixture(t);
  const unavailable = await post(absent.base, ids);
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), { error: 'Role assistant unavailable' });
  const malformed = await fixture(t, {
    async runAttempt() { return { completed: false, status: 'unconfirmed', modelEvaluated: false,
      privatePacket: true }; },
    async readOutcome() { return { completed: false, status: 'unconfirmed', modelEvaluated: false }; },
  });
  const denied = await post(malformed.base, ids);
  assert.equal(denied.status, 503);
  assert.deepEqual(await denied.json(), { error: 'Role assistant unavailable' });
});
