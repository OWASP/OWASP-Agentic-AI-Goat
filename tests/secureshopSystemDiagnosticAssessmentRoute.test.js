'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { EventEmitter } = require('node:events');
const express = require('express');
const { createBoundRoleChatRouter } = require('../server/routes/secureshop/boundRoleChat');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { resultValue } = require('../server/database/postgres/objectiveJudgmentRepository');
const { projectJudgment } = require('../server/agent-runtime/dpiSemanticCreditPolicy');
const diagnosticEvidence = require('../server/services/secureshopSystemDiagnosticEvidence');
const { fixture: evidenceFixture } = require('./secureshopSystemDiagnosticEvidence.test');

const launchBearer = 'd'.repeat(43);
const scope = Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 3,
  platformOwnerId: 71, platformSessionId: 72 });
const personaSession = Object.freeze({ sessionId: randomUUID(), authorityVersion: '3' });
const ids = Object.freeze({ sessionId: randomUUID(), requestId: randomUUID(), proposalId: randomUUID() });
const basePath = '/agents/admin/assistant/system/diagnostic/assess';
const closedUnconfirmed = Object.freeze({ completed: false, status: 'unconfirmed', modelEvaluated: false });
const eventTarget = () => {
  const emitter = new EventEmitter();
  return { once: emitter.once.bind(emitter), off: emitter.off.bind(emitter),
    emit: emitter.emit.bind(emitter), listenerCount: emitter.listenerCount.bind(emitter) };
};

async function fixture(t, handlers = {}) {
  const calls = [];
  let role = 'admin', available = true;
  const runtime = Object.fromEntries([
    'createSession', 'run', 'readRequest', 'confirmUserAdministration', 'confirmPolicy',
    'confirmMcpRegistry', 'confirmSystemRestart', 'confirmAcl', 'runAuditJob', 'readAuditJob',
    'readAuditOperation', 'readSystemConfigOperation',
  ].map(name => [name, async () => assert.fail(`Unexpected ${name} invocation`)]));
  runtime.runSystemDiagnosticAssessment = async input => {
    calls.push({ method: 'run', input });
    return handlers.run ? handlers.run(input) : closedUnconfirmed;
  };
  runtime.readSystemDiagnosticAssessment = async input => {
    calls.push({ method: 'read', input });
    return handlers.read ? handlers.read(input) : closedUnconfirmed;
  };
  const app = express();
  app.use(express.json());
  const router = createBoundRoleChatRouter({ role: 'admin', runtime,
    launches: { async resolveCapability(value) { return available && value === launchBearer ? scope : null; } },
    authenticatePersona(req, res, next) {
      if (req.get('authorization') !== 'Bearer diagnostic-admin')
        return res.status(401).json({ error: 'Authentication required' });
      req.ssUser = { id: 71, role };
      req.ssPersonaSession = personaSession;
      return next();
    },
  });
  app.use('/api/secureshop', router);
  const server = await new Promise(resolve => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  t.after(() => new Promise(resolve => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  const postRoute = router.stack.find(layer => layer.route?.path === basePath && layer.route.methods.post);
  const getRoute = router.stack.find(layer => layer.route?.path === `${basePath}/:sessionId/:requestId/:proposalId`
    && layer.route.methods.get);
  assert.ok(postRoute, 'diagnostic assessment POST route must be mounted');
  assert.ok(getRoute, 'diagnostic assessment GET route must be mounted');
  return { calls, router, postHandler: postRoute.route.stack.at(-1).handle,
    getHandler: getRoute.route.stack.at(-1).handle,
    base: `http://127.0.0.1:${server.address().port}/api/secureshop${basePath}`,
    setRole(value) { role = value; }, setAvailable(value) { available = value; } };
}

const headers = (extra = {}) => ({ authorization: 'Bearer diagnostic-admin',
  'x-dvaia-secureshop-launch': launchBearer, 'content-type': 'application/json', ...extra });
const post = (base, body = ids, suffix = '', requestHeaders = headers()) => fetch(`${base}${suffix}`, {
  method: 'POST', headers: requestHeaders, body: JSON.stringify(body),
});
const savedPath = base => `${base}/${ids.sessionId}/${ids.requestId}/${ids.proposalId}`;

async function canonicalJudgment(evaluationId) {
  const source = evidenceFixture();
  const execution = { runId: randomUUID(), ownerKey: JSON.stringify(['SecureShopBoundConversation', randomUUID()]),
    durableGeneration: '0' };
  const candidate = diagnosticEvidence.buildSystemDiagnosticCandidate({ ...source.input, execution });
  const command = candidate.evidence.find(row => row.id === 'system_diagnostic_command');
  const output = candidate.evidence.find(row => row.id === 'system_diagnostic_execution');
  // Controlled transport only; the production Judge and persistence projector
  // construct the internal DTO. This test does not grant objective credit.
  const judge = createObjectiveJudge({ model: { async generate() {
    return { provider: 'controlled', model: 'route-contract', response: JSON.stringify({
      observation: 'The original command has an additional uname command and stdout contains the baseline followed by the isolated target hostname.',
      satisfied: true, citations: [{ evidenceId: command.id, quote: command.content.command },
        { evidenceId: output.id, quote: output.content.stdout }] }) };
  } } });
  const result = await judge({ rubric: diagnosticEvidence.RUBRIC, ...candidate, execution });
  assert.equal(result.verdict, 'pass');
  const row = Object.fromEntries(Object.entries({ family: 'family', scenario: 'scenario',
    objectiveId: 'objective_id', rubricVersion: 'rubric_version', evidenceDigest: 'evidence_digest',
    runId: 'run_id', mode: 'mode' }).map(([field, column]) => [column, result[field]]));
  const stored = resultValue(result, row);
  assert.ok(stored.criteria.length && stored.evidenceDigest && stored.scopedCriteria);
  return { ...projectJudgment({ disposition: 'awarded', result: stored }), evaluationId, canRetry: false };
}

test('system diagnostic assessment captures current admin authority, projects a closed DTO, and keeps saved GET read-only', async t => {
  const evaluationId = randomUUID();
  const judgment = await canonicalJudgment(evaluationId);
  const f = await fixture(t, {
    run: async () => ({ completed: true, replayed: false, judgment }),
    read: async () => ({ completed: true, replayed: true, judgment }),
  });
  const upper = Object.fromEntries(Object.entries(ids).map(([key, value]) => [key, value.toUpperCase()]));
  const started = await post(f.base, upper);
  assert.equal(started.status, 200);
  assert.equal(started.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await started.json(), { completed: true, replayed: false,
    judgment: { evaluationId, verdict: 'pass', canRetry: false } });

  const saved = await fetch(`${f.base}/${upper.sessionId}/${upper.requestId}/${upper.proposalId}`, { headers: headers() });
  assert.equal(saved.status, 200);
  assert.equal(saved.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await saved.json(), { completed: true, replayed: true,
    judgment: { evaluationId, verdict: 'pass', canRetry: false } });
  assert.deepEqual(f.calls.map(call => call.method), ['run', 'read']);
  for (const call of f.calls) {
    assert.deepEqual(Object.keys(call.input).sort(),
      ['persona', 'personaSession', 'proposalId', 'requestId', 'scope', 'sessionId', 'signal']);
    assert.deepEqual(call.input.scope, scope);
    assert.deepEqual(call.input.persona, { id: 71, role: 'admin' });
    assert.deepEqual(call.input.personaSession, personaSession);
    assert.deepEqual([call.input.sessionId, call.input.requestId, call.input.proposalId],
      [ids.sessionId, ids.requestId, ids.proposalId]);
    assert.ok(call.input.signal instanceof AbortSignal);
  }
});

test('system diagnostic assessment rejects client-provided authority and identifiers before either service method', async t => {
  const f = await fixture(t);
  const rejectedBodies = [
    { ...ids, command: 'uname -a' },
    { ...ids, receipt: { forged: true } },
    { ...ids, targetId: randomUUID() },
    { ...ids, scope: { platformOwnerId: 1 } },
    { ...ids, persona: { id: 1, role: 'admin' } },
    { ...ids, proposalId: 'not-a-uuid' },
    { sessionId: ids.sessionId, requestId: ids.requestId },
  ];
  for (const body of rejectedBodies) {
    const response = await post(f.base, body);
    assert.equal(response.status, 400);
    await response.text();
  }
  assert.equal((await post(f.base, ids, '?mode=vuln')).status, 400);
  assert.equal((await fetch(`${savedPath(f.base)}?private=1`, { headers: headers() })).status, 400);
  assert.equal((await fetch(`${f.base}/${ids.sessionId}/${ids.requestId}/invalid`, { headers: headers() })).status, 400);
  const directResponse = { statusCode: 0, status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; } };
  await f.getHandler({ body: { receipt: 'injected' }, params: { ...ids }, query: {}, headers: {},
    ssLaunch: scope, ssPersonaSession: personaSession, boundPersona: { id: 71, role: 'admin' } }, directResponse);
  assert.equal(directResponse.statusCode, 400);
  assert.deepEqual(f.calls, []);
});

test('system diagnostic assessment rejects missing authentication, non-admin identity, and unavailable launch before service', async t => {
  const f = await fixture(t);
  const unauthenticated = await post(f.base, ids, '', headers({ authorization: 'Bearer wrong' }));
  assert.equal(unauthenticated.status, 401);
  await unauthenticated.text();
  f.setRole('merchant');
  const foreignRole = await post(f.base);
  assert.equal(foreignRole.status, 403);
  await foreignRole.text();
  f.setRole('admin'); f.setAvailable(false);
  const unavailable = await post(f.base);
  assert.equal(unavailable.status, 401);
  await unavailable.text();
  assert.deepEqual(f.calls, []);
});

test('system diagnostic assessment rejects malformed outcomes without returning private service data', async t => {
  const f = await fixture(t, { run: async () => ({ ...closedUnconfirmed, privateTrace: 'never expose this' }) });
  const response = await post(f.base);
  assert.equal(response.status, 503);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await response.json();
  assert.equal(JSON.stringify(body).includes('privateTrace'), false);
  assert.equal(JSON.stringify(body).includes('never expose this'), false);
  assert.equal(f.calls.length, 1);
});

test('full canonical judgments still require valid public fields on POST and saved GET', async t => {
  const judgment = await canonicalJudgment(randomUUID());
  let outcome;
  const f = await fixture(t, { run: async () => outcome, read: async () => outcome });
  const mutations = [
    value => { delete value.judgment.evaluationId; },
    value => { value.judgment.evaluationId = 'invalid'; },
    value => { delete value.judgment.verdict; },
    value => { value.judgment.verdict = 'unknown'; },
    value => { delete value.judgment.canRetry; },
    value => { value.judgment.canRetry = 'false'; },
    value => { value.judgment = Object.create(value.judgment); },
    value => { value.judgment = []; },
    value => { value.judgment = null; },
    value => { value.judgment.verdict = 'fail'; },
  ];
  for (const mutate of mutations) {
    outcome = { completed: true, replayed: false, judgment: structuredClone(judgment) };
    mutate(outcome);
    for (const response of [await post(f.base), await fetch(savedPath(f.base), { headers: headers() })]) {
      assert.equal(response.status, 503);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      const body = await response.json();
      assert.equal(body.code, 'SYSTEM_DIAGNOSTIC_ASSESSMENT_UNAVAILABLE');
      assert.equal(Object.hasOwn(body, 'judgment'), false);
      assert.equal(JSON.stringify(body).includes(judgment.evidenceDigest), false);
    }
  }
});

test('system diagnostic assessment aborts a disconnected POST and releases route listeners without a response', { timeout: 5000 }, async t => {
  let entered, release, seenSignal;
  const enteredWork = new Promise(resolve => { entered = resolve; });
  const work = new Promise(resolve => { release = resolve; });
  const f = await fixture(t, { run: async input => {
    seenSignal = input.signal;
    entered();
    await work;
    return closedUnconfirmed;
  } });
  const req = { ...eventTarget(), body: ids, query: {}, headers: {}, is: value => value === 'application/json',
    ssLaunch: scope, ssPersonaSession: personaSession, boundPersona: { id: 71, role: 'admin' } };
  const res = { ...eventTarget(), writableEnded: false, writableFinished: false, destroyed: false,
    headersSent: false, headers: {}, statusCode: 0,
    status(value) { this.statusCode = value; return this; },
    set(key, value) { this.headers[key] = value; return this; },
    json(value) { this.body = value; return this; } };
  const pending = f.postHandler(req, res);
  await enteredWork;
  res.emit('close');
  assert.equal(seenSignal.aborted, true);
  release();
  await pending;
  assert.equal(res.body, undefined);
  assert.equal(req.listenerCount('aborted'), 0);
  assert.equal(res.listenerCount('close'), 0);
});
