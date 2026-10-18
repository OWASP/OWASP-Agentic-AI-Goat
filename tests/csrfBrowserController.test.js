'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { csrfBrowserBody } = require('../server/middleware/csrfBrowserBody');
const { createApplicationCors } = require('../server/middleware/applicationCors');
const { createCsrfBrowserController } = require('../server/services/csrfBrowserController');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
const { ownerWorkflowRoute, getOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');

async function fixture(t, { gate = { visible: true }, completed = new Set(), failure, gateFailure } = {}) {
  const calls = [];
  const statuses = [];
  const sandbox = { flush: async () => { calls.push('flush'); }, getTabState: tab => ({ tab, balance: 83 }) };
  const workflow = { run: async packet => {
    calls.push(packet);
    if (failure) throw failure;
    const attempt = await packet.beginGrading(packet.execution);
    const grade = await packet.finalGrade({ execution: packet.execution, check: packet.execution.check,
      gradingAttempt: attempt, userId: packet.userId, objectiveId: packet.objectiveId });
    return { graded: true, grade, payloadDigest: 'c'.repeat(64), browser: {
      observation: { method: 'POST', resourceType: 'document', postData: 'must not leak', cookiePresent: true },
      responseStatus: 200, responseObserved: true, boundary: 'owned fixture' } };
  } };
  const handler = createCsrfBrowserController({ workflow, getExecution: getOwnerExecution,
    getGate: async () => { if (gateFailure) throw gateFailure; return gate; }, getCompleted: async () => completed, sandboxFor: () => sandbox, actionHandlerDeps: {},
    beginGrading: async (userId, execution) => { assert.equal(userId, 7); return { execution }; },
    finalGrade: async packet => {
      assert.equal(calls.at(-1), 'flush', 'durable effect is flushed before final grading');
      assert.equal(packet.gradingAttempt.execution, packet.execution);
      return { completed: true, judgments: [{ verdict: 'pass' }], projectionPending: [] };
    } });
  const app = express();
  app.use(createApplicationCors());
  app.use('/api/workshop/csrf/browser-attempt', csrfBrowserBody);
  // Explicit transport-auth fixture. Production mounts authenticateToken here.
  app.post('/api/workshop/csrf/browser-attempt', (req, res, next) => {
    if (req.get('authorization') !== 'Bearer owned-fixture') return res.status(401).json({ error: 'unauthorized' });
    req.user = { id: 7 }; req.session = { userId: 99 }; next();
  }, ownerWorkflowRoute(createRunCoordinator({ family: 'CSRF', ledger: {
    begin: async () => ({}), finish: async (_scope, result) => { statuses.push(result.status); },
  } }), req => String(req.user.id), handler));
  app.post('/api/workshop/csrf/agent-action', (_req, res) => res.json({ practice: true }));
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (body, headers = {}, path = '/api/workshop/csrf/browser-attempt') => fetch(base + path, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer owned-fixture', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body) });
  return { calls, request, statuses };
}
const payload = { tab: 'post', objectiveId: 'csrf_p1', html: '<p>  exact €\n markup  </p>' };

test('HTTP browser admission preserves raw HTML, fixes identity and returns only public result fields', async t => {
  const f = await fixture(t);
  const response = await f.request(payload);
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.deepEqual(result.newlyCompleted, ['csrf_p1']);
  assert.equal(result.victimState.balance, 83);
  const packet = f.calls.find(value => typeof value === 'object');
  assert.equal(packet.html, payload.html);
  assert.equal(packet.userId, 7);
  assert.equal(packet.execution.ownerKey, '["CSRF","7"]');
  assert.equal(packet.victimOrigin, 'http://victim.csrf.invalid');
  assert.equal(packet.attackerOrigin, 'http://attacker.csrf.invalid');
  assert.match(packet.victimCookie.value, /^[a-zA-Z0-9_-]{32}$/);
  assert.equal(JSON.stringify(result).includes(packet.victimCookie.value), false);
  assert.equal(JSON.stringify(result).includes('must not leak'), false);
  assert.deepEqual(f.statuses, ['completed']);
});

test('HTTP browser admission rejects cookie-only, wrong-origin, malformed and oversized requests before execution', async t => {
  const f = await fixture(t);
  assert.equal((await f.request(payload, { authorization: '', cookie: 'connect.sid=owned' })).status, 401);
  assert.equal((await f.request(payload, { origin: 'https://untrusted.example' })).status, 403);
  assert.equal((await f.request(payload, { origin: 'https://untrusted.example' }, '/api/workshop/csrf/agent-action')).status, 200);
  assert.equal((await f.request('html=example', { 'content-type': 'application/x-www-form-urlencoded' })).status, 415);
  assert.equal((await f.request('{')).status, 400);
  assert.equal((await f.request({ ...payload, html: 'x'.repeat(410000) })).status, 413);
  for (const body of [{ ...payload, html: 'x'.repeat(65537) }, { ...payload, userId: 99 },
    { ...payload, receipt: {} }, { ...payload, observation: {} }, { ...payload, victimCookie: {} },
    { ...payload, tab: 'get' }, { ...payload, objectiveId: 'csrf_x3' }, { ...payload, html: ' ' }]) {
    assert.equal((await f.request(body)).status, 400);
  }
  assert.equal(f.calls.length, 0);
});

test('hidden objectives and unmet prerequisites cannot launch a browser', async t => {
  for (const [gate, status] of [[{ visible: false }, 404], [{ visible: true, prerequisite: 'csrf_g1' }, 409]]) {
    const f = await fixture(t, { gate });
    assert.equal((await f.request(payload)).status, status);
    assert.equal(f.calls.length, 0);
    assert.deepEqual(f.statuses, ['failed'], 'rejected admission cannot appear as a completed agent run');
  }
});

test('browser failures produce bounded retry/errors without private launch paths or completion claims', async t => {
  for (const [code, status] of [['CSRF_BROWSER_BUSY', 429], ['CSRF_BROWSER_TIMEOUT', 504],
    ['CSRF_BROWSER_REQUEST_TOO_LARGE', 400], ['LAUNCH_FAILED', 503]]) {
    const f = await fixture(t, { failure: Object.assign(new Error(code === 'LAUNCH_FAILED'
      ? '/private/operator/cache/chrome: secret launch failure' : 'bounded request error'), { code }) });
    const response = await f.request(payload);
    assert.equal(response.status, status);
    if (status === 429) assert.equal(response.headers.get('retry-after'), '5');
    const body = await response.json();
    assert.equal(body.newlyCompleted, undefined);
    assert.equal(JSON.stringify(body).includes('/private/'), false);
    assert.deepEqual(f.statuses, ['failed'], 'HTTP error and coordinator ledger status agree');
  }
});

test('configuration/database admission errors are redacted and recorded as failed runs', async t => {
  const f = await fixture(t, { gateFailure: new Error('/private/operator/database: credentials unavailable') });
  const response = await f.request(payload);
  assert.equal(response.status, 503);
  assert.equal(JSON.stringify(await response.json()).includes('/private/'), false);
  assert.deepEqual(f.statuses, ['failed']);
  assert.equal(f.calls.length, 0);
});
