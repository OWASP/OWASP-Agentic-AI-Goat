'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const express = require('express');
const { createBoundRoleChatRouter } = require('../server/routes/secureshop/boundRoleChat');

test('System assessment check uses only authenticated authority and original saved IDs', async t => {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 2, platformSessionId: 3 };
  const credential = { sessionId: randomUUID(), authorityVersion: '1' };
  const original = { sessionId: randomUUID(), requestId: randomUUID() };
  let role = 'admin', authenticated = true, launchAvailable = true, failure;
  const calls = [];
  const runtime = Object.fromEntries(['createSession', 'run', 'readRequest',
    'confirmUserAdministration', 'confirmPolicy', 'confirmMcpRegistry',
    'confirmSystemRestart', 'confirmAcl', 'runAuditJob', 'readAuditJob',
    'readAuditOperation', 'readSystemConfigOperation'].map(name => [name, async () => {
    assert.fail(`Assessment check must not call ${name}`);
  }]));
  runtime.retrySystemConfigAssessment = async input => {
    calls.push(input);
    if (failure) throw failure;
    return { completed: false, status: 'ineligible', modelEvaluated: false };
  };
  const app = express();
  app.use(express.json());
  app.use(createBoundRoleChatRouter({ role: 'admin', runtime,
    launches: { resolveCapability: async () => launchAvailable ? scope : null },
    authenticatePersona(req, res, next) {
      if (!authenticated) return res.status(401).json({ error: 'Authentication required' });
      req.ssUser = { id: 7, role };
      req.ssPersonaSession = credential;
      next();
    },
  }));
  const server = app.listen(0, '127.0.0.1');
  t.after(() => new Promise(resolve => server.close(resolve)));
  await new Promise(resolve => server.once('listening', resolve));
  const url = `http://127.0.0.1:${server.address().port}/agents/admin/assistant/system/config/assessment-retry`;
  const headers = { 'content-type': 'application/json', 'x-owasp-ai-goat-secureshop-launch': 'a'.repeat(43) };
  const post = (body = original, suffix = '', suppliedHeaders = headers) => fetch(url + suffix,
    { method: 'POST', headers: suppliedHeaders, body: JSON.stringify(body) });
  const response = await post({ sessionId: original.sessionId.toUpperCase(), requestId: original.requestId.toUpperCase() });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await response.json(), { completed: false, status: 'ineligible', modelEvaluated: false });
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].scope, scope);
  assert.deepEqual(calls[0].persona, { id: 7, role: 'admin' });
  assert.equal(calls[0].personaSession, credential);
  assert.equal(calls[0].sessionId, original.sessionId);
  assert.equal(calls[0].requestId, original.requestId);
  assert.ok(calls[0].signal instanceof AbortSignal);

  for (const body of [{ ...original, mode: 'vuln' }, { ...original, persona: { id: 99 } },
    { ...original, completed: true }, { ...original, requestId: 'invalid' }, { sessionId: original.sessionId }]) {
    assert.equal((await post(body)).status, 400);
  }
  assert.equal((await post(original, '?mode=vuln')).status, 400);
  assert.equal((await post(original, '', { ...headers, 'content-type': 'text/plain' })).status, 400);
  role = 'customer';
  assert.equal((await post()).status, 403);
  role = 'admin'; authenticated = false;
  assert.equal((await post()).status, 401);
  authenticated = true; launchAvailable = false;
  assert.equal((await post()).status, 401);
  assert.equal(calls.length, 1);

  launchAvailable = true;
  failure = Object.assign(new Error('private diagnostic must not escape'), { code: 'SHOP_AUTH_INVALID' });
  const revoked = await post();
  assert.equal(revoked.status, 401);
  assert.equal(revoked.headers.get('x-owasp-ai-goat-secureshop-launch-state'), 'unavailable');
  assert.deepEqual(await revoked.json(), { error: 'Shop session unavailable' });
  failure = new Error('private diagnostic must not escape');
  const unavailable = await post();
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), { error: 'Role assistant unavailable' });
  assert.equal(calls.length, 3);
});
