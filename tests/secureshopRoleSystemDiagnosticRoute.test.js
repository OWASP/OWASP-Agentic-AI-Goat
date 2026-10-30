'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createBoundRoleChatRouter } = require('../server/routes/secureshop/boundRoleChat');
const launch = { launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1,
  platformOwnerId: 4, platformSessionId: 5 };
const personaSession = { sessionId: '30000000-0000-4000-8000-000000000001', authorityVersion: '2' };
const ids = { sessionId: '40000000-0000-4000-8000-000000000001',
  requestId: '50000000-0000-4000-8000-000000000001', proposalId: '60000000-0000-4000-8000-000000000001' };
const headers = { 'content-type': 'application/json', 'x-owasp-ai-goat-secureshop-launch': 'a'.repeat(43),
  authorization: 'Bearer private-token' };
async function setup(t, overrides = {}, userRole = 'admin') {
  const calls = [];
  const runtime = Object.fromEntries(['createSession', 'run', 'readRequest', 'confirmUserAdministration',
    'confirmPolicy', 'confirmMcpRegistry', 'confirmSystemRestart', 'confirmAcl', 'runAuditJob',
    'readAuditJob', 'readAuditOperation', 'readSystemConfigOperation'].map(key => [key, async () => {}]));
  Object.assign(runtime, {
    async confirmSystemDiagnostic(input) { calls.push(['confirm', input]); return { state: 'pending', operationId: input.proposalId }; },
    async readSystemDiagnostic(input) { calls.push(['read', input]); return { state: 'completed', operationId: input.proposalId }; },
  }, overrides);
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', createBoundRoleChatRouter({ role: 'admin', runtime,
    launches: { async resolveCapability() { return launch; } },
    authenticatePersona(req, _res, next) { req.ssUser = { id: 7, role: userRole }; req.ssPersonaSession = personaSession; next(); } }));
  const server = app.listen(0, '127.0.0.1');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  await new Promise(resolve => server.once('listening', resolve));
  return { calls, base: `http://127.0.0.1:${server.address().port}/api/secureshop/agents/admin/assistant/system/diagnostic/confirm` };
}
test('diagnostic confirmation binds IDs to server authority and recovery is GET-only', async t => {
  const { base, calls } = await setup(t);
  const confirmation = await fetch(base, { method: 'POST', headers, body: JSON.stringify(ids) });
  assert.equal(confirmation.status, 202); assert.equal(confirmation.headers.get('cache-control'), 'no-store');
  await confirmation.json();
  const saved = await fetch(`${base}/${ids.sessionId}/${ids.requestId}/${ids.proposalId}`, { headers });
  assert.equal(saved.status, 200); assert.equal(saved.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await saved.json(), { state: 'completed', operationId: ids.proposalId });
  assert.deepEqual(calls.map(row => row[0]), ['confirm', 'read']);
  for (const [, input] of calls) {
    for (const [key, value] of Object.entries(ids)) assert.equal(input[key], value);
    assert.equal(input.scope.launchId, launch.launchId);
    assert.deepEqual(input.persona, { id: 7, role: 'admin' });
    assert.deepEqual(input.personaSession, personaSession);
    assert.equal(Object.hasOwn(input, 'token'), false);
    assert.equal(Object.hasOwn(input, 'cmd_template'), false);
  }
});
test('injected command, authority, query and malformed IDs cannot reach confirmation', async t => {
  const { base, calls } = await setup(t);
  for (const body of [{ ...ids, cmd_template: 'echo', args: 'injected' },
    { ...ids, persona: { id: 1, role: 'admin' } }, { ...ids, proposalId: 'invalid' },
    { sessionId: ids.sessionId, requestId: ids.requestId }]) {
    const response = await fetch(base, { method: 'POST', headers, body: JSON.stringify(body) });
    assert.equal(response.status, 400); await response.text();
  }
  const query = await fetch(`${base}?mode=vuln`, { method: 'POST', headers, body: JSON.stringify(ids) });
  assert.equal(query.status, 400); await query.text();
  const read = await fetch(`${base}/${ids.sessionId}/${ids.requestId}/invalid`, { headers });
  assert.equal(read.status, 400); await read.text();
  assert.deepEqual(calls, []);
});
test('fixed denial and uncertain outcome preserve explicit non-retry responses', async t => {
  for (const [code, status] of [['SYSTEM_DIAGNOSTIC_FIXED_DENIED', 403], ['SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN', 503]]) {
    const { base } = await setup(t, { async confirmSystemDiagnostic() { throw Object.assign(Error('private details'), { code }); } });
    const response = await fetch(base, { method: 'POST', headers, body: JSON.stringify(ids) });
    assert.equal(response.status, status); const body = await response.json();
    assert.equal(body.code, code); assert.equal(body.error.includes('private'), false);
    assert.equal(body.automaticRetry, code.endsWith('UNCERTAIN') ? false : undefined);
  }
});
test('customer persona cannot confirm an admin diagnostic', async t => {
  const { base, calls } = await setup(t, {}, 'customer');
  const response = await fetch(base, { method: 'POST', headers, body: JSON.stringify(ids) });
  assert.equal(response.status, 403); await response.text(); assert.deepEqual(calls, []);
});
