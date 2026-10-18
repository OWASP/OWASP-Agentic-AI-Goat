'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const http = require('node:http');
const { randomUUID, createHash } = require('node:crypto');
const { createBoundSystemDiagnosticRouter } = require('../server/routes/secureshop/boundSystemDiagnostic');
const ID = '44444444-4444-4444-8444-444444444444';
const SCOPE = { launchId: ID, scenarioId: '55555555-5555-4555-8555-555555555555', generation: '1', platformOwnerId: 7, platformSessionId: 9 };
const SESSION = { sessionId: '66666666-6666-4666-8666-666666666666', authorityVersion: '2' };
function receipt(operationId = ID) {
  const stdout = Buffer.from('owned diagnostic output');
  const stderr = Buffer.from('');
  const digest = value => createHash('sha256').update(value).digest('hex');
  const request = { operationId, cmd_template: 'printf', args: 'owned' };
  const result = { version: 'secureshop-owned-system-diagnostic.v1', isolation: 'bwrap-system-diagnostic-v1', operationId,
    requestSha256: digest(JSON.stringify({ version: 'secureshop-owned-system-diagnostic.v1', request })), command: 'printf owned', executed: true,
    exitCode: 0, signal: null, drained: true, stdout: stdout.toString('base64'), stderr: stderr.toString('base64'), encoding: 'base64',
    stdoutBytes: stdout.length, stderrBytes: 0, stdoutSha256: digest(stdout), stderrSha256: digest(stderr), timedOut: false, truncated: false };
  return { version: 'secureshop-owned-system-diagnostic-http.v1', targetId: ID, hostname: `system-diag-${ID.replaceAll('-', '')}`,
    bindingSha256: 'a'.repeat(64), result };
}
function appFor(service, state = {}) {
  const app = express(); app.use(express.json());
  app.use((req, _res, next) => { req.ssLaunch = SCOPE; req.ssUser = state.user || { id: 3, role: 'admin' }; req.ssPersonaSession = state.session === false ? null : SESSION; next(); });
  app.use('/api/secureshop', createBoundSystemDiagnosticRouter({ service, authenticatePersona: (_req, _res, next) => next() })); return app;
}
function request(app, method, path, body) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => { const address = server.address(); const data = body === undefined ? null : JSON.stringify(body);
      const req = http.request({ host: address.address, port: address.port, path, method, headers: data ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {} }, res => {
      let text = ''; res.on('data', chunk => { text += chunk; }); res.on('end', () => { server.close(); resolve({ status: res.statusCode, body: text ? JSON.parse(text) : null, headers: res.headers }); }); });
      req.on('error', reject); if (data) req.write(data); req.end(); });
  });
}
const base = () => ({ async administration() { return { diagnosticCapability: 'secureshop-owned-system-diagnostic.v1', scopeKey: 'b'.repeat(64) }; },
  async execute(input) { return { state: 'completed', operationId: input.operationId, requestSha256: 'c'.repeat(64), receipt: receipt(input.operationId) }; },
  async operation(input) { return { state: 'completed', operationId: input.operationId, requestSha256: 'c'.repeat(64), receipt: receipt(input.operationId) }; } });
test('GET capability and completed POST project UI-compatible receipt fields', async () => {
  let result = await request(appFor(base()), 'GET', '/api/secureshop/admin/system/diagnostic'); assert.equal(result.status, 200); assert.equal(result.body.administration.scopeKey.length, 64);
  result = await request(appFor(base()), 'POST', '/api/secureshop/admin/system/diagnostic', { operationId: ID, cmd_template: 'printf', args: 'owned' });
  assert.equal(result.status, 200); assert.equal(result.body.ok, true); assert.equal(result.body.cmd, 'printf owned'); assert.equal(result.body.stdout, 'owned diagnostic output'); assert.equal(result.body.exitCode, 0);
});
test('pending, unknown, not-executed and operation replay are explicit', async () => {
  for (const state of ['pending', 'unknown', 'not_executed']) {
    const result = await request(appFor({ ...base(), async execute(input) { return { state, operationId: input.operationId }; } }), 'POST', '/api/secureshop/admin/system/diagnostic', { operationId: ID, cmd_template: 'printf', args: 'owned' });
    assert.equal(result.status, state === 'pending' ? 202 : 200); assert.equal(result.body.automaticRetry, state === 'unknown' || state === 'not_executed' ? false : undefined);
  }
  const result = await request(appFor(base()), 'GET', `/api/secureshop/admin/system/diagnostic-operations/${ID}`); assert.equal(result.status, 200); assert.equal(result.body.operationId, ID);
});
test('closed body, query, auth and status mapping fail before service effects', async () => {
  let calls = 0; const service = { ...base(), async execute() { calls++; return { state: 'completed', operationId: ID, receipt: receipt() }; } };
  for (const body of [{ operationId: ID, cmd_template: 'printf', args: 'x', extra: true }, { operationId: 'bad', cmd_template: 'printf', args: 'x' }]) assert.equal((await request(appFor(service), 'POST', '/api/secureshop/admin/system/diagnostic', body)).status, 400);
  assert.equal((await request(appFor(service), 'POST', '/api/secureshop/admin/system/diagnostic?x=1', { operationId: ID, cmd_template: 'printf', args: 'x' })).status, 400); assert.equal(calls, 0);
  const unauthenticated = await request(appFor(service, { session: false }), 'GET', '/api/secureshop/admin/system/diagnostic'); assert.equal(unauthenticated.status, 401); assert.equal(unauthenticated.headers['cache-control'], 'no-store');
  assert.equal((await request(appFor(service, { user: { id: 3, role: 'customer' } }), 'GET', '/api/secureshop/admin/system/diagnostic')).status, 403);
  for (const [code, expected] of [['OPERATION_CONFLICT', 409], ['SYSTEM_DIAGNOSTIC_BUSY', 503], ['SYSTEM_DIAGNOSTIC_QUOTA_EXCEEDED', 429]]) {
    const result = await request(appFor({ ...service, async execute() { throw Object.assign(new Error('private'), { code }); } }), 'POST', '/api/secureshop/admin/system/diagnostic', { operationId: ID, cmd_template: 'printf', args: 'x' }); assert.equal(result.status, expected); assert.equal(result.body.error.includes('private'), false);
  }
});
test('fixed-mode execution denial is explicit while retained operation reads remain available', async () => {
  let attempts = 0, reads = 0;
  const service = { ...base(),
    async execute() {
      attempts++;
      throw Object.assign(new Error('private mode authority details'), { code: 'SYSTEM_DIAGNOSTIC_FIXED_DENIED' });
    },
    async operation(input) { reads++; return base().operation(input); },
  };
  const app = appFor(service);
  const denied = await request(app, 'POST', '/api/secureshop/admin/system/diagnostic',
    { operationId: ID, cmd_template: 'printf', args: 'owned' });
  assert.equal(denied.status, 403);
  assert.deepEqual(denied.body, { ok: false, error: 'Shell diagnostics are disabled in Fixed mode.',
    code: 'SYSTEM_DIAGNOSTIC_FIXED_DENIED' });
  assert.equal(denied.headers['cache-control'], 'no-store');
  const saved = await request(app, 'GET', `/api/secureshop/admin/system/diagnostic-operations/${ID}`);
  assert.equal(saved.status, 200);
  assert.equal(saved.body.stdout, 'owned diagnostic output');
  assert.equal(attempts, 1);
  assert.equal(reads, 1);
});
test('disconnect aborts the service signal and does not publish a late response', async t => {
  let aborted = false, started; const entered = new Promise(resolve => { started = resolve; });
  const server = appFor({ ...base(), async execute(_input, { signal }) { started(); await new Promise(resolve => { signal.addEventListener('abort', () => { aborted = true; resolve(); }, { once: true }); }); return { state: 'pending', operationId: ID }; } }).listen(0, '127.0.0.1');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }); await new Promise(resolve => server.once('listening', resolve));
  const req = http.request({ host: '127.0.0.1', port: server.address().port, path: '/api/secureshop/admin/system/diagnostic', method: 'POST', headers: { 'content-type': 'application/json' } }); req.on('error', () => {}); req.end(JSON.stringify({ operationId: ID, cmd_template: 'printf', args: 'x' })); await entered; req.destroy(); await new Promise(resolve => setTimeout(resolve, 10)); assert.equal(aborted, true);
});
