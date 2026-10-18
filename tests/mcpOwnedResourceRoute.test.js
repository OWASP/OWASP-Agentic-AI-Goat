'use strict';

process.env.EXPORT_INTERNALS = '1';
process.env.NODE_ENV = 'test';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const Module = require('node:module');
const path = require('node:path');
const express = require('express');
const { createMcpOwnedResourceApplication } = require('../server/services/mcp/ownedResourceApplication');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');

const fixtureIdentityAdapter = {
  repository:{}, jwtSecret:'mcp-owned-resource-fixture-signing-key-2026',
  async validateSession(token) {
    const match = /^controlled-(1|7)$/.exec(token);
    if (!match) return null;
    const id = Number(match[1]);
    return { user:{id,username:`student-${id}`,role:'student',admin_level:0},
      session:{id:id + 40,user_id:id} };
  },
};
const fixtureAdminAuth = createPostgresAdminAuth(fixtureIdentityAdapter);
function fixturePlatformUser(id) {
  return (req, _res, next) => {
    const value = `Bearer controlled-${id}`;
    req.headers.authorization = value;
    req.rawHeaders.push('Authorization', value);
    req.user = { id, username:`student-${id}`, role:'student', admin_level:0 };
    req.identitySession = { id:id + 40, user_id:id };
    next();
  };
}

// This route has broad legacy imports. Supply explicit inert application
// boundaries and reject every real database/provider import so a unit test can
// never initialize or seed a working learner store.
const originalLoad = Module._load;
const blockedImports = [];
const forbidden = request => /(?:^|\/)(?:database|multiProviderAIService|postgresIdentityAdapter|ollamaService|providerRouter)(?:\/|\.js|$)/.test(request) || /^(?:pg|sqlite3|better-sqlite3|openai|@anthropic-ai\/sdk)(?:\/|$)/.test(request);
const retirementEvents = [];
let visibleObjectives = {};
let retirementProof = async () => { throw Object.assign(Error('Owned cleanup pending'), { code: 'MCP_OWNER_RESOURCES_PENDING' }); };
const databaseFixture = { engine: 'postgres', runtimePool: async () => ({}),
  resetUser: async owner => retirementEvents.push(['store', owner]) };

const progress = Object.fromEntries(['syncObjectiveComplete','checkAndMarkWorkshopComplete','resetWorkshopProgress',
  'syncWorkshopStarted','getUserWorkshopProgress'].map(name => [name, async () => {
  if (name === 'resetWorkshopProgress') retirementEvents.push(['canonical']);
  return name === 'getUserWorkshopProgress' ? [] : undefined;
}]));
Module._load = function isolatedMcpRoute(request, parent, isMain) {
  if (request === '../middleware/adminAuth') return fixtureAdminAuth;
  if (request === '../services/postgresIdentityAdapter') return { getPostgresIdentityAdapter: () => fixtureIdentityAdapter };
  if (request === '../middleware/rateLimiter') return { generalRateLimiter:(_req,_res,next) => next() };
  if (request === '../agent-runtime/runCoordinator') return { createRunCoordinator: options => createRunCoordinator({...options,ledger:null}) };
  if (request === '../utils/progressSync') return progress;
  if (request === '../database/mcpWorkshopDb') return databaseFixture;
  if (request === '../database/postgres/mcpResourceRepository') return { createMcpResourceRepository: () => ({
    assertOwnerResourcesRetired: scope => retirementProof(scope) }) };
  if (request === '../services/multiProviderAIService' || request === '../multiProviderAIService') {
    return { provider: 'fixture', checkOllamaAvailable: async () => false };
  }
  if (request === '../services/workshopConfigService') return { createWorkshopConfigService: () => ({
    getSnapshot: async () => ({ exercises: { mcp_workshop: { isVisible: true, objectives: visibleObjectives } } }),
  }) };
  if (request === '../services/mcpObjectiveGrader') return { createMcpObjectiveGrader: () => ({
    begin: async () => null, evaluate: async () => ({ completed: false, judgment: {} }),
  }) };
  if (forbidden(request)) {
    blockedImports.push(request);
    throw Object.assign(new Error(`Unsafe MCP route dependency forbidden: ${request}`), { code: 'MCP_TEST_REAL_DEPENDENCY_FORBIDDEN' });
  }
  return originalLoad.call(this, request, parent, isMain);
};
// Keep the guard installed through delayed imports and every mounted request.
const route = require('../server/routes/mcpWorkshop');
let selectedModeScope = { generation: 0, mode: null, modeStamp: 'default' };
route._internals.setModeAuthorityForTests({ readScope: async () => ({ ...selectedModeScope }) });
test.after(() => { Module._load = originalLoad; });

test('lifetime isolation rejects delayed real database and provider imports before module entry', async () => {
  await new Promise(resolve => setImmediate(resolve));
  for (const request of ['../server/database/authDb', '../server/database/postgres/index', 'pg', 'sqlite3', 'better-sqlite3', '../server/services/ollamaService', 'openai']) {
    assert.throws(() => require(request), { code: 'MCP_TEST_REAL_DEPENDENCY_FORBIDDEN' });
  }
  assert.equal(Object.keys(require.cache).some(name => /[\/]server[\/]database[\/]/.test(name)), false);
});

function candidate({ ready, owner = 1, assertCurrent = async () => true }) {
  let allocations = 0;
  const app = createMcpOwnedResourceApplication({
    sessionResolver: { async resolveRequest(req) {
      if (req.user?.id !== owner) throw Object.assign(new Error('Authenticated platform owner changed'),
        { code: 'MCP_PLATFORM_OWNER_MISMATCH', statusCode: 409 });
      const identity = { platformOwnerId: owner, platformSessionId: 41 };
      Object.defineProperty(identity, 'assertCurrent', { enumerable: false, value: assertCurrent });
      return Object.freeze(identity);
    } },
    readiness: async () => ({ ready, runnerReady: ready, repositoryReady: ready,
      runnerIsolation: ready ? 'bwrap-seccomp-v1' : null }),
    repository: { async reserveRunnerTarget() {}, async beginRunnerRetirement() {}, async completeRunnerRetirement() {} },
    mailResources: { async send() { throw new Error('not reached'); }, async cleanup() {}, async project() { return { ok: true, messages: [] }; } },
    targets: { async admit() { allocations += 1; throw new Error('not reached'); }, async retire() {}, async readRetirement() {} },
  });
  return { app, allocations: () => allocations };
}
async function post(application, body = { message: 'send a report' }) {
  route._internals.setOwnedResourcesForTests(application);
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(1));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/mcp/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  } finally { route._internals.setOwnedResourcesForTests(null); await new Promise(resolve => server.close(resolve)); }
}

test('mounted workshop chat returns explicit unavailable before legacy tools when owned adapters are unready', async () => {
  const f = candidate({ ready: false }); const response = await post(f.app);
  assert.equal(response.status, 503); assert.equal(response.body.error, 'MCP_OWNED_RESOURCES_UNAVAILABLE');
  assert.equal(f.allocations(), 0);
});

test('supported PostgreSQL MCP execution surfaces reject disabled owned runtime before legacy fallback', async () => {
  route._internals.setOwnedResourcesForTests(null);
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(1));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/workshop/mcp`;
    for (const [path, init] of [
      ['/chat', { method: 'POST', body: JSON.stringify({ message: 'run ls' }) }],
      ['/jsonrpc', { method: 'POST', body: JSON.stringify({ method: 'tools/list', id: 1 }) }],
      ['/mcp', { method: 'GET' }],
      ['/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }) }],
      ['/mcp', { method: 'DELETE' }],
      ['/tools', { method: 'GET' }],
    ]) {
      const response = await fetch(`${base}${path}`, { ...init,
        headers: { 'content-type': 'application/json' } });
      const body = await response.json();
      assert.equal(response.status, 503, `${path}: ${JSON.stringify(body)}`);
      assert.equal(body.error, 'MCP_OWNED_RESOURCES_UNAVAILABLE');
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('disabled PostgreSQL runtime blocks mutation/effect surfaces without probing legacy state', async () => {
  route._internals.setOwnedResourcesForTests(null);
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(1));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const mcpSandbox = require('../server/services/mcp/sandboxShell');
  const probes = require('../server/services/mcp/_probes');
  const sandboxState = mcpSandbox.getSandboxState;
  const listenerData = mcpSandbox.getListenerData;
  const appendListenerData = mcpSandbox.appendListenerData;
  const health = require('../server/services/mcp/sandboxRunnerClient').health;
  const probeHttp = probes.http;
  const failProbe = async () => { throw new Error('legacy probe must not run'); };
  mcpSandbox.getSandboxState = mcpSandbox.getListenerData = mcpSandbox.appendListenerData = failProbe;
  require('../server/services/mcp/sandboxRunnerClient').health = failProbe;
  probes.http = failProbe;
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/workshop/mcp`;
    const infra = await fetch(`${base}/infra`);
    const infraBody = await infra.json();
    assert.equal(infra.status, 200); assert.equal(infraBody.mode, 'unavailable');
    assert.equal(infraBody.note, 'The MCP exercise runtime is unavailable.');
    assert.deepEqual(infraBody.sidecars, []);
    for (const [path, init] of [
      ['/exfil', { method: 'GET' }], ['/listener/mcp_1', { method: 'GET' }],
      ['/listener/mcp_1', { method: 'POST', body: JSON.stringify({ leak: true }) }],
      ['/progress/reset', { method: 'POST', body: '{}' }],
      ['/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }) }],
      ['/mcp', { method: 'DELETE' }],
    ]) {
      const response = await fetch(`${base}${path}`, { ...init, headers: { 'content-type': 'application/json' } });
      const body = await response.json();
      assert.equal(response.status, 503, `${path}: ${JSON.stringify(body)}`);
      assert.equal(path === '/progress/reset' ? body.code : body.error, 'MCP_OWNED_RESOURCES_UNAVAILABLE');
    }
  } finally {
    mcpSandbox.getSandboxState = sandboxState; mcpSandbox.getListenerData = listenerData;
    mcpSandbox.appendListenerData = appendListenerData;
    require('../server/services/mcp/sandboxRunnerClient').health = health; probes.http = probeHttp;
    await new Promise(resolve => server.close(resolve));
  }
});

test('authentication remains first on supported PostgreSQL guarded surfaces', async () => {
  route._internals.setOwnedResourcesForTests(null);
  const app = express(); app.use(express.json()); app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/workshop/mcp`;
    for (const [path, init] of [
      ['/chat', { method: 'POST', body: JSON.stringify({ message: 'run ls' }) }],
      ['/jsonrpc', { method: 'POST', body: JSON.stringify({ method: 'tools/list', id: 1 }) }],
      ['/mcp', { method: 'GET' }],
      ['/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }) }],
      ['/mcp', { method: 'DELETE' }], ['/tools', { method: 'GET' }],
      ['/exfil', { method: 'GET' }], ['/listener/mcp_1', { method: 'GET' }],
      ['/progress/reset', { method: 'POST', body: '{}' }], ['/infra', { method: 'GET' }],
    ]) {
      const response = await fetch(`${base}${path}`, { ...init, headers: { 'content-type': 'application/json' } });
      assert.equal(response.status, 401, path);
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('mounted workshop chat rejects canonical platform owner mismatch before target admission', async () => {
  const f = candidate({ ready: true, owner: 2 }); const response = await post(f.app);
  assert.equal(response.status, 409); assert.equal(response.body.error, 'MCP_PLATFORM_OWNER_MISMATCH');
  assert.equal(f.allocations(), 0);
});

test('PostgreSQL listener is unavailable even when owned runtime is enabled and never reads legacy state', async () => {
  const qualification = require('../server/services/mcp/ownedQualification').createOwnedQualification(true);
  route._internals.setOwnedResourcesForTests({ enabled: true, qualification });
  const mcpSandbox = require('../server/services/mcp/sandboxShell');
  const originalGet = mcpSandbox.getListenerData;
  const originalAppend = mcpSandbox.appendListenerData;
  let legacyReads = 0;
  mcpSandbox.getListenerData = () => { legacyReads += 1; throw new Error('legacy listener read'); };
  mcpSandbox.appendListenerData = () => { legacyReads += 1; throw new Error('legacy listener write'); };
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(1));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/workshop/mcp/listener/mcp_1`;
    for (const init of [{ method: 'GET' }, { method: 'POST', body: JSON.stringify({ leak: true }) }]) {
      const response = await fetch(base, { ...init, headers: { 'content-type': 'application/json' } });
      const body = await response.json();
      assert.equal(response.status, 503); assert.equal(body.error, 'MCP_OWNED_RESOURCES_UNAVAILABLE');
    }
    assert.equal(legacyReads, 0);
  } finally {
    mcpSandbox.getListenerData = originalGet; mcpSandbox.appendListenerData = originalAppend;
    route._internals.setOwnedResourcesForTests(null); await new Promise(resolve => server.close(resolve));
  }
});

test('owned qualification preserves all instructor-visible objectives while identifying only qualified grading paths', () => {
  const qualification = require('../server/services/mcp/ownedQualification').createOwnedQualification(true);
  route._internals.setOwnedResourcesForTests({ enabled: true, qualification });
  const value = route._internals.qualificationFor(route._internals.OBJECTIVES);
  assert.equal(value.objectives.length, 11);
  assert.deepEqual(value.objectives.filter(item => item.qualified).map(item => item.objectiveId),
    ['mcp_cmd_injection', 'mcp_confused_deputy']);
  route._internals.setOwnedResourcesForTests(null);
});

test('disabled PostgreSQL runtime reports every visible objective as pending and rejects candidates', () => {
  route._internals.setOwnedResourcesForTests(null);
  const value = route._internals.qualificationFor(route._internals.OBJECTIVES);
  assert.equal(value.mode, 'qualified_subset');
  assert.equal(value.version, 'mcp-owned-runtime-unavailable');
  assert.equal(value.objectives.length, 11);
  assert.ok(value.objectives.every(item => item.qualified === false));
  assert.deepEqual(route._internals.qualifiedObjectiveCandidates(
    route._internals.OBJECTIVES, new Set(route._internals.OBJECTIVES)), []);
});

test('legacy SQLite qualification metadata and candidates remain available with an inert SQLite database fixture', () => {
  route._internals.setOwnedResourcesForTests(null);
  databaseFixture.engine = 'sqlite';
  try {
    const value = route._internals.qualificationFor(route._internals.OBJECTIVES);
    assert.equal(value.mode, 'legacy'); assert.equal(value.version, null);
    assert.ok(value.objectives.every(item => item.qualified === null));
    assert.deepEqual(route._internals.qualifiedObjectiveCandidates(
      ['mcp_ssrf', 'mcp_shadow_server'], new Set(['mcp_ssrf', 'mcp_shadow_server'])),
      ['mcp_ssrf', 'mcp_shadow_server']);
  } finally { databaseFixture.engine = 'postgres'; }
});

test('protected qualification still intersects grading candidates with instructor visibility', () => {
  const { createOwnedQualification, PROTECTED_STATE_CAPABILITY } = require('../server/services/mcp/ownedQualification');
  const qualification = createOwnedQualification(true, { protectedStateCapability: PROTECTED_STATE_CAPABILITY });
  route._internals.setOwnedResourcesForTests({ enabled: true, qualification });
  assert.deepEqual(route._internals.qualifiedObjectiveCandidates(
    ['mcp_secret_exposure', 'mcp_broken_authz', 'mcp_ssrf'], new Set(['mcp_secret_exposure', 'mcp_ssrf']), qualification),
    ['mcp_secret_exposure']);
  route._internals.setOwnedResourcesForTests(null);
});

test('observed candidate projection preserves catalog order while retaining the exact qualified set', () => {
  const { createOwnedQualification, PROTECTED_STATE_CAPABILITY, OBSERVED_ACTION_CAPABILITY,
    OBSERVED_ACTION_QUALIFIED_OBJECTIVES } = require('../server/services/mcp/ownedQualification');
  const qualification = createOwnedQualification(true, { protectedStateCapability: PROTECTED_STATE_CAPABILITY,
    observedActionCapability: OBSERVED_ACTION_CAPABILITY, enableObservedAction: true });
  route._internals.setOwnedResourcesForTests({ enabled: true, qualification });
  const projected = route._internals.qualificationFor(route._internals.OBJECTIVES).objectives
    .filter(item => item.qualified).map(item => item.objectiveId);
  assert.equal(projected.length, OBSERVED_ACTION_QUALIFIED_OBJECTIVES.length);
  assert.deepEqual(new Set(projected), new Set(OBSERVED_ACTION_QUALIFIED_OBJECTIVES));
  assert.notDeepEqual(projected, OBSERVED_ACTION_QUALIFIED_OBJECTIVES);
  route._internals.setOwnedResourcesForTests(null);
});

test('compound poisoned action projects ordered status and read activity without leaking into status', () => {
  const protectedFixture = 'SYNTHETIC_MCP_PROTECTED_VALUE_FOR_UNIT_ONLY';
  const observed = { toolUsed: 'check_system_status', auditEnabled: true, toolResult: {
    args: {}, observationOutput: 'System status: HEALTHY', observationReal: true,
    observationError: null, observationBlocked: false, consequenceOutput: protectedFixture,
    modelAction: { tool: 'read_file', params: { path: '/var/secrets/master_key.txt' } },
    selectedArgs: { path: '/var/secrets/master_key.txt' }, objective: 'mcp_tool_poisoning', achieved: true,
    real: true, error: null, blocked: false,
  } };
  const records = route._internals.activityRecordsForObservation(observed);
  assert.deepEqual(records.map(item => item.toolUsed), ['check_system_status', 'read_file']);
  assert.equal(records[0].toolResult.output, 'System status: HEALTHY');
  assert.equal(records[0].toolResult.real, true); assert.equal(records[0].toolResult.blocked, false);
  assert.equal(records[0].toolResult.output.includes(protectedFixture), false);
  assert.deepEqual(records[1].args, { path: '/var/secrets/master_key.txt' });
  assert.equal(records[1].toolResult.output, protectedFixture);
  assert.equal(records[1].toolResult.objective, 'mcp_tool_poisoning');
  const representativePostgresRow = { ...records[1], args: JSON.stringify(records[1].args), success: 1 };
  assert.deepEqual(JSON.parse(representativePostgresRow.args), { path: '/var/secrets/master_key.txt' });
  assert.equal(representativePostgresRow.success, 1);
});

test('candidate runtime installer uses an explicit test-only qualification without widening production activation', () => {
  const qualification = Object.freeze({ version: 'mcp-owned-protected-candidate.v1',
    qualifiedObjectives: Object.freeze(['mcp_secret_exposure']), canGrade: id => id === 'mcp_secret_exposure' });
  const incomplete = { enabled: true, qualification, admitChat() {}, readOnly() {}, readiness() {}, reset() {}, state() {} };
  const requests = { admit() {}, complete() {} };
  const conversations = { list() {}, clearBeforeCurrentGeneration() {} };
  assert.throws(() => route._internals.installOwnedRuntimeForQualificationForTests(
    { application: incomplete, requests, conversations }, qualification), /Complete qualified MCP owned runtime/);
  const productionQualification = require('../server/services/mcp/ownedQualification').createOwnedQualification(true);
  assert.throws(() => route.installOwnedResources({ ...incomplete, qualification: productionQualification }),
    /Qualified MCP owned-resource application/);

  const application = { ...incomplete, retireOwner() {} };
  assert.throws(() => route.installOwnedRuntime({ application, requests, conversations }),
    /Complete qualified MCP owned runtime/);
  route._internals.installOwnedRuntimeForQualificationForTests({ application, requests, conversations }, qualification);
  assert.deepEqual(route._internals.qualificationFor(['mcp_secret_exposure']).objectives,
    [{ objectiveId: 'mcp_secret_exposure', qualified: true }]);
  route._internals.setConversationPersistenceForTests(null);
  route._internals.setOwnedResourcesForTests(null);

  const productionApplication = { ...incomplete, qualification: productionQualification, retireOwner() {} };
  route.installOwnedResources(productionApplication);
  assert.equal(route._internals.qualificationFor(['mcp_recon']).version, productionQualification.version);
  route._internals.setOwnedResourcesForTests(null);
});

test('owned learner chat requires a UUID and crosses durable request persistence before returning', async () => {
  const qualification = require('../server/services/mcp/ownedQualification').createOwnedQualification(true);
  let admissions = 0;
  const application = { enabled: true, qualification, async admitChat(_req, execution) {
    admissions += 1;
    return { execution, sandbox: {}, protocol: {}, state: () => ({ auditEnabled: true, sentReports: [],
      installedPlugins: [], registeredServers: [], shadowTools: [] }) };
  } };
  const calls = [];
  route._internals.setOwnedResourcesForTests(application);
  route._internals.setConversationPersistenceForTests({ service: { async execute(input) {
    calls.push(input); return { success: true, response: 'persisted owned response', completedObjectives: [] };
  } } });
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(1));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/workshop/mcp/chat`;
    const missing = await fetch(base, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'run ls' }) });
    assert.equal(missing.status, 400); assert.equal(calls.length, 0); assert.equal(admissions, 0);
    for (const body of [
      { message: { command: 'run ls' }, requestId: '423e4567-e89b-42d3-a456-426614174000' },
      { message: ['run ls'], requestId: '423e4567-e89b-42d3-a456-426614174000' },
      { message: ' '.repeat(10), requestId: '423e4567-e89b-42d3-a456-426614174000' },
      { message: 'x'.repeat(16385), requestId: '423e4567-e89b-42d3-a456-426614174000' },
    ]) {
      const malformed = await fetch(base, { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body) });
      assert.equal(malformed.status, 400); assert.equal(calls.length, 0); assert.equal(admissions, 0);
    }
    const requestId = '423e4567-e89b-42d3-a456-426614174000';
    const response = await fetch(base, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'run ls', requestId }) });
    assert.equal(response.status, 200); assert.equal((await response.json()).response, 'persisted owned response');
    assert.equal(calls.length, 1); assert.equal(admissions, 1);
    assert.equal(calls[0].userId, 1); assert.equal(calls[0].requestId, requestId);
  } finally {
    route._internals.setConversationPersistenceForTests(null);
    route._internals.setOwnedResourcesForTests(null);
    await new Promise(resolve => server.close(resolve));
  }
});

test('owned infrastructure reports only its qualified live subset without probing legacy sidecars', async () => {
  const qualification = require('../server/services/mcp/ownedQualification').createOwnedQualification(true);
  const sandboxRunner = require('../server/services/mcp/sandboxRunnerClient');
  const probes = require('../server/services/mcp/_probes');
  const originalHealth = sandboxRunner.health; const originalProbe = probes.http;
  const originalOwnedTargetUrl = process.env.MCP_OWNED_TARGET_URL;
  process.env.MCP_OWNED_TARGET_URL = 'http://127.0.0.1:59999';
  let legacyProbes = 0;
  let ready = true;
  sandboxRunner.health = async () => { legacyProbes += 1; throw new Error('legacy runner must not be probed'); };
  probes.http = async () => { legacyProbes += 1; throw new Error('legacy sidecar must not be probed'); };
  route._internals.setOwnedResourcesForTests({ enabled: true, qualification,
    async readiness() { return { ready, runnerReady: ready, mailReady: true,
      runnerIsolation: 'bwrap-seccomp-v1', runnerEndpoint: 'http://127.0.0.1:48123/' }; } });
  const app = express(); app.use(fixturePlatformUser(1));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/mcp/infra`);
    const body = await response.json(); assert.equal(response.status, 200, JSON.stringify(body));
    assert.equal(body.mode, 'real'); assert.equal(body.sidecars.length, 2); assert.equal(legacyProbes, 0);
    assert.equal(body.sidecars[0].url, 'http://127.0.0.1:48123/');
    assert.deepEqual(body.runtimeQualification.qualifiedObjectives,
      ['mcp_cmd_injection', 'mcp_confused_deputy']);
    assert.match(body.note, /2 exercises[\s\S]*other 9 catalog objectives remain visible but unavailable/i);
    assert.deepEqual(body.sidecars[0].objectives, ['Command Injection']);
    assert.deepEqual(body.sidecars[1].objectives, ['Confused Deputy']);
    ready = false;
    const unavailable = await (await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/mcp/infra`)).json();
    assert.equal(unavailable.mode, 'unavailable');
    assert.equal(unavailable.sidecars[0].up, false);
    assert.doesNotMatch(unavailable.note, /Qualified subset ready/);
    assert.deepEqual(unavailable.runtimeQualification.qualifiedObjectives, qualification.qualifiedObjectives);
    assert.equal(legacyProbes, 0);
  } finally {
    sandboxRunner.health = originalHealth; probes.http = originalProbe;
    if (originalOwnedTargetUrl === undefined) delete process.env.MCP_OWNED_TARGET_URL;
    else process.env.MCP_OWNED_TARGET_URL = originalOwnedTargetUrl;
    route._internals.setOwnedResourcesForTests(null); await new Promise(resolve => server.close(resolve));
  }
});

test('mounted conversation supplies admitted owned sandbox and protocol to the actual turn boundary', async () => {
  const sentinelSandbox = Object.freeze({ kind: 'owned-sandbox' });
  const sentinelProtocol = Object.freeze({ kind: 'owned-protocol' });
  const sentinelObserver = async () => ({ confusedDeputyWitness: { fixture: true } });
  const application = { enabled: true, async admitChat(req, execution) {
    assert.equal(req.user.id, 1); assert.equal(execution.ownerKey, JSON.stringify(['MCP', '1']));
    return { sandbox: sentinelSandbox, protocol: sentinelProtocol, execution, observeObjective: sentinelObserver,
      state: () => ({ auditEnabled: true, sentReports: [], installedPlugins: [], registeredServers: [], shadowTools: [] }) };
  }, state() { return { auditEnabled: true, sentReports: [], installedPlugins: [], registeredServers: [], shadowTools: [] }; } };
  route._internals.setOwnedResourcesForTests(application);
  let completed = 0;
  const requests = { async admit() { return { state: 'admitted' }; }, async complete() { completed += 1; } };
  const conversations = { async list() { return []; }, async clearBeforeCurrentGeneration() { return { removedTurns: 0 }; } };
  const service = { async execute(_request, perform) { const result = await perform({ history: [] }); completed += 1; return result; } };
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(1));
  app.use('/conversation', route.createConversationRouter({ requests, conversations, service,
    perform: async ({ sandbox, protocolManager, stateReader, objectiveObserver }) => {
      assert.equal(sandbox, sentinelSandbox); assert.equal(protocolManager, sentinelProtocol);
      assert.equal(objectiveObserver, sentinelObserver);
      assert.equal(stateReader().auditEnabled, true); return { response: 'owned path observed' };
    } }));
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/conversation/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ requestId: '123e4567-e89b-42d3-a456-426614174000', message: 'safe owned control' }),
    });
    assert.equal(response.status, 200, await response.text()); assert.equal(completed, 1);
  } finally {
    route._internals.setOwnedResourcesForTests(null); await new Promise(resolve => server.close(resolve));
  }
});

test('mounted conversation checks owned readiness before durable request admission', async () => {
  const f = candidate({ ready: false }); route._internals.setOwnedResourcesForTests(f.app);
  let requestAdmissions = 0;
  const requests = { async admit() { requestAdmissions += 1; throw new Error('not reached'); }, async complete() {} };
  const conversations = { async list() { return []; }, async clearBeforeCurrentGeneration() { return {}; } };
  const app = express(); app.use(express.json()); app.use(fixturePlatformUser(1));
  app.use('/conversation', route.createConversationRouter({ requests, conversations }));
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/conversation/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ requestId: '223e4567-e89b-42d3-a456-426614174000', message: 'must not persist' }),
    });
    assert.equal(response.status, 503); assert.equal(requestAdmissions, 0); assert.equal(f.allocations(), 0);
  } finally { route._internals.setOwnedResourcesForTests(null); await new Promise(resolve => server.close(resolve)); }
});

test('mounted conversation records only safe internal failure coordinates while public response stays generic', async () => {
  const diagnostics = [];
  const application = { enabled: true, async admitChat() { return { sandbox: {}, protocol: {} }; }, state() { return {}; } };
  route._internals.setOwnedResourcesForTests(application);
  const requests = { async admit() { return { state: 'admitted' }; } };
  const conversations = { async list() { return []; } };
  const service = { async execute(_input, perform) {
    try { return await perform({ history: [] }); }
    catch (error) { Object.defineProperty(error, 'mcpConversationStage', { value: 'actor_turn' }); throw error; }
  } };
  const app = express(); app.use(express.json()); app.use(fixturePlatformUser(1));
  app.use('/conversation', route.createConversationRouter({ requests, conversations, service,
    diagnose: event => diagnostics.push(event), perform: async () => {
      throw Object.assign(new Error('private SMTP host and payload must stay private'), { code: 'MCP_MAIL_UNCERTAIN' });
    } }));
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const requestId = '323e4567-e89b-42d3-a456-426614174000';
    const response = await fetch(`http://127.0.0.1:${server.address().port}/conversation/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ requestId, message: 'send' }),
    });
    assert.equal(response.status, 503); assert.deepEqual(await response.json(),
      { code: 'CONVERSATION_UNAVAILABLE', error: 'Conversation service is unavailable' });
    assert.equal(diagnostics.length, 1);
    assert.deepEqual(diagnostics[0], { version: 1, ownerId: 1, requestId,
      runId: diagnostics[0].runId, stage: 'actor_turn', errorCode: 'MCP_MAIL_UNCERTAIN', errorType: 'Error' });
    assert.match(diagnostics[0].runId, /^[a-f0-9-]{36}$/); assert.ok(!JSON.stringify(diagnostics).includes('SMTP host'));
  } finally { route._internals.setOwnedResourcesForTests(null); await new Promise(resolve => server.close(resolve)); }
});

test('mounted Inspector and Streamable HTTP use the admitted session-bound execution', async () => {
  let effects = 0;
  const revoked = () => { throw Object.assign(new Error('durable session revoked'), { code: 'MCP_PLATFORM_SESSION_REQUIRED' }); };
  const protocol = {
    async callTool(_session, _name, _args, { execution }) { await execution.check(); effects += 1; return { output: 'unsafe' }; },
    async listTools(_session, { execution }) { await execution.check(); effects += 1; return []; },
    async handleHttp(_session, _req, _res, { execution }) { await execution.check(); effects += 1; },
  };
  const application = { enabled: true, async admitChat(_req, execution) {
    return { sandbox: {}, protocol, execution: Object.freeze({ ...execution, check: async () => revoked() }), state: () => ({}) };
  }, async readOnly() {}, async reset() {}, state() {} };
  route._internals.setOwnedResourcesForTests(application);
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(1)); app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/workshop/mcp`;
    const inspector = await fetch(`${base}/jsonrpc`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'run_command', arguments: { command: 'pwd' } } }) });
    assert.equal(inspector.status, 500); assert.equal(effects, 0);
    const transport = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) });
    assert.equal(transport.status, 500); assert.equal(effects, 0);
  } finally { route._internals.setOwnedResourcesForTests(null); await new Promise(resolve => server.close(resolve)); }
});

test('enabled catalog and captured-effects reads never fall back after exact-session admission fails', async () => {
  let reads = 0;
  const unavailable = Object.assign(new Error('current binding unavailable'),
    { code: 'MCP_OWNED_RESOURCE_SCOPE_INVALID', statusCode: 409 });
  const application = { enabled: true, async admitChat() { throw unavailable; },
    async readOnly() { reads += 1; throw unavailable; }, async reset() {}, state() {} };
  route._internals.setOwnedResourcesForTests(application);
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(1));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    for (const pathname of ['/tools', '/exfil']) {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/mcp${pathname}`);
      assert.equal(response.status, 409);
      assert.deepEqual(await response.json(), pathname === '/tools'
        ? { error: 'MCP_OWNED_RESOURCE_SCOPE_INVALID' }
        : { success: false, error: 'MCP_OWNED_RESOURCE_SCOPE_INVALID' });
    }
    assert.equal(reads, 2);
  } finally { route._internals.setOwnedResourcesForTests(null); await new Promise(resolve => server.close(resolve)); }
});

test('enabled catalog and captured-effects reads use the exact owned session projections', async () => {
  const sandbox = { toolListTools: () => [{ name: 'session_tool', description: 'Only this binding', rogue: true }] };
  const state = { auditEnabled: false, sentReports: [{ to: 'outside@example.test', delivered: true }],
    installedPlugins: ['owned'], registeredServers: [], shadowTools: [], exfil: [] };
  const application = { enabled: true, async admitChat() {}, async reset() {}, state() {},
    async readOnly() { return { sandbox, state: () => state,
      realExecution: { available: true, isolation: 'bwrap-seccomp-v1', bwrap: true },
      async mailProjection() { return { ok: true, messages: [{ id: 'owned-mail' }] }; } }; } };
  route._internals.setOwnedResourcesForTests(application);
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(1));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const tools = await (await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/mcp/tools`)).json();
    assert.deepEqual(tools.tools.map(item => item.name), ['session_tool']);
    const exfil = await (await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/mcp/exfil`)).json();
    assert.deepEqual(exfil.state, state); assert.deepEqual(exfil.deliveredMail, [{ id: 'owned-mail' }]);
    assert.deepEqual(exfil.realExecution, { available: true, isolation: 'bwrap-seccomp-v1', bwrap: true });
    assert.equal(exfil.mailSinkAvailable, true);
  } finally { route._internals.setOwnedResourcesForTests(null); await new Promise(resolve => server.close(resolve)); }
});

test('compound ticket activity retains separate read and proposed report args and outcomes', () => {
  for (const delivered of [false, true]) {
    const params = { to: 'owned@example.invalid', body: 'Exact model text.' };
    const effect = { tool: 'send_report', args: params, output: delivered ? 'delivered bytes' : 'recipient absent from ticket',
      error: delivered ? null : 'recipient absent from ticket', blocked: !delivered, real: delivered,
      achieved: delivered, objective: 'mcp_indirect_injection' };
    const compound = { ...effect, tool: 'read_ticket', args: { id: delivered ? '4295' : '4290' },
      observationOutput: 'Actual ticket bytes', observationReal: true, observationError: null, observationBlocked: false,
      consequenceOutput: effect.output, modelAction: { tool: effect.tool, params } };
    const records = route._internals.activityRecordsForObservation({ toolUsed: 'read_ticket', toolResult: compound });
    assert.deepEqual(records.map(row => row.toolUsed), ['read_ticket', 'send_report']);
    assert.deepEqual(records[0].args, compound.args);assert.deepEqual(records[1].args, params);
    assert.equal(records[0].toolResult.output, 'Actual ticket bytes');
    assert.equal(records[0].toolResult.error, null);assert.equal(records[0].toolResult.achieved, false);
    assert.equal(records[1].toolResult.output, effect.output);assert.equal(records[1].toolResult.error, effect.error);
    assert.equal(records[1].toolResult.blocked, !delivered);assert.equal(records[1].toolResult.achieved, delivered);
  }
});


test('PostgreSQL owner reset requires authoritative retirement before caller mutation, including default-off owners', async () => {
  const priorProof = retirementProof;
  try {
    route._internals.setOwnedResourcesForTests(null);
    retirementEvents.length = 0;
    retirementProof = async ({ platformOwnerId }) => {
      retirementEvents.push(['proof', platformOwnerId]);
      return Object.freeze({ platformOwnerId, status: 'retired', targetCount: 0, mailIntentCount: 0 });
    };
    await route.resetOwner('7', async () => retirementEvents.push(['clear']));
    assert.deepEqual(retirementEvents, [['proof', 7], ['clear']]);

    for (const failure of [Object.assign(Error('debt'), { code: 'MCP_OWNER_RESOURCES_PENDING' }),
      Error('repository unavailable')]) {
      retirementEvents.length = 0; retirementProof = async () => { throw failure; };
      await assert.rejects(route.resetOwner('7', async () => retirementEvents.push(['clear'])));
      assert.deepEqual(retirementEvents, []);
    }

    let pending = true; let checks = 0;
    const check = async () => { checks++; };
    retirementProof = async ({ platformOwnerId }) => {
      retirementEvents.push(['proof', platformOwnerId]);
      if (pending) throw Object.assign(Error('debt'), { code: 'MCP_OWNER_RESOURCES_PENDING' });
      return { platformOwnerId, status: 'retired', targetCount: 1, mailIntentCount: 1 };
    };
    route._internals.setOwnedResourcesForTests({ enabled: true, async retireOwner(input) {
      assert.equal(input.platformOwnerId, 7); assert.equal(typeof input.check, 'function');
      retirementEvents.push(['retire', 7]);
      const priorChecks = checks; await input.check();
      assert.equal(checks, priorChecks + 1, 'Composed authority invokes the supplied deletion check');
      pending = false;
      return { ok: true, receipts: [] };
    } });
    retirementEvents.length = 0;
    await route.resetOwner('7', async () => retirementEvents.push(['clear']), { check });
    assert.deepEqual(retirementEvents, [['proof', 7], ['retire', 7], ['proof', 7], ['clear']]);
    assert.ok(checks >= 6);

    retirementEvents.length = 0;
    await route.resetOwner('7', async () => retirementEvents.push(['clear']), { check });
    assert.deepEqual(retirementEvents, [['proof', 7], ['retire', 7], ['proof', 7], ['clear']],
      'Already-retired durable state must still reconcile enabled in-memory context');

    pending = true; retirementEvents.length = 0;
    route._internals.setOwnedResourcesForTests({ enabled: true, async retireOwner() {
      retirementEvents.push(['retire-failed']); throw Error('runner unavailable');
    } });
    await assert.rejects(route.resetOwner('7', async () => retirementEvents.push(['clear'])));
    assert.deepEqual(retirementEvents, [['proof', 7], ['retire-failed']]);

    retirementEvents.length = 0;
    await assert.rejects(route.resetOwner('7', async () => retirementEvents.push(['clear']),
      { check: async () => { throw Error('lease lost'); } }), /lease lost/);
    assert.deepEqual(retirementEvents, []);
  } finally { retirementProof = priorProof; route._internals.setOwnedResourcesForTests(null); }
});

test('resource-free PostgreSQL student reset works without owned runtime and never touches the legacy sandbox', async () => {
  const previous = retirementProof;
  route._internals.setOwnedResourcesForTests(null); retirementEvents.length = 0;
  retirementProof = async ({ platformOwnerId }) => {
    retirementEvents.push(['proof', platformOwnerId]);
    return { platformOwnerId, status: 'retired', targetCount: 0, mailIntentCount: 0 };
  };
  const sandbox = require('../server/services/mcp/sandboxShell'), priorReset = sandbox.resetSandbox;
  sandbox.resetSandbox = () => { throw Error('legacy cleanup forbidden'); };
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(7));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/mcp/progress/reset`,
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(response.status, 200); assert.deepEqual(await response.json(), { success: true });
    assert.deepEqual(retirementEvents, [['proof', 7], ['store', '7'], ['canonical']]);
  } finally {
    retirementProof = previous;
    sandbox.resetSandbox = priorReset; await new Promise(resolve => server.close(resolve));
  }
});

test('already-retired PostgreSQL learner reset still validates the genuine current platform session', async () => {
  const previous = retirementProof;
  retirementEvents.length = 0;
  retirementProof = async ({ platformOwnerId }) => {
    retirementEvents.push(['proof', platformOwnerId]);
    return { platformOwnerId, status: 'retired', targetCount: 0, mailIntentCount: 0 };
  };
  const stale = Object.assign(new Error('Platform session is stale'), {
    code: 'MCP_PLATFORM_SESSION_STALE', statusCode: 409,
  });
  const fixture = candidate({ ready: true, owner: 7, assertCurrent: async () => {
    retirementEvents.push(['session-check', 7]); throw stale;
  } });
  route._internals.setOwnedResourcesForTests(fixture.app);
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(7));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/mcp/progress/reset`,
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { success: false, code: 'RESET_INCOMPLETE',
      failedSteps: ['resources'], error: 'Reset cleanup is incomplete. Retry the reset.' });
    assert.deepEqual(retirementEvents, [['proof', 7], ['session-check', 7]]);
  } finally {
    retirementProof = previous; route._internals.setOwnedResourcesForTests(null);
    await new Promise(resolve => server.close(resolve));
  }
});

test('mounted learner reset cannot clear progress after a same-owner reset supersedes its lease', async () => {
  const previous = retirementProof;
  retirementEvents.length = 0;
  retirementProof = async ({ platformOwnerId }) => {
    retirementEvents.push(['proof', platformOwnerId]);
    return { platformOwnerId, status: 'retired', targetCount: 0, mailIntentCount: 0 };
  };
  let successor;
  route._internals.setOwnedResourcesForTests({
    enabled: true,
    async reset(request, { check } = {}) {
      assert.equal(request.user.id, 7);
      assert.equal(typeof check, 'function');
      retirementEvents.push(['learner-retired', 7]);
      successor = route.resetOwner('7', async execution => {
        assert.equal(typeof execution?.check, 'function');
        await execution.check();
        retirementEvents.push(['successor-clear', 7]);
      });
      return { ok: true, receipts: [] };
    },
    async retireOwner({ platformOwnerId, check } = {}) {
      assert.equal(platformOwnerId, 7); assert.equal(typeof check, 'function');
      await check(); retirementEvents.push(['successor-retired', 7]);
      return { ok: true, receipts: [] };
    },
  });
  const app = express(); app.use(express.json());
  app.use(fixturePlatformUser(7));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/mcp/progress/reset`,
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), { error: 'Request invalidated by reset' });
    assert.ok(successor instanceof Promise, 'the owned reset must start the same-owner successor');
    await successor;
    assert.deepEqual(retirementEvents, [
      ['proof', 7], ['learner-retired', 7],
      ['proof', 7], ['successor-retired', 7], ['proof', 7], ['successor-clear', 7],
    ]);
    assert.equal(retirementEvents.some(([name]) => name === 'store' || name === 'canonical'), false);
  } finally {
    if (successor) await successor.catch(() => {});
    retirementProof = previous; route._internals.setOwnedResourcesForTests(null);
    await new Promise(resolve => server.close(resolve));
  }
});


test('mounted grading uses owner mode, never request or process mode, and fences a mid-turn mode change', async () => {
  const agent = require('../server/services/mcp/workshopAgent');
  const previousChat = agent.chat, previousMode = process.env.LAB_MODE;
  const modes = []; const histories = []; let calls = 0;
  const application = { enabled: true,
    qualification: require('../server/services/mcp/ownedQualification').createOwnedQualification(true),
    admitChat: async () => ({ state: () => ({ auditEnabled: true }) }) };
  visibleObjectives = { mcp_cmd_injection: { isVisible: true } };
  route._internals.setObjectiveGraderForTests({ begin: async () => null, evaluate: async input => {
    modes.push(input.mode); return { completed: false, judgment: { mode: input.mode, verdict: 'fail' } };
  } });
  const result = { response: 'Controlled mode routing fixture', objectivesHit: ['mcp_cmd_injection'] };
  agent.chat = async (_owner, _session, _message, _legacy, options) => {
    calls += 1; histories.push(options.conversationHistory); return result;
  };
  try {
    for (const mode of ['fixed', 'vuln']) {
      selectedModeScope = { generation: 0, mode, modeStamp: mode };
      process.env.LAB_MODE = mode === 'fixed' ? 'vuln' : 'fixed';
      const response = await post(application, { message: 'fixture', mode: mode === 'fixed' ? 'vuln' : 'fixed' });
      assert.equal(response.status, 200); assert.deepEqual(response.body.judgments, [{ mode, verdict: 'fail' }]);
    }
    assert.deepEqual(modes, ['fixed', 'vuln']);
    assert.deepEqual(histories, [undefined, []]);
    selectedModeScope = { generation: 0, mode: 'invalid', modeStamp: 'invalid' };
    const invalid = await post(application, { message: 'fixture', mode: 'vuln' });
    assert.equal(invalid.status, 503); assert.equal(invalid.body.error, 'WORKSHOP_MODE_SCOPE_UNAVAILABLE');
    assert.equal(calls, 2); assert.equal(modes.length, 2);
    selectedModeScope = { generation: 0, mode: 'vuln', modeStamp: 'before' };
    agent.chat = async () => { selectedModeScope.modeStamp = 'after'; return result; };
    const changed = await post(application);
    assert.equal(changed.status, 409); assert.equal(changed.body.error, 'WORKSHOP_MODE_CHANGED');
    assert.equal(modes.length, 2);
  } finally {
    agent.chat = previousChat; visibleObjectives = {};
    selectedModeScope = { generation: 0, mode: null, modeStamp: 'default' };
    if (previousMode === undefined) delete process.env.LAB_MODE; else process.env.LAB_MODE = previousMode;
    route._internals.setObjectiveGraderForTests({ begin: async () => null, evaluate: async () => ({ completed: false, judgment: {} }) });
  }
});

test('mounted MCP mode endpoint persists authenticated chat mode without clearing workshop progress', async () => {
  let persisted = null;
  let writes = 0;
  const service = {
    getMode: async ({ userId, workshopKey }) => {
      assert.equal(userId, 1); assert.equal(workshopKey, 'mcp_workshop'); return persisted;
    },
    setMode: async ({ userId, workshopKey, mode }) => {
      assert.equal(userId, 1); assert.equal(workshopKey, 'mcp_workshop');
      if (!['vuln', 'fixed'].includes(mode)) throw new TypeError('Invalid mode');
      persisted = mode; writes += 1; return mode;
    },
  };
  route._internals.setModeAuthorityForTests({ service });
  const app = express(); app.use(express.json()); app.use(fixturePlatformUser(1));
  app.use('/api/workshop/mcp', route);
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/api/workshop/mcp/mode`;
  const priorRetirementEvents = retirementEvents.slice();
  try {
    const initial = await fetch(url).then(response => response.json());
    assert.equal(initial.mode, null); assert.equal(initial.effectiveMode, 'vuln');
    assert.deepEqual(initial.selectableModes, ['vuln', 'fixed']);
    assert.deepEqual(initial.scope, { kind: 'chat', id: 'mcp_assistant' });
    const changed = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ mode: 'fixed', userId: 999 }) });
    assert.equal(changed.status, 200);
    assert.equal((await changed.json()).effectiveMode, 'fixed');
    assert.equal(writes, 1);
    assert.equal((await fetch(url).then(response => response.json())).mode, 'fixed');
    assert.deepEqual(retirementEvents, priorRetirementEvents,
      'a mode transition must not reset completions or owner artifacts');
  } finally {
    route._internals.setModeAuthorityForTests({ service: require('../server/services/workshopModeService') });
    await new Promise(resolve => server.close(resolve));
  }
});

test('mounted audit disable and clear retain logging-control activity while suppressing ordinary activity', async () => {
  const agent=require('../server/services/mcp/workshopAgent'),previous=agent.chat,oldLog=databaseFixture.logToolCall;
  const history=[{toolName:'prior_platform_event',resultSummary:'retained'}],original=JSON.stringify(history);
  databaseFixture.logToolCall=async row=>history.push(row);
  const application={enabled:true,qualification:require('../server/services/mcp/ownedQualification').createOwnedQualification(true),admitChat:async()=>({state:()=>({auditEnabled:false})})};
  try {
    for(const action of ['disable','clear']){
      agent.chat=async()=>({response:'Controlled audit observation',objectivesHit:[],toolObservations:[
        {toolUsed:'set_audit_logging',auditEnabled:false,toolResult:{args:{action},output:'Target telemetry changed'}},
        {toolUsed:'read_file',auditEnabled:false,toolResult:{args:{path:'/synthetic'},output:'Controlled read'}}
      ]});
      const response=await post(application,{message:'Controlled audit lesson'});assert.equal(response.status,200);
      assert.equal(JSON.stringify(history.slice(0,1)),original,'clear cannot erase prior platform activity');
    }
    assert.deepEqual(history.slice(1).map(x=>x.toolName),['set_audit_logging','set_audit_logging']);
    assert.deepEqual(history.slice(1).map(x=>JSON.parse(x.args).action),['disable','clear']);
  } finally {agent.chat=previous;if(oldLog===undefined)delete databaseFixture.logToolCall;else databaseFixture.logToolCall=oldLog;}
});
