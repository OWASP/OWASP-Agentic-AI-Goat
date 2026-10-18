'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const C = require('../server/services/secureshopRoleMcpRegistryProposal');
const R = require('../server/services/secureshopMcpRegistryContract');
const { createBoundMcpRegistryChat } = require('../server/services/secureshopBoundMcpRegistryChat');
const { createOwnedMcpRegistry } = require('../server/services/secureshopOwnedMcpRegistry');
const { createOwnedMcpRegistryAdminReadOverlay } = require('../server/services/secureshopOwnedMcpRegistryAdminReadOverlay');
const { mcpSchemaDigest } = require('../server/services/secureshopMcpSchemaDigest');
const jsonb = v => Array.isArray(v) ? v.map(jsonb) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().reverse().map(k => [k, jsonb(v[k])])) : v;
const modeCapability = { version: 1, featureId: 'admin_assistant', policyVersion: 'owned-admin-read-and-confirmation-v1',
  effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const candidate = { name: 'catalog', transport: 'sse', url: 'http://owned.invalid/mcp', stdio_cmd: '' };
function fixture() {
  const context = { scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 1, platformSessionId: 2 }, persona: { id: 3, role: 'admin' },
  personaSession: { sessionId: randomUUID(), authorityVersion: '1' } };
  let head = '0', mode = 'vuln', enabled = true, revoked = false, executionError, publicationError;
  let executions = 0, admissions = 0;
  const entries = [], scenarios = [], operations = new Map(), history = [], events = [];
  const tools = [{ name: 'search', description: 'Synthetic catalog tool', inputSchema: { type: 'object', properties: {} } }];
  const check = input => { if (revoked || (input && JSON.stringify(input.personaSession) !== JSON.stringify(context.personaSession)))
    throw Object.assign(Error('authority unavailable'), { code: 'STALE_AUTHORITY' }); };
  const repository = {
    prepare(raw) { check(raw); return { ...structuredClone(raw), request: R.normalizeRegistryRequest(raw.request) }; },
    async beginPrepared(prepared) {
      check(prepared); admissions++; const r = prepared.request, prior = operations.get(r.operationId);
      if (prior) { assert.deepEqual(prior.request, r); return { newlyAdmitted: false, operation: { ...prior.result, replayed: true } }; }
      if (r.expectedVersion !== head) throw Object.assign(Error('stale'), { code: 'MCP_REGISTRY_OPERATION_CONFLICT' });
      const result = { version: 'secureshop-owned-mcp-registry.v1', operationId: r.operationId,
        state: 'admitted', action: r.action, requestSha256: R.registryRequestDigest(r), replayed: false };
      operations.set(r.operationId, { request: r, result });
      return { newlyAdmitted: true, prepared, fence: { assertRemoteAdmission: async () => check(prepared) } };
    },
    async activeEntries() { return structuredClone(entries); },
    async publish(admission, changes) {
      if (publicationError) throw publicationError;
      const r = admission.prepared.request; head = String(BigInt(head) + 1n);
      const row = operations.get(r.operationId); row.result = { ...row.result, state: 'completed', registryVersion: head, changes };
      return jsonb(row.result);
    },
    async finish(admission, state) { const row = operations.get(admission.prepared.request.operationId); row.result.state = state; },
    async read(input) { check(input); const row = operations.get(input.operationId);
      if (!row) throw Object.assign(Error('not found'), { code: 'MCP_REGISTRY_OPERATION_NOT_FOUND' });
      return jsonb({ ...row.result, replayed: true }); },
  };
  const executor = { async execute(r, options) { executions++; events.push('execute');
    if (executionError) throw executionError;
    const old = entries.find(e => e.name === r.name);
    // Controlled stand-in for the existing mode-specific replacement policy.
    if (old && options.mode === 'fixed') throw Object.assign(Error('replacement denied'), { effectNotStarted: true });
    return [{ name: r.name || 'imported', entryId: old?.id || randomUUID(), action: r.action,
      schemaSha256: r.action === 'retire' ? null : mcpSchemaDigest(tools), effect: { controlled: true } }];
  } };
  const service = createOwnedMcpRegistry({ repository, executor, readMode: async () => mode });
  const base = { async mcpServers() { return { servers: structuredClone(scenarios) }; },
    async mcpHistory() { return { history: [] }; }, async mcpTools(_scope, name) { events.push('scenario-detail');
      return { name, version: '1', schema_hash: mcpSchemaDigest(tools), tools: tools.map(t => ({ tool_name: t.name,
        description: t.description, input_schema_json: JSON.stringify(t.inputSchema) })) }; } };
  const overlay = createOwnedMcpRegistryAdminReadOverlay({ base, enabled: true, repository: {
    async head() { return head; }, async servers() { return structuredClone(entries); }, async history() { return history; },
    async tools(_scope, name) { events.push('owned-detail'); return entries.some(e => e.name === name)
      ? { version: head, schema_hash: mcpSchemaDigest(tools), tools_json: structuredClone(tools) } : null; },
  } });
  const admin = Object.fromEntries(['mcpServers', 'mcpTools', 'mcpHistory'].map(k => [k, async input => {
    check(input); return overlay[k](input.scope, input.name, input.provenance);
  }]));
  const api = createBoundMcpRegistryChat({ admin, getRegistry: async () => enabled ? { service, mode } : null });
  const seed = (name = 'catalog') => { const row = { id: randomUUID(), name, provenance: 'owned_registry',
    transport: 'sse', url: 'http://old.invalid/mcp', stdio_cmd: null, last_schema_hash: mcpSchemaDigest(tools), status: 'registered' };
    entries.push(row); return row; };
  return { api, context, admin, repository, service, entries, scenarios, operations, tools, history, events, seed,
    count: () => ({ executions, admissions }), advance: () => { head = String(BigInt(head) + 1n); },
    setHead: v => { head = v; }, setMode: v => { mode = v; }, disable: () => { enabled = false; },
    revoke: () => { revoked = true; }, executionError: e => { executionError = e; }, publicationError: e => { publicationError = e; } };
}
async function prepare(f, action = 'register', fields = candidate, selection) {
  const source = { sessionId: randomUUID(), requestId: randomUUID() };
  const state = await f.api.snapshot({ context: f.context });
  const s = state.servers[0];
  const selected = selection === undefined ? action === 'retire' ? { choiceId: randomUUID(), id: s.id,
    provenance: s.provenance, snapshotSha256: s.snapshotSha256 } : null : selection;
  const args = { context: f.context, source, origin: { step: 1, callId: 'model-call' }, action,
    selected, candidate: fields, modeCapability };
  return { source, args, proposal: await f.api.prepare(args) };
}
test('prepare is no-effect, canonical JSONB roundtrip preserves exact request and deterministic source UUID', async () => {
  const f = fixture();
  for (const [action, fields] of [['register', candidate], ['register', { name: 'stdio', transport: 'stdio', url: '', stdio_cmd: 'node synthetic.js --teaching' }],
    ['import', { xml_url: 'http://owned.invalid/manifest.xml?lesson=xxe' }]]) {
    const { proposal, source, args } = await prepare(f, action, fields);
    assert.deepEqual(C.validateRoleMcpRegistryProposal(jsonb(proposal), source), proposal);
    assert.deepEqual(await f.api.prepare(args), proposal);
    assert.equal(proposal.requestSha256, R.registryRequestDigest(proposal.request));
    assert.equal(proposal.proposalId, proposal.request.operationId);
    assert.equal(Object.hasOwn(C.projectRoleMcpRegistryProposal(proposal, source), 'origin'), false);
    for (const [key, value] of Object.entries(fields)) assert.equal(proposal.request[key], value);
  }
  assert.deepEqual(f.count(), { executions: 0, admissions: 0 }); assert.equal(f.operations.size, 0);
});
test('MCP09 same-name replacement is truthfully reviewed and existing service controls mode semantics', async () => {
  for (const mode of ['vuln', 'fixed']) {
    const f = fixture(); const old = f.seed(); f.setMode(mode);
    const { proposal, source } = await prepare(f);
    assert.equal(proposal.before.id, old.id); assert.equal(proposal.before.url, old.url);
    assert.equal(proposal.request.url, candidate.url); assert.equal(proposal.choiceId, null);
    assert.equal(proposal.sourceSnapshotSha256, proposal.before.snapshotSha256);
    assert.deepEqual(C.validateRoleMcpRegistryProposal(jsonb(proposal), source), proposal);
    assert.equal(f.count().executions, 0);
    if (mode === 'vuln') assert.equal((await f.api.confirm({ context: f.context, proposal, source })).ok, true);
    else { await assert.rejects(f.api.confirm({ context: f.context, proposal, source }), /replacement denied/);
      assert.equal((await f.api.operation({ context: f.context, operationId: proposal.proposalId })).state, 'failed'); }
  }
});
test('register/import/retire confirm reuse exact existing service receipts and replay after head advance', async () => {
  for (const action of ['register', 'import', 'retire']) {
    const f = fixture(); if (action === 'retire') f.seed();
    const { proposal, source } = await prepare(f, action, action === 'retire' ? null : action === 'import' ? { xml_url: 'http://owned.invalid/x' } : candidate);
    const result = await f.api.confirm({ context: f.context, proposal: jsonb(proposal), source });
    assert.equal(result.ok, true); assert.equal(result.requestSha256, proposal.requestSha256);
    f.advance(); const count = f.count().executions;
    const expected = { ...result, replayed: true };
    assert.deepEqual(await f.api.confirm({ context: f.context, proposal, source }), expected);
    assert.deepEqual(await f.api.operation({ context: f.context, operationId: proposal.proposalId }), expected);
    assert.equal(f.count().executions, count);
  }
});
test('full repeated projection rejects mixed old rows/new head even when the heads match', async () => {
  const f = fixture(); f.seed(); const original = f.admin.mcpServers; let calls = 0;
  f.admin.mcpServers = async input => { const value = await original(input); calls++;
    if (calls === 1) value.servers[0].url = 'http://stale.invalid'; return value; };
  await assert.rejects(f.api.snapshot({ context: f.context }), { code: 'MCP_CHOICE_STALE' });
  assert.equal(calls, 2); assert.equal(f.count().executions, 0);
});
test('detail retains complete schema and provenance even for a scenario shadowed by an owned name', async () => {
  const f = fixture(); f.tools[0].description = 'x'.repeat(18000); f.seed();
  f.scenarios.push({ id: randomUUID(), name: 'catalog', trust_scenario: 'rug_pull',
    last_schema_hash: mcpSchemaDigest(f.tools), status: 'discovered' });
  f.history.push({ name: 'catalog', provenance: 'owned_registry', version: '0', schema_hash: mcpSchemaDigest(f.tools), ts: new Date('2026-10-01') });
  const state = await f.api.snapshot({ context: f.context });
  for (const server of state.servers) {
    const selected = { choiceId: randomUUID(), id: server.id, provenance: server.provenance, snapshotSha256: server.snapshotSha256 };
    const detail = await f.api.detail({ context: f.context, selected });
    assert.equal(detail.tools[0].description.length, 18000); assert.ok(Buffer.byteLength(JSON.stringify(detail)) > 16384);
    assert.equal(detail.history.length, server.provenance === 'owned_registry' ? 1 : 0);
    if (server.provenance === 'scenario') await assert.rejects(prepare(f, 'retire', null, selected), { code: 'MCP_CHOICE_DENIED' });
  }
  assert.deepEqual(f.events, ['owned-detail', 'scenario-detail']);
});
test('detail schema corruption, oversize and revision races deny without truncated authority', async () => {
  for (const kind of ['hash', 'oversize', 'race']) {
    const f = fixture(); f.seed(); const state = await f.api.snapshot({ context: f.context }); const server = state.servers[0];
    const original = f.admin.mcpTools;
    f.admin.mcpTools = async input => { const value = await original(input);
      if (kind === 'hash') value.schema_hash = '0'.repeat(64);
      if (kind === 'oversize') value.tools[0].description = 'x'.repeat(65536);
      if (kind === 'race') f.advance(); return value; };
    await assert.rejects(f.api.detail({ context: f.context, selected: { choiceId: randomUUID(), id: server.id,
      provenance: server.provenance, snapshotSha256: server.snapshotSha256 } }));
    assert.equal(f.count().executions, 0);
  }
});
test('unknown and failed durable outcomes remain non-success, same UUID replay never redispatches', async () => {
  for (const kind of ['executor', 'pre-effect', 'publish']) {
    const f = fixture(); const { proposal, source } = await prepare(f);
    const cause = Object.assign(Error('controlled failure'), kind === 'pre-effect' ? { effectNotStarted: true } : {});
    if (kind === 'publish') f.publicationError(cause); else f.executionError(cause);
    await assert.rejects(f.api.confirm({ context: f.context, proposal, source }));
    const result = await f.api.operation({ context: f.context, operationId: proposal.proposalId });
    assert.equal(result.state, kind === 'pre-effect' ? 'failed' : 'unknown');
    assert.equal(result.ok, false); assert.equal(result.automaticRetry, false);
    assert.deepEqual(await f.api.confirm({ context: f.context, proposal, source }), result);
    assert.equal(f.count().executions, 1);
  }
});
test('current scope/mode/session, stale head, late fence and abort prevent unauthorized effect', async () => {
  for (const kind of ['scope', 'mode', 'session', 'head', 'fence', 'abort']) {
    const f = fixture(); const { proposal, source } = await prepare(f); const context = structuredClone(f.context);
    const abort = new AbortController(); let beforeEffect;
    if (kind === 'scope') context.scope.generation++;
    if (kind === 'mode') f.setMode('fixed');
    if (kind === 'session') context.personaSession.sessionId = randomUUID();
    if (kind === 'head') f.advance();
    if (kind === 'fence') beforeEffect = async () => { throw Error('original scene changed'); };
    if (kind === 'abort') beforeEffect = async () => abort.abort();
    await assert.rejects(f.api.confirm({ context, proposal, source, beforeEffect, signal: abort.signal }));
    assert.equal(f.count().executions, 0); assert.equal(f.operations.size, 0);
  }
});
test('closed proposal rejects forged nested fields, source, replacement snapshot and extra candidate keys', async () => {
  const f = fixture(); f.seed(); const { proposal, source } = await prepare(f);
  for (const p of [{ ...proposal, extra: true }, { ...proposal, action: 'retire' },
    { ...proposal, before: { ...proposal.before, url: 'http://forged.invalid' } },
    { ...proposal, modeCapability: { ...modeCapability, extra: true } },
    { ...proposal, request: { ...proposal.request, stdio_cmd: 'unexpected' } }]) assert.throws(() => C.validateRoleMcpRegistryProposal(p, source));
  assert.throws(() => C.validateRoleMcpRegistryProposal(proposal, { ...source, requestId: randomUUID() }));
  await assert.rejects(prepare(f, 'register', { ...candidate, owner: 'other' }));
  await assert.rejects(prepare(f, 'import', { xml_url: 'file:///synthetic' }));
  assert.deepEqual(f.count(), { executions: 0, admissions: 0 });
});
test('terminal readable head remains inspectable while new proposal and unavailable registry fail closed', async () => {
  const f = fixture(); f.seed(); f.setHead('9007199254740991');
  assert.equal((await f.api.snapshot({ context: f.context })).registryVersion, '9007199254740991');
  await assert.rejects(prepare(f)); f.disable();
  assert.equal((await f.api.snapshot({ context: f.context })).registryReady, false);
  await assert.rejects(prepare(f), { code: 'MCP_CHAT_UNAVAILABLE' });
});
test('malformed or mismatched authoritative operation receipt cannot project completion', async () => {
  for (const field of ['requestSha256', 'operationId', 'registryVersion', 'changes']) {
    const f = fixture(); const { proposal, source } = await prepare(f); const original = f.repository.publish;
    f.repository.publish = async (...args) => { const value = await original(...args);
      value[field] = field === 'changes' ? [] : field === 'operationId' ? randomUUID() : field === 'registryVersion' ? '9' : '0'.repeat(64); return value; };
    await assert.rejects(f.api.confirm({ context: f.context, proposal, source }), { code: 'MCP_CHAT_STATE_INVALID' });
    assert.equal(f.count().executions, 1, 'read projection failure must not claim no effect');
  }
});
test('actual discovery hash includes SDK annotations while detail truthfully projects common fields', async () => {
  const f = fixture();
  const { discoverRegistryTools } = require('../server/services/secureshopMcpRegistryDiscovery');
  const discovered = await discoverRegistryTools({ async listTools() { return { tools: [{ ...f.tools[0],
    annotations: { readOnlyHint: true }, outputSchema: { type: 'object', properties: { found: { type: 'boolean' } } } }] }; } });
  f.tools.splice(0, f.tools.length, ...structuredClone(discovered.tools)); f.seed();
  const state = await f.api.snapshot({ context: f.context }); const server = state.servers[0];
  const detail = await f.api.detail({ context: f.context, selected: { choiceId: randomUUID(), id: server.id,
    provenance: server.provenance, snapshotSha256: server.snapshotSha256 } });
  assert.equal(detail.server.schemaSha256, discovered.schemaSha256);
  assert.notEqual(mcpSchemaDigest(detail.tools), discovered.schemaSha256);
  assert.deepEqual(Object.keys(detail.tools[0]), ['name', 'description', 'inputSchema']);
  assert.deepEqual(f.count(), { executions: 0, admissions: 0 });
});
test('exact operation GET rejects an otherwise valid receipt for a different UUID', async () => {
  const f = fixture(); const { proposal, source } = await prepare(f);
  await f.api.confirm({ context: f.context, proposal, source });
  const original = f.repository.read;
  f.repository.read = async input => ({ ...await original(input), operationId: randomUUID() });
  await assert.rejects(f.api.operation({ context: f.context, operationId: proposal.proposalId }), { code: 'MCP_CHAT_STATE_INVALID' });
  assert.equal(f.count().executions, 1);
});
