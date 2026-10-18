'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createOwnedMcpRegistryRepository } = require('../server/database/postgres/secureshopOwnedMcpRegistryRepository');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const { registryRequestDigest } = require('../server/services/secureshopMcpRegistryContract');
const { mcpSchemaDigest } = require('../server/services/secureshopMcpSchemaDigest');

function fixture(mode = 'vuln') {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 7, platformSessionId: 11 };
  const persona = { id: 3, role: 'admin' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
  const operationId = randomUUID();
  const input = { scope, persona, personaSession, operationId };
  const request = { version: 1, action: 'import', operationId, expectedVersion: '0',
    xml_url: 'http://metadata.internal/manifest.xml' };
  const requestSha256 = registryRequestDigest(request);
  const bindingSha256 = canonicalDigest(['owned-mcp-registry-binding-v1', scope,
    persona, personaSession, mode, requestSha256]);
  const columns = { platform_launch_id: scope.launchId, platform_scenario_id: scope.scenarioId,
    platform_launch_generation: '1', original_platform_owner_id: 7, original_platform_session_id: 11 };
  const tools = [{ name: 'search', description: 'Owned tool', inputSchema: { type: 'object' } }];
  const schemaSha256 = mcpSchemaDigest(tools);
  const effect = { isolation: 'owned-mcp-registry-v1', mode, entityReads: [] };
  const changes = ['catalog-a', 'catalog-b'].map(name => ({ name, entryId: randomUUID(),
    action: 'import', schemaSha256, effect }));
  const receipt = { version: 'secureshop-owned-mcp-registry.v1', operationId,
    state: 'completed', action: 'import', requestSha256, registryVersion: '1', changes };
  const operation = { ...columns, operation_id: operationId, persona_id: 3,
    persona_role: 'admin', persona_session_id: personaSession.sessionId, authority_version: '1',
    mode, action: 'import', expected_version: '0', state: 'completed', redacted_at: null,
    request_json: request, request_sha256: Buffer.from(requestSha256, 'hex'),
    binding_sha256: Buffer.from(bindingSha256, 'hex'), receipt_json: receipt,
    receipt_sha256: Buffer.from(canonicalDigest(receipt), 'hex') };
  const revisions = changes.map(change => ({ ...columns, operation_id: operationId,
    name: change.name, entry_id: change.entryId, registry_version: '1', action: 'import',
    transport: 'streamable-http', endpoint_text: 'http://benign.training/mcp',
    schema_sha256: Buffer.from(schemaSha256, 'hex'), tools_json: tools,
    effect_json: { ...effect, requestSha256, bindingSha256 }, redacted_at: null }));
  const calls = [], events = [];
  let active = true, atRead = null;
  const client = { query: async (sql, args) => {
    assert.match(sql, /^SELECT /);
    calls.push({ sql, args });
    if (atRead) await atRead();
    return { rows: sql.includes('bound_mcp_registry_operations') ? [operation] : revisions };
  } };
  const repository = createOwnedMcpRegistryRepository({ pool: { query: async () => assert.fail() },
    personaAuthority: { capture: captured => {
      assert.deepEqual(captured, { scope, personaId: 3, role: 'admin',
        sessionId: personaSession.sessionId, authorityVersion: '1' });
      return { binding: { ...scope, personaId: 3, role: 'admin',
        sessionId: personaSession.sessionId, authorityVersion: '1' },
      withPersonaEffect: async work => { events.push('fence'); if (!active) throw Error('revoked');
        return work(client); },
      assertRemoteAdmission: async () => { events.push('post'); if (!active) throw Error('revoked'); } };
    } } });
  return { input, operation, revisions, calls, events, repository,
    rehash: () => { operation.receipt_sha256 = Buffer.from(canonicalDigest(operation.receipt_json), 'hex'); },
    revoke: () => { active = false; }, onRead: fn => { atRead = fn; } };
}

test('import evidence reader supports first-version multi-entry imports in both modes using only scoped SELECTs', async () => {
  for (const mode of ['fixed', 'vuln']) {
    const f = fixture(mode), result = await f.repository.readAssessmentImport(f.input);
    assert.equal(result.operation.mode, mode);
    assert.equal(result.operation.receipt_json.registryVersion, '1');
    assert.equal(result.revisions.length, 2);
    assert.deepEqual(f.events, ['fence', 'post']);
    for (const call of f.calls) {
      assert.deepEqual(call.args, [f.input.scope.launchId, f.input.scope.scenarioId, 1, 7, 11, f.input.operationId]);
      assert.match(call.sql, /redacted_at IS NULL/);
      assert.doesNotMatch(call.sql, /bound_mcp_registry_entries|admit_|publish_|UPDATE|INSERT|DELETE/);
    }
    result.operation.receipt_json.changes[0].effect.entityReads.push('caller mutation');
    assert.deepEqual(f.operation.receipt_json.changes[0].effect.entityReads, []);
  }
});

test('import evidence reader rejects wrong owner, generation, session, incomplete and retired operations', async () => {
  for (const mutate of [
    f => { f.operation.original_platform_owner_id++; },
    f => { f.operation.platform_launch_generation = '2'; },
    f => { f.operation.platform_launch_id = randomUUID(); },
    f => { f.operation.persona_id++; },
    f => { f.operation.persona_session_id = randomUUID(); },
    f => { f.operation.authority_version = '2'; },
    f => { f.operation.persona_role = 'merchant'; },
    f => { f.operation.operation_id = randomUUID(); },
    f => { f.operation.state = 'unknown'; },
    f => { f.operation.action = 'register'; },
    f => { f.operation.redacted_at = new Date(); },
  ]) {
    const f = fixture(); mutate(f);
    await assert.rejects(f.repository.readAssessmentImport(f.input), { code: 'MCP_REGISTRY_OPERATION_NOT_FOUND' });
    assert.equal(f.calls.length, 1);
  }
});

test('import evidence reader checks original request, mode binding and receipt integrity', async () => {
  for (const mutate of [
    f => { f.operation.request_json.xml_url += '?changed'; },
    f => { f.operation.mode = 'fixed'; },
    f => { f.operation.request_sha256[0] ^= 1; },
    f => { f.operation.binding_sha256[0] ^= 1; },
    f => { f.operation.receipt_json.registryVersion = '2'; },
    f => { f.operation.receipt_json.extra = true; f.rehash(); },
    f => { f.operation.receipt_json.changes.push(f.operation.receipt_json.changes[0]); f.rehash(); },
  ]) {
    const f = fixture(); mutate(f);
    await assert.rejects(f.repository.readAssessmentImport(f.input), error =>
      ['MCP_REGISTRY_OPERATION_NOT_FOUND', 'MCP_REGISTRY_INTEGRITY_UNAVAILABLE'].includes(error.code));
  }
});

test('import evidence reader requires every exact immutable revision and effect, not current registry rows', async () => {
  for (const mutate of [
    f => { f.revisions.pop(); },
    f => { f.revisions[1] = f.revisions[0]; },
    f => { f.revisions[0].operation_id = randomUUID(); },
    f => { f.revisions[0].original_platform_session_id++; },
    f => { f.revisions[0].registry_version = '2'; },
    f => { f.revisions[0].entry_id = randomUUID(); },
    f => { f.revisions[0].redacted_at = new Date(); },
    f => { f.revisions[0].schema_sha256[0] ^= 1; },
    f => { f.revisions[0].tools_json = []; },
    f => { f.revisions[0].effect_json.entityReads = [{ value: 'substitution' }]; },
    f => { f.revisions[0].effect_json.requestSha256 = 'a'.repeat(64); },
  ]) {
    const f = fixture(); mutate(f);
    await assert.rejects(f.repository.readAssessmentImport(f.input), { code: 'MCP_REGISTRY_OPERATION_NOT_FOUND' });
  }
});

test('import reader snapshots input before awaiting authority and rechecks revocation after the read', async () => {
  const f = fixture();
  const input = structuredClone(f.input);
  f.onRead(async () => { input.operationId = randomUUID(); input.scope.generation = 99; });
  await f.repository.readAssessmentImport(input);
  assert.ok(f.calls.every(call => call.args[5] === f.input.operationId && call.args[2] === 1));
  const revoked = fixture(); revoked.revoke();
  await assert.rejects(revoked.repository.readAssessmentImport(revoked.input), /revoked/);
  assert.equal(revoked.calls.length, 0);
  const during = fixture(); during.onRead(async () => during.revoke());
  await assert.rejects(during.repository.readAssessmentImport(during.input), /revoked/);
  assert.deepEqual(during.events, ['fence', 'post']);
});

test('registration reader reuses exact publication checks but cannot read an import as registration',async()=>{
 const f=fixture();await assert.rejects(f.repository.readAssessmentRegistration(f.input),{code:'MCP_REGISTRY_OPERATION_NOT_FOUND'});
 const operation=f.operation,request={version:1,action:'register',operationId:f.input.operationId,expectedVersion:'0',
  name:'catalog-a',transport:'streamable-http',url:'http://metadata.training/mcp',stdio_cmd:''};
 const requestSha256=registryRequestDigest(request),bindingSha256=canonicalDigest(['owned-mcp-registry-binding-v1',
  f.input.scope,f.input.persona,f.input.personaSession,'vuln',requestSha256]);
 Object.assign(operation,{action:'register',request_json:request,request_sha256:Buffer.from(requestSha256,'hex'),binding_sha256:Buffer.from(bindingSha256,'hex')});
 operation.receipt_json.action='register';operation.receipt_json.requestSha256=requestSha256;
 operation.receipt_json.changes.length=1;operation.receipt_json.changes[0].action='register';
 f.revisions.length=1;Object.assign(f.revisions[0],{action:'register',endpoint_text:request.url,
 effect_json:{...operation.receipt_json.changes[0].effect,requestSha256,bindingSha256}});f.rehash();
 const saved=await f.repository.readAssessmentRegistration(f.input);
 assert.deepEqual(saved,structuredClone({operation:f.operation,revisions:f.revisions}));
 for(const key of ['request_sha256','binding_sha256','receipt_sha256']){
  assert.ok(saved.operation[key] instanceof Uint8Array);
  assert.equal(Buffer.from(saved.operation[key]).toString('hex'),f.operation[key].toString('hex'));
 }
 await assert.rejects(f.repository.readAssessmentImport(f.input),{code:'MCP_REGISTRY_OPERATION_NOT_FOUND'});
 f.revisions[0].endpoint_text='http://benign.training/mcp';
 await assert.rejects(f.repository.readAssessmentRegistration(f.input),{code:'MCP_REGISTRY_OPERATION_NOT_FOUND'});
});
