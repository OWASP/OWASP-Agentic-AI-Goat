'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRegisteredToolSnapshotRepository } = require('../server/database/postgres/secureshopRegisteredToolSnapshot');
const { mcpSchemaDigest } = require('../server/services/secureshopMcpSchemaDigest');

const UUID = '11111111-1111-4111-8111-111111111111';
const ENTRY = '22222222-2222-4222-8222-222222222222';
const SIBLING = '33333333-3333-4333-8333-333333333333';
const binding = Object.freeze({
  launchId: UUID, scenarioId: '44444444-4444-4444-8444-444444444444', generation: 2,
  platformOwnerId: 7, platformSessionId: 8, shopUserId: 9, role: 'admin',
});

function tools(count = 1, prefix = 'lookup') {
  return Array.from({ length: count }, (_, index) => ({
    name: `${prefix}-${index}`,
    description: 'Bound registered lookup',
    inputSchema: { type: 'object', properties: {} },
  }));
}

function row({ entryId = ENTRY, name = 'owned', version = '4', endpoint = 'http://127.0.0.1:8091/', rows = tools() } = {}) {
  return {
    entry_id: entryId, name, transport: 'streamable-http', endpoint_text: endpoint,
    registry_version: version, schema_sha256: mcpSchemaDigest(rows), tools_json: rows,
  };
}
function fixture(rows, overrides = {}) {
  const calls = [];
  const pool = { async query(query) { calls.push({ pool: 'plain', query }); return { rows }; } };
  const fence = {
    binding: { ...binding, personaId: binding.shopUserId },
    async withPersonaEffect(work) { calls.push({ fence: 'persona' }); return work(pool); },
    async withCrossStoreEffect(work) { calls.push({ fence: 'cross' }); return work(); },
    ...overrides,
  };
  const repository = createRegisteredToolSnapshotRepository({ pool });
  return { calls, fence, captured: repository.capture(binding, fence) };
}

test('captures immutable active tool snapshots through the persona transaction', async () => {
  const f = fixture([row()]);
  const result = await f.captured.read();
  assert.deepEqual(result, [{
    name: 'owned', entryId: ENTRY, registryVersion: '4', transport: 'streamable-http',
    endpoint: 'http://127.0.0.1:8091/', schemaSha256: mcpSchemaDigest(tools()), tools: tools(),
  }]);
  assert.equal(f.calls[0].fence, 'persona');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result[0].tools), true);
});

test('rejects changed endpoint, schema, or registry version before remote work', async () => {
  for (const changed of [
    row({ endpoint: 'http://127.0.0.1:8092/' }),
    row({ rows: tools(1, 'changed-schema') }),
    row({ version: '5' }),
  ]) {
    let phase = 'original';
    const pool = { async query() { return { rows: [phase === 'original' ? row() : changed] }; } };
    const calls = [];
    const fence = {
      binding: { ...binding, personaId: binding.shopUserId },
      async withPersonaEffect(work) { calls.push('persona'); return work(pool); },
      async withCrossStoreEffect(work) { calls.push('cross'); return work(); },
    };
    const captured = createRegisteredToolSnapshotRepository({ pool }).capture(binding, fence);
    const entry = (await captured.read())[0];
    phase = 'changed';
    await assert.rejects(captured.withCurrentEntry(entry, async () => calls.push('remote')), { code: 'MCP_REGISTRY_SNAPSHOT_UNAVAILABLE' });
    assert.deepEqual(calls, ['persona', 'cross']);
  }
});

test('rejects sibling fence bindings before reading', async () => {
  const fence = { binding: { ...binding, personaId: binding.shopUserId, platformOwnerId: 99 },
    withPersonaEffect: async () => {}, withCrossStoreEffect: async () => {} };
  await assert.rejects(Promise.resolve().then(() => createRegisteredToolSnapshotRepository({ pool: { query: async () => ({ rows: [] }) } }).capture(binding, fence)), {
    code: 'MCP_REGISTRY_SNAPSHOT_UNAVAILABLE',
  });
});

test('rejects duplicate identities and row/tool bounds', async () => {
  const duplicateId = fixture([row(), row({ name: 'other' })]);
  await assert.rejects(duplicateId.captured.read(), { code: 'MCP_REGISTRY_SNAPSHOT_UNAVAILABLE' });
  const duplicateName = fixture([row(), row({ entryId: SIBLING })]);
  await assert.rejects(duplicateName.captured.read(), { code: 'MCP_REGISTRY_SNAPSHOT_UNAVAILABLE' });
  await assert.rejects(fixture(Array.from({ length: 33 }, (_, i) => row({ entryId: `${String(i + 10).padStart(8, '0')}-2222-4222-8222-222222222222`, name: `owned-${i}` }))).captured.read(), { code: 'MCP_REGISTRY_SNAPSHOT_UNAVAILABLE' });
  await assert.rejects(fixture([row({ rows: tools(65) })]).captured.read(), { code: 'MCP_INVOCATION_INVALID' });
});

test('withCurrentEntry reads the plain pool inside cross-store effect without nested persona fencing', async () => {
  const f = fixture([row()]);
  const snapshot = (await f.captured.read())[0];
  let remote;
  const value = await f.captured.withCurrentEntry(snapshot, async current => {
    remote = current;
    return 'completed';
  });
  assert.equal(value, 'completed');
  assert.equal(remote.entryId, ENTRY);
  assert.deepEqual(f.calls.map(call => call.fence || call.pool), ['persona', 'plain', 'cross', 'plain']);
  assert.equal(f.calls.filter(call => call.fence === 'persona').length, 1);
});
