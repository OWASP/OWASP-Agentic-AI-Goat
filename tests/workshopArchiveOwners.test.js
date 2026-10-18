'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { mapMcpArchive } = require('../db/postgres/map-mcp-archive');
const { prepareAgentWorkshopImport } = require('../db/postgres/import-agent-workshop-archive');
const { input: mcpInput } = require('./fixtures/mcpArchive');
const { input: agentInput } = require('./fixtures/agentWorkshopArchive');
function bound(raw) {
  raw.ownerBinding = { archiveDigest: raw.archiveDigest, identityMap: { 7: 71 } };
  for (const rows of Object.values(raw.tables)) for (const row of rows) {
    if (Object.hasOwn(row, 'user_key')) row.user_key = '7';
    if (Object.hasOwn(row, 'user_id')) row.user_id = '7';
  }
  return raw;
}
test('MCP remaps only attendee ownership, retaining exact source provenance and teaching arguments', () => {
  const raw = bound(mcpInput());
  raw.tables.mcp_workshop_tool_log[0].args = '{"user_id":7,"victim":"7"}';
  const mapped = mapMcpArchive(raw);
  assert.equal(mapped.snapshot.progress[0].userKey, '71');
  assert.equal(mapped.snapshot.toolLog[0].userKey, '71');
  assert.equal(mapped.snapshot.toolLog[0].args, raw.tables.mcp_workshop_tool_log[0].args);
  assert.equal(mapped.snapshot.provenance[0].id, '["7","mcp_recon"]');
  assert.equal(mapped.snapshot.provenance[0].row.user_key, '7');
  assert.match(mapped.report.identityMapSha256, /^[a-f0-9]{64}$/);
});
for (const family of ['finflow', 'supply_chain']) test(`${family} maps owners without changing teaching data or source rows`, () => {
  const raw = bound(agentInput(family));
  const mapped = prepareAgentWorkshopImport(raw);
  assert.equal(mapped.snapshot.progress[0].userId, '71');
  assert.equal(mapped.snapshot.sourceRows[0].row.user_id, '7');
  for (const row of mapped.snapshot.toolLog) {
    assert.equal(row.userId, '71');
    assert.equal(row.params, raw.tables.finflow_tool_log[0].params);
  }
  raw.ownerBinding.identityMap = {};
  assert.throws(() => prepareAgentWorkshopImport(raw), { code: 'UNMAPPED_ARCHIVE_OWNER' });
});
test('unreviewed ambiguous owners and forged proofs fail before workshop pool checkout', async () => {
  const raw = mcpInput();
  raw.ownerBinding = { archiveDigest: raw.archiveDigest, identityMap: { 7: 71 } };
  assert.throws(() => mapMcpArchive(raw), { code: 'UNRESOLVED_OPAQUE_ARCHIVE_OWNER' });
  let connected = false;
  const pool = { connect: async () => { connected = true; throw new Error('must not connect'); } };
  await assert.rejects(require('../db/postgres/import-mcp-archive').importMcpArchive(pool, bound(mcpInput()), { apply: true, ownerProof: {} }), { code: 'VERIFIED_ARCHIVE_OWNER_BINDING_REQUIRED' });
  await assert.rejects(require('../db/postgres/import-agent-workshop-archive').importAgentWorkshopArchive(pool, bound(agentInput('finflow')), { apply: true, ownerProof: {} }), { code: 'VERIFIED_ARCHIVE_OWNER_BINDING_REQUIRED' });
  assert.equal(connected, false);
});

test('explicit leading-zero alias maps to the same identity and cannot silently merge progress', () => {
  const raw = bound(mcpInput());
  raw.opaqueOwnerResolutions = [{sourceKey:'0007',disposition:'map_source_identity',sourceId:'7'}];
  raw.tables.mcp_workshop_progress[0].user_key = '0007';
  assert.equal(mapMcpArchive(raw).snapshot.progress[0].userKey, '71');
  raw.tables.mcp_workshop_progress.push({...raw.tables.mcp_workshop_progress[0],user_key:'7'});
  assert.throws(() => mapMcpArchive(raw), {code:'DUPLICATE_MCP_SOURCE_KEY'});
});

test('all mapped owner dispositions must be consumed by actual source rows', () => {
 for (const [raw, mapper] of [[bound(mcpInput()),mapMcpArchive],[bound(agentInput('finflow')),prepareAgentWorkshopImport],[bound(agentInput('supply_chain')),prepareAgentWorkshopImport]]) {
  raw.opaqueOwnerResolutions=[{sourceKey:'unused-owner',disposition:'preserve_opaque'}];
  assert.throws(()=>mapper(raw),{code:'UNUSED_OPAQUE_OWNER_RESOLUTION'});
 }
});
