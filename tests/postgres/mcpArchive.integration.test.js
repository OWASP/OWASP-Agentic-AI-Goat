'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {createNativeOwnerProof}=require('./helpers/archiveOwnerBinding');
const {input}=require('../fixtures/mcpArchive');
const {createPool}=require('../../server/database/postgres');
const {migrate}=require('../../db/postgres/migrate');
const {importMcpArchive}=require('../../db/postgres/import-mcp-archive');
const {createMcpWorkshopDb}=require('../../server/database/postgres/mcpWorkshopDb');
function boundInput(){const raw=input();raw.ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};for(const rows of Object.values(raw.tables))for(const row of rows)row.user_key='7';return raw;}
test('native MCP archive dryrun, late rollback, exact state, immutable provenance and incomplete progress repair',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_MCP_IMPORT_TEST_MIGRATION_URL},async()=>{
 const migration=createPool(process.env,'PG_MCP_IMPORT_TEST_MIGRATION_URL'),pool=createPool(process.env,'PG_MCP_IMPORT_TEST_RUNTIME_URL');
 let ownerFixture;
 try{
  await migrate(migration,path.join(__dirname,'../../db/postgres/workshop-migrations/mcp'));
  const raw=boundInput();ownerFixture=await createNativeOwnerProof(migration,raw.ownerBinding);const {ownerProof}=ownerFixture;assert.equal((await importMcpArchive(migration,raw,{ownerProof})).applied,false);
  assert.equal((await pool.query('SELECT count(*)::int n FROM mcp.progress')).rows[0].n,0);
  await migration.query("CREATE FUNCTION mcp.reject_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'late fixture failure'; END $$");
  await migration.query('CREATE TRIGGER reject_fixture BEFORE INSERT ON mcp.import_provenance FOR EACH ROW EXECUTE FUNCTION mcp.reject_fixture()');
  await assert.rejects(importMcpArchive(migration,raw,{apply:true,ownerProof}),/late fixture failure/);
  assert.equal((await pool.query('SELECT count(*)::int n FROM mcp.tool_log')).rows[0].n,0);
  await migration.query('DROP TRIGGER reject_fixture ON mcp.import_provenance');
  let release,started;const gate=new Promise(r=>release=r),enter=new Promise(r=>started=r);
  const pending=importMcpArchive({connect:async()=>{started();await gate;return migration.connect();}},raw,{apply:true,ownerProof});await enter;
  raw.tables.mcp_workshop_progress[0].user_key='mutated';raw.archiveDigest='f'.repeat(64);release();assert.equal((await pending).archiveDigest,'a'.repeat(64));
  assert.equal((await migration.query('SELECT identity_map_sha256 FROM mcp.import_batches')).rows[0].identity_map_sha256,ownerProof.identityMapSha256);
  const before=(await pool.query('SELECT *,created_at::text stamp FROM mcp.progress')).rows[0];assert.equal(before.user_key,'71');assert.equal(before.completed,0);assert.equal(before.completed_at,null);assert.match(before.stamp,/\.123456/);
  const log=(await pool.query('SELECT * FROM mcp.tool_log')).rows[0];assert.equal(log.id,'29');assert.equal(log.args,' { "exact": true } ');assert.equal(log.success,null);assert.equal(log.created_at,null);
  assert.equal((await migration.query('SELECT count(*)::int n FROM mcp.import_provenance')).rows[0].n,2);
  assert.equal((await pool.query("SELECT count(*)::int n FROM mcp.progress WHERE user_key='7'")).rows[0].n,0);
  await assert.rejects(migration.query('DELETE FROM mcp.import_provenance'),{code:'55000'});
  await assert.rejects(pool.query('SELECT * FROM mcp.import_provenance'),{code:'42501'});
  await assert.rejects(importMcpArchive(migration,boundInput(),{apply:true,ownerProof}),{code:'MCP_IMPORT_REQUIRES_EMPTY_TARGET'});
  const store=createMcpWorkshopDb(pool);await store.initialize(migration);await store.initialize(migration);
  assert.equal((await store.getProgress('71'))[0].completed,0);
  await store.markProgress('71','mcp_recon');assert.equal((await store.getProgress('71'))[0].completed,1);
  assert.equal((await store.logToolCall({userKey:'other',toolName:'fixture',args:'{}',resultSummary:'fixture'})).id,'30');
  await store.resetUser('71');assert.equal((await store.listActivity('other')).length,1);assert.equal((await migration.query('SELECT count(*)::int n FROM mcp.import_provenance')).rows[0].n,2);
 }finally{await ownerFixture?.cleanup();await Promise.all([migration.end(),pool.end()]);}
});
test('native empty MCP import records a durable batch and rejects repeat application',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_MCP_EMPTY_IMPORT_TEST_MIGRATION_URL},async()=>{
 const migration=createPool(process.env,'PG_MCP_EMPTY_IMPORT_TEST_MIGRATION_URL');
 let ownerFixture;
 try{
  await migrate(migration,path.join(__dirname,'../../db/postgres/workshop-migrations/mcp'));
  const raw=boundInput();ownerFixture=await createNativeOwnerProof(migration,raw.ownerBinding);const {ownerProof}=ownerFixture;raw.tables.mcp_workshop_progress=[];raw.tables.mcp_workshop_tool_log=[];
  assert.equal((await importMcpArchive(migration,raw,{ownerProof})).applied,false);
  assert.equal((await migration.query('SELECT count(*)::int n FROM mcp.import_batches')).rows[0].n,0);
  assert.equal((await importMcpArchive(migration,raw,{apply:true,ownerProof})).applied,true);
  assert.equal((await migration.query('SELECT count(*)::int n FROM mcp.import_batches')).rows[0].n,1);
  await assert.rejects(importMcpArchive(migration,raw,{apply:true,ownerProof}),{code:'MCP_IMPORT_REQUIRES_EMPTY_TARGET'});
  await assert.rejects(migration.query('DELETE FROM mcp.import_batches'),{code:'55000'});
 }finally{await ownerFixture?.cleanup();await migration.end();}
});
