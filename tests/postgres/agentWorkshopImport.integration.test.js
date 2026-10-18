'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),fs=require('node:fs/promises');
const {createNativeOwnerProof}=require('./helpers/archiveOwnerBinding');
const {createPool}=require('../../server/database/postgres');
const {migrate}=require('../../db/postgres/migrate');
const {readAgentWorkshopArchive,importAgentWorkshopArchive}=require('../../db/postgres/import-agent-workshop-archive');
const {archive}=require('../fixtures/agentWorkshopArchive');
for(const family of ['finflow','supply_chain'])test(`${family} archive native import dry-run, rollback, provenance and restart`,{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env[`PG_${family.toUpperCase()}_IMPORT_TEST_MIGRATION_URL`]},async()=>{
 const prefix=`PG_${family.toUpperCase()}_IMPORT_TEST`,migration=createPool(process.env,prefix+'_MIGRATION_URL'),pool=createPool(process.env,prefix+'_RUNTIME_URL');let directory,ownerFixture;
 try{
  await migrate(migration,path.join(__dirname,'../../db/postgres/workshop-migrations',family));
  directory=await archive(family);const read=await readAgentWorkshopArchive({archive:directory,family,naiveTimestamps:'UTC'});
  const raw={...read.input,review:{archiveDigest:read.input.archiveDigest,tables:[]},ownerBinding:{archiveDigest:read.input.archiveDigest,identityMap:{7:71}},opaqueOwnerResolutions:[{sourceKey:'0007',disposition:'map_source_identity',sourceId:'7'}]};
  ownerFixture=await createNativeOwnerProof(migration,raw.ownerBinding);const {ownerProof}=ownerFixture;
  assert.equal((await importAgentWorkshopArchive(migration,raw,{ownerProof})).applied,false);
  assert.equal((await migration.query(`SELECT count(*)::int n FROM ${family}.progress`)).rows[0].n,0);
  assert.equal((await migration.query(`SELECT count(*)::int n FROM ${family}.objectives`)).rows[0].n,0);
  await migration.query(`CREATE FUNCTION ${family}.reject_fixture_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture late failure'; END $$`);
  await migration.query(`CREATE TRIGGER fixture_failure BEFORE INSERT ON ${family}.import_provenance FOR EACH ROW EXECUTE FUNCTION ${family}.reject_fixture_import()`);
  await assert.rejects(importAgentWorkshopArchive(migration,raw,{apply:true,ownerProof}),/fixture late failure/);
  assert.equal((await migration.query(`SELECT count(*)::int n FROM ${family}.progress`)).rows[0].n,0);
  await migration.query(`DROP TRIGGER fixture_failure ON ${family}.import_provenance`);
  await migration.query(`DROP FUNCTION ${family}.reject_fixture_import()`);
  const originalDigest=raw.archiveDigest;
  let checkoutStarted,releaseCheckout;
  const started=new Promise(resolve=>{checkoutStarted=resolve;});
  const gate=new Promise(resolve=>{releaseCheckout=resolve;});
  const delayedPool={connect:async()=>{checkoutStarted();await gate;return migration.connect();}};
  const importPending=importAgentWorkshopArchive(delayedPool,raw,{apply:true,ownerProof});
  await started;
  raw.archiveDigest='f'.repeat(64);
  raw.review.archiveDigest=raw.archiveDigest;
  const progressTable=family==='finflow'?'finflow_progress':'sc_progress';
  raw.tables[progressTable][0].user_id='changed-after-checkout';
  raw.review.tables.push({table:'invented',disposition:'changed'});
  releaseCheckout();
  const imported=await importPending;
  assert.equal(imported.applied,true);
  assert.equal(imported.archiveDigest,originalDigest);
  assert.deepEqual(imported.retainedNotImported,[]);
  raw.archiveDigest=originalDigest;raw.review={archiveDigest:originalDigest,tables:[]};
  raw.tables[progressTable][0].user_id='0007';
  assert.equal((await migration.query(`SELECT identity_map_sha256 FROM ${family}.import_batches`)).rows[0].identity_map_sha256,ownerProof.identityMapSha256);
  const progress=(await pool.query(`SELECT *,completed_at::text stamp FROM ${family}.progress`)).rows;
  assert.equal(progress[0].user_id,'71');
  assert.equal((await pool.query(`SELECT count(*)::int n FROM ${family}.progress WHERE user_id='7'`)).rows[0].n,0);assert.match(progress[0].stamp,/\.123456/);
  const provenance=(await migration.query(`SELECT * FROM ${family}.import_provenance WHERE source_id='17'`)).rows[0];
  assert.equal(provenance.archive_sha256,originalDigest);
  assert.equal(provenance.source_row.user_id,'0007');
  assert.deepEqual(provenance.source_row.id,{type:'integer',value:'17'});
  assert.equal(provenance.source_row.completed_at,'2025-01-02 03:04:05.123456');
  await assert.rejects(migration.query(`DELETE FROM ${family}.import_provenance`),{code:'55000'});
  await assert.rejects(importAgentWorkshopArchive(migration,raw,{apply:true,ownerProof}),{code:'WORKSHOP_IMPORT_REQUIRES_EMPTY_TARGET'});
  const store=family==='finflow'?require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(pool):require('../../server/database/postgres/supplyChainWorkshopDb').createSupplyChainWorkshopDb(pool);
  await store.initialize(migration);await store.initialize(migration);
  assert.deepEqual((await pool.query(`SELECT *,completed_at::text stamp FROM ${family}.progress`)).rows,progress);
  if(family==='finflow'){
   const log=(await pool.query('SELECT * FROM finflow.tool_log')).rows[0];assert.equal(log.params,' { "path": "../fixture" } ');assert.equal(log.id,'29');
   await store.logToolCall('other',{name:'fixture',params:{},result:'fixture',mode:'fixed'});
   assert.equal((await pool.query("SELECT id FROM finflow.tool_log WHERE user_id='other'")).rows[0].id,'30');
  }
 }finally{await ownerFixture?.cleanup();if(directory)await fs.rm(directory,{recursive:true,force:true});await Promise.all([migration.end(),pool.end()]);}
});

for(const family of ['finflow','supply_chain'])test(`${family} empty import persists immutable digest and redacted retention decisions`,{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env[`PG_${family.toUpperCase()}_EMPTY_IMPORT_TEST_MIGRATION_URL`]},async()=>{
 const pool=createPool(process.env,`PG_${family.toUpperCase()}_EMPTY_IMPORT_TEST_MIGRATION_URL`);let ownerFixture;
 try{
  await migrate(pool,path.join(__dirname,'../../db/postgres/workshop-migrations',family));
  const raw=require('../fixtures/agentWorkshopArchive').input(family);
  raw.ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};
  ownerFixture=await createNativeOwnerProof(pool,raw.ownerBinding);const {ownerProof}=ownerFixture;
  for(const table of Object.keys(raw.tables))raw.tables[table]=[];
  raw.tables['private-owner@example.test']=[{secret:'private retained value'}];
  raw.review.tables=[{table:'private-owner@example.test',disposition:'retain_archive_no_native_equivalent'}];
  await importAgentWorkshopArchive(pool,raw,{ownerProof});
  assert.equal((await pool.query(`SELECT count(*)::int n FROM ${family}.import_batches`)).rows[0].n,0);
  await importAgentWorkshopArchive(pool,raw,{apply:true,ownerProof});
  const batch=(await pool.query(`SELECT * FROM ${family}.import_batches`)).rows[0];
  assert.equal(batch.archive_sha256,raw.archiveDigest);
  assert.equal(batch.timestamp_policy,'UTC');
  assert.ok(Object.values(batch.counts).every(count=>count===0));
  assert.equal(batch.retained_decisions[0].rows,1);
  assert.equal(batch.retained_decisions[0].disposition,'retain_archive_no_native_equivalent');
  for(const value of ['private-owner@example.test','private retained value'])assert.equal(JSON.stringify(batch).includes(value),false);
  // Even catalog removal cannot turn an already imported destination into a fresh one.
  await pool.query(`DELETE FROM ${family}.objectives`);
  await assert.rejects(importAgentWorkshopArchive(pool,raw,{apply:true,ownerProof}),{code:'WORKSHOP_IMPORT_REQUIRES_EMPTY_TARGET'});
  await assert.rejects(pool.query(`DELETE FROM ${family}.import_batches`),{code:'55000'});
 }finally{await ownerFixture?.cleanup();await pool.end();}
});
