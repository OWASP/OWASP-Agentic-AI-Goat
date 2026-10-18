'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const{createPool}=require('../../server/database/postgres'),{migrate}=require('../../db/postgres/migrate');
const{fixture}=require('../fixtures/csrfArchive'),{importCsrfArchive}=require('../../db/postgres/import-csrf-archive');
const{createNativeOwnerProof}=require('./helpers/archiveOwnerBinding');
for(const empty of [false,true])test(`CSRF native import ${empty?'empty receipt':'victims, progress upgrade and owner reset'}`,{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env[empty?'PG_CSRF_EMPTY_IMPORT_TEST_MIGRATION_URL':'PG_CSRF_IMPORT_TEST_MIGRATION_URL']},async()=>{
 const prefix=empty?'PG_CSRF_EMPTY_IMPORT_TEST':'PG_CSRF_IMPORT_TEST',pool=createPool(process.env,prefix+'_MIGRATION_URL'),runtime=createPool(process.env,prefix+'_RUNTIME_URL');
 let ownerFixture;
 try{
  await migrate(pool,path.join(__dirname,'../../db/postgres/workshop-migrations/csrf'));
  const raw=fixture(),ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};raw.ownerBinding=ownerBinding;
  raw.opaqueOwnerResolutions=empty?[]:[{sourceKey:'0007',disposition:'map_source_identity',sourceId:'7'},{sourceKey:'other',disposition:'preserve_opaque'}];
  if(empty)for(const source of Object.values(raw.sources))for(const table of Object.keys(source.tables))source.tables[table]=[];
  ownerFixture=await createNativeOwnerProof(pool,ownerBinding);
  await importCsrfArchive(pool,raw,{ownerProof:ownerFixture.ownerProof});assert.equal((await pool.query('SELECT count(*)::int n FROM csrf.import_batches')).rows[0].n,0);
  await pool.query("CREATE FUNCTION csrf.fail_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'late csrf failure'; END $$");await pool.query('CREATE TRIGGER fail_fixture BEFORE INSERT ON csrf.import_batches FOR EACH ROW EXECUTE FUNCTION csrf.fail_fixture()');
  await assert.rejects(importCsrfArchive(pool,raw,{apply:true,ownerProof:ownerFixture.ownerProof}),/late csrf failure/);assert.equal((await pool.query('SELECT count(*)::int n FROM csrf.wallets')).rows[0].n,0);await pool.query('DROP TRIGGER fail_fixture ON csrf.import_batches');await pool.query('DROP FUNCTION csrf.fail_fixture()');
  await importCsrfArchive(pool,raw,{apply:true,ownerProof:ownerFixture.ownerProof});assert.equal((await pool.query('SELECT count(*)::int n FROM csrf.import_batches')).rows[0].n,1);
  const store=require('../../server/database/postgres/csrfWorkshopDb').createCsrfWorkshopDb(runtime);await store.initialize(pool);
  if(!empty){
   assert.equal((await runtime.query("SELECT balance FROM csrf.wallets WHERE user_key='71'")).rows[0].balance,'9007199254740993');
   assert.equal((await store.getVictimState('csrf_71')).get.balance,9000);
   for(const id of ['csrf_g1','csrf_g2'])await store.markProgress('71',id);
   assert.ok((await store.getProgress('0007')).every(row=>row.completed===1));
   await store.logToolCall({userKey:'other',tabId:'get',toolName:'fixture',args:'{}',resultSummary:'fixture',flag:null});assert.equal((await store.listActivity('other'))[0].id,'30');
   await store.resetUser('71');assert.equal(await store.getVictimState('csrf_71'),null);assert.equal((await runtime.query("SELECT balance FROM csrf.wallets WHERE user_key='other'")).rows[0].balance,'-50');assert.equal((await store.listActivity('other')).length,1);
  }
  await assert.rejects(importCsrfArchive(pool,raw,{apply:true,ownerProof:ownerFixture.ownerProof}),{code:'CSRF_IMPORT_REQUIRES_EMPTY_TARGET'});await assert.rejects(pool.query('DELETE FROM csrf.import_batches'),{code:'55000'});
 }finally{if(ownerFixture)await ownerFixture.cleanup();await Promise.all([pool.end(),runtime.end()]);}
});
