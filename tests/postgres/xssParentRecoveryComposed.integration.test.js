'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createPool}=require('../../server/database/postgres');
const {initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const {createXssWorkshopDb}=require('../../server/database/postgres/xssWorkshopDb');
const {createXssProfileResetJournalRepository}=require('../../server/database/postgres/xssProfileResetJournalRepository');
const {createXssScopedProfileResetRepository}=require('../../server/database/postgres/xssScopedProfileResetRepository');
const {createXssScopedProfileReset}=require('../../server/services/xssScopedProfileReset');
const {createRunCoordinator}=require('../../server/agent-runtime/runCoordinator');
const {createPostgresRunLedger}=require('../../server/agent-runtime/postgresRunLedger');
const keys=['PG_XSS_RECOVERY_IDENTITY_RUNTIME_URL','PG_XSS_RECOVERY_IDENTITY_MIGRATION_URL',
 'PG_XSS_RECOVERY_STORE_RUNTIME_URL','PG_XSS_RECOVERY_STORE_MIGRATION_URL'];
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&keys.every(key=>process.env[key]);
test('composed parent recovery retires late writes and preserves committed reset receipts', {skip:!enabled},async()=>{
 for(const [i,key] of keys.entries()){
  const url=new URL(process.env[key]);assert.equal(url.hostname,'127.0.0.1');
  assert.equal(url.pathname,i<2?'/dvaia_test_xss_recovery_identity':'/dvaia_test_xss_recovery_store');
  assert.equal(url.username,`dvaia_${i<2?'identity':'xss'}_${i%2?'migration':'runtime'}`);
 }
 const pools=keys.map(key=>createPool(process.env,key));
 const [identity,migration,storePool,storeMigration]=pools;
 // Production uses a separate lease pool; lifecycle and journal transactions
 // must retain independent connection capacity while the owner lease is held.
 const leasePool=createPool(process.env,keys[0],{purpose:'lease'});pools.push(leasePool);
 try{
  const identityApplied=await initializeIdentityRepository(identity,migration);
  const identityManifest=(await require('../../db/postgres/migrate').readMigrations(require('node:path').resolve(__dirname,'../../db/postgres/identity-migrations'))).map(row=>row.name);
  for(const required of ['0079_xss_deletion_redaction_recovery_filter.sql','0080_legacy_ai_private_history.sql'])assert.ok(identityManifest.includes(required),required);
  assert.deepEqual(identityApplied,identityManifest);
  assert.deepEqual((await migration.query('SELECT name FROM dvaia_migrations.ledger ORDER BY name')).rows.map(row=>row.name),identityManifest);
  assert.deepEqual(await initializeIdentityRepository(identity,migration),[],
   'current identity migration tail replays as a no-op');
  await seedWorkshopPlatform(migration);
  await createXssWorkshopDb(storePool).initializeXssWorkshopDb(storeMigration);
  const owner=(await migration.query(`INSERT INTO identity.users(username,email,password)
   VALUES('composed-reset','composed-reset@fixture.invalid',$1) RETURNING id`,
   ['$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA'])).rows[0].id;
  const ownerKey=JSON.stringify(['XSS',String(owner)]);
  await migration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[ownerKey]);
  await migration.query("INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation) VALUES($1,'xss_workshop',0)",[owner]);
  await storePool.query("INSERT INTO xss.profiles(user_key,name,bio,website) VALUES($1,'Original','keep','https://fixture.invalid')",[String(owner)]);
  const journal=createXssProfileResetJournalRepository(identity),store=createXssScopedProfileResetRepository(storePool);
  const ledger=createPostgresRunLedger(identity,{leasePool});
  const service=createXssScopedProfileReset({pool:identity,runs:createRunCoordinator({family:'XSS',ledger}),ledger,journal,store,
   readWorkshopGeneration:async id=>(await identity.query("SELECT generation FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key='xss_workshop'",[id])).rows[0].generation});
  const advance=async()=>{
   await migration.query('UPDATE graph_runtime.owners SET generation=generation+1 WHERE owner_key=$1',[ownerKey]);
   await migration.query("UPDATE workshop_platform.user_state SET generation=generation+1 WHERE user_id=$1 AND workshop_key='xss_workshop'",[owner]);
  };
  const original=await journal.begin({operationId:randomUUID(),ownerId:owner,graphParentGeneration:'0',workshopGeneration:'0'});
  const tuple=operation=>({operationId:operation.operationId,ownerId:owner,graphParentGeneration:operation.graphParentGeneration,
   workshopGeneration:operation.workshopGeneration,children:operation.children});
  await advance();
  const retired=await service.recoverAfterParentReset({ownerId:owner,operationId:original.operationId});
  assert.equal(retired.status,'superseded');
  await assert.rejects(store.apply(tuple(original)));
  assert.equal((await storePool.query('SELECT name FROM xss.profiles WHERE user_key=$1',[String(owner)])).rows[0].name,'Original');
  assert.equal((await service.recoverAfterParentReset({ownerId:owner,operationId:original.operationId})).status,'superseded');
  const committed=await journal.begin({operationId:randomUUID(),ownerId:owner,graphParentGeneration:'1',workshopGeneration:'1'});
  await store.apply(tuple(committed));
  await storePool.query("UPDATE xss.profiles SET name='Later edit' WHERE user_key=$1",[String(owner)]);
  await advance();
  const reconciled=await service.recoverAfterParentReset({ownerId:owner,operationId:committed.operationId});
  assert.equal(reconciled.status,'superseded');
  assert.equal((await storePool.query('SELECT name FROM xss.profiles WHERE user_key=$1',[String(owner)])).rows[0].name,'Later edit');
  for (const table of ['xss_profile_reset_operations','xss_profile_reset_steps']) {
   await assert.rejects(migration.query(`UPDATE identity.${table} SET failure_code=NULL WHERE operation_id=$1`,
    [original.operationId]), {code:'23514'});
  }
  const fresh=await service.reset({operationId:randomUUID(),ownerId:owner,graphParentGeneration:'2',workshopGeneration:'2'});
  assert.equal(fresh.status,'completed');
  // Migration repair must preserve every core coordinate/state invariant,
  // not merely admit the new terminal supersession path.
  for (const patch of [
    {userTo:2}, {llmTo:2}, {status:'running'}, {status:'completed'},
    {expires:true}, {failure:'UNEXPECTED_FAILURE'},
  ]) {
    await assert.rejects(migration.query(`INSERT INTO identity.xss_profile_reset_operations
      (operation_id,owner_id,owner_key,graph_parent_generation,workshop_generation,
       stored_user_from,stored_user_to,stored_llm_from,stored_llm_to,status,lease_expires_at,failure_code)
      VALUES($1,$2,$3,2,2,0,$4,0,$5,$6,$7,$8)`,
      [randomUUID(),owner,ownerKey,patch.userTo??1,patch.llmTo??1,patch.status??'pending',
        patch.expires?new Date():null,patch.failure??null]), {code:'23514'});
  }

  // Compose the real admin parent journal with the real store receipt and
  // canonical finalizer. Replay must precede graph invalidation.
  const {createXssParentResetJournalRepository}=require('../../server/database/postgres/xssParentResetJournalRepository');
  const {createXssParentReset}=require('../../server/services/xssParentReset');
  const {withStudentLifecycleLock}=require('../../server/database/postgres/studentLifecycleLock');
  const parentJournal=createXssParentResetJournalRepository(identity);
  await parentJournal.assertReady();
  const parentRuns=createRunCoordinator({family:'XSS',ledger});
  const parentReset=createXssParentReset({journal:parentJournal,childJournal:journal,store,runs:parentRuns});
  const invokeParent=(operationId,service=parentReset)=>withStudentLifecycleLock(identity,owner,
   (_,lifecycle)=>service({ownerId:owner,operationId,lifecycle}));
  await migration.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'xss_workshop','xss_s1')",[owner]);
  const priorEvaluation=randomUUID();
  await migration.query(`INSERT INTO workshop_platform.objective_judgments
   (user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,generation)
   VALUES($1,$2,'xss_workshop','xss_s1','XSS','stored_user','fixture',$3,2)`,[owner,priorEvaluation,'a'.repeat(64)]);
  const parentId=randomUUID();
  await parentJournal.begin({operationId:parentId,ownerId:owner});
  const validationLease=await parentJournal.claim({operationId:parentId,ownerId:owner});
  const validClear={operationId:parentId,ownerId:owner,profileRevisions:{name:'1',bio:'1',website:'1'},
   progressRemoved:0,originsRemoved:0,appliedAt:'2026-09-19T12:00:00.000Z',replayed:false};
  for(const malformed of [
   {...validClear,profileRevisions:{...validClear.profileRevisions,name:null}},
   {...validClear,progressRemoved:null},{...validClear,originsRemoved:null},
   {...validClear,appliedAt:'invalid timestamp'},
  ])await assert.rejects(identity.query('SELECT * FROM identity.acknowledge_xss_parent_clear($1,$2,$3::jsonb)',
   [parentId,validationLease.lease.token,JSON.stringify(malformed)]),{code:'22023'});
  await assert.rejects(identity.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'xss_workshop','xss_g1')",[owner]),{code:'55000'});
  await assert.rejects(identity.query(`UPDATE workshop_platform.objective_judgments SET disposition='not_pass'
   WHERE user_id=$1 AND evaluation_id=$2`,[owner,priorEvaluation]),{code:'55000'});
  await parentJournal.fail({operationId:parentId,leaseToken:validationLease.lease.token,code:'TEST_VALIDATION_COMPLETE'});
  const parentResult=await invokeParent(parentId);
  assert.equal(parentResult.status,'completed');
  assert.equal(parentResult.workshopGenerationTo,'3');
  assert.equal(parentResult.graphGeneration,'3');
  assert.equal((await migration.query("SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='xss_workshop'",[owner])).rows[0].n,0);
  await storePool.query("UPDATE xss.profiles SET name='After completed parent' WHERE user_key=$1",[String(owner)]);
  const replayedParent=await invokeParent(parentId);
  assert.equal(replayedParent.graphGeneration,'3');
  assert.equal((await migration.query('SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey])).rows[0].generation,'3');
  assert.equal((await storePool.query('SELECT name FROM xss.profiles WHERE user_key=$1',[String(owner)])).rows[0].name,'After completed parent');
  // Persisted store clear followed by a failed identity acknowledgement must
  // reuse the same clear receipt, preserving later edits on the retry.
  const childPending=await journal.begin({operationId:randomUUID(),ownerId:owner,graphParentGeneration:'3',workshopGeneration:'3'});
  const interruptedParent=randomUUID();let failAck=true;
  const faultJournal={...parentJournal,acknowledgeClear:async value=>{
   if(failAck){failAck=false;throw new Error('Injected acknowledgement failure');}
   return parentJournal.acknowledgeClear(value);
  }};
  const recoverableReset=createXssParentReset({journal:faultJournal,childJournal:journal,store,runs:parentRuns});
  await assert.rejects(invokeParent(interruptedParent,recoverableReset),/Injected acknowledgement failure/);
  await storePool.query("UPDATE xss.profiles SET name='After interrupted clear' WHERE user_key=$1",[String(owner)]);
  const recoveredParent=await invokeParent(interruptedParent,recoverableReset);
  assert.equal(recoveredParent.status,'completed');assert.equal(recoveredParent.workshopGenerationTo,'4');
  assert.equal((await journal.read(childPending.operationId)).status,'superseded');
  assert.equal((await storePool.query('SELECT name FROM xss.profiles WHERE user_key=$1',[String(owner)])).rows[0].name,'After interrupted clear');

  // Qualify the mounted administrative entry point with the real composition.
  // Each call owns exactly one platform lifecycle admission; explicit replay
  // must return the retained operation before any second graph/store clear.
  const {createXssParentResetComposition}=require('../../server/services/xssParentResetComposition');
  const {createPostgresWorkshopResetService,createPostgresWorkshopResetAdapters,
   withPostgresStudentResetAdmission}=require('../../server/services/postgresWorkshopResetService');
  const administrativeComposition=createXssParentResetComposition({identityPool:identity,store,runs:parentRuns});
  assert.equal(await administrativeComposition.assertReady(),true);
  const administrativeAdapters=createPostgresWorkshopResetAdapters(specifier=>{
   if(specifier==='./xssParentResetComposition')return {getXssParentResetComposition:async()=>administrativeComposition};
   if(specifier==='./postgresIdentityAdapter')return {getPostgresIdentityAdapter:()=>({pool:identity})};
   if(specifier==='../database/postgres/xssParentResetJournalRepository')return require('../../server/database/postgres/xssParentResetJournalRepository');
   assert.fail(`ordinary reset reached an effect dependency before XSS admission: ${specifier}`);
  });
  let lifecycleAdmissions=0;
  const administrativeReset=createPostgresWorkshopResetService({
   progress:{async resetWorkshopProgress(){assert.fail('administrative XSS composition owns canonical reset');}},
   adapters:administrativeAdapters,
   withStudentResetAdmission:(studentId,work)=>{
    lifecycleAdmissions+=1;
    return withPostgresStudentResetAdmission(identity,studentId,work);
   },
  });
  const sibling=(await migration.query(`INSERT INTO identity.users(username,email,password)
   VALUES('composed-reset-sibling','composed-reset-sibling@fixture.invalid',$1) RETURNING id`,
  ['$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA'])).rows[0].id;
  const siblingKey=JSON.stringify(['XSS',String(sibling)]);
  await migration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,7)',[siblingKey]);
  await migration.query("INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation) VALUES($1,'xss_workshop',6)",[sibling]);
  await storePool.query("INSERT INTO xss.profiles(user_key,name,bio,website) VALUES($1,'Sibling','keep','https://sibling.invalid')",[String(sibling)]);
  await migration.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'xss_workshop','xss_s1'),($2,'xss_workshop','xss_s1')",[owner,sibling]);
  await storePool.query("UPDATE xss.profiles SET name='Administrative original' WHERE user_key=$1",[String(owner)]);
  const graphBeforeStudentReset=(await migration.query('SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey])).rows[0].generation;
  const workshopBeforeStudentReset=(await migration.query("SELECT generation::text FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key='xss_workshop'",[owner])).rows[0].generation;
  const profileBeforeStudentReset=(await storePool.query('SELECT name,bio,website FROM xss.profiles WHERE user_key=$1',[String(owner)])).rows[0];
  const completionsBeforeStudentReset=(await migration.query("SELECT objective_id FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='xss_workshop' ORDER BY objective_id",[owner])).rows;
  const administrativeOperation=randomUUID();
  await parentJournal.begin({operationId:administrativeOperation,ownerId:owner});
  await assert.rejects(administrativeReset.resetStudent({userId:owner,workshopKey:'xss_workshop'}),
   {code:'XSS_PARENT_RESET_UNAVAILABLE'});
  assert.equal((await migration.query('SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey])).rows[0].generation,graphBeforeStudentReset);
  assert.equal((await migration.query("SELECT generation::text FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key='xss_workshop'",[owner])).rows[0].generation,workshopBeforeStudentReset);
  assert.deepEqual((await storePool.query('SELECT name,bio,website FROM xss.profiles WHERE user_key=$1',[String(owner)])).rows[0],profileBeforeStudentReset);
  assert.deepEqual((await migration.query("SELECT objective_id FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='xss_workshop' ORDER BY objective_id",[owner])).rows,completionsBeforeStudentReset);
  const expectedAdministrativeGraph=(BigInt(graphBeforeStudentReset)+1n).toString();
  const expectedAdministrativeWorkshop=(BigInt(workshopBeforeStudentReset)+1n).toString();
  const administrativeResult=await administrativeReset.resetAdministrativeStudent({
   userId:owner,workshopKey:'xss_workshop',
  });
  assert.equal(administrativeResult.operationId,administrativeOperation);
  assert.equal(administrativeResult.ownerId,owner);
  assert.equal(administrativeResult.status,'completed');
  assert.equal(administrativeResult.workshopGenerationTo,expectedAdministrativeWorkshop);
  assert.equal(administrativeResult.graphGeneration,expectedAdministrativeGraph);
  assert.equal((await migration.query("SELECT generation::text FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key='xss_workshop'",[owner])).rows[0].generation,expectedAdministrativeWorkshop);
  assert.equal((await migration.query('SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey])).rows[0].generation,expectedAdministrativeGraph);
  await storePool.query("UPDATE xss.profiles SET name='After administrative completion' WHERE user_key=$1",[String(owner)]);
  await migration.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'xss_workshop','xss_s1')",[owner]);
  const administrativeReplay=await administrativeReset.resetAdministrativeStudent({
   userId:owner,workshopKey:'xss_workshop',operationId:administrativeOperation,
  });
  assert.equal(administrativeReplay.operationId,administrativeOperation);
  assert.equal(administrativeReplay.graphGeneration,expectedAdministrativeGraph);
  assert.equal(administrativeReplay.workshopGenerationTo,expectedAdministrativeWorkshop);
  assert.equal(lifecycleAdmissions,3,'blocked student reset and both administrative requests each own one lifecycle admission');
  assert.equal((await migration.query('SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey])).rows[0].generation,expectedAdministrativeGraph);
  assert.equal((await migration.query("SELECT generation::text FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key='xss_workshop'",[owner])).rows[0].generation,expectedAdministrativeWorkshop);
  assert.equal((await storePool.query('SELECT name FROM xss.profiles WHERE user_key=$1',[String(owner)])).rows[0].name,'After administrative completion');
  assert.equal((await migration.query("SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='xss_workshop'",[owner])).rows[0].n,1);
  assert.equal((await migration.query('SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1',[siblingKey])).rows[0].generation,'7');
  assert.equal((await migration.query("SELECT generation::text FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key='xss_workshop'",[sibling])).rows[0].generation,'6');
  assert.equal((await storePool.query('SELECT name FROM xss.profiles WHERE user_key=$1',[String(sibling)])).rows[0].name,'Sibling');
  assert.equal((await migration.query("SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='xss_workshop'",[sibling])).rows[0].n,1);

  assert.deepEqual((await migration.query('SELECT state FROM identity.xss_scope_state WHERE owner_id=$1 ORDER BY scope_key',[owner])).rows,
   [{state:'active'},{state:'active'}]);
 }finally{
  const closed=await Promise.allSettled(pools.map(pool=>pool.end()));
  const errors=closed.filter(row=>row.status==='rejected').map(row=>row.reason);
  if(errors.length)throw new AggregateError(errors,'Composed reset pool cleanup failed');
 }
});
