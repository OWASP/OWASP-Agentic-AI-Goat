'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');

test('native run drain fences all generations, waits for active work and aborts without a leaked lease',{
 skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_RUN_DRAIN_RUNTIME_URL,
},async()=>{
 for(const key of ['PG_RUN_DRAIN_RUNTIME_URL','PG_RUN_DRAIN_MIGRATION_URL','PG_RUN_DRAIN_LEASE_URL'])assert.match(new URL(process.env[key]).pathname,/^\/owasp_ai_goat_test_/);
 const {createPool}=require('../../server/database/postgres');
 const runtime=createPool(process.env,'PG_RUN_DRAIN_RUNTIME_URL');
 const migration=createPool(process.env,'PG_RUN_DRAIN_MIGRATION_URL');
 const leasePool=createPool(process.env,'PG_RUN_DRAIN_LEASE_URL',{purpose:'lease'});
 const heldCleanup=[];
 try{
  const identityApi=require('../../server/database/postgres/identityRepository');
  await identityApi.initializeIdentityRepository(runtime,migration);
  await migration.query(await fs.readFile(path.resolve(__dirname,'../../docs/modernization/drafts/student-deletion-journal.sql'),'utf8'));
  const users=identityApi.createIdentityRepository(runtime),passwordHash=await require('bcryptjs').hash('owned fixture',4);
  const create=name=>users.createUser({username:name,email:`${name}@fixture.test`,passwordHash});
  const admin=await create('drain_admin'),subject=await create('drain_subject'),sibling=await create('drain_sibling');
  await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[admin.id]);
  const {RUN_FAMILIES}=require('../../server/database/postgres/agentRunReadRepository');
  const jobs=require('../../server/database/postgres/studentDeletionRepository').createStudentDeletionRepository(runtime,{steps:['revoke_runs','identity']});
  const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(runtime,{leasePool});
  const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'MCP',ledger});
  const drain=require('../../server/services/studentDeletionRunDrain').createStudentDeletionRunDrain({pool:runtime,ledger,timeoutMs:10000});

  async function heldRun(userId){
   let release,execution,startedResolve;
   const gate=new Promise(resolve=>{release=resolve;});
   const started=new Promise(resolve=>{startedResolve=resolve;});
   const result=coordinator.run(String(userId),{},async current=>{execution=current;startedResolve();await gate;return{done:true};}).then(value=>({value}),error=>({error}));
   heldCleanup.push(async()=>{release();await result;});
   await started;return{release,get execution(){return execution;},result};
  }
  async function waitForGeneration(ownerKey,minimum=1){
   for(let attempt=0;attempt<200;attempt++){
    const row=(await runtime.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey])).rows[0];
    if(row&&Number(row.generation)>=minimum)return Number(row.generation);
    await new Promise(resolve=>setTimeout(resolve,10));
   }
   throw new Error('Generation was not invalidated');
  }

  const held=await heldRun(subject.id);
  const siblingKey=JSON.stringify(['MCP',String(sibling.id)]);
  await runtime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)',[siblingKey]);
  const admitted=await jobs.admit({requesterId:admin.id,subjectId:subject.id});
  assert.equal((await runtime.query('SELECT count(*)::int AS n FROM identity.student_deletion_run_blocks WHERE job_id=$1',[admitted.jobId])).rows[0].n,RUN_FAMILIES.length);
  const claim=await jobs.claim(admitted.jobId);let cleanupStarted=false;
  const pending=drain({subjectId:subject.id,jobId:admitted.jobId,check:()=>jobs.renew({jobId:admitted.jobId,leaseToken:claim.leaseToken})}).then(value=>{cleanupStarted=true;return value;});
  await waitForGeneration(held.execution.ownerKey);
  await assert.rejects(held.execution.check(),{name:'AbortError'});
  let lateEffects=0;
  await assert.rejects(held.execution.effect('late',async()=>{lateEffects++;}),{name:'AbortError'});
  assert.equal(lateEffects,0,'Invalidation fences a late effect before its callback');
  const subjectOwnerKeys=RUN_FAMILIES.map(family=>JSON.stringify([family,String(subject.id)]));
  for(let attempt=0;attempt<200;attempt++){
   const count=(await runtime.query('SELECT count(*)::int AS n FROM graph_runtime.owners WHERE owner_key=ANY($1::text[]) AND generation>=1',[subjectOwnerKeys])).rows[0].n;
   if(count===RUN_FAMILIES.length)break;
   if(attempt===199)assert.fail('Every installed owner generation must be invalidated before drain');
   await new Promise(resolve=>setTimeout(resolve,10));
  }
  await new Promise(resolve=>setTimeout(resolve,50));
  assert.equal(cleanupStarted,false,'Cleanup cannot advance while the old owner lease is held');
  assert.equal((await runtime.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[siblingKey])).rows[0].generation,'0');
  held.release();assert.equal((await held.result).error?.name,'AbortError');
  assert.deepEqual(await pending,{completed:true,invalidatedOwners:RUN_FAMILIES.length});

  const abortSubject=await create('drain_abort');
  const abortHeld=await heldRun(abortSubject.id);
  const abortJob=await jobs.admit({requesterId:admin.id,subjectId:abortSubject.id});
  const abortClaim=await jobs.claim(abortJob.jobId),controller=new AbortController();
  const aborted=drain({subjectId:abortSubject.id,jobId:abortJob.jobId,signal:controller.signal,
   check:()=>jobs.renew({jobId:abortJob.jobId,leaseToken:abortClaim.leaseToken})});
  await waitForGeneration(abortHeld.execution.ownerKey);
  await new Promise(resolve=>setTimeout(resolve,50));controller.abort(Object.assign(new Error('fixture cancellation'),{name:'AbortError'}));
  await assert.rejects(aborted,{name:'AbortError'});
  abortHeld.release();assert.equal((await abortHeld.result).error?.name,'AbortError');
  await new Promise(resolve=>setTimeout(resolve,50));
  const probe=await leasePool.connect();
  try{
   const acquired=(await probe.query('SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS acquired',[abortHeld.execution.ownerKey])).rows[0].acquired;
   assert.equal(acquired,true,'Cancelled acquisition does not later retain the owner lease');
   await probe.query('SELECT pg_advisory_unlock(hashtextextended($1,0))',[abortHeld.execution.ownerKey]);
  }finally{probe.release();}

  const slowSubject=await create('drain_heartbeat');
  const slowJob=await jobs.admit({requesterId:admin.id,subjectId:slowSubject.id});
  let adapterStartedResolve;
  const adapterStarted=new Promise(resolve=>{adapterStartedResolve=resolve;});
  const worker=require('../../server/services/studentDeletionWorker').createStudentDeletionWorker({repository:jobs,adapters:{
   revoke_runs:async({signal})=>{adapterStartedResolve();await new Promise(resolve=>setTimeout(resolve,1400));signal.throwIfAborted();return{completed:true};},
  }});
  const slowRun=worker.run(slowJob.jobId,{leaseMs:1000});
  await adapterStarted;await new Promise(resolve=>setTimeout(resolve,1100));
  assert.equal(await jobs.claim(slowJob.jobId,1000),null,'Native heartbeat retains the lease beyond its original deadline');
  assert.deepEqual(await slowRun,{state:'incomplete',code:'DELETION_INCOMPLETE'});
  assert.equal((await runtime.query("SELECT state FROM identity.student_deletion_steps WHERE job_id=$1 AND step_key='revoke_runs'",[slowJob.jobId])).rows[0].state,'completed');
 }finally{
  await Promise.allSettled(heldCleanup.map(cleanup=>cleanup()));
  await Promise.all([runtime.end(),migration.end(),leasePool.end()]);
 }
});
