'use strict';
// Disposable native worker proof. Controlled response-loss seams wrap real COMMIT;
// these are not claims about OS/network failure or guardian/Judge execution.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {randomUUID,createHash}=require('node:crypto');
const {createPool}=require('../../server/database/postgres');
const {migrate}=require('../../db/postgres/migrate');
const {createCtfLifecycleRepository}=require('../../server/database/postgres/ctfLifecycleRepository');
const {projectCtfBatch}=require('../../server/services/ctfProjectionWorker');
const {stageDigest}=require('../../server/agent-runtime/ctfStageJudge');
const {createCtfProjectionWorkerLifecycle}=require('../../server/services/ctfProjectionWorkerLifecycle');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_WORKER_LIFECYCLE_ISOLATED==='1';
const targets={IDENTITY:'0112_ctf_student_deletion.sql',CTF:'0010_student_deletion_delivery.sql'};
const dirs={IDENTITY:'identity-migrations',CTF:'workshop-migrations/ctf'};
const sha=x=>createHash('sha256').update(x).digest('hex');
const one=async(p,q,a=[])=>(await p.query(q,a)).rows[0];
// Fault policy is test-owned and never replaces SQL results or receipts.
function observedPool(pool,trace,label,{afterCommit}={}){
 return {async connect(){
  const client=await pool.connect();assert.equal(trace.borrowed,0,'worker may borrow only one store at a time');trace.borrowed++;
  let released=false;
  return {async query(sql,args){const result=await client.query(sql,args);if(sql==='COMMIT'){trace.commits.push(label);await afterCommit?.();}return result;},
   release(discard){assert(!released);released=true;trace.borrowed--;client.release(discard);}};
 }};
}

test('owned projection lifecycle defers deletion and drains interrupted native projection',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],owned=[],releases=[],databases=new Set();t.after(async()=>{for(const release of releases)release();for(const w of owned)await w.stop();await Promise.allSettled(pools.map(p=>p.end()));});
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_WORKER_LIFECYCLE_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit isolated pairs required');
   const urls=keys.map(k=>new URL(process.env[k]));
   for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_worklife_/);}
   assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);assert.notEqual(urls[0].username,urls[1].username);assert(!databases.has(urls[0].pathname));databases.add(urls[0].pathname);
   const [runtime,migration]=keys.map(k=>createPool(process.env,k));pools.push(runtime,migration);stores[kind]={runtime,migration};
   assert.equal((await one(runtime,'SELECT current_user AS role')).role,`dvaia_${kind.toLowerCase()}_runtime`);
   const directory=path.resolve(__dirname,'../../db/postgres',dirs[kind]);
   const prefix=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-worker-prefix-'));t.after(()=>fs.rmSync(prefix,{recursive:true,force:true}));
   for(const name of fs.readdirSync(directory).filter(n=>n.endsWith('.sql')&&n<targets[kind]))fs.copyFileSync(path.join(directory,name),path.join(prefix,name));
   await migrate(migration,prefix);
   if(state==='POPULATED'&&kind==='CTF'){
    await require('../../server/database/postgres/ctfDb').seed(migration);
    await migration.query("INSERT INTO ctf.ctf_participants(id,user_id,username) VALUES(900,900,'sibling')");
    await migration.query("INSERT INTO ctf.ctf_progress(id,participant_id,stage_id,status) VALUES(900,900,1,'completed')");
   }
   fs.copyFileSync(path.join(directory,targets[kind]),path.join(prefix,targets[kind]));await migrate(migration,prefix);assert.deepEqual(await migrate(migration,prefix),[]);
  }
  const {IDENTITY:i,CTF:c}=stores;
  await require('../../server/database/postgres/ctfDb').seed(c.migration);
  if(state==='FRESH'){await c.migration.query("INSERT INTO ctf.ctf_participants(id,user_id,username) VALUES(900,900,'sibling')");await c.migration.query("INSERT INTO ctf.ctf_progress(id,participant_id,stage_id,status) VALUES(900,900,1,'completed')");}
  const sibling=()=>c.runtime.query('SELECT * FROM ctf.ctf_progress WHERE participant_id=900 ORDER BY id').then(r=>r.rows);
  const siblingBefore=await sibling();
  const rawToken='owned-worker-'+randomUUID(),adminToken='owned-admin-'+randomUUID();
  await i.migration.query("INSERT INTO identity.users(id,username,email,password,role,admin_level) VALUES(701,'worker-owner','worker@fixture.invalid',$1,'student',0),(702,'worker-admin','admin@fixture.invalid',$1,'admin',1)",['$2b$04$'+'a'.repeat(53)]);
  const session=(await one(i.migration,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(701,$1,now()+interval '1 hour') RETURNING id",[sha(rawToken)])).id;
  const adminSession=(await one(i.migration,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(702,$1,now()+interval '1 hour') RETURNING id",[sha(adminToken)])).id;
  // Explicit migration-owned initial projection binding, not runtime activation.
  const seed=randomUUID(),stage=await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE id=1');
  await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='ready' WHERE scope_key='global'");
  await i.migration.query("INSERT INTO identity.ctf_authority(scope_key,lifecycle_state) VALUES('stage:1','ready')");
  await i.migration.query('INSERT INTO identity.ctf_stage_bindings VALUES(1,$1,0,0,$2,$3,true,$4,$5,$6,$7,$8,0,$9)',[stage.stage_number,stageDigest(stage),stage.stage_order,stage.adaptive_mode,stage.feedback_mode,JSON.parse(stage.hints).length,stage.level_score,stage.max_attempts,seed]);
  const config=Object.fromEntries((await c.runtime.query('SELECT key,value FROM ctf.ctf_config')).rows.map(r=>[r.key,r.value]));
  await i.migration.query('INSERT INTO identity.ctf_config_binding VALUES(true,0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,0,$16)',[
   ...['ctf_enabled','ctf_visible_to_students','ctf_registration_open','student_leaderboard_visible','public_leaderboard_visible','ctf_nav_visible','ctf_show_technique_feedback','ctf_show_attempt_counter'].map(k=>config[k]==='true'),
   ...['ctf_max_participants','ctf_time_limit','leaderboard_update_interval','ctf_hint_gating_attempts','ctf_hint_cost_1','ctf_hint_cost_2','ctf_hint_cost_3'].map(k=>config[k]),seed]);
  await c.migration.query('UPDATE ctf.projection_cursor SET initialized=true WHERE singleton');
  await c.migration.query("INSERT INTO ctf.projection_scopes(scope_key,revision,applied_operation_id) VALUES('global',0,$1),('stage:1',0,$1)",[seed]);
  const repository=createCtfLifecycleRepository(i.runtime);
  const scope=async({owner=true,atStage=false,progress=false,participant=false}={})=>{
   const g=await one(i.runtime,"SELECT revision::text FROM identity.ctf_authority WHERE scope_key='global'");
   const o=await one(i.runtime,"SELECT owner_generation::text FROM identity.ctf_authority WHERE scope_key='owner:701'");
   const st=await one(i.runtime,"SELECT revision::text FROM identity.ctf_authority WHERE scope_key='stage:1'");
   const p=await one(i.runtime,'SELECT participant_id::text FROM identity.ctf_participant_bindings WHERE owner_id=701');
   const pr=await one(i.runtime,'SELECT progress_id::text FROM identity.ctf_progress_bindings WHERE owner_id=701 AND owner_generation=$1 AND stage_id=1',[o?.owner_generation||'0']);
   return{globalRevision:g.revision,ownerId:owner?'701':null,ownerGeneration:owner?(o?.owner_generation||'0'):null,participantId:(atStage||participant)?p.participant_id:null,stageId:atStage?'1':null,stageRevision:atStage?st.revision:null,progressId:progress?pr.progress_id:null};
  };
  const enqueue=async(kind,body,options={})=>{
   const admin=['config_mutation','owner_reset','catalog_mutation'].includes(kind);const input={actorId:admin?'702':'701',sessionId:String(admin?adminSession:session),rawToken:admin?adminToken:rawToken,operationId:randomUUID(),kind,body,scope:await scope(options)};
   const row=await repository.enqueue(input);return{input,row};
  };
  const run=async({identity,ctfPool,signal}={})=>{const lane={borrowed:0,commits:[]};return projectCtfBatch({identity:identity||createCtfLifecycleRepository(observedPool(i.runtime,lane,'identity')),ctfPool:ctfPool||observedPool(c.runtime,lane,'ctf'),signal,maxEvents:1});};
  const count=async op=>(await one(c.runtime,'SELECT count(*)::integer AS n FROM ctf.projection_receipts WHERE operation_id=$1',[op])).n;
  const registration=await enqueue('register',{username:'worker-owner',email:null,teamName:null,teachingSessionToken:'synthetic-owned',clientIp:null,userAgent:null});
  await run();assert.equal((await repository.enqueue(registration.input)).sequence,registration.row.sequence);assert.equal(await count(registration.input.operationId),1);
  await assert.rejects(repository.enqueue({...registration.input,body:{...registration.input.body,username:'different'}}));

  async function waitFor(predicate){const end=Date.now()+5000;while(!await predicate()){assert(Date.now()<end,'native controlled phase deadline');await new Promise(r=>setTimeout(r,10));}}
  const makeWorker=(ctfPool=c.runtime,overrides={})=>{const w=createCtfProjectionWorkerLifecycle({identity:repository,ctfPool,readiness:async()=>true,pollMs:20,maxEvents:1,batchTimeoutMs:3000,drainMs:1000,...overrides});owned.push(w);return w;};
  // Two process-like lifecycle instances read the exact same durable head.
  // Barrier is after each real next transaction releases its connection.
  const concurrentStart=await enqueue('start',{}, {atStage:true});
  let arrivals=0,releaseReaders;const readerBarrier=new Promise(r=>{releaseReaders=r;});releases.push(releaseReaders);
  const distinctIdentities=[createCtfLifecycleRepository(i.runtime),createCtfLifecycleRepository(i.runtime)];
  const competitors=distinctIdentities.map(identity=>makeWorker(c.runtime,{identity:{...identity,next:async options=>{const e=await identity.next(options);if(e?.command?.operationId===concurrentStart.input.operationId){if(++arrivals===2)releaseReaders();await readerBarrier;}return e;}}}));
  try{for(const w of competitors)w.start();await waitFor(()=>arrivals===2);
   await waitFor(async()=>(await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[concurrentStart.input.operationId])).state==='applied');
   await waitFor(()=>competitors.every(w=>w.status().lastOutcome==='applied'));
   assert.equal(await count(concurrentStart.input.operationId),1);
   assert.equal((await one(c.runtime,'SELECT count(*)::int n FROM ctf.ctf_progress WHERE participant_id=$1 AND stage_id=1',[concurrentStart.input.scope.participantId])).n,1);
  }finally{releaseReaders();for(const w of competitors)assert.equal((await w.stop()).drained,true);}

  let ready=true;const gated=makeWorker(c.runtime,{readiness:async()=>ready});gated.start();await waitFor(()=>gated.status().lastOutcome==='applied');
  ready=false;gated.wake();await waitFor(()=>gated.status().lastOutcome==='not_ready');
  const waiting=await enqueue('config_mutation',{key:'ctf_show_attempt_counter',value:'true'},{owner:false});
  ready=true;gated.wake();await new Promise(r=>setTimeout(r,60));
  assert.equal((await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[waiting.input.operationId])).state,'pending');assert.equal(await count(waiting.input.operationId),0);
  gated.start();await waitFor(async()=>(await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[waiting.input.operationId])).state==='applied');assert.equal((await gated.stop()).drained,true);

  // Normal head, followed by a separately leased deletion. No synthetic event
  // receipt or worker ACK: deletion admission and projection are actual SQL.
  const first=await enqueue('config_mutation',{key:'ctf_show_attempt_counter',value:'false'},{owner:false});
  const worker=makeWorker();worker.start();await waitFor(async()=>(await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[first.input.operationId])).state==='applied');
  assert.equal((await worker.pause()).drained,true);
  const subject=703,jobId=randomUUID(),leaseToken=randomUUID();
  await i.migration.query("INSERT INTO identity.users(id,username,email,password,role,is_active) VALUES(703,'delete-703','delete-703@fixture.invalid',$1,'student',0)",['$2b$04$'+'a'.repeat(53)]);
  await i.migration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,2)',[JSON.stringify(['CTF','703'])]);
  await i.migration.query("INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by,state,lease_token,lease_expires_at) VALUES($1,703,702,'running',$2,clock_timestamp()+interval '5 minutes')",[jobId,leaseToken]);
  const steps=['revoke_runs','secureshop','excessive_agency','session_disclosure','sql_injection_workshop','nosql_injection_workshop','mcp_workshop','csrf_workshop','direct_prompt_injection','indirect_prompt_injection','supply_chain_rce','ctf','legacy_challenge','sensitive_lookup','xss','finflow','identity'];
  for(let n=0;n<steps.length;n++)await i.migration.query("INSERT INTO identity.student_deletion_steps(job_id,step_key,ordinal,state,completed_at) VALUES($1,$2,$3,$4,CASE WHEN $3<11 THEN clock_timestamp() ELSE NULL END)",[jobId,steps[n],n,n<11?'completed':'pending']);
  await i.migration.query('INSERT INTO identity.student_deletion_run_blocks(owner_key,job_id) VALUES($1,$2)',[JSON.stringify(['CTF','703']),jobId]);
  const deletion=require('../../server/database/postgres/ctfDeletionRepository').createCtfDeletionRepository(i.runtime);
  const {projectCtfDeletion}=require('../../server/database/postgres/ctfDeletionProjectionAdapter');
  const {withCtfTransaction}=require('../../server/database/postgres/ctfLifecycleRepository');
  const deletionScope={jobId,leaseToken,subjectId:subject},event=await deletion.admit(deletionScope);
  const cursorBefore=await one(i.runtime,"SELECT applied_sequence FROM identity.ctf_authority WHERE scope_key='global'");
  worker.start();await waitFor(()=>worker.status().lastOutcome==='deferred');
  assert.equal(worker.status().state,'running');assert.equal(await count(event.command.operationId),0);
  assert.deepEqual(await one(i.runtime,"SELECT applied_sequence FROM identity.ctf_authority WHERE scope_key='global'"),cursorBefore);
  const receipt=await withCtfTransaction(c.runtime,client=>projectCtfDeletion(client,event));
  assert.equal((await deletion.acknowledge(deletionScope,event,receipt)).completed,true);
  const after=await enqueue('config_mutation',{key:'ctf_show_attempt_counter',value:'true'},{owner:false});worker.wake();
  await waitFor(async()=>(await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[after.input.operationId])).state==='applied');
  assert.equal(await count(event.command.operationId),1);assert.equal(await count(after.input.operationId),1);assert.equal((await worker.stop()).drained,true);

  // Hold only the test-owned return AFTER an actual CTF COMMIT. Abort must
  // prevent identity ACK; a new owned worker reconciles the retained receipt.
  let committed=false,releaseBarrier;const barrier=new Promise(r=>{releaseBarrier=r;});releases.push(releaseBarrier);
  const lane={borrowed:0,commits:[]};
  const heldPool=observedPool(c.runtime,lane,'ctf',{afterCommit:async()=>{committed=true;await barrier;}});
  const interrupted=await enqueue('config_mutation',{key:'ctf_show_attempt_counter',value:'false'},{owner:false});
  const interruptedWorker=makeWorker(heldPool);interruptedWorker.start();
  try{await waitFor(()=>committed);assert.equal((await interruptedWorker.stop()).drained,true);
   assert.equal(lane.borrowed,0);assert.equal((await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[interrupted.input.operationId])).state,'pending');
   assert.equal(await count(interrupted.input.operationId),1);
  }finally{releaseBarrier();}
  const recovery=makeWorker();recovery.start();await waitFor(async()=>(await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[interrupted.input.operationId])).state==='applied');
  assert.equal(await count(interrupted.input.operationId),1);assert.equal((await recovery.stop()).drained,true);
  assert.deepEqual(await sibling(),siblingBefore);
 }
});
