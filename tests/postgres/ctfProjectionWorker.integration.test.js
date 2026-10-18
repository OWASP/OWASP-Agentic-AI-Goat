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
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_PROJECTION_WORKER_ISOLATED==='1';
const targets={IDENTITY:'0105_ctf_lifecycle_projection.sql',CTF:'0007_ordered_projection_receipts.sql'};
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

test('real enqueue, dispatcher and acknowledgment recover exact committed effects without model calls',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],databases=new Set();t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_WORKER_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit isolated pairs required');
   const urls=keys.map(k=>new URL(process.env[k]));
   for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_worker_/);}
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
   const p=await one(i.runtime,'SELECT participant_id::text FROM identity.ctf_participant_bindings WHERE owner_id=701');
   const pr=await one(i.runtime,'SELECT progress_id::text FROM identity.ctf_progress_bindings WHERE owner_id=701 AND owner_generation=$1 AND stage_id=1',[o?.owner_generation||'0']);
   return{globalRevision:g.revision,ownerId:owner?'701':null,ownerGeneration:owner?(o?.owner_generation||'0'):null,participantId:(atStage||participant)?p.participant_id:null,stageId:atStage?'1':null,stageRevision:atStage?'0':null,progressId:progress?pr.progress_id:null};
  };
  const enqueue=async(kind,body,options={})=>{
   const admin=['config_mutation','owner_reset'].includes(kind);const input={actorId:admin?'702':'701',sessionId:String(admin?adminSession:session),rawToken:admin?adminToken:rawToken,operationId:randomUUID(),kind,body,scope:await scope(options)};
   const row=await repository.enqueue(input);return{input,row};
  };
  const run=async({identity,ctfPool,signal}={})=>{const lane={borrowed:0,commits:[]};return projectCtfBatch({identity:identity||createCtfLifecycleRepository(observedPool(i.runtime,lane,'identity')),ctfPool:ctfPool||observedPool(c.runtime,lane,'ctf'),signal,maxEvents:1});};
  const count=async op=>(await one(c.runtime,'SELECT count(*)::integer AS n FROM ctf.projection_receipts WHERE operation_id=$1',[op])).n;
  const registration=await enqueue('register',{username:'worker-owner',email:null,teamName:null,teachingSessionToken:'synthetic-owned',clientIp:null,userAgent:null});
  await run();assert.equal((await repository.enqueue(registration.input)).sequence,registration.row.sequence);assert.equal(await count(registration.input.operationId),1);
  await assert.rejects(repository.enqueue({...registration.input,body:{...registration.input.body,username:'different'}}));
  const start=await enqueue('start',{}, {atStage:true});
  // Barrier ensures both workers read the same pending event before either applies it.
  let readers=0,open;const barrier=new Promise(r=>{open=r;});
  const concurrentIdentity={...repository,async next(opts){const e=await repository.next(opts);if(++readers===2)open();await barrier;return e;}};
  const outcomes=await Promise.all([run({identity:concurrentIdentity}),run({identity:concurrentIdentity})]);
  assert(outcomes.every(r=>r[0].state==='applied'));assert.equal(await count(start.input.operationId),1);
  const attempt=await enqueue('admit_attempt',{failed:false},{atStage:true,progress:true});await run();
  for(let n=1;n<Number(config.ctf_hint_gating_attempts);n++){await enqueue('admit_attempt',{failed:false},{atStage:true,progress:true});await run();}
  const hint=await enqueue('hint',{expectedHints:0,cost:Number(config.ctf_hint_cost_1)},{atStage:true,progress:true});await run();
  const progressId=hint.input.scope.progressId;
  assert.equal((await one(c.runtime,'SELECT hints_used FROM ctf.ctf_progress WHERE id=$1',[progressId])).hints_used,1);
  assert.equal((await one(i.runtime,'SELECT hints_used FROM identity.ctf_progress_bindings WHERE progress_id=$1',[progressId])).hints_used,1);
  // Real CTF COMMIT succeeds, but the worker observes a response loss and must not ack/retry.
  const pending=await enqueue('config_mutation',{key:'ctf_show_attempt_counter',value:'false'},{owner:false});
  const trace={borrowed:0,commits:[]};let injected=0;
  const lost=observedPool(c.runtime,trace,'ctf',{afterCommit(){injected++;throw Error('controlled committed response loss');}});
  await assert.rejects(run({ctfPool:lost}),/controlled committed response loss/);assert.equal(injected,1);assert.equal(trace.borrowed,0);
  assert.equal(await count(pending.input.operationId),1);assert.equal((await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[pending.input.operationId])).state,'pending');
  const receiptBefore=await one(c.runtime,'SELECT * FROM ctf.projection_receipts WHERE operation_id=$1',[pending.input.operationId]);await run();
  assert.deepEqual(await one(c.runtime,'SELECT * FROM ctf.projection_receipts WHERE operation_id=$1',[pending.input.operationId]),receiptBefore);
  // Identity COMMIT response loss retains its real acknowledgment and never redelivers.
  const next=await enqueue('config_mutation',{key:'ctf_show_attempt_counter',value:'true'},{owner:false});let ackCommits=0;
  const identityLoss=createCtfLifecycleRepository(observedPool(i.runtime,trace,'identity',{afterCommit(){if(++ackCommits===2)throw Error('controlled acknowledgment response loss');}}));
  await assert.rejects(run({identity:identityLoss}),/controlled acknowledgment response loss/);
  assert.equal((await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[next.input.operationId])).state,'applied');assert.equal(await count(next.input.operationId),1);assert.deepEqual(await run(),[]);
  // Cancellation exactly after durable CTF COMMIT leaves identity pending for explicit recovery.
  const cancelEvent=await enqueue('config_mutation',{key:'ctf_show_attempt_counter',value:'false'},{owner:false});const controller=new AbortController();
  await assert.rejects(run({signal:controller.signal,ctfPool:observedPool(c.runtime,trace,'ctf',{afterCommit(){controller.abort();}})}));
  assert.equal(await count(cancelEvent.input.operationId),1);assert.equal((await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[cancelEvent.input.operationId])).state,'pending');await run();
  assert.equal(await count(cancelEvent.input.operationId),1);assert.equal(trace.borrowed,0);
  assert.equal((await one(c.runtime,'SELECT attempts_count FROM ctf.ctf_progress WHERE id=$1',[progressId])).attempts_count,Number(config.ctf_hint_gating_attempts));
  assert.equal((await one(i.runtime,'SELECT count(*)::integer AS n FROM identity.ctf_attempt_admissions WHERE operation_id=$1',[attempt.input.operationId])).n,1);
  const immutableReceipts=(await c.runtime.query('SELECT * FROM ctf.projection_receipts ORDER BY sequence')).rows;
  const reset=await enqueue('owner_reset',{}, {participant:true});await run();
  assert.equal((await one(c.runtime,'SELECT count(*)::integer AS n FROM ctf.ctf_progress WHERE participant_id=$1',[reset.input.scope.participantId])).n,0);
  assert.equal((await one(i.runtime,"SELECT owner_generation::text FROM identity.ctf_authority WHERE scope_key='owner:701'")).owner_generation,String(BigInt(reset.input.scope.ownerGeneration)+1n));
  assert.deepEqual((await c.runtime.query('SELECT * FROM ctf.projection_receipts WHERE sequence<$1 ORDER BY sequence',[reset.row.sequence])).rows,immutableReceipts);
  assert.equal((await repository.enqueue(reset.input)).sequence,reset.row.sequence);assert.deepEqual(await run(),[]);
  assert.deepEqual(await sibling(),siblingBefore);
  const g=await one(i.runtime,"SELECT applied_sequence::text FROM identity.ctf_authority WHERE scope_key='global'");
  assert.equal((await one(c.runtime,'SELECT applied_sequence::text FROM ctf.projection_cursor')).applied_sequence,g.applied_sequence);
  assert.equal((await one(i.runtime,"SELECT count(*)::integer AS n FROM identity.ctf_outbox WHERE state<>'applied'")).n,0);
 }
});
