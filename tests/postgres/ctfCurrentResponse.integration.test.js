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
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_CURRENT_RESPONSE_ISOLATED==='1';
const targets={IDENTITY:'0111_ctf_operation_recovery.sql',CTF:'0008_authoritative_decision_delivery.sql'};
// Explicit independent qualification subset: qualified0101-0109 then0111.
// Qualified preparation bootstrap0110/0009 is intentionally outside this fixture closure; no mounted readiness claim.
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

test('current response native lock compatibility and scope fences',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],databases=new Set();t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_OPERATION_RECOVERY_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit isolated pairs required');
   const urls=keys.map(k=>new URL(process.env[k]));
   for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_opread_/);}
   assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);assert.notEqual(urls[0].username,urls[1].username);assert(!databases.has(urls[0].pathname));databases.add(urls[0].pathname);
   const [runtime,migration]=keys.map(k=>createPool(process.env,k));pools.push(runtime,migration);stores[kind]={runtime,migration};
   assert.equal((await one(runtime,'SELECT current_user AS role')).role,`dvaia_${kind.toLowerCase()}_runtime`);
   const directory=path.resolve(__dirname,'../../db/postgres',dirs[kind]);
   const prefix=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-worker-prefix-'));t.after(()=>fs.rmSync(prefix,{recursive:true,force:true}));
   for(const name of fs.readdirSync(directory).filter(n=>n.endsWith('.sql')&&n<targets[kind]&&!n.startsWith('0110_')))fs.copyFileSync(path.join(directory,name),path.join(prefix,name));
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

  const {createCtfOperationRecoveryRepository}=require('../../server/database/postgres/ctfOperationRecoveryRepository');
  const reader=createCtfOperationRecoveryRepository(i.runtime),sessionInput={actorId:701,sessionId:session,rawToken};
  const args={operationId:registration.input.operationId,session:sessionInput},read=()=>reader.readAuthorized(args);
  assert.equal((await read()).state,'pending');
  await assert.rejects(i.migration.query('UPDATE identity.ctf_outbox SET command_hash=$1 WHERE operation_id=$2',['f'.repeat(64),args.operationId]),/immutable/);
  // Migration-role state seam tests blocked reads without claiming a real
  // projection failure. Restore pending before executing the real worker.
  await i.migration.query("UPDATE identity.ctf_outbox SET state='blocked' WHERE operation_id=$1",[args.operationId]);
  assert.equal((await read()).state,'blocked');assert.equal((await read()).currentState,false);
  await i.migration.query("UPDATE identity.ctf_outbox SET state='pending' WHERE operation_id=$1",[args.operationId]);await run();
  const saved=await read();assert.equal(saved.state,'applied');assert.equal(saved.currentState,false);
  assert.equal(saved.canonicalCommand,(await one(i.runtime,'SELECT canonical_command FROM identity.ctf_outbox WHERE operation_id=$1',[args.operationId])).canonical_command);
  assert.equal((await read()).canonicalResult,saved.canonicalResult);
  const {createCtfCurrentResponseRepository}=require('../../server/database/postgres/ctfCurrentResponseRepository');
  const {createCtfAuthorityResponseProjection}=require('../../server/services/ctfAuthorityResponseProjection');
  const current=createCtfCurrentResponseRepository({identityPool:i.runtime,ctfPool:c.runtime});
  const projector=createCtfAuthorityResponseProjection({repository:current});
  const currentRegister=await current.read(args); // Real0111 locks require READ WRITE.
  assert.equal(String(currentRegister.participant.participant_id),currentRegister.receipt.data.participantId);
  assert.equal((await projector.project({command:saved.command,session:sessionInput})).body.sessionToken,'synthetic-owned');
  // Migration-owned synthetic pending seam; UUID satisfies the real state invariant.
  await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=$1 WHERE scope_key='owner:701'",[randomUUID()]);
  await assert.rejects(current.read(args),{code:'CTF_RESPONSE_STALE'});
  await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='ready',pending_operation_id=NULL WHERE scope_key='owner:701'");
  const started=await enqueue('start',{}, {atStage:true});await run();
  const startArgs={operationId:started.input.operationId,session:sessionInput},startOperation=await reader.readAuthorized(startArgs);
  const response=await projector.project({command:startOperation.command,session:sessionInput});
  assert.equal(response.status,200);assert.equal(response.body.stage.id,1);assert.equal(response.body.attemptsSoFar,0);
  assert(!Object.hasOwn(response.body.stage,'system_prompt'));assert(!Object.hasOwn(response.body.stage,'success_criteria'));
  await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=$1 WHERE scope_key='stage:1'",[randomUUID()]);
  await assert.rejects(current.read(startArgs),{code:'CTF_RESPONSE_STALE'});
  await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='ready',pending_operation_id=NULL WHERE scope_key='stage:1'");
  await i.migration.query("UPDATE identity.ctf_authority SET revision=revision+1 WHERE scope_key='stage:1'");
  await assert.rejects(current.read(startArgs),{code:'CTF_RESPONSE_STALE'});
  await i.migration.query("UPDATE identity.ctf_authority SET revision=revision-1 WHERE scope_key='stage:1'");
  assert.equal((await current.read(startArgs)).stage.stage_id,'1');
  await c.migration.query('UPDATE ctf.ctf_stages SET stage_name=$1 WHERE id=1',['changed-owned-stage']);
  await assert.rejects(projector.project({command:startOperation.command,session:sessionInput}),{code:'CTF_RESPONSE_STALE'});
  await c.migration.query('UPDATE ctf.ctf_stages SET stage_name=$1 WHERE id=1',[stage.stage_name]);
  // Test-owned prior attempt counters, not guardian/Judge proof or completion.
  await i.migration.query('UPDATE identity.ctf_progress_bindings SET attempts_count=3,failed_attempts=3 WHERE owner_id=701');
  await c.migration.query('UPDATE ctf.ctf_progress SET attempts_count=3,failed_attempts=3 WHERE participant_id=$1',[currentRegister.participant.participant_id]);
  const hinted=await enqueue('hint',{expectedHints:0,cost:Number(config.ctf_hint_cost_1)},{atStage:true,progress:true});await run();
  const hintArgs={operationId:hinted.input.operationId,session:sessionInput},hintOperation=await reader.readAuthorized(hintArgs);
  const hintResponse=await projector.project({command:hintOperation.command,session:sessionInput});
  assert.equal(hintResponse.body.hint,JSON.parse(stage.hints)[0]);assert.equal(hintResponse.body.hintsUsed,1);
  const interrupted=createCtfAuthorityResponseProjection({repository:{read:current.read,readStage:async(...params)=>{const value=await current.readStage(...params);await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=$1 WHERE scope_key='owner:701'",[randomUUID()]);return value;}}});
  await assert.rejects(interrupted.project({command:startOperation.command,session:sessionInput}),{code:'CTF_RESPONSE_STALE'});
  await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='ready',pending_operation_id=NULL WHERE scope_key='owner:701'");
  assert.equal(await reader.readAuthorized({...args,operationId:randomUUID()}),null);
  assert.equal(await reader.readAuthorized({...args,session:{actorId:702,sessionId:adminSession,rawToken:adminToken}}),null);
  const second=(await one(i.migration,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(701,$1,now()+interval '1 hour') RETURNING id",[sha('second')])).id;
  assert.equal(await reader.readAuthorized({...args,session:{actorId:701,sessionId:second,rawToken:'second'}}),null);
  await assert.rejects(reader.readAuthorized({...args,session:{...sessionInput,rawToken:'wrong'}}),{code:'28000'});
  await i.migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[session]);await assert.rejects(read(),{code:'28000'});await assert.rejects(current.read(args),{code:'28000'});
  await i.migration.query('UPDATE identity.user_sessions SET is_active=1,expires_at=now()-interval \'1 second\' WHERE id=$1',[session]);await assert.rejects(read(),{code:'28000'});await assert.rejects(current.read(args),{code:'28000'});
  await i.migration.query("UPDATE identity.user_sessions SET expires_at=now()+interval '1 hour' WHERE id=$1",[session]);
  const reset=await enqueue('owner_reset',{}, {participant:true});await assert.rejects(current.read(startArgs),{code:'CTF_RESPONSE_STALE'});await run();await assert.rejects(current.read(args),{code:'CTF_RESPONSE_STALE'});await assert.rejects(current.read(hintArgs),{code:'CTF_RESPONSE_STALE'});
  assert.equal((await read()).canonicalResult,saved.canonicalResult);assert.equal((await read()).currentState,false,'old registration cannot restore current membership');
  const adminArgs={operationId:reset.input.operationId,session:{actorId:702,sessionId:adminSession,rawToken:adminToken}};
  assert.equal((await reader.readAuthorized(adminArgs)).state,'applied');
  await i.migration.query("UPDATE identity.users SET role='student',admin_level=0 WHERE id=702");await assert.rejects(reader.readAuthorized(adminArgs),{code:'42501'});await assert.rejects(current.read(adminArgs),{code:'42501'});
  assert.deepEqual(await sibling(),siblingBefore);
  await i.migration.query('INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by) VALUES($1,701,702)',[randomUUID()]);await assert.rejects(read(),{code:'28000'});
 }
});
