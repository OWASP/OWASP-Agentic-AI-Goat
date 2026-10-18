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
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_ADMIN_READ_ISOLATED==='1';
const targets={IDENTITY:'0111_ctf_operation_recovery.sql',CTF:'0008_authoritative_decision_delivery.sql'};
// Explicit independent qualification subset: qualified0101-0109 then0111.
// Qualified bootstrap0110/0009 intentionally excluded from this operation-reader closure.
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

test('coherent current read native helper shapes and publication fences',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],databases=new Set();t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_ADMIN_READ_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit isolated pairs required');
   const urls=keys.map(k=>new URL(process.env[k]));
   for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_adminread_/);}
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
  // POPULATED sibling is intentionally created before the target migration;
  // FRESH creates the same owned historical fixture only after fresh migration.
  if(state==='FRESH'){
   await c.migration.query("INSERT INTO ctf.ctf_participants(id,user_id,username) VALUES(900,900,'sibling')");
   await c.migration.query("INSERT INTO ctf.ctf_progress(id,participant_id,stage_id,status) VALUES(900,900,1,'completed')");
  }
  assert.equal((await one(c.runtime,'SELECT count(*)::int n FROM ctf.ctf_participants WHERE id=900 AND user_id=900')).n,1);
  assert.equal((await one(c.runtime,"SELECT count(*)::int n FROM ctf.ctf_progress WHERE id=900 AND participant_id=900 AND stage_id=1 AND status='completed'")).n,1);
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
  const {createCtfAuthorityRequestRepository}=require('../../server/database/postgres/ctfAuthorityRequestRepository');
  const {createCtfAuthorityPrepare}=require('../../server/services/ctfAuthorityPrepare');
  const {createCtfOperationRecoveryRepository}=require('../../server/database/postgres/ctfOperationRecoveryRepository');
  const {createCtfCurrentResponseRepository}=require('../../server/database/postgres/ctfCurrentResponseRepository');
  const {createCtfAuthorityResponseProjection}=require('../../server/services/ctfAuthorityResponseProjection');
  const preparationReader=createCtfAuthorityRequestRepository(i.runtime),prepare=createCtfAuthorityPrepare({repository:preparationReader});
  const operations=createCtfOperationRecoveryRepository(i.runtime),current=createCtfCurrentResponseRepository({identityPool:i.runtime,ctfPool:c.runtime}),responses=createCtfAuthorityResponseProjection({repository:current});
  const learner={actorId:'701',sessionId:String(session),rawToken},instructor={actorId:'702',sessionId:String(adminSession),rawToken:adminToken};
  async function execute(kind,input,who=instructor){
   const prepared=await prepare({kind,input,session:who});const operationId=randomUUID();
   await repository.enqueue({...who,operationId,kind,...prepared});await run();
   const operation=await operations.readAuthorized({operationId,session:who});assert.equal(operation.state,'applied');
   return{operation,who,response:await responses.project({command:operation.command,session:who})};
  }

  // Historical inactive sibling has no current identity membership; its old
  // progress remains in historical aggregates without inventing authority.
  await c.migration.query('UPDATE ctf.ctf_participants SET is_active=0 WHERE id=900');
  // Explicit historical fixture event for the already inactive sibling; this is
  // not a completion/model receipt. owner_remove legitimately deletes its own events.
  await c.migration.query("INSERT INTO ctf.ctf_events(event_type,participant_id,event_data,is_public) VALUES('new_participant',900,$1,1)",[JSON.stringify({username:'sibling'})]);
  for(const st of (await c.runtime.query('SELECT * FROM ctf.ctf_stages WHERE id<>1 ORDER BY id')).rows){
   await i.migration.query("INSERT INTO identity.ctf_authority(scope_key,lifecycle_state) VALUES($1,'ready')",['stage:'+st.id]);
   await i.migration.query('INSERT INTO identity.ctf_stage_bindings VALUES($1,$2,0,0,$3,$4,true,$5,$6,$7,$8,$9,0,$10)',[st.id,st.stage_number,stageDigest(st),st.stage_order,st.adaptive_mode,st.feedback_mode,JSON.parse(st.hints).length,st.level_score,st.max_attempts,seed]);
  }
  const {createCtfCurrentReadRepository}=require('../../server/database/postgres/ctfCurrentReadRepository');
  const reads=createCtfCurrentReadRepository({identityPool:i.runtime,ctfPool:c.runtime,readiness:async()=>true});
  const read=(kind,session=learner)=>reads.read({kind,session});
  const registration=await execute('register',{teamName:'native'},learner);
  const status=await read('status');assert.equal(status.registered,true);assert.equal(status.participant.id,Number(registration.response.body.participantId));
  assert(Array.isArray((await read('stages')).stages));assert.equal((await read('config')).config.current_participants,1);
  assert(Array.isArray((await read('leaderboard',null)).leaderboard));assert((await read('events',null)).events.some(e=>e.event_type==='new_participant'&&e.stage_id===null));
  assert.equal((await read('analytics',instructor)).analytics.participants.total,1);await assert.rejects(read('analytics'),{code:'ADMIN_REQUIRED'});
  for(const kind of ['adminStages','adminAttempts','adminParticipants'])await assert.rejects(read(kind,learner),{code:'ADMIN_REQUIRED'});
  const full=(await read('adminStages',instructor)).stages;assert(full.every(s=>Object.hasOwn(s,'system_prompt')&&Object.hasOwn(s,'success_criteria')));
  assert((await read('adminParticipants',instructor)).participants.some(p=>p.id===900&&p.is_active===0));
  assert.deepEqual((await read('adminAttempts',instructor)).attempts,[]);
  // Migration-owned historical roster/equal-time attempt fixtures, never credit.
  await c.migration.query("INSERT INTO ctf.ctf_participants(id,user_id,username,is_active) SELECT x,x,'historical-'||x,0 FROM generate_series(2000,2256) x");
  const roster=(await read('adminParticipants',instructor)).participants;
  assert.equal(roster.filter(p=>p.id>=2000&&p.id<=2256).length,257);assert.equal(roster.length,259);
  const seeded=(await c.migration.query("INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,blocked,was_successful,technique_tag,attempt_timestamp) VALUES(900,1,1,'older equal time',0,0,'other','2026-01-01'),(900,1,2,'newer equal time',1,0,'other','2026-01-01') RETURNING id")).rows;
  const attempts=(filters,limit=1)=>reads.read({kind:'adminAttempts',session:instructor,filters,limit});
  assert.equal((await attempts({participantId:900,stageId:1,offset:0})).attempts[0].id,seeded[1].id);
  assert.equal((await attempts({participantId:900,stageId:1,offset:1})).attempts[0].id,seeded[0].id);
  assert.equal((await attempts({participantId:900,blocked:true,techniqueTag:'other',wasSuccessful:false})).attempts[0].id,seeded[1].id);
  await execute('config_mutation',{key:'ctf_visible_to_students',value:'false'});
  await execute('config_mutation',{key:'ctf_enabled',value:'false'});
  for(const kind of ['adminStages','adminAttempts','adminParticipants'])assert(await read(kind,instructor));
  await assert.rejects(read('stages',learner),{code:'CTF_DISABLED'});
  await execute('config_mutation',{key:'ctf_enabled',value:'true'});
  await execute('config_mutation',{key:'ctf_visible_to_students',value:'true'});
  const {createCtfAdminPreviewSnapshot}=require('../../server/services/ctfAdminPreviewSnapshot');
  const preview=createCtfAdminPreviewSnapshot({current:reads});
  const captured=await preview.capture({stageId:1,session:instructor});assert.equal(await preview.revalidate(captured.lease),true);
  // Session revocation between capture and publication uses real independent SQL.
  await i.migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[adminSession]);
  await assert.rejects(preview.revalidate(captured.lease),{code:'SESSION_REVOKED'});
  await i.migration.query('UPDATE identity.user_sessions SET is_active=1 WHERE id=$1',[adminSession]);
  const aba=await preview.capture({stageId:1,session:instructor});
  const originalName=aba.stage.stage_name;
  await execute('catalog_mutation',{action:'update',stageId:'1',fields:{stage_name:'temporary edit'}});
  await execute('catalog_mutation',{action:'update',stageId:'1',fields:{stage_name:originalName}});
  assert.equal(stageDigest(await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE id=1')),stageDigest(aba.stage));
  await assert.rejects(preview.revalidate(aba.lease),{code:'CTF_PREVIEW_STALE'});
  // A later allocated stage-local command does not globally invalidate unrelated
  // config or history before its projection. Pending relevant stage is denied.
  const prepared=await prepare({kind:'catalog_mutation',input:{action:'update',stageId:'1',fields:{stage_name:'Read fence stage'}},session:instructor});const operationId=randomUUID();
  await repository.enqueue({...instructor,operationId,kind:'catalog_mutation',...prepared});
  assert.equal((await read('config')).config.current_participants,1);
  await assert.rejects(read('stages'),{code:'CTF_READ_UNAVAILABLE'});
  // Commit the real CTF projection while deliberately failing identity ACK.
  await assert.rejects(run({identity:{...repository,acknowledge:async()=>{throw Error('controlled ACK withheld');}}}),/controlled ACK withheld/);
  await assert.rejects(read('config'),{code:'CTF_READ_UNAVAILABLE'});await run();
  assert.equal((await read('stages')).stages.find(x=>x.id===1).stage_name,'Read fence stage');
  await assert.rejects(preview.revalidate(captured.lease),{code:'CTF_PREVIEW_STALE'});
  // Pause an owner mutation before mirror application: current membership reads
  // deny even though CTF still retains the pre-reset participant.
  const resetPrepared=await prepare({kind:'owner_reset',input:{ownerId:'701'},session:instructor});const resetId=randomUUID();
  await repository.enqueue({...instructor,operationId:resetId,kind:'owner_reset',...resetPrepared});
  await assert.rejects(read('status'),{code:'CTF_READ_UNAVAILABLE'});await run();
  assert.equal((await read('status')).registered,true);
  await execute('owner_remove',{ownerId:'701'});
  assert.equal((await read('status')).registered,false);
  const afterRemoveEvents=(await read('events',null)).events;
  assert(!afterRemoveEvents.some(e=>e.participant_id===Number(registration.response.body.participantId)),'owner_remove deletes its own events');
  assert(afterRemoveEvents.some(e=>e.participant_id===900&&e.event_type==='new_participant'),'independent inactive sibling history remains readable');
  await execute('register',{teamName:null},learner);
  // Gate the final identity acquisition only AFTER the CTF snapshot releases
  // its connection. Mutations use a separate unwrapped identity connection.
  async function publicationRace(mutate){
   let released=false,arrive,open;const atBoundary=new Promise(r=>{arrive=r;}),gate=new Promise(r=>{open=r;});
   const identityPool={connect:async()=>{if(released)await gate;return i.runtime.connect();}};
   const ctfPool={connect:async()=>{const client=await c.runtime.connect();return{query:client.query.bind(client),release(...args){client.release(...args);released=true;arrive();}};}};
   const reader=createCtfCurrentReadRepository({identityPool,ctfPool,readiness:async()=>true});
   const result=reader.read({kind:'status',session:learner}).then(value=>({value}),error=>({error}));
   let timer;try{await Promise.race([atBoundary,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('publication barrier deadline')),3000);})]);await mutate();}finally{clearTimeout(timer);open();}
   const settled=await result;assert(settled.error,'stale publication must deny');return settled.error;
  }
  assert.equal((await publicationRace(()=>i.migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[session]))).code,'SESSION_REVOKED');
  await i.migration.query('UPDATE identity.user_sessions SET is_active=1 WHERE id=$1',[session]);
  assert.equal((await publicationRace(()=>execute('owner_reset',{ownerId:'701'}))).code,'CTF_READ_UNAVAILABLE');
  await i.migration.query("UPDATE identity.user_sessions SET is_active=0 WHERE id=$1",[session]);await assert.rejects(read('status'),{code:'SESSION_REVOKED'});await i.migration.query('UPDATE identity.user_sessions SET is_active=1 WHERE id=$1',[session]);
  await i.migration.query("UPDATE identity.user_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",[session]);await assert.rejects(read('status'),{code:'SESSION_REVOKED'});await i.migration.query("UPDATE identity.user_sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1",[session]);
  assert.deepEqual(await sibling(),siblingBefore,'all targeted reads/mutations preserve historical sibling before intentional global reset');
  await execute('global_reset',{});assert.equal((await read('status')).registered,false);
  assert(Array.isArray((await read('events',null)).events));
 }
});
