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
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_ADMIN_RESPONSE_ISOLATED==='1';
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

test('canonical prepare enqueue ACK and current admin response SQL matrix',{skip:!enabled,timeout:180000},async t=>{
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
  const again=x=>responses.project({command:x.operation.command,session:x.who});
  await assert.rejects(preparationReader.read({session:learner,ownerId:'702',admin:false}));
  await assert.rejects(prepare({kind:'config_mutation',input:{key:'ctf_enabled',value:'true'},session:learner}));
  const registration=await execute('register',{teamName:'native'},learner);assert.equal(registration.response.body.message,'Successfully registered for CTF');
  const configResult=await execute('config_mutation',{key:'ctf_show_attempt_counter',value:'false'});assert.deepEqual(configResult.response.body,{message:'Configuration updated successfully'});
  assert.equal((await one(i.runtime,'SELECT show_attempt_counter FROM identity.ctf_config_binding WHERE singleton')).show_attempt_counter,false);
  const zero=await execute('config_mutation',{key:'ctf_hint_cost_1',value:'0'});assert.equal(zero.response.status,200);
  assert.equal((await one(i.runtime,'SELECT hint_cost_1 FROM identity.ctf_config_binding WHERE singleton')).hint_cost_1,0);
  await assert.rejects(again(configResult),{code:'CTF_RESPONSE_STALE'});
  const fields=Object.fromEntries(['stage_number','stage_name','stage_description','difficulty_level','ai_guardian_name','ai_guardian_personality','system_prompt','success_criteria','hints','stage_order','difficulty','defense_style','adaptive_mode','level_score','time_bonus_seconds','feedback_mode','is_active','max_attempts'].map(k=>[k,stage[k]]));
  Object.assign(fields,{stage_number:99,stage_name:'Native new stage',stage_order:99});
  const created=await execute('catalog_mutation',{action:'create',fields});assert.equal(created.response.body.message,'Stage created');const newId=String(created.response.body.id);
  const updated=await execute('catalog_mutation',{action:'update',stageId:newId,fields:{stage_name:'Native updated stage',level_score:0}});assert.deepEqual(updated.response.body,{message:'Stage updated'});
  await assert.rejects(again(created),{code:'CTF_RESPONSE_STALE'});
  const deleted=await execute('catalog_mutation',{action:'delete',stageId:newId,fields:{}});assert.deepEqual(deleted.response.body,{message:'Stage deleted'});await assert.rejects(again(updated),{code:'CTF_RESPONSE_STALE'});
  const banned=await execute('ban',{ownerId:'701',reason:'owned fixture'});assert.deepEqual(banned.response.body,{message:'User banned from CTF'});
  const unbanned=await execute('unban',{ownerId:'701'});assert.deepEqual(unbanned.response.body,{message:'User unbanned'});await assert.rejects(again(banned),{code:'CTF_RESPONSE_STALE'});
  // Matching migration-owned synthetic memory in both stores; no fabricated decision receipt.
  for(const stageId of [1,2]){const text='owned payload stage '+stageId,payloadHash=sha(text);
   await c.migration.query('INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet) VALUES($1,$2,$3)',[stageId,payloadHash,text]);
   await i.migration.query("INSERT INTO identity.ctf_adaptive_memory(memory_id,kind,stage_id,stage_revision,clear_revision,payload_hash,normalized_payload,legacy_source) VALUES($1,'payload',$2,0,0,$3,$4,'native-admin-response-fixture')",[randomUUID(),stageId,payloadHash,text]);
  }
  const siblingMemory=await c.runtime.query('SELECT * FROM ctf.ctf_payload_blocklist WHERE stage_id=2 ORDER BY id');
  const siblingIdentityMemory=await i.runtime.query('SELECT * FROM identity.ctf_adaptive_memory WHERE stage_id=2 ORDER BY memory_id');
  let priorClear;
  for(const memory of ['technique','payload']){const cleared=await execute('blocklist_clear',{memory,stageId:'1'});assert.equal(cleared.response.body.message,`${memory==='technique'?'Technique':'Payload'} blocklist cleared (${memory==='payload'?1:0} entries removed)`);if(priorClear)await assert.rejects(again(priorClear),{code:'CTF_RESPONSE_STALE'});priorClear=cleared;}
  assert.deepEqual((await c.runtime.query('SELECT * FROM ctf.ctf_payload_blocklist WHERE stage_id=2 ORDER BY id')).rows,siblingMemory.rows);
  assert.deepEqual((await i.runtime.query('SELECT * FROM identity.ctf_adaptive_memory WHERE stage_id=2 ORDER BY memory_id')).rows,siblingIdentityMemory.rows);
  assert.equal((await one(c.runtime,'SELECT count(*)::integer n FROM ctf.ctf_payload_blocklist WHERE stage_id=1')).n,0);
  assert.equal((await one(i.runtime,"SELECT count(*)::integer n FROM identity.ctf_adaptive_memory WHERE kind='payload' AND stage_id=1")).n,0);
  const startedAfterClear=await execute('start',{stageId:'1'},learner);assert.equal(startedAfterClear.response.status,200);
  const historicProgress=await one(i.runtime,'SELECT stage_digest FROM identity.ctf_progress_bindings WHERE owner_id=701 AND stage_id=1');
  await execute('catalog_mutation',{action:'update',stageId:'1',fields:{stage_name:'Current content after progress'}});
  const restartedAfterEdit=await execute('start',{stageId:'1'},learner);assert.equal(restartedAfterEdit.response.body.stage.stage_name,'Current content after progress');
  assert.equal((await one(i.runtime,'SELECT stage_digest FROM identity.ctf_progress_bindings WHERE owner_id=701 AND stage_id=1')).stage_digest,historicProgress.stage_digest,'existing progress retains historic content stamp');
  await assert.rejects(again(startedAfterClear),{code:'CTF_RESPONSE_STALE'});
  const ownerReset=await execute('owner_reset',{ownerId:'701'});assert.deepEqual(ownerReset.response.body,{message:'Participant reset successfully'});

  const removed=await execute('owner_remove',{ownerId:'701'});assert.equal(removed.response.body.message,'worker-owner removed from CTF. They can re-register.');
  const replacement=await execute('register',{teamName:null},learner);assert.equal(replacement.response.status,200);await assert.rejects(again(removed),{code:'CTF_RESPONSE_STALE'});
  assert.deepEqual(await sibling(),siblingBefore,'owner/admin targeted operations preserve sibling before intentional global reset');
  const reset=await execute('global_reset',{});assert.deepEqual(reset.response.body,{message:'CTF reset successfully'});await assert.rejects(again(replacement),{code:'CTF_RESPONSE_STALE'});
  await i.migration.query("UPDATE identity.users SET role='student',admin_level=0 WHERE id=702");await assert.rejects(again(reset),{code:'42501'});
  // Global reset intentionally affects all CTF memberships; immutable identity history remains.
  assert.equal((await one(i.runtime,'SELECT count(*)::integer n FROM identity.ctf_outbox')).n>0,true);
 }
});
