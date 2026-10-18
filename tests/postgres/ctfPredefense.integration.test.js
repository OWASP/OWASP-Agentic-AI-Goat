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
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_PREDEFENSE_ISOLATED==='1';
const targets={IDENTITY:'0113_ctf_predefense_claim.sql',CTF:'0010_student_deletion_delivery.sql'};
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

test('actual pre-defense claims, immutable outcomes and canonical admission delivery',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],databases=new Set();t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_PREDEFENSE_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit isolated pairs required');
   const urls=keys.map(k=>new URL(process.env[k]));
   for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_predef_/);}
   assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);assert.notEqual(urls[0].username,urls[1].username);assert(!databases.has(urls[0].pathname));databases.add(urls[0].pathname);
   const [runtime,migration]=keys.map(k=>createPool({...process.env,PG_POOL_MAX_WORKSHOP:kind==='IDENTITY'?'2':'1'},k));pools.push(runtime,migration);stores[kind]={runtime,migration};
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
  const start=await enqueue('start',{}, {atStage:true});
  // Barrier ensures both workers read the same pending event before either applies it.
  let readers=0,open;const barrier=new Promise(r=>{open=r;});
  const concurrentIdentity={...repository,async next(opts){const e=await repository.next(opts);if(++readers===2)open();await barrier;return e;}};
  const outcomes=await Promise.all([run({identity:concurrentIdentity}),run({identity:concurrentIdentity})]);
  assert(outcomes.every(r=>r[0].state==='applied'));assert.equal(await count(start.input.operationId),1);
  const {createCtfPredefenseRepository}=require('../../server/database/postgres/ctfPredefenseRepository');
  const {inputDocument}=require('../../server/services/ctfPredefenseContract');
  const {hashPayload}=require('../../server/services/promptInjectionCTF');
  const pre=createCtfPredefenseRepository(i.runtime),original={actorId:'701',sessionId:String(session),rawToken};
  const otherToken='other-session-'+randomUUID(),otherSession=(await one(i.migration,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(701,$1,now()+interval '1 hour') RETURNING id",[sha(otherToken)])).id;
  const other={actorId:'701',sessionId:String(otherSession),rawToken:otherToken};
  async function prepare(payload='synthetic input defense fixture',tag='other'){
   const sc=await scope({atStage:true,progress:true}),current=await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE id=1');
   const owner=await one(i.runtime,"SELECT revision::text FROM identity.ctf_authority WHERE scope_key='owner:701'");
   const runId=randomUUID();await i.migration.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,'[\"CTF\",\"701\"]',$2,'running')",[runId,sc.ownerGeneration]);
   const h=hashPayload(payload),input={version:1,binding:{...sc,sessionId:String(session),runId,ownerRevision:owner.revision,stageDigest:stageDigest(current)},payload,normalizedPayload:h.normalized,payloadHash:h.hash,techniqueTag:tag,techniqueConfidence:0.5};
   const stageSnapshot=JSON.stringify(Object.keys(current).sort().map(k=>[k,current[k]]));
   return{session:original,input,stageSnapshot,runId,inputHash:inputDocument(input,stageSnapshot).documentHash};
  }
  const outcome=(f,decision)=>({version:1,inputHash:f.inputHash,inputDecision:decision,reason:'Synthetic controlled defense observation',languageStatus:null,providerReceipt:null});
  const counts=()=>one(i.runtime,'SELECT attempts_count,failed_attempts FROM identity.ctf_progress_bindings WHERE progress_id=$1',[start.input.scope.progressId||currentProgress]);
  const currentProgress=(await scope({atStage:true,progress:true})).progressId;
  async function deliver(f,decision,expectedDisposition,expectedFailed){
   await pre.storeOutcome({session:original,runId:f.runId,outcome:outcome(f,decision)});
   const before=await counts(),consumed=await pre.consume({session:original,runId:f.runId});
   assert.equal(consumed.disposition,expectedDisposition);assert.equal(consumed.failed,expectedFailed);
   // This is the actual SQL-generated canonical command, not a constructed row.
   const next=await repository.next();assert.equal(next.command.operationId,consumed.operationId);assert.equal(next.command.body.failed,expectedFailed);
   await run();
   const after=await counts();assert.equal(after.attempts_count,before.attempts_count+1);assert.equal(after.failed_attempts,before.failed_attempts+(expectedFailed?1:0));
   const physical=await one(c.runtime,'SELECT attempts_count,failed_attempts FROM ctf.ctf_progress WHERE id=$1',[currentProgress]);assert.deepEqual(physical,after);
   const replay=await pre.consume({session:original,runId:f.runId});assert.equal(replay.operationId,consumed.operationId);assert.equal(replay.replayed,true);assert.equal(replay.currentState,false);
   assert.deepEqual(await counts(),after);return consumed;
  }
  const first=await prepare();
  // Two independent connections race the real SQL insertion. No provider seam
  // is invoked by this fixture; only exactly one claim may grant execution.
  assert.equal(i.runtime.options.max,2,'identity fixture explicitly budgets two simultaneous backends');
  const claimPids=[];let arrivals=0,releaseClaims,rejectClaims;
  const claimGate=new Promise((resolve,reject)=>{releaseClaims=resolve;rejectClaims=reject;});
  claimGate.catch(()=>{}); // Observe timeout immediately even if a connection fails before the gate.
  const gateTimeout=setTimeout(()=>rejectClaims(Error('claim SQL submission barrier timed out')),1000);
  function racePool(base){return{async connect(){const client=await base.connect();const pid=(await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;return{async query(sql,args){if(sql.includes('identity.claim_ctf_predefense')){claimPids.push(pid);if(++arrivals===2)releaseClaims();await claimGate;}return client.query(sql,args);},release(discard){client.release(discard);}};}};}
  let raced;try{raced=await Promise.all([createCtfPredefenseRepository(racePool(i.runtime)).claim(first),createCtfPredefenseRepository(racePool(i.runtime)).claim(first)]);}finally{clearTimeout(gateTimeout);}
  assert.equal(new Set(claimPids).size,2,'claims submitted on distinct backend PIDs');
  t.diagnostic(JSON.stringify({phase:'predefense-claim-race',state,backendPids:claimPids}));
  assert.deepEqual(raced.map(r=>r.claimed).sort(),[false,true]);
  assert.equal(raced[0].admissionOperationId,raced[1].admissionOperationId);
  assert.notEqual(raced[0].admissionOperationId,first.runId);
  assert.equal((await pre.consume({session:original,runId:first.runId})).status,'unknown');
  assert.equal((await pre.claim(first)).claimed,false);
  await assert.rejects(pre.storeOutcome({session:other,runId:first.runId,outcome:outcome(first,'allow')}),{code:'42501'});
  const switched=structuredClone(first);switched.session=other;switched.input.binding.sessionId=String(otherSession);
  await assert.rejects(pre.claim(switched),/replay conflict/);
  let outcomeCommits=0;
  const lostOutcomePool={async connect(){const client=await i.runtime.connect();return{async query(sql,args){const result=await client.query(sql,args);if(sql==='COMMIT'&&++outcomeCommits===1)throw Object.assign(Error('controlled committed outcome response loss'),{code:'CTF_TRANSACTION_UNCERTAIN'});return result;},release(discard){client.release(discard);}};}};
  const exactOutcome=outcome(first,'block');
  await assert.rejects(createCtfPredefenseRepository(lostOutcomePool).storeOutcome({session:original,runId:first.runId,outcome:exactOutcome}),{code:'CTF_TRANSACTION_UNCERTAIN'});
  const persistedOutcome=await one(i.runtime,'SELECT canonical_outcome,outcome_hash FROM identity.ctf_predefense_outcomes WHERE run_id=$1',[first.runId]);assert(persistedOutcome);
  assert.equal((await pre.storeOutcome({session:original,runId:first.runId,outcome:exactOutcome})).replayed,true);
  assert.deepEqual(await one(i.runtime,'SELECT canonical_outcome,outcome_hash FROM identity.ctf_predefense_outcomes WHERE run_id=$1',[first.runId]),persistedOutcome);
  assert.equal((await pre.claim(first)).claimed,false);assert.equal(outcomeCommits,1);
  await deliver(first,'block','input',true);
  await assert.rejects(pre.storeOutcome({session:original,runId:first.runId,outcome:outcome(first,'allow')}),/replay conflict/);
  const allowed=await prepare('synthetic allowed');await pre.claim(allowed);await deliver(allowed,'allow','continue',false);

  // Explicit migration-owned adaptive fixture configuration, not route/admin
  // activation. Ordinary progress historical stage digest remains unchanged.
  await c.migration.query("UPDATE ctf.ctf_stages SET adaptive_mode='hybrid' WHERE id=1");
  const adaptiveStage=await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE id=1');
  await i.migration.query("UPDATE identity.ctf_stage_bindings SET adaptive_mode='hybrid',stage_digest=$1 WHERE stage_id=1",[stageDigest(adaptiveStage)]);
  const text='abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz';
  const fuzzyText='abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyy';
  const exact=hashPayload(text),fuzzy=hashPayload(fuzzyText);
  async function memory(id,h){await i.migration.query("INSERT INTO identity.ctf_adaptive_memory(memory_id,kind,stage_id,stage_revision,clear_revision,payload_hash,normalized_payload,legacy_source) VALUES($1,'payload',1,0,0,$2,$3,'synthetic-predefense-native-fixture')",[id,h.hash,h.normalized]);}
  await memory('00000000-0000-0000-0000-000000000011',fuzzy);
  await memory('00000000-0000-0000-0000-000000000012',exact);
  const payload=await prepare(text),payloadClaim=await pre.claim(payload);
  assert.equal(payloadClaim.initialAdaptive.disposition,'payload');assert.equal(payloadClaim.initialAdaptive.matchedPayloadHash,exact.hash,'exact match wins even when fuzzy memory sorts first');
  assert.equal((await deliver(payload,'skipped','payload',false)).matchedPayloadHash,exact.hash);
  await i.migration.query('DELETE FROM identity.ctf_adaptive_memory WHERE payload_hash=$1',[exact.hash]);
  const fuzzySecond=hashPayload('abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxzz');
  await memory('00000000-0000-0000-0000-000000000013',fuzzySecond);
  const multiple=await prepare(text),multipleClaim=await pre.claim(multiple);
  assert.equal(multipleClaim.initialAdaptive.matchedPayloadHash,fuzzy.hash,'first immutable memory_id wins multiple fuzzy matches');
  assert.equal((await deliver(multiple,'skipped','payload',false)).matchedPayloadHash,fuzzy.hash);
  const generated=await prepare(text,'role_play');
  await i.migration.query("INSERT INTO identity.ctf_adaptive_memory(memory_id,kind,stage_id,stage_revision,clear_revision,owner_id,owner_generation,technique_tag,legacy_source) VALUES($1,'technique',1,0,0,701,$2,'role_play','synthetic-predefense-native-fixture')",[randomUUID(),generated.input.binding.ownerGeneration]);
  assert.equal((await pre.claim(generated)).initialAdaptive.disposition,'category');await deliver(generated,'skipped','category',false);
  const skipped=await prepare(text);await pre.claim(skipped);await pre.storeOutcome({session:original,runId:skipped.runId,outcome:outcome(skipped,'skipped')});
  await i.migration.query('DELETE FROM identity.ctf_adaptive_memory WHERE stage_id=1');
  await assert.rejects(pre.consume({session:original,runId:skipped.runId}),/block cleared after skipped/);
  const changed=await prepare(text);await pre.claim(changed);await pre.storeOutcome({session:original,runId:changed.runId,outcome:outcome(changed,'block')});
  await memory(randomUUID(),exact);
  const changedConsumed=await pre.consume({session:original,runId:changed.runId});assert.equal(changedConsumed.disposition,'payload');assert.equal(changedConsumed.failed,false);await repository.next();await run();
  await i.migration.query('DELETE FROM identity.ctf_adaptive_memory WHERE stage_id=1');

  // Completeness bound is explicit: never turn a truncated memory into allow.
  await i.migration.query("INSERT INTO identity.ctf_adaptive_memory(memory_id,kind,stage_id,stage_revision,clear_revision,payload_hash,normalized_payload,legacy_source) SELECT gen_random_uuid(),'payload',1,0,0,encode(sha256(convert_to('bounded memory '||n,'UTF8')),'hex'),'bounded memory '||n,'synthetic-predefense-native-overflow' FROM generate_series(1,257)n");
  const overflow=await prepare();await assert.rejects(pre.claim(overflow),/adaptive snapshot unavailable/);
  assert.equal((await one(i.runtime,'SELECT count(*)::int n FROM identity.ctf_predefense_claims WHERE run_id=$1',[overflow.runId])).n,0);
  await i.migration.query('DELETE FROM identity.ctf_adaptive_memory WHERE stage_id=1');
  const clearScope=await scope({owner:false,atStage:true});clearScope.participantId=null;
  await repository.enqueue({actorId:'702',sessionId:String(adminSession),rawToken:adminToken,operationId:randomUUID(),kind:'blocklist_clear',body:{memory:'payload'},scope:clearScope});await run();
  const stamps=await one(i.runtime,"SELECT a.revision::text current_revision,s.stage_revision::text content_revision FROM identity.ctf_authority a CROSS JOIN identity.ctf_stage_bindings s WHERE a.scope_key='stage:1' AND s.stage_id=1");
  assert.notEqual(stamps.current_revision,stamps.content_revision,'memory clear advances authority without rewriting content provenance');
  const afterClear=await prepare();assert.equal(afterClear.input.binding.stageRevision,stamps.current_revision);await pre.claim(afterClear);await deliver(afterClear,'allow','continue',false);
  const revoked=await prepare();await pre.claim(revoked);
  await i.migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[session]);
  await assert.rejects(pre.storeOutcome({session:original,runId:revoked.runId,outcome:outcome(revoked,'allow')}),{code:'28000'});
  await assert.rejects(pre.claim(revoked),{code:'28000'});
  await i.migration.query('UPDATE identity.user_sessions SET is_active=1 WHERE id=$1',[session]);
  const stale=await prepare();await pre.claim(stale);await pre.storeOutcome({session:original,runId:stale.runId,outcome:outcome(stale,'allow')});
  await enqueue('owner_reset',{}, {participant:true});await run();
  await assert.rejects(pre.consume({session:original,runId:stale.runId}),/scope stale/);
  const history=await pre.consume({session:original,runId:first.runId});assert.equal(history.replayed,true);assert.equal(history.currentState,false);
  assert.equal((await pre.claim(stale)).claimed,false,'historical claim never grants reexecution');
  await assert.rejects(i.runtime.query('DELETE FROM identity.ctf_predefense_claims'),{code:'42501'});
  await assert.rejects(i.migration.query('UPDATE identity.ctf_predefense_outcomes SET outcome=outcome'),/immutable/);
  assert.deepEqual(await sibling(),siblingBefore);
 }
});
