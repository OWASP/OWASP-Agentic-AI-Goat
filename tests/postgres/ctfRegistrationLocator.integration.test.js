'use strict';
// Disposable native worker proof. Controlled response-loss seams wrap real COMMIT;
// these are not claims about OS/network failure or guardian/Judge execution.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {randomUUID,createHash}=require('node:crypto');
const {createPool}=require('../../server/database/postgres');
const {migrate}=require('../../db/postgres/migrate');
const {createCtfLifecycleRepository,withCtfTransaction}=require('../../server/database/postgres/ctfLifecycleRepository');
const {projectCtfBatch}=require('../../server/services/ctfProjectionWorker');
const {stageDigest}=require('../../server/agent-runtime/ctfStageJudge');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_REGISTRATION_LOCATOR_ISOLATED==='1';
const targets={IDENTITY:'0118_ctf_predefense_registration_locator.sql',CTF:'0012_ordered_telemetry_receipts.sql'};
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

test('original registration locator capture and blocked delivery preserve telemetry ownership',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],databases=new Set();t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_REGISTRATION_LOCATOR_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit isolated pairs required');
   const urls=keys.map(k=>new URL(process.env[k]));
   for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_locator_/);}
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
   const h=hashPayload(payload),input={version:1,binding:{...sc,sessionId:String(session),runId,ownerRevision:owner.revision,stageDigest:stageDigest(current)},payload,normalizedPayload:h.normalized,payloadHash:h.hash,techniqueTag:tag,techniqueConfidence:1e-7};
   const stageSnapshot=JSON.stringify(Object.keys(current).sort().map(k=>[k,current[k]]));
   return{session:original,input,stageSnapshot,runId,inputHash:inputDocument(input,stageSnapshot).documentHash};
  }
  const outcome=(f,decision)=>({version:1,inputHash:f.inputHash,inputDecision:decision,reason:'Synthetic 🌍 \"guard\"\nobservation',languageStatus:null,providerReceipt:null});
  const {createCtfBlockedPredefenseRepository}=require('../../server/database/postgres/ctfBlockedPredefenseRepository');
  const blocked=createCtfBlockedPredefenseRepository(i.runtime);
  async function inputBlock(registrationToken='synthetic-owned'){const f=await prepare('Synthetic 🌍 \"payload\"\nline');await pre.claim({...f,registrationToken});await pre.storeOutcome({session:original,runId:f.runId,outcome:outcome(f,'block')});const consumed=await pre.consume({session:original,runId:f.runId});return{f,consumed};}
  // Two held clients prove separate backends, rather than Promise.all on one lease.
  const race=await prepare(),encoded=inputDocument(race.input,race.stageSnapshot);
  const clients=await Promise.all([i.runtime.connect(),i.runtime.connect()]);
  let answers;
  try{
   const pids=await Promise.all(clients.map(async cl=>(await cl.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));assert.notEqual(pids[0],pids[1]);t.diagnostic('locator claim backend PIDs '+pids.join(','));
   answers=await Promise.all(clients.map((cl,n)=>cl.query('SELECT identity.claim_ctf_predefense_with_locator($1,$2,$3,$4,$5,$6,$7) AS value',[701,session,sha(rawToken),encoded.canonicalDocument,encoded.documentHash,race.stageSnapshot,n?'replacement':'original']).then(r=>r.rows[0].value)));
  }finally{clients.forEach(cl=>cl.release());}
  assert.equal(answers.filter(a=>a.claimed).length,1);assert.equal(answers[0].registrationToken,answers[1].registrationToken);
  const replay=await pre.claim({...race,registrationToken:'third'});assert.equal(replay.claimed,false);assert.equal(replay.registrationToken,answers[0].registrationToken);
  await assert.rejects(pre.claim({...race,session:other,registrationToken:'other'}));
  await assert.rejects(i.runtime.query('SELECT identity.claim_ctf_predefense($1,$2,$3,$4,$5,$6)',[701,session,sha(rawToken),encoded.canonicalDocument,encoded.documentHash,race.stageSnapshot]),{code:'42501'});
  await assert.rejects(i.runtime.query('UPDATE identity.ctf_predefense_registration_locators SET registration_token=NULL'),{code:'42501'});
  await assert.rejects(i.migration.query('UPDATE identity.ctf_predefense_registration_locators SET registration_token=NULL'),/immutable/);
  // A pre-0118 claim simulated through the migration role remains unbound forever.
  const legacy=await prepare(),legacyBytes=inputDocument(legacy.input,legacy.stageSnapshot);
  await i.migration.query('SELECT identity.claim_ctf_predefense($1,$2,$3,$4,$5,$6)',[701,session,sha(rawToken),legacyBytes.canonicalDocument,legacyBytes.documentHash,legacy.stageSnapshot]);
  const legacyReplay=await pre.claim({...legacy,registrationToken:'cannot-backfill'});assert.equal(legacyReplay.registrationToken,null);assert.equal(legacyReplay.registrationLocatorBound,false);
  const nullClaim=await prepare();await pre.claim({...nullClaim,registrationToken:null});assert.equal((await pre.claim({...nullClaim,registrationToken:'cannot-replace-null'})).registrationToken,null);
  const lostClaim=await prepare();let didLose=false;const lossTrace={borrowed:0,commits:[]};
  const lossRepo=createCtfPredefenseRepository(observedPool(i.runtime,lossTrace,'identity',{afterCommit(){if(!didLose){didLose=true;throw Object.assign(Error('controlled locator COMMIT response loss'),{code:'CTF_TRANSACTION_UNCERTAIN'});}}}));
  await assert.rejects(lossRepo.claim({...lostClaim,registrationToken:'saved-before-loss'}),/COMMIT response loss/);
  const recoveredClaim=await pre.claim({...lostClaim,registrationToken:'replacement-after-loss'});assert.equal(recoveredClaim.claimed,false);assert.equal(recoveredClaim.registrationToken,'saved-before-loss');assert.equal(recoveredClaim.outcome,null);
  const clockBefore=(await one(c.runtime,"SELECT total_active_time FROM ctf.ctf_sessions WHERE session_token='synthetic-owned'")).total_active_time;
  const {f,consumed}=await inputBlock();
  await assert.rejects(blocked.enqueueFromClaim({runId:f.runId,session:original}),/admission not acknowledged/);
  assert.equal((await one(i.runtime,'SELECT count(*)::int n FROM identity.ctf_outbox WHERE operation_id=$1',[consumed.blockedOperationId])).n,0);
  await run();
  await assert.rejects(blocked.enqueueFromClaim({runId:f.runId,session:other}),{code:'42501'});
  // Direct runtime forgery must fail against the SQL-derived immutable body.
  await assert.rejects(i.runtime.query('SELECT identity.enqueue_ctf_blocked_predefense($1,$2,$3,$4,$5,$6)',[701,session,sha(rawToken),f.runId,'{}',sha('{}')]),/canonical command mismatch/);
  await assert.rejects(withCtfTransaction(i.runtime,async client=>{
   const prepared=(await client.query('SELECT identity.prepare_ctf_blocked_predefense($1,$2,$3,$4) AS value',[701,session,sha(rawToken),f.runId])).rows[0].value;
   prepared.command.body.reason+=' FORGED';
   const canonical=require('../../server/services/ctfLifecycleCommands').canonicalCtfJson(prepared.command);
   await client.query('SELECT identity.enqueue_ctf_blocked_predefense($1,$2,$3,$4,$5,$6)',[701,session,sha(rawToken),f.runId,canonical,sha(canonical)]);
  }),/canonical command mismatch/);
  const admitted=await blocked.enqueueFromClaim({runId:f.runId,session:original});assert.equal(admitted.operationId,consumed.blockedOperationId);
  const event=await repository.next();assert.equal(event.command.kind,'record_blocked_attempt');assert.equal(event.command.operationId,consumed.blockedOperationId);
  assert.equal(event.command.body.teachingSessionToken,'synthetic-owned');assert.equal(event.command.body.payload,f.input.payload);assert.equal(event.command.body.matchedPayloadHash,null);assert.equal(event.command.body.reason,'Synthetic 🌍 \"guard\"\nobservation');assert.equal(event.command.body.techniqueConfidence,1e-7);
  await run();
  const receipt=await one(c.runtime,'SELECT canonical_result,result_hash FROM ctf.projection_receipts WHERE operation_id=$1',[consumed.blockedOperationId]);assert(receipt);
  const attemptRows=(await c.runtime.query('SELECT * FROM ctf.ctf_attempts WHERE participant_id=$1',[f.input.binding.participantId])).rows;assert.equal(attemptRows.length,1);assert.equal(attemptRows[0].session_id,'synthetic-owned');assert.equal((await one(c.runtime,"SELECT total_active_time FROM ctf.ctf_sessions WHERE session_token='synthetic-owned'")).total_active_time,clockBefore);
  const {resolveAttemptRegistrationLocator}=require('../../server/database/postgres/ctfAttemptRegistrationLocator');
  await c.migration.query("INSERT INTO ctf.ctf_sessions(participant_id,session_token) VALUES(900,'foreign-locator')");
  assert.equal(await resolveAttemptRegistrationLocator(c.runtime,f.input.binding,'foreign-locator'),null);
  assert.equal(await resolveAttemptRegistrationLocator(c.runtime,{...f.input.binding,ownerGeneration:String(BigInt(f.input.binding.ownerGeneration)+1n)},'synthetic-owned'),null);
  assert.equal((await blocked.enqueueFromClaim({runId:f.runId,session:original})).replayed,true);
  assert.deepEqual((await c.runtime.query('SELECT * FROM ctf.ctf_attempts WHERE participant_id=$1',[f.input.binding.participantId])).rows,attemptRows);
  const foreignBlock=await inputBlock('foreign-locator');await run();await blocked.enqueueFromClaim({runId:foreignBlock.f.runId,session:original});await run();
  const foreignReceipt=JSON.parse((await one(c.runtime,'SELECT canonical_result FROM ctf.projection_receipts WHERE operation_id=$1',[foreignBlock.consumed.blockedOperationId])).canonical_result);
  assert.equal((await one(c.runtime,'SELECT session_id FROM ctf.ctf_attempts WHERE id=$1',[foreignReceipt.data.attemptId])).session_id,null);
  const stale=await inputBlock();await run();await enqueue('owner_reset',{}, {participant:true});await run();
  await assert.rejects(blocked.enqueueFromClaim({runId:stale.f.runId,session:original}),/scope stale/);
  const historical=await blocked.enqueueFromClaim({runId:f.runId,session:original});assert.equal(historical.replayed,true);assert.equal(historical.currentState,false);
  // Real decision functions and ordered delivery: controlled evidence, no model calls.
  await enqueue('register',{username:'worker-owner',email:null,teamName:null,teachingSessionToken:'decision-owned',clientIp:null,userAgent:null});await run();
  await enqueue('start',{}, {atStage:true});await run();
  const {createCtfProjectionDecisionRepository}=require('../../server/database/postgres/ctfDecisionProjectionRepository');
  const {validateCtfDecisionDocument}=require('../../server/services/ctfDecisionService');
  const {canonicalCtfJson}=require('../../server/services/ctfLifecycleCommands');
  const decisions=createCtfProjectionDecisionRepository(i.runtime);
  for(const verdict of ['fail','inconclusive','unavailable','blocked','pass']){
   const candidate=await prepare('owned synthetic '+verdict),claimResult=await pre.claim({...candidate,registrationToken:verdict==='fail'?'foreign-locator':'decision-owned'});
   await pre.storeOutcome({session:original,runId:candidate.runId,outcome:outcome(candidate,'allow')});
   const consumption=await pre.consume({session:original,runId:candidate.runId});assert.equal(consumption.disposition,'continue');await run();
   const currentStage=await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE id=1');
   const {ownerRevision,...decisionBinding}=candidate.input.binding;
   const captured={version:1,binding:{...decisionBinding,admissionId:claimResult.admissionOperationId,stageNumber:currentStage.stage_number},payload:candidate.input.payload,techniqueTag:candidate.input.techniqueTag,normalizedPayload:candidate.input.normalizedPayload,payloadHash:candidate.input.payloadHash};
   const inputBytes=canonicalCtfJson(captured);
   await decisions.capture({session:original,canonicalInput:inputBytes,inputHash:sha(inputBytes),stageSnapshot:candidate.stageSnapshot});
   const response='SYNTHETIC',judgeReceipt=canonicalCtfJson({verdict,provider:'ollama',model:'controlled fixture',judgeVersion:'controlled-v1',rubricVersion:'ctf-visible-secret-v2'});
   const doc={...captured,visibleResponse:response,observedSecret:true,guardian:{version:'ctf-guardian-provenance-v1',provider:'ollama',model:'controlled fixture',rawResponseSha256:sha(response),visibleResponseSha256:sha(response),rawResponseBytes:9,visibleResponseBytes:9},judgment:{verdict,provider:'ollama',model:'controlled fixture',judgeVersion:'controlled-v1',rubricVersion:'ctf-visible-secret-v2',receiptHash:sha(judgeReceipt)},judgeReceipt};
   await decisions.stage({proposalId:candidate.runId,session:original,...validateCtfDecisionDocument(doc)});
   const authorized=await decisions.authorize({proposalId:candidate.runId,decisionId:candidate.runId,session:original});assert.equal(authorized.verdict,verdict);
   const ev=await repository.next();assert.equal(ev.facts.teachingSessionToken,verdict==='fail'?'foreign-locator':'decision-owned');
   await run();const decisionReceipt=await one(c.runtime,'SELECT * FROM ctf.projection_receipts WHERE operation_id=$1',[candidate.runId]);
   assert.equal((await one(c.runtime,'SELECT session_id FROM ctf.ctf_attempts WHERE decision_id=$1',[candidate.runId])).session_id,verdict==='fail'?null:'decision-owned');
   await repository.acknowledge(ev,{canonicalResult:decisionReceipt.canonical_result,resultHash:decisionReceipt.result_hash});
   assert.equal((await one(c.runtime,'SELECT count(*)::int n FROM ctf.ctf_attempts WHERE decision_id=$1',[candidate.runId])).n,1);
  }
  assert.equal((await one(c.runtime,"SELECT total_active_time FROM ctf.ctf_sessions WHERE session_token='decision-owned'")).total_active_time,0);
  await i.migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[session]);
  await assert.rejects(blocked.enqueueFromClaim({runId:f.runId,session:original}),{code:'28000'});
  await assert.rejects(i.runtime.query('DELETE FROM identity.ctf_predefense_blocked_commands'),{code:'42501'});
  await assert.rejects(i.migration.query('UPDATE identity.ctf_predefense_blocked_commands SET command_hash=command_hash'),/immutable/);
  assert.deepEqual(await sibling(),siblingBefore);
 }
});
