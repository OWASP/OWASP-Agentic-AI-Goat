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
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_DECISION_PROJECTION_ISOLATED==='1';
const targets={IDENTITY:'0107_ctf_decision_projection.sql',CTF:'0008_authoritative_decision_delivery.sql'};
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

test('real lifecycle admission, context claim, decision authorization and ordered projection preserve canonical effects',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],databases=new Set();t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_DECISION_PROJECTION_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit isolated pairs required');
   const urls=keys.map(k=>new URL(process.env[k]));
   for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_decision_projection_/);}
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
  const {createCtfProjectionDecisionRepository,acknowledgeCtfDecision}=require('../../server/database/postgres/ctfDecisionProjectionRepository');
  const {validateCtfDecisionDocument}=require('../../server/services/ctfDecisionService');
  const {canonicalCtfJson}=require('../../server/services/ctfLifecycleCommands');
  const {hashPayload}=require('../../server/services/promptInjectionCTF');
  const projectionRepository=createCtfProjectionDecisionRepository(i.runtime),runId=randomUUID(),proposalId=runId;
  const sc=await scope({atStage:true,progress:true});
  await i.migration.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,$3,'running')",[runId,'["CTF","701"]',sc.ownerGeneration]);
  const binding={...sc,sessionId:String(session),admissionId:attempt.input.operationId,runId,stageNumber:stage.stage_number,stageDigest:stageDigest(stage)};
  const payload='owned synthetic successful payload',normalized=hashPayload(payload),input={version:1,binding,payload,techniqueTag:'other',normalizedPayload:normalized.normalized,payloadHash:normalized.hash};
  const canonicalInput=canonicalCtfJson(input),sessionInput={actorId:'701',sessionId:String(session),rawToken};
  const stageSnapshot=JSON.stringify(Object.keys(stage).sort().map(k=>[k,stage[k]]));
  await assert.rejects(projectionRepository.capture({session:sessionInput,canonicalInput,inputHash:sha(canonicalInput),stageSnapshot:'[]'}),/snapshot digest mismatch/);
  assert.equal((await one(i.runtime,'SELECT count(*)::integer AS n FROM identity.ctf_decision_inputs')).n,0,'invalid context cannot consume inference claim');
  assert.equal((await projectionRepository.capture({session:sessionInput,canonicalInput,inputHash:sha(canonicalInput),stageSnapshot})).claimed,true);
  const response='SYNTHETIC',judgeReceipt=canonicalCtfJson({verdict:'pass',provider:'ollama',model:'synthetic fixture only',judgeVersion:'controlled-v1',rubricVersion:'ctf-visible-secret-v2'});
  const evidence={...input,visibleResponse:response,observedSecret:true,guardian:{version:'ctf-guardian-provenance-v1',provider:'ollama',model:'synthetic fixture only',rawResponseSha256:sha(response),visibleResponseSha256:sha(response),rawResponseBytes:9,visibleResponseBytes:9},judgment:{verdict:'pass',provider:'ollama',model:'synthetic fixture only',judgeVersion:'controlled-v1',rubricVersion:'ctf-visible-secret-v2',receiptHash:sha(judgeReceipt)},judgeReceipt};
  await projectionRepository.stage({proposalId,session:sessionInput,...validateCtfDecisionDocument(evidence)});
  const authorized=await projectionRepository.authorize({proposalId,decisionId:runId,session:sessionInput});assert.equal(authorized.accepted,true);
  const decisionEvent=await repository.next();assert.equal(decisionEvent.command.kind,'decision');
  const factSnapshot=await one(i.runtime,'SELECT * FROM identity.ctf_decision_projection_facts WHERE decision_id=$1',[runId]);
  assert.equal(factSnapshot.facts.hintPenaltyTotal,Number(config.ctf_hint_cost_1));
  const trace={borrowed:0,commits:[]};let lostCommit=false;
  const lost=observedPool(c.runtime,trace,'ctf',{afterCommit(){lostCommit=true;throw Error('controlled decision committed response loss');}});
  await assert.rejects(run({ctfPool:lost}),/controlled decision committed response loss/);assert(lostCommit);
  assert.equal((await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[runId])).state,'pending');
  const receipt=await one(c.runtime,'SELECT * FROM ctf.projection_receipts WHERE operation_id=$1',[runId]);assert(receipt);
  const forged=JSON.parse(receipt.canonical_result);forged.data.successfulAttempts+=1;const forgedRaw=canonicalCtfJson(forged);
  await assert.rejects(i.runtime.query('SELECT * FROM identity.ack_ctf_decision_projection($1,$2,$3,$4,$5)',[runId,receipt.sequence,receipt.command_hash,forgedRaw,sha(forgedRaw)]),/effects mismatch/);
  await run();
  const ackAgain=await repository.acknowledge(decisionEvent,{canonicalResult:receipt.canonical_result,resultHash:receipt.result_hash});assert.equal(ackAgain.state,'applied');
  assert.equal((await one(i.runtime,"SELECT applied_sequence::text FROM identity.ctf_authority WHERE scope_key='owner:701'")).applied_sequence,'0','owner scope cannot carry global cursor');
  const completed=await one(c.runtime,'SELECT * FROM ctf.ctf_progress WHERE id=$1',[progressId]);
  const canonicalDecision=await one(i.runtime,'SELECT completion_time_ms::text,hint_penalty_total FROM identity.ctf_decisions WHERE decision_id=$1',[runId]);assert.equal(String(completed.completion_time),canonicalDecision.completion_time_ms);assert.equal(completed.successful_attempts,1);
  assert.equal((await one(c.runtime,'SELECT count(*)::integer AS n FROM ctf.ctf_attempts WHERE decision_id=$1',[runId])).n,1);
  assert.deepEqual(await one(c.runtime,'SELECT * FROM ctf.projection_receipts WHERE operation_id=$1',[runId]),receipt);
  const beforeScore=(await one(c.runtime,'SELECT total_score FROM ctf.ctf_leaderboard WHERE participant_id=$1',[sc.participantId])).total_score;
  const global=await one(i.runtime,"SELECT revision::text FROM identity.ctf_authority WHERE scope_key='global'");
  await repository.enqueue({actorId:'702',sessionId:String(adminSession),rawToken:adminToken,operationId:randomUUID(),kind:'catalog_mutation',body:{action:'update',fields:{level_score:stage.level_score+777}},scope:{ownerId:null,ownerGeneration:null,participantId:null,progressId:null,stageId:'1',stageRevision:'0',globalRevision:global.revision}});await run();
  // Bootstrap imported sibling authority, then use the REAL ordered admin reset.
  await i.migration.query("INSERT INTO identity.users(id,username,email,password,role) VALUES(900,'sibling','sibling@fixture.invalid',$1,'student')",['$2b$04$'+'a'.repeat(53)]);
  await i.migration.query("INSERT INTO graph_runtime.owners(owner_key,generation) VALUES('[\"CTF\",\"900\"]',0)");
  await i.migration.query("INSERT INTO identity.ctf_authority(scope_key,owner_generation,lifecycle_state) VALUES('owner:900',0,'ready')");
  await i.migration.query("INSERT INTO identity.ctf_participant_bindings VALUES(900,0,900,0,0,true,false,clock_timestamp(),0,$1)",[seed]);
  await c.migration.query("INSERT INTO ctf.projection_scopes(scope_key,revision,owner_generation,applied_operation_id) VALUES('owner:900',0,0,$1)",[seed]);
  await repository.enqueue({actorId:'702',sessionId:String(adminSession),rawToken:adminToken,operationId:randomUUID(),kind:'owner_reset',body:{},scope:{ownerId:'900',ownerGeneration:'0',participantId:'900',progressId:null,stageId:null,stageRevision:null,globalRevision:global.revision}});await run();
  assert.equal((await one(c.runtime,'SELECT total_score FROM ctf.ctf_leaderboard WHERE participant_id=$1',[sc.participantId])).total_score,beforeScore);
  assert.deepEqual(await one(i.runtime,'SELECT * FROM identity.ctf_decision_projection_facts WHERE decision_id=$1',[runId]),factSnapshot);
  assert.deepEqual(await one(c.runtime,'SELECT * FROM ctf.projection_receipts WHERE operation_id=$1',[runId]),receipt);
  async function prepareNextDecision({verdict='pass',mode='none',techniqueTag='other',payload='matrix '+randomUUID()}={}){
   const g=await one(i.runtime,"SELECT revision::text FROM identity.ctf_authority WHERE scope_key='global'"),st=await one(i.runtime,"SELECT revision::text FROM identity.ctf_authority WHERE scope_key='stage:1'");
   await repository.enqueue({actorId:'702',sessionId:String(adminSession),rawToken:adminToken,operationId:randomUUID(),kind:'catalog_mutation',body:{action:'update',fields:{adaptive_mode:mode}},scope:{ownerId:null,ownerGeneration:null,participantId:null,progressId:null,stageId:'1',stageRevision:st.revision,globalRevision:g.revision}});await run();
   await enqueue('owner_reset',{}, {participant:true});await run();
   await enqueue('register',{username:'worker-owner',email:null,teamName:null,teachingSessionToken:randomUUID(),clientIp:null,userAgent:null});await run();
   await enqueue('start',{}, {atStage:true});await run();
   const admitted=await enqueue('admit_attempt',{failed:false},{atStage:true,progress:true});await run();
   const currentScope=await scope({atStage:true,progress:true}),currentStage=await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE id=1'),id=randomUUID();
   await i.migration.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,$3,'running')",[id,'["CTF","701"]',currentScope.ownerGeneration]);
   const bound={...currentScope,sessionId:String(session),admissionId:admitted.input.operationId,runId:id,stageNumber:1,stageDigest:stageDigest(currentStage)},np=hashPayload(payload);
   const captured={version:1,binding:bound,payload,techniqueTag,normalizedPayload:np.normalized,payloadHash:np.hash},inputBytes=canonicalCtfJson(captured);
   await projectionRepository.capture({session:sessionInput,canonicalInput:inputBytes,inputHash:sha(inputBytes),stageSnapshot:JSON.stringify(Object.keys(currentStage).sort().map(k=>[k,currentStage[k]]))});
   const jr=canonicalCtfJson({verdict,provider:'ollama',model:'controlled fixture',judgeVersion:'controlled-v1',rubricVersion:'ctf-visible-secret-v2'});
   const doc={...captured,visibleResponse:response,observedSecret:true,guardian:{version:'ctf-guardian-provenance-v1',provider:'ollama',model:'controlled fixture',rawResponseSha256:sha(response),visibleResponseSha256:sha(response),rawResponseBytes:9,visibleResponseBytes:9},judgment:{verdict,provider:'ollama',model:'controlled fixture',judgeVersion:'controlled-v1',rubricVersion:'ctf-visible-secret-v2',receiptHash:sha(jr)},judgeReceipt:jr};
   await projectionRepository.stage({proposalId:id,session:sessionInput,...validateCtfDecisionDocument(doc)});
   return{id,scope:currentScope,payload,authorize:()=>projectionRepository.authorize({proposalId:id,decisionId:id,session:sessionInput})};
  }
  for(const verdict of ['pass','fail','inconclusive','unavailable','blocked']){
   const candidate=await prepareNextDecision({verdict});const result=await candidate.authorize();assert.equal(result.verdict,verdict);await run();
   const row=await one(c.runtime,'SELECT * FROM ctf.ctf_progress WHERE id=$1',[candidate.scope.progressId]);
   assert.equal(row.attempts_count,1);assert.equal(row.successful_attempts,verdict==='pass'?1:0);assert.equal(row.failed_attempts,verdict==='pass'?0:1);
   assert.equal((await one(c.runtime,'SELECT verdict FROM ctf.ctf_judgments WHERE decision_id=$1',[candidate.id])).verdict,verdict);
   assert.equal((await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[candidate.id])).state,'applied');
  }
  // Memory arrives after staged inference; authorization revalidates a complete
  // canonical snapshot. Two near matches plus technique match choose one exact
  // payload identity deterministically, without any second model call.
  const basePayload='the quick brown fox jumps over the lazy dog while another learner carefully observes the guardian response and records a deliberate bounded security experiment';
  const hybrid=await prepareNextDecision({mode:'hybrid',techniqueTag:'role_play',payload:basePayload});
  const memoryIds=['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002'];const normalizedRows=[];
  for(let n=0;n<2;n++){
   const np=hashPayload(basePayload+(n?'b':'a'));normalizedRows.push(np);
   assert(require('../../server/services/promptInjectionCTF').isNearDuplicate(hashPayload(basePayload).hash,hashPayload(basePayload).normalized,[{payload_hash:np.hash,normalized_snippet:np.normalized}]).blocked);
   await i.migration.query("INSERT INTO identity.ctf_adaptive_memory(memory_id,kind,stage_id,stage_revision,clear_revision,payload_hash,normalized_payload,legacy_source) VALUES($1,'payload',1,$2,0,$3,$4,'controlled memory race')",[memoryIds[n],hybrid.scope.stageRevision,np.hash,np.normalized]);
   await c.migration.query('INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id) VALUES(1,$1,$2,$3)',[np.hash,np.normalized,hybrid.scope.participantId]);
  }
  await i.migration.query("INSERT INTO identity.ctf_adaptive_memory(memory_id,kind,stage_id,stage_revision,clear_revision,owner_id,owner_generation,technique_tag,legacy_source) VALUES($1,'technique',1,$2,0,701,$3,'role_play','controlled technique race')",[randomUUID(),hybrid.scope.stageRevision,hybrid.scope.ownerGeneration]);
  await c.migration.query("INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag) VALUES($1,1,'role_play')",[hybrid.scope.participantId]);
  assert.equal((await hybrid.authorize()).verdict,'blocked');
  const hybridFacts=(await one(i.runtime,'SELECT facts FROM identity.ctf_decision_projection_facts WHERE decision_id=$1',[hybrid.id])).facts;
  assert.equal(hybridFacts.matchedPayloadMemoryId,memoryIds[0]);assert.equal(hybridFacts.matchedPayloadHash,normalizedRows[0].hash);
  let decisionReaders=0,releaseDecision;const decisionBarrier=new Promise(resolve=>{releaseDecision=resolve;});
  const paired={...repository,async next(options){const event=await repository.next(options);if(++decisionReaders===2)releaseDecision();await decisionBarrier;return event;}};
  const concurrentDecisions=await Promise.all([run({identity:paired}),run({identity:paired})]);assert(concurrentDecisions.every(x=>x[0].state==='applied'));
  assert.equal((await one(c.runtime,'SELECT count(*)::integer AS n FROM ctf.ctf_attempts WHERE decision_id=$1',[hybrid.id])).n,1);
  assert.equal((await one(c.runtime,'SELECT hit_count FROM ctf.ctf_payload_blocklist WHERE stage_id=1 AND payload_hash=$1',[normalizedRows[0].hash])).hit_count,1);
  assert.equal((await one(c.runtime,'SELECT hit_count FROM ctf.ctf_payload_blocklist WHERE stage_id=1 AND payload_hash=$1',[normalizedRows[1].hash])).hit_count,0);
  const techniqueOnly=await prepareNextDecision({mode:'technique',techniqueTag:'role_play',payload:'entirely distinct teaching technique payload'});
  await i.migration.query("INSERT INTO identity.ctf_adaptive_memory(memory_id,kind,stage_id,stage_revision,clear_revision,owner_id,owner_generation,technique_tag,legacy_source) VALUES($1,'technique',1,$2,0,701,$3,'role_play','controlled technique only')",[randomUUID(),techniqueOnly.scope.stageRevision,techniqueOnly.scope.ownerGeneration]);
  await c.migration.query("INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag) VALUES($1,1,'role_play')",[techniqueOnly.scope.participantId]);
  assert.equal((await techniqueOnly.authorize()).verdict,'blocked');await run();
  const onlyFacts=(await one(i.runtime,'SELECT facts FROM identity.ctf_decision_projection_facts WHERE decision_id=$1',[techniqueOnly.id])).facts;
  assert.equal(onlyFacts.matchedPayloadMemoryId,null);assert.equal(onlyFacts.matchedPayloadHash,null);
  assert.equal((await one(c.runtime,'SELECT hit_count FROM ctf.ctf_payload_blocklist WHERE stage_id=1 AND payload_hash=$1',[normalizedRows[0].hash])).hit_count,1);
  assert.equal(trace.borrowed,0);
 }
});
