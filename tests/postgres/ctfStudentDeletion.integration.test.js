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
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_DELETION_ISOLATED==='1';
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

test('actual deletion lease/drain admission and ordered cleanup preserve authority evidence and siblings',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],databases=new Set();t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_DELETION_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit isolated pairs required');
   const urls=keys.map(k=>new URL(process.env[k]));
   for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_delete_/);}
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

  // All earlier decision work above is REAL identity admission/authorization
  // and CTF projection with synthetic provider receipts, never model proof.
  const {createCtfDeletionRepository}=require('../../server/database/postgres/ctfDeletionRepository');
  const {projectCtfDeletion}=require('../../server/database/postgres/ctfDeletionProjectionAdapter');
  const {withCtfTransaction}=require('../../server/database/postgres/ctfLifecycleRepository');
  const {canonicalCtfJson:encode}=require('../../server/services/ctfLifecycleCommands');
  const deletion=createCtfDeletionRepository(i.runtime);
  assert.equal((await one(c.runtime,'SELECT state FROM ctf.bootstrap_control WHERE singleton')).state,'open');
  const guards=(await c.migration.query("SELECT t.tgenabled FROM pg_trigger t JOIN pg_class r ON r.oid=t.tgrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='ctf' AND t.tgname='ctf_bootstrap_source_fence'")).rows;
  assert(guards.length>0&&guards.every(t=>t.tgenabled==='O'),'registered bootstrap guards must remain enabled');
  const steps=['revoke_runs','secureshop','excessive_agency','session_disclosure','sql_injection_workshop','nosql_injection_workshop','mcp_workshop','csrf_workshop','direct_prompt_injection','indirect_prompt_injection','supply_chain_rce','ctf','legacy_challenge','sensitive_lookup','xss','finflow','identity'];
  const immutableBefore=(await i.runtime.query('SELECT * FROM identity.ctf_decisions ORDER BY sequence')).rows;
  const evidenceBefore=(await i.runtime.query('SELECT * FROM identity.ctf_decision_proposals ORDER BY proposal_id')).rows;
  const targetParticipant=sc.participantId;
  await i.migration.query("UPDATE graph_runtime.runs SET status='completed' WHERE run_id=$1",[runId]);
  await c.migration.query("INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id) VALUES(1,$1,'retained shared payload',$2)",[sha('retained shared payload'),targetParticipant]);
  const deletionSiblingBefore=await one(c.runtime,'SELECT * FROM ctf.ctf_progress WHERE participant_id=900');
  await c.migration.query('SELECT ctf.refresh_authorized_leaderboard(clock_timestamp())');
  const siblingScore=await one(c.runtime,'SELECT total_score,total_completion_time FROM ctf.ctf_leaderboard WHERE participant_id=900');
  async function seedJob(subject){
   if(subject!==701){
    await i.migration.query("INSERT INTO identity.users(id,username,email,password,role,is_active) VALUES($1,$2,$3,$4,'student',0)",[subject,'delete-'+subject,'delete-'+subject+'@fixture.invalid','$2b$04$'+'a'.repeat(53)]);
    await i.migration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,2)',[JSON.stringify(['CTF',String(subject)])]);
   }else{
    await i.migration.query('UPDATE identity.users SET is_active=0 WHERE id=701');
    await i.migration.query("UPDATE graph_runtime.owners SET generation=generation+1 WHERE owner_key='[\"CTF\",\"701\"]'");
   }
   const jobId=randomUUID(),leaseToken=randomUUID();
   await i.migration.query("INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by,state,lease_token,lease_expires_at) VALUES($1,$2,702,'running',$3,clock_timestamp()+interval '5 minutes')",[jobId,subject,leaseToken]);
   for(let n=0;n<steps.length;n++)await i.migration.query("INSERT INTO identity.student_deletion_steps(job_id,step_key,ordinal,state,completed_at) VALUES($1,$2,$3,$4,CASE WHEN $3<11 THEN clock_timestamp() ELSE NULL END)",[jobId,steps[n],n,n<11?'completed':'pending']);
   await i.migration.query('INSERT INTO identity.student_deletion_run_blocks(owner_key,job_id) VALUES($1,$2)',[JSON.stringify(['CTF',String(subject)]),jobId]);
   return{jobId,leaseToken,subjectId:subject};
  }
  // Global configuration fences new deletion admission until acknowledged.
  // Independent stage work below then exercises ordered CTF delivery.
  const globalEarlier=await enqueue('config_mutation',{key:'ctf_show_attempt_counter',value:'false'},{owner:false});
  const scopeDelete=await seedJob(701),ownerKey='["CTF","701"]';
  await assert.rejects(deletion.admit({...scopeDelete,leaseToken:randomUUID()}),{code:'42501'});
  await assert.rejects(deletion.admit({...scopeDelete,subjectId:702}),{code:'42501'});
  await i.migration.query("UPDATE identity.student_deletion_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE job_id=$1",[scopeDelete.jobId]);await assert.rejects(deletion.admit(scopeDelete),{code:'42501'});
  await i.migration.query("UPDATE identity.student_deletion_jobs SET lease_expires_at=clock_timestamp()+interval '5 minutes' WHERE job_id=$1",[scopeDelete.jobId]);
  await i.migration.query("UPDATE identity.student_deletion_steps SET state='pending',completed_at=NULL WHERE job_id=$1 AND step_key='revoke_runs'",[scopeDelete.jobId]);await assert.rejects(deletion.admit(scopeDelete),/step unavailable/);
  await i.migration.query("UPDATE identity.student_deletion_steps SET state='completed',completed_at=clock_timestamp() WHERE job_id=$1 AND step_key='revoke_runs'",[scopeDelete.jobId]);
  await i.migration.query("UPDATE identity.student_deletion_steps SET ordinal=90 WHERE job_id=$1 AND step_key='ctf'",[scopeDelete.jobId]);await assert.rejects(deletion.admit(scopeDelete),/step unavailable/);
  await i.migration.query("UPDATE identity.student_deletion_steps SET ordinal=11 WHERE job_id=$1 AND step_key='ctf'",[scopeDelete.jobId]);
  await i.migration.query('DELETE FROM identity.student_deletion_run_blocks WHERE owner_key=$1',[ownerKey]);await assert.rejects(deletion.admit(scopeDelete),/step unavailable/);
  await i.migration.query('INSERT INTO identity.student_deletion_run_blocks(owner_key,job_id) VALUES($1,$2)',[ownerKey,scopeDelete.jobId]);
  await i.migration.query("UPDATE graph_runtime.runs SET status='running' WHERE run_id=$1",[runId]);await assert.rejects(deletion.admit(scopeDelete),/not drained/);
  await i.migration.query("UPDATE graph_runtime.runs SET status='completed' WHERE run_id=$1",[runId]);
  const held=await i.migration.connect();try{await held.query('SELECT pg_advisory_lock(hashtextextended($1,0))',[ownerKey]);await assert.rejects(deletion.admit(scopeDelete),/run lease unavailable/);}finally{await held.query('SELECT pg_advisory_unlock(hashtextextended($1,0))',[ownerKey]);held.release();}
  await assert.rejects(deletion.admit(scopeDelete),/CTF deletion authority unavailable/);
  await run();assert.equal((await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[globalEarlier.input.operationId])).state,'applied');
  // A content-only stage event fences its stage, not global/owner authority.
  // Keep every owner field null in this admin scope, unlike learner scopes.
  const localScope=await scope({owner:false,atStage:true});localScope.participantId=null;
  const earlier={input:{actorId:'702',sessionId:String(adminSession),rawToken:adminToken,operationId:randomUUID(),kind:'catalog_mutation',body:{action:'update',fields:{stage_name:'Deletion queue ordering fixture'}},scope:localScope}};
  await repository.enqueue(earlier.input);
  const event=await deletion.admit(scopeDelete);assert.equal(event.command.participantId,targetParticipant);
  assert.equal((await deletion.admit(scopeDelete)).commandHash,event.commandHash);
  await assert.rejects(withCtfTransaction(c.runtime,client=>projectCtfDeletion(client,event)),/CURSOR_UNAVAILABLE/);
  assert.equal((await one(c.runtime,'SELECT count(*)::int n FROM ctf.ctf_participants WHERE id=$1',[targetParticipant])).n,1);
  await run();assert.equal((await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[earlier.input.operationId])).state,'applied');
  const actualReceipt=await withCtfTransaction(c.runtime,client=>projectCtfDeletion(client,event));
  const deletionForged=JSON.parse(actualReceipt.canonicalResult);deletionForged.data.subjectId='900';const deletionBad=encode(deletionForged);
  await assert.rejects(i.runtime.query('SELECT identity.ack_ctf_student_deletion($1,$2,$3,$4,$5)',[scopeDelete.jobId,scopeDelete.leaseToken,701,deletionBad,sha(deletionBad)]),/receipt mismatch/);
  // A renewed deletion worker lease recovers the same committed CTF receipt.
  const renewed=randomUUID();await i.migration.query('UPDATE identity.student_deletion_jobs SET lease_token=$1 WHERE job_id=$2',[renewed,scopeDelete.jobId]);
  await assert.rejects(deletion.acknowledge(scopeDelete,event,actualReceipt),{code:'42501'});scopeDelete.leaseToken=renewed;
  const recoveredEvent=await deletion.admit(scopeDelete);
  const replay=await withCtfTransaction(c.runtime,client=>projectCtfDeletion(client,recoveredEvent));
  assert.equal(replay.resultHash,actualReceipt.resultHash);assert.equal((await deletion.acknowledge(scopeDelete,event,replay)).completed,true);
  assert.equal((await deletion.acknowledge(scopeDelete,event,replay)).completed,true);
  for(const table of ['ctf_participants','ctf_judgments','ctf_attempts','ctf_progress','ctf_events','ctf_sessions','ctf_technique_blocklist']){
   const column=table==='ctf_participants'?'id':'participant_id';assert.equal((await one(c.runtime,`SELECT count(*)::int n FROM ctf.${table} WHERE ${column}=$1`,[targetParticipant])).n,0);
  }
  assert.equal((await one(c.runtime,'SELECT first_winner_participant_id FROM ctf.ctf_payload_blocklist WHERE payload_hash=$1',[sha('retained shared payload')])).first_winner_participant_id,null);
  assert.deepEqual((await i.runtime.query('SELECT * FROM identity.ctf_decisions ORDER BY sequence')).rows,immutableBefore);
  assert.deepEqual((await i.runtime.query('SELECT * FROM identity.ctf_decision_proposals ORDER BY proposal_id')).rows,evidenceBefore);
  assert.deepEqual(await one(c.runtime,'SELECT * FROM ctf.ctf_progress WHERE participant_id=900'),deletionSiblingBefore);
  assert.deepEqual(await one(c.runtime,'SELECT total_score,total_completion_time FROM ctf.ctf_leaderboard WHERE participant_id=900'),siblingScore);
  assert.equal((await one(i.runtime,"SELECT lifecycle_state FROM identity.ctf_authority WHERE scope_key='owner:701'")).lifecycle_state,'blocked');
  for(const [subject,banned] of [[703,true],[704,false]]){
   const scoped=await seedJob(subject);if(banned)await c.migration.query("INSERT INTO ctf.ctf_bans(user_id,reason,banned_by) VALUES($1,'synthetic',702)",[subject]);
   const e=await deletion.admit(scoped);assert.equal(e.command.participantId,null);
   const r=await withCtfTransaction(c.runtime,client=>projectCtfDeletion(client,e));assert.equal(r.value.data.removed.bans,banned?1:0);assert.equal(r.value.data.removed.participants,0);
   assert.equal((await deletion.acknowledge(scoped,e,r)).completed,true);
  }
  // Genuine deletion commands have no platform actor/session. A live admin
  // sees no row; a migration-owned attributed forgery isolates the kind guard
  // from session denial, without granting runtime any mutation capability.
  assert.equal((await one(i.runtime,'SELECT identity.read_ctf_user_operation($1,$2,$3,$4) AS value',[event.command.operationId,702,adminSession,sha(adminToken)])).value,null);
  const attributed=randomUUID();
  await i.migration.query("INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash,canonical_command,actor_id,session_id) SELECT (SELECT max(sequence)+1 FROM identity.ctf_outbox),$1,kind,command,command_hash,canonical_command,702,$2 FROM identity.ctf_outbox WHERE operation_id=$3",[attributed,adminSession,event.command.operationId]);
  await assert.rejects(i.runtime.query('SELECT identity.read_ctf_user_operation($1,$2,$3,$4)',[attributed,702,adminSession,sha(adminToken)]),e=>e.code==='42501'&&e.message==='CTF operation unavailable');

 }
});
