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
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_RESPONSE_DIAGNOSTICS_ISOLATED==='1';
const targets={IDENTITY:'0119_ctf_response_diagnostics.sql',CTF:'0012_ordered_telemetry_receipts.sql'};
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

test('proposal diagnostics atomically bind original claimed input and preserve historical unknowns',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],databases=new Set();t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_RESPONSE_DIAGNOSTICS_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit isolated pairs required');
   const urls=keys.map(k=>new URL(process.env[k]));
   for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_diagnostics_/);}
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
   stores[kind].applyTarget=async()=>{fs.copyFileSync(path.join(directory,targets[kind]),path.join(prefix,targets[kind]));await migrate(migration,prefix);assert.deepEqual(await migrate(migration,prefix),[]);};
   if(kind!=='IDENTITY')await stores[kind].applyTarget();
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
  await run();assert.equal(await count(start.input.operationId),1);
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
  const {createCtfProjectionDecisionRepository}=require('../../server/database/postgres/ctfDecisionProjectionRepository');
  const {validateCtfDecisionDocument}=require('../../server/services/ctfDecisionService');
  const {canonicalCtfJson}=require('../../server/services/ctfLifecycleCommands');
  const {createCtfResponseDiagnosticsRepository}=require('../../server/database/postgres/ctfResponseDiagnosticsRepository');
  const {encodeResponseDiagnostics}=require('../../server/services/ctfResponseDiagnostics');
  const decisions=createCtfProjectionDecisionRepository(i.runtime),diagnostics=createCtfResponseDiagnosticsRepository(i.runtime);
  async function candidate(unavailable=false){
   const f=await prepare('owned diagnostic '+randomUUID()),claim=await pre.claim(f);
   await pre.storeOutcome({session:original,runId:f.runId,outcome:outcome(f,'allow')});
   assert.equal((await pre.consume({session:original,runId:f.runId})).disposition,'continue');await run();
   const {ownerRevision,...binding}=f.input.binding;
   const input={version:1,binding:{...binding,admissionId:claim.admissionOperationId,stageNumber:stage.stage_number},payload:f.input.payload,techniqueTag:f.input.techniqueTag,normalizedPayload:f.input.normalizedPayload,payloadHash:f.input.payloadHash};
   const raw=canonicalCtfJson(input);await decisions.capture({session:original,canonicalInput:raw,inputHash:sha(raw),stageSnapshot:f.stageSnapshot});
   const response='OWNED DIAGNOSTIC',judgeReceipt=canonicalCtfJson({verdict:'fail',rubricVersion:'ctf-visible-secret-v2'});
   const doc={...input,visibleResponse:response,observedSecret:false,guardian:{version:'ctf-guardian-provenance-v1',provider:'ollama',model:'controlled fixture',rawResponseSha256:sha(response),visibleResponseSha256:sha(response),rawResponseBytes:Buffer.byteLength(response),visibleResponseBytes:Buffer.byteLength(response)},judgment:{verdict:'fail',provider:null,model:null,judgeVersion:null,rubricVersion:'ctf-visible-secret-v2',receiptHash:sha(judgeReceipt)},judgeReceipt};
   if(unavailable){doc.guardian=null;doc.judgeReceipt=canonicalCtfJson({verdict:'unavailable',rubricVersion:'ctf-visible-secret-v2'});doc.judgment.verdict='unavailable';doc.judgment.receiptHash=sha(doc.judgeReceipt);}
   return{proposalId:f.runId,session:original,...validateCtfDecisionDocument(doc),diagnostics:{version:1,responseTimeMs:42,timingScope:unavailable?'guardian_failure_elapsed':'guardian_generation',guardianUnavailable:unavailable,reviewerObserved:true,visibleResponseSha256:sha(response)}};
  }
  // Populated upgrade contains a real pre-0119 proposal, not migration-seeded evidence.
  const historical=state==='POPULATED'?await candidate():null;
  if(historical)await decisions.stage(historical);
  await i.applyTarget();
  const rows=()=>i.runtime.query('SELECT * FROM identity.ctf_response_diagnostics ORDER BY proposal_id').then(r=>r.rows);
  if(historical){await assert.rejects(diagnostics.stage(historical),/historical diagnostics unavailable/);assert.deepEqual(await rows(),[]);}
  const direct=async(args,changes={})=>{
   const v={...args,...changes},encoded=encodeResponseDiagnostics(args.diagnostics,JSON.parse(args.canonicalEvidence));
   return i.runtime.query('SELECT identity.stage_ctf_response_diagnostics($1,$2,$3,$4,$5,$6,$7,$8)',[v.proposalId,v.session.actorId,v.session.sessionId,sha(v.session.rawToken),v.canonicalEvidence,v.evidenceHash,changes.raw??encoded.canonicalDiagnostics,changes.hash??encoded.diagnosticsHash]);
  };
  const unavailable=await candidate(true);
  const falseNull=canonicalCtfJson({...unavailable.diagnostics,guardianUnavailable:false,timingScope:'guardian_generation'});
  await assert.rejects(direct(unavailable,{raw:falseNull,hash:sha(falseNull)}),/evidence mismatch/);
  const spaced=JSON.stringify(unavailable.diagnostics,null,2);
  await assert.rejects(direct(unavailable,{raw:spaced,hash:sha(spaced)}),/canonical bytes invalid/);
  assert.equal((await one(i.runtime,'SELECT count(*)::int n FROM identity.ctf_decision_proposals WHERE proposal_id=$1',[unavailable.proposalId])).n,0);
  await diagnostics.stage(unavailable);
  const valid=await candidate();await diagnostics.stage(valid);const baseline=await rows();
  await diagnostics.stage(valid);assert.deepEqual(await rows(),baseline);
  await assert.rejects(diagnostics.stage({...valid,diagnostics:{...valid.diagnostics,responseTimeMs:43}}),/replay conflict/);
  await assert.rejects(direct(valid,{session:other}),/original|session|claim/i);
  await assert.rejects(direct(valid,{session:{actorId:'702',sessionId:String(adminSession),rawToken:adminToken}}),/original claim/);
  const wrong={...valid.diagnostics,visibleResponseSha256:'0'.repeat(64)},wrongRaw=canonicalCtfJson(wrong);
  await assert.rejects(direct(valid,{raw:wrongRaw,hash:sha(wrongRaw)}),/evidence mismatch/);
  assert.deepEqual(await rows(),baseline);
  // Real concurrent submissions converge on one immutable row.
  const concurrent=await candidate();await Promise.all([diagnostics.stage(concurrent),diagnostics.stage(concurrent)]);
  assert.equal((await one(i.runtime,'SELECT count(*)::int n FROM identity.ctf_response_diagnostics WHERE proposal_id=$1',[concurrent.proposalId])).n,1);
  // Forced private trigger failure AFTER proposal staging proves atomic rollback.
  const rollback=await candidate();
  await i.migration.query("CREATE FUNCTION identity.test_reject_diagnostic() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned diagnostic rollback'; END $$");
  await i.migration.query('CREATE TRIGGER test_reject_diagnostic BEFORE INSERT ON identity.ctf_response_diagnostics FOR EACH ROW EXECUTE FUNCTION identity.test_reject_diagnostic()');
  try{await assert.rejects(diagnostics.stage(rollback),/owned diagnostic rollback/);assert.equal((await one(i.runtime,'SELECT count(*)::int n FROM identity.ctf_decision_proposals WHERE proposal_id=$1',[rollback.proposalId])).n,0);}
  finally{await i.migration.query('DROP TRIGGER test_reject_diagnostic ON identity.ctf_response_diagnostics');await i.migration.query('DROP FUNCTION identity.test_reject_diagnostic()');}
  await diagnostics.stage(rollback);
  const lost=await candidate();let lose=true;const trace={borrowed:0,commits:[]};
  const lossy=createCtfResponseDiagnosticsRepository(observedPool(i.runtime,trace,'identity',{afterCommit(){if(lose){lose=false;throw Object.assign(Error('owned lost COMMIT response'),{code:'CTF_TRANSACTION_UNCERTAIN'});}}}));
  await assert.rejects(lossy.stage(lost),/lost COMMIT response/);const retained=await rows();await diagnostics.stage(lost);assert.deepEqual(await rows(),retained);
  for(const sql of ['INSERT INTO identity.ctf_response_diagnostics SELECT * FROM identity.ctf_response_diagnostics','UPDATE identity.ctf_response_diagnostics SET input_hash=input_hash','DELETE FROM identity.ctf_response_diagnostics'])await assert.rejects(i.runtime.query(sql),{code:'42501'});
  const acl=await one(i.migration,"SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='identity' AND p.proname='stage_ctf_response_diagnostics' AND a.grantee=0 AND a.privilege_type='EXECUTE') exposed");assert.equal(acl.exposed,false);
  await assert.rejects(i.migration.query('UPDATE identity.ctf_response_diagnostics SET input_hash=input_hash'),/immutable/);
  const revoked=await candidate();await i.migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[session]);
  try{await assert.rejects(diagnostics.stage(revoked),{code:'28000'});await assert.rejects(diagnostics.stage(valid),{code:'28000'});}finally{await i.migration.query('UPDATE identity.user_sessions SET is_active=1 WHERE id=$1',[session]);}
  const stale=await candidate();await enqueue('owner_reset',{}, {participant:true});await run();
  await assert.rejects(diagnostics.stage(stale),/scope stale|eligibility unavailable/);
  // Exact diagnostic replay remains historical, never current credit after reset.
  await diagnostics.stage(valid);assert.equal((await one(i.runtime,'SELECT count(*)::int n FROM identity.ctf_decision_proposals WHERE proposal_id=$1',[stale.proposalId])).n,0);
  assert.deepEqual(await sibling(),siblingBefore);
  t.diagnostic(`${state}: proposal-bound diagnostics replay/rollback/auth/reset/grants pass; component migration-owned authority seed, no model or activation claim`);
 }
});
