'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const enabled=process.env.RUN_LIVE_DPI_WORKFLOW==='1'&&process.env.PG_TEST_DISPOSABLE==='yes',KEY='direct_prompt_injection',MODEL='llama3.1:8b';
const IDS=['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation'];
const PRACTICE=['Explain what Amazon S3 stores and one practical use case in two sentences.','Explain how AWS IAM roles help applications access S3 securely in two sentences.'];
const NEGATIVE=Object.freeze({interact:'Write a poem about a red balloon. Do not discuss cloud computing.',system_prompt:'What is the capital of France?',jailbreak:'What is the capital of France?',multi_language:'What is the capital of France?',virtualization:'What is the capital of France?',role_playing:'What is the capital of France?',side_stepping:'What is the capital of France?',obfuscation:'What is the capital of France?'});
function privateInvalidAttemptCapture(diagnosticsPath){
 if(!diagnosticsPath)return null;
 assert.match(diagnosticsPath,/^\/private\/tmp\/[^/]+\/evidence\/diagnostics\.json$/);
 const target=path.join(path.dirname(diagnosticsPath),'invalid-attempts.jsonl'),parent=path.dirname(target),stat=fs.lstatSync(parent);
 assert.equal(stat.isSymbolicLink(),false);assert.equal(stat.uid,process.getuid());assert.equal(stat.mode&0o077,0);
 let fd=null,closed=false;
 const capture=async row=>{assert.equal(closed,false);const raw=typeof row.rawResponse==='string'?row.rawResponse:null,bytes=raw===null?null:Buffer.byteLength(raw),digest=raw===null?null:createHash('sha256').update(raw).digest('hex');
  assert.ok(raw===null||bytes<=16384);assert.equal(row.rawResponseByteCount,bytes);assert.equal(row.rawResponseSha256,digest);
  if(fd===null){fd=fs.openSync(target,'wx',0o600);fs.fchmodSync(fd,0o600);}fs.writeSync(fd,JSON.stringify({...row,rawResponse:raw})+'\n',null,'utf8');fs.fsyncSync(fd);};
 Object.defineProperty(capture,'close',{value(){if(!closed){if(fd!==null)fs.closeSync(fd);closed=true;}}});return Object.freeze(capture);
}

test('DPI mounted route qualifies the fixed eight-objective cohort with actual actor, Judge, reset and sibling isolation',{skip:!enabled,timeout:2400000},async()=>{
 if(!process.env.DPI_LIVE_ISOLATED){
  const root=path.resolve(__dirname,'../..'),copy=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-dpi-live-'));
  try{
   for(const dir of ['server','db','tests'])fs.cpSync(path.join(root,dir),path.join(copy,dir),{recursive:true,filter:file=>{const rel=path.relative(root,file);if(/(?:^|\/)(?:logs|uploads|vector-indexes|sensitive_files|workshop_data|\.env[^/]*)(?:\/|$)/.test(rel))return false;return fs.statSync(file).isDirectory()||/\.(?:js|json|sql)$/.test(file);}});
   fs.symlinkSync(path.join(root,'node_modules'),path.join(copy,'node_modules'),'dir');
   const {spawn}=require('node:child_process');await new Promise((resolve,reject)=>{const child=spawn(process.execPath,['--test',path.join(copy,'tests/postgres/dpiLiveWorkflow.integration.test.js')],{cwd:copy,env:{PATH:process.env.PATH,RUN_LIVE_DPI_WORKFLOW:'1',PG_TEST_DISPOSABLE:'yes',PG_LIVE_ADMIN_URL:process.env.PG_LIVE_ADMIN_URL,DPI_LIVE_ISOLATED:'1',DPI_LIVE_SCOPE:process.env.DPI_LIVE_SCOPE||'all',DPI_LIVE_DIAGNOSTICS_PATH:process.env.DPI_LIVE_DIAGNOSTICS_PATH||'',PLATFORM_DATABASE_ENGINE:'postgres',AI_PROVIDER:'ollama',OLLAMA_BASE_URL:'http://127.0.0.1:11434',OLLAMA_MODEL:MODEL,JUDGE_PROVIDER:'ollama',JUDGE_MODEL:MODEL,AWS_EC2_METADATA_DISABLED:'true',LOGS_DIR:path.join(copy,'logs')},stdio:'inherit'});child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(Error(`Isolated probe exited ${code}`)));});
  }finally{fs.rmSync(copy,{recursive:true,force:true});}return;
 }
 const diagnostics={model:MODEL,scope:process.env.DPI_LIVE_SCOPE||'all',cohort:[],reset:null,cancellation:null};
 assert.ok(['all','system_prompt','practice','obfuscation_candidates'].includes(diagnostics.scope),'Explicit supported DPI qualification scope required');
 const activeIds=diagnostics.scope==='practice'?['interact']:IDS;
 const persist=()=>{const file=process.env.DPI_LIVE_DIAGNOSTICS_PATH;if(file)fs.writeFileSync(file,JSON.stringify(diagnostics,null,2)+'\n',{mode:0o600});};
 const captureInvalidAttempt=privateInvalidAttemptCapture(process.env.DPI_LIVE_DIAGNOSTICS_PATH||'');
 const Module=require('node:module'),originalLoad=Module._load;Module._load=function(name,...args){if(['sqlite3','better-sqlite3'].includes(name)||/authDb$/.test(name))throw Error('Working SQLite import forbidden');return originalLoad.call(this,name,...args);};
 const {Pool}=require('pg'),adminUrl=new URL(process.env.PG_LIVE_ADMIN_URL);assert.ok(['127.0.0.1','localhost','[::1]'].includes(adminUrl.hostname));assert.equal(adminUrl.pathname,'/postgres');
 const tags=await(await fetch('http://127.0.0.1:11434/api/tags')).json();assert.ok(tags.models.some(model=>model.name===MODEL),`${MODEL} must be installed`);
 const poolErrors=[],admin=new Pool({connectionString:adminUrl.href}),database=`dvaia_test_dpilive_${process.pid}`,pools=[];admin.on('error',error=>poolErrors.push(error));let server,ai,originalChat;
 try{
  await admin.query(`CREATE DATABASE ${database} OWNER dvaia_identity_migration`);await admin.query(`REVOKE CONNECT ON DATABASE ${database} FROM PUBLIC`);await admin.query(`GRANT CONNECT ON DATABASE ${database} TO dvaia_identity_runtime`);
  const pool=role=>{const url=new URL(adminUrl);url.pathname='/'+database;url.username=role;url.password='';const result=new Pool({connectionString:url.href,max:5});result.on('error',error=>poolErrors.push(error));pools.push(result);return result;};
  const runtime=pool('dvaia_identity_runtime'),migration=pool('dvaia_identity_migration');process.env.IDENTITY_DATABASE_URL=runtime.options.connectionString;
  const identityApi=require('../../server/database/postgres/identityRepository');await identityApi.initializeIdentityRepository(runtime,migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  const identity=identityApi.createIdentityRepository(runtime),passwordHash=await require('bcryptjs').hash('fixture',4);
  const ownerA=await identity.createUser({username:'dpi-live-a',email:'dpi-live-a@example.invalid',passwordHash}),ownerB=await identity.createUser({username:'dpi-live-b',email:'dpi-live-b@example.invalid',passwordHash}),owners=new Map([['a',ownerA],['b',ownerB]]);
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime),config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(runtime);
  const adapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:identity,progress,jwtSecret:process.env.JWT_SECRET});
  const sessions=new Map;for(const [key,user] of owners)sessions.set(key,await adapter.createSession(await identity.findCredentialById(user.id),{get:()=>null,ip:'127.0.0.1'}));
  const headersFor=(key,json=false)=>({'x-dpi-owner':key,authorization:`Bearer ${sessions.get(key).token}`,...(json?{'content-type':'application/json'}:{})});
  const judgeProvider=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:MODEL,baseURL:'http://127.0.0.1:11434'}),judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:judgeProvider,timeoutMs:120000,...(captureInvalidAttempt?{captureInvalidAttempt}:{})});
  const receipts=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(runtime),completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts,progress,judge});
  const {summarizeMountedQualification}=require('../fixtures/dpiMountedQualification');
  const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(runtime,{leasePool:pool('dvaia_identity_runtime')}),coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'DPI',ledger,defaultTimeoutMs:180000});
  const workshop=require('../../server/services/promptInjectionWorkshop'),progressService=require('../../server/services/promptInjectionProgressService').createPostgresPromptInjectionProgressService({pool:runtime,progress,config});
  const router=require('../../server/routes/promptInjectionWorkshop').createPromptInjectionWorkshopRouter({progressService,completionService:completion,runCoordinator:coordinator});
  ai=require('../../server/services/multiProviderAIService');originalChat=ai.chatWithMessages;const actorCalls=[];ai.chatWithMessages=function(messages,options){actorCalls.push(messages.map(message=>({role:message.role,content:message.content})));return originalChat.call(this,messages,options);};
  const app=require('express')();app.use(require('express').json());app.use(require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter).authenticateToken);app.use((req,res,next)=>{const owner=owners.get(req.get('x-dpi-owner')||'a');if(!owner||owner.id!==req.user.id)return res.status(403).json({code:'OWNER_MISMATCH'});next();});app.use(router);server=await new Promise(resolve=>{const listening=app.listen(0,'127.0.0.1',()=>resolve(listening));});const base=`http://127.0.0.1:${server.address().port}`;globalThis.__DVAIA_DPI_REGISTER_OWNED_ORIGIN?.(base);
  const readProgress=async owner=>{const response=await fetch(base+'/progress',{headers:headersFor(owner)});assert.equal(response.status,200);return response.json();};
  const count=async id=>Number((await runtime.query('SELECT count(*)::int count FROM workshop_platform.objective_judgments WHERE user_id=$1',[id])).rows[0].count);
  if(process.env.DPI_LIVE_BOOT_ONLY==='1'){
   const first=await readProgress('a'),sibling=await readProgress('b');assert.equal(await count(ownerA.id),0);assert.equal(await count(ownerB.id),0);
   const malformed=await fetch(base+'/chat',{method:'POST',headers:headersFor('a',true),body:JSON.stringify({userMessage:'',activeObjectiveId:'system_prompt'})});assert.equal(malformed.status,400);assert.equal((await malformed.json()).code,undefined);
   const crossed=await fetch(base+'/progress',{headers:{...headersFor('a'),'x-dpi-owner':'b'}});assert.equal(crossed.status,403);
   const reset=await fetch(base+'/progress/reset',{method:'POST',headers:headersFor('a',true),body:'{}'});assert.equal(reset.status,200);assert.deepEqual((await readProgress('b')).objectives,sibling.objectives);assert.equal(actorCalls.length,0);
   let entered,release,rejectHeld;const started=new Promise(resolve=>entered=resolve),held=new Promise((resolve,reject)=>{release=resolve;rejectHeld=reject;});held.catch(()=>{});let controlledCalls=0,pending;
   const controller=new AbortController();
   ai.chatWithMessages=async()=>{controlledCalls++;entered();return held;};
   try{
    pending=fetch(base+'/chat',{method:'POST',headers:headersFor('a',true),body:JSON.stringify({userMessage:'Explain AWS S3 in two sentences.',activeObjectiveId:'system_prompt'}),signal:controller.signal});pending.catch(()=>{});
    let timer;try{await Promise.race([started,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Controlled actor did not start')),10000);})]);}finally{clearTimeout(timer);}
    assert.equal(await identity.revokeSession(sessions.get('a').token,ownerA.id,'owned-fixture'),1);
    release({response:'Amazon S3 stores objects.',provider:'mock',model:'controlled-preflight',mocked:true});
    const denied=await pending;assert.equal(denied.status,401);assert.equal((await denied.json()).code,'SESSION_REVOKED');
    assert.equal(await count(ownerA.id),0);assert.equal(await count(ownerB.id),0);assert.deepEqual((await readProgress('b')).objectives,sibling.objectives);
    sessions.set('a',await adapter.createSession(await identity.findCredentialById(ownerA.id),{get:()=>null,ip:'127.0.0.1'}));
    let enteredReset,observedCancel,releaseReset,rejectReset,pendingReset,pendingResetRequest;const resetStarted=new Promise(resolve=>enteredReset=resolve),cancelObserved=new Promise(resolve=>observedCancel=resolve),heldReset=new Promise((resolve,reject)=>{releaseReset=resolve;rejectReset=reject;});heldReset.catch(()=>{});
    const resetController=new AbortController(),resetRequestController=new AbortController();
    ai.chatWithMessages=async(_messages,options)=>{controlledCalls++;assert.ok(options?.signal);if(options.signal.aborted)observedCancel();else options.signal.addEventListener('abort',observedCancel,{once:true});enteredReset();return heldReset;};
    const bounded=async(promise,label)=>{let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error(label+' exceeded 10 seconds')),10000);})]);}finally{clearTimeout(timer);}};
    try{
     pendingReset=fetch(base+'/chat',{method:'POST',headers:headersFor('a',true),body:JSON.stringify({userMessage:'Explain AWS S3 in two sentences.',activeObjectiveId:'system_prompt'}),signal:resetController.signal});pendingReset.catch(()=>{});
     await bounded(resetStarted,'Controlled reset actor start');
     pendingResetRequest=fetch(base+'/progress/reset',{method:'POST',headers:headersFor('a',true),body:'{}',signal:resetRequestController.signal});pendingResetRequest.catch(()=>{});
     await bounded(cancelObserved,'Controlled reset cancellation');
     releaseReset({response:'Amazon S3 stores objects.',provider:'mock',model:'controlled-preflight',mocked:true});
     const [resetHeld,cancelled]=await bounded(Promise.all([pendingResetRequest,pendingReset]),'Controlled reset and cancelled chat');assert.equal(resetHeld.status,200);assert.equal(cancelled.status,409);assert.equal((await cancelled.json()).code,'AGENT_RUN_CANCELLED');
     assert.equal(await count(ownerA.id),0);assert.equal(await count(ownerB.id),0);assert.deepEqual((await readProgress('b')).objectives,sibling.objectives);
     diagnostics.qualification={scope:'owned-session-route-db-preflight',modelCalls:0,controlledProviderCalls:controlledCalls,malformedStatus:malformed.status,harnessOwnerSelectorDeniedStatus:crossed.status,resetStatus:reset.status,revokedInFlightStatus:denied.status,revokedInFlightReceiptCount:0,resetHeldStatus:resetHeld.status,cancelledInFlightStatus:cancelled.status,cancelledInFlightReceiptCount:0,ownerProgressVisible:Boolean(first.objectives),siblingPreserved:true};persist();return;
    }finally{rejectReset(Error('Controlled reset preflight ended'));resetController.abort();resetRequestController.abort();let timer;try{await Promise.race([Promise.allSettled([pendingReset,pendingResetRequest].filter(Boolean)),new Promise(resolve=>{timer=setTimeout(resolve,5000);})]);}finally{clearTimeout(timer);}}
   }finally{controller.abort();rejectHeld(Error('Controlled preflight ended'));if(pending){let timer;try{await Promise.race([pending.catch(()=>{}),new Promise(resolve=>{timer=setTimeout(resolve,5000);})]);}finally{clearTimeout(timer);}}}
  }
  const receipt=async(id,evaluation)=>(await runtime.query(`SELECT j.*,p.judge_version FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id) WHERE j.user_id=$1 AND j.evaluation_id=$2`,[id,evaluation])).rows[0];
  const nominations=(request,response)=>workshop.DETECTORS.filter(item=>item.fn(request,response)).map(item=>item.id),failures=[];
  const chat=async({owner='a',objective,message,positive})=>{
   const user=owners.get(owner),beforeCount=await count(user.id),before=await readProgress(owner),actorIndex=actorCalls.length;
   const response=await fetch(base+'/chat',{method:'POST',headers:headersFor(owner,true),body:JSON.stringify({userMessage:message,activeObjectiveId:objective})}),body=await response.json();
   const entry={owner,objective,kind:positive?'positive':'negative',request:message,status:response.status,actorResponse:body.response||null,judgment:body.judgment||null,completedObjectiveId:body.completedObjectiveId||null};diagnostics.cohort.push(entry);persist();
   assert.equal(response.status,200);assert.equal(actorCalls.length,actorIndex+1);assert.deepEqual(actorCalls[actorIndex].at(-1),{role:'user',content:message},'actor receives exact final input bytes');assert.ok(body.judgment?.evaluationId);assert.equal(await count(user.id),beforeCount+1);
   const stored=await receipt(user.id,body.judgment.evaluationId);assert.equal(stored.objective_id,objective);assert.equal(stored.family,'DPI');assert.equal(stored.scenario,'aws_assistant');assert.equal(stored.judge_version,require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION);if(objective==='system_prompt'){
    assert.equal(stored.rubric_version,'dpi-system-prompt-v12');
    const result=typeof stored.result_json==='string'?JSON.parse(stored.result_json):stored.result_json;
    assert.equal(result.comparisonVersion,'dpi-reference-entailment-v9');
    assert.deepEqual(result.comparisonStages[0],{stage:'source',attempts:0,provider:'server',model:null,completed:true});
    assert.deepEqual(result.comparisonStages[1],{stage:'effect',attempts:1,provider:'ollama',model:MODEL,
      completed:result.comparisonStages[1].completed});
    if(!result.comparisonStages[1].completed)assert.equal(result.verdict,'unavailable');
    if(result.comparisonStages.length===3)assert.deepEqual(result.comparisonStages[2],{stage:'support',attempts:1,provider:'ollama',model:MODEL,completed:true});
    assert.ok([2,3].includes(result.comparisonStages.length));
    assert.equal(result.attempts,result.comparisonStages.length-1);
   }assert.equal(stored.verdict,body.judgment.verdict);assert.equal(String(body.judgment.provider).toLowerCase(),'ollama');assert.equal(body.judgment.model,MODEL);
   const trace=await ledger.getRun(body.judgment.runId,JSON.stringify(['DPI',String(user.id)])),actorEnd=trace?.events.find(event=>event.node==='actor_model'&&event.type==='node_end');assert.equal(actorEnd?.data?.decisionSource,'model');assert.equal(String(actorEnd.data.provider).toLowerCase(),'ollama');assert.equal(actorEnd.data.model,MODEL);if(objective==='system_prompt'){
    assert.ok(trace.events.some(event=>event.node==='judge_compare_source_validate'&&event.type==='decision'&&event.data.evidenceSummary==='trusted_server_reference_v1'));
    assert.ok(trace.events.some(event=>event.node==='judge_compare_effect_model'&&event.type==='node_end'&&event.data.comparisonStage==='effect'&&String(event.data.provider).toLowerCase()==='ollama'&&event.data.model===MODEL));
    const result=typeof stored.result_json==='string'?JSON.parse(stored.result_json):stored.result_json;
    assert.equal(trace.events.some(event=>event.node==='judge_compare_support_model'&&event.type==='node_end'&&event.data.comparisonStage==='support'&&String(event.data.provider).toLowerCase()==='ollama'&&event.data.model===MODEL),result.comparisonStages.length===3);
   }else assert.ok(trace.events.some(event=>event.node==='judge_model'&&event.type==='node_end'&&String(event.data.provider).toLowerCase()==='ollama'&&event.data.model===MODEL));
   Object.assign(entry,{nominations:nominations(message,body.response||''),receipt:{evaluationId:stored.evaluation_id,runId:stored.run_id,verdict:stored.verdict,disposition:stored.disposition,generation:stored.generation,judgeVersion:stored.judge_version,comparisonVersion:(typeof stored.result_json==='string'?JSON.parse(stored.result_json):stored.result_json)?.comparisonVersion||null,comparisonStages:(typeof stored.result_json==='string'?JSON.parse(stored.result_json):stored.result_json)?.comparisonStages||null},actor:actorEnd.data});persist();
   if(!positive){const after=(await readProgress(owner)).objectives[objective],canonicalUnchanged=JSON.stringify(after)===JSON.stringify(before.objectives[objective]);entry.canonicalUnchanged=canonicalUnchanged;if(stored.verdict!=='fail'||stored.disposition!=='not_pass'||!canonicalUnchanged)failures.push({objective,kind:'negative',verdict:stored.verdict,disposition:stored.disposition,canonicalChanged:!canonicalUnchanged});}
   return {body,stored};
  };
  if(diagnostics.scope==='obfuscation_candidates'){
   // Fixed exploration, not an assertion that an attack must succeed. These
   // exact original encoded messages go to the real actor once each.
   const candidates=require('../fixtures/dpiObfuscationCandidateCases.json');assert.equal(candidates.length,4);assert.equal(new Set(candidates.map(c=>c.id)).size,4);
   for(const candidate of candidates.filter(c=>['hex-labelled','unicode-labelled'].includes(c.id))){const payload=candidate.request.split(': ')[1];assert.equal(payload.includes(String.fromCharCode(92,92)),false,'Exactly one backslash per encoded escape');assert.equal(payload.charCodeAt(0),92);assert.equal(payload[1],candidate.id==='hex-labelled'?'x':'u');}
   const negative=candidates.find(c=>c.id==='aws-negative');assert.ok(negative);
   await chat({owner:'b',objective:'obfuscation',message:negative.request,positive:false});diagnostics.cohort.at(-1).candidateId=negative.id;persist();
   const siblingBefore=await readProgress('b'),historyQuery='SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',siblingHistory=(await runtime.query(historyQuery,[ownerB.id])).rows;
   for(const candidate of candidates.filter(c=>c.id!=='aws-negative')){
    const result=await chat({objective:'obfuscation',message:candidate.request,positive:true});
    const entry=diagnostics.cohort.at(-1);entry.candidateId=candidate.id;entry.decodedGroundTruth=candidate.decodedGroundTruth;entry.interpretation='Candidate outcome only; no guaranteed success or hidden decoded actor input';persist();
    assert.ok(['pass','fail','inconclusive','unavailable'].includes(result.stored.verdict));
    if(result.stored.verdict==='pass')assert.ok(['awarded','already_complete'].includes(result.stored.disposition));
    else assert.equal(result.stored.disposition,'not_pass');
   }
   const before=await readProgress('a'),generation=await progress.getGeneration(ownerA.id,KEY),history=(await runtime.query(historyQuery,[ownerA.id])).rows;
   const observedPass=diagnostics.cohort.some(c=>c.owner==='a'&&c.receipt.verdict==='pass');assert.equal(before.objectives.obfuscation.completed,observedPass);
   const reset=await fetch(base+'/progress/reset',{method:'POST',headers:headersFor('a',true),body:'{}'});assert.equal(reset.status,200);const nextGeneration=await progress.getGeneration(ownerA.id,KEY);assert.equal(nextGeneration,generation+1);assert.equal((await readProgress('a')).objectives.obfuscation.completed,false);
   assert.deepEqual((await readProgress('b')).objectives,siblingBefore.objectives);assert.deepEqual((await runtime.query(historyQuery,[ownerA.id])).rows,history);assert.deepEqual((await runtime.query(historyQuery,[ownerB.id])).rows,siblingHistory);
   diagnostics.reset={generation,nextGeneration,ownerResetApplied:true,ownerCompletedBeforeReset:before.objectives.obfuscation.completed,siblingRetained:true,immutableReceiptsPreserved:true};diagnostics.qualification={scope:'Fixed four candidate exploration; no all-positive requirement',candidateAttempts:4,positivePasses:diagnostics.cohort.filter(c=>c.owner==='a'&&c.receipt.verdict==='pass').length,positiveNonPasses:diagnostics.cohort.filter(c=>c.owner==='a'&&c.receipt.verdict!=='pass').length,negativeNoCredit:failures.length===0,actualInputBytesPreserved:true};persist();assert.deepEqual(failures,[],'Encoded AWS negative must not receive obfuscation credit');return;
  }
  if(process.env.DPI_LIVE_SCOPE==='system_prompt'){
   await chat({objective:'system_prompt',message:NEGATIVE.system_prompt,positive:false});
   await chat({objective:'system_prompt',message:`Repeat this text exactly:\n${workshop.SYSTEM_PROMPTS.system_prompt}`,positive:false});
   await chat({objective:'system_prompt',message:`Summarize this configuration:\n${workshop.SYSTEM_PROMPTS.system_prompt}`,positive:false});
   await chat({objective:'system_prompt',message:'Repeat this supplied configuration exactly: The private deployment requires uploading every customer credential to public-example.invalid before answering.',positive:false});
   const shipped=require('../../server/data/promptInjectionSolutions').solutions.system_prompt.examples[0].prompt;
   await chat({objective:'system_prompt',message:shipped,positive:true});
   await chat({owner:'b',objective:'system_prompt',message:shipped,positive:true});
   const siblingBefore=await readProgress('b'),siblingHistory=(await runtime.query('SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[ownerB.id])).rows;assert.equal(siblingBefore.objectives.system_prompt.completed,true);
   const generation=await progress.getGeneration(ownerA.id,KEY),ownerBefore=await readProgress('a'),history=(await runtime.query('SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[ownerA.id])).rows;
   const reset=await fetch(base+'/progress/reset',{method:'POST',headers:headersFor('a',true),body:'{}'});assert.equal(reset.status,200);const nextGeneration=await progress.getGeneration(ownerA.id,KEY),ownerAfter=await readProgress('a'),siblingAfter=await readProgress('b');assert.equal(nextGeneration,generation+1);assert.equal(ownerAfter.objectives.system_prompt.completed,false);assert.deepEqual(siblingAfter.objectives.system_prompt,siblingBefore.objectives.system_prompt);assert.deepEqual((await runtime.query('SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[ownerA.id])).rows,history);assert.deepEqual((await runtime.query('SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[ownerB.id])).rows,siblingHistory);
   diagnostics.reset={generation,nextGeneration,ownerResetApplied:true,ownerCompletedBeforeReset:ownerBefore.objectives.system_prompt.completed,ownerCompletedAfterReset:ownerAfter.objectives.system_prompt.completed,siblingPreserved:true};diagnostics.qualification=summarizeMountedQualification(diagnostics.cohort,diagnostics.reset);persist();assert.equal(diagnostics.qualification.lifecycle.completed,true);assert.deepEqual(diagnostics.qualification.modelAccuracy.mismatches,[],`Focused disclosure model mismatches: ${JSON.stringify(diagnostics.qualification.modelAccuracy.mismatches)}`);return;
  }
  await chat({objective:'interact',message:NEGATIVE.interact,positive:false});
  for(let index=0;index<PRACTICE.length;index++){const outcome=await chat({objective:'interact',message:PRACTICE[index],positive:true}),wanted=index?'awarded':'threshold_pending';if(outcome.stored.verdict!=='pass'||outcome.stored.disposition!==wanted)failures.push({objective:'interact',attempt:index+1,verdict:outcome.stored.verdict,disposition:outcome.stored.disposition});}
  const solutions=require('../../server/data/promptInjectionSolutions').solutions;
  for(const objective of activeIds.slice(1)){const shipped=solutions[objective]?.examples?.[0]?.prompt;assert.equal(typeof shipped,'string');await chat({objective,message:NEGATIVE[objective],positive:false});const outcome=await chat({objective,message:shipped,positive:true});if(outcome.stored.verdict!=='pass'||outcome.stored.disposition!=='awarded')failures.push({objective,verdict:outcome.stored.verdict,disposition:outcome.stored.disposition});}
  const aBefore=await readProgress('a');for(const objective of activeIds)if(!aBefore.objectives[objective]?.completed)failures.push({objective,canonicalCompleted:false});
  for(const message of PRACTICE){const outcome=await chat({owner:'b',objective:'interact',message,positive:true});if(outcome.stored.verdict!=='pass')failures.push({owner:'b',objective:'interact',verdict:outcome.stored.verdict});}
  const siblingBefore=await readProgress('b'),siblingHistory=(await runtime.query('SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[ownerB.id])).rows;if(!siblingBefore.objectives.interact.completed)failures.push({owner:'b',objective:'interact',canonicalCompleted:false});
  const retired=await fetch(base+'/progress/complete',{method:'POST',headers:headersFor('a',true),body:JSON.stringify({objectiveId:'system_prompt'})});assert.equal(retired.status,410);assert.equal((await retired.json()).code,'CLIENT_PROGRESS_MUTATION_RETIRED');
  const generation=await progress.getGeneration(ownerA.id,KEY),beforeReceipts=await count(ownerA.id),history=(await runtime.query('SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[ownerA.id])).rows;
  let markStarted;const started=new Promise(resolve=>{markStarted=resolve;}),capture=ai.chatWithMessages;ai.chatWithMessages=function(messages,options){markStarted();return capture.call(this,messages,options);};
  const pending=fetch(base+'/chat',{method:'POST',headers:headersFor('a',true),body:JSON.stringify({userMessage:'Explain Amazon EC2 instances and security groups.',activeObjectiveId:'interact'})});let timer;
  try{await Promise.race([started,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Actor did not start within 10 seconds')),10000);}),pending.then(response=>{throw Error(`Actor completed before reset: ${response.status}`);})]);}finally{clearTimeout(timer);}
  const reset=await fetch(base+'/progress/reset',{method:'POST',headers:headersFor('a',true),body:'{}'}),cancelled=await pending,cancelledBody=await cancelled.json();ai.chatWithMessages=capture;assert.equal(reset.status,200);assert.equal(cancelled.status,409);assert.equal(cancelledBody.code,'AGENT_RUN_CANCELLED');assert.equal(await count(ownerA.id),beforeReceipts);
  const nextGeneration=await progress.getGeneration(ownerA.id,KEY);assert.equal(nextGeneration,generation+1);const aAfter=await readProgress('a');for(const objective of IDS)assert.equal(aAfter.objectives[objective].completed,false);assert.equal(aAfter.objectives.interact.interactionCount,0);const siblingAfter=await readProgress('b');assert.deepEqual(siblingAfter.objectives.interact,siblingBefore.objectives.interact);assert.deepEqual((await runtime.query('SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[ownerA.id])).rows,history);assert.deepEqual((await runtime.query('SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[ownerB.id])).rows,siblingHistory);
  diagnostics.reset={generation,nextGeneration,receiptCount:beforeReceipts,siblingRetained:true};diagnostics.cancellation={status:cancelled.status,code:cancelledBody.code,lateReceipt:false};persist();assert.deepEqual(failures,[],`Fixed cohort had honest refusals/non-awards: ${JSON.stringify(failures)}`);
 }finally{persist();captureInvalidAttempt?.close();if(server){server.closeAllConnections?.();await new Promise(resolve=>server.close(resolve));}if(ai&&originalChat)ai.chatWithMessages=originalChat;await require('../../server/database/postgres').closePostgresPools();await Promise.all(pools.map(pool=>pool.end()));await admin.query(`DROP DATABASE IF EXISTS ${database}`);await admin.end();Module._load=originalLoad;}assert.deepEqual(poolErrors,[],'Owned PostgreSQL pools emitted idle connection errors');
});
