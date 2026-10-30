'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
const KEY='direct_prompt_injection',MODEL='llama3.1:8b';
(async()=>{
 const root=process.env.DPI_SCOPED_EVIDENCE_ROOT;assert.ok(root);assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const write=(name,value)=>fs.writeFileSync(path.join(root,name),JSON.stringify(value,null,2)+'\n',{mode:0o600});
 const result={status:'preparing',actors:[],calibration:[],scope:['controlled-publication-privacy'],limitations:['All actor/reviewer outputs in this fixture are controlled synthetic inputs; no semantic qualification.','Controlled provider outputs only; no actual model or semantic qualification.','No browser or installed database claim.']};const save=()=>write('candidate-result.json',result);save();
 let transport,server,ai,originalChat;const pools=[];
 try{
  const pool=variable=>{const u=new URL(process.env[variable]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_dpi_[a-f0-9]+_identity$/);const p=new Pool({connectionString:u.href,max:4});pools.push(p);return p;};
  const runtime=pool('DPI_IDENTITY_RUNTIME_URL'),migration=pool('DPI_IDENTITY_MIGRATION_URL');process.env.IDENTITY_DATABASE_URL=runtime.options.connectionString;
  const identityApi=require('../../server/database/postgres/identityRepository');await identityApi.initializeIdentityRepository(runtime,migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  const identity=identityApi.createIdentityRepository(runtime),progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime),config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(runtime);
  const authAdapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:identity,progress,jwtSecret:process.env.JWT_SECRET}),auth=require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(authAdapter);
  const passwordHash=await require('bcryptjs').hash(randomUUID(),4),owners={};
  for(const key of ['vuln','fixed','b']){const user=await identity.createUser({username:'dpi-'+key+'-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash});const session=await authAdapter.createSession(await identity.findCredentialById(user.id),{ip:'127.0.0.1',get:()=>undefined});assert.equal((await authAdapter.validateSession(session.token)).user.id,user.id);owners[key]={user,session};}
  const modes=require('../../server/database/postgres/workshopRevisionRepository').createWorkshopModeRepository(runtime);
  let selectedCase,calls=0,reviewGate,reviewEntered;const marker='HELD_PRIVATE_DRAFT_73914: 4.';
  const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:async()=>{throw Error('Fixed mode must not invoke completion Judge');}});
  const receipts=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(runtime),completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts,progress,judge});
  const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(runtime,{leasePool:pool('DPI_IDENTITY_RUNTIME_URL')}),coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'DPI',ledger,defaultTimeoutMs:300000});
  const progressService=require('../../server/services/promptInjectionProgressService').createPostgresPromptInjectionProgressService({pool:runtime,progress,config});
  const router=require('../../server/routes/promptInjectionWorkshop').createPromptInjectionWorkshopRouter({validateSession:token=>authAdapter.validateSession(token),modeService:require('../../server/services/workshopModeService').createWorkshopModeService(modes),progressService,completionService:completion,runCoordinator:coordinator});
  ai=require('../../server/services/multiProviderAIService');originalChat=ai.chatWithMessages;
  ai.chatWithMessages=async(messages,options)=>{calls++;options.signal?.throwIfAborted();const reviewer=messages[0].content===require('../../server/agent-runtime/dpiPublicationDefense').POLICY;
   if(reviewer&&reviewGate){reviewEntered();await Promise.race([reviewGate,new Promise((_,reject)=>options.signal.addEventListener('abort',()=>reject(options.signal.reason),{once:true}))]);options.signal.throwIfAborted();}
   if(reviewer&&selectedCase.unavailable)throw Error('controlled reviewer unavailable');
   return {provider:'ollama',model:'CONTROLLED-NOT-ACTUAL',response:reviewer?(selectedCase.invalid?'invalid':JSON.stringify({category:selectedCase.allow?'aws_assistance':'out_of_scope_content',coverage:'complete'})):messages.length===2?JSON.stringify(selectedCase.decode?{action:'decode_payload'}:{action:'final',response:selectedCase.draft}):selectedCase.draft};
  };
  const readRepository=require('../../server/database/postgres/agentRunReadRepository').createPostgresAgentRunReadRepository(runtime);
  const app=require('express')();app.use(require('express').json());app.use(auth.authenticateToken);app.use('/runs',require('../../server/routes/agentRuns').createAgentRunsRouter({authenticateToken:auth.authenticateToken,repository:readRepository,listJudgments:userId=>receipts.listRecoverable({userId,judgeVersion:require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION}),regrade:require('../../server/services/objectiveRegradeService').createObjectiveRegradeService({receipts,completion,coordinatorFactory:()=>coordinator})}));app.use(router);
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base='http://127.0.0.1:'+server.address().port,headers=key=>({'content-type':'application/json',authorization:'Bearer '+owners[key].session.token});
  const send=(route,body,key='fixed')=>fetch(base+route,{method:body===undefined?'GET':'POST',headers:headers(key),...(body===undefined?{}:{body:JSON.stringify(body)})});
  const state=async key=>(await runtime.query('SELECT evaluation_id,verdict,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[owners[key].user.id])).rows;
  assert.equal((await send('/mode',{mode:'fixed'})).status,200);assert.equal((await (await send('/mode')).json()).fixedQualification.status,'experimental_unqualified');const sibling=await state('b');
  const request=require('../fixtures/dpiOwnedDecoderCases').scopedCases().actors[0].request;
  for(const row of [{id:'no-tool-held',draft:marker},{id:'decoded-held',decode:true,draft:marker},{id:'aws-published',decode:true,allow:true,draft:'AWS Lambda runs code in response to events.'},{id:'invalid-review',decode:true,invalid:true,draft:marker},{id:'unavailable-review',unavailable:true,draft:marker}]){
   selectedCase=row;const response=await send('/chat',{userMessage:request,activeObjectiveId:'obfuscation'}),body=await response.json();assert.equal(response.status,200,JSON.stringify(body));assert.equal(body.publication.status,row.allow?'published':row.invalid||row.unavailable?'unavailable':'withheld');assert.equal(body.publication.qualification.status,'experimental_unqualified');assert.equal(body.judgment.observationCode,'fixed_mode_ineligible');assert.equal(body.judgment.verdict,'fail');assert.equal(body.completedObjectiveId,null);
   if(row.allow)assert.equal(body.response,row.draft);else assert.equal(JSON.stringify(body).includes(marker),false);
   const stored=(await runtime.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=$1 AND evaluation_id=$2',[owners.fixed.user.id,body.judgment.evaluationId])).rows[0];assert(stored);const recovery=await receipts.getRecovery({userId:owners.fixed.user.id,evaluationId:stored.evaluation_id});const packet=JSON.parse(recovery.packet);assert.equal(packet.evidence.find(e=>e.id==='response').content,row.draft);const publicationAudit=packet.evidence.find(e=>e.id==='fixed_publication_audit')?.content;assert.equal(publicationAudit?.status,body.publication.status);assert.equal(publicationAudit?.receipt?.runId,stored.run_id);assert.ok(publicationAudit?.policySha256);assert.equal(publicationAudit?.draft,undefined);
   const effects=(await runtime.query('SELECT effect_key,status FROM graph_runtime.effects WHERE run_id=$1',[stored.run_id])).rows;assert.ok(effects.some(e=>e.status==='completed'&&e.effect_key.includes('dpi-publication:'))); // Ledger stores receipt/status only; reviewer audit is asserted in the canonical packet above.
   for(const route of ['/runs/'+stored.run_id,'/runs/judgments','/progress']){const r=await send(route);assert.equal(r.status,200);assert.equal((await r.text()).includes(marker),false);}
   const before=calls,retry=await send('/runs/judgments/'+stored.evaluation_id+'/retry',{});assert.equal((await retry.text()).includes(marker),false);assert.equal(calls,before);
   result.actors.push({id:row.id,publication:body.publication,grade:body.judgment.verdict,privateDraftRetained:true,publicDtoMarkerAbsent:true,retryNoCalls:true});save();
  }
  // A canonical mode change during review must fence publication after it settles.
  selectedCase={decode:true,allow:true,draft:marker};let release;reviewGate=new Promise(resolve=>release=resolve);const entered=new Promise(resolve=>reviewEntered=resolve);const pending=send('/chat',{userMessage:request,activeObjectiveId:'obfuscation'});await entered;assert.equal((await send('/mode',{mode:'vuln'})).status,200);release();const stale=await pending;assert.notEqual(stale.status,200);assert.equal((await stale.text()).includes(marker),false);reviewGate=null;
  assert.equal((await send('/mode',{mode:'fixed'})).status,200);
  const raceResults=[];
  for(const kind of ['reset','revoke']){
   selectedCase={decode:true,allow:true,draft:marker};let releaseRace,enteredRace;reviewGate=new Promise(resolve=>releaseRace=resolve);const enteredPromise=new Promise(resolve=>enteredRace=resolve);reviewEntered=enteredRace;
   const judgmentsBefore=await state('fixed');const racing=send('/chat',{userMessage:request,activeObjectiveId:'obfuscation'});await enteredPromise;
   if(kind==='reset'){
    const resetting=send('/progress/reset',{});const resetResponse=await resetting;assert.equal(resetResponse.status,200);releaseRace();
   }else{await authAdapter.logout(owners.fixed.session.token);releaseRace();}
   const blocked=await racing,blockedText=await blocked.text();assert.notEqual(blocked.status,200,kind+' must deny late publication');assert.equal(blockedText.includes(marker),false);assert.deepEqual(await state('fixed'),judgmentsBefore,kind+' must not persist late audit/judgment');reviewGate=null;
   raceResults.push({kind,heldBeforeAuthorityChange:true,httpStatus:blocked.status,noDraftPublished:true,noLateJudgmentOrAudit:true});
   if(kind==='revoke'){owners.fixed.session=await authAdapter.createSession(await identity.findCredentialById(owners.fixed.user.id),{ip:'127.0.0.1',get:()=>undefined});assert.equal((await authAdapter.validateSession(owners.fixed.session.token)).user.id,owners.fixed.user.id);}
  }
  result.inFlightRaces=raceResults;
  const immutable=await state('fixed');assert.equal((await send('/progress/reset',{})).status,200);assert.deepEqual(await state('fixed'),immutable);assert.deepEqual(await state('b'),sibling);assert.equal((await (await send('/progress')).json()).objectives.obfuscation.completed,false);
  let effectCalls=0;await coordinator.run(owners.fixed.user.id,{idempotencyKey:'publication-replay-probe'},e=>e.effectWithReceipt('probe',async()=>{effectCalls++;return {private:'value'};}));await assert.rejects(coordinator.run(owners.fixed.user.id,{idempotencyKey:'publication-replay-probe'},e=>e.effectWithReceipt('probe',async()=>{effectCalls++;})),{code:'GRAPH_EFFECT_REPLAY_BLOCKED'});assert.equal(effectCalls,1);result.effectReplayBlocked=true;
  const before=calls;await authAdapter.logout(owners.fixed.session.token);assert.equal((await send('/chat',{userMessage:request,activeObjectiveId:'obfuscation'})).status,401);assert.equal(calls,before);
  result.lifecycle={modeChangeDuringReviewFenced:true,resetZero:true,immutablePreserved:true,siblingPreserved:true,revokedSessionDenied:true};result.actualInference=0;result.controlledCalls=calls;result.status='passed-controlled-privacy-only';save();
 }catch(error){result.status='failed';result.error={name:error.name,message:error.message};save();throw error;}
 finally{if(ai&&originalChat)ai.chatWithMessages=originalChat;if(server)await new Promise(resolve=>server.close(resolve));await require('../../server/database/postgres').closePostgresPools();await Promise.all(pools.map(p=>p.end()));save();}
})().catch(error=>{console.error(error);process.exitCode=1;});
