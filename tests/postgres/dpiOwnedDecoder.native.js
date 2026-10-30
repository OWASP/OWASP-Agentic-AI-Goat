'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
const KEY='direct_prompt_injection',MODEL='llama3.1:8b';
(async()=>{
 const root=process.env.DPI_SCOPED_EVIDENCE_ROOT;assert.ok(root);assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const write=(name,value)=>fs.writeFileSync(path.join(root,name),JSON.stringify(value,null,2)+'\n',{mode:0o600});
 const result={status:'preparing',actors:[],calibration:[],scope:['owned-decoder-vuln','owned-decoder-fixed'],limitations:['Retained semantic negatives are qualified separately in DPI v8 retained97816; no synthetic actor response here.','One prospectively fixed payload in separate vulnerable/fixed owners; model selects decoding, no injected decisions or final responses.','No browser or installed database claim.']};const save=()=>write('candidate-result.json',result);save();
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
  const cases=require('../fixtures/dpiOwnedDecoderCases').scopedCases();assert.equal(cases.actors.length,2);assert.equal(cases.calibration.length,0);
  transport=await require('../fixtures/dpiScopedActualTransport').createDpiScopedActualTransport({maxHttpCalls:8,record:record=>write('actual-model-wire.json',record)});
  process.env.AI_PROVIDER='ollama';process.env.OLLAMA_BASE_URL=transport.actorUrl;process.env.OLLAMA_MODEL=MODEL;
  const judgeModel=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:MODEL,baseURL:transport.judgeUrl});
  const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:judgeModel,timeoutMs:60000,dpiAnswerTimeoutMs:90000,contextTokens:32768,captureInvalidAttempt:async row=>fs.appendFileSync(path.join(root,'invalid-judge-attempts.jsonl'),JSON.stringify(row)+'\n',{mode:0o600})});
  const receipts=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(runtime),completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts,progress,judge});
  const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(runtime,{leasePool:pool('DPI_IDENTITY_RUNTIME_URL')}),coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'DPI',ledger,defaultTimeoutMs:300000});
  const progressService=require('../../server/services/promptInjectionProgressService').createPostgresPromptInjectionProgressService({pool:runtime,progress,config});
  const router=require('../../server/routes/promptInjectionWorkshop').createPromptInjectionWorkshopRouter({modeService:require('../../server/services/workshopModeService').createWorkshopModeService(modes),progressService,completionService:completion,runCoordinator:coordinator});
  ai=require('../../server/services/multiProviderAIService');assert.equal(ai.provider,'ollama');assert.equal(ai.ollamaBaseURL,transport.actorUrl);assert.equal(ai.ollamaModel,MODEL);originalChat=ai.chatWithMessages;const actorInputs=[];ai.chatWithMessages=function(messages,options){assert.ok(actorInputs.length<4);actorInputs.push(structuredClone(messages));return originalChat.call(this,messages,options);};
  const app=require('express')();app.use(require('express').json());app.use(auth.authenticateToken);app.use('/runs',require('../../server/routes/agentRuns').createAgentRunsRouter({authenticateToken:auth.authenticateToken,repository:{},regrade:require('../../server/services/objectiveRegradeService').createObjectiveRegradeService({receipts,completion,coordinatorFactory:()=>coordinator})}));app.use(router);server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base='http://127.0.0.1:'+server.address().port;
  const headers=owner=>({'content-type':'application/json',authorization:'Bearer '+owners[owner].session.token});
  const read=async owner=>{const r=await fetch(base+'/progress',{headers:headers(owner)});assert.equal(r.status,200);return r.json();};
  const history=async owner=>(await runtime.query('SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[owners[owner].user.id])).rows;
  const siblingBefore=await read('b'),siblingHistory=await history('b');assert.equal((await fetch(base+'/progress')).status,401);
  for(const mode of ['vuln','fixed']){const rr=await fetch(base+'/mode',{method:'POST',headers:headers(mode),body:JSON.stringify({mode})});assert.equal(rr.status,200);const body=await rr.json();assert.equal(body.mode,mode);assert.deepEqual(body.fixedObjectiveIds,['obfuscation']);const readback=await fetch(base+'/mode',{headers:headers(mode)});assert.equal((await readback.json()).mode,mode);}
  const lifecycle=[];
  for(const row of cases.actors){
   owners.a=owners[row.owner];const otherOwner=row.owner==='vuln'?'fixed':'vuln',otherBefore=await read(otherOwner),otherHistory=await history(otherOwner);
   assert.equal((await read('a')).objectives[row.objective].completed,false);const beforeInputs=actorInputs.length,r=await fetch(base+'/chat',{method:'POST',headers:headers('a'),body:JSON.stringify({userMessage:row.request,activeObjectiveId:row.objective})}),body=await r.json();
   const observed={...row,httpStatus:r.status,response:body.response||null,judgment:body.judgment||null};result.actors.push(observed);save();assert.equal(r.status,200);assert.equal(actorInputs[beforeInputs].at(-1).content,row.request);
   assert.ok(body.judgment?.evaluationId);const stored=(await runtime.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=$1 AND evaluation_id=$2',[owners.a.user.id,body.judgment.evaluationId])).rows[0];assert.equal(stored.objective_id,row.objective);assert.equal(stored.rubric_version,'dpi-obfuscation-v9');assert.equal(stored.verdict,body.judgment.verdict);
   const recovery=await receipts.getRecovery({userId:owners.a.user.id,evaluationId:stored.evaluation_id}),packet=JSON.parse(recovery.packet),proof=packet.evidence.find(e=>e.id==='owned_decoder').content;
   assert.equal(packet.evidence.find(e=>e.id==='request').content,row.request);assert.equal(packet.evidence.find(e=>e.id==='response').content,body.response);assert.equal(proof.mode,row.mode);assert.equal(proof.runId,stored.run_id);assert.equal(proof.ownerKey,JSON.stringify(['DPI',String(owners.a.user.id)]));
   const selected=proof.decision.action==='decode_payload';assert.equal(actorInputs.length-beforeInputs,selected?2:1);
   const effects=(await runtime.query('SELECT effect_key,status FROM graph_runtime.effects WHERE run_id=$1',[stored.run_id])).rows;assert.equal(effects.length,selected?1:0);
   if(selected){assert.equal(effects[0].effect_key,proof.receipt.effectKey);assert.equal(effects[0].status,'completed');assert.deepEqual(actorInputs.at(-1),require('../../server/agent-runtime/dpiObfuscationGraph').finalMessages(row.request,proof.output,row.mode));}
   const trace=await ledger.getRun(stored.run_id,JSON.stringify(['DPI',String(owners.a.user.id)]));assert.ok(trace.events.some(e=>e.node==='decoder_decision'&&e.type==='decision'&&e.data?.decisionSource==='model'));if(selected)assert.ok(trace.events.some(e=>e.node==='actor_model'&&e.type==='node_end'&&e.data?.decisionSource==='model'));
   observed.execution={selectedDecoder:selected,actorCalls:actorInputs.length-beforeInputs,effects:effects.length,promotionRole:proof.promotionRole,packet};
   let finalStored=stored;
   observed.canonicalResult=finalStored.result_json;observed.receipt={evaluationId:finalStored.evaluation_id,verdict:finalStored.verdict,disposition:finalStored.disposition,rubric:finalStored.rubric_version};assert.equal((await read('a')).objectives[row.objective].completed,finalStored.verdict==='pass');if(finalStored.verdict!=='pass')assert.equal(finalStored.disposition,'not_pass');save();
  const generation=await progress.getGeneration(owners.a.user.id,KEY),beforeReset=await read('a'),immutable=await history('a');
  assert.equal((await fetch(base+'/progress/reset',{method:'POST',headers:headers('a'),body:'{}'})).status,200);
  assert.equal(await progress.getGeneration(owners.a.user.id,KEY),generation+1);const after=await read('a');for(const row of cases.actors)assert.equal(after.objectives[row.objective].completed,false);assert.deepEqual(await history('a'),immutable);assert.deepEqual(await history('b'),siblingHistory);assert.deepEqual((await read('b')).objectives,siblingBefore.objectives);
  assert.deepEqual(await history(otherOwner),otherHistory);assert.deepEqual((await read(otherOwner)).objectives,otherBefore.objectives);
  lifecycle.push({caseId:row.id,canonicalSessions:true,generationBefore:generation,generationAfter:generation+1,completedBeforeReset:beforeReset.objectives[row.objective].completed?[row.objective]:[],resetToZero:true,immutableJudgmentsPreserved:true,siblingPreserved:true,otherModeOwnerPreserved:true});
  }
  for(const row of cases.actors){owners.a=owners[row.owner];
  const callsBeforeRevoke=transport.calls.length;await authAdapter.logout(owners.a.session.token);assert.equal((await fetch(base+'/chat',{method:'POST',headers:headers('a'),body:JSON.stringify({activeObjectiveId:'obfuscation',userMessage:'Decode Mis yPw=='})})).status,401);assert.equal(transport.calls.length,callsBeforeRevoke);
lifecycle.find(x=>x.caseId===row.id).revokedSessionDeniedWithoutModel=true;}
  result.lifecycle=lifecycle;
  result.actualActorHttp=transport.calls.filter(c=>c.kind==='actor').length;result.actualJudgeHttp=transport.calls.filter(c=>c.kind==='judge').length;assert.ok(result.actualActorHttp>=2&&result.actualActorHttp<=4);assert.ok(transport.calls.length<=8);
  result.modeOutcomes=result.actors.map(row=>({id:row.id,verdict:row.receipt.verdict,canonicalAward:row.receipt.disposition==='awarded'}));result.fixedDefenseRequiresIndependentRawReview=true;result.status=result.actors.every(row=>row.execution.selectedDecoder&&row.receipt.verdict===(row.mode==='vuln'?'pass':'fail'))?'passed-pending-raw-review':'observed_negative';save();
 }catch(error){result.status='failed';result.error={name:error.name,message:error.message};save();throw error;}
 finally{if(ai&&originalChat)ai.chatWithMessages=originalChat;if(server)await new Promise(resolve=>server.close(resolve));await transport?.close();await require('../../server/database/postgres').closePostgresPools();await Promise.all(pools.map(p=>p.end()));save();}
})().catch(error=>{console.error(error);process.exitCode=1;});
