'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
const KEY='direct_prompt_injection',MODEL='llama3.1:8b';
const cohort=process.env.DPI_SCOPED_COHORT??'current';
assert.ok(['current','historical-wrong-answer'].includes(cohort),'Closed DPI scoped cohort required');
const calibrationCount=cohort==='historical-wrong-answer'?8:10,maxHttpCalls=cohort==='historical-wrong-answer'?22:26;
(async()=>{
 const root=process.env.DPI_SCOPED_EVIDENCE_ROOT;assert.ok(root);assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
 const write=(name,value)=>fs.writeFileSync(path.join(root,name),JSON.stringify(value,null,2)+'\n',{mode:0o600});
 const result={cohort,maxHttpCalls,status:'preparing',actors:[],calibration:[],scope:['virtualization','obfuscation'],limitations:['Synthetic responses qualify Judge semantics only, never actor execution or credit.','One prospectively fixed shipped actor attempt per objective; refusals and unavailability are retained.','No browser or installed database claim.']};const save=()=>write('candidate-result.json',result);save();
 let transport,server,ai,originalChat;const pools=[];
 try{
  const pool=variable=>{const u=new URL(process.env[variable]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_dpi_[a-f0-9]+_identity$/);const p=new Pool({connectionString:u.href,max:4});pools.push(p);return p;};
  const runtime=pool('DPI_IDENTITY_RUNTIME_URL'),migration=pool('DPI_IDENTITY_MIGRATION_URL');process.env.IDENTITY_DATABASE_URL=runtime.options.connectionString;
  const identityApi=require('../../server/database/postgres/identityRepository');await identityApi.initializeIdentityRepository(runtime,migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  const identity=identityApi.createIdentityRepository(runtime),progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime),config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(runtime);
  const authAdapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:identity,progress,jwtSecret:process.env.JWT_SECRET}),auth=require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(authAdapter);
  const passwordHash=await require('bcryptjs').hash(randomUUID(),4),owners={};
  for(const key of ['a','b']){const user=await identity.createUser({username:'dpi-'+key+'-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash});const session=await authAdapter.createSession(await identity.findCredentialById(user.id),{ip:'127.0.0.1',get:()=>undefined});assert.equal((await authAdapter.validateSession(session.token)).user.id,user.id);owners[key]={user,session};}
  const {scopedCases,calibrationPacket}=require('../fixtures/dpiScopedV3Cases'),cases=scopedCases({cohort});assert.equal(cases.actors.length,2);assert.equal(cases.calibration.length,calibrationCount);
  transport=await require('../fixtures/dpiScopedActualTransport').createDpiScopedActualTransport({maxHttpCalls,record:record=>write('actual-model-wire.json',record)});
  process.env.AI_PROVIDER='ollama';process.env.OLLAMA_BASE_URL=transport.actorUrl;process.env.OLLAMA_MODEL=MODEL;
  const judgeModel=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:MODEL,baseURL:transport.judgeUrl});
  const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:judgeModel,timeoutMs:65000,captureInvalidAttempt:async row=>fs.appendFileSync(path.join(root,'invalid-judge-attempts.jsonl'),JSON.stringify(row)+'\n',{mode:0o600})});
  const receipts=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(runtime),completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts,progress,judge});
  const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(runtime,{leasePool:pool('DPI_IDENTITY_RUNTIME_URL')}),coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'DPI',ledger,defaultTimeoutMs:180000});
  const progressService=require('../../server/services/promptInjectionProgressService').createPostgresPromptInjectionProgressService({pool:runtime,progress,config});
  const router=require('../../server/routes/promptInjectionWorkshop').createPromptInjectionWorkshopRouter({progressService,completionService:completion,runCoordinator:coordinator});
  ai=require('../../server/services/multiProviderAIService');assert.equal(ai.provider,'ollama');assert.equal(ai.ollamaBaseURL,transport.actorUrl);assert.equal(ai.ollamaModel,MODEL);originalChat=ai.chatWithMessages;const actorInputs=[];ai.chatWithMessages=function(messages,options){assert.ok(actorInputs.length<2);actorInputs.push(structuredClone(messages));return originalChat.call(this,messages,options);};
  const app=require('express')();app.use(require('express').json());app.use(auth.authenticateToken);app.use(router);server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base='http://127.0.0.1:'+server.address().port;
  const headers=owner=>({'content-type':'application/json',authorization:'Bearer '+owners[owner].session.token});
  const read=async owner=>{const r=await fetch(base+'/progress',{headers:headers(owner)});assert.equal(r.status,200);return r.json();};
  const history=async owner=>(await runtime.query('SELECT evaluation_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[owners[owner].user.id])).rows;
  const siblingBefore=await read('b'),siblingHistory=await history('b');assert.equal((await fetch(base+'/progress')).status,401);
  for(const row of cases.actors){
   const beforeInputs=actorInputs.length,r=await fetch(base+'/chat',{method:'POST',headers:headers('a'),body:JSON.stringify({userMessage:row.request,activeObjectiveId:row.objective})}),body=await r.json();
   const observed={...row,httpStatus:r.status,response:body.response||null,judgment:body.judgment||null};result.actors.push(observed);save();assert.equal(r.status,200);assert.equal(actorInputs.length,beforeInputs+1);assert.deepEqual(actorInputs.at(-1).at(-1),{role:'user',content:row.request});
   assert.ok(body.judgment?.evaluationId);const stored=(await runtime.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=$1 AND evaluation_id=$2',[owners.a.user.id,body.judgment.evaluationId])).rows[0];assert.equal(stored.objective_id,row.objective);assert.equal(stored.rubric_version,'dpi-'+row.objective+'-v3');assert.equal(stored.verdict,body.judgment.verdict);
   const trace=await ledger.getRun(stored.run_id,JSON.stringify(['DPI',String(owners.a.user.id)])),actorEnd=trace.events.find(e=>e.node==='actor_model'&&e.type==='node_end');assert.equal(actorEnd?.data?.decisionSource,'model');assert.equal(String(actorEnd.data.provider).toLowerCase(),'ollama');assert.equal(actorEnd.data.model,MODEL);
   observed.receipt={evaluationId:stored.evaluation_id,verdict:stored.verdict,disposition:stored.disposition,rubric:stored.rubric_version};assert.equal((await read('a')).objectives[row.objective].completed,stored.verdict==='pass');if(stored.verdict!=='pass')assert.equal(stored.disposition,'not_pass');save();
  }
  const canonicalBeforeCalibration=await history('a');
  for(const row of cases.calibration){const packet=await calibrationPacket(row),outcome=await judge(packet);result.calibration.push({...row,packet,outcome,matched:outcome.verdict===row.expected});save();}
  assert.deepEqual(await history('a'),canonicalBeforeCalibration,'Synthetic calibration cannot write receipts or credit');
  const generation=await progress.getGeneration(owners.a.user.id,KEY),beforeReset=await read('a'),immutable=await history('a');
  assert.equal((await fetch(base+'/progress/reset',{method:'POST',headers:headers('a'),body:'{}'})).status,200);
  assert.equal(await progress.getGeneration(owners.a.user.id,KEY),generation+1);const after=await read('a');for(const row of cases.actors)assert.equal(after.objectives[row.objective].completed,false);assert.deepEqual(await history('a'),immutable);assert.deepEqual(await history('b'),siblingHistory);assert.deepEqual((await read('b')).objectives,siblingBefore.objectives);
  const callsBeforeRevoke=transport.calls.length;await authAdapter.logout(owners.a.session.token);assert.equal((await fetch(base+'/chat',{method:'POST',headers:headers('a'),body:JSON.stringify({activeObjectiveId:'obfuscation',userMessage:'Decode Mis yPw=='})})).status,401);assert.equal(transport.calls.length,callsBeforeRevoke);
  result.lifecycle={canonicalSessions:true,revokedSessionDeniedWithoutModel:true,generationBefore:generation,generationAfter:generation+1,completedBeforeReset:cases.actors.filter(row=>beforeReset.objectives[row.objective].completed).map(row=>row.objective),resetToZero:true,immutableJudgmentsPreserved:true,siblingPreserved:true};
  result.actualActorHttp=transport.calls.filter(c=>c.kind==='actor').length;result.actualJudgeHttp=transport.calls.filter(c=>c.kind==='judge').length;assert.equal(result.actualActorHttp,2);assert.ok(transport.calls.length<=maxHttpCalls);
  result.status=result.actors.every(row=>row.receipt.verdict==='pass')&&result.calibration.every(row=>row.matched)?'passed':'observed_negative';save();
 }catch(error){result.status='failed';result.error={name:error.name,message:error.message};save();throw error;}
 finally{if(ai&&originalChat)ai.chatWithMessages=originalChat;if(server)await new Promise(resolve=>server.close(resolve));await transport?.close();await require('../../server/database/postgres').closePostgresPools();await Promise.all(pools.map(p=>p.end()));save();}
})().catch(error=>{console.error(error);process.exitCode=1;});
