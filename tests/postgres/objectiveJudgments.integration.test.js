'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const{randomUUID}=require('node:crypto');
const {createPool}=require('../../server/database/postgres');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const {createWorkshopProgressRepository}=require('../../server/database/postgres/workshopProgressRepository');
const {createWorkshopConfigRepository}=require('../../server/database/postgres/workshopConfigRepository');
const {createWorkshopModeRepository}=require('../../server/database/postgres/workshopRevisionRepository');
const {createObjectiveJudgmentRepository}=require('../../server/database/postgres/objectiveJudgmentRepository');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_JUDGMENTS_TEST_RUNTIME_URL;
test('durable judgments: scoped idempotency, reset/mode/visibility fences, atomic completion and preserved history',{skip:!enabled},async()=>{
 for(const k of ['PG_JUDGMENTS_TEST_RUNTIME_URL','PG_JUDGMENTS_TEST_MIGRATION_URL'])assert.match(new URL(process.env[k]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
 const pool=createPool(process.env,'PG_JUDGMENTS_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_JUDGMENTS_TEST_MIGRATION_URL');
 try{
  await initializeIdentityRepository(pool,migration);await seedWorkshopPlatform(migration);
  const users=createIdentityRepository(pool),hash=await require('bcryptjs').hash('Fixture@123',4);
  const a=await users.createUser({username:'judge-a',email:'a@judge.test',passwordHash:hash}),b=await users.createUser({username:'judge-b',email:'b@judge.test',passwordHash:hash});
  const repo=createObjectiveJudgmentRepository(pool),progress=createWorkshopProgressRepository(pool),config=createWorkshopConfigRepository(pool),modes=createWorkshopModeRepository(pool);
  const input=(overrides={})=>({userId:a.id,evaluationId:randomUUID(),workshopKey:'sql_injection_workshop',objectiveId:'sqli_1',family:'ARIA',scenario:'sqli_1',rubricVersion:'1',evidenceDigest:'a'.repeat(64),runId:null,mode:'fixed',...overrides});
  const result=(s,overrides={})=>({family:s.family,scenario:s.scenario,objectiveId:s.objectiveId,rubricVersion:s.rubricVersion,evidenceDigest:s.evidenceDigest,runId:s.runId,mode:s.mode,verdict:'pass',criteria:[{id:'observed',satisfied:true,evidenceRefs:['receipt-1']}],explanation:'Observed required action.',provider:'ollama',model:'llama3.1:8b',judgeVersion:'2026-09-11.roles-v3',judgePolicyDigest:'d'.repeat(64),durationMs:123,attempts:1,errorCode:null,contextTokens:32768,usage:{outputTokens:5},...overrides});
  const s=input();await repo.beginEvaluation(s);
  const [first,retry]=await Promise.all([repo.recordVerdict({...s,result:result(s)}),repo.recordVerdict({...s,result:result(s)})]);
  assert.equal(first.disposition,'awarded');assert.equal(retry.disposition,'awarded');assert.equal((await progress.getWorkshopProgress(a.id,s.workshopKey)).completedObjectiveCount,1);
  assert.equal(first.result.judgeVersion,'2026-09-11.roles-v3');
  for(const [key,value] of Object.entries({judgePolicyDigest:'d'.repeat(64),durationMs:123,attempts:1,errorCode:null,contextTokens:32768})) assert.equal((await repo.getEvaluation(s)).result[key],value,key);
  const verified=input({objectiveId:'sqli_4'});await repo.beginEvaluation(verified);
  const verifiedReceipt=await repo.recordVerdict({...verified,result:result(verified,{attempts:2,verification:{verdict:'pass',attempts:1},totalCalls:3})});
  assert.equal(verifiedReceipt.disposition,'awarded');
  assert.deepEqual((await repo.getEvaluation(verified)).result.verification,{verdict:'pass',attempts:1});
  assert.equal((await repo.getEvaluation(verified)).result.totalCalls,3);
  const contradictory=input({objectiveId:'sqli_5'});await repo.beginEvaluation(contradictory);
  const completedBefore=(await progress.getWorkshopProgress(a.id,s.workshopKey)).completedObjectiveCount;
  await assert.rejects(repo.recordVerdict({...contradictory,result:result(contradictory,{verification:{verdict:'fail',attempts:1},totalCalls:2})}),{code:'BAD_REQUEST'});
  assert.equal((await repo.getEvaluation(contradictory)).verdict,null,'Rejected verifier contradiction leaves the receipt pending');
  assert.equal((await progress.getWorkshopProgress(a.id,s.workshopKey)).completedObjectiveCount,completedBefore,'Rejected verifier contradiction cannot award completion');
  assert.equal((await createObjectiveJudgmentRepository(pool).getEvaluation(s)).result.judgeVersion,'2026-09-11.roles-v3','A fresh repository reads the persisted judge version');
  assert.equal(await repo.getEvaluation({userId:b.id,evaluationId:s.evaluationId}),null);
  await assert.rejects(repo.recordVerdict({userId:b.id,evaluationId:s.evaluationId,result:result(s)}),{code:'NOT_FOUND'});
  await assert.rejects(repo.beginEvaluation({...s,evidenceDigest:'b'.repeat(64)}),{code:'IDEMPOTENCY_CONFLICT'});
  await assert.rejects(repo.recordVerdict({...s,result:result(s,{scenario:'different'})}),{code:'JUDGMENT_SCOPE_MISMATCH'});
  await assert.rejects(repo.recordVerdict({...s,result:result(s,{verdict:'fail'})}),{code:'IDEMPOTENCY_CONFLICT'});
  const other={...s,userId:b.id};await repo.beginEvaluation(other);assert.equal((await repo.recordVerdict({...other,result:result(other)})).disposition,'awarded','Evaluation UUID is scoped by owner');
  await modes.setMode({userId:a.id,workshopKey:s.workshopKey,mode:'vuln'});
  assert.equal((await repo.beginEvaluation(s)).disposition,'mode_changed');
  assert.equal((await repo.recordVerdict({...s,result:result(s)})).disposition,'mode_changed');
  assert.equal((await repo.getEvaluation(s)).disposition,'awarded','Historical receipt remains immutable');
  await modes.setMode({userId:a.id,workshopKey:s.workshopKey,mode:'fixed'});
  await config.setObjectiveVisibility(s.workshopKey,'sqli_1',false);
  assert.equal((await repo.beginEvaluation(s)).disposition,'hidden');
  await config.setObjectiveVisibility(s.workshopKey,'sqli_1',true);
  const pending=input({objectiveId:'sqli_2'});await repo.beginEvaluation(pending);await progress.resetWorkshopProgress(a.id,s.workshopKey);
  assert.equal((await repo.recordVerdict({...pending,result:result(pending)})).disposition,'stale_generation');assert.equal((await progress.getWorkshopProgress(a.id,s.workshopKey)).completedObjectiveCount,0);
  assert.equal((await repo.getEvaluation(s)).disposition,'awarded','Reset retains receipt history');
  assert.equal((await repo.recordVerdict({...s,result:result(s)})).disposition,'stale_generation');assert.equal((await progress.getWorkshopProgress(a.id,s.workshopKey)).completedObjectiveCount,0,'Old receipt replay must not restore reset completion');
  const hidden=input();await repo.beginEvaluation(hidden);await config.setObjectiveVisibility(s.workshopKey,'sqli_1',false);assert.equal((await repo.recordVerdict({...hidden,result:result(hidden)})).disposition,'hidden');await config.setObjectiveVisibility(s.workshopKey,'sqli_1',true);
  const changed=input();await repo.beginEvaluation(changed);await modes.setMode({userId:a.id,workshopKey:s.workshopKey,mode:'vuln'});assert.equal((await repo.recordVerdict({...changed,result:result(changed)})).disposition,'mode_changed');await modes.setMode({userId:a.id,workshopKey:s.workshopKey,mode:'fixed'});
  for(const verdict of ['fail','inconclusive','unavailable']){const pending=input();await repo.beginEvaluation(pending);assert.equal((await repo.recordVerdict({...pending,result:result(pending,{verdict})})).disposition,'not_pass');}
  for(const code of ['JUDGE_QUEUE_FULL','JUDGE_STORAGE_CONSTRAINT','JUDGE_STORAGE_SCHEMA','JUDGE_STORAGE_PERMISSION','JUDGE_TRANSPORT']){
    const unavailable=input();await repo.beginEvaluation(unavailable);
    const stored=await repo.recordVerdict({...unavailable,result:result(unavailable,{verdict:'unavailable',errorCode:code})});
    assert.equal(stored.result.errorCode,code);assert.equal(stored.disposition,'not_pass');
    assert.equal((await repo.getEvaluation(unavailable)).result.errorCode,code);
    assert.equal((await repo.listRecoverable({userId:a.id,judgeVersion:'fixture'})).find(r=>r.evaluationId===unavailable.evaluationId).errorCode,code);
  }
  const dpi=input({workshopKey:'direct_prompt_injection',objectiveId:'jailbreak',family:'DPI',scenario:'aws_assistant',mode:'vuln'});
  const scoped=await repo.beginEvaluation(dpi);assert.equal(scoped.canonicalMode,null);assert.equal(scoped.modeGuard,'server_scope');assert.equal((await repo.recordVerdict({...dpi,result:result(dpi)})).disposition,'awarded');
  const dpiProgress=require('../../server/services/promptInjectionProgressService').createPostgresPromptInjectionProgressService({pool,progress,config});
  await dpiProgress.resetProgress({userId:a.id,userKey:String(a.id)});
  const practice=()=>input({workshopKey:'direct_prompt_injection',objectiveId:'interact',family:'DPI',scenario:'aws_assistant',mode:'vuln'});
  const practiceOne=practice();await repo.beginEvaluation(practiceOne);
  assert.equal((await repo.recordVerdict({...practiceOne,result:result(practiceOne)})).disposition,'threshold_pending');
  assert.equal((await dpiProgress.getProgress({userId:a.id,userKey:String(a.id)})).objectives.interact.interactionCount,1);
  assert.equal((await progress.getWorkshopProgress(a.id,'direct_prompt_injection')).completedObjectiveCount,0);
  const stalePractice=practice();await repo.beginEvaluation(stalePractice);
  await dpiProgress.resetProgress({userId:a.id,userKey:String(a.id)});
  assert.equal((await repo.recordVerdict({...stalePractice,result:result(stalePractice)})).disposition,'stale_generation');
  assert.equal((await dpiProgress.getProgress({userId:a.id,userKey:String(a.id)})).objectives.interact.interactionCount,0,'Reset discards the first receipt counter');
  const practiceAfterResetOne=practice();await repo.beginEvaluation(practiceAfterResetOne);
  assert.equal((await repo.recordVerdict({...practiceAfterResetOne,result:result(practiceAfterResetOne)})).disposition,'threshold_pending');
  const practiceAfterResetTwo=practice();await repo.beginEvaluation(practiceAfterResetTwo);
  assert.equal((await repo.recordVerdict({...practiceAfterResetTwo,result:result(practiceAfterResetTwo)})).disposition,'awarded');
  const practiceProgress=await dpiProgress.getProgress({userId:a.id,userKey:String(a.id)});
  assert.equal(practiceProgress.objectives.interact.interactionCount,2);
  assert.equal(practiceProgress.objectives.interact.completed,true,'Only the second unique passing receipt awards practice');
  const sensitive=input({workshopKey:'sensitive_info_disclosure',objectiveId:'tool_enum',family:'FinFlow',scenario:'recon',mode:'vuln'});
  assert.equal((await repo.beginEvaluation(sensitive)).canonicalMode,'vuln');assert.equal((await repo.recordVerdict({...sensitive,result:result(sensitive,{mode:'vulnerable'})})).disposition,'awarded');
  const atomic=input();await repo.beginEvaluation(atomic);
  await migration.query("CREATE FUNCTION workshop_platform.reject_judgment_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rollback'; END $$");
  await migration.query('CREATE TRIGGER reject_judgment_update BEFORE UPDATE ON workshop_platform.objective_judgments FOR EACH ROW EXECUTE FUNCTION workshop_platform.reject_judgment_update()');
  await assert.rejects(repo.recordVerdict({...atomic,result:result(atomic)}),/fixture rollback/);assert.equal((await progress.getWorkshopProgress(a.id,s.workshopKey)).completedObjectiveCount,0);assert.equal((await repo.getEvaluation(atomic)).verdict,null);
  await migration.query('DROP TRIGGER reject_judgment_update ON workshop_platform.objective_judgments');
  assert.equal((await repo.recordVerdict({...atomic,result:result(atomic)})).disposition,'awarded');
  const failedAfterSuccess=input();await repo.beginEvaluation(failedAfterSuccess);await repo.recordVerdict({...failedAfterSuccess,result:result(failedAfterSuccess,{verdict:'fail'})});assert.equal((await progress.getWorkshopProgress(a.id,s.workshopKey)).completedObjectiveCount,1,'Later fail never revokes historical completion');
  const {createObjectiveCompletionService}=require('../../server/services/objectiveCompletionService');
  const {createObjectiveJudge}=require('../../server/agent-runtime/objectiveJudge');
  const judge=createObjectiveJudge({model:{generate:async()=>({response:JSON.stringify({verdict:'pass',explanation:'Observed SQL result',criteria:[{id:'proof',satisfied:true,evidenceRefs:['tool']}]}),provider:'fixture',model:'fixture',metadata:{eval_count:3}})}});
  const service=createObjectiveCompletionService({receipts:repo,progress,judge});
  const execution={runId:randomUUID(),check:async()=>{}};
  const rubric={family:'ARIA',scenario:'sql',objectiveId:'sqli_3',version:'test-v1',mode:'fixed',criteria:[{id:'proof',description:'Observed result',allowedSources:['tool_result']}],requiredFacts:[]};
  const attempt=await service.beginAttempt({userId:b.id,workshopKey:'sql_injection_workshop',execution});
  const graded=await service.evaluate({userId:b.id,workshopKey:'sql_injection_workshop',rubric,evidence:[{id:'tool',source:'tool_result',content:'observed result'}],execution,attempt});
  assert.equal(graded.completed,true);assert.equal(graded.receipt.disposition,'awarded');
  const staleAttempt=await service.beginAttempt({userId:b.id,workshopKey:'sql_injection_workshop',execution});await progress.resetWorkshopProgress(b.id,'sql_injection_workshop');
  await assert.rejects(service.evaluate({userId:b.id,workshopKey:'sql_injection_workshop',rubric,evidence:[{id:'tool',source:'tool_result',content:'old result'}],execution,attempt:staleAttempt}),{code:'STALE_GENERATION'});
  const modeAbaAttempt=await service.beginAttempt({userId:b.id,workshopKey:'sql_injection_workshop',execution});
  await modes.setMode({userId:b.id,workshopKey:'sql_injection_workshop',mode:'vuln'});
  await modes.setMode({userId:b.id,workshopKey:'sql_injection_workshop',mode:'fixed'});
  await assert.rejects(service.evaluate({userId:b.id,workshopKey:'sql_injection_workshop',rubric,evidence:[{id:'tool',source:'tool_result',content:'old mode result'}],execution,attempt:modeAbaAttempt}),{code:'MODE_CHANGED'});


  // Recovery stores the exact input before an outage and never reruns a tool.
  let judgeCalls=0;
  const recoveryService=createObjectiveCompletionService({receipts:repo,progress,judge:async packet=>{
    judgeCalls++;
    if(judgeCalls===1)throw Error('fixture outage');
    const prepared=require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(packet);
    return result({family:packet.rubric.family,scenario:packet.rubric.scenario,objectiveId:packet.rubric.objectiveId,rubricVersion:packet.rubric.version,evidenceDigest:prepared.evidenceDigest,runId:packet.execution.runId,mode:packet.rubric.mode});
  }});
  const recoveryExecution={runId:randomUUID(),ownerKey:JSON.stringify(['ARIA',String(b.id)]),durableGeneration:'0',check:async()=>{}};
  const recoveryAttempt=await recoveryService.beginAttempt({userId:b.id,workshopKey:s.workshopKey,execution:recoveryExecution});
  const unavailable=await recoveryService.evaluate({userId:b.id,workshopKey:s.workshopKey,rubric,evidence:[{id:'tool',source:'tool_result',content:'original result'}],execution:recoveryExecution,attempt:recoveryAttempt});
  assert.equal(unavailable.judgment.canRetry,true);
  const originalId=unavailable.receipt.evaluationId;
  const stored=await repo.getRecovery({userId:b.id,evaluationId:originalId});
  await migration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0) ON CONFLICT DO NOTHING',[recoveryExecution.ownerKey]);
  const discover=await repo.listRecoverable({userId:b.id,judgeVersion:stored.judge_version});
  const discovered=discover.find(row=>row.evaluationId===originalId);
  assert.equal(discovered.canRetry,true);
  assert.equal(discovered.evidenceDigest,stored.evidence_digest,'Discovery exposes the receipt digest, never the retained evidence packet');
  assert.ok(discover.length<=20);assert.ok(discover.every(row=>!('packet' in row)&&!('result_json' in row)));
  assert.ok(!(await repo.listRecoverable({userId:a.id,judgeVersion:stored.judge_version})).some(row=>row.evaluationId===originalId));
  assert.equal(JSON.parse(stored.packet).evidence[0].content,'original result');
  await assert.rejects(repo.beginRetry({userId:a.id,evaluationId:originalId,judgeVersion:stored.judge_version,ownerGeneration:'0'}),{code:'NOT_FOUND'});
  await assert.rejects(repo.beginRetry({userId:b.id,evaluationId:originalId,judgeVersion:'changed',ownerGeneration:'0'}),{code:'JUDGE_VERSION_CHANGED'});
  const retried=await recoveryService.retry({userId:b.id,evaluationId:originalId,execution:recoveryExecution});
  assert.equal(retried.completed,true);assert.equal(retried.judgment.canRetry,false);assert.notEqual(retried.receipt.evaluationId,originalId);
  assert.equal((await repo.getEvaluation({userId:b.id,evaluationId:originalId})).verdict,'unavailable');
  assert.equal((await repo.listRecoverable({userId:b.id,judgeVersion:stored.judge_version})).find(row=>row.evaluationId===originalId).canRetry,false,'Reserved child disables new retry offer');
  assert.equal((await recoveryService.retry({userId:b.id,evaluationId:originalId,execution:recoveryExecution})).replayed,true);assert.equal(judgeCalls,2);
  const terminalAfterVersionChange=await repo.beginRetry({userId:b.id,evaluationId:originalId,judgeVersion:'later-deployment',ownerGeneration:'0'});
  assert.equal(terminalAfterVersionChange.receipt.evaluationId,retried.receipt.evaluationId,'A version bump still replays the immutable terminal child');
  assert.equal(terminalAfterVersionChange.receipt.verdict,'pass');
  await assert.rejects(recoveryService.retry({userId:b.id,evaluationId:retried.receipt.evaluationId,execution:recoveryExecution}),{code:'EVIDENCE_INVALID'});
  const {prepareJudgeInput,JUDGE_VERSION}=require('../../server/agent-runtime/objectiveJudge');
  const preparedRecovery=prepareJudgeInput({rubric,evidence:[{id:'tool',source:'tool_result',content:'saved'}]});
  const recoveryInput=input({userId:b.id,objectiveId:rubric.objectiveId,family:rubric.family,scenario:rubric.scenario,rubricVersion:rubric.version,evidenceDigest:preparedRecovery.evidenceDigest,runId:recoveryExecution.runId,recovery:{packet:preparedRecovery.packet,judgeVersion:JUDGE_VERSION,ownerKey:recoveryExecution.ownerKey,ownerGeneration:'0'}});
  await repo.beginEvaluation(recoveryInput);await repo.recordVerdict({...recoveryInput,result:result(recoveryInput,{verdict:'unavailable'})});
  const retryInput={userId:b.id,evaluationId:recoveryInput.evaluationId,judgeVersion:JUDGE_VERSION,ownerGeneration:'0'};
  const reserved=await repo.beginRetry(retryInput);
  await assert.rejects(repo.beginRetry({...retryInput,judgeVersion:'later-deployment'}),{code:'JUDGE_VERSION_CHANGED'},'A pending child cannot resume under a different judge version');
  const resumed=await repo.beginRetry(retryInput);assert.equal(reserved.receipt.evaluationId,resumed.receipt.evaluationId,'Crash recovery reuses child');
  await repo.beginRetry(retryInput);await assert.rejects(repo.beginRetry(retryInput),{code:'RETRY_EXHAUSTED'});
  const bad=input({recovery:{...recoveryInput.recovery,packet:'x'.repeat(24001)}});
  await assert.rejects(repo.beginEvaluation(bad),{code:'BAD_REQUEST'});assert.equal(await repo.getEvaluation(bad),null,'Packet failure atomically rolls back receipt');
  await migration.query("UPDATE workshop_platform.grade_packets SET expires_at=now()-interval '1 second' WHERE user_id=$1 AND evaluation_id=$2",[b.id,recoveryInput.evaluationId]);
  await assert.rejects(repo.beginRetry(retryInput),{code:'EVIDENCE_EXPIRED'});
  await modes.setMode({userId:b.id,workshopKey:s.workshopKey,mode:'vuln'});await modes.setMode({userId:b.id,workshopKey:s.workshopKey,mode:'fixed'});
  await assert.rejects(recoveryService.retry({userId:b.id,evaluationId:originalId,execution:recoveryExecution}),{code:'MODE_CHANGED'});
  const childScope={userId:b.id,evaluationId:retried.receipt.evaluationId,workshopKey:s.workshopKey,objectiveId:rubric.objectiveId,family:rubric.family,scenario:rubric.scenario,rubricVersion:rubric.version,evidenceDigest:retried.receipt.evidenceDigest,runId:retried.receipt.runId,mode:'fixed'};
  assert.equal((await repo.beginEvaluation(childScope)).disposition,'mode_changed','Begin replay detects mode timestamp change');
  assert.equal((await repo.recordVerdict({...childScope,result:retried.receipt.result})).disposition,'mode_changed','Record replay detects mode timestamp change');
  await migration.query('DELETE FROM workshop_platform.grade_packets WHERE user_id=$1 AND evaluation_id=$2',[b.id,retried.receipt.evaluationId]);
  await migration.query('DELETE FROM workshop_platform.grade_packets WHERE user_id=$1 AND evaluation_id=$2',[b.id,reserved.receipt.evaluationId]);
  assert.equal((await repo.recordVerdict({userId:b.id,evaluationId:reserved.receipt.evaluationId,result:result(recoveryInput)})).disposition,'mode_changed','Pending grade cannot award after packet deletion and mode ABA');
  assert.equal((await repo.recordVerdict({...childScope,result:retried.receipt.result})).disposition,'mode_changed','Packet deletion cannot erase durable mode fence');
  await progress.resetWorkshopProgress(b.id,s.workshopKey);
  await assert.rejects(recoveryService.retry({userId:b.id,evaluationId:originalId,execution:recoveryExecution}),{code:'STALE_GENERATION'});

  // Exercise the completion gate through native receipt storage, not a permissive fake.
  const factService=createObjectiveCompletionService({receipts:repo,progress,judge:async packet=>{
    const prepared=prepareJudgeInput(packet);
    return result({family:packet.rubric.family,scenario:packet.rubric.scenario,
      objectiveId:packet.rubric.objectiveId,rubricVersion:packet.rubric.version,
      evidenceDigest:prepared.evidenceDigest,runId:packet.execution.runId,mode:packet.rubric.mode});
  }});
  const factAttempt=await factService.beginAttempt({userId:b.id,workshopKey:s.workshopKey,execution:recoveryExecution});
  const factArgs={userId:b.id,workshopKey:s.workshopKey,
    rubric:{...rubric,requiredFacts:['effect_observed']},facts:{effect_observed:false},
    evidence:[{id:'receipt-1',source:'tool_result',content:'No effect occurred'}],
    execution:recoveryExecution,attempt:factAttempt,evaluationId:randomUUID()};
  const factOutcome=await factService.evaluate(factArgs);
  assert.equal(factOutcome.completed,false);
  assert.equal(factOutcome.receipt.disposition,'not_pass');
  const factReceipt=await createObjectiveJudgmentRepository(pool).getEvaluation({userId:b.id,evaluationId:factOutcome.receipt.evaluationId});
  assert.equal(factReceipt.verdict,'fail');
  assert.equal(factReceipt.result.errorCode,'REQUIRED_FACTS_NOT_SATISFIED');
  assert.equal((await progress.getWorkshopProgress(b.id,s.workshopKey)).completedObjectiveCount,0);
  assert.equal((await factService.evaluate(factArgs)).completed,false,'Replay cannot turn failed facts into credit');
  await assert.rejects(repo.beginRetry({userId:b.id,evaluationId:factReceipt.evaluationId,
    judgeVersion:JUDGE_VERSION,ownerGeneration:'0'}),{code:'RETRY_NOT_ALLOWED'});

 }finally{await Promise.all([pool.end(),migration.end()]);}
});


test('historical finalized inventory judgments replay unchanged across JSONB and schema upgrades',{skip:!enabled},async()=>{
 for(const k of ['PG_JUDGMENTS_TEST_RUNTIME_URL','PG_JUDGMENTS_TEST_MIGRATION_URL'])assert.match(new URL(process.env[k]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
 const pool=createPool(process.env,'PG_JUDGMENTS_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_JUDGMENTS_TEST_MIGRATION_URL');
 try{
  await initializeIdentityRepository(pool,migration);await seedWorkshopPlatform(migration);
  const users=createIdentityRepository(pool),passwordHash=await require('bcryptjs').hash('HistoricalFixture@123',4),suffix=randomUUID();
  const a=await users.createUser({username:`historical-a-${suffix}`,email:`a-${suffix}@judge.test`,passwordHash}),b=await users.createUser({username:`historical-b-${suffix}`,email:`b-${suffix}@judge.test`,passwordHash});
  const repo=createObjectiveJudgmentRepository(pool);
  const input=overrides=>({userId:a.id,evaluationId:randomUUID(),evidenceDigest:'a'.repeat(64),runId:null,...overrides});
  const result=(scope,overrides)=>({family:scope.family,scenario:scope.scenario,objectiveId:scope.objectiveId,rubricVersion:scope.rubricVersion,evidenceDigest:scope.evidenceDigest,runId:scope.runId,mode:scope.mode,verdict:'pass',explanation:'Historical controlled receipt.',provider:'ollama',model:'llama3.1:8b',judgeVersion:'historical-fixture',judgePolicyDigest:'d'.repeat(64),durationMs:123,attempts:1,errorCode:null,contextTokens:32768,usage:{outputTokens:5},...overrides});
  const login=await users.createSession({userId:a.id,token:randomUUID(),expiresAt:new Date(Date.now()+3600000).toISOString(),expectedPasswordHash:passwordHash});
  const launch=await require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(pool).issueOrRenew({platformSessionId:login.id,platformOwnerId:a.id,expiresAt:new Date(Date.now()+3600000).toISOString()});
  const binding=launch.binding;
  // Import an immutable historical receipt, not a newly graded completion.
  // Its v1 audit predates decisionSummary and cannot pass today's normalizer.
  const historic=input({workshopKey:'secureshop_agent_security',objectiveId:'ss_inventory_cross_merchant_stock',family:'SecureShop',scenario:'bound_inventory',rubricVersion:'secureshop-inventory-v3',mode:'vuln'});
  const classification={requestRelation:'implements_request',authorizationRelation:'violates_merchant_ownership',requestExcerpt:'change stock',policyExcerpt:'own products only',selectedProductId:22};
  const effectSummary='Stock mutation for product 22, retailer 18: 5 to 8.';
  const oldResult=result(historic,{criteria:[{id:'owned_stock_authorization_bypass',satisfied:true,evidenceRefs:['inventory_stock'],citations:[classification.requestExcerpt,classification.policyExcerpt,effectSummary].map(quote=>({evidenceId:'inventory_stock',quote}))}],inventoryStockComparison:{version:'inventory-ownership-comparison-v1',stages:[{stage:'instruction',attempts:1,provider:'ollama',model:'llama3.1:8b',completed:true,responseSha256:['b'.repeat(64)]}],observation:{version:'inventory-ownership-comparison-v1',relation:'verified_unauthorized_mutation',sourceSha256:'c'.repeat(64),classification,merchantId:12,retailerId:18,productId:22,changed:true,vulnerable:true,effectSummary}}});
  const originalDigest=require('node:crypto').createHash('sha256').update(JSON.stringify(oldResult)).digest('hex');
  await migration.query(`INSERT INTO workshop_platform.objective_judgments
    (user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,run_id,generation,mode,canonical_mode,verdict,result_json,result_digest,disposition,evaluated_at,platform_launch_id,platform_scenario_id,platform_launch_generation)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULL,0,'vuln',NULL,'pass',$9::jsonb,$10,'awarded',now(),$11,$12,$13)`,
    [a.id,historic.evaluationId,historic.workshopKey,historic.objectiveId,historic.family,historic.scenario,historic.rubricVersion,historic.evidenceDigest,JSON.stringify(oldResult),originalDigest,binding.launchId,binding.scenarioId,binding.generation]);
  await migration.query('INSERT INTO workshop_platform.user_state(user_id,workshop_key) VALUES($1,$2) ON CONFLICT DO NOTHING',[a.id,historic.workshopKey]);
  await assert.rejects(repo.recordVerdict({...historic,result:oldResult}),{code:'GRADE_STORE_NOT_READY'});
  await migration.query(`INSERT INTO workshop_platform.objective_contributions(user_id,evaluation_id,workshop_key,objective_id,platform_launch_id,platform_scenario_id,platform_launch_generation,workshop_generation) VALUES($1,$2,$3,$4,$5,$6,$7,0)`,[a.id,historic.evaluationId,historic.workshopKey,historic.objectiveId,binding.launchId,binding.scenarioId,binding.generation]);
  const historicalSnapshot=async()=>({
    row:(await migration.query('SELECT *,xmin::text AS row_version FROM workshop_platform.objective_judgments WHERE user_id=$1 AND evaluation_id=$2',[a.id,historic.evaluationId])).rows[0],
    completions:(await pool.query('SELECT * FROM workshop_platform.completions WHERE user_id=$1 ORDER BY workshop_key,objective_id',[a.id])).rows,
    contributions:(await migration.query('SELECT *,xmin::text AS row_version FROM workshop_platform.objective_contributions WHERE user_id=$1 ORDER BY evaluation_id',[a.id])).rows
  });
  const beforeHistorical=await historicalSnapshot(),storedHistorical=await repo.getEvaluation(historic);
  assert.notEqual(JSON.stringify(storedHistorical.result),JSON.stringify(oldResult),'PostgreSQL JSONB reordered the original normalized object');
  assert.equal(beforeHistorical.row.result_digest,originalDigest);
  assert.throws(()=>require('../../server/database/postgres/objectiveJudgmentRepository').resultValue(oldResult,beforeHistorical.row),{code:'BAD_REQUEST'});
  for(const replayResult of [oldResult,storedHistorical.result]){
    const replay=await createObjectiveJudgmentRepository(pool).recordVerdict({...historic,result:replayResult});
    assert.deepEqual(replay.result,storedHistorical.result);
    assert.deepEqual(await historicalSnapshot(),beforeHistorical,'Replay neither updates immutable receipt/xmin nor creates completion');
  }
  const altered=structuredClone(storedHistorical.result);altered.inventoryStockComparison.observation.retailerId=12;
  await assert.rejects(repo.recordVerdict({...historic,result:altered}),{code:'BAD_REQUEST'});
  await assert.rejects(repo.recordVerdict({...historic,userId:b.id,result:oldResult}),{code:'NOT_FOUND'});
  const legacyPending={...historic,evaluationId:randomUUID()};
  // A pending legacy record must still use contemporary validation.
  await migration.query(`INSERT INTO workshop_platform.objective_judgments
    (user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,generation,mode,canonical_mode,platform_launch_id,platform_scenario_id,platform_launch_generation)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,'vuln',NULL,$9,$10,$11)`,
    [a.id,legacyPending.evaluationId,historic.workshopKey,historic.objectiveId,historic.family,historic.scenario,historic.rubricVersion,historic.evidenceDigest,binding.launchId,binding.scenarioId,binding.generation]);
  await assert.rejects(repo.recordVerdict({...legacyPending,result:oldResult}),{code:'BAD_REQUEST'});
  assert.equal((await repo.getEvaluation(legacyPending)).verdict,null);
  assert.deepEqual(await historicalSnapshot(),beforeHistorical);
  // Advance the grandfathered scope under the migration role: this proves the
  // repository generation fence, not the separate launch-retirement workflow.
  await migration.query('UPDATE workshop_platform.user_state SET generation=generation+1 WHERE user_id=$1 AND workshop_key=$2',[a.id,historic.workshopKey]);
  const staleReplay=await repo.recordVerdict({...historic,result:storedHistorical.result});
  assert.equal(staleReplay.disposition,'stale_generation');assert.equal(staleReplay.historicalDisposition,'awarded');
  assert.deepEqual(await historicalSnapshot(),beforeHistorical,'Generation change cannot rewrite receipt or reaward');
 }finally{await Promise.all([pool.end(),migration.end()]);}
});
