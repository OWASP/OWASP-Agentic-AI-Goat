'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createObjectiveCompletionService}=require('../server/services/objectiveCompletionService');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const rubric={family:'ARIA',scenario:'sqli_1',objectiveId:'sqli_1',version:'v1',mode:'fixed',criteria:[{id:'proof',description:'Observed',allowedSources:['tool_result']}],requiredFacts:[]};
const evidence=[{id:'tool1',source:'tool_result',content:'observed'}];
function fixture(judge){
 let generation=0,calls=[];const records=new Map();
 const execution={runId:randomUUID(),check:async()=>{calls.push('check');}};
 const receipts={async beginEvaluation(s){calls.push('begin');if(s.expectedGeneration!==generation)throw Object.assign(new Error('stale'),{code:'STALE_GENERATION'});const r=records.get(s.evaluationId)||{...s,generation,verdict:null};records.set(s.evaluationId,r);return r;},async recordVerdict(s){calls.push('record');const r=records.get(s.evaluationId);const out={...r,result:s.result,verdict:s.result.verdict,disposition:r.generation!==generation?'stale_generation':s.result.verdict==='pass'?'awarded':'not_pass'};records.set(s.evaluationId,out);return out;}};
 const service=createObjectiveCompletionService({receipts,progress:{getGeneration:async()=>generation},judge:judge||(async input=>{calls.push('judge');return{family:input.rubric.family,scenario:input.rubric.scenario,objectiveId:input.rubric.objectiveId,rubricVersion:input.rubric.version,mode:input.rubric.mode,runId:input.execution.runId,evidenceDigest:prepareJudgeInput(input).evidenceDigest,verdict:'pass',criteria:[{id:'proof',satisfied:true,evidenceRefs:['tool1']}],explanation:'Observed',provider:'fixture',model:'fixture',usage:null};})});
 return{service,execution,calls,reset:()=>generation++};
}
test('completion begins before judge and binds a workshop-level context to owner/execution/digest',async()=>{
 const f=fixture();const attempt=await f.service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution:f.execution});
 const args={userId:1,workshopKey:'sql_injection_workshop',rubric,evidence,execution:f.execution,evaluationId:randomUUID(),attempt};const result=await f.service.evaluate(args);
 assert.equal(result.completed,true);assert.ok(f.calls.indexOf('begin')<f.calls.indexOf('judge'));assert.ok(f.calls.indexOf('judge')<f.calls.indexOf('record'));
 assert.equal(result.judgment.evidenceDigest,prepareJudgeInput({rubric,evidence}).evidenceDigest);
 assert.equal((await f.service.evaluate(args)).replayed,true);assert.equal(f.calls.filter(c=>c==='judge').length,1);
 await assert.rejects(f.service.evaluate({...args,execution:{...f.execution}}),{code:'ATTEMPT_SCOPE_MISMATCH'});
 await assert.rejects(f.service.evaluate({...args,userId:2}),{code:'ATTEMPT_SCOPE_MISMATCH'});
});
test('SecureShop attempts capture immutable launch scope only from the protected execution',async()=>{
 const launch={launchId:randomUUID(),scenarioId:randomUUID(),generation:7,platformOwnerId:41,platformSessionId:91};
 const execution={runId:randomUUID(),check:async()=>{}};let capturedScope;
 const receipts={
  async beginEvaluation(scope){capturedScope=scope;return {...scope,generation:3,verdict:null};},
  async recordVerdict({result}){return {...capturedScope,generation:3,verdict:result.verdict,result,disposition:'awarded'};}
 };
 const service=createObjectiveCompletionService({receipts,progress:{getGeneration:async()=>3},
  captureInstanceScope:async actual=>{assert.equal(actual,execution);return launch;},
  judge:async input=>({family:input.rubric.family,scenario:input.rubric.scenario,
   objectiveId:input.rubric.objectiveId,rubricVersion:input.rubric.version,
   evidenceDigest:prepareJudgeInput(input).evidenceDigest,runId:input.execution.runId,
   mode:input.rubric.mode,verdict:'pass',criteria:[{id:'proof',satisfied:true,evidenceRefs:['tool1']}],explanation:'Observed'})});
 const secureRubric={...rubric,family:'SecureShop',scenario:'review-moderation',objectiveId:'moderate_review'};
 const attempt=await service.beginAttempt({userId:41,workshopKey:'secureshop_agent_security',objectiveId:'moderate_review',execution});
 launch.generation=99;launch.platformOwnerId=999;launch.launchId=randomUUID();
 await service.evaluate({userId:41,workshopKey:'secureshop_agent_security',rubric:secureRubric,evidence,execution,attempt});
 assert.deepEqual(capturedScope.instanceScope,{launchId:attempt.instanceScope.launchId,
  scenarioId:attempt.instanceScope.scenarioId,generation:7,platformOwnerId:41,platformSessionId:91});
 assert.equal(Object.isFrozen(attempt.instanceScope),true);
 await assert.rejects(service.evaluate({userId:41,workshopKey:'secureshop_agent_security',rubric:secureRubric,
  evidence,execution,evaluationId:randomUUID(),attempt:{...attempt,instanceScope:{...attempt.instanceScope,generation:8}}}),
 {code:'ATTEMPT_SCOPE_MISMATCH'});
});
test('SecureShop grading fails closed without a trusted matching launch capture',async()=>{
 const base={receipts:{beginEvaluation:async()=>{throw Error('must not persist');},recordVerdict:async()=>{}},progress:{getGeneration:async()=>0}};
 const execution={runId:randomUUID(),check:async()=>{}};
 const missing=createObjectiveCompletionService(base);
 await assert.rejects(missing.beginAttempt({userId:4,workshopKey:'secureshop_agent_security',execution}),{code:'GRADE_STORE_NOT_READY'});
 const wrong=createObjectiveCompletionService({...base,captureInstanceScope:async()=>({launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:5,platformSessionId:9})});
 await assert.rejects(wrong.beginAttempt({userId:4,workshopKey:'secureshop_agent_security',execution}),{code:'ATTEMPT_SCOPE_MISMATCH'});
});
test('persistence refuses an overgenerous Judge pass without required observed facts',async()=>{
 const f=fixture();
 const attempt=await f.service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution:f.execution});
 const result=await f.service.evaluate({userId:1,workshopKey:'sql_injection_workshop',
  rubric:{...rubric,requiredFacts:['effect_observed']},evidence,facts:{effect_observed:false},execution:f.execution,attempt});
 assert.equal(result.completed,false);
 assert.equal(result.receipt.disposition,'not_pass');
 assert.equal(result.judgment.verdict,'fail');
 assert.equal(result.judgment.errorCode,'REQUIRED_FACTS_NOT_SATISFIED');
 const {resultValue}=require('../server/database/postgres/objectiveJudgmentRepository');
 const stored=resultValue(result.judgment,{family:rubric.family,scenario:rubric.scenario,
  objective_id:rubric.objectiveId,rubric_version:rubric.version,mode:rubric.mode,
  run_id:f.execution.runId,evidence_digest:result.judgment.evidenceDigest});
 assert.equal(stored.verdict,'fail');
 assert.equal(stored.errorCode,'REQUIRED_FACTS_NOT_SATISFIED');
 assert.equal(require('../server/agent-runtime/judgeErrors').canRetryJudgeError(stored.errorCode),false);
});
test('retry persistence applies the same required-fact gate to the stored packet',async()=>{
 const scopedRubric={...rubric,requiredFacts:['effect_observed']};
 const prepared=prepareJudgeInput({rubric:scopedRubric,evidence,facts:{effect_observed:false}});
 const receipt={evaluationId:randomUUID(),runId:randomUUID(),rubricVersion:rubric.version,evidenceDigest:prepared.evidenceDigest};
 let persisted;
 const service=createObjectiveCompletionService({progress:{getGeneration:async()=>0},receipts:{
  beginEvaluation:async()=>{},beginRetry:async()=>({receipt,packet:prepared.packet}),
  recordVerdict:async({result})=>{persisted=result;return {...receipt,result,disposition:result.verdict==='pass'?'awarded':'not_pass'};},
 },judge:async()=>({verdict:'pass',criteria:[],explanation:'Overgenerous fixture'})});
 const result=await service.retry({userId:1,evaluationId:receipt.evaluationId,execution:{runId:randomUUID(),check:async()=>{}}});
 assert.equal(persisted.verdict,'fail');assert.equal(result.completed,false);
 assert.equal(persisted.errorCode,'REQUIRED_FACTS_NOT_SATISFIED');
});
test('reset after evidence but before evaluation rejects without invoking judge',async()=>{
 const f=fixture();const attempt=await f.service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution:f.execution});f.reset();
 await assert.rejects(f.service.evaluate({userId:1,workshopKey:'sql_injection_workshop',rubric,evidence,execution:f.execution,attempt}),{code:'STALE_GENERATION'});assert.equal(f.calls.includes('judge'),false);
});
test('ordinary model failure is recorded unavailable; cancellation is not converted to failure',async()=>{
 const f=fixture(async()=>{throw new Error('network');});const attempt=await f.service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution:f.execution});
 const result=await f.service.evaluate({userId:1,workshopKey:'sql_injection_workshop',rubric,evidence,execution:f.execution,attempt});assert.equal(result.judgment.verdict,'unavailable');assert.equal(result.completed,false);assert.ok(f.calls.includes('record'));
 const cancelled=fixture(async()=>{throw Object.assign(new Error('reset'),{name:'AbortError'});});const other=await cancelled.service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution:cancelled.execution});await assert.rejects(cancelled.service.evaluate({userId:1,workshopKey:'sql_injection_workshop',rubric,evidence,execution:cancelled.execution,attempt:other}),{name:'AbortError'});assert.equal(cancelled.calls.includes('record'),false);
});
test('new unavailable judgments expose retry only for repository-supported error categories',async()=>{
 const unavailable=errorCode=>async input=>({family:input.rubric.family,scenario:input.rubric.scenario,objectiveId:input.rubric.objectiveId,rubricVersion:input.rubric.version,mode:input.rubric.mode,runId:input.execution.runId,evidenceDigest:prepareJudgeInput(input).evidenceDigest,verdict:'unavailable',errorCode,criteria:[],explanation:'Unavailable',provider:null,model:null,usage:null});
 for(const [errorCode,expected] of [['JUDGE_TIMEOUT',true],['JUDGE_CONTEXT_LIMIT',false],['INVALID_OR_OVERSIZED_EVIDENCE',false]]){
  const f=fixture(unavailable(errorCode));f.execution.ownerKey='["ARIA","1"]';f.execution.durableGeneration='0';
  const attempt=await f.service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution:f.execution});
  const result=await f.service.evaluate({userId:1,workshopKey:'sql_injection_workshop',rubric,evidence,execution:f.execution,attempt});
  assert.equal(result.judgment.canRetry,expected,errorCode);
 }
});
test('oversized evidence yields durable inconclusive without calling the model',async()=>{
 const f=fixture();const attempt=await f.service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution:f.execution});const result=await f.service.evaluate({userId:1,workshopKey:'sql_injection_workshop',rubric,evidence:[{id:'tool1',source:'tool_result',content:'x'.repeat(25000)}],execution:f.execution,attempt});assert.equal(result.judgment.verdict,'inconclusive');assert.equal(f.calls.includes('judge'),false);assert.ok(f.calls.includes('record'));
});
test('reset during judge preserves verdict but prevents completion at receipt commit',async()=>{
 let f;
 f=fixture(async input=>{f.reset();return{family:input.rubric.family,scenario:input.rubric.scenario,objectiveId:input.rubric.objectiveId,rubricVersion:input.rubric.version,mode:input.rubric.mode,runId:input.execution.runId,evidenceDigest:prepareJudgeInput(input).evidenceDigest,verdict:'pass',criteria:[{id:'proof',satisfied:true,evidenceRefs:['tool1']}],explanation:'Observed',provider:'fixture',model:'fixture',usage:null};});
 const attempt=await f.service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution:f.execution});const result=await f.service.evaluate({userId:1,workshopKey:'sql_injection_workshop',rubric,evidence,execution:f.execution,attempt});assert.equal(result.judgment.verdict,'pass');assert.equal(result.completed,false);assert.equal(result.receipt.disposition,'stale_generation');
});

test('retry judge events attach to new coordinator run while receipt keeps original evidence run',async()=>{
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
 const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
 const traces=require('../server/agent-runtime/runTraceStore');
 const prepared=prepareJudgeInput({rubric,evidence});const originalRunId=randomUUID(),evaluationId=randomUUID();
 const receipt={evaluationId,runId:originalRunId,rubricVersion:rubric.version,evidenceDigest:prepared.evidenceDigest};
 const service=createObjectiveCompletionService({progress:{getGeneration:async()=>0},receipts:{beginEvaluation:async()=>{},beginRetry:async()=>({receipt,packet:prepared.packet}),recordVerdict:async({result})=>({...receipt,result,verdict:result.verdict,disposition:'awarded'})},judge:createObjectiveJudge({model:{generate:async()=>({response:JSON.stringify({verdict:'pass',explanation:'Observed',criteria:[{id:'proof',satisfied:true,evidenceRefs:['tool1']}]}),provider:'fixture',model:'fixture'})}})});
 const coordinator=createRunCoordinator({family:'ARIA',ledger:null});
 const result=await coordinator.run('trace-retry',{},execution=>service.retry({userId:1,evaluationId,execution}));
 assert.notEqual(result.retryRunId,originalRunId);assert.equal(result.judgment.runId,originalRunId);
 const run=traces.getRun(result.retryRunId,JSON.stringify(['ARIA','trace-retry']));
 assert.ok(run.events.some(e=>e.node==='judge_model'&&e.type==='node_start'));
 assert.ok(run.events.some(e=>e.node==='judge_model'&&e.type==='node_end'));
 assert.ok(run.events.some(e=>e.data.verdict==='pass'));
});

test('mode flip-back during evidence retains the original mode stamp and cannot reach judging',async()=>{
 let stamp='before',judgeCalls=0;
 const execution={runId:randomUUID(),check:async()=>{}};
 const service=createObjectiveCompletionService({
  progress:{getGeneration:async()=>0,getEvaluationScope:async()=>({generation:0,mode:'fixed',modeStamp:stamp})},
  receipts:{beginEvaluation:async scope=>{
   assert.equal(scope.expectedMode,'fixed');assert.equal(scope.expectedModeStamp,'before');
   if(scope.expectedModeStamp!==stamp)throw Object.assign(Error('Mode changed while evidence was generated'),{code:'MODE_CHANGED'});
  },recordVerdict:async()=>{throw Error('Must not persist');}},
  judge:async()=>{judgeCalls++;throw Error('Must not judge');}
 });
 const attempt=await service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution});
 // Another worker switches fixed -> vuln -> fixed; generation and final mode match.
 stamp='after-two-changes';
 await assert.rejects(service.evaluate({userId:1,workshopKey:'sql_injection_workshop',rubric,evidence,execution,attempt}),{code:'MODE_CHANGED'});
 assert.equal(judgeCalls,0);
});

test('unavailable replay preserves evaluation ID and rechecks retained recovery scope',async()=>{
 const {JUDGE_VERSION}=require('../server/agent-runtime/objectiveJudge');
 const evaluationId=randomUUID(),execution={runId:randomUUID(),ownerKey:'["ARIA","1"]',durableGeneration:'3',check:async()=>{}};
 let recoveryReads=0;
 let recovery={packet:'retained',child_evaluation_id:null,judge_version:JUDGE_VERSION,owner_key:execution.ownerKey,owner_generation:'3',expires_at:new Date(Date.now()+60000)};
 const receipt={evaluationId,generation:0,verdict:'unavailable',disposition:'not_pass',result:{verdict:'unavailable'}};
 const service=createObjectiveCompletionService({progress:{getGeneration:async()=>0},receipts:{beginEvaluation:async()=>receipt,recordVerdict:async()=>{throw Error('Must not regrade');},getRecovery:async()=>{recoveryReads++;return recovery;}},judge:async()=>{throw Error('Must not invoke judge');}});
 const attempt=await service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution});
 const args={userId:1,workshopKey:'sql_injection_workshop',rubric,evidence,execution,evaluationId,attempt};
 const valid=await service.evaluate(args);assert.equal(valid.judgment.evaluationId,evaluationId);assert.equal(valid.judgment.canRetry,true);assert.equal(valid.replayed,true);
 for(const patch of [{xss_binding_current:false},{packet:null},{child_evaluation_id:randomUUID()},{judge_version:'obsolete'},{owner_generation:'2'},{owner_key:'other'},{expires_at:new Date(0)}]){
  const prior=recovery;recovery={...recovery,...patch};assert.equal((await service.evaluate(args)).judgment.canRetry,false);recovery=prior;
 }
 receipt.disposition='stale_generation';assert.equal((await service.evaluate(args)).judgment.canRetry,false);
 receipt.disposition='not_pass';receipt.result={verdict:'unavailable',errorCode:'JUDGE_CONTEXT_LIMIT'};const readsBeforeTerminal=recoveryReads;assert.equal((await service.evaluate(args)).judgment.canRetry,false);assert.equal(recoveryReads,readsBeforeTerminal);
 receipt.result={verdict:'unavailable',errorCode:'INVALID_OR_OVERSIZED_EVIDENCE'};assert.equal((await service.evaluate(args)).judgment.canRetry,false);
});

test('escaped judge failures retain bounded categories without exception text, including retry',async()=>{
 const cases=[['AI_QUEUE_FULL','JUDGE_QUEUE_FULL'],['23514','JUDGE_STORAGE_CONSTRAINT'],['42P01','JUDGE_STORAGE_SCHEMA'],['42501','JUDGE_STORAGE_PERMISSION'],['ECONNRESET','JUDGE_TRANSPORT'],['ETIMEDOUT','JUDGE_TIMEOUT'],['attacker-controlled-code','JUDGE_UNAVAILABLE']];
 for(const [code,expected] of cases){
  const failure=Object.assign(Error('private SQL / token / provider body'),{code});
  const f=fixture(async()=>{throw failure;});const attempt=await f.service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution:f.execution});
  const result=await f.service.evaluate({userId:1,workshopKey:'sql_injection_workshop',rubric,evidence,execution:f.execution,attempt});
  assert.equal(result.judgment.errorCode,expected);assert.equal(result.completed,false);assert.ok(!JSON.stringify(result).includes('private SQL'));
  const prepared=prepareJudgeInput({rubric,evidence});const receipt={evaluationId:randomUUID(),runId:randomUUID(),family:rubric.family,scenario:rubric.scenario,objectiveId:rubric.objectiveId,mode:rubric.mode,rubricVersion:rubric.version,evidenceDigest:prepared.evidenceDigest};
  const service=createObjectiveCompletionService({progress:{getGeneration:async()=>0},receipts:{beginEvaluation:async()=>{},beginRetry:async()=>({receipt,packet:prepared.packet}),recordVerdict:async({result})=>({...receipt,result,verdict:result.verdict,disposition:'not_pass'})},judge:async()=>{throw failure;}});
  const retry=await service.retry({userId:1,evaluationId:receipt.evaluationId,execution:f.execution});assert.equal(retry.judgment.errorCode,expected);assert.equal(retry.completed,false);assert.ok(!JSON.stringify(retry).includes('private SQL'));
 }
 const {canRetryJudgeError}=require('../server/agent-runtime/judgeErrors');for(const [,code] of cases)assert.equal(canRetryJudgeError(code),true);
 assert.equal(canRetryJudgeError('INVALID_OR_OVERSIZED_EVIDENCE'),false);assert.equal(canRetryJudgeError('forged'),false);
});

test('canonical prerequisites require the original current attempt and never accept local progress claims', async () => {
  let generation = 2, completed = false, reads = 0;
  const execution = { runId: randomUUID(), check: async () => {} };
  const service = createObjectiveCompletionService({
    receipts: { beginEvaluation: async () => {}, recordVerdict: async () => {} },
    progress: { getGeneration: async () => generation,
      getObjectiveCompletionState: async (uid, workshop, objective, options) => {
        reads++; assert.equal(uid, 17); assert.equal(workshop, 'xss_workshop'); assert.equal(objective, 'xss_g2');
        assert.equal(options.expectedGeneration, 2); return { generation, completed };
      } },
  });
  const attempt = await service.beginAttempt({ userId: 17, workshopKey: 'xss_workshop', execution });
  const args = { userId: 17, workshopKey: 'xss_workshop', objectiveId: 'xss_g2', execution, attempt,
    clientCompleted: ['xss_g2'] };
  assert.equal(await service.hasPrerequisite(args), false);
  completed = true; assert.equal(await service.hasPrerequisite(args), true);
  for (const change of [{ userId: 18 }, { attempt: { ...attempt } }, { execution: { ...execution } }, { workshopKey: 'other' }]) {
    await assert.rejects(service.hasPrerequisite({ ...args, ...change }), { code: 'ATTEMPT_SCOPE_MISMATCH' });
  }
  assert.equal(reads, 2);
  generation++; await assert.rejects(service.hasPrerequisite(args), { code: 'STALE_GENERATION' });
  const unavailable = fixture();
  const otherAttempt = await unavailable.service.beginAttempt({ userId: 17, workshopKey: 'xss_workshop', execution: unavailable.execution });
  await assert.rejects(unavailable.service.hasPrerequisite({ ...args, execution: unavailable.execution, attempt: otherAttempt }), { code: 'GRADE_STORE_NOT_READY' });
});

test('XSS attempt captures exact child authority and forwards it to evaluation',async()=>{
 const runId=randomUUID();
 const binding=Object.freeze({runId,ownerId:17,ownerKey:'["XSS","17"]',scopeKey:'stored_llm',parentGeneration:'4',childGeneration:'9007199254740993'});
 const execution={runId,ownerKey:binding.ownerKey,durableGeneration:'4',scopeBinding:binding,check:async()=>{}};
 let captured;
 const service=createObjectiveCompletionService({progress:{getGeneration:async()=>2},receipts:{
  beginEvaluation:async scope=>{captured=scope;return{...scope,generation:2,verdict:'fail',result:{verdict:'fail'},disposition:'not_pass'};},recordVerdict:async()=>assert.fail('replay'),
 }});
 const attempt=await service.beginAttempt({userId:17,workshopKey:'xss_workshop',execution});
 const scopedRubric={...rubric,family:'XSS',scenario:'stored_llm',objectiveId:'xss_g2'};
 await service.evaluate({userId:17,workshopKey:'xss_workshop',execution,attempt,rubric:scopedRubric,evidence});
 assert.deepEqual(captured.xssScope,binding);assert.ok(Object.isFrozen(attempt.xssScope));
 await assert.rejects(service.evaluate({userId:17,workshopKey:'xss_workshop',execution,attempt,rubric:{...scopedRubric,objectiveId:'xss_s1'},evidence}),/objective does not match/);
 assert.deepEqual(captured.xssScope,binding);
 execution.scopeBinding=Object.freeze({...binding,childGeneration:'9007199254740994'});
 await assert.rejects(service.evaluate({userId:17,workshopKey:'xss_workshop',execution,attempt,rubric:scopedRubric,evidence}),{code:'ATTEMPT_SCOPE_MISMATCH'});
});
test('XSS attempt refuses cross-owner and cross-workshop scope before reading progress',async()=>{
 let reads=0;const runId=randomUUID();
 const execution={runId,ownerKey:'["XSS","17"]',durableGeneration:'4',check:async()=>{},scopeBinding:Object.freeze({runId,ownerId:18,ownerKey:'["XSS","18"]',scopeKey:'stored_llm',parentGeneration:'4',childGeneration:'0'})};
 const service=createObjectiveCompletionService({progress:{getGeneration:async()=>{reads++;return 0;}},receipts:{beginEvaluation:async()=>{},recordVerdict:async()=>{}}});
 await assert.rejects(service.beginAttempt({userId:17,workshopKey:'xss_workshop',execution}));
 await assert.rejects(service.beginAttempt({userId:17,workshopKey:'sql_injection_workshop',execution}));
 assert.equal(reads,0);
});

test('scoped XSS replay requires affirmative stored child eligibility',async()=>{
 const {JUDGE_VERSION}=require('../server/agent-runtime/objectiveJudge');
 const runId=randomUUID(),evaluationId=randomUUID();
 const execution={runId,ownerKey:'["XSS","17"]',durableGeneration:'4',check:async()=>{},scopeBinding:Object.freeze({runId,ownerId:17,ownerKey:'["XSS","17"]',scopeKey:'stored_llm',parentGeneration:'4',childGeneration:'2'})};
 let eligibility;
 const receipt={evaluationId,generation:0,verdict:'unavailable',disposition:'not_pass',result:{verdict:'unavailable'}};
 const service=createObjectiveCompletionService({progress:{getGeneration:async()=>0},receipts:{
  beginEvaluation:async()=>receipt,recordVerdict:async()=>assert.fail('replay'),
  getRecovery:async()=>({packet:'retained',judge_version:JUDGE_VERSION,owner_key:execution.ownerKey,owner_generation:'4',expires_at:new Date(Date.now()+60000),xss_binding_current:eligibility}),
 }});
 const attempt=await service.beginAttempt({userId:17,workshopKey:'xss_workshop',execution});
 const args={userId:17,workshopKey:'xss_workshop',execution,attempt,evaluationId,evidence,rubric:{...rubric,family:'XSS',scenario:'stored_llm',objectiveId:'xss_g2'}};
 for(const value of [undefined,null,false,'true']){
  eligibility=value;assert.equal((await service.evaluate(args)).judgment.canRetry,false);
 }
 eligibility=true;assert.equal((await service.evaluate(args)).judgment.canRetry,true);
});

test('scoped XSS execution cannot silently drop its grading binding',async()=>{
 let reads=0;
 const execution={runId:randomUUID(),ownerKey:'["XSS","17"]',durableGeneration:'4',scope:{userId:17,scopeKey:'stored_llm'},check:async()=>{}};
 const service=createObjectiveCompletionService({progress:{getGeneration:async()=>{reads++;return 0;}},receipts:{beginEvaluation:async()=>{},recordVerdict:async()=>{}}});
 await assert.rejects(service.beginAttempt({userId:17,workshopKey:'xss_workshop',execution}),{code:'ATTEMPT_SCOPE_MISMATCH'});
 assert.equal(reads,0);
});
