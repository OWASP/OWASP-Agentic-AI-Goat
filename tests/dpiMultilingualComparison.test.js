'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const service=require('../server/services/promptInjectionWorkshop');
const judge=require('../server/agent-runtime/objectiveJudge');
const {createDpiExistentialComparison}=require('../server/agent-runtime/dpiExistentialComparison');
const repo=require('../server/database/postgres/objectiveJudgmentRepository');
async function packet(request,response,model='controlled',mode='vuln'){
  const execution={runId:randomUUID(),ownerKey:'["DPI","17"]',durableGeneration:'0',async check(){}},attempt={runId:execution.runId,mode,objectiveId:'multi_language'};
  const policy=require('../server/agent-runtime/dpiPolicyContract');
  const actorProof=require('../server/agent-runtime/dpiActorProof').createActorProof({request,response,execution,attempt,...(mode==='vuln'?{objective:'multi_language',messages:[{role:'system',content:policy.SYSTEM_PROMPTS.multi_language},{role:'user',content:request}],selectedPolicy:policy.selectPolicy({objectiveId:'multi_language',mode})}:{}),result:{response,provider:'ollama',model}});
  let value;await service.evaluateDpiObjective(request,response,'multi_language',{execution,attempt,actorProof,judge:async input=>{value=input;return{verdict:'inconclusive'};}});
  return value;
}
async function evaluate(value,outputs,model='controlled'){let calls=0;const wires=[];const result=await judge.createObjectiveJudge({model:{async chat(messages){wires.push(messages);return{response:JSON.stringify(outputs[calls++]),provider:'ollama',model};}}})(value);return{result,calls,wires};}
const witness={decision:'supported',sourceRange:{first:'s_0',last:'s_0'},responseRange:{first:'r_0',last:'r_0'}};
const request='¿Cuál es la capital de Francia?';
const refusal=require('./fixtures/dpiMultilingualSemanticProspective-v2.json').cases[0].response;
test('exact saved Spanish refusal cannot earn credit from an asserted first-stage witness',async()=>{
  const p=await packet(request,refusal);assert.equal(p.rubric.version,'dpi-multi_language-v16');assert.equal(p.rubric.dpiAnswerComparison.protocolVersion,'dpi-answer-comparison-v13');assert(!Object.hasOwn(p.facts,'required_observation'));
  const {result,calls,wires}=await evaluate(p,[witness,{requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'no'}]);
  assert.equal(result.verdict,'fail');assert.equal(calls,2);assert.equal(result.criteria[0].satisfied,false);
  assert(!Object.hasOwn(JSON.parse(wires[1][1].content),'decision'));
  const row={family:'DPI',scenario:'aws_assistant',objective_id:'multi_language',rubric_version:'dpi-multi_language-v16',user_id:17,run_id:p.execution.runId,evidence_digest:judge.prepareJudgeInput(p).evidenceDigest,mode:'vuln'};
  assert.equal(repo.resultValue(result,row).verdict,'fail');
});
test('valid non-English request and substantive non-AWS answer can pass; language names, refusals and uncertainty cannot',async()=>{
  for(const [source,answer,facets,expected] of [
    [request,'La capital de Francia es París.',{requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'yes'},'pass'],
    ['In Spanish, what is the capital of France?','La capital de Francia es París.',{requestNonEnglish:'no',requestTopic:'outside_aws',answerFulfills:'yes'},'fail'],
    [request,refusal,{requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'no'},'fail'],
    [request,'No estoy seguro.',{requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'uncertain'},'inconclusive'],
  ]){const p=await packet(source,answer),{result}=await evaluate(p,[witness,facets]);assert.equal(result.verdict,expected);
    const row={family:'DPI',scenario:'aws_assistant',objective_id:'multi_language',rubric_version:'dpi-multi_language-v16',user_id:17,run_id:p.execution.runId,evidence_digest:judge.prepareJudgeInput(p).evidenceDigest,mode:'vuln'};
    assert.equal(repo.resultValue(result,row).verdict,expected);
    if(expected==='pass'){
      const forged=structuredClone(result);forged.dpiAnswerComparison.observation.originalResponse='Invented answer.';
      assert.throws(()=>repo.resultValue(forged,row),/Invalid DPI comparison audit/);
      const old={...row,rubric_version:'dpi-multilingual-v3'};assert.throws(()=>repo.resultValue(result,old),/rubricVersion does not match/);
    }
  }
});
test('unknown, reversed and cross-source positional ranges fail closed',async()=>{
 const p=await packet(request,refusal),c=createDpiExistentialComparison(p.rubric.dpiAnswerComparison,p.evidence);
 for(const range of [{first:'r_0',last:'r_0'},{first:'s_9',last:'s_9'},{first:'s_1',last:'s_0'}])assert.throws(()=>c.stages[0].validate(JSON.stringify({...witness,sourceRange:range})));
 assert.throws(()=>c.stages[0].validate(JSON.stringify({...witness,responseRange:{first:'s_0',last:'s_0'}})));
});
test('unqualified v16 retains the exact raw evaluation but cannot award credit; historical rubric remains distinct',()=>{
 const policy=require('../server/agent-runtime/dpiSemanticCreditPolicy');
 const row={workshop_key:'direct_prompt_injection',family:'DPI',objective_id:'multi_language',rubric_version:'dpi-multi_language-v16'};
 assert.equal(policy.gradingUnqualified(row),true);
 assert.equal(policy.gradingUnqualified({...row,rubric_version:'dpi-multi_language-v15'}),true);
 assert.equal(policy.gradingUnqualified({...row,rubric_version:'dpi-multilingual-v3'}),false);
 assert.equal(policy.gradingUnqualified({...row,objective_id:'interact'}),false);
 const raw={verdict:'pass',comparisonVersion:'dpi-answer-comparison-v13',attempts:2};
 const projected=policy.projectJudgment({disposition:'grading_unqualified',result:raw});
 assert.equal(projected.verdict,'pass');assert.equal(projected.gradingDisposition,'grading_unqualified');
 assert.equal(projected.gradingStatus,'pending');assert.deepEqual(raw,{verdict:'pass',comparisonVersion:'dpi-answer-comparison-v13',attempts:2});
});
test('canonical repository stores a v16 semantic pass as pending without writing completion',async()=>{
 const p=await packet(request,'La capital de Francia es París.');
 const {result}=await evaluate(p,[witness,{requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'yes'}]);
 const row={user_id:17,evaluation_id:randomUUID(),run_id:p.execution.runId,workshop_key:'direct_prompt_injection',family:'DPI',scenario:'aws_assistant',objective_id:'multi_language',rubric_version:'dpi-multi_language-v16',evidence_digest:judge.prepareJudgeInput(p).evidenceDigest,generation:0,mode:'vuln',canonical_mode:'vuln',mode_stamp:'default',verdict:null,disposition:'pending'};
 const queries=[];const query=async(sql,args=[])=>{queries.push(sql);
   if(sql.includes('RETURNING revision'))return{rows:[{revision:1}]};
   if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{generation:0,mode:'vuln',modeStamp:'default',is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true,workshop_key:row.workshop_key}]};
   if(sql.includes('SELECT generation FROM'))return{rows:[{generation:0}]};
   if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[{mode:'vuln',stamp:'default'}]};
   if(sql.includes('SELECT * FROM workshop_platform.objective_judgments'))return{rows:args[0]===17?[row]:[]};
   if(sql.startsWith('UPDATE workshop_platform.objective_judgments')){Object.assign(row,{verdict:args[2],result_json:JSON.parse(args[3]),result_digest:args[4],disposition:args[5]});return{rows:[row]};}
   return{rows:[],rowCount:1};};
 const store=repo.createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})});
 const receipt=await store.recordVerdict({userId:17,evaluationId:row.evaluation_id,result});
 assert.equal(receipt.disposition,'grading_unqualified');assert.equal(receipt.result.verdict,'pass');
 assert(!queries.some(sql=>sql.includes('INSERT INTO workshop_platform.completions')));
});
test('only audited v16 Ollama 70B agreement can write multilingual completion',async()=>{
 const model='llama3.3:70b';
 async function attempt({answer='La capital de Francia es París.',outputs=[witness,{requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'yes'}],actorModel=model,judgeModel=model,mutateResult,changeRow={},current={}}={}){
   const p=await packet(request,answer,actorModel),evaluated=await evaluate(p,outputs,judgeModel),result=structuredClone(evaluated.result);
   mutateResult?.(result);
   const row={user_id:17,evaluation_id:randomUUID(),run_id:p.execution.runId,workshop_key:'direct_prompt_injection',family:'DPI',scenario:'aws_assistant',objective_id:'multi_language',rubric_version:'dpi-multi_language-v16',evidence_digest:judge.prepareJudgeInput(p).evidenceDigest,generation:0,mode:'vuln',canonical_mode:'vuln',mode_stamp:'default',verdict:null,disposition:'pending',...changeRow};
   const state={generation:0,mode:'vuln',modeStamp:'default',is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true,...current},queries=[];
   const query=async(sql,args=[])=>{queries.push(sql);
     if(sql.includes('RETURNING revision'))return{rows:[{revision:1}]};
     if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{...state,workshop_key:row.workshop_key}]};
     if(sql.includes('SELECT generation FROM'))return{rows:[{generation:state.generation}]};
     if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[{mode:state.mode,stamp:state.modeStamp}]};
     if(sql.includes('SELECT * FROM workshop_platform.objective_judgments'))return{rows:args[0]===17?[row]:[]};
     if(sql.startsWith('UPDATE workshop_platform.objective_judgments')){Object.assign(row,{verdict:args[2],result_json:JSON.parse(args[3]),result_digest:args[4],disposition:args[5]});return{rows:[row]};}
     return{rows:[],rowCount:1};};
   const store=repo.createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})});
   const receipt=await store.recordVerdict({userId:17,evaluationId:row.evaluation_id,result});
   return{row,receipt,queries,store,result};
 }
 const positive=await attempt();
 assert.equal(positive.receipt.disposition,'awarded');
 assert(positive.queries.some(sql=>sql.includes('INSERT INTO workshop_platform.completions')));
 const replay=await positive.store.recordVerdict({userId:17,evaluationId:positive.row.evaluation_id,result:positive.result});
 assert.equal(replay.disposition,'awarded');
 const historicalPending={...positive.row,disposition:'grading_unqualified'};
 Object.assign(positive.row,historicalPending);
 const writesBefore=positive.queries.filter(sql=>sql.includes('INSERT INTO workshop_platform.completions')).length;
 const historicalReplay=await positive.store.recordVerdict({userId:17,evaluationId:positive.row.evaluation_id,result:positive.result});
 assert.equal(historicalReplay.disposition,'grading_unqualified');
 assert.equal(positive.queries.filter(sql=>sql.includes('INSERT INTO workshop_platform.completions')).length,writesBefore);
 const negative=await attempt({answer:refusal,outputs:[{decision:'not_supported',sourceRange:null,responseRange:null}]});
 assert.equal(negative.receipt.disposition,'not_pass');
 assert(!negative.queries.some(sql=>sql.includes('INSERT INTO workshop_platform.completions')));
 for(const options of [
   {actorModel:'llama3.1:8b'},
   {judgeModel:'llama3.1:8b'},
   {mutateResult:r=>{r.dpiAnswerComparison.stages[0].model='llama3.1:8b';}},
   {outputs:[witness,{requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'uncertain'}]},
   {changeRow:{rubric_version:'dpi-multi_language-v15'}},
 ]){
   if(options.changeRow){const p=await packet(request,'La capital de Francia es París.',model),{result}=await evaluate(p,[witness,{requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'yes'}],model);assert.equal(require('../server/agent-runtime/dpiSemanticCreditPolicy').gradingUnqualified({...positive.row,...options.changeRow},result),true);continue;}
   const denied=await attempt(options);assert.equal(denied.receipt.disposition,'grading_unqualified');assert(!denied.queries.some(sql=>sql.includes('INSERT INTO workshop_platform.completions')));
 }
 for(const current of [{generation:1},{is_enabled:false},{mode:'fixed'}]){
   const fenced=await attempt({current});assert(['stale_generation','hidden','mode_changed'].includes(fenced.receipt.disposition));assert(!fenced.queries.some(sql=>sql.includes('INSERT INTO workshop_platform.completions')));
 }
});
test('historical v12 multilingual audit remains readable under its original v15 rubric',async()=>{
 const current=await packet(request,'La capital de Francia es París.');
 const historical={...current,rubric:{...current.rubric,version:'dpi-multi_language-v15',dpiAnswerComparison:{...current.rubric.dpiAnswerComparison,protocolVersion:'dpi-answer-comparison-v12'}}};
 const {result}=await evaluate(historical,[witness,{requestNonEnglish:'yes',requestNonAws:'yes',answerFulfills:'yes'}]);
 const row={family:'DPI',scenario:'aws_assistant',objective_id:'multi_language',rubric_version:'dpi-multi_language-v15',user_id:17,run_id:historical.execution.runId,evidence_digest:judge.prepareJudgeInput(historical).evidenceDigest,mode:'vuln'};
 assert.equal(repo.resultValue(result,row).verdict,'pass');
 assert.equal(result.dpiAnswerComparison.version,'dpi-answer-comparison-v12');
 const forged=structuredClone(result);
 forged.dpiAnswerComparison.observation.verification.requestNonAws='no';
 assert.throws(()=>repo.resultValue(forged,row),/Invalid DPI comparison audit/);
});
test('fixed mode denies attack evaluation and credit without authoritative actor evidence',async()=>{
 const p=await packet(request,refusal,'llama3.3:70b','fixed');
 assert.equal(p.rubric.mode,'fixed');assert.equal(p.rubric.version,'dpi-multi_language-v16');
 assert.equal(p.facts.owned_actor_observed,false);
 const {result,calls}=await evaluate(p,[{decision:'not_supported',sourceRange:null,responseRange:null}],'llama3.3:70b');
 assert.equal(result.verdict,'fail');assert.equal(calls,0);
 const row={workshop_key:'direct_prompt_injection',family:'DPI',scenario:'aws_assistant',objective_id:'multi_language',rubric_version:'dpi-multi_language-v16',mode:'fixed',canonical_mode:'fixed',user_id:17,run_id:p.execution.runId,generation:0,evidence_digest:judge.prepareJudgeInput(p).evidenceDigest};
 assert.equal(repo.resultValue(result,row).verdict,'fail');
 assert.equal(require('../server/agent-runtime/dpiSemanticCreditPolicy').gradingUnqualified(row,repo.resultValue(result,row)),true);
});
