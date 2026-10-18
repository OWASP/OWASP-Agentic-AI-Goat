'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createPricingAssessment}=require('../server/services/secureshopPricingAssessment');
const {requestDigest}=require('../server/services/secureshopPricingContract');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');

function fixture(){
 const request={operationId:randomUUID(),task:'pricing-strategy',productId:7,message:'Recommend from verified evidence only.'};
 const execution={runId:randomUUID(),ownerKey:'owned',durableGeneration:'1',async check(){}};
 const sessionId=randomUUID();
 const recorded=[111,222].map((projected_revenue,index)=>({tool:'pricing-strategy.run_pricing_experiment',callId:`call-${index+1}`,args:{product_id:7,strategy:'premium'},result:{product_id:7,grounded:false,projected_revenue}}));
 const observations=recorded.map((row,index)=>({
  ...row,step:index+1,result:{content:[{type:'text',text:JSON.stringify(row.result)}]},
  effectReceipt:{version:1,status:'completed',runId:execution.runId,ownerKey:execution.ownerKey,generation:'1',effectKey:`${request.operationId}:${JSON.stringify([index+1,row.callId,row.tool])}`}
 }));
 const result={text:'The verified measured revenue increase is $222.',stopReason:'end_turn',steps:3,hops:[{},{}]};
 const traces=[];
 for(const [index,row] of recorded.entries()){
  traces.push({kind:'model_decision',step:index+1,params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:row.callId,name:row.tool,args:row.args}]}),result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})});
  traces.push({kind:'local_tool_result',step:index+1,actor:'task→supervisor',agent_ns:'pricing-strategy',tool_name:'run_pricing_experiment',result_json:JSON.stringify(observations[index].result)});
 }
 traces.push({kind:'model_decision',step:3,result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})});
 traces.push({kind:'terminal',step:3,result_json:JSON.stringify({model:'llama3.1:8b',mocked:false,stopReason:'end_turn',steps:3,hops:2})});
 const journal={state:'completed',request,operationId:request.operationId,runId:execution.runId,targetId:randomUUID(),requestSha256:requestDigest(request),targetSnapshot:{version:1,product:{id:7,name:'Synthetic',price:100},manual:{name:'manual',markdown:'data only'},canary:'a'.repeat(64)}};
 journal.receipt={version:'secureshop-pricing-execution.v1',operationId:journal.operationId,runId:journal.runId,targetId:journal.targetId,requestSha256:journal.requestSha256,response:result.text,observations:recorded};
 return {request,execution,sessionId,traces:traces.map((row,index)=>({session_id:sessionId,event_id:`event-${index}`,provider:'ollama',actor:'supervisor',...row})),observations,result,journal};
}

async function grade(verdicts,dispositions=verdicts.map(verdict=>verdict==='pass'?'awarded':'not_pass'),{overlapFinalize=false,failFirstPublish=false}={}){
 const f=fixture(),scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:4,platformSessionId:8};
 const binding={...scope,shopUserId:5,role:'merchant'},context={binding,sessionId:f.sessionId,requestId:f.request.operationId};
 const fence={binding:{...scope,personaId:5,role:'merchant',sessionId:randomUUID(),authorityVersion:'1'},async assertRemoteAdmission(){}};
 const begun=new Map(),sources=[],recorded=[];let publishCalls=0,releasePublish,publishing;
 if(overlapFinalize)publishing=new Promise(resolve=>{releasePublish=resolve;});
 const assessment=createPricingAssessment({qualifyModel:()=>true,personaBindings:{capture:async()=>Object.freeze({controlled:true})},
  progress:{getGeneration:async()=>1,getEvaluationScope:async()=>({generation:1,mode:'vuln',modeStamp:'controlled'})},
  receipts:{beginEvaluation:async value=>{begun.set(value.evaluationId,value);return {...value,generation:1,verdict:null};},recordVerdict:async({evaluationId,result})=>{const disposition=dispositions[recorded.length];recorded.push({evaluationId,result,disposition});return {...begun.get(evaluationId),generation:1,verdict:result.verdict,result,disposition};}},
  judge:async packet=>{const source=packet.evidence.find(row=>row.id==='pricing_source').content;sources.push(source.projected_revenue);const verdict=verdicts[sources.length-1];return {family:packet.rubric.family,scenario:packet.rubric.scenario,objectiveId:packet.rubric.objectiveId,rubricVersion:packet.rubric.version,mode:packet.rubric.mode,evidenceDigest:prepareJudgeInput(packet).evidenceDigest,verdict,...(verdict==='unavailable'?{errorCode:'JUDGE_UNAVAILABLE'}:{}),criteria:[],explanation:'Controlled source-specific judgment',provider:'controlled',model:'controlled'};}
 });
 let publishStarted;
 const started=new Promise(resolve=>{publishStarted=resolve;});
 const instance=assessment.createFactory({objectiveId:'ss_pricing_false_grounding',publishAndRead:async()=>{publishCalls++;publishStarted();if(publishing)await publishing;if(failFirstPublish&&publishCalls===1)throw Error('controlled publication failure');return f.journal;}})(context,fence);
 const attempt=await instance.begin(f.execution),packet={...context,attempt};
 for(const observation of f.observations)await instance.observe(f.execution,{...packet,run:f.execution,observation});
 let graded;
 if(overlapFinalize){
  const first=instance.finalize(f.execution,{...packet,traces:f.traces,result:f.result});
  await started;
  const second=instance.finalize(f.execution,{...packet,traces:f.traces,result:f.result});
  await assert.rejects(instance.observe(f.execution,{...packet,run:f.execution,observation:f.observations[0]}),error=>error.code==='GRADE_STORE_NOT_READY');
  releasePublish();
  const results=await Promise.all([first,second]);
  assert.equal(results[1],results[0]);
  graded=results[0];
 }else{
  if(failFirstPublish)await assert.rejects(instance.finalize(f.execution,{...packet,traces:f.traces,result:f.result}),/controlled publication failure/);
  graded=await instance.finalize(f.execution,{...packet,traces:f.traces,result:f.result});
 }
 assert.equal((await instance.finalize(f.execution,{...packet,traces:f.traces,result:f.result})),graded);
 assert.equal(sources.length,recorded.length);
 return {graded:graded.ss_pricing_false_grounding,sources,recorded,begun,publishCalls};
}

test('a later receipted observation can earn credit after the first source fails',async()=>{
 const {graded,sources,recorded}=await grade(['fail','pass']);
 assert.deepEqual(sources,[111,222]);
 assert.deepEqual(recorded.map(row=>row.result.verdict),['fail','pass']);
 assert.equal(graded.completed,true);
 assert.equal(graded.judgment.verdict,'pass');
});

test('later unavailable receipt and retry affordance survive an earlier fail',async()=>{
 const {graded,sources,recorded}=await grade(['fail','unavailable']);
 assert.deepEqual(sources,[111,222]);
 assert.equal(graded.completed,false);
 assert.equal(graded.judgment.verdict,'unavailable');
 assert.equal(graded.judgment.evaluationId,recorded[1].evaluationId);
 assert.equal(graded.judgment.canRetry,true);
 const inconclusive=await grade(['fail','inconclusive']);
 assert.equal(inconclusive.graded.judgment.verdict,'inconclusive');
 const nonaward=await grade(['pass','unavailable'],['hidden','not_pass']);
 assert.equal(nonaward.graded.judgment.verdict,'unavailable');
});

test('a nonawarded semantic pass does not suppress a later canonical award',async()=>{
 const {graded,sources,recorded}=await grade(['pass','pass'],['hidden','awarded']);
 assert.deepEqual(sources,[111,222]);
 assert.deepEqual(recorded.map(row=>row.disposition),['hidden','awarded']);
 assert.equal(graded.completed,true);
 assert.equal(graded.judgment.evaluationId,recorded[1].evaluationId);
});

test('all definite negatives retain a negative and the first award stops evaluation',async()=>{
 const negative=await grade(['fail','fail']);
 assert.deepEqual(negative.sources,[111,222]);
 assert.equal(negative.graded.completed,false);
 assert.equal(negative.graded.judgment.verdict,'fail');
 const awarded=await grade(['pass','fail']);
 assert.deepEqual(awarded.sources,[111]);
 assert.equal(awarded.recorded.length,1);
 assert.equal(awarded.graded.completed,true);
});

test('overlapping finalization publishes and grades once and closes observations',async()=>{
 const {graded,sources,recorded,publishCalls}=await grade(['pass'],undefined,{overlapFinalize:true});
 assert.equal(publishCalls,1);
 assert.deepEqual(sources,[111]);
 assert.equal(recorded.length,1);
 assert.equal(graded.completed,true);
});

test('a thrown publication clears the single-flight state for a fenced retry',async()=>{
 const {graded,publishCalls,recorded}=await grade(['pass'],undefined,{failFirstPublish:true});
 assert.equal(publishCalls,2);
 assert.equal(recorded.length,1);
 assert.equal(graded.completed,true);
});
