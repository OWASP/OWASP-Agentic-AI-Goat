'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const calibration=require('./fixtures/secureshopPersonaCrossV2JudgeCalibration');
const {createSecureShopPersonaInboxRubric,prepareSecureShopPersonaInboxCrossCandidate,
  CROSS_AUTHORITY_FACT}=require('../server/services/secureshopPersonaInboxAssessment');
const {createObjectiveCompletionService}=require('../server/services/objectiveCompletionService');
const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
function response(item,overrides={}){return{response:JSON.stringify({verdict:'pass',
  explanation:'The authenticated completed effect disclosed another persona private message.',criteria:[{
    id:'cross_persona_resource_effect',satisfied:true,evidenceRefs:['disclosed_private_message'],
    citations:[{evidenceId:'disclosed_private_message',quote:item.body}]}]}),provider:'controlled',model:'controlled',
  mocked:false,fallback:false,metadata:{eval_count:12},...overrides};}
test('v2 calibration uses exact production rubric and admits only three authenticated packets',async()=>{
 const rubric=createSecureShopPersonaInboxRubric('cross','vuln');assert.equal(rubric.version,'secureshop-persona-inbox-v2');
 assert.equal(rubric.criterionScoped,undefined);assert.equal(rubric.criteria[0].factId,CROSS_AUTHORITY_FACT);
 assert.equal(rubric.criteria[0].quoteRequired,true);assert.deepEqual(rubric.criteria[0].allowedSources,['tool_result']);
 const positives=await calibration.positives();assert.equal(positives.length,3);for(const item of positives){
  assert.equal(item.input.evidence.find(row=>row.id==='persona_inbox_chain').content.effectReceipt.generation,'0');
  assert.equal(prepareSecureShopPersonaInboxCrossCandidate(item.input).facts[CROSS_AUTHORITY_FACT],true);
 }
});
test('invalid packet controls are rejected locally without a provider call',async()=>{
 for(const item of await calibration.invalidControls()){
  assert.equal(prepareSecureShopPersonaInboxCrossCandidate(item.input).facts[CROSS_AUTHORITY_FACT],false);
 }
});
test('three repeated authentic bodies require one generic Judge call and grounded citation each',async()=>{
 const rows=[],attempts=[];const output=await calibration.runCalibration({classify:async({item})=>response(item),
  recordAttempt:async row=>attempts.push(row),recordResult:async row=>rows.push(row)});
 assert.equal(output.calls,calibration.EXPECTED_PROVIDER_CALLS);assert.equal(output.qualified,true);
 assert.equal(rows.length,9);assert.ok(rows.every(row=>row.attempts.length===1&&row.judgment.verdict==='pass'));
 assert.equal(attempts.length,9);assert.ok(rows.every(row=>row.packetSha256&&row.policySha256&&row.resultSha256
  &&row.persistedResult.verdict==='pass'));
 assert.deepEqual(new Set(rows.map(row=>row.bodySha256)).size,3);
});
test('canonical completion persists the generic Judge body citation before awarding credit',async()=>{
 const rubric=createSecureShopPersonaInboxRubric('cross','vuln');let recorded;
 const positive=(await calibration.positives())[0];
 const candidate=prepareSecureShopPersonaInboxCrossCandidate(positive.input);
 const judge=createObjectiveJudge({model:{async chat(){return response(positive);}},timeoutMs:1000});
 const execution={runId:'77000000-0000-4000-8000-000000000001',ownerKey:'owner',durableGeneration:1,
  async check(){},signal:new AbortController().signal};
 const service=createObjectiveCompletionService({judge,captureInstanceScope:()=>({
  launchId:'11000000-0000-4000-8000-000000000001',scenarioId:'22000000-0000-4000-8000-000000000001',
  generation:1,platformOwnerId:41,platformSessionId:51}),
  progress:{async getGeneration(){return 1;},async getEvaluationScope(){return{generation:1,mode:'vuln',modeStamp:'stamp'};}},
  receipts:{async beginEvaluation(scope){return{...scope,verdict:null,generation:1};},
   async recordVerdict({result}){recorded=result;return{result,verdict:result.verdict,
    disposition:result.verdict==='pass'?'awarded':'not_pass',generation:1};}}});
 const attempt=await service.beginAttempt({userId:41,workshopKey:'secureshop_agent_security',
  objectiveId:'ss_cross_persona_effect',execution});
 const outcome=await service.evaluate({userId:41,workshopKey:'secureshop_agent_security',rubric,
  ...candidate,execution,attempt});
 assert.equal(outcome.completed,true);assert.equal(recorded.verdict,'pass');
 assert.deepEqual(recorded.criteria[0].citations,[{evidenceId:'disclosed_private_message',
  quote:calibration.BODIES[0]}]);
});
test('generic Judge nonpass, unavailable, mock, and false authority remain nonqualifying',async()=>{
 const nonpass=await calibration.runCalibration({classify:async({item})=>response(item,{response:JSON.stringify({
  verdict:'inconclusive',explanation:'The model did not establish a final judgment.',criteria:[{
   id:'cross_persona_resource_effect',satisfied:true,evidenceRefs:['disclosed_private_message'],
   citations:[{evidenceId:'disclosed_private_message',quote:item.body}]}]})}),assertExpected:false});
 assert.equal(nonpass.qualified,false);assert.ok(nonpass.results.filter(row=>row.kind==='semantic')
  .every(row=>row.judgment.verdict==='inconclusive'));
 const unavailable=await calibration.runCalibration({classify:async()=>({response:'{',provider:'controlled',model:'controlled',mocked:false,fallback:false}),assertExpected:false});
 assert.equal(unavailable.qualified,false);assert.ok(unavailable.results.filter(row=>row.kind==='semantic').every(row=>row.judgment.verdict==='unavailable'));
 const mocked=await calibration.runCalibration({classify:async({item})=>response(item,{provider:'mock',mocked:true}),assertExpected:false});
 assert.equal(mocked.qualified,false);assert.ok(mocked.results.filter(row=>row.kind==='semantic')
  .every(row=>row.judgment.verdict==='unavailable'));
 const falseCandidate=prepareSecureShopPersonaInboxCrossCandidate((await calibration.invalidControls())[0].input);
 assert.equal(falseCandidate.facts[CROSS_AUTHORITY_FACT],false);
});

test('branded production candidates reject nested mutation before any Judge call',async()=>{
 const mutations=[
  value=>{value.evidence[0]={...value.evidence[0],content:`${value.evidence[0].content} altered`};},
  value=>{value.evidence[0]={...value.evidence[0],source:'student_input'};},
  value=>{value.evidence[1]={...value.evidence[1],content:{...value.evidence[1].content,
   modelCall:{...value.evidence[1].content.modelCall,args:{message_id:value.evidence[1].content.messageId+1}}}};},
  value=>{value.evidence[1]={...value.evidence[1],content:{...value.evidence[1].content,effectReceipt:{
   ...value.evidence[1].content.effectReceipt,status:'failed'}}};},
 ];
 for(const mutate of mutations){const branded=(await calibration.positives())[0].input;mutate(branded);
  const prepared=prepareSecureShopPersonaInboxCrossCandidate(branded);
  assert.equal(prepared.facts[CROSS_AUTHORITY_FACT],false);
  let calls=0;if(prepared.facts[CROSS_AUTHORITY_FACT])calls+=1;
  assert.equal(calls,0);}
});

test('diagnostic retains malformed semantic outcomes and rejects schema repairs after all cases',async()=>{
 let attempts=0;const results=[];const malformedThenValid=await calibration.runCalibration({
  classify:async({item,attempt})=>{attempts+=1;return attempt===1
   ?{response:'{',provider:'controlled',model:'controlled',mocked:false,fallback:false}:response(item);},
  recordResult:async row=>results.push(row),assertExpected:false});
 assert.equal(attempts,calibration.MAX_PROVIDER_CALLS);assert.equal(results.length,9);
 assert.equal(malformedThenValid.qualified,false);assert.ok(results.every(row=>row.attempts.length===2));
});

test('diagnostic records an incorrect result then completes the remaining semantic matrix',async()=>{
 const rows=[];const output=await calibration.runCalibration({classify:async({item,trial})=>trial===1&&item.id==='merchant_reads_customer'
  ?response(item,{response:JSON.stringify({verdict:'fail',explanation:'Controlled semantic false negative for retained diagnostic coverage.',criteria:[{
   id:calibration.CRITERION_ID,satisfied:false,evidenceRefs:[],citations:[]}]})}):response(item),
 recordResult:async row=>rows.push(row),assertExpected:false});
 assert.equal(rows.length,9);assert.equal(output.calls,10);assert.equal(output.semanticMismatches.length,1);
 assert.equal(rows[0].attempts.length,2);assert.equal(rows[0].judgment.verdict,'unavailable');
 assert.ok(rows.slice(1).every(row=>row.judgment.verdict==='pass'));
 assert.equal(output.qualified,false);
});

test('attempt evidence is bounded, tri-state, and fatal retention failures stop the batch',async()=>{
 const seen=[];await assert.rejects(calibration.runCalibration({classify:async({item})=>response(item,{mocked:undefined}),
  qualification:true,recordAttempt:async row=>seen.push(row)}),/mismatches/);
 assert.equal(seen.length,9);assert.equal(seen[0].mocked,null);
 let calls=0;await assert.rejects(calibration.runCalibration({classify:async()=>{calls+=1;return{response:'x'.repeat(
  calibration.MAX_RAW_RESPONSE_BYTES+1),provider:'controlled',model:'controlled',mocked:false,fallback:false};},
  recordAttempt:async row=>seen.push(row)}),error=>error.code==='CALIBRATION_RESPONSE_TOO_LARGE');
 assert.equal(calls,1);assert.equal(seen.at(-1).responseRetained,false);
 calls=0;await assert.rejects(calibration.runCalibration({classify:async({item})=>{calls+=1;return response(item);},
  recordAttempt:async()=>{throw Object.assign(new Error('retention failed'),{code:'RETENTION_FAILED'});}}),/retention failed/);
 assert.equal(calls,1);
 calls=0;const transport=[];await assert.rejects(calibration.runCalibration({classify:async()=>{calls+=1;
  throw Object.assign(new Error('transport failed'),{code:'TRANSPORT_FAILED'});},
  recordAttempt:async row=>transport.push(row)}),error=>error.code==='TRANSPORT_FAILED');
 assert.equal(calls,1);assert.equal(transport.length,1);assert.equal(transport[0].transportErrorCode,'TRANSPORT_FAILED');
});
