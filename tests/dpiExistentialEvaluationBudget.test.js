'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createDpiExistentialEvaluation}=require('../server/agent-runtime/dpiExistentialEvaluation');
function harness({limits=[1,1],maximumCalls=2,failFirst=false,alwaysFail=false,retryWhen,failCode,publicDispatch=false,publicVersion='dpi-answer-comparison-v14'}={}){
 const calls=[],invalids=[],events=[];let validations=0;
 const stages=limits.map((maximumCalls,i)=>({id:'stage_'+i,...(maximumCalls===undefined?{}:{maximumCalls}),...(retryWhen===undefined?{}:{retryWhen}),messages:()=>({messages:[],format:{}}),validate:()=>{validations++;if(alwaysFail||(failFirst&&validations===1))throw Object.assign(Error('invalid'),failCode?{code:failCode}:{});return i;},repairMessage:()=> 'repair'}));
 const comparison={policy:{version:publicDispatch?publicVersion:'controlled-budget-test',maximumCalls},stages,combine:()=>({verdict:'fail',criteria:[],observation:{}})};
 const factory=publicDispatch?require('../server/agent-runtime/dpiAnswerEvaluation').createDpiAnswerEvaluation:createDpiExistentialEvaluation;
 const evaluator=factory({comparison,invoke:async(_wire,stage,attempt)=>{calls.push({stage,attempt});return{response:'{}',provider:'controlled',model:'controlled',tokens:1};},admit:()=>{},check:async()=>{},invalid:async(stage,attempt)=>invalids.push({stage,attempt}),emit:async(node,type,data)=>events.push({node,type,data})});
 return{evaluator,calls,invalids,events};
}
test('single-call stages use exactly two calls for a complete two-stage evaluation',async()=>{const {evaluator,calls}=harness();const result=await evaluator.run();assert.equal(calls.length,2);assert.equal(result.attempts,2);assert.equal(result.verdict,'fail');});
test('invalid single-call stage stops without repair or later inference',async()=>{const {evaluator,calls}=harness({alwaysFail:true});const result=await evaluator.run();assert.equal(calls.length,1);assert.equal(result.verdict,'unavailable');assert.equal(result.errorCode,'INVALID_JUDGE_OUTPUT');assert.equal(result.attempts,1);});
test('legacy omitted stage budgets retain the two-attempt repair allowance',async()=>{const {evaluator,calls}=harness({limits:[undefined,undefined],maximumCalls:4,failFirst:true});const result=await evaluator.run();assert.equal(calls.length,3);assert.deepEqual(calls.map(call=>call.attempt),[1,2,1]);assert.equal(result.verdict,'fail');});
test('opt-in retry predicate allows only its selected validation error',async()=>{
 const allowed=harness({limits:[2],maximumCalls:2,failFirst:true,failCode:'selected',retryWhen:error=>error.code==='selected'});
 assert.equal((await allowed.evaluator.run()).verdict,'fail');assert.deepEqual(allowed.calls.map(call=>call.attempt),[1,2]);
 const denied=harness({limits:[2],maximumCalls:2,failFirst:true,failCode:'other',retryWhen:error=>error.code==='selected'});
 const unavailable=await denied.evaluator.run();assert.equal(unavailable.errorCode,'INVALID_JUDGE_OUTPUT');assert.deepEqual(denied.calls.map(call=>call.attempt),[1]);
});
test('invalid capture and event precede a failing retry predicate',async()=>{
 const value=harness({limits:[2],maximumCalls:2,failFirst:true,retryWhen:()=>{throw Error('retry gate failed');}});
 await assert.rejects(value.evaluator.run(),/retry gate failed/);assert.deepEqual(value.invalids,[{stage:'stage_0',attempt:1}]);
 assert.equal(value.events.some(row=>row.node==='judge_dpi_answer_stage_0_validate'&&row.type==='invalid'&&row.data.attempt===1),true);
 assert.deepEqual(value.calls.map(call=>call.attempt),[1]);
});
test('invalid or overallocated stage budgets fail before inference',()=>{for(const limits of [[0],[3],[1.5],[-1],[NaN],[1,2]])assert.throws(()=>harness({limits,maximumCalls:2}),/Invalid DPI stage call budget/);assert.throws(()=>harness({limits:[1],maximumCalls:1,retryWhen:true}),/Invalid DPI stage call budget/);});

test('public v14 evaluator dispatch preserves the two-call ceiling and fail-closed schema error',async()=>{
 for(const alwaysFail of [false,true]){
  const {evaluator,calls}=harness({publicDispatch:true,alwaysFail});
  const result=await evaluator.run();
  assert.equal(calls.length,alwaysFail?1:2);
  assert.equal(result.verdict,alwaysFail?'unavailable':'fail');
  assert.equal(result.dpiAnswerComparison.version,'dpi-answer-comparison-v14');
 }
});
test('public v21 evaluator dispatch preserves the selected-stage one-call ceiling',async()=>{
 const {evaluator,calls}=harness({limits:[1],maximumCalls:1,publicDispatch:true,publicVersion:'dpi-answer-comparison-v21'});
 const result=await evaluator.run();
 assert.deepEqual(calls,[{stage:'stage_0',attempt:1}]);
 assert.equal(result.attempts,1);
 assert.equal(result.verdict,'fail');
 assert.equal(result.dpiAnswerComparison.version,'dpi-answer-comparison-v21');
});
test('public v14 comparison and audit dispatch refuse missing trusted execution',()=>{
 const {createDpiAnswerComparison}=require('../server/agent-runtime/dpiAnswerComparison');
 const {normalizeDpiAnswerAudit}=require('../server/agent-runtime/dpiAnswerAudit');
 assert.throws(()=>createDpiAnswerComparison({primary:true,objective:'virtualization',protocolVersion:'dpi-answer-comparison-v14'},[]));
 assert.throws(()=>normalizeDpiAnswerAudit({version:'dpi-answer-comparison-v14',stages:[{stage:'source',attempts:1,provider:null,model:null,completed:false,responseSha256:[]}]},{verdict:'unavailable',criteria:[],attempts:1,mode:'vuln'}));
});
