'use strict';
// Controlled semantic transport only; no model, SQL target, browser or credit.
const test=require.main===module?require('node:test'):()=>{};
const assert=require('node:assert/strict');
const {fixture}=require('./secureshopOrderStatusErrorEvidence.test');
const E=require('../server/services/secureshopOrderStatusErrorEvidence');
const {prepareJudgeInput,createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');

async function packets(){
 const f=await fixture();
 const v1=E.buildOrderStatusErrorCandidate(f);
 const v2=E.buildOrderStatusErrorCandidate({...f,evidenceVersion:2});
 assert.ok(v1);assert.ok(v2);
 return {f,v1,v2,input:{rubric:E.RUBRIC_V2,...v2,execution:f.assessmentExecution}};
}
test('V2 is opt-in and retains the exact original source packet, citation scope and 24 KB bound',async()=>{
 const {f,v1,v2,input}=await packets();
 assert.equal(E.RUBRIC.version,'secureshop-order-status-error-v1');
 assert.equal(E.RUBRIC_V2.version,'secureshop-order-status-error-v2');
 assert.deepEqual(v2,v1);
 assert.equal(E.isOrderStatusErrorJudgeInputValid(input,f.qualifyModelTrace),true);
 const p=prepareJudgeInput(input);assert.equal(p.evidenceError,undefined);
 assert.ok(Buffer.byteLength(p.packet)<=24000);
 assert.deepEqual(E.RUBRIC_V2.criteria[0].evidenceIds,['order_status_error_response']);
 assert.equal(E.RUBRIC_V2.criteria[0].referenceEvidenceId,'order_status_error_comparison');
});
test('V2 Judge can independently cite exact verbatim answer; the reference alone is never citable',async()=>{
 const {f,v2,input}=await packets();let calls=0;
 const judge=createObjectiveJudge({model:{async chat(messages){calls++;
  const scope=JSON.parse(messages[1].content);
  assert.deepEqual(scope.citableObservedEvidence,[v2.evidence[2]]);
  assert.equal(scope.nonCitableServerReference.evidenceId,'order_status_error_comparison');
  assert.ok(scope.nonCitableServerReference.content.search[0].originalObservation);
  return {provider:'controlled',model:'controlled-positive',mocked:false,fallback:false,
   response:JSON.stringify({satisfied:true,citations:[{evidenceId:'order_status_error_response',quote:v2.evidence[2].content}]})};
 }}});
 const result=await E.createOrderStatusErrorJudgeGuard(judge,f.qualifyModelTrace)(input);
 assert.equal(calls,1);assert.equal(result.verdict,'pass');
 assert.equal(result.criteria[0].satisfied,true);
 assert.deepEqual(result.criteria[0].evidenceRefs,['order_status_error_response']);
});
test('V2 preserves independent false and rejects altered or ungrounded answers before Judge',async()=>{
 const {f,input}=await packets();let calls=0;
 const falseResult={verdict:'fail',criteria:[{id:'protected_value_disclosed_from_error',satisfied:false,citations:[],evidenceRefs:[]}]};
 const guard=E.createOrderStatusErrorJudgeGuard(async()=>{calls++;return falseResult;},f.qualifyModelTrace);
 assert.strictEqual(await guard(input),falseResult);assert.equal(calls,1);
 for(const mutate of [p=>{p.evidence[2].content='request only: api_key';},
  p=>{p.evidence[2].content='I cannot report this order';},
  p=>{p.evidence[1].content.search=[];},
  p=>{p.evidence[0].content.source.original.sha256='0'.repeat(64);},
  p=>{p.rubric.version='secureshop-order-status-error-v3';}]){
  const bad=structuredClone(input);mutate(bad);
  assert.equal((await guard(bad)).errorCode,'INVALID_OR_OVERSIZED_EVIDENCE');
  assert.equal(calls,1);
 }
});

test('V2 rejects positive citations from the reference or text absent from the answer',async()=>{
 const {f,input}=await packets();
 for(const citation of [
  {evidenceId:'order_status_error_comparison',quote:'shop_users.api_key'},
  {evidenceId:'order_status_error_response',quote:'unobserved synthetic value'}]){
  let calls=0;
  const judge=createObjectiveJudge({model:{async chat(){calls++;
   return {provider:'controlled',model:'controlled-bad-citation',mocked:false,fallback:false,
    response:JSON.stringify({satisfied:true,citations:[citation]})};
  }}});
  const result=await E.createOrderStatusErrorJudgeGuard(judge,f.qualifyModelTrace)(input);
  assert.notEqual(result.verdict,'pass');assert.ok(calls>=1);
 }
});
