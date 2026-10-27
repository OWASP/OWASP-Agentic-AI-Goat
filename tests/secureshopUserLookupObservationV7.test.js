'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const V7=require('./fixtures/secureshopUserLookupObservationV7');
const E=require('../server/services/secureshopUserLookupEvidence');
const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
async function evaluate(plan,control,make){
 const receipts=[];let criterion=-1;
 const judge=createObjectiveJudge({model:{async chat(messages,tools,options){
  const raw=JSON.stringify(make(messages,criterion));
  const receipt=V7.project(plan,control,criterion,raw,options.format);receipts.push(receipt);
  return {provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false,response:V7.projectedReply(receipt),metadata:{eval_count:30}};
 }}});
 const result=await judge({...V7.modelInput(plan,control).original,execution:{emit(event){
  if(event.node==='judge_scoped_model'&&event.type==='start')criterion=E.RUBRIC.criteria.findIndex(c=>c.id===event.data.criterionId);
 }}});return {result,receipts};
}
const explanation={observation:'The supplied original response has been examined without treating the reference as a reply.',attribution:'uncertain'};
test('genuine pair is admitted without polarity, presence flags, or auxiliary spans in model input',()=>{
 const p=V7.prepare();assert.equal(p.provenance.holdoutUsed,false);
 for(let i=0;i<2;i++){const input=V7.modelInput(p,i);assert(E.isUserLookupJudgeInputValid(input.original));
  assert.deepEqual(Object.keys(input),['original','instructionAddition']);
  assert.equal(input.original.rubric.criteria.length,4);assert(!Object.hasOwn(input,'provenance'));
  assert(!Object.hasOwn(input,'auxiliary'));assert(!Object.hasOwn(input,'expectedVerdict'));
 }
 assert.throws(()=>V7.modelInput(structuredClone(p),0));assert.throws(()=>V7.modelInput(p,2));
});
test('observation never changes a false boolean; production validator accepts original false shape',async()=>{
 const p=V7.prepare(),{result,receipts}=await evaluate(p,0,()=>({...explanation,satisfied:false,citations:[]}));
 assert.equal(result.verdict,'fail');assert.equal(receipts.length,4);
 for(const r of receipts){assert.equal(JSON.parse(r.projectedText).satisfied,false);assert.equal(r.productionValidationRequired,true);
  assert.equal(r.creditAuthorized,false);assert.notEqual(r.rawSha256,r.projectedSha256);
  assert.throws(()=>V7.projectedReply(structuredClone(r)));}
});
test('exact original response citations remain valid through unchanged canonical validator',async()=>{
 const p=V7.prepare();const answer=V7.modelInput(p,0).original.evidence[2].content;
 const {result}=await evaluate(p,0,()=>({...explanation,attribution:'both',satisfied:true,
  citations:[{evidenceId:'user_lookup_response',quote:answer}]}));
 assert.equal(result.verdict,'pass');assert.equal(result.criteria.length,4);
});
test('fabricated citation is not rescued by plausible observation or true boolean',async()=>{
 const p=V7.prepare();const {result,receipts}=await evaluate(p,1,()=>({...explanation,attribution:'both',satisfied:true,
  citations:[{evidenceId:'user_lookup_response',quote:'An invented passage that is absent from the original response.'}]}));
 assert.equal(result.verdict,'unavailable');assert.equal(receipts.length,2);
});
test('source-only citations, malformed explanation and unknown fields fail closed',async()=>{
 const p=V7.prepare();for(const reply of [
  {...explanation,satisfied:true,citations:[{evidenceId:'user_lookup_source',quote:'source only'}]},
  {...explanation,observation:'tiny',satisfied:false,citations:[]},
  {...explanation,attribution:'positive',satisfied:false,citations:[]},
  {...explanation,satisfied:false,citations:[],expectedVerdict:'fail'},
 ]){const {result}=await evaluate(p,0,()=>reply);assert.equal(result.verdict,'unavailable');}
 assert.throws(()=>V7.format(p,{}),/unchanged canonical/);
 assert.equal(V7.PROTOCOL.maximumPhysicalCalls,16);assert.equal(V7.PROTOCOL.evaluationTimeoutMs,90000);
});
