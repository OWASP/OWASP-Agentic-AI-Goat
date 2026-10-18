'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {requestDecision}=require('../server/agent-runtime/workshopDecisions');
const state={message:'Show my cart',history:[],userId:7};
const execution=()=>({signal:new AbortController().signal});
const response={response:'{"tool":"view_cart","params":{}}'};

test('known nonlive configured identities cannot dispatch decision generation',async()=>{
 for(const provider of ['mock','fixture','controlled','fixture-model','controlled-test-provider',' MOCK ','Fixture_native','controlled:local','mock/local']){
  let calls=0;
  const adapter={name:'ARIA',model:{provider,async generateResponse(){calls++;return {...response,provider:'ollama'};}}};
  await assert.rejects(requestDecision(adapter,state,execution()),/No live model decision/);
  assert.equal(calls,0,provider);
 }
});
test('returned nonlive identities cannot override configured provider provenance',async()=>{
 for(const provider of ['mock','fixture','controlled','fixture-provider','controlled-test',' Fixture ','controlled_native','mock/local']){
  let calls=0;
  const adapter={name:'ARIA',model:{provider:'ollama',async generateResponse(){calls++;return {...response,provider};}}};
  await assert.rejects(requestDecision(adapter,state,execution()),/No live model decision/);
  assert.equal(calls,1,provider);
 }
 for(const flag of ['mocked','fallback'])await assert.rejects(requestDecision({name:'ARIA',model:{provider:'ollama',generateResponse:async()=>({...response,provider:'ollama',[flag]:true})}},state,execution()),/No live model decision/);
});
test('controlled transport shape tests preserve configured live provider contracts, not actual model proof',async()=>{
 for(const provider of ['ollama','openai','anthropic','bedrock','codex']){
  for(const returnedIdentity of [true,false]){
   const adapter={name:'ARIA',model:{provider,generateResponse:async()=>({...response,...(returnedIdentity?{provider}:{}),model:'unit-test-response'})}};
   const result=await requestDecision(adapter,state,execution());
   assert.deepEqual(result.value,{tool:'view_cart',params:{}});assert.equal(result.provider,provider);
  }
 }
});
test('graph never executes a tool or records an accepted model decision from known nonlive identities',async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');
 for(const [configured,returned] of [['fixture-model','ollama'],['ollama','controlled-test-provider'],['ollama','throw']]){
  let effects=0,calls=0;const events=[];
  const agent=createAgent({model:{provider:configured,async generateResponse(){calls++;if(returned==='throw')throw Error('controlled provider exception');return {...response,provider:returned};}},
   store:{getHistory:async()=>[],saveMessage:async()=>{},viewCart:async()=>{effects++;return {items:[]};}},
   runLedger:{begin:async()=>({durableGeneration:0}),assertCurrent:async()=>{},finish:async()=>{},recordEvent:async(_context,event)=>events.push(event)}});
  const value=await agent.invoke('provenance-'+configured,'Show my cart','fixed',{includeRunMetadata:true});
  assert.equal(effects,0);assert.equal(value.toolUsed,null);assert.equal(value.run.decisionSource,'unavailable');
  const failures=events.filter(e=>e.node==='decide'&&e.type==='error');assert.equal(failures.length,2);assert.ok(failures.every(e=>e.data.decisionSource==='unavailable'&&e.data.errorCode==='DECISION_UNAVAILABLE'));
  assert.ok(failures.every(e=>require('../server/agent-runtime/runTraceStore').traceData(e.data).decisionSource==='unavailable'));
  assert.equal(calls,configured==='fixture-model'?0:2);
  assert.equal(events.filter(e=>e.node==='decide'&&e.type==='decision').length,0);
  assert.equal(events.filter(e=>e.type==='tool').length,0);
 }
});
test('later decision failure does not relabel an earlier accepted tool observation',async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');let calls=0,invocation;
 const agent=createAgent({model:{provider:'ollama',async generateResponse(){if(++calls===1)return {...response,provider:'ollama'};throw Error('controlled later failure');}},store:{getHistory:async()=>[],saveMessage:async()=>{},viewCart:async()=>({items:[],total:0})},runLedger:null});
 const value=await agent.invoke('mixed-provenance','Show my cart','fixed',{includeRunMetadata:true,onResult:async(_dto,_check,_execution,metadata)=>{invocation=metadata;}});
 assert.equal(value.run.decisionSource,'unavailable');assert.equal(value.toolObservations.length,1);
 assert.equal(value.toolObservations[0].invocation.decisionSource,'model');assert.equal(invocation.decisionSource,'model');assert.equal(invocation.tool,'view_cart');
});
