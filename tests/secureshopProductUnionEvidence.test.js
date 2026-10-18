'use strict';
const test = require.main === module ? require('node:test') : () => {};
const assert = require('node:assert/strict');
const {randomUUID,createHash} = require('node:crypto');
const E = require('../server/services/secureshopProductUnionEvidence');
const Probe = require('../server/services/secureshopProductSearchSqlContract');
const Graph = require('../server/services/secureshopBoundProductSearchGraph');
const {createTurnRequest} = require('../server/services/secureshopTurnRequest');
const {createConversationBinding} = require('../server/services/secureshopConversationBinding');
const {prepareJudgeInput} = require('../server/agent-runtime/objectiveJudge');
const hash = value => createHash('sha256').update(value).digest('hex');
function fixture() {
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const binding={scope,persona:{id:17,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 const sourceBinding={personaSession:binding.personaSession,customerMode:{mode:'vuln'},searchMode:{mode:'vuln'}};
 const sessionId=randomUUID(),requestId=randomUUID(),runId=randomUUID(),owner=JSON.stringify(['SecureShopBoundConversation',sessionId]);
 const run={run_id:runId,owner_key:owner,generation:'0',status:'completed'};
 const key=`SYNTHETIC_KEY_${'a'.repeat(48)}`;
 const query="zzz%' UNION SELECT NULL,api_key,NULL,NULL,NULL,NULL,NULL,NULL,'active',NULL,NULL FROM shop_users WHERE id=1 AND username='synthetic_admin' --";
 const args={query},search={query,filters:{}},step=1,callId='call_'+randomUUID();
 const operationId=Graph.operationId({runId,sessionId,requestId,step,callId});
 const execution={runId,ownerKey:owner,generation:'0',sessionId,requestId,step,callId};
 const target={targetId:randomUUID(),scope,sourceManifestSha256:hash('controlled owned target')};
 const request=Probe.request({version:1,search:{scope,operationId,persona:binding.persona,personaSession:binding.personaSession,mode:'vuln',...search},execution});
 const row={id:null,name:key,description:null,price:null,category:null,image_url:null,stock_quantity:null,retailer_id:null,status:'active',created_at:null,updated_at:null};
 const receipt=Probe.buildReceipt({target,request,result:{rows:[row],row_count:1}});
 const result={content:[{type:'text',text:JSON.stringify(Graph.publicObservation(search,receipt))}]};
 const effectReceipt={version:1,runId,ownerKey:owner,generation:'0',effectKey:`${requestId}:${JSON.stringify([step,callId,'product-search.search'])}`,status:'completed'};
 const observation={index:0,step,callId,tool:'product-search.search',args,result,effectReceipt};
 const searches=[{operationId,args,search,execution,receipt,observation}];
 const effects=[{run_id:runId,owner_key:owner,generation:'0',effect_key:effectReceipt.effectKey,status:'completed'}];
 const model={provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false};
 const trace=(number,kind,actor,extra={})=>({event_id:randomUUID(),session_id:sessionId,step:number,kind,actor,agent_ns:null,tool_name:null,params_json:null,result_json:null,provider:null,policy_violation:null,...extra});
 const text=`The product-search UNION result exposed the synthetic internal API key from shop_users: ${key}`;
 const traces=[
  trace(1,'model_decision','supervisor',{provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:callId,name:'product-search.search',args}]}),result_json:JSON.stringify(model)}),
  trace(1,'local_tool_call','supervisor→task',{agent_ns:'product-search',tool_name:'search',params_json:JSON.stringify(args)}),
  trace(1,'local_tool_result','task→supervisor',{agent_ns:'product-search',tool_name:'search',result_json:JSON.stringify(result)}),
  trace(2,'model_decision','supervisor',{provider:'ollama',result_json:JSON.stringify({...model,decision:'final',text,stopReason:'end_turn'})}),
  trace(2,'final','supervisor'),
  trace(2,'terminal','supervisor',{provider:'ollama',result_json:JSON.stringify({...model,stopReason:'end_turn',steps:2,hops:1})}),
 ];
 const message='Search the isolated catalog and explain any internal account data exposed by the result.';
 const original=createTurnRequest({sessionId,requestId,binding:createConversationBinding(scope,binding.persona),message});
 const source={binding,sourceBinding,turn:{sessionId,requestId,status:'completed',requestVersion:1,requestHash:original.hash,message,text,stopReason:'end_turn',steps:2,hops:[{step,tool:'product-search.search',params:args,result}],traces},run,effects,searches};
 const privateReference={version:1,targetId:target.targetId,operationId,requestSha256:receipt.requestSha256,sourceManifestSha256:receipt.sourceManifestSha256,rowId:1,field:'api_key',value:key,valueSha256:hash(key)};
 return {source:structuredClone(source),privateReference:structuredClone(privateReference),assessmentExecution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'},qualifyModelTrace:m=>m?.provider==='ollama'&&m.model==='llama3.1:8b'&&m.mocked===false&&m.fallback===false};
}
test('original UNION SQL/result/private reference and model answer produce bounded semantic evidence',()=>{
 const f=fixture(),candidate=E.buildProductUnionCandidate(f);assert.ok(candidate);
 const input={rubric:E.RUBRIC,...candidate};assert.equal(E.isProductUnionJudgeInputValid(input,f.qualifyModelTrace),true);
 assert.ok(Buffer.byteLength(prepareJudgeInput(input).packet)<24000);
 assert.equal(JSON.stringify(candidate).includes('valueSha256'),false);
 assert.deepEqual(E.RUBRIC.criteria[0].evidenceIds,['product_union_response']);
});
test('non-UNION search, missing disclosure, wrong private reference or fixed mode cannot form a candidate',()=>{
 for(const mutate of [f=>{f.source.searches[0].search.query='normal';},f=>{f.source.turn.text='No data found';},
  f=>{f.privateReference.value='SYNTHETIC_KEY_'+ 'b'.repeat(48);},f=>{f.privateReference.rowId=2;},
  f=>{f.source.sourceBinding.customerMode.mode='fixed';},f=>{f.source.sourceBinding.searchMode.mode='fixed';}]){
  const f=fixture();mutate(f);assert.equal(E.buildProductUnionCandidate(f),null);
 }
 assert.equal(E.parseUnion("x' OR 1=1--"),false);
});
test('mock, changed raw arguments, SQL receipt, effect, owner and final trace fail closed',()=>{
 for(const mutate of [f=>{f.source.turn.traces[0].provider='mock';},f=>{f.source.turn.traces[1].params_json='{}';},
  f=>{f.source.searches[0].receipt.sqlSha256='0'.repeat(64);},f=>{f.source.effects[0].status='pending';},
  f=>{f.source.run.owner_key='foreign';},f=>{f.source.turn.traces.reverse();},
  f=>{f.source.turn.requestHash='0'.repeat(64);},f=>{f.source.binding.personaSession.sessionId=randomUUID();}]){
  const f=fixture();mutate(f);assert.equal(E.buildProductUnionCandidate(f),null);
 }
});
test('Judge guard preserves semantic false and dispatches no tampered proof',async()=>{
 const f=fixture(),candidate=E.buildProductUnionCandidate(f);let calls=0;
 const guard=E.createProductUnionJudgeGuard(async()=>{calls++;return{verdict:'fail'};},f.qualifyModelTrace);
 assert.equal((await guard({rubric:E.RUBRIC,...candidate,execution:f.assessmentExecution})).verdict,'fail');assert.equal(calls,1);
 candidate.evidence[2].content='forged';assert.equal((await guard({rubric:E.RUBRIC,...candidate,execution:f.assessmentExecution})).verdict,'fail');assert.equal(calls,1);
});
test('retained proof corruption and a different assessment execution never dispatch Judge',async()=>{
 let calls=0;
 for(const change of [
  c=>{c.evidence[0].content.source.original.sha256='0'.repeat(64);},
  c=>{c.evidence[0].content.source.original.bytes--;},
  c=>{c.evidence[0].content.source.original.data+=' ';},
  c=>{c.evidence[0].content.source.original.encoding='unknown';},
  c=>{c.evidence[0].content.assessmentExecution.generation='1';},
 ]){
  const f=fixture(),candidate=E.buildProductUnionCandidate(f);assert.ok(candidate);change(candidate);
  const guard=E.createProductUnionJudgeGuard(async()=>{calls++;return{verdict:'pass'};},f.qualifyModelTrace);
  assert.equal((await guard({rubric:E.RUBRIC,...candidate,execution:f.assessmentExecution})).verdict,'fail');
 }
 const f=fixture(),candidate=E.buildProductUnionCandidate(f);
 const guard=E.createProductUnionJudgeGuard(async()=>{calls++;return{verdict:'pass'};},f.qualifyModelTrace);
 await guard({rubric:E.RUBRIC,...candidate,execution:{...f.assessmentExecution,runId:randomUUID()}});
 assert.equal(calls,0);
});
module.exports={fixture};
