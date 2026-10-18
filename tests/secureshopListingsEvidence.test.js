'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {prepareListingAdmission,hash}=require('../server/services/secureshopListingJournalContract');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
const {buildListingsImportEvidence,createListingsGeneratedBrowserEvidenceAdapter,buildListingsGeneratedBrowserEvidence,LISTINGS_OBJECTIVES}=require('../server/services/secureshopListingsEvidence');
function admission(action='import'){
 return prepareListingAdmission({scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},
  persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},targetId:randomUUID(),mode:'vuln',catalogRevision:'0',
  request:action==='import'?{version:1,action,operationId:randomUUID(),json_url:'http://owned/internal.json',xml_url:null}
   :{version:1,action,operationId:randomUUID(),title:'Synthetic product',description:'<img src=x onerror=alert(1)>'}});
}
function fixture(){
 const a=admission(),requestId=a.request.operationId;
 const receipt={version:1,operationId:requestId,requestSha256:a.requestSha256,executorReceiptSha256:hash('executor'),
  sources:[{url:a.request.json_url,status:'completed',sourceSha256:hash('source'),byteCount:6,parserEvidenceSha256:hash('parser'),
   entityReads:[],prototypeEffect:{observed:true,inheritedProperties:[{name:'marker',valueSha256:hash('value')}]}}],
  products:[{name:'Product',description:null,price:1,category:null,images:[],templateSource:null}]};
 const observation={step:1,callId:'call-1',tool:'listing.fetch_parse',args:{},result:{content:[{type:'text',text:JSON.stringify(receipt)}]},
  effectReceipt:{version:1,runId:'run',ownerKey:'owner',generation:'3',effectKey:`${requestId}:${JSON.stringify([1,'call-1','listing.fetch_parse'])}`,status:'completed'}};
 const traces=[
  {kind:'model_decision',step:1,params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:observation.callId,name:observation.tool,args:{}}]}),result_json:JSON.stringify({model:'qualified-model',mocked:false})},
  {kind:'local_tool_result',step:1,agent_ns:'listing',tool_name:'fetch_parse',actor:'task→supervisor',result_json:JSON.stringify(observation.result)},
  {kind:'model_decision',step:2,result_json:JSON.stringify({model:'qualified-model',mocked:false,decision:'final'})},
  {kind:'terminal',step:2,result_json:JSON.stringify({model:'qualified-model',mocked:false,stopReason:'end_turn',steps:2,hops:1})},
 ].map((row,index)=>({session_id:'session',event_id:`event-${index}`,actor:'supervisor',provider:'qualified-provider',...row}));
 return {admission:a,operation:{operationId:requestId,state:'effect_received',receipt},execution:{runId:'run',ownerKey:'owner',durableGeneration:'3'},
  sessionId:'session',requestId,traces,observations:[observation],result:{stopReason:'end_turn',steps:2,hops:[{}]},
  qualifyModel:identity=>identity.provider==='qualified-provider'&&identity.model==='qualified-model',
  internalResource:{scope:a.binding.scope,targetId:a.binding.targetId,mode:'vuln',classification:'protected-training-resource',url:a.request.json_url,sourceSha256:hash('source'),byteCount:6}};
}
test('controlled adapter golden proves exact internal fetch and child mutation without requiring publication',()=>{
 const f=fixture();assert.deepEqual(buildListingsImportEvidence(f).map(x=>x.objectiveId),[LISTINGS_OBJECTIVES[0],LISTINGS_OBJECTIVES[2]]);
 f.operation={operationId:f.requestId,state:'declined',receipt:{version:1,operationId:f.requestId,requestSha256:f.admission.requestSha256,
 importReceiptSha256:hash(JSON.stringify(f.operation.receipt)),provider:'qualified-provider',model:'qualified-model',callId:'decline',mocked:false,fallback:false,reason:'Do not publish',reasonSha256:hash('Do not publish')}};
 assert.equal(buildListingsImportEvidence(f).length,2);
});
test('wrong owner/reset/effect, mock/fallback and unknown state fail eligibility',()=>{
 for(const mutate of [f=>f.observations[0].effectReceipt.ownerKey='foreign',f=>f.observations[0].effectReceipt.generation='4',
 f=>f.observations[0].effectReceipt.effectKey='other',f=>f.operation.state='unknown',f=>f.qualifyModel=()=>false,
 f=>f.traces[0].provider='mock',f=>f.traces[0].result_json=JSON.stringify({model:'qualified-model',mocked:false,fallback:true}),
 f=>f.operation.receipt.executorReceiptSha256=hash('changed')]){
  const f=fixture();mutate(f);assert.equal(buildListingsImportEvidence(f).length,0);
 }
});
test('arbitrary/foreign/stale internal URLs do not prove the server-issued internal resource',()=>{
 for(const patch of [{targetId:randomUUID()},{sourceSha256:hash('foreign')},{url:'http://elsewhere'}, {scope:{}}]){
  const f=fixture();Object.assign(f.internalResource,patch);assert.deepEqual(buildListingsImportEvidence(f).map(x=>x.objectiveId),[LISTINGS_OBJECTIVES[2]]);
 }
});
test('XML must contain actual nonempty entity read receipt',()=>{
 const f=fixture(),raw={...f.admission.binding,request:{...f.admission.request,json_url:null,xml_url:'http://owned/manifest.xml'}};
 f.admission=prepareListingAdmission(raw);const receipt=f.operation.receipt;
 receipt.requestSha256=f.admission.requestSha256;receipt.sources[0]={...receipt.sources[0],url:raw.request.xml_url,prototypeEffect:null,
 entityReads:[{name:'lesson',uri:'file:///owned/synthetic.txt',byteCount:4,sha256:hash('test')}]};
 f.observations[0].result.content[0].text=JSON.stringify(receipt);f.traces[1].result_json=JSON.stringify(f.observations[0].result);
 assert.deepEqual(buildListingsImportEvidence(f).map(x=>x.objectiveId),[LISTINGS_OBJECTIVES[1]]);
 receipt.sources[0].entityReads[0].byteCount=0;f.observations[0].result.content[0].text=JSON.stringify(receipt);f.traces[1].result_json=JSON.stringify(f.observations[0].result);
 assert.equal(buildListingsImportEvidence(f).length,0);
});
async function browserFixture(browserPatch={}){
 const a=admission('rewrite'),html=a.request.description,model={provider:'qualified-provider',model:'qualified-model',callId:'exact-model-call',mocked:false,fallback:false};
 const receipt={version:1,operationId:a.request.operationId,requestSha256:a.requestSha256,sourceSha256:hash(JSON.stringify([a.request.title,a.request.description])),...model,html,htmlSha256:hash(html)};
 const save={version:1,saveOperationId:randomUUID(),rewriteOperationId:a.request.operationId,targetId:a.binding.targetId,
 productId:5,bindingSha256:a.bindingSha256,requestSha256:hash('save'),sourceSha256:receipt.sourceSha256,htmlSha256:receipt.htmlSha256};
 const source={admission:a,saveOperationId:save.saveOperationId,productId:5,html,htmlSha256:hash(html)};
 const binding=createConversationBinding(a.binding.scope,a.binding.persona),sessionId=randomUUID();
 const request=createTurnRequest({sessionId,requestId:a.request.operationId,binding,message:a.requestJson});
 const turn={sessionId,requestId:a.request.operationId,requestHash:request.hash,requestVersion:request.version,status:'completed',binding,
 result:{text:html,stopReason:'end_turn',steps:1,hops:[],taskMetadata:{listings:{action:'rewrite',decision:'rewritten',operationId:a.request.operationId,model}}}};
 const execution={runId:'browser-run',ownerKey:'owner',durableGeneration:3},browserRequestId=randomUUID();
 const browser={executed:true,targetEventExecuted:true,targetEffectObserved:true,syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,markers:['alert:1'],blockedRequests:[],...browserPatch};
 const boundary={identity:execution,async check(){},async effectWithReceipt(node,fn){return {value:await fn(),receipt:{version:1,status:'completed',runId:execution.runId,ownerKey:execution.ownerKey,generation:'3',effectKey:`${browserRequestId}:${node}`}};}};
 const adapter=createListingsGeneratedBrowserEvidenceAdapter({browserQualification:{async qualify(markup,{eventSource}){assert.ok(markup.includes(eventSource));return browser;}},
 renderProductDescription:async product=>`<article>${product.description_html}</article>`,componentSourceDigest:hash('component'),componentArtifactDigest:hash('artifact')});
 const browserEvidence=await adapter.capture({source,boundary,execution,requestId:browserRequestId});
 return {admission:a,operation:{operationId:a.request.operationId,state:'completed',receipt},save,source,readback:structuredClone(source),turn,execution,browserEvidence,qualifyModel:()=>true};
}
test('controlled browser adapter requires exact canonical rewrite/save and private attributed browser capture',async()=>{
 const f=await browserFixture();assert.equal(buildListingsGeneratedBrowserEvidence(f).length,1);
});
test('preview, copied same-HTML turn, forged marker, changed source and unqualified model never qualify',async()=>{
 for(const mutate of [f=>f.save=null,f=>f.operation.state='effect_received',f=>f.turn.requestId=randomUUID(),
 f=>f.turn.result.taskMetadata.listings.operationId=randomUUID(),f=>f.turn.result.taskMetadata.listings.model.callId='other-call',
 f=>f.browserEvidence={executed:true,markers:['claimed']},f=>f.readback.html='changed',f=>f.qualifyModel=()=>false,
 f=>f.save.saveOperationId='invalid',f=>f.execution={...f.execution,ownerKey:'foreign'},f=>f.turn.binding={...f.turn.binding,generation:2}]){
  const f=await browserFixture();mutate(f);assert.equal(buildListingsGeneratedBrowserEvidence(f).length,0);
 }
});

test('a browser marker without attributed target execution/effect is ineligible',async()=>{
 for(const patch of [{targetEventExecuted:false},{targetEffectObserved:false},{syntheticCookieOnly:false},{markers:[]}]){
  const f=await browserFixture(patch);assert.equal(buildListingsGeneratedBrowserEvidence(f).length,0);
 }
});
