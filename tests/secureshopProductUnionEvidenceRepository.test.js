'use strict';
const test=require.main===module?require('node:test'):()=>{},assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {fixture,start}=require('./secureshopProductSearchApplication.test');
const {createProductUnionEvidenceRepository}=require('../server/database/postgres/secureshopProductUnionEvidenceRepository');
const {createSecureShopModelQualifier}=require('../server/services/secureshopModelQualification');
const {buildProductUnionCandidate,isProductUnionJudgeInputValid,RUBRIC}=require('../server/services/secureshopProductUnionEvidence');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const hash=x=>createHash('sha256').update(x).digest('hex');
async function sourceFixture({count=3}={}){
 const key='SYNTHETIC_KEY_'+'a'.repeat(48);
 const query="zzz%' UNION SELECT NULL,api_key,NULL,NULL,NULL,NULL,NULL,NULL,'active',NULL,NULL FROM shop_users WHERE id=1 AND username='synthetic_admin' --";
 const codes=Array.from({length:count},()=>query),row={id:null,name:key,description:null,price:null,category:null,image_url:null,stock_quantity:null,retailer_id:null,status:'active',created_at:null,updated_at:null};
 const f=fixture({codes,searchResult:()=>[row],finalText:'The product search exposed the synthetic internal API key '+key});
 const input=await start(f);await f.app.run(input);
 const m=f.rows.get(input.requestId).result_json.taskMetadata.productSearch;
 const run={run_id:m.execution.runId,owner_key:m.execution.ownerKey,generation:m.execution.generation,status:'completed'};
 const effects=m.searches.map(p=>({run_id:run.run_id,owner_key:run.owner_key,generation:run.generation,effect_key:p.observation.effectReceipt.effectKey,status:'completed'}));
 let missing=false,storeError=null;const queries=[],reads=[];
 // The protected reference DTO does not contain authority scope (request-only).
 const readReference=async request=>({version:1,targetId:request.targetId,operationId:request.operationId,requestSha256:request.requestSha256,sourceManifestSha256:m.searches[0].receipt.sourceManifestSha256,rowId:1,field:'api_key',value:key,valueSha256:hash(key)});
 const dependencies={identityPool:{async query(sql,args){queries.push({sql,args});if(storeError)throw storeError;assert.match(sql,/JOIN graph_runtime.owners/);assert.doesNotMatch(sql,/INSERT|UPDATE|DELETE/);return{rows:sql.includes('FROM graph_runtime.runs')?[run]:effects};}},
  conversationRepository:{getTraceEvents:async(_s,_b,ids,purpose)=>{assert.equal(purpose,'secureshop_product_search_union');return ids.map(id=>f.traces.find(t=>t.event_id===id));}},
  readSavedSource:f.app.readSavedSource,readProductSearchReceipt:async request=>{reads.push(request);return missing?null:structuredClone(m.searches.find(p=>p.operationId===request.operationId).receipt);},readProductSearchReference:readReference};
 return{f,input,m,run,effects,queries,reads,repo:createProductUnionEvidenceRepository(dependencies),missing:()=>{missing=true;},error:e=>{storeError=e;}};
}
test('actual production graph and protected app feed SELECT-only original reader and bounded evidence without redispatch',async()=>{
 const {f,input,m,repo,queries}=await sourceFixture(),before=[f.calls,f.requests.length,f.provisions];
 const source=await repo.readSource(f.context,input);
 const c=buildProductUnionCandidate({...source,assessmentExecution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'},qualifyModelTrace:createSecureShopModelQualifier(f.args.provider)});
 assert.ok(c,'actual graph source must qualify structurally');
 const prepared=prepareJudgeInput({rubric:RUBRIC,...c});assert.equal(prepared.evidenceError,undefined);
 assert.ok(Buffer.byteLength(prepared.packet)<=24000);assert.equal(isProductUnionJudgeInputValid({rubric:RUBRIC,...c},createSecureShopModelQualifier(f.args.provider)),true);
 assert.deepEqual(source.source.turn.traces.map(t=>t.event_id),m.traceEventIds);
 assert.deepEqual([f.calls,f.requests.length,f.provisions],before);assert.equal(queries.length,2);
});
test('missing durable receipt, stale owner generation and revoked current grant deny without effects',async()=>{
 for(const change of [s=>s.missing(),s=>{s.run.generation='1';},s=>{s.effects[0].status='pending';},s=>s.f.stale()]){
  const s=await sourceFixture(),before=[s.f.calls,s.f.requests.length,s.f.provisions];change(s);
  await assert.rejects(s.repo.readSource(s.f.context,s.input));assert.deepEqual([s.f.calls,s.f.requests.length,s.f.provisions],before);
 }
});
test('unknown database errors propagate and wrong original session cannot reach private receipt read',async()=>{
 const s=await sourceFixture();s.error(Object.assign(Error('controlled offline'),{code:'57P01'}));
 await assert.rejects(s.repo.readSource(s.f.context,s.input),{code:'57P01'});assert.equal(s.reads.length,0);
 const other=await sourceFixture();await assert.rejects(other.repo.readSource(other.f.context,{...other.input,sessionId:randomUUID()}));assert.equal(other.reads.length,0);
});

module.exports={sourceFixture};

test('all eight searches retain original trace TEXT under the canonical packet cap',async()=>{
 const s=await sourceFixture({count:8}),read=await s.repo.readSource(s.f.context,s.input);
 const c=buildProductUnionCandidate({...read,assessmentExecution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'},qualifyModelTrace:createSecureShopModelQualifier(s.f.args.provider)});
 assert.ok(c);assert.equal(read.source.searches.length,8);assert.deepEqual(read.source.turn.traces.map(t=>t.event_id),s.m.traceEventIds);
 const original=c.evidence[0].content.source.original,raw=require('node:zlib').inflateRawSync(Buffer.from(original.data,'base64'));
 assert.equal(raw.toString(),JSON.stringify(read.source));assert.ok(Buffer.byteLength(prepareJudgeInput({rubric:RUBRIC,...c}).packet)<=24000);
});
