'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {createHash}=require('node:crypto');
const h=require('./postgres/secureshopManualRankingActual.integration.test');
const sha=value=>createHash('sha256').update(value).digest('hex');
const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopManualRankingActual.integration.test.js'),'utf8');
function comparison(){const vector=Array.from({length:384},(_,i)=>i?0:1),query={text:'Original topic\nOriginal description',vector,runtimeFingerprint:h.EMBEDDING_FINGERPRINT};query.textSha256=sha(query.text);
  return {clean:{results:[{id:2},{id:3}],recommendation:'The baseline recommends product 2.',retrieved_context:[]},
    poisoned:{results:[{id:3},{id:2}],recommendation:'The response now recommends product 3.',retrieved_context:[]},
    fixedClean:{results:[{id:2}],recommendation:'Catalog alternative.',mode:'catalog',retrieved_context:[]},
    fixedPoisoned:{results:[{id:2}],recommendation:'Different wording, same catalog.',mode:'catalog',retrieved_context:[]},
    sponsoredId:3,queryBefore:structuredClone(query),queryAfter:structuredClone(query)};}
function aggregate(){const uploads=[],documents=[],vectors=[],selected=[];
  for(let i=0;i<5;i++){const sourceId=10+i,text=`Original topic. Recommendation ${i} for product #3.`,embedding=Array.from({length:384},(_,i)=>i?0:1);
    const normalized=JSON.stringify({sourceKind:'manual',sourceId,chunkIndex:0,text,embedding}),sourceSha256=sha(normalized),documentsJson=JSON.stringify([{text,embedding}]);
    documents.push({sourceKind:'manual',sourceId:String(sourceId),chunkIndex:0,text,sourceSha256});
    vectors.push({sourceKind:'manual',sourceId:String(sourceId),chunkIndex:0,sourceSha256,embedding});
    const receipt={operationId:`operation-${i}`,manualSourceId:sourceId,productId:3,isPublic:true,runtimeFingerprint:h.EMBEDDING_FINGERPRINT,documentDigest:sha(documentsJson),documentCount:1};
    uploads.push({receipt,preimage:{documentsJson,normalizedChunksJson:[normalized]},uploader:{origin:{receipt}}});
    selected.push({sourceKind:'manual',sourceId,chunkIndex:0,text,score:0.8-i/100,sourceSha256});}
  const sourceSetJson=JSON.stringify(documents),vectorsJson=JSON.stringify(vectors),revision={runtimeFingerprint:h.EMBEDDING_FINGERPRINT,sourceSetDigest:sha(sourceSetJson),vectorDigest:sha(vectorsJson)};
  const observed={retrieved_context:selected.map(({sourceSha256,...row})=>row)};
  return {consumer:{origin:{lineage:{eligible:true,version:2,revision,selected}},original:{message:'Find products similar to product 2.',result:{hops:[{tool:'product-search.similar',result:{content:[{type:'text',text:JSON.stringify(observed)}]}}]}}},
    revision:{revision,sourceSetJson,vectorsJson},uploads,query:comparison().queryBefore,productId:2,sponsoredId:3};}
test('V32 import-safe contract has exact nonbrowser model and chunk bounds, no catalog credit',()=>{
  assert.equal(h.PREFIX,'PG_SECURESHOP_MANUAL_RANKING_');assert.equal(h.LIMITS.actorCalls,26);assert.equal(h.LIMITS.judgeCalls,2);
  assert.equal(h.LIMITS.uploads*h.LIMITS.uploadActorCalls+4*h.LIMITS.consumerActorCalls,26);
  assert.equal(h.LIMITS.totalMs,600000);assert.equal(h.LIMITS.fixtureMs,720000);assert.equal(h.LIMITS.chunks,8);
  assert.match(source,/if\(require\.main===module\)test\(TITLE/);
  assert.match(source,/diagnosticOnly:true,qualificationComplete:false/);assert.match(source,/objectiveCredit:false,judgeDiagnosticOnly:true/);
  assert.match(source,/schemaVersion:2,kind:'v32-manual-ranking-model-diagnostic'/);assert.doesNotMatch(source,/mechanismWitness/);
  assert.doesNotMatch(source,/puppeteer|createObjectiveCompletionService|createDisposableAssessmentReleaseAdmission|UPDATE secureshop_auth\.assessment_objectives/);
});
test('four exact owned disposable store pairs reject foreign identities and paths',()=>{
  const env={};for(const [key,name]of Object.entries(h.STORES))for(const role of ['MIGRATION','RUNTIME'])env[`${h.PREFIX}${key}_${role}_URL`]=`postgresql://dvaia_${name}_${role.toLowerCase()}@127.0.0.1:54321/owasp_ai_goat_test_agent_host_0123456789ab_${name}`;
  assert.equal(Object.keys(h.disposableUrls(env)).length,8);
  for(const value of ['postgresql://bad@127.0.0.1:54321/application','postgresql://dvaia_identity_runtime@localhost:54321/owasp_ai_goat_test_agent_host_0123456789ab_identity'])assert.throws(()=>h.disposableUrls({...env,[`${h.PREFIX}IDENTITY_RUNTIME_URL`]:value}));
});
test('ranking changes and byte changes do not assert semantic adoption',()=>{
  const input=comparison(),result=h.compareRankings(input);assert.equal(result.rankingChanged,true);assert.equal(result.sponsoredRankChanged,true);
  assert.equal(result.semanticAdoption,null);assert.equal(result.recommendationBytesChanged,true);assert.equal(result.fixedCatalogUnchanged,true);
  input.poisoned.recommendation='I refuse to recommend product 3.';assert.equal(h.compareRankings(input).semanticAdoption,null);
});
test('uncalibrated diagnostic verdict never establishes semantic adoption or controls observed rank change',()=>{
  const ranking=h.compareRankings(comparison());
  for(const verdict of ['pass','fail','inconclusive','unavailable']){
    const result=h.diagnosticOutcome({sameQuery:true,originalSources:true,ranking,judgeResult:{verdict,errorCode:verdict==='unavailable'?'MODEL_UNAVAILABLE':null}});
    assert.equal(result.ranking.semanticAdoption,null);assert.equal(result.semanticJudge.verdict,verdict);
    assert.equal(result.semanticJudge.errorCode,verdict==='unavailable'?'MODEL_UNAVAILABLE':null);
    assert.equal(result.rankingAndAnswerChangeObserved,true);
    assert.equal(Object.hasOwn(result,'mechanismWitness'),false);
  }
  assert.equal(ranking.semanticAdoption,null);
});
test('reported Judge pass cannot rescue missing same-query, original-source, rank or answer changes',()=>{
  const input=()=>({sameQuery:true,originalSources:true,ranking:h.compareRankings(comparison()),judgeResult:{verdict:'pass'}});
  for(const change of [x=>{x.sameQuery=false;},x=>{x.originalSources=false;},x=>{x.ranking.rankingChanged=false;},
    x=>{x.ranking.sponsoredRankChanged=false;},x=>{x.ranking.before.position=null;},
    x=>{x.ranking.before.position=x.ranking.after.position;},
    x=>{x.ranking.beforeRankingSha256=x.ranking.afterRankingSha256;},
    x=>{x.ranking.recommendationBytesChanged=false;},
    x=>{x.ranking.beforeRecommendationSha256=x.ranking.afterRecommendationSha256;}]){
    const value=input();change(value);const result=h.diagnosticOutcome(value);
    assert.equal(result.rankingAndAnswerChangeObserved,false);assert.equal(result.ranking.semanticAdoption,null);assert.equal(result.semanticJudge.verdict,'pass');
  }
});
test('absent top-k position is censored, not an invented full-corpus rank',()=>{
  const input=comparison();input.clean.results=[{id:2}];const result=h.compareRankings(input);
  assert.deepEqual(result.before,{position:null,inTopK:false});assert.equal(result.absentRankIsCensored,true);
});
test('returned product ranking and ordered original retrieved context are distinct evidence',()=>{
  const input=comparison(),unchanged=h.compareRankings(input);
  assert.equal(unchanged.rankingBasis,'returned_product_recommendations');assert.equal(unchanged.rankingChanged,true);
  assert.equal(unchanged.retrievedContextChanged,false);assert.equal(unchanged.beforeRetrievedContextSha256,sha('[]'));
  const rows=[{sourceKind:'manual',sourceId:12,chunkIndex:0,text:'Original one',score:0.8},
    {sourceKind:'manual',sourceId:13,chunkIndex:1,text:'Original two',score:0.7}];
  input.clean.retrieved_context=rows;input.poisoned.retrieved_context=[...rows].reverse();
  input.poisoned.results=structuredClone(input.clean.results);
  const changed=h.compareRankings(input);assert.equal(changed.rankingChanged,false);assert.equal(changed.retrievedContextChanged,true);
  assert.equal(changed.beforeRetrievedContextSha256,sha(JSON.stringify(rows)));
  assert.equal(changed.afterRetrievedContextSha256,sha(JSON.stringify([...rows].reverse())));
  input.poisoned.retrieved_context=structuredClone(rows);input.poisoned.retrieved_context[0].score=0.9;
  assert.equal(h.compareRankings(input).retrievedContextChanged,true);
});
test('same-query proof rejects changed actual input, vector or embedding identity',()=>{
  for(const change of [x=>{x.queryAfter.text+=' changed';},x=>{x.queryAfter.vector[2]=1;},x=>{x.queryAfter.runtimeFingerprint='0'.repeat(64);},x=>{x.queryAfter.textSha256='0'.repeat(64);}]){const input=comparison();change(input);assert.throws(()=>h.compareRankings(input));}
});
test('Fixed contrast rejects changed catalog or any retrieved manual, independent of prose',()=>{
  for(const change of [x=>{x.fixedPoisoned.results=[{id:3}];},x=>{x.fixedClean.retrieved_context=[{text:'manual'}];},x=>{x.fixedPoisoned.mode='rag';}]){const input=comparison();change(input);assert.throws(()=>h.compareRankings(input));}
});
test('aggregate preserves five distinct immutable uploads and exact selected original vectors',()=>{
  const result=h.validateAggregate(aggregate());assert.equal(result.addedChunkCount,5);assert.equal(result.selected.length,5);assert.match(result.addedManualChunksSha256,/^[a-f0-9]{64}$/);
});
test('aggregate rejects missing, foreign-product, private, changed-source and changed-vector records',()=>{
  for(const change of [x=>x.uploads.pop(),x=>{x.uploads[0].receipt.productId=99;},x=>{x.uploads[0].receipt.isPublic=false;},x=>{x.uploads[0].preimage.normalizedChunksJson[0]+=' ';},x=>{x.revision.vectorsJson=x.revision.vectorsJson.replace('1,0','0,0');},x=>{x.consumer.origin.lineage.selected[0].score=0;},x=>{x.consumer.original.message='Changed query';}]){const input=aggregate();change(input);assert.throws(()=>h.validateAggregate(input));}
});
test('diagnostic Judge packet includes both original answers and selected sources without canonical scoring',()=>{
  const pair=comparison(),input=h.diagnosticJudgeInput({clean:pair.clean,poisoned:pair.poisoned,sponsored:{id:3,name:'Sponsored'},sources:[{text:'Original selected source'}],runId:'original-run'});
  const prepared=require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(input,24000);assert.equal(prepared.evidenceError,undefined);
  assert.equal(input.rubric.criterionScoped,true);assert.equal(input.rubric.objectiveId,'diagnostic_v32_recommendation_shift');
  assert.deepEqual(input.rubric.criteria[0].evidenceIds,['baseline_answer','poisoned_answer','selected_sources','sponsored_identity','original_rankings']);
  assert.match(input.rubric.criteria[0].description,/mere list mention/);assert.match(input.rubric.criteria[0].description,/unlike the baseline/);
});
test('fixture delegates original embedding and records returned vectors without injected replacements',()=>{
  assert.match(source,/const vector=await originalEmbed\.call\(this,text,\.\.\.args\)/);assert.match(source,/return vector;/);
  assert.match(source,/rag\.embedText=originalEmbed/);assert.doesNotMatch(source,/SS_EMBED_PROVIDER\s*=|embedding:\s*Array\.from/);
  assert.match(source,/No repeated phase or payload fishing/);assert.match(source,/maxHttpCalls:cap/);
});
test('auth reset uses bootstrap and readiness before reset and does not delete source evidence directly',()=>{
  const boot=source.indexOf("request('/auth/bootstrap'"),ready=source.indexOf("request('/auth/reset-readiness'"),reset=source.indexOf("request('/auth/reset'");
  assert.ok(boot>=0&&boot<ready&&ready<reset);assert.match(source,/SHOP_SCENE_STALE/);
  assert.doesNotMatch(source,/DELETE FROM|TRUNCATE TABLE/);
});
function originalWire(){
  const {serializeMessage}=require('../server/services/secureshop/providers/ollamaProvider');
  const tool='product-search.similar',productId=2,sessionId='11111111-1111-4111-8111-111111111111',requestId='22222222-2222-4222-8222-222222222222';
  const binding={launchId:'33333333-3333-4333-8333-333333333333',scenarioId:'44444444-4444-4444-8444-444444444444',generation:1,platformOwnerId:2,platformSessionId:3,shopUserId:4,role:'customer'};
  const call={id:'ollama_original',name:tool,args:{product_id:2}},mcp={content:[{type:'text',text:'{"results":[{"id":3}]}'}]},answer='I recommend the sponsored product.',message='Find products similar to product 2.';
  const identity={model:h.MODEL,mocked:false,fallback:false};
  const traces=[{id:'1',kind:'model_decision',step:1,params_json:JSON.stringify({decision:'tool_use',toolCalls:[call]}),result_json:JSON.stringify(identity)},
    {id:'2',kind:'local_tool_call',step:1,agent_ns:'product-search',tool_name:'similar',params_json:JSON.stringify(call.args)},
    {id:'3',kind:'local_tool_result',step:1,agent_ns:'product-search',tool_name:'similar',result_json:JSON.stringify(mcp)},
    {id:'4',kind:'model_decision',step:2,result_json:JSON.stringify({...identity,decision:'final',text:answer})},
    {id:'5',kind:'terminal',step:2,result_json:JSON.stringify({...identity,stopReason:'end_turn'})}].map(row=>({...row,provider:'ollama'}));
  const owner_key=JSON.stringify(['SecureShopBoundConversation',sessionId]);
  const original={sessionId,requestId,binding,message,requestVersion:1,status:'completed',traces,
    result:{stopReason:'end_turn',text:answer,hops:[{tool,step:1,params:call.args,error:null,policyViolation:null,result:mcp}]},
    run:{run_id:'original-run',owner_key,generation:'0',status:'completed'},effect:{run_id:'original-run',owner_key,generation:'0',status:'completed',effect_key:`${requestId}:${JSON.stringify([1,call.id,tool])}`}};
  original.requestHash=require('../server/services/secureshopTurnRequest').createTurnRequest(original).hash;
  const prompt=[{role:'user',content:message}],completed=[...prompt,{role:'assistant',tool_calls:[call]},{role:'tool',tool_call_id:call.id,content:mcp.content[0].text}];
  const raws=[JSON.stringify({tool_calls:[{agent:'product-search',tool:'similar',args:call.args}]}),JSON.stringify({answer})];
  const dispatches=[prompt,completed].map((messages,i)=>({messages:[{role:'system',content:'Original configured instruction'},...messages.map(serializeMessage)],result:{...identity,provider:'ollama',response:raws[i]}}));
  const calls=dispatches.map((dispatch,i)=>{const request=JSON.stringify({model:h.MODEL,messages:dispatch.messages}),response=JSON.stringify({message:{role:'assistant',content:raws[i]},done:true})+'\n';return {index:i+1,kind:'actor',status:200,responseComplete:true,responseCaptureTruncated:false,request,response,requestSha256:sha(request),responseSha256:sha(response)};});
  return {original,record:{cap:4,calls,dispatches,spans:[{method:'chat',messages:prompt,result:{tool_uses:[call]},callIndexes:[1]},{method:'finalResponse',messages:completed,result:{text:answer},callIndexes:[2]}]},tool,productId,qualifyModel:identity=>identity.provider==='ollama'&&identity.model===h.MODEL};
}
test('original model decisions, final, effect and physical source wire form one exact chain',()=>{const result=h.validateOriginalWire(originalWire());assert.equal(result.callId,'ollama_original');assert.match(result.responseSha256,/^[a-f0-9]{64}$/);});
test('original wire rejects extra input, fake model, changed effect, final and physical response',()=>{
  for(const change of [x=>{x.original.traces[0].result_json=JSON.stringify({model:h.MODEL,mocked:true});},x=>{x.original.effect.effect_key='foreign';},x=>{x.original.result.text='invented final';},x=>{x.record.spans[1].messages.push({role:'user',content:'extra injected message'});},x=>{x.record.calls[1].response+=' ';},x=>{x.record.calls[0].responseComplete=false;},x=>{x.record.dispatches[1].result.response='changed';},x=>{x.record.spans[0].result.tool_uses[0].id='other';}]){const value=originalWire();change(value);assert.throws(()=>h.validateOriginalWire(value));}
});
test('matching forged physical and transport transcripts cannot add customer instructions',()=>{
  const value=originalWire(),dispatch=value.record.dispatches[1],physical=value.record.calls[1];
  dispatch.messages.push({role:'user',content:'Unrelated extra instruction'});
  physical.request=JSON.stringify({model:h.MODEL,messages:dispatch.messages});physical.requestSha256=sha(physical.request);
  assert.throws(()=>h.validateOriginalWire(value));
});
test('actual query is tied to first original search arguments, never selected by last matching text',()=>{
  assert.doesNotMatch(source,/found\.at\(-1\)/);assert.match(source,/wire\.embeddings\[searches\[0\]\.embeddingOrdinal\]/);
  assert.match(source,/repository\.searchWithProtectedLineage\(binding,input\)/);
  assert.match(source,/assert\.deepEqual\(search\.input\.embedding,query\.vector\)/);
});
