'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const http=require('node:http');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const fs=require('node:fs');
const {createHash}=require('node:crypto');
const {randomUUID}=require('node:crypto');
const {loseUploadAckAfterCommit,assertRecovery,assertSiblingSource,enterMerchantListingsWithAuthority,assertDistinctOwnedTargets,
  assertUploadedOwnerTarget,peerManualAuthority,assertUploaderActor}=require('./fixtures/secureshopManualUploadQ05');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');

const descriptor=Object.freeze({productId:'7',sha256:'a'.repeat(64),sizeBytes:'8',
  filename:'owned-manual.txt',mime:'text/plain',public:'true'});
const operationId='00000000-0000-4000-8000-000000000001',recoveryScopeKey='b'.repeat(64);
const lookup={version:1,kind:'product_manual',operationId,recoveryScopeKey,state:'indexed',receipt:{
  productId:7,sha256:descriptor.sha256,sizeBytes:8,filename:descriptor.filename,mime:descriptor.mime,
  isPublic:true,chunkCount:1,chunkIds:['manual:8:0'],completedAt:'2026-10-21T00:00:00.000Z'}};
const root=path.resolve(__dirname,'..');
const fixture=path.join(__dirname,'postgres/secureshopManualRagRendered.integration.test.js');
const retainedSha256='24762fbe5246df13e1e766268fbd33157ef577f039fda3a49c29b2363102e7ce';
function readPinnedRetained(file){
  let saved;
  try{saved=fs.readFileSync(file);}catch(error){if(error.code==='ENOENT')return null;throw error;}
  assert.equal(createHash('sha256').update(saved).digest('hex'),retainedSha256);
  return JSON.parse(saved);
}
function rows(){return [{method:'GET',pathname:'/uploads/product-manual/receipt',query:{...descriptor},
  status:200,error:null,response:JSON.stringify({...lookup,state:'not_found',receipt:null})},
  {method:'POST',pathname:'/uploads',status:200,error:'ABORTED',response:'{'},
  {method:'GET',pathname:'/uploads/product-manual/receipt',query:{...descriptor,recoveryScopeKey},
    status:200,error:null,response:JSON.stringify(lookup)}];}

function syntheticUploader(){
  const model='controlled-model',productId=7,filename='owned-manual.txt',fileBytes=8,
    fileSha256='a'.repeat(64),callId='ollama_controlled';
  const config=require('../server/services/secureshopManualExecutionConfig').createSecureShopManualExecutionConfig();
  const task=`Store and index this manual for product ${productId}. File metadata: ${JSON.stringify({
    filename,mime:'text/plain',bytes:fileBytes,sha256:fileSha256})}`;
  const upload={ok:true,kind:'product_manual',scope_id:productId,filename,size_bytes:fileBytes,
    operationId,provider:'ollama',model};
  const observation={ok:true,kind:'product_manual',scope_id:productId,filename,size_bytes:fileBytes,
    operationId};
  const decision=JSON.stringify({tool_calls:[{agent:'uploads',tool:'upload_product_manual',
    args:{product_id:productId}}]});
  const final=JSON.stringify({answer:'Stored and indexed.'});
  const initial=[{role:'system',content:config.buildBasePrompt('merchant')},
    {role:'user',content:task}];
  const finalMessages=[...initial,{role:'assistant',content:JSON.stringify({tool_calls:[{
    id:callId,agent:'uploads',tool:'upload_product_manual',args:{product_id:productId}}]})},
    {role:'user',content:`Tool observation for completed call ${JSON.stringify(callId)} (tool result):\n${JSON.stringify(observation)}`}];
  const decisionSchema=require('../server/services/secureshop/providers/ollamaProvider')
    .closedDecisionSchema(config.manifest.getForRole('merchant'));
  const finalSchema=require('../server/agent-runtime/providers/finalResponseContract').FINAL_RESPONSE_SCHEMA;
  function wire(index,messages,format,content){
    const request=JSON.stringify({model,stream:true,messages,format,
      options:{num_ctx:8192,temperature:0,num_predict:2048}});
    const response=JSON.stringify({model,message:{role:'assistant',content},done:true,
      done_reason:'stop',eval_count:2})+'\n';
    return {index,kind:'actor',model,request,requestBytes:Buffer.byteLength(request),
      requestSha256:createHash('sha256').update(request).digest('hex'),status:200,response,
      responseBytes:Buffer.byteLength(response),responseObservedBytes:Buffer.byteLength(response),
      responseSha256:createHash('sha256').update(response).digest('hex'),
      responseComplete:true,responseCaptureTruncated:false,terminalReason:'end'};
  }
  const calls=[wire(1,initial,decisionSchema,decision),wire(2,finalMessages,finalSchema,final)];
  const spans=[{method:'chat',result:{provider:'ollama',model,mocked:false,stop_reason:'tool_use',
    tool_uses:[{id:callId,name:'uploads.upload_product_manual',args:{product_id:productId}}]},
    wires:[calls[0]]},{method:'finalResponse',result:{provider:'ollama',model,mocked:false,
      stop_reason:'end_turn',responseMode:'structured_final',text:'Stored and indexed.'},wires:[calls[1]]}];
  return {spans,calls,productId,filename,fileBytes,fileSha256,upload,manualRows:[{row:{
    operation_id:operationId,product_id:productId,filename,byte_count:fileBytes,
    file_sha256:`\\x${fileSha256}`,receipt_version:2}}],model,actorCap:14};
}

test('synthetic original uploader and supported correction stay within the physical budget',()=>{
  const input=syntheticUploader();
  assert.equal(assertUploaderActor(input).physicalActorCalls,2);
  for(const [spanIndex,correction] of [[0,
    'The previous decision was not a valid single JSON object matching the requested schema. No tool was executed from that output. Return exactly one corrected decision, without commentary or additional objects.'],[1,
    'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.']]){
    const repaired=structuredClone(input),span=repaired.spans[spanIndex];
    const first=structuredClone(span.wires[0]),last=span.wires[0];
    const priorRaw='not valid JSON';
    first.response=JSON.stringify({model:input.model,message:{role:'assistant',content:priorRaw},
      done:true,done_reason:'length',eval_count:2})+'\n';
    first.responseBytes=Buffer.byteLength(first.response);first.responseObservedBytes=first.responseBytes;
    first.responseSha256=createHash('sha256').update(first.response).digest('hex');
    const request=JSON.parse(last.request);
    request.messages.push({role:'assistant',content:priorRaw},{role:'user',content:correction});
    if(spanIndex===1)request.options.num_predict=2046;
    last.request=JSON.stringify(request);last.requestBytes=Buffer.byteLength(last.request);
    last.requestSha256=createHash('sha256').update(last.request).digest('hex');
    span.wires.unshift(first);repaired.calls=repaired.spans.flatMap(item=>item.wires);
    repaired.calls.forEach((item,index)=>{item.index=index+1;});
    assert.equal(assertUploaderActor(repaired).physicalActorCalls,3);
    const invalid=structuredClone(repaired);invalid.spans[spanIndex].wires[0].response=first.response.replace('"done":true','"done":false');
    invalid.calls=invalid.spans.flatMap(item=>item.wires);
    assert.throws(()=>assertUploaderActor(invalid));
    const changedFormat=structuredClone(repaired);
    const firstRequest=JSON.parse(changedFormat.spans[spanIndex].wires[0].request);
    firstRequest.format={type:'object'};
    const changedWire=changedFormat.spans[spanIndex].wires[0];
    changedWire.request=JSON.stringify(firstRequest);
    changedWire.requestBytes=Buffer.byteLength(changedWire.request);
    changedWire.requestSha256=createHash('sha256').update(changedWire.request).digest('hex');
    changedFormat.calls=changedFormat.spans.flatMap(item=>item.wires);
    assert.throws(()=>assertUploaderActor(changedFormat),'The first physical request must have the original schema');
  }
  for(const mutate of [value=>{value.calls.push(structuredClone(value.calls[1]));},
    value=>{value.spans.push(structuredClone(value.spans[0]));},
    value=>{value.spans[0].result.tool_uses[0].name='product-search.similar';},
    value=>{value.spans[1].method='chat';},
    value=>{value.calls[1].kind='judge';value.spans[1].wires[0].kind='judge';},
    value=>{value.upload.operationId=randomUUID();},
    value=>{value.manualRows[0].row.file_sha256='\\x'+'0'.repeat(64);},
  ]){const changed=structuredClone(input);mutate(changed);assert.throws(()=>assertUploaderActor(changed));}
});

test('retained genuine merchant uploader is verified when immutable private evidence is present',t=>{
  const retained=path.join(root,'tasks/qualification/run-g5dcmdia/manual-upload-q05-wire.json');
  const wire=readPinnedRetained(retained);
  if(!wire){t.skip('Private retained capture is absent; synthetic controls still run');return;}
  const input={spans:wire.actorSpans,calls:wire.actorCalls,
    productId:wire.originalCapture.q05Committed.body.scope_id,
    filename:wire.originalCapture.payload.filename,fileBytes:wire.originalCapture.payload.bytes,
    fileSha256:wire.originalCapture.payload.sha256,upload:wire.originalCapture.q05Committed.body,
    manualRows:wire.originalCapture.manualReceipts,model:wire.model,actorCap:14};
  const accepted=assertUploaderActor(input);
  assert.equal(accepted.physicalActorCalls,2);
  assert.equal(accepted.tool,'uploads.upload_product_manual');
  for(const [spanIndex,correction] of [[0,
    'The previous decision was not a valid single JSON object matching the requested schema. No tool was executed from that output. Return exactly one corrected decision, without commentary or additional objects.'],[1,
    'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.']]){
    const repaired=structuredClone(input),span=repaired.spans[spanIndex];
    const first=structuredClone(span.wires[0]),last=span.wires[0];
    const priorRaw='not valid JSON';
    first.response=JSON.stringify({model:input.model,message:{role:'assistant',content:priorRaw},
      done:true,done_reason:'length',eval_count:2})+'\n';
    first.responseBytes=Buffer.byteLength(first.response);first.responseObservedBytes=first.responseBytes;
    first.responseSha256=createHash('sha256').update(first.response).digest('hex');
    first.responseChunkCount=1;
    const request=JSON.parse(last.request);
    request.messages.push({role:'assistant',content:priorRaw},{role:'user',content:correction});
    if(spanIndex===1)request.options.num_predict=2046;
    last.request=JSON.stringify(request);last.requestBytes=Buffer.byteLength(last.request);
    last.requestSha256=createHash('sha256').update(last.request).digest('hex');
    span.wires.unshift(first);
    repaired.calls=repaired.spans.flatMap(item=>item.wires);
    repaired.calls.forEach((wire,index)=>{wire.index=index+1;});
    assert.equal(assertUploaderActor(repaired).physicalActorCalls,3);
    const validPrior=spanIndex===0?'{"reply":"premature"}':'{"answer":"premature"}';
    const invalidRepair=repaired.spans[spanIndex].wires[0];
    invalidRepair.response=JSON.stringify({model:input.model,
      message:{role:'assistant',content:validPrior},done:true,done_reason:'stop',eval_count:2})+'\n';
    invalidRepair.responseBytes=Buffer.byteLength(invalidRepair.response);
    invalidRepair.responseObservedBytes=invalidRepair.responseBytes;
    invalidRepair.responseSha256=createHash('sha256').update(invalidRepair.response).digest('hex');
    const correctedRequest=JSON.parse(repaired.spans[spanIndex].wires[1].request);
    correctedRequest.messages.at(-2).content=validPrior;
    const correctedWire=repaired.spans[spanIndex].wires[1];
    correctedWire.request=JSON.stringify(correctedRequest);
    correctedWire.requestBytes=Buffer.byteLength(correctedWire.request);
    correctedWire.requestSha256=createHash('sha256').update(correctedWire.request).digest('hex');
    assert.throws(()=>assertUploaderActor(repaired),'A valid prior answer cannot be laundered as correction');
  }
  assert.equal(wire.requests.filter(row=>row.method==='POST'&&row.pathname==='/uploads').length,1);
  assert.equal(wire.requests.filter(row=>row.method==='POST'&&/\/products\/\d+\/similar/.test(row.pathname)).length,0);
  for(const mutate of [
    value=>{value.calls.push(structuredClone(value.calls[1]));},
    value=>{value.spans.push(structuredClone(value.spans[0]));},
    value=>{value.spans[0].result.tool_uses[0].name='product-search.similar';},
    value=>{value.spans[1].method='chat';},
    value=>{value.calls[1].kind='judge';value.spans[1].wires[0].kind='judge';},
    value=>{value.calls[1].request=JSON.stringify({...JSON.parse(value.calls[1].request),messages:[]});
      value.calls[1].requestBytes=Buffer.byteLength(value.calls[1].request);
      value.calls[1].requestSha256=createHash('sha256').update(value.calls[1].request).digest('hex');
      value.spans[1].wires[0]=structuredClone(value.calls[1]);},
    value=>{value.upload.operationId=randomUUID();},
    value=>{value.manualRows[0].row.file_sha256='\\x'+'0'.repeat(64);},
  ]){const changed=structuredClone(input);mutate(changed);assert.throws(()=>assertUploaderActor(changed));}
});

test('retained evidence is skipped only when absent; present corrupt bytes fail',()=>{
  const privateDir=fs.mkdtempSync(path.join(root,'tasks/qualification/q05-uploader-control-'));
  try{
    const evidence=path.join(privateDir,'wire.json');
    assert.equal(readPinnedRetained(evidence),null);
    fs.writeFileSync(evidence,'{}',{flag:'wx',mode:0o600});
    assert.throws(()=>readPinnedRetained(evidence));
  }finally{fs.rmSync(privateDir,{recursive:true});}
});

test('actual HTTP 200 original bound reply is retained but browser receives only partial bytes',async()=>{
  let committed=null,used=null,sideEffects=0;
  const server=http.createServer((req,res)=>{
    req.path='/uploads';
    req.body={kind:'product_manual',scope_id:'7',mime:'text/plain',public:'true',
      recoveryScopeKey};
    req.file={originalname:'owned-manual.txt',buffer:Buffer.from('original')};
    used=loseUploadAckAfterCommit(req,res,value=>{committed=value;});
    sideEffects++;
    res.setHeader('content-type','application/json');
    res.end(JSON.stringify({ok:true,kind:'product_manual',operationId,scope_id:7}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const response=await fetch(`http://127.0.0.1:${server.address().port}/uploads`,{method:'POST'});
    assert.equal(response.status,200);
    await assert.rejects(response.text());
    assert.equal(sideEffects,1);assert.equal(used(),true);
    assert.deepEqual(committed.body,{ok:true,kind:'product_manual',operationId,scope_id:7});
    assert.equal(committed.raw,JSON.stringify(committed.body));
    assert.equal(committed.bytes,JSON.stringify(committed.body).length);
    assert.match(committed.sha256,/^[a-f0-9]{64}$/);
    assert.deepEqual(committed.request.fields,reqBody());
  } finally {await new Promise(resolve=>server.close(resolve));}
});
function reqBody(){return {kind:'product_manual',scope_id:'7',mime:'text/plain',public:'true',recoveryScopeKey};}

test('one initial absence, one committed POST and exact recovery GET bind descriptor and budget',()=>{
  assert.deepEqual(assertRecovery({requests:rows(),descriptor,operationId,recoveryScopeKey}),lookup);
  for(const mutate of [r=>r.push({...r[1]}),r=>r.pop(),r=>{r[2].query.sha256='c'.repeat(64);},
    r=>{r[2].query.recoveryScopeKey='c'.repeat(64);},r=>{r[2].response=JSON.stringify({...lookup,operationId:randomUUID()});},
    r=>{r[2].response=JSON.stringify({...lookup,receipt:{...lookup.receipt,sha256:'c'.repeat(64)}});},
    r=>{r[2].status=401;}]){
    const changed=structuredClone(rows());mutate(changed);
    assert.throws(()=>assertRecovery({requests:changed,descriptor,operationId,recoveryScopeKey}));
  }
  assert.throws(()=>assertRecovery({requests:rows(),descriptor,operationId,recoveryScopeKey,actorAfter:1}));
  assert.throws(()=>assertRecovery({requests:rows(),descriptor,operationId,recoveryScopeKey,judgeAfter:1}));
});
test('sibling isolation requires a nonempty canonical manual, documents and exact file digest',()=>{
  const peerTargetId='00000000-0000-4000-8000-000000000003';
  const before={targetId:peerTargetId,products:Array.from({length:125},(_,id)=>({row:{product_id:id+1,target_id:peerTargetId}})),
    ingests:[{row:{target_id:peerTargetId,operation_id:operationId,manual_source_id:8,file_sha256:`\\x${descriptor.sha256}`,
      file_target_id:operationId,virtual_path:'/uploads/product_manuals/7/manual',byte_count:8}}],
    documents:[{row:{target_id:peerTargetId,source_kind:'manual',source_id:8,body:'Owned sibling source'}}],
    file:{operationId,targetId:operationId,virtualPath:'/uploads/product_manuals/7/manual',
      sha256:descriptor.sha256,bytes:8}};
  assert.equal(assertSiblingSource(before,structuredClone(before)),true);
  for(const mutate of [v=>v.ingests.pop(),v=>v.documents.pop(),v=>{v.file.bytes=0;},
    v=>{v.file.sha256='c'.repeat(64);},v=>{v.documents[0].row.body='changed';}]){
    const after=structuredClone(before);mutate(after);
    assert.throws(()=>assertSiblingSource(before,after));
  }
  assert.throws(()=>assertSiblingSource({...before,ingests:[]},before));
});
test('physical Listings click binds the normal owned-product GET, never optional readiness 503',async()=>{
  const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
    platformOwnerId:1001,platformSessionId:2001};
  const authority={scope,persona:{id:1001,role:'merchant'}},requests=[],map=new Map(),events=[];
  const unavailable={method:'GET',pathname:'/merchant/listings/readiness',status:503,error:null};
  const row={method:'GET',pathname:'/merchant/products',status:200,error:null,
    query:{retailer_id:'1001',page:'1',per_page:'20',sort:'updated_desc'},
    response:JSON.stringify({products:[{id:7,name:'Owned listing'}]})};
  const frame={waitForSelector:async(selector,options)=>{assert.equal(selector,
    'a[href="/secureshop/merchant/listings"]');assert.deepEqual(options,{visible:true});events.push('visible');},
  click:async selector=>{assert.equal(selector,'a[href="/secureshop/merchant/listings"]');
    events.push('click');requests.push(unavailable,row);map.set(row,authority);}};
  const observed=async(read,label,timeout)=>{events.push('observe');
    assert.equal(label,'physical owned merchant product list authority');assert.equal(timeout,20000);
    const found=read();assert.ok(found,'Navigation must cause the request before observation');return found;};
  const args={frame,requests,authorityByRequest:map,observed,merchantId:1001,productId:7};
  const value=await enterMerchantListingsWithAuthority(args);
  assert.deepEqual(events,['visible','click','observe']);
  assert.deepEqual(value,{listing:row,authority});assert.deepEqual(requests,[unavailable,row]);
  for(const mutate of [v=>v.status=503,v=>v.error='ABORTED',v=>v.query.retailer_id='1002',
    v=>v.response=JSON.stringify({products:[{id:8}]}),v=>v.response='not-json']){
    const bad=structuredClone(row);mutate(bad);
    await assert.rejects(enterMerchantListingsWithAuthority({...args,frame:{...frame,click:async()=>{
      requests.length=0;requests.push(unavailable,bad);map.set(bad,authority);}}}));
  }
  await assert.rejects(enterMerchantListingsWithAuthority({...args,frame:{...frame,click:async()=>{
    requests.length=0;requests.push(unavailable,row);map.delete(row);}}}));
  await assert.rejects(enterMerchantListingsWithAuthority({...args,frame:{...frame,click:async()=>{
    requests.length=0;requests.push(unavailable,row);map.set(row,{...authority,persona:{id:1002,role:'merchant'}});}}}));
});
test('actual bound catalog rejects missing session; retrieval accepts exact persona and trusted effect',async()=>{
  const {createSecureShopBoundCatalog}=require('../server/services/secureshopBoundCatalog');
  const {createSecureShopBoundProductRetrieval}=require('../server/services/secureshopBoundProductRetrieval');
  const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
    platformOwnerId:1002,platformSessionId:2002};
  const binding={...scope,targetId:randomUUID(),kind:'products'};
  const actor={user:{id:42,role:'merchant',username:'peer'},sessionId:randomUUID(),authorityVersion:'2'};
  const product={id:7,retailer_id:42,status:'active',name:'Owned source',description:'source',
    description_html:null,price:2,category:'test',image_url:null,images:[],stock_quantity:1,template_source:null};
  let reads=0,provisions=0,checks=0;
  const fence={binding:{...scope,personaId:42,role:'merchant',sessionId:actor.sessionId,
    authorityVersion:actor.authorityVersion},assertRemoteAdmission:async()=>{checks++;},
    withCrossStoreEffect:async work=>work()};
  const personaAuthority={async capture(input){assert.deepEqual(input,{scope,personaId:42,role:'merchant',
    sessionId:actor.sessionId,authorityVersion:'2'});return fence;}};
  const authority=await peerManualAuthority({personaAuthority,scope,actor});
  assert.deepEqual(authority.persona,{id:42,role:'merchant'});
  const catalog=createSecureShopBoundCatalog({sourcePool:{async query(){throw Error('Preseeded catalog must not reread source');}},
    repository:{async open(){return{ownMerchantId:42};},async provision(){provisions++;throw Error('No reseed');},
      async list(){reads++;return{rows:[product],total:1};},async get(){reads++;return product;},
      async categories(){return[];},async createListing(){},async updateListing(){},async archiveListing(){}},
    resolveTarget:async()=>binding,checkCurrent:async()=>{},ownMerchantId:42,personaAuthority});
  await assert.rejects(catalog.getOwnedMerchantProduct({scope,persona:authority.persona,productId:7}),
    {code:'SHOP_AUTH_INVALID'});
  await assert.rejects(catalog.getOwnedMerchantProduct({scope,persona:authority.persona,
    personaSession:{...authority.personaSession,authorityVersion:'0'},productId:7}),
  {code:'SHOP_AUTH_INVALID'});
  assert.equal(reads,0);assert.equal(provisions,0);
  const owned=await catalog.getOwnedMerchantProduct({scope,persona:authority.persona,
    personaSession:authority.personaSession,productId:7});
  assert.equal(owned.product.id,7);assert.equal(owned.binding.targetId,binding.targetId);
  const retrieval=createSecureShopBoundProductRetrieval({catalog,checkCurrent:async()=>{},
    repository:{async readMetadata(){return{...binding,embeddingModel:'test:v1',embeddingDimension:2,
      documentCount:1};},async provision(){provisions++;throw Error('No rebuild');},async search(){return[];}},
    embedder:{async embed(){throw Error('No model call');}}});
  await assert.rejects(retrieval.ensureProvisioned({scope,persona:{...authority.persona,username:'peer'},
    personaEffect:authority.personaEffect}),{code:'INVALID_ARGUMENT'});
  const meta=await retrieval.ensureProvisioned({scope,persona:authority.persona,
    personaEffect:authority.personaEffect});
  assert.equal(meta.documentCount,1);assert.equal(provisions,0);assert.ok(reads>=2);assert.ok(checks>0);
});
test('actual Q05 owner/peer guard reads retained grant and rejects unbound or identical targets',async()=>{
  const ownerScope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
    platformOwnerId:1001,platformSessionId:2001};
  const setupScope={...ownerScope,launchId:randomUUID(),scenarioId:randomUUID(),
    platformSessionId:1999};
  const peerScope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
    platformOwnerId:1002,platformSessionId:2002};
  const ownerBirth={...ownerScope,launchId:randomUUID(),scenarioId:randomUUID(),
    platformSessionId:3001};
  const peerBirth={...peerScope,launchId:randomUUID(),scenarioId:randomUUID(),
    platformSessionId:3002};
  const ownerTargetId=randomUUID(),peerTargetId=randomUUID(),ownerSceneId=randomUUID(),peerSceneId=randomUUID();
  const binding=(execution,birth,targetId,sceneId)=>createSceneBinding({...birth,targetId},
    {sceneId,sceneGeneration:1,grantId:randomUUID(),execution,withLease:async work=>work()});
  const owner=binding(ownerScope,ownerBirth,ownerTargetId,ownerSceneId);
  const setupTarget=binding(setupScope,ownerBirth,ownerTargetId,ownerSceneId);
  const peer=binding(peerScope,peerBirth,peerTargetId,peerSceneId);
  assert.notDeepEqual(ownerScope,ownerBirth,'Control must exercise distinct storage birth and execution');
  assert.notDeepEqual(ownerScope,setupScope,'Control must exercise revoked setup versus current physical merchant launch');
  let reads=0;
  const scenes={readRetained:async scope=>{reads++;assert.deepEqual(scope,ownerScope);return owner;}};
  assert.deepEqual(await assertDistinctOwnedTargets({scenes,setupScope,setupTarget,
    ownerScope,ownerTarget:owner,peerScope,peerTarget:peer}),owner);
  assert.equal(reads,1);
  assert.equal(assertUploadedOwnerTarget({ownerScope,ownerTarget:owner,uploadScope:ownerScope,
    uploadedScene:binding(ownerScope,ownerBirth,ownerTargetId,ownerSceneId)}),true);
  for(const invalid of [null,binding(ownerScope,ownerBirth,peerTargetId,ownerSceneId),
    binding(ownerScope,{...ownerBirth,platformSessionId:9},ownerTargetId,ownerSceneId),
    binding({...ownerScope,launchId:randomUUID()},ownerBirth,ownerTargetId,ownerSceneId),
    {...owner,scene:{...owner.scene}}]){
    await assert.rejects(assertDistinctOwnedTargets({scenes:{readRetained:async()=>invalid},
      setupScope,setupTarget,ownerScope,ownerTarget:owner,peerScope,peerTarget:peer}));
  }
  for(const invalid of [binding(peerScope,peerBirth,ownerTargetId,peerSceneId),
    binding({...peerScope,platformOwnerId:ownerScope.platformOwnerId},
      {...peerBirth,platformOwnerId:ownerScope.platformOwnerId},peerTargetId,peerSceneId),
    binding({...peerScope,launchId:randomUUID()},peerBirth,peerTargetId,peerSceneId),
    {...peer,scene:{...peer.scene}}]){
    await assert.rejects(assertDistinctOwnedTargets({scenes,setupScope,setupTarget,
      ownerScope,ownerTarget:owner,peerScope,peerTarget:invalid}));
  }
  for(const invalid of [null,binding(ownerScope,ownerBirth,randomUUID(),ownerSceneId),
    binding(ownerScope,{...ownerBirth,platformSessionId:9},ownerTargetId,ownerSceneId),
    binding({...ownerScope,launchId:randomUUID()},ownerBirth,ownerTargetId,ownerSceneId),
    binding(ownerScope,ownerBirth,ownerTargetId,randomUUID())]){
    await assert.rejects(assertDistinctOwnedTargets({scenes,setupScope,setupTarget,ownerScope,ownerTarget:invalid,
      peerScope,peerTarget:peer}));
  }
  for(const invalid of [binding(setupScope,ownerBirth,randomUUID(),ownerSceneId),
    binding({...setupScope,launchId:randomUUID()},ownerBirth,ownerTargetId,ownerSceneId),
    binding(setupScope,ownerBirth,ownerTargetId,randomUUID())]){
    await assert.rejects(assertDistinctOwnedTargets({scenes,setupScope,setupTarget:invalid,
      ownerScope,ownerTarget:owner,peerScope,peerTarget:peer}));
  }
  for(const invalid of [binding(ownerScope,ownerBirth,randomUUID(),ownerSceneId),
    binding(ownerScope,{...ownerBirth,platformSessionId:9},ownerTargetId,ownerSceneId),
    binding(ownerScope,ownerBirth,ownerTargetId,randomUUID()),null]){
    assert.throws(()=>assertUploadedOwnerTarget({ownerScope,ownerTarget:owner,
      uploadScope:ownerScope,uploadedScene:invalid}));
  }
  assert.throws(()=>assertUploadedOwnerTarget({ownerScope,ownerTarget:owner,uploadScope:peerScope,
    uploadedScene:owner}));
});
test('Q05 actual fixture module admits only explicit separate mode and remains native-gated',()=>{
  const base={PATH:process.env.PATH||'/usr/bin:/bin',TMPDIR:path.join(root,'tasks/tmp'),
    SECURESHOP_MANUAL_RAG_BROWSER_NATIVE:'0',PG_TEST_DISPOSABLE:'no',LIVE_OLLAMA_TEST:'0'};
  const run=env=>spawnSync(process.execPath,['--test','--test-reporter=tap',fixture],{cwd:root,
    env:{...base,...env},encoding:'utf8',timeout:10000,maxBuffer:1024*1024});
  const admitted=run({SECURESHOP_MANUAL_UPLOAD_Q05:'1'});
  assert.equal(admitted.status,0,admitted.stderr);
  assert.match(admitted.stdout,/Q05 physical manual upload committed lost ACK/);
  assert.match(admitted.stdout,/# pass 2\b/);assert.match(admitted.stdout,/# skipped 1\b/);
  const original=run({});assert.equal(original.status,0,original.stderr);
  assert.match(original.stdout,/V26 physical uploaded manual instruction adoption/);
  for(const env of [{SECURESHOP_MANUAL_UPLOAD_Q05:'0'},
    {SECURESHOP_MANUAL_UPLOAD_Q05:'1',SECURESHOP_MANUAL_RAG_PAIRED:'1'},
    {SECURESHOP_MANUAL_UPLOAD_Q05:'1',SECURESHOP_MANUAL_RAG_FIXED_ONLY:'1'},
    {SECURESHOP_MANUAL_UPLOAD_Q05:'1',SECURESHOP_MANUAL_RAG_PAYLOAD_VARIANT:'role-spoof-v1'}]){
    const rejected=run(env);assert.notEqual(rejected.status,0);
  }
});
