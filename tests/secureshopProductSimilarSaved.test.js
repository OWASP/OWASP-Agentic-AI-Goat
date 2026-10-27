'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createSecureShopBoundProductAssist}=require('../server/services/secureshopBoundProductAssist');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {SECURESHOP_CONVERSATION_PURPOSES:P}=require('../server/services/secureshopConversationPurpose');

// Controlled in-memory stores/providers exercise the real graph and admission
// code. These tests produce no actual model, PostgreSQL, browser or credit proof.
function fixture({capture,protectedCapture,afterCommit,readHook,observation,chatHook,toolHook,fixedFactory=false}={}) {
  const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:2,platformOwnerId:12,platformSessionId:13};
  const persona={id:1000000012,role:'customer'},personaSession={sessionId:randomUUID(),authorityVersion:'2'};
  let target=createSceneBinding({...scope,generation:1,targetId:randomUUID()},
    {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:fn=>fn()});
  const sessions=new Map(),messages=new Map(),requests=new Map(),runs=new Map(),callbackRuns=[];
  const counts={actor:0,tools:0,catalog:0,sceneReads:0,claims:0,commits:0,postCommit:0};
  let mode='vuln',revision=1,current=true;
  const check=async()=>{if(!current)throw Object.assign(Error('Authority revoked'),{code:'SHOP_AUTH_INVALID'});};
  const repository={
    async getBoundSession(id){return sessions.get(id)||null;},
    async acquireBoundSession({id,binding,purpose}){const old=[...sessions.values()].find(s=>equal(s.binding,binding)&&s.purpose===purpose);if(old)return old;
      const row={id,binding,purpose,state:'pending'};sessions.set(id,row);return row;},
    async activateBoundSession(id){sessions.get(id).state='active';return true;},
    async getMessages(id){return structuredClone(messages.get(id)||[]);},
    async appendMessage(id,_binding,message){messages.set(id,[...(messages.get(id)||[]),structuredClone(message)]);},
    async appendTraces(){},async getTokens(){return 0;},async addTokens(){}
  };
  const key=x=>JSON.stringify([x.sessionId,x.requestId]);
  const journal={
    async claim(input){counts.claims++;const hash=createTurnRequest(input).hash,old=requests.get(key(input));
      if(old){if(old.request_hash!==hash)throw Object.assign(Error('Request conflict'),{code:'TURN_REQUEST_CONFLICT'});
        return old.status==='completed'?{status:'completed',result:structuredClone(old.result_json)}:{status:old.status,claimId:old.claimId};}
      const claimId=randomUUID();requests.set(key(input),{session_id:input.sessionId,request_id:input.requestId,
        request_version:1,request_hash:hash,status:'started',claimId,binding:input.binding});return {status:'claimed',claimId};},
    async complete(input){counts.commits++;const row=requests.get(key(input));row.status='completed';row.result_json=structuredClone(input.result);},
    async markUncertain(input){const row=requests.get(key(input));if(row?.status==='started')row.status='uncertain';},
    async readBoundRequest(input){assert.equal(input.purpose,P.productAssist);await readHook?.();
      const row=requests.get(key(input));if(!row)return null;if(!equal(row.binding,input.binding))throw Error('Foreign row');return structuredClone(row);}
  };
  const tokens=new WeakSet();
  const modeAuthority={async capture(input){const generation=revision,selectedMode=mode;const token={snapshot:{version:1,featureId:'product_assist',
    policyVersion:'bounded-product-data-and-catalog-neighbors-v1',mode,generation,modeStamp:String(revision).repeat(64),scope:input},
    async assertCurrent(){if(revision!==generation||mode!==selectedMode)throw Object.assign(Error('Mode changed'),{code:'SECURESHOP_FEATURE_MODE_STALE'});}};tokens.add(token);return token;},
    assertToken(token){assert.ok(tokens.has(token));return token;}};
  const personaAuthority={async capture(input){await check();return {binding:{...input.scope,personaId:input.personaId,role:input.role,
    sessionId:input.sessionId,authorityVersion:input.authorityVersion},assertRemoteAdmission:check,
    withCrossStoreEffect:async fn=>{await check();return fn();},withPersonaEffect:async fn=>{await check();return fn();}};}};
  const coordinator={async run(owner,options,work){const admitted=await options.admit();if(admitted.skip)return admitted.value;
    const runId=randomUUID();runs.set(runId,{status:'running'});
    try { const result=await work({runId,ownerKey:JSON.stringify(['SecureShopBoundConversation',owner]),generation:0,durableGeneration:'0',signal:options.signal,
      check,async effect(_key,fn){return fn();},async trace(){}});runs.get(runId).status='completed';return result; }
    catch(error){runs.get(runId).status='failed';throw error;}}};
  const value=observation||{seed:{id:7,name:'Owned'},results:[{id:8,name:'Neighbor'}],count:1,mode:'manuals',
    retrieved_context:[{sourceKind:'manual',sourceId:1,chunkIndex:0,text:'Original owned raw manual',score:0.8}]};
  const provider={async chat(){counts.actor++;await chatHook?.();return {provider:'ollama',model:'controlled-test',mocked:false,stop_reason:'tool_use',
    tool_uses:[{id:'original-call',name:'product-search.similar',args:{product_id:7}}],usage:{input_tokens:0,output_tokens:0}};},
    async finalResponse(){counts.actor++;return {provider:'ollama',model:'controlled-test',mocked:false,text:'Observed original recommendation.',stop_reason:'end_turn',responseMode:'structured_final',usage:{input_tokens:0,output_tokens:0}};}};
  const assist=createSecureShopBoundProductAssist({launches:{assertCurrent:check},conversationRepository:repository,journal,coordinator,
    provider,personaAuthority,modeAuthority,catalog:{async getProduct(input){counts.catalog++;return input.productId===7?{product:{id:7}}:null;}},
    scenes:{async readRetained(){counts.sceneReads++;await check();return target;}},
    afterSimilarCommit:async packet=>{counts.postCommit++;callbackRuns.push(runs.get(packet.execution.runId)?.status);
      assert.equal(requests.get(key(packet)).status,'completed');assert.equal(runs.get(packet.execution.runId)?.status,'completed');await afterCommit?.(packet);},
    async createProductTools(input){
      if(fixedFactory){const {createSecureShopBoundProductTools}=require('../server/services/secureshopBoundProductTools');
        const seed={id:7,name:'Owned',price:10,stock_quantity:1,category:'Home',description:'Owned catalog'};
        return createSecureShopBoundProductTools({...input,catalog:{async getProduct(){return {product:seed};},
          async listProducts(){return {products:[seed],total:1};}},retrieval:{async similar(){throw Error('Fixed must not retrieve');}}});}
      return new Map([['product-search.similar',async()=>{counts.tools++;await toolHook?.();
      input.captureManualRagSource?.({target:JSON.parse(JSON.stringify(target)),lineage:capture||{eligible:false,reason:'missing_original'},
        ...(protectedCapture || {})});
      return {content:[{type:'text',text:JSON.stringify(value)}]};}]]);}
  });
  const base={scope,persona,personaSession,productId:7};
  return {assist,base,counts,requests,runs,callbackRuns,key,value,async input(){return {...base,...await assist.createSimilarSession(base),requestId:randomUUID()};},
    setMode(){mode='fixed';revision++;},revoke(){current=false;},switchScene(){target=createSceneBinding({...scope,generation:1,targetId:randomUUID()},
      {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:fn=>fn()});}};
}

test('explicit session admission precedes one original run; saved GET and exact completed replay add no actor/tool/commit',async()=>{
  const f=fixture(),input=await f.input();assert.equal(f.counts.actor,0);assert.equal(f.counts.tools,0);
  const missing=await f.assist.readSimilar(input);assert.deepEqual(missing,{status:'not_found',sessionId:input.sessionId,requestId:input.requestId});
  const result=await f.assist.runSimilar(input);assert.equal(result.sessionId,input.sessionId);assert.equal(result.requestId,input.requestId);
  assert.equal(f.counts.actor,2);assert.equal(f.counts.tools,1);assert.equal(f.counts.postCommit,1);
  const before={...f.counts};const saved=await f.assist.readSimilar(input);
  assert.deepEqual(saved,{status:'completed',result});assert.equal(f.counts.catalog,before.catalog);
  for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);
  assert.deepEqual(await f.assist.runSimilar(input),result);
  for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);
});
test('strict malformed/foreign identity, changed product/hash and original persona session cannot recover or rerun another request',async()=>{
  const f=fixture(),input=await f.input();await f.assist.runSimilar(input);const before={...f.counts};
  for(const changed of [{requestId:'bad'},{sessionId:randomUUID()},{productId:8},
    {personaSession:{...input.personaSession,sessionId:randomUUID()}},
    {personaSession:{...input.personaSession,authorityVersion:'3'}}])await assert.rejects(f.assist.readSimilar({...input,...changed}));
  await assert.rejects(f.assist.runSimilar({...input,requestId:'bad'}),{code:'INVALID_ARGUMENT'});
  await assert.rejects(f.assist.runSimilar({...input,productId:8}),{code:'TURN_REQUEST_CONFLICT'});
  const row=f.requests.get(f.key(input));row.request_hash='a'.repeat(64);await assert.rejects(f.assist.readSimilar(input),{code:'PRODUCT_MODEL_UNAVAILABLE'});
  for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);
});
test('pending/uncertain are GET-only states; mode, scene, revocation and interrupted read stay fenced',async()=>{
  for(const status of ['started','uncertain']){const f=fixture(),input=await f.input();await f.assist.runSimilar(input);
    f.requests.get(f.key(input)).status=status;const before={...f.counts};
    assert.deepEqual(await f.assist.readSimilar(input),{status:'pending',sessionId:input.sessionId,requestId:input.requestId});
    await assert.rejects(f.assist.runSimilar(input),{code:'TURN_RECOVERY_REQUIRED'});assert.equal(f.counts.actor,before.actor);assert.equal(f.counts.tools,before.tools);}
  for(const change of ['setMode','switchScene','revoke']){const f=fixture(),input=await f.input();await f.assist.runSimilar(input);f[change]();await assert.rejects(f.assist.readSimilar(input));}
  let release,entered;const gate=new Promise(r=>release=r),started=new Promise(r=>entered=r);
  const f=fixture({readHook:async()=>{entered();await gate;}}),input=await f.input();await f.assist.runSimilar(input);
  const reading=f.assist.readSimilar(input);await started;f.revoke();release();await assert.rejects(reading,{code:'SHOP_AUTH_INVALID'});
});
test('private lineage persists before postcommit while oversized input stays explicitly ineligible and public DTO unchanged',async()=>{
  const capture={eligible:true,version:1,original:'private canonical original'};
  const f=fixture({capture}),input=await f.input(),result=await f.assist.runSimilar(input);
  assert.equal(Object.hasOwn(result,'manualRagConsumerOrigin'),false);
  assert.deepEqual(f.requests.get(f.key(input)).result_json.taskMetadata.manualRagConsumerOrigin.lineage,capture);
  const large=fixture({capture:{eligible:true,version:1,original:'x'.repeat(70000)}}),largeInput=await large.input();
  const ordinary=await large.assist.runSimilar(largeInput),saved=await large.assist.readSimilar(largeInput);
  assert.deepEqual(saved.result,ordinary);
  assert.deepEqual(large.requests.get(large.key(largeInput)).result_json.taskMetadata.manualRagConsumerOrigin.lineage,
    {eligible:false,reason:'metadata_limit'});
  assert.equal(large.counts.actor,2);assert.equal(large.counts.tools,1);
});

test('protected source capture is additive, saved before callback and does not rerun on recovery',async()=>{
  // Controlled capture exercises persistence only, not source qualification.
  const capture={eligible:false,reason:'missing_original'};
  const protectedCapture={protectedLineage:{eligible:true,version:2,original:'private source reference'},
    query:{version:1,kind:'product_name_description',text:'Owned\nPublic topic'}};
  const f=fixture({capture,protectedCapture}),input=await f.input();
  const result=await f.assist.runSimilar(input),row=f.requests.get(f.key(input));
  const metadata=row.result_json.taskMetadata,origin=metadata.protectedManualConsumerOrigin;
  assert.deepEqual(metadata.manualRagConsumerOrigin.lineage,capture);
  assert.deepEqual(origin.lineage,protectedCapture.protectedLineage);
  assert.deepEqual(origin.query,protectedCapture.query);
  assert.deepEqual(origin.source,{sessionId:input.sessionId,requestId:input.requestId});
  assert.deepEqual(origin.traceEventIds,metadata.manualRagConsumerOrigin.traceEventIds);
  assert.equal(Object.hasOwn(result,'protectedManualConsumerOrigin'),false);
  assert.deepEqual(result.retrieved_context,f.value.retrieved_context);
  assert.equal(result.recommendation,'Observed original recommendation.');
  const before={...f.counts};
  assert.deepEqual((await f.assist.readSimilar(input)).result,result);
  assert.deepEqual(await f.assist.runSimilar(input),result);
  for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);
});

test('oversized protected capture cannot evict public source metadata or truncate original context',async()=>{
  const capture={eligible:true,version:1,original:'public reference retained'};
  const f=fixture({capture,protectedCapture:{protectedLineage:{eligible:true,version:2,original:'x'.repeat(70000)},
    query:{text:'Owned\nPublic topic'}}}),input=await f.input();
  const result=await f.assist.runSimilar(input),metadata=f.requests.get(f.key(input)).result_json.taskMetadata;
  assert.equal(Object.hasOwn(metadata,'protectedManualConsumerOrigin'),false);
  assert.deepEqual(metadata.manualRagConsumerOrigin.lineage,capture);
  assert.ok(Buffer.byteLength(JSON.stringify(metadata))<=65536);
  assert.deepEqual(result.retrieved_context,f.value.retrieved_context);
  assert.deepEqual((await f.assist.readSimilar(input)).result,result);
  assert.equal(f.counts.actor,2);assert.equal(f.counts.tools,1);
});

test('production tool factory forwards only its server-owned private callback; fixed catalog path performs no retrieval capture',async()=>{
  const {createSecureShopBoundProductTools}=require('../server/services/secureshopBoundProductTools');
  const f=fixture(),captured=[];let retrieves=0;
  const seed={id:7,name:'Owned',price:10,stock_quantity:1,category:'Home',description:'Owned catalog'};
  const catalog={async getProduct(){return {product:seed};},async listProducts(){return {products:[seed],total:1};}};
  const retrieval={async similar(input){retrieves++;input.captureManualRagSource({lineage:{eligible:false,reason:'missing_original'}});return f.value;}};
  const create=mode=>createSecureShopBoundProductTools({...f.base,operation:'similar',mode,catalog,retrieval,
    checkCurrent:async()=>{},captureManualRagSource:value=>captured.push(value)});
  const value=await create('vuln').get('product-search.similar')({product_id:7});
  assert.deepEqual(JSON.parse(value.content[0].text),f.value);assert.equal(retrieves,1);assert.equal(captured.length,1);
  const fixed=await create('fixed').get('product-search.similar')({product_id:7});
  assert.equal(JSON.parse(fixed.content[0].text).mode,'catalog');
  assert.deepEqual(JSON.parse(fixed.content[0].text).retrieved_context,[]);
  assert.equal(retrieves,1);assert.equal(captured.length,1);
});


test('near-cap ordinary source is preserved through v2 original, saved GET and POST replay without metadata overflow',async()=>{
  const {canonicalDigest}=require('../server/services/mcp/protocolContext');
  const value={seed:{id:7,name:'Owned'},results:[],count:0,mode:'manuals',retrieved_context:[
    {sourceKind:'manual',sourceId:1,chunkIndex:0,text:'',score:0.8}]};
  const overhead=Buffer.byteLength(JSON.stringify({productAssist:{version:1,operation:'similar',productId:7,observation:value,
    provider:'ollama',model:'controlled-test'}}));
  value.retrieved_context[0].text='x'.repeat(65520-overhead);
  const f=fixture({observation:value}),input=await f.input(),result=await f.assist.runSimilar(input);
  const row=f.requests.get(f.key(input));
  assert.equal(row.result_json.taskMetadata.productAssist.version,2);
  assert.ok(Buffer.byteLength(JSON.stringify(row.result_json.taskMetadata))<65536);
  assert.equal(result.retrieved_context[0].text,value.retrieved_context[0].text);
  assert.equal(JSON.parse(row.result_json.hops[0].result.content[0].text).retrieved_context[0].text,value.retrieved_context[0].text);
  // PostgreSQL may reorder JSONB object keys, without modifying the original
  // MCP text string. The pointer must survive that normal storage round trip.
  const original=row.result_json.hops[0].result;
  row.result_json.hops[0].result={content:[{text:original.content[0].text,type:'text'}]};
  assert.equal(canonicalDigest(row.result_json.hops[0].result),row.result_json.taskMetadata.productAssist.observationHop.observationSha256);
  const before={...f.counts};assert.deepEqual((await f.assist.readSimilar(input)).result,result);
  assert.deepEqual(await f.assist.runSimilar(input),result);
  for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);
  const legacy=fixture({observation:value}),old=await legacy.assist.similar(legacy.base);
  assert.equal(old.retrieved_context[0].text,value.retrieved_context[0].text);
  const legacyRow=[...legacy.requests.values()][0];assert.equal(legacyRow.result_json.taskMetadata.productAssist.version,1);
  assert.equal(Object.hasOwn(legacyRow.result_json.taskMetadata,'manualRagConsumerOrigin'),false);
});
test('v2 digest, wrong step/product/result and duplicate successful hop substitutions deny GET and replay without new work',async()=>{
  const mutations=[r=>r.taskMetadata.productAssist.observationHop.observationSha256='a'.repeat(64),
    r=>r.taskMetadata.productAssist.observationHop.step=3,r=>r.hops[0].params.product_id=8,
    r=>r.hops[0].result.content[0].text=r.hops[0].result.content[0].text.replace('Owned','Changed'),
    r=>r.hops.push({...structuredClone(r.hops[0]),step:2}),r=>r.hops[0].error='failed'];
  for(const mutate of mutations){const f=fixture(),input=await f.input();await f.assist.runSimilar(input);const before={...f.counts};
    mutate(f.requests.get(f.key(input)).result_json);
    await assert.rejects(f.assist.readSimilar(input),{code:'PRODUCT_MODEL_UNAVAILABLE'});
    await assert.rejects(f.assist.runSimilar(input),{code:'PRODUCT_MODEL_UNAVAILABLE'});
    for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);}
});
test('current scene is fenced during actor/retrieval and completed POST replay after mode, scene or persona changes',async()=>{
  for(const stage of ['chatHook','toolHook']){let f;f=fixture({[stage]:async()=>f.switchScene()});const input=await f.input();
    await assert.rejects(f.assist.runSimilar(input));assert.equal(f.counts.commits,0);assert.equal(f.counts.postCommit,0);
    if(stage==='chatHook')assert.equal(f.counts.tools,0);}
  for(const changed of ['setMode','switchScene']){const f=fixture(),input=await f.input();await f.assist.runSimilar(input);const before={...f.counts};
    f[changed]();await assert.rejects(f.assist.runSimilar(input));
    for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);}
  const f=fixture(),input=await f.input();await f.assist.runSimilar(input);const before={...f.counts};
  await assert.rejects(f.assist.runSimilar({...input,personaSession:{...input.personaSession,sessionId:randomUUID()}}));
  assert.equal(f.counts.actor,before.actor);assert.equal(f.counts.tools,before.tools);
});
test('strict fixed catalog run has ordinary v2 saved read/replay without requiring poisoning lineage',async()=>{
  const f=fixture({fixedFactory:true});f.setMode();const input=await f.input(),result=await f.assist.runSimilar(input);
  assert.equal(result.mode,'catalog');assert.deepEqual(result.retrieved_context,[]);
  assert.equal(result.modeCapability.effectiveMode,'fixed');
  assert.equal(result.modeCapability.policyVersion,'bounded-product-data-and-catalog-neighbors-v1','Summary-only policy must not invalidate existing Similar recovery');
  const row=f.requests.get(f.key(input));assert.equal(row.result_json.taskMetadata.productAssist.version,2);
  assert.equal(row.result_json.taskMetadata.manualRagConsumerOrigin.lineage.eligible,false);
  const before={...f.counts};assert.deepEqual((await f.assist.readSimilar(input)).result,result);
  assert.deepEqual(await f.assist.runSimilar(input),result);
  for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);
});


test('automatic source assessment observes completed coordinator run, skips replay, and cannot erase or mutate original result',async()=>{
  const seen=[];const f=fixture({afterCommit:async packet=>{
    seen.push({runId:packet.execution.runId,requestId:packet.requestId,replayed:Object.hasOwn(packet.result,'replayed')});
    packet.result.text='Attempted callback mutation';
    throw Object.assign(Error('controlled unavailable assessment'),{code:'DB_UNAVAILABLE'});
  }}),input=await f.input();
  const warnings=[],warn=console.warn;let result;
  try {console.warn=message=>warnings.push(message);result=await f.assist.runSimilar(input);}finally{console.warn=warn;}
  assert.deepEqual(f.callbackRuns,['completed']);assert.equal(seen.length,1);assert.equal(seen[0].requestId,input.requestId);
  assert.equal(seen[0].replayed,false);assert.equal(f.runs.get(seen[0].runId).status,'completed');
  assert.equal(result.recommendation,'Observed original recommendation.');
  assert.equal(f.requests.get(f.key(input)).result_json.text,'Observed original recommendation.');
  assert.equal(warnings.length,1);assert.match(warnings[0],/completed response retained/);
  const before={...f.counts};assert.deepEqual((await f.assist.readSimilar(input)).result,result);
  assert.deepEqual(await f.assist.runSimilar(input),result);assert.deepEqual(f.callbackRuns,['completed']);
  for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);
});
