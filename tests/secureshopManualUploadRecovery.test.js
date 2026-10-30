'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const contract = require('../server/services/secureshopManualUploadRecoveryContract');
const {createSecureShopBoundManualIngestion} = require('../server/services/secureshopBoundManualIngestion');
const {createSecureShopBoundCatalog} = require('../server/services/secureshopBoundCatalog');
const {createSceneBinding} = require('../server/services/secureshopSceneBinding');
const scope = Object.freeze({launchId:'10000000-0000-4000-8000-000000000001',
  scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:1,platformSessionId:2});
const persona = Object.freeze({id:12,role:'merchant'});
const personaSession = Object.freeze({sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'1'});
const descriptor = Object.freeze({productId:7,sha256:'a'.repeat(64),sizeBytes:5,
  filename:'../../manual.html',mime:'text/custom',isPublic:false});
function scene(generation = 1) {
  return createSceneBinding({...scope,targetId:'40000000-0000-4000-8000-000000000001'}, {
    sceneId:'50000000-0000-4000-8000-000000000001',sceneGeneration:generation,
    grantId:'60000000-0000-4000-8000-000000000001',execution:scope,withLease:async work=>work()});
}
function indexed() {
  return {operationId:contract.manualUploadOperationId(scope,persona.id,descriptor),merchantId:persona.id,
    productId:7,fileReceipt:{sha256:descriptor.sha256,bytes:5},filename:descriptor.filename,mime:descriptor.mime,
    isPublic:false,documentCount:2,manualSourceId:31,chunkIds:['manual:31:0','manual:31:1'],
    completedAt:'2026-10-19T00:00:00.000Z',provider:'not-a-completion',replayed:true};
}
function fixture() {
  const state = {binding:scene(),receipt:null,active:true,revoked:false,session:personaSession,reads:0,retained:0,checks:0,onRead:null};
  const forbidden = async()=>assert.fail('Recovery invoked model/provision/write/embedding/conversation work');
  const authority = {capture: input=>({binding:{...input.scope,...input},
    async assertRemoteAdmission() {state.checks++;if(!state.active || state.revoked
      || input.sessionId !== state.session.sessionId || input.authorityVersion !== state.session.authorityVersion)
      throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});},
    withCrossStoreEffect:forbidden})};
  const catalog = {getOwnedMerchantProduct:forbidden,async readRetainedOwnedMerchantProduct(input) {
    state.retained++;
    assert.equal(input.persona.id,persona.id);assert.deepEqual(input.personaSession,state.session);
    return {binding:state.binding,product:{id:7,retailer_id:12,status:'active'}};
  }};
  const ingestion = createSecureShopBoundManualIngestion({launches:{async assertCurrent(input){
    assert.deepEqual(input,scope);if(!state.active)throw Object.assign(Error('stale'),{code:'STALE_LAUNCH'});
  }},conversationRepository:{acquireBoundSession:forbidden},journal:{},coordinator:{run:forbidden},
  provider:{chat:forbidden,finalResponse:forbidden},catalog,retrieval:{ensureProvisioned:forbidden},
  writer:{writeAndReadBack:forbidden},extractor:forbidden,embedder:{embed:forbidden},personaAuthority:authority,
  repository:{appendManual:forbidden,async readReceipt(binding,{operationId}) {
    assert.equal(binding,state.binding);assert.equal(operationId,contract.manualUploadOperationId(scope,12,descriptor));
    state.reads++;await state.onRead?.();
    if(!state.receipt)throw Object.assign(Error('absent'),{code:'BOUND_MANUAL_INGEST_RECEIPT_UNAVAILABLE'});
    return state.receipt;
  }}});
  const read = overrides=>ingestion.readReceipt({scope,persona,personaSession,descriptor,...overrides});
  return {state,read,ingestion};
}
test('descriptor operation identity preserves historical v1 bytes without exposing scope', () => {
  const hash=createHash('sha256').update(JSON.stringify(['owasp-ai-goat-manual-v1',scope,12,7,descriptor.sha256,
    descriptor.filename,descriptor.mime,false])).digest('hex');
  assert.equal(contract.manualUploadOperationId(scope,12,descriptor),
    `${hash.slice(0,8)}-${hash.slice(8,12)}-5${hash.slice(13,16)}-a${hash.slice(17,20)}-${hash.slice(20,32)}`);
  assert.deepEqual(contract.normalizeManualUploadDescriptor(descriptor),descriptor);
  for(const patch of [{sha256:'A'.repeat(64)},{sizeBytes:0},{sizeBytes:20971521},{filename:'bad\nname'},
    {mime:''},{isPublic:'false'},{productId:0},{extra:true}])
    assert.throws(()=>contract.normalizeManualUploadDescriptor({...descriptor,...patch}),{code:'INVALID_ARGUMENT'});
  const accessor={...descriptor};Object.defineProperty(accessor,'mime',{get(){assert.fail('getter invoked');}});
  assert.throws(()=>contract.normalizeManualUploadDescriptor(accessor),{code:'INVALID_ARGUMENT'});
});
test('read-only absent observation can later become indexed without a second upload or claimed model completion', async()=>{
  const f=fixture();const first=await f.read();
  assert.deepEqual(first,{version:1,kind:'product_manual',operationId:contract.manualUploadOperationId(scope,12,descriptor),
    recoveryScopeKey:contract.manualUploadRecoveryScopeKey(f.state.binding,12,personaSession),state:'not_found',receipt:null});
  f.state.receipt=indexed();const next=await f.read({recoveryScopeKey:first.recoveryScopeKey});
  assert.equal(next.state,'indexed');assert.equal(next.receipt.chunkCount,2);
  assert.deepEqual(Object.keys(next).sort(),['kind','operationId','receipt','recoveryScopeKey','state','version']);
  assert.deepEqual(Object.keys(next.receipt).sort(),['chunkCount','chunkIds','completedAt','filename','isPublic','mime','productId','sha256','sizeBytes']);
  assert.equal(f.state.reads,2);assert.equal(f.state.retained,4);
  assert.equal(JSON.stringify(next).includes('provider'),false);assert.equal(JSON.stringify(next).includes('replayed'),false);
});
test('null/absent lookup still revalidates reset and retained scene before returning',async()=>{
  for(const change of [f=>{f.state.active=false;},f=>{f.state.binding=scene(2);},f=>{f.state.revoked=true;}]){
    const f=fixture();f.state.onRead=()=>change(f);
    await assert.rejects(f.read(),error=>['STALE_LAUNCH','UPLOAD_RECOVERY_SCOPE_STALE','SHOP_AUTH_INVALID'].includes(error.code));
  }
});
test('current login cannot reuse an old recovery key, and SQL errors never become not_found',async()=>{
  const f=fixture();const original=await f.read();
  f.state.session={...personaSession,authorityVersion:'2'};
  await assert.rejects(f.read({personaSession:f.state.session,recoveryScopeKey:original.recoveryScopeKey}),
    {code:'UPLOAD_RECOVERY_SCOPE_STALE'});
  assert.equal(f.state.reads,1);
  await assert.rejects(f.read(),{code:'SHOP_AUTH_INVALID'});
  const g=fixture();g.state.onRead=()=>{throw Object.assign(Error('database unavailable'),{code:'57P01'});};
  await assert.rejects(g.read(),{code:'57P01'});
});
test('stale recovery key, scene and shop session fail before receipt access',async()=>{
  const f=fixture();const first=await f.read();f.state.binding=scene(2);
  await assert.rejects(f.read({recoveryScopeKey:first.recoveryScopeKey}),{code:'UPLOAD_RECOVERY_SCOPE_STALE'});
  assert.equal(f.state.reads,1);
  const key=contract.manualUploadRecoveryScopeKey(scene(),12,personaSession);
  for(const changed of [{...personaSession,authorityVersion:'2'},
    {...personaSession,sessionId:'30000000-0000-4000-8000-000000000002'}])
    assert.notEqual(contract.manualUploadRecoveryScopeKey(scene(),12,changed),key);
  assert.notEqual(contract.manualUploadRecoveryScopeKey(scene(),13,personaSession),key);
  await assert.rejects(f.read({recoveryScopeKey:''}),{code:'INVALID_ARGUMENT'});
});
test('indexed projection rejects every descriptor mismatch and foreign merchant, never accepts model completion fields',()=>{
  const original=indexed();
  for(const patch of [{productId:8},{merchantId:13},{filename:'other'},{mime:'other'},{isPublic:true},
    {operationId:'00000000-0000-4000-8000-000000000000'},{fileReceipt:{sha256:'b'.repeat(64),bytes:5}},
    {fileReceipt:{sha256:descriptor.sha256,bytes:6}},{chunkIds:['manual:31:1','manual:31:0']}])
    assert.throws(()=>contract.projectManualUploadReceipt({...original,...patch},descriptor,12,original.operationId),
      {code:'BOUND_MANUAL_INGEST_MISMATCH'});
});
test('foreign/reset execution scope cannot select a receipt from the original binding',async()=>{
  const f=fixture();
  for(const changed of [{...scope,platformSessionId:3},{...scope,platformOwnerId:2},{...scope,generation:2}])
    await assert.rejects(f.read({scope:changed}));
  assert.equal(f.state.reads,0);
});
test('catalog recovery uses retained reads and exact ownership, never source/provision/adopt/grant',async()=>{
  let selected=scene(),owner=12,exists=true;const calls=[];
  const forbidden=async()=>assert.fail('Read-only catalog path attempted preparation');
  const repository={open:async()=>({ownMerchantId:12}),get:async(binding,id)=>{
    calls.push(id);assert.equal(binding,selected);return exists?{id,retailer_id:owner,status:'inactive'}:null;
  },provision:forbidden,list:forbidden,categories:forbidden,createListing:forbidden,updateListing:forbidden,archiveListing:forbidden};
  const catalog=createSecureShopBoundCatalog({sourcePool:{query:forbidden},repository,resolveTarget:forbidden,
    checkCurrent:async value=>assert.deepEqual(value,scope),scenes:{resolve:forbidden,finalize:forbidden,readRetained:async()=>selected}});
  const args={scope,persona,productId:7};
  assert.equal((await catalog.readRetainedOwnedMerchantProduct(args)).product.status,'inactive');
  owner=13;await assert.rejects(catalog.readRetainedOwnedMerchantProduct(args),{code:'OWNER_MISMATCH'});
  exists=false;await assert.rejects(catalog.readRetainedOwnedMerchantProduct(args),{code:'OWNER_MISMATCH'});
  selected=null;await assert.rejects(catalog.readRetainedOwnedMerchantProduct(args),{code:'SHOP_SCENE_STALE'});
  assert.deepEqual(calls,[7,7,7]);
});
test('retained corpus pages cannot silently select a different scene or invoke catalog preparation',async()=>{
  let selected=scene();const original=selected;let lists=0;
  const forbidden=async()=>assert.fail('retained read attempted preparation');
  const effect=require('../server/services/secureshopPersonaProductEffect').createPersonaProductEffect({
    binding:{...scope,personaId:12,role:'merchant'},assertRemoteAdmission:async()=>{},withCrossStoreEffect:forbidden});
  const catalog=createSecureShopBoundCatalog({sourcePool:{query:forbidden},resolveTarget:forbidden,checkCurrent:async()=>{},
    scenes:{resolve:forbidden,finalize:forbidden,readRetained:async()=>selected},repository:{
      open:async()=>({ownMerchantId:12}),get:forbidden,provision:forbidden,categories:forbidden,
      createListing:forbidden,updateListing:forbidden,archiveListing:forbidden,
      list:async(binding,query)=>{lists++;assert.equal(binding.targetId,original.targetId);assert.equal(query.status,'active');
        return {rows:[{id:7}],total:1};}}});
  const args={scope,persona,personaEffect:effect,binding:original,offset:0,limit:100};
  assert.deepEqual(await catalog.listRetainedManualProducts(args),{products:[{id:7}],total:1});
  selected=scene(2);await assert.rejects(catalog.listRetainedManualProducts(args),{code:'SHOP_SCENE_STALE'});
  assert.equal(lists,1);
});
