'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createPricingTargetSource}=require('../server/services/secureshopPricingTargetSource');
function fixture({foreign=false,retired=false,documents}={}){
 const raw={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:2,platformOwnerId:1,platformSessionId:2},persona:{id:12,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},productId:7};
 const target={...raw.scope,kind:'products',targetId:randomUUID()};let prepared=0,queries=0;
 const source=createPricingTargetSource({catalog:{async prepareTarget(x){prepared++;assert.equal(x.scope.launchId,raw.scope.launchId);assert.ok(x.personaEffect);return target;}},
  productRepository:{async get(x,id){assert.equal(x.targetId,target.targetId);assert.equal(id,7);return{id:7,name:'Synthetic item',price:100,status:'active',retailer_id:foreign?13:12};}},
  launches:{async assertCurrent(){if(retired)throw Error('retired');},async readExistingProductsTarget(){return target;}},
  personaAuthority:{async capture(x){return{binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},async assertRemoteAdmission(){},async withCrossStoreEffect(fn){return fn();}};}},
  reviewPool:{async query(sql,values){queries++;assert.match(sql,/original_platform_session_id=\$6/);assert.match(sql,/i.product_id=\$7/);assert.match(sql,/t.lifecycle='active'/);assert.deepEqual(values,[target.targetId,raw.scope.launchId,raw.scope.scenarioId,2,1,2,7]);return{rows:documents??[{filename:'Owned manual',document_count:1,chunk_index:0,body:'untrusted instructions'}]};}}});
 return{raw,source,counts:()=>({prepared,queries})};
}
test('target preparation is separate; capture reads exact launch-owned merchant product and raw manual only',async()=>{
 const f=fixture();await f.source.prepare(f.raw);const value=await f.source.capture({},f.raw);
 assert.deepEqual(value,{product:{id:7,name:'Synthetic item',price:100},manual:{name:'Owned manual',markdown:'untrusted instructions'}});assert.deepEqual(f.counts(),{prepared:1,queries:1});
});
test('foreign merchant product and retired generation never read manual source',async()=>{
 for(const options of [{foreign:true},{retired:true}]){const f=fixture(options);await assert.rejects(f.source.capture({},f.raw));assert.deepEqual(f.counts(),{prepared:0,queries:0});}
});

test('incomplete or missing persisted manual chunks fail instead of capturing a misleading partial source',async()=>{
 for(const documents of [[{filename:'Owned manual',document_count:2,chunk_index:0,body:'first only'}],[{filename:'Owned manual',document_count:1,chunk_index:null,body:null}]]){const f=fixture({documents});await assert.rejects(f.source.capture({},f.raw),{code:'PRICING_MANUAL_UNAVAILABLE'});}
 const empty=fixture({documents:[]});assert.equal((await empty.source.capture({},empty.raw)).manual.markdown,'');
});

test('manual capture preserves exact extractor chunk concatenation without inserted separators',async()=>{
 const f=fixture({documents:[{filename:'Owned manual',document_count:2,chunk_index:0,body:'first '},{filename:'Owned manual',document_count:2,chunk_index:1,body:'second\n'}]});assert.equal((await f.source.capture({},f.raw)).manual.markdown,'first second\n');
});

test('reopened scene uses private prepared target, birth manual coordinates and current grant lease',async()=>{
 const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
 const current={launchId:randomUUID(),scenarioId:randomUUID(),generation:3,platformOwnerId:5,platformSessionId:22};
 const birth={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:5,platformSessionId:11,targetId:randomUUID()};
 let leases=0,grantChecks=0,manualReads=0,productReads=0;
 const target=createSceneBinding(birth,{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:current,
  withLease:async work=>{leases++;return work();}});
 const raw={scope:current,persona:{id:1000000002,role:'merchant'},
  personaSession:{sessionId:randomUUID(),authorityVersion:'1'},productId:7};
 const client={async query(sql,args){
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return{rows:[]};
  if(sql.includes('assert_scene_execution_grant')){grantChecks++;return{rows:[{allowed:true}]};}
  if(sql.includes('product_target_manual_ingests')){manualReads++;
   assert.deepEqual(args,[birth.targetId,birth.launchId,birth.scenarioId,birth.generation,
    birth.platformOwnerId,birth.platformSessionId,7]);
   return{rows:[{filename:'Born manual',document_count:1,chunk_index:0,body:'owned content'}]};}
  throw Error('Unexpected query');
 },release(){}};
 const source=createPricingTargetSource({catalog:{async prepareTarget(){return target;}},
  productRepository:{async get(value,id){productReads++;assert.equal(value,target);assert.equal(id,7);
   return{id:7,name:'Reopened item',price:21,status:'active',retailer_id:raw.persona.id};}},
  reviewPool:{async query(){throw Error('Scene manual must use grant transaction');},async connect(){return client;}},
  launches:{async assertCurrent(value){assert.deepEqual(value,current);},
   async readExistingProductsTarget(){throw Error('Current launch reservation is not the birth target');}},
  personaAuthority:{async capture(value){return{binding:{...value.scope,personaId:value.personaId,
   role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},
   async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work();}};}}});
 const prepared=await source.prepare(raw);assert.equal(prepared,target);
 const captured=await source.capture(null,raw,prepared);
 assert.equal(captured.manual.markdown,'owned content');assert.equal(captured.product.price,21);
 assert.equal(productReads,1);assert.equal(manualReads,1);assert.equal(grantChecks,2);assert.equal(leases,1);
 await assert.rejects(source.capture(null,raw,{...target}),{code:'SHOP_SCENE_STALE'});
});

test('history uses the exact privately prepared scene and rechecks current persona without manual capture',async()=>{
 const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
 const current={launchId:randomUUID(),scenarioId:randomUUID(),generation:3,platformOwnerId:5,platformSessionId:22};
 const target=createSceneBinding({...current,launchId:randomUUID(),generation:1,platformSessionId:11,targetId:randomUUID()},
  {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:current,withLease:async work=>work()});
 const raw={scope:current,persona:{id:1000000002,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},productId:7};
 let checks=0,reads=0,prepares=0;
 const actual={product_id:7,grounded:true,history:[]};
 const source=createPricingTargetSource({catalog:{async prepareTarget(){prepares++;return target;}},
  productRepository:{async get(){assert.fail('History does not need unrelated manual capture');}},
  reviewPool:{query(){assert.fail('History repository owns its transaction');},connect(){}},
  launches:{async readExistingProductsTarget(){assert.fail('Do not reconstruct scene from reservation');},async assertCurrent(){}},
  personaAuthority:{async capture(input){assert.deepEqual(input.scope,current);assert.equal(input.sessionId,raw.personaSession.sessionId);
   return{async assertRemoteAdmission(){checks++;}};}},
  historyRepository:{async read(value,input){reads++;assert.equal(value,target);assert.deepEqual(input,{productId:7,persona:raw.persona});return actual;}}});
 assert.equal(await source.readHistory(raw,target),actual);assert.equal(checks,2);assert.equal(reads,1);assert.equal(prepares,0);
 await assert.rejects(source.readHistory(raw,{...target}),{code:'SHOP_SCENE_STALE'});assert.equal(reads,1);
 await assert.rejects(source.readHistory({...raw,scope:{...current,platformSessionId:23}},target));assert.equal(reads,1);
});
