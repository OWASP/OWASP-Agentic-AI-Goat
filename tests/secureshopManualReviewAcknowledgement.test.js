'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const reviewScene=require('../server/services/secureshopReviewSceneBinding');
const {createManualReviewDecision}=require('../server/services/secureshopManualReviewDecision');

const birth={targetId:'12345678-1234-4123-8123-123456789ab1',launchId:'12345678-1234-4123-8123-123456789ab2',scenarioId:'12345678-1234-4123-8123-123456789ab3',generation:1,platformOwnerId:16,platformSessionId:164};
const current={launchId:'12345678-1234-4123-8123-123456789ab4',scenarioId:'12345678-1234-4123-8123-123456789ab5',generation:1,platformOwnerId:16,platformSessionId:292};
const actor={id:1000000001,role:'merchant'},sessionId='12345678-1234-4123-8123-123456789ab6',operationId='12345678-1234-4123-8123-123456789ab7';
const scene=createSceneBinding({...birth,targetId:'12345678-1234-4123-8123-123456789ab8'},{sceneId:'12345678-1234-4123-8123-123456789ab9',sceneGeneration:1,grantId:'12345678-1234-4123-8123-123456789aba',execution:current,withLease:work=>work()});
const target=reviewScene.attach(birth,scene);
const expectedKey=JSON.stringify([current.launchId,current.generation,current.platformOwnerId,current.platformSessionId,actor.id,sessionId]);
const receipt={operationId,kind:'manual',moderatorKind:'manual',reviewId:7,decision:'approved',notes:null,applied:true,resultStatus:'approved',scope:{...birth},actor:{...actor,personaSessionId:sessionId,authorityVersion:'1'}};
const input={scope:current,persona:actor,personaSession:{sessionId,authorityVersion:'1'},operationId,reviewId:7,decision:'approve'};

function fixture(selected=receipt){
 let decides=0,reads=0;
 const authority={capture:({scope,personaId,role,sessionId:captured,authorityVersion})=>({binding:{...scope,personaId,role,sessionId:captured,authorityVersion},assertRemoteAdmission:async()=>{},withCrossStoreEffect:work=>work()})};
 const repository={decide:async()=>{decides++;return{applied:true,receipt:selected}},readDecisionReceipt:async()=>{reads++;return selected}};
 const service=createManualReviewDecision({authority,repository,resolveTarget:async()=>target});
 return {service,counts:()=>({decides,reads})};
}

test('scene review acknowledgement keeps immutable birth receipt separate from current execution',async()=>{
 const {service,counts}=fixture();
 assert.equal((await service.capability(input)).scopeKey,expectedKey);
 const applied=await service.decide(input);
 assert.equal(applied.executionScopeKey,expectedKey);
 assert.deepEqual(applied.receipt.scope,birth);
 const recovered=await service.read(input);
 assert.equal(recovered.executionScopeKey,expectedKey);
 assert.equal(recovered.receipt,receipt);
 assert.deepEqual(counts(),{decides:1,reads:1});
});

test('saved read performs no decision and rejects mismatched birth, actor, session or version',async()=>{
 for(const changed of [
  {...receipt,scope:{...birth,targetId:'12345678-1234-4123-8123-123456789abb'}},
  {...receipt,scope:{...birth,platformOwnerId:17}},
  {...receipt,actor:{...receipt.actor,id:1000000002}},
  {...receipt,actor:{...receipt.actor,personaSessionId:'12345678-1234-4123-8123-123456789abc'}},
  {...receipt,actor:{...receipt.actor,authorityVersion:'2'}},
 ]){
  const {service,counts}=fixture(changed);
  await assert.rejects(service.read(input),{code:'SHOP_AUTH_INVALID'});
  assert.deepEqual(counts(),{decides:0,reads:1});
 }
});

test('POST rejects a receipt for a different action or review after effect admission',async()=>{
 for(const changed of [
  {...receipt,reviewId:8},
  {...receipt,decision:'rejected'},
  {...receipt,notes:'different'},
 ]){
  const {service}=fixture(changed);
  await assert.rejects(service.decide(input),{code:'SHOP_AUTH_INVALID'});
 }
 const {service}=fixture();
 assert.equal((await service.decide({...input,operationId:operationId.toUpperCase()})).receipt.operationId,operationId);
});
