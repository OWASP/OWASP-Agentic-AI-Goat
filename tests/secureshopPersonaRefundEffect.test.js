'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPersonaRefundEffect}=require('../server/services/secureshopPersonaRefundEffect');
const {createSecureShopBoundRefundTools}=require('../server/services/secureshopBoundRefundTools');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
test('candidate refund uses short store lease with stable exact invocation identity and preserves boundary errors',async()=>{
 const scope={launchId:'launch',scenarioId:'scenario',generation:1,platformOwnerId:1,platformSessionId:2},binding={...scope,personaId:3,role:'customer',sessionId:'session',authorityVersion:'1'};let held=false,revoked=false;const calls=[];
 const fence={binding,withCrossStoreEffect:async work=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});held=true;try{return await work();}finally{held=false;}}};
 const repository=createPersonaRefundEffect({fence,repository:{create:async(s,input)=>{assert.equal(held,true);calls.push(input);return{ok:true};}}});
 const tools=createSecureShopBoundRefundTools({repository,commerce:{order:async()=>{assert.equal(held,false);return{order:{id:4}};}},scope,persona:{id:3,role:'customer'},binding:{requestId:'request',runId:'run'},checkCurrent:async()=>{},resolveTarget:async()=>scope,fixedIntent:{orderId:4,reason:'original'}});
 const args={order_id:4,reason:'original'},invocation={callId:'call',step:1,tool:'support.refund_request'};
 await tools['support.order_status']({order_id:4});await tools['support.refund_request'](args,invocation);await tools['support.refund_request'](args,invocation);assert.equal(calls[0].operation.operationId,calls[1].operation.operationId);assert.equal(calls[0].reason,'original');assert.equal(calls[0].effectTimeoutMs,3000);
 revoked=true;await assert.rejects(tools['support.refund_request'](args,invocation),{code:'SHOP_AUTH_INVALID'});assert.equal(calls.length,2);
});

test('refund effect keeps immutable target birth while admitting only branded current execution',async()=>{
 const birth={targetId:'10000000-0000-4000-8000-000000000001',launchId:'20000000-0000-4000-8000-000000000001',scenarioId:'30000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:9,platformSessionId:19};
 const current={...birth,launchId:'20000000-0000-4000-8000-000000000002',platformSessionId:20};
 const target=createSceneBinding(birth,{sceneId:'40000000-0000-4000-8000-000000000001',sceneGeneration:1,
  grantId:'50000000-0000-4000-8000-000000000001',execution:current,withLease:work=>work()});
 let writes=0;
 const effect=createPersonaRefundEffect({fence:{binding:{...current,personaId:41,role:'customer',sessionId:'60000000-0000-4000-8000-000000000001',authorityVersion:'1'},withCrossStoreEffect:work=>work()},
  repository:{async create(input){writes++;assert.equal(input,target);return{ok:true};}}});
 const input={shopUserId:41,requestId:'70000000-0000-4000-8000-000000000001',runId:'80000000-0000-4000-8000-000000000001',orderId:12,reason:'duplicate charge'};
 const invocation={callId:'call',step:1,tool:'support.refund_request'};
 assert.deepEqual(await effect.create(target,input,invocation),{ok:true});
 await assert.rejects(effect.create(JSON.parse(JSON.stringify(target)),input,invocation),{code:'SHOP_SCENE_STALE'});
 const foreign=createSceneBinding(birth,{sceneId:'40000000-0000-4000-8000-000000000001',sceneGeneration:1,
  grantId:'50000000-0000-4000-8000-000000000002',execution:{...current,platformSessionId:21},withLease:work=>work()});
 await assert.rejects(effect.create(foreign,input,invocation),{code:'SHOP_AUTH_INVALID'});
 assert.equal(writes,1);
});
