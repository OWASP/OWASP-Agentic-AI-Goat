'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopBoundCommerce}=require('../server/services/secureshopBoundCommerce');
const scope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:2,platformOwnerId:7,platformSessionId:8};
const session={sessionId:'40000000-0000-4000-8000-000000000001',authorityVersion:'1'};
test('cart recovery identity derives from checked authority and changes with every isolation boundary',async()=>{
 const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(k=>[k,async()=>({items:[],subtotal:0})]));
 const catalog={prepareTarget:async()=>({targetId:'30000000-0000-4000-8000-000000000001'}),hasProduct:async()=>true};
 let checks=0;
 const personaAuthority={capture:async value=>({binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},assertRemoteAdmission:async()=>{checks++;},withCrossStoreEffect:async fn=>fn()})};
 const service=createSecureShopBoundCommerce({repository,catalog,personaAuthority});
 assert.equal(service.couponAvailable,false);
 assert.equal(createSecureShopBoundCommerce({repository,catalog,personaAuthority,
  couponWorkflow:{apply:async()=>({ok:true})}}).couponAvailable,true);
 const base={scope,persona:{id:41,role:'customer'},personaSession:session};
 const first=await service.cart(base);assert.match(first.couponScopeKey,/^[a-f0-9]{64}$/);assert.equal((await service.cart(base)).couponScopeKey,first.couponScopeKey);
 for(const next of [{...base,scope:{...scope,generation:3}},{...base,scope:{...scope,platformSessionId:9}},{...base,persona:{id:42,role:'customer'}},{...base,personaSession:{...session,authorityVersion:'2'}},{...base,personaSession:{...session,sessionId:'40000000-0000-4000-8000-000000000002'}}])assert.notEqual((await service.cart(next)).couponScopeKey,first.couponScopeKey);
 assert.ok(checks>=21);assert.equal(JSON.stringify(first).includes(session.sessionId),false);
});
test('coupon reference bridge roundtrip accepts only bounded reference fields',async()=>{
 const {validateShopSnapshot}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
 const key='secureshop.coupon.operation.v1',ref={scopeKey:'a'.repeat(64),digest:'b'.repeat(64),operationId:'10000000-0000-4000-8000-000000000001'};
 const snapshot={secureshop_v2_token:null,ss_guest_cart:null,[key]:JSON.stringify(ref)};
 assert.equal(validateShopSnapshot(snapshot)[key],snapshot[key]);
 for(const bad of [{...ref,code:'private'}, {...ref,operationId:'bad'}, {...ref,digest:'x'}, {...ref,digest:[ref.digest]}])assert.throws(()=>validateShopSnapshot({...snapshot,[key]:JSON.stringify(bad)}));
});
