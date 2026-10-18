'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {hash}=require('../server/services/secureshopCouponContract');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const {createCheckoutHistoryRepository}=require('../server/database/postgres/secureshopCheckoutHistoryRepository');
function fixture(){
 const birth={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:71,platformSessionId:72};
 const origin={...birth,launchId:randomUUID(),platformSessionId:73};
 const scope={...birth,launchId:randomUUID(),platformSessionId:74};
 const target=createSceneBinding({...birth,targetId:randomUUID()},{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:work=>work()});
 const actor=1000000001,operationId=randomUUID(),sessionId=randomUUID();
 const request={scope:origin,targetId:target.targetId,persona:{id:actor,role:'customer'},personaSession:{sessionId,authorityVersion:'1'},mode:'vuln',operationId,shippingAddress:'Synthetic address',paymentMethod:'Card ending 4242'};
 const result={orderId:7,total:9,subtotal:10,discount:1};
 const row={operation_id:operationId,target_id:target.targetId,shop_user_id:actor,kind:'checkout',persona_session_id:sessionId,authority_version:'1',mode:'vuln',state:'completed',request_json:JSON.stringify(request),result_json:JSON.stringify(result),created_at:new Date('2026-10-01T00:00:00Z')};
 row.request_sha256=hash(row.request_json);row.result_sha256=hash(row.result_json);
 const order={order_id:7,total_amount:'9.00',subtotal_amount:'10.00',discount_amount:'1.00',shipping_address:request.shippingAddress,payment_method:request.paymentMethod};
 const state={row,order,current:true,grant:true,originGrant:true,active:true,queries:[]};
 const client={release(){},async query(sql,args){state.queries.push({sql,args});
  if(sql.includes('assert_scene_execution_grant'))return{rows:[{allowed:state.grant}]};
  if(sql.includes('FROM secureshop_review.product_targets'))return{rows:[],rowCount:state.active?1:0};
  if(sql.includes('FROM secureshop_review.scene_execution_grants'))return{rows:[],rowCount:state.originGrant?1:0};
  if(sql.includes('FROM secureshop_review.product_target_orders'))return{rows:state.order?[state.order]:[]};
  if(sql.includes('FROM secureshop_review.bound_commerce_operations'))return{rows:state.row?[state.row]:[]};
  return{rows:[]};}};
 const repo=createCheckoutHistoryRepository({pool:{connect:async()=>client},checkCurrent:async()=>{if(!state.current)throw Object.assign(Error('stale'),{code:'STALE_LAUNCH'});}});
 return{repo,state,target,scope,origin,request,result,actor,operationId};
}
test('historical checkout survives relogin with exact original receipt and current selected scene, read only',async()=>{
 const f=fixture(),before=JSON.stringify(f.state.row);
 const value=await f.repo.read(f.target,f.actor,f.operationId);
 assert.deepEqual(value,{scopeKey:hash({version:1,ownerId:71,shopUserId:f.actor,targetId:f.target.targetId}),operationId:f.operationId,status:'completed',order:{id:7,total:9,subtotal:10,discount:1}});
 assert.deepEqual(await f.repo.list(f.target,f.actor),{scopeKey:value.scopeKey,operations:[{operationId:f.operationId,orderId:7,createdAt:'2026-10-01T00:00:00.000Z'}]});
 assert.equal(JSON.stringify(f.state.row),before);
 assert.ok(f.state.queries.every(({sql})=>!/^\s*(INSERT|UPDATE|DELETE)/i.test(sql)));
 assert.ok(f.state.queries.some(({sql})=>sql.includes('LIMIT 20')));
 assert.equal(JSON.stringify(value).includes('Synthetic address'),false);
 assert.equal(JSON.stringify(value).includes(f.request.personaSession.sessionId),false);
 const renewed=createSceneBinding({...f.target},{...f.target.scene,execution:{...f.scope,platformSessionId:99},withLease:work=>work()});
 assert.equal((await f.repo.read(renewed,f.actor,f.operationId)).scopeKey,value.scopeKey);
});
test('checkout reads reject copied capabilities, sibling actor/scene, retirement, missing grants and stale current authority',async()=>{
 for(const alter of [f=>({target:{...f.target}}),f=>({actor:f.actor+1}),f=>{f.state.row.target_id=randomUUID();return{};},f=>{f.state.active=false;return{};},f=>{f.state.grant=false;return{};},f=>{f.state.originGrant=false;return{};},f=>{f.state.current=false;return{};}]){
  const f=fixture(),input=alter(f);await assert.rejects(f.repo.read(input.target||f.target,input.actor||f.actor,f.operationId));
  assert.equal(f.state.queries.some(({sql})=>sql==='COMMIT'),false);
 }
});
test('missing/redacted/admitted checkout is unconfirmed and never authorizes another effect',async()=>{
 for(const state of ['absent','admitted','redacted']){const f=fixture();if(state==='absent')f.state.row=null;else f.state.row.state=state;
  await assert.rejects(f.repo.read(f.target,f.actor,f.operationId),{code:'CHECKOUT_RECEIPT_NOT_FOUND'});
 }
});
test('checkout original text hashes, old provenance and matching owned order amounts are all required',async()=>{
 const changes=[f=>f.state.row.request_json+=' ',f=>f.state.row.result_sha256='a'.repeat(64),f=>f.state.row.authority_version='2',f=>f.state.row.persona_session_id=randomUUID(),f=>f.state.order=null,f=>f.state.order.total_amount='10.00',f=>f.state.order.shipping_address='Other',f=>f.state.row.mode='fixed',f=>{const r={...f.request,scope:{...f.origin,platformOwnerId:99}};f.state.row.request_json=JSON.stringify(r);f.state.row.request_sha256=hash(f.state.row.request_json);}];
 for(const change of changes){const f=fixture();change(f);await assert.rejects(f.repo.read(f.target,f.actor,f.operationId),{code:'COMMERCE_INTEGRITY_UNAVAILABLE'});}
});
test('checkout history service resolves existing scene without provisioning and drops stale post-read results',async()=>{
 const f=fixture();let stale=false,reads=0;
 const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(k=>[k,async()=>null]));
 repository.checkoutHistory=async(target,id)=>{assert.equal(target,f.target);assert.equal(id,f.actor);reads++;return{scopeKey:'a'.repeat(64),operations:[]};};
 repository.checkoutReceipt=async()=>{stale=true;return{};};
 const personaAuthority={capture(value){return{binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},withCrossStoreEffect(){throw Error('No effects');},async assertRemoteAdmission(){if(stale)throw Object.assign(Error('stale'),{code:'SHOP_AUTH_INVALID'});}};}};
 const service=require('../server/services/secureshopBoundCommerce').createSecureShopBoundCommerce({repository,personaAuthority,resolveExistingTarget:async()=>f.target,catalog:{hasProduct(){throw Error('No catalog reads');},prepareTarget(){throw Error('No provisioning');}}});
 const input={scope:f.scope,persona:{id:f.actor,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'2'}};
 assert.deepEqual(await service.checkoutHistory(input),{scopeKey:'a'.repeat(64),operations:[]});assert.equal(reads,1);
 await assert.rejects(service.checkoutReceipt({...input,operationId:f.operationId}),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(service.checkoutHistory({...input,persona:{id:f.actor,role:'merchant'}}),{code:'OWNER_MISMATCH'});
});
