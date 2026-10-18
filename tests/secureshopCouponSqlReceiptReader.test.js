'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createOwnedCouponSqlReceiptReader,prepareCouponDependencies}=require('../server/services/secureshopCouponProduction');
const {createAnalyticsLifecycle}=require('../server/services/secureshopAnalyticsLifecycle');
function fixture({missing=false}={}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const operationId=randomUUID(),requestSha256='b'.repeat(64);
 const target={targetId:randomUUID(),scope,sourceManifestSha256:'c'.repeat(64)};
 const receipt={version:1,kind:'coupon',operationId,requestSha256,targetId:target.targetId,scope,sourceManifestSha256:target.sourceManifestSha256,resultSha256:'d'.repeat(64),result:{coupon:null}};
 const calls=[];let returned=receipt;
 const service={async resolve(value,options){calls.push(['resolve',value,options]);if(missing)throw Object.assign(Error('missing'),{code:'ANALYTICS_TARGET_UNAVAILABLE'});return target;},
  async readCouponReceipt(value,options){calls.push(['readCouponReceipt',value,options]);return returned;},
  async provision(){throw Error('read may not provision');},async lookupCoupon(){throw Error('read may not execute');}};
 const read=createOwnedCouponSqlReceiptReader({service}),input={scope,operationId,requestSha256};
 return {read,input,target,receipt,calls,set:value=>{returned=value;}};
}
test('coupon SQL reader resolves only the existing analytics target and returns its immutable receipt',async()=>{
 const f=fixture(),signal=new AbortController().signal;
 assert.deepEqual(await f.read(f.input,{signal}),{targetId:f.target.targetId,receipt:f.receipt});
 assert.deepEqual(f.calls.map(c=>c[0]),['resolve','readCouponReceipt']);
 assert.deepEqual(f.calls[1][1],{...f.input,targetId:f.target.targetId});
 assert.equal(f.calls[1][2].signal,signal);
});
test('absent target and absent completed receipt return null without provisioning or executing',async()=>{
 const missing=fixture({missing:true});assert.equal(await missing.read(missing.input),null);assert.deepEqual(missing.calls.map(c=>c[0]),['resolve']);
 const pending=fixture();pending.set(null);assert.equal(await pending.read(pending.input),null);assert.deepEqual(pending.calls.map(c=>c[0]),['resolve','readCouponReceipt']);
});
test('coupon SQL reader denies foreign scope, target, manifest, operation and hash mismatch',async()=>{
 const f=fixture();
 for(const value of [{...f.receipt,targetId:randomUUID()},{...f.receipt,sourceManifestSha256:'e'.repeat(64)},
  {...f.receipt,scope:{...f.receipt.scope,platformOwnerId:9}},{...f.receipt,operationId:randomUUID()},
  {...f.receipt,requestSha256:'e'.repeat(64)}]){
  f.set(value);await assert.rejects(f.read(f.input),{code:'ANALYTICS_QUERY_CONFLICT'});
 }
 await assert.rejects(f.read({...f.input,extra:true}),{code:'ANALYTICS_TARGET_INVALID'});
 await assert.rejects(f.read({...f.input,operationId:'invalid'}),{code:'COUPON_INVALID'});
});
test('coupon SQL reader snapshots validated original IDs before asynchronous resolve',async()=>{
 let release,entered;const held=new Promise(resolve=>{release=resolve;}),atResolve=new Promise(resolve=>{entered=resolve;});
 const f=fixture(),input={...f.input};
 const read=createOwnedCouponSqlReceiptReader({service:{async resolve(scope){entered();await held;return f.target;},
  async readCouponReceipt(request){assert.equal(request.operationId,f.receipt.operationId);assert.equal(request.requestSha256,f.receipt.requestSha256);return f.receipt;}}});
 const pending=read(input);await atResolve;input.operationId=randomUUID();input.requestSha256='e'.repeat(64);release();
 assert.deepEqual(await pending,{targetId:f.target.targetId,receipt:f.receipt});
});
test('prepared coupon dependencies expose the same reader and require its runtime support',async()=>{
 const f=fixture(),service={resolve:async()=>f.target,readCouponReceipt:async()=>f.receipt,
  lookupCoupon:async()=>{},provision:async()=>{},retire:async()=>({retired:true})};
 const lifecycle=createAnalyticsLifecycle({cleanupAuthority:{getOperation:async()=>null},service});
 const runtime={admissions:true,service,assertReady:async()=>true};
 const reviewPool={connect:async()=>{},async query(sql){
  if(sql.includes('FROM unnest'))return {rows:['bound_commerce_operations','product_target_cart_coupons'].map(name=>({name,ready:true}))};
  if(sql.includes('information_schema.columns'))return {rows:['subtotal_amount','discount_amount','coupon_code','coupon_percent'].map(column_name=>({table_name:'product_target_orders',column_name})).concat({table_name:'product_target_order_items',column_name:'discount_amount'})};
  if(sql.includes('FROM pg_trigger'))return {rows:[['bound_commerce_operation_guard','bound_commerce_operations','guard_bound_commerce_operation',31],['cart_coupon_guard','product_target_cart_coupons','guard_cart_coupon',23],['retire_bound_commerce_operations','product_targets','retire_bound_commerce_operations',17],['default_order_subtotal','product_target_orders','default_order_subtotal',7]].map(([tgname,table,fn,type])=>({tgname,relation:'secureshop_review.'+table,function:'secureshop_review.'+fn+'()',type}))};
  if(sql.includes('FROM pg_proc'))return {rows:['guard_bound_commerce_operation','guard_cart_coupon','retire_bound_commerce_operations','default_order_subtotal'].map(proname=>({proname,executable:true,public_execute:false}))};
  if(sql.includes('deletes_operations'))return {rows:[{deletes_operations:false,deletes_coupon:true}]};
  throw Error('Unexpected SQL');
 }};
 const args={reviewPool,commercePool:{query:async()=>({rows:[]})},launches:{assertCurrent:async()=>{}},runtime,lifecycle};
 await assert.rejects(prepareCouponDependencies({...args,runtime:{...runtime,service:{...service,readCouponReceipt:undefined}}}),{code:'COUPON_RUNTIME_UNAVAILABLE'});
 const prepared=await prepareCouponDependencies(args);
 assert.deepEqual(await prepared.readCouponReceipt(f.input),{targetId:f.target.targetId,receipt:f.receipt});
});
