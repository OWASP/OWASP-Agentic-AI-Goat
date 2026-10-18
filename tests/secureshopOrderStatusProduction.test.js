
'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {prepareOrderStatusDependencies}=require('../server/services/secureshopOrderStatusProduction');
const {createAnalyticsLifecycle}=require('../server/services/secureshopAnalyticsLifecycle');
function fixture(){let reads=0,effects=0;const service=Object.fromEntries(['provision','lookupOrderStatus','readOrderStatusReceipt','readOrderStatusReference','retire'].map(k=>[k,async()=>{effects++;return{retired:true}}]));
 const lifecycle=createAnalyticsLifecycle({cleanupAuthority:{getOperation:async()=>null},service});
 return{runtime:{admissions:true,service,assertReady:async()=>{reads++;}},lifecycle,get reads(){return reads},get effects(){return effects}};
}
test('production admits only exact ready service with authenticated lifecycle; preparation has no effects',async()=>{
 const f=fixture(),value=await prepareOrderStatusDependencies(f);assert.equal(value.service,f.runtime.service);assert.equal(f.reads,1);assert.equal(f.effects,0);
});
test('disabled, incomplete, forged or other-service lifecycle and readiness failure deny',async()=>{
 const f=fixture();
 for(const input of [{...f,runtime:{...f.runtime,admissions:false}},{...f,lifecycle:{}},{...f,lifecycle:fixture().lifecycle},{...f,runtime:{...f.runtime,service:{...f.runtime.service,readOrderStatusReference:undefined}}}])
 await assert.rejects(prepareOrderStatusDependencies(input),{code:'ORDER_STATUS_RUNTIME_UNAVAILABLE'});
 f.runtime.assertReady=async()=>{throw Error('offline')};await assert.rejects(prepareOrderStatusDependencies(f),/offline/);assert.equal(f.effects,0);
});
