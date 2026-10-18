'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const Probe=require('../server/services/secureshopCouponProbeContract');

const coupons=[{id:1,code:'WELCOME10',discount_percent:10,active:1}];
function source(){return {version:1,lookup:{scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},operationId:randomUUID(),persona:{id:3,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode:'vuln',code:"' OR 1=1--",coupons},execution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation','probe']),generation:'0',sessionId:randomUUID(),requestId:randomUUID(),step:1,callId:'coupon-probe:1'}};}
function valid(){return source();}
test('probe contract binds the existing coupon sink to a closed run tuple and canonical receipt digests',()=>{
 const input=valid(),request=Probe.request(input),target={targetId:randomUUID(),scope:input.lookup.scope,sourceManifestSha256:'a'.repeat(64)};
 const receipt=Probe.buildReceipt({target,request,result:{coupon:coupons[0]}});
 assert.deepEqual(Probe.receipt(receipt,request),receipt);
 assert.match(Probe.statement(request).text,/code='' OR 1=1--'/);
 assert.equal(Probe.result({coupon:null}).coupon,null);
});
test('probe contract keeps distinct conversation and credential sessions in the digest while rejecting malformed execution and receipt fields',()=>{
 const input=valid(),request=Probe.request(input),target={targetId:randomUUID(),scope:input.lookup.scope,sourceManifestSha256:'a'.repeat(64)},receipt=Probe.buildReceipt({target,request,result:{coupon:null}});
 assert.notEqual(request.execution.sessionId,request.lookup.personaSession.sessionId);
 assert.throws(()=>Probe.request({...input,execution:{...input.execution,step:10}}),{code:'COUPON_PROBE_INVALID'});
 for(const field of ['sqlSha256','valuesSha256','resultSha256','requestSha256'])assert.throws(()=>Probe.receipt({...receipt,[field]:'b'.repeat(64)},request),{code:'COUPON_PROBE_RECEIPT_INVALID'});
 assert.throws(()=>Probe.receipt({...receipt,result:{coupon:{...coupons[0],active:0}}},request),{code:'COUPON_PROBE_RECEIPT_INVALID'});
});
test('read and private reference requests are closed, target-bound, and position-bounded',()=>{
 const input=valid(),request=Probe.request(input),read={scope:request.lookup.scope,targetId:randomUUID(),operationId:request.lookup.operationId,requestSha256:'a'.repeat(64)};
 assert.deepEqual(Probe.readRequest(read),read);
 assert.equal(Probe.referenceRequest({...read,position:1}).position,1);
 for(const value of [{...read,extra:true},{...read,targetId:'not-a-uuid'},{...read,requestSha256:'nope'},{...read,position:0},{...read,position:257}])assert.throws(()=>Object.hasOwn(value,'position')?Probe.referenceRequest(value):Probe.readRequest(value),{code:'COUPON_PROBE_INVALID'});
});
