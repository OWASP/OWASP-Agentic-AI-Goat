'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPricingHttpListener}=require('../sidecars/sandbox-runner/owned-pricing-http/http-listener');
const {createPricingHttpClient}=require('../server/services/secureshopPricingHttpClient');
const token='a'.repeat(43);
const options=executor=>({enabled:true,token,host:'127.0.0.1',port:0,executor});
test('standalone listener is opt-in and refuses false readiness before binding',async()=>{
 assert.throws(()=>createPricingHttpListener({enabled:false}),{code:'PRICING_LISTENER_DISABLED'});
 const listener=createPricingHttpListener(options({assertReady:async()=>({ready:false}),checkReadiness:async()=>({ready:true}),execute:async()=>assert.fail('execution')}));
 await assert.rejects(listener.start(),{code:'PRICING_LISTENER_NOT_READY'});assert.equal(listener.address(),null);await listener.close();
});
test('actual loopback listener uses private authenticated health; readiness is not command dispatch',async t=>{
 let checks=0,commands=0;
 const listener=createPricingHttpListener(options({async assertReady(){checks++;return{ready:true};},async checkReadiness(){return{ready:true};},async execute(){commands++;return{drained:true,result:{controlled:true}};}}));
 t.after(()=>listener.close());const address=await listener.start();const client=createPricingHttpClient({baseURL:`http://127.0.0.1:${address.port}`,token});
 assert.deepEqual(await client.assertReady(),{ready:true});assert.equal(checks,2);assert.equal(commands,0);
 await listener.close();assert.equal(listener.address(),null);
});
test('held readiness cannot produce false successful drain after startup timeout',async()=>{
 let resolve;const held=new Promise(r=>{resolve=r;});
 const listener=createPricingHttpListener({...options({assertReady:()=>held,checkReadiness:async()=>({ready:true}),execute:async()=>({})}),readinessTimeoutMs:10,closeTimeoutMs:10});
 await assert.rejects(listener.start(),{code:'PRICING_LISTENER_NOT_READY'});
 await assert.rejects(listener.close(),{code:'PRICING_LISTENER_DRAIN_FAILED'});assert.equal(listener.address(),null);resolve({ready:true});
});
