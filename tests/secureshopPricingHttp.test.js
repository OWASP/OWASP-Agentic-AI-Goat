'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http'),{randomUUID}=require('node:crypto');
const {createPricingHttpClient,isPricingHttpOutcomeUncertain}=require('../server/services/secureshopPricingHttpClient');
const {createPricingHttpHandler}=require('../sidecars/sandbox-runner/owned-pricing-http/http-handler');
const {VERSION,bindResult,validateResult}=require('../sidecars/sandbox-runner/owned-pricing-http/wire');
const token='a'.repeat(43);
const binding=()=>({targetId:randomUUID(),operationId:randomUUID(),runId:randomUUID(),callId:'tool-1',requestSha256:'b'.repeat(64)});
const input=()=>({mode:'vuln',url:'http://benign.training/quote',canary:'c'.repeat(64),manual:'owned synthetic input',quote:{productId:1,name:'item',price:10,currency:'USD'}});
async function fixture(t,{hold=false}={}){
 let count=0,ready=0,released;const executor={async checkReadiness(){return{ready:true};},async assertReady(){ready++;return{ready:true};},async execute({signal}){count++;if(hold)await new Promise((resolve,reject)=>{released=resolve;signal.addEventListener('abort',()=>reject(Error('aborted')),{once:true});});return{drained:true,result:{controlled:true}};}};
 const handler=createPricingHttpHandler({enabled:true,token,executor,maxConcurrent:1});
 const server=http.createServer((req,res)=>handler.handle(req,res).then(handled=>{if(!handled){res.writeHead(404);res.end();}}));
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(async()=>{await handler.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
 const baseURL=`http://127.0.0.1:${server.address().port}`;
 return{baseURL,handler,server,count:()=>count,ready:()=>ready,release:()=>released?.(),client:createPricingHttpClient({baseURL,token,timeoutMs:1000})};
}
test('actual loopback client/handler authenticates and correlates fixed execution; readiness separate from dispatch',async t=>{
 // Controlled executor, no native isolation or genuine HTTP target claim.
 const f=await fixture(t);let checks=0;
 assert.deepEqual(await f.client.checkReadiness(),{ready:true});
 const result=await f.client.execute({input:input(),binding:binding(),assertCurrent:async()=>{checks++;}});
 assert.deepEqual(result,{drained:true,result:{controlled:true}});assert.equal(f.count(),1);assert.equal(f.ready(),2);assert.equal(checks,3);
 const bad=createPricingHttpClient({baseURL:f.baseURL,token:'z'.repeat(43)});await assert.rejects(bad.checkReadiness());assert.equal(f.count(),1);
 const malformed=await fetch(f.baseURL+'/secureshop/pricing/observe',{method:'POST',headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body:JSON.stringify({version:VERSION,...binding(),input:input(),root:'/private'})});
 assert.equal(malformed.status,400);assert.equal(f.count(),1);
});
test('private wrapper rejects foreign invocation even when controlled worker result is identical',()=>{
 const request={version:VERSION,...binding(),input:input()},value=bindResult(request,{drained:true,result:{controlled:true}});
 assert.throws(()=>validateResult(request,{...value,targetId:randomUUID()}));
 assert.throws(()=>validateResult({...request,input:{...request.input,url:'http://admin.training:8080/'}},value));
});
test('pre-dispatch authority rejection remains precise; timeout after POST is unknown with no retry',async t=>{
 const f=await fixture(t,{hold:true});
 const denied=Object.assign(Error('revoked'),{code:'SHOP_AUTH_REVOKED'});
 await assert.rejects(f.client.execute({input:input(),binding:binding(),assertCurrent:async()=>{throw denied;}}),error=>error===denied);assert.equal(f.count(),0);
 await assert.rejects(f.client.execute({input:input(),binding:binding()}),isPricingHttpOutcomeUncertain);assert.equal(f.count(),1);
});
