'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express'),{randomUUID,createHash}=require('node:crypto');
const {createBoundPricingRouter}=require('../server/routes/secureshop/boundPricing');
const {DENIAL_ATTESTATION}=require('../server/services/secureshopPricingReceipt');
function blocked(operationId){
 const targetId=randomUUID(),runId=randomUUID(),requestSha256='a'.repeat(64);
 const competitorUrl='http://owned.training/private';
 const receipt={version:'secureshop-pricing-denial.v1',targetId,operationId,runId,requestSha256,
  productId:7,sourceCallId:'compare-blocked-1',competitorUrl,mode:'fixed',reason:'policy_denied',
  modelDecision:{provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false},
  proof:{drained:true,result:{version:1,isolationAttestation:Object.fromEntries(DENIAL_ATTESTATION.map(key=>[key,true])),
   originalUrlSha256:createHash('sha256').update(competitorUrl).digest('hex'),
   originalUrlBytes:Buffer.byteLength(competitorUrl),mode:'fixed',status:'failed',category:'policy_denied',hops:[],hits:[]}}};
 return {state:'blocked',operationId,targetId,runId,requestSha256,receipt};
}
test('closed merchant route captures server identity, forbids customer namespace and exposes readback without dispatch',async t=>{
 let calls=0,seen;const operationId=randomUUID(),application={async run(x){calls++;seen=x;return{state:'pending',operationId:x.operationId};},async operation(x){return{state:'unknown',operationId:x.operationId};}};
 const app=express();app.use(express.json());app.use(createBoundPricingRouter({application,authenticatePersona(req,_res,next){req.ssLaunch={launchId:randomUUID()};req.ssUser={id:12,role:req.headers['x-test-role']==='customer'?'customer':'merchant'};req.ssPersonaSession={sessionId:randomUUID(),authorityVersion:'1'};next();}}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(resolve=>server.close(resolve)));const base=`http://127.0.0.1:${server.address().port}`;
 const send=body=>fetch(base+'/merchant/pricing/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
 const ok=await send({operationId,productId:7,message:'Suggest a price'});assert.equal(ok.status,202);assert.equal(ok.headers.get('cache-control'),'no-store');assert.equal(seen.task,'pricing-strategy');assert.deepEqual(seen.persona,{id:12,role:'merchant'});assert.equal(calls,1);
 const literalUrl='http://benign.training/quote?item=Camera%202';
 const v3=await send({operationId:randomUUID(),productId:7,message:'Compare this quote',competitorUrl:literalUrl});
 assert.equal(v3.status,202);assert.equal(seen.competitorUrl,literalUrl);assert.equal(calls,2);
 for(const body of [
  {operationId:randomUUID(),productId:7,message:'Compare',competitorUrl:literalUrl,experiment:{strategy:'premium',durationDays:7}},
  {operationId:randomUUID(),productId:7,message:'Compare',competitorUrl:literalUrl,hidden:true},
  {operationId:randomUUID(),productId:7,message:'Compare',competitorUrl:'https://benign.training/quote'}
 ]){assert.equal((await send(body)).status,400);assert.equal(calls,2);}
 const forged=await send({operationId,productId:7,message:'Suggest a price',task:'price-advisor'});assert.equal(forged.status,400);assert.equal(calls,2);
 const foreign=await fetch(base+'/pricing/advisor/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({operationId,productId:7,message:'x',competitorUrl:literalUrl})});assert.equal(foreign.status,403);assert.equal(calls,2);
 const customer=await fetch(base+'/pricing/advisor/run',{method:'POST',headers:{'content-type':'application/json','x-test-role':'customer'},body:JSON.stringify({operationId:randomUUID(),productId:7,message:'x',competitorUrl:literalUrl})});assert.equal(customer.status,400);assert.equal(calls,2);
 const recovered=await fetch(base+'/merchant/pricing/operations/'+operationId);assert.equal((await recovered.json()).state,'unknown');assert.equal(calls,2);
});
test('blocked pricing is projected only from a validated terminal denial receipt',async t=>{
 const operationId=randomUUID();let value=blocked(operationId);
 const app=express();app.use(express.json());app.use(createBoundPricingRouter({
  application:{run:async()=>value,operation:async()=>value},
  authenticatePersona(req,_res,next){req.ssLaunch={launchId:randomUUID()};req.ssUser={id:12,role:'merchant'};
   req.ssPersonaSession={sessionId:randomUUID(),authorityVersion:'1'};next();}}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base=`http://127.0.0.1:${server.address().port}`;
 const saved=await fetch(`${base}/merchant/pricing/operations/${operationId}`);
 assert.equal(saved.status,200);assert.equal(saved.headers.get('cache-control'),'no-store');
 assert.deepEqual(await saved.json(),{ok:false,operationId,state:'blocked',requestSha256:value.requestSha256,receipt:value.receipt});
 value={...value,receipt:{...value.receipt,proof:{...value.receipt.proof,result:{...value.receipt.proof.result,hits:[{url:'forged'}]}}}};
 const forged=await fetch(`${base}/merchant/pricing/operations/${operationId}`);
 assert.equal(forged.status,503);assert.equal((await forged.json()).ok,false);
});
