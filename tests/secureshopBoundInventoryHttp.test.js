'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express'),{randomUUID}=require('node:crypto');
const {createBoundInventoryRouter}=require('../server/routes/secureshop/boundInventory');
async function fixture(role,work){const calls=[],application={readiness:async context=>({ready:true}),run:async input=>{calls.push(input);return{ok:true,requestId:input.requestId,status:'completed'};},retry:async input=>{calls.push(input);return{ok:true,status:'completed',requestId:input.requestId,originalRequestId:input.originalRequestId,grading:{status:'disabled',completed:false}};},recover:async input=>{calls.push(input);return{status:'pending',requestId:input.requestId};},listHistory:async input=>{calls.push(input);return{ok:true,operations:[]};},readHistory:async input=>{calls.push(input);return{ok:true,status:'completed',historical:true,requestId:input.requestId,mode:'vuln',answer:'saved',operations:[]};}},app=express();app.use(express.json());app.use(createBoundInventoryRouter({application,authenticatePersona(req,res,next){req.ssLaunch={launchId:randomUUID()};req.ssUser={id:2,role};req.ssPersonaSession={sessionId:randomUUID(),authorityVersion:'1'};next();}}));const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));try{await work(`http://127.0.0.1:${server.address().port}`,calls);}finally{await new Promise(resolve=>server.close(resolve));}}
test('merchant route derives authority and keeps unknown recovery nonmutating',async()=>fixture('merchant',async(base,calls)=>{const requestId=randomUUID(),response=await fetch(base+'/merchant/inventory/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({requestId,message:'Set product 7 stock to 2',access:'write',stockChange:{productId:7,quantity:2}})});assert.equal(response.status,200);assert.equal(calls[0].access,'write');assert.equal(calls[0].persona.id,2);assert.equal(calls[0].persona.role,'merchant');assert.ok(calls[0].personaSession.sessionId);const read=await fetch(base+'/merchant/inventory/operations/'+requestId);assert.equal(read.status,200);assert.equal((await read.json()).status,'pending');}));
test('closed run schema denies owner selection, malformed UUID and untrusted tool selection',async()=>fixture('merchant',async(base,calls)=>{for(const body of[{requestId:'bad',message:'x'},{requestId:randomUUID(),message:'x',scope:{}},{requestId:randomUUID(),message:'x',tool:'set_stock'}]){const response=await fetch(base+'/merchant/inventory/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});assert.equal(response.status,400);}assert.equal(calls.length,0);}));
test('nonmerchant cannot invoke or recover inventory',async()=>fixture('customer',async(base,calls)=>{assert.equal((await fetch(base+'/merchant/inventory/readiness')).status,403);assert.equal((await fetch(base+'/merchant/inventory/operations/'+randomUUID())).status,403);assert.equal(calls.length,0);}));
test('new inventory requests require explicit read or write task access',async()=>fixture('merchant',async(base,calls)=>{
 const send=body=>fetch(base+'/merchant/inventory/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
 const baseBody={requestId:randomUUID(),message:'Inspect stock'};
 for(const access of [null,true,'admin'])assert.equal((await send({...baseBody,access})).status,400);
 assert.equal((await send(baseBody)).status,400);assert.equal(calls.length,0);
 assert.equal((await send({...baseBody,access:'read',stockChange:null})).status,200);assert.equal(calls[0].access,'read');
}));

test('retry DTO is closed and derives persona while stock and retry UUIDs must differ',async()=>fixture('merchant',async(base,calls)=>{const body={requestId:randomUUID(),originalRequestId:randomUUID(),evaluationId:randomUUID()},send=body=>fetch(base+'/merchant/inventory/judge-retry',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});assert.equal((await send(body)).status,200);assert.equal(calls[0].persona.role,'merchant');assert.equal((await send({...body,scope:{}})).status,400);assert.equal((await send({...body,requestId:body.originalRequestId})).status,400);assert.equal(calls.length,1);}));
test('historical inventory reads derive the current merchant and accept only a request UUID',async()=>fixture('merchant',async(base,calls)=>{
 const requestId=randomUUID();const list=await fetch(base+'/merchant/inventory/history');assert.equal(list.status,200);assert.deepEqual(await list.json(),{ok:true,operations:[]});
 const read=await fetch(base+'/merchant/inventory/history/'+requestId);assert.equal(read.status,200);assert.equal((await read.json()).historical,true);
 assert.equal(calls[1].requestId,requestId);assert.equal(calls[1].persona.role,'merchant');assert.ok(calls[1].personaSession.sessionId);
 assert.equal((await fetch(base+'/merchant/inventory/history/bad')).status,400);
 assert.equal((await fetch(base+'/merchant/inventory/history?owner=2')).status,400);
 assert.equal(calls.length,2);
}));
test('nonmerchant historical inventory reads are denied before application calls',async()=>fixture('customer',async(base,calls)=>{
 assert.equal((await fetch(base+'/merchant/inventory/history')).status,403);
 assert.equal((await fetch(base+'/merchant/inventory/history/'+randomUUID())).status,403);
 assert.equal(calls.length,0);
}));
test('503 inventory diagnostic records only bounded error metadata and keeps the response generic',async()=>{
 const logged=[],app=express(),httpId=randomUUID(),operationId=randomUUID();
 app.use((req,_res,next)=>{req.requestId=httpId;next();});
 app.use(createBoundInventoryRouter({
  application:{readiness:async()=>({ready:true}),run:async()=>({ok:true}),recover:async()=>{throw Object.assign(Error('private synthetic mailbox text'),{code:'INVENTORY_RECOVERY_UNAVAILABLE'});},listHistory:async()=>({ok:true,operations:[]}),readHistory:async()=>({ok:true,status:'completed',historical:true})},
  authenticatePersona(req,_res,next){req.ssLaunch={launchId:randomUUID()};req.ssUser={id:2,role:'merchant'};req.ssPersonaSession={sessionId:randomUUID(),authorityVersion:'1'};next();},
  logger:{error(...args){logged.push(args);}},
 }));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
 try{const response=await fetch(`http://127.0.0.1:${server.address().port}/merchant/inventory/operations/${operationId}`);
  assert.equal(response.status,503);assert.deepEqual(await response.json(),{ok:false,error:'Inventory unavailable'});
  assert.deepEqual(logged,[["secureshop_inventory_failure",{component:'secureshop_inventory',requestId:httpId,operation:'recover',errorCode:'INVENTORY_RECOVERY_UNAVAILABLE',errorName:'Error'}]]);
  assert.equal(JSON.stringify(logged).includes('private synthetic mailbox text'),false);
  assert.equal(JSON.stringify(logged).includes(operationId),false);
 }finally{await new Promise(resolve=>server.close(resolve));}
});

test('HTTP stock authority requires exact bounded tuple or explicit read null before application dispatch',async()=>fixture('merchant',async(base,calls)=>{
 const send=body=>fetch(base+'/merchant/inventory/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({requestId:randomUUID(),message:'Inspect stock',...body})});
 for(const body of [
  {access:'read'}, {access:'read',stockChange:[]}, {access:'read',stockChange:{productId:7,quantity:2}},
  {access:'write',stockChange:null}, {access:'write',stockChange:{productId:0,quantity:1}},
  {access:'write',stockChange:{productId:7,quantity:-1}}, {access:'write',stockChange:{productId:2147483648,quantity:1}},
  {access:'write',stockChange:{productId:7,quantity:2147483648}}, {access:'write',stockChange:{productId:'7',quantity:2}},
  {access:'write',stockChange:{productId:7,quantity:2,retailerId:2}},
 ])assert.equal((await send(body)).status,400);
 assert.equal(calls.length,0);
 assert.equal((await send({access:'write',stockChange:{productId:2147483647,quantity:0}})).status,200);
 assert.deepEqual(calls[0].stockChange,{productId:2147483647,quantity:0});
}));
