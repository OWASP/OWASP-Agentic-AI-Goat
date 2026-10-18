'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http');
const {createSecureShopSystemConfigClient,validateSystemConfigReceipt,isSystemConfigOutcomeUncertain,HTTP_VERSION,CAPABILITY,MAX_RESPONSE_BYTES}=require('../server/services/secureshopSystemConfigClient');
const {VERSION,ISOLATION,hash,requestDigest}=require('../sidecars/sandbox-runner/owned-system/contract');
const request={operationId:'11111111-1111-4111-8111-111111111111',path:'....//.env'};
const health={version:HTTP_VERSION,ready:true,isolation:ISOLATION,configReadCapability:CAPABILITY};
const token='a'.repeat(43);
const response=value=>new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});
function receipt(req=request){const content='SYNTHETIC_CONFIG=true\n';return {version:VERSION,isolation:ISOLATION,operationId:req.operationId,requestSha256:requestDigest(req),status:'completed',exitCode:0,timedOut:false,truncated:false,drained:true,readResult:{ok:true,input:req.path,sanitized:'../.env',targetPath:'/app/.env',size:Buffer.byteLength(content),content,contentSha256:hash(content)}};}
function client(fetchImpl,extra={}){return createSecureShopSystemConfigClient({baseURL:'http://127.0.0.1:8090',token,fetchImpl,...extra});}
test('strict origin/token and closed input reject before transport',async()=>{
 for(const baseURL of ['file:///private','http://user:pass@localhost','http://localhost/path','http://localhost/?a=1','http://localhost/#part'])assert.throws(()=>createSecureShopSystemConfigClient({baseURL,token}));
 assert.throws(()=>createSecureShopSystemConfigClient({baseURL:'http://localhost',token:'bad\ntoken'}));let calls=0;await assert.rejects(client(()=>calls++).read({...request,root:'/private'}));assert.equal(calls,0);
});
test('exact auth header/fixed routes preserve raw traversal and immutable request across authority await',async()=>{
 let resolve;const held=new Promise(r=>resolve=r);let checks=0;const calls=[];
 const c=client(async(url,options)=>{calls.push({url:String(url),options});return response(options.method==='GET'?health:receipt());});const mutable={...request};const pending=c.read(mutable,{assertCurrent:async()=>{if(++checks===1)await held;}});mutable.path='changed';resolve();const result=await pending;
 assert.equal(result.readResult.content,'SYNTHETIC_CONFIG=true\n');assert.equal(checks,3);assert.equal(calls.length,2);assert.equal(calls[0].url,'http://127.0.0.1:8090/secureshop/system/health');assert.equal(calls[1].url,'http://127.0.0.1:8090/secureshop/system/config-read');
 assert.deepEqual(JSON.parse(calls[1].options.body),request);assert.deepEqual(calls[1].options.headers,{authorization:`Bearer ${token}`,'content-type':'application/json'});assert.equal(calls[1].options.redirect,'error');assert.equal(calls[1].options.credentials,'omit');assert.ok(Object.isFrozen(result.readResult));
});
test('old capability and failed health are unavailable before any POST',async()=>{
 for(const body of [{...health,configReadCapability:'old'},{...health,ready:false},{...health,extra:'unexpected'}]){let posts=0;await assert.rejects(client(async(u,o)=>{if(o.method==='POST')posts++;return response(body);}).read(request),e=>e.code==='SYSTEM_CONFIG_UNAVAILABLE'&&!isSystemConfigOutcomeUncertain(e));assert.equal(posts,0);}
});
test('pre-dispatch authority denial retains type; post-dispatch authority loss is branded unknown',async()=>{
 const denied=Object.assign(new Error('private authority cause'),{code:'SHOP_AUTH_REVOKED'});let calls=0;await assert.rejects(client(()=>calls++).read(request,{assertCurrent:()=>{throw denied;}}),e=>e===denied);assert.equal(calls,0);
 let checks=0;await assert.rejects(client(async(u,o)=>response(o.method==='GET'?health:receipt())).read(request,{assertCurrent:()=>{if(++checks===3)throw denied;}}),e=>isSystemConfigOutcomeUncertain(e)&&!e.message.includes('private'));
 assert.equal(isSystemConfigOutcomeUncertain({code:'SYSTEM_CONFIG_OUTCOME_UNCERTAIN'}),false);
});
test('completed negative and explicit executor unavailable stay distinct from successful file read',async()=>{
 const negative={...receipt(),readResult:{ok:false,error:'config not found'}};assert.equal(validateSystemConfigReceipt(request,negative).readResult.ok,false);
 const unavailable={...receipt(),status:'unavailable',exitCode:124,timedOut:true};delete unavailable.readResult;assert.equal(validateSystemConfigReceipt(request,unavailable).status,'unavailable');
 const wrong={...unavailable,exitCode:0,timedOut:false};assert.throws(()=>validateSystemConfigReceipt(request,wrong));
});
test('receipt mismatch and arbitrary/private fields fail unknown without retry or cause exposure',async()=>{
 for(const patch of [{operationId:'22222222-2222-4222-8222-222222222222'},{requestSha256:'0'.repeat(64)},{privateRoot:'/private'},{readResult:{...receipt().readResult,content:'forged'}},{readResult:{...receipt().readResult,targetPath:'/etc/passwd'}},{drained:false}]){
 let posts=0;await assert.rejects(client(async(u,o)=>{if(o.method==='GET')return response(health);posts++;return response({...receipt(),...patch});}).read(request),e=>isSystemConfigOutcomeUncertain(e)&&e.automaticRetry===false);assert.equal(posts,1);
 }
});
test('HTTP errors and lost connection are unknown after exactly one POST; response text is private',async()=>{
 for(const fail of [()=>new Response('private server cause',{status:503}),()=>{throw new Error('private socket cause');}]){let posts=0;await assert.rejects(client(async(u,o)=>{if(o.method==='GET')return response(health);posts++;return fail();}).read(request),e=>isSystemConfigOutcomeUncertain(e)&&!e.message.includes('private'));assert.equal(posts,1);}
});
test('oversized declared and streamed responses are bounded unknown outcomes',async()=>{
 for(const make of [()=>new Response('{}',{headers:{'content-length':String(MAX_RESPONSE_BYTES+1)}}),()=>new Response(new ReadableStream({start(c){c.enqueue(new Uint8Array(MAX_RESPONSE_BYTES+1));c.close();}}))]){
 await assert.rejects(client(async(u,o)=>o.method==='GET'?response(health):make()).read(request),isSystemConfigOutcomeUncertain);
 }
});
test('hard wall bounds hung fetch and streaming body even if implementation ignores abort',async()=>{
 for(const make of [()=>new Promise(()=>{}),()=>new Response(new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('{'));}}))]){
 const start=Date.now();await assert.rejects(client(async(u,o)=>o.method==='GET'?response(health):make(),{timeoutMs:100}).read(request),isSystemConfigOutcomeUncertain);assert.ok(Date.now()-start<1000);
 }
});
test('real loopback HTTP receives private bearer and closed request; no automatic redirect follows',async()=>{
 const seen=[];const server=http.createServer((req,res)=>{seen.push({url:req.url,auth:req.headers.authorization});if(req.url.endsWith('/health')){res.setHeader('content-type','application/json');res.end(JSON.stringify(health));}else{res.writeHead(302,{location:'/unexpected'});res.end();}});await new Promise(r=>server.listen(0,'127.0.0.1',r));try{
 const c=createSecureShopSystemConfigClient({baseURL:`http://127.0.0.1:${server.address().port}`,token});await assert.rejects(c.read(request),isSystemConfigOutcomeUncertain);assert.deepEqual(seen.map(r=>r.url),['/secureshop/system/health','/secureshop/system/config-read']);assert.ok(seen.every(r=>r.auth===`Bearer ${token}`));
 }finally{await new Promise(r=>server.close(r));}
});
test('early content-length rejection explicitly cancels unread body',async()=>{
 let cancelled=false;const stream=new ReadableStream({cancel(){cancelled=true;}});
 await assert.rejects(client(async(u,o)=>o.method==='GET'?response(health):new Response(stream,{headers:{'content-length':'not-a-number'}})).read(request),isSystemConfigOutcomeUncertain);assert.equal(cancelled,true);
});
test('external abort during stalled body cancels stream and remains unknown; preabort never dispatches',async()=>{
 const before=new AbortController();before.abort();let calls=0;await assert.rejects(client(()=>calls++).read(request,{signal:before.signal}),e=>e.name==='AbortError');assert.equal(calls,0);
 const controller=new AbortController();let cancelled=false,post;const dispatched=new Promise(r=>post=r);const stream=new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('{'));},cancel(){cancelled=true;}});
 const pending=client(async(u,o)=>{if(o.method==='GET')return response(health);post();return new Response(stream);}).read(request,{signal:controller.signal});await dispatched;await new Promise(r=>setImmediate(r));controller.abort();await assert.rejects(pending,isSystemConfigOutcomeUncertain);assert.equal(cancelled,true);
});
