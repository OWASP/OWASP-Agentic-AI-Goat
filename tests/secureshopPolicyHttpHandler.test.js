'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');const http=require('node:http');const crypto=require('node:crypto');
const {createPolicyRenderHttpHandler,MAX_BODY_BYTES}=require('../sidecars/sandbox-runner/policy-render/http-handler');
const {requestDigest,createLiteralRenderResult}=require('../server/services/secureshopPromptPolicyContract');
const request=()=>({operationId:crypto.randomUUID(),name:'policy',markdown:'Hello',targets:['admin']});
const receipt=r=>({version:1,operationId:r.operationId,requestSha256:requestDigest(r),isolation:'bwrap-policy-template-v1',rendered:'Hello',renderedSha256:crypto.createHash('sha256').update('Hello').digest('hex'),exitCode:0,timedOut:false,truncated:false,drained:true});
async function fixture(t,executor,options={}){const handler=createPolicyRenderHttpHandler({executor,...options});const server=http.createServer(async(req,res)=>{if(!await handler.handle(req,res)){res.writeHead(404);res.end();}});await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(async()=>{await handler.close();server.closeAllConnections();await new Promise(r=>server.close(r));});return {handler,server,url:`http://127.0.0.1:${server.address().port}/secureshop/policy-render`};}
const post=(url,body)=>fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
test('actual HTTP returns validated receipt and excludes malformed body before execution',async t=>{let calls=0;const {url}=await fixture(t,{render:async r=>{calls++;return receipt(r);}});const good=request();const res=await post(url,good);assert.equal(res.status,200);assert.equal(res.headers.get('cache-control'),'no-store');assert.deepEqual(await res.json(),receipt(good));assert.equal((await post(url,{...good,extra:true})).status,400);assert.equal((await post(url,{...good,markdown:'x'.repeat(MAX_BODY_BYTES)})).status,413);assert.equal((await fetch(url)).status,405);assert.equal(calls,1);});
test('invalid executor receipt never returns successful render',async t=>{const {url}=await fixture(t,{render:async r=>({...receipt(r),drained:false})});const res=await post(url,request());assert.equal(res.status,503);assert.deepEqual(await res.json(),{error:'POLICY_RENDER_UNAVAILABLE'});});
test('capacity excludes another render and shutdown waits for executor drain',async t=>{let admit,release,drained=false;const admitted=new Promise(r=>admit=r);const {url,handler}=await fixture(t,{render:(_r,{signal})=>new Promise((_resolve,reject)=>{admit();signal.addEventListener('abort',()=>{release=()=>{drained=true;reject(signal.reason);};},{once:true});})},{maxConcurrent:1});const first=post(url,request());await admitted;assert.equal((await post(url,request())).status,503);let closed=false;const closing=handler.close().then(()=>{closed=true;});await new Promise(r=>setImmediate(r));assert.equal(closed,false);release();await closing;assert.equal(drained,true);assert.equal((await first).status,503);assert.equal((await post(url,request())).status,503);});
test('slow body times out and frees admission without rendering',async t=>{let calls=0;const {url}=await fixture(t,{render:async r=>{calls++;return receipt(r);}},{bodyTimeoutMs:100,maxConcurrent:1});const status=await new Promise((resolve,reject)=>{const req=http.request(url,{method:'POST',headers:{'content-type':'application/json'}},res=>{res.resume();res.on('end',()=>{resolve(res.statusCode);req.destroy();});});req.on('error',reject);req.write('{');});assert.equal(status,408);assert.equal(calls,0);assert.equal((await post(url,request())).status,200);});
test('client disconnect aborts executor and retains capacity until descendant drain',async t=>{
 let admitted,aborted,release;const ready=new Promise(r=>admitted=r),cancelled=new Promise(r=>aborted=r);
 const {url}=await fixture(t,{render:(_r,{signal})=>new Promise((_resolve,reject)=>{admitted();signal.addEventListener('abort',()=>{release=()=>reject(signal.reason);aborted();},{once:true});})},{maxConcurrent:1});
 const req=http.request(url,{method:'POST',headers:{'content-type':'application/json'}});req.on('error',()=>{});req.end(JSON.stringify(request()));await ready;req.destroy();await cancelled;
 assert.equal((await post(url,request())).status,503);release();
});
test('invalid UTF8 and oversized chunked JSON never reach renderer',async t=>{
 let calls=0;const {url}=await fixture(t,{render:async r=>{calls++;return receipt(r);}});
 async function raw(bytes){return new Promise((resolve,reject)=>{const req=http.request(url,{method:'POST',headers:{'content-type':'application/json','transfer-encoding':'chunked'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.end(bytes);});}
 assert.equal(await raw(Buffer.from([0x7b,0x22,0xff,0x22,0x3a,0x31,0x7d])),400);
 assert.equal(await raw(Buffer.alloc(MAX_BODY_BYTES+1,0x20)),413);assert.equal(calls,0);
});
test('disconnect during body consumption releases slot and server remains usable',async t=>{
 let calls=0;const {url,server}=await fixture(t,{render:async r=>{calls++;return receipt(r);}},{maxConcurrent:1});
 const receiving=new Promise(resolve=>server.once('request',incoming=>incoming.once('data',resolve)));
 const req=http.request(url,{method:'POST',headers:{'content-type':'application/json'}});req.on('error',()=>{});req.write('{');await receiving;req.destroy();
 // A successful later request proves neither a stuck admission nor server failure.
 let status;for(let i=0;i<10;i++){status=(await post(url,request())).status;if(status===200)break;await new Promise(r=>setTimeout(r,5));}
 assert.equal(status,200);assert.equal(calls,1);
});

test('v2 fixed HTTP accepts only a literal result and forwards the exact mode envelope',async t=>{
 let observed, calls=0;
 const {url}=await fixture(t,{render:async value=>{calls++;observed=value;return createLiteralRenderResult(value.request);}});
 const body={version:2,mode:'fixed',request:request()};
 const response=await post(url,body);
 assert.equal(response.status,200);
 assert.deepEqual(await response.json(),createLiteralRenderResult(body.request));
 assert.deepEqual(observed,{...body,request:{...body.request,targets:['admin']}});
 assert.equal(calls,1);
 assert.equal((await post(url,{...body,mode:'vuln'})).status,503);
 assert.equal((await post(url,{...body,extra:true})).status,400);
});
