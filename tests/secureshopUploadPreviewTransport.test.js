'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{Readable}=require('node:stream'),{EventEmitter}=require('node:events'),{randomUUID,createHash}=require('node:crypto');
const {createUploadPreviewHttpHandler}=require('../sidecars/sandbox-runner/owned-system/upload-preview-http-handler');
const {createSecureShopUploadPreviewClient,isUploadPreviewOutcomeUncertain}=require('../server/services/secureshopUploadPreviewClient');
const {requestDigest,ISOLATION}=require('../sidecars/sandbox-runner/owned-system/upload-preview-contract');
const sha=x=>createHash('sha256').update(x).digest('hex'),token='a'.repeat(43),bytes=Buffer.from('controlled invalid image');
const request={version:1,operationId:randomUUID(),uploadOperationId:randomUUID(),uploadEffectId:randomUUID(),storageKey:randomUUID(),bindingSha256:sha('binding'),uploadRequestSha256:sha('upload'),bodySha256:sha(bytes),byteCount:bytes.length,bytesBase64:bytes.toString('base64'),mode:'fixed'};
function receipt(r){return{version:1,operationId:r.operationId,uploadOperationId:r.uploadOperationId,uploadEffectId:r.uploadEffectId,storageKey:r.storageKey,requestSha256:requestDigest(r),bindingSha256:r.bindingSha256,bodySha256:r.bodySha256,mode:r.mode,isolation:ISOLATION,runtime:{nodeVersion:'v26.10.0',platform:'linux',arch:'arm64'},decoder:null,status:'invalid_image',scriptSyntaxValid:null,originalInterpreterStarted:false,reencoded:null,exitCode:null,timedOut:false,truncated:false,drained:true,workerAttested:true,codeEffectObserved:false,effectSha256:null};}
function transport(handler){return async(url,options)=>new Promise((resolve,reject)=>{
 const body=options.body||'',headers={...options.headers,...(body?{'content-length':String(Buffer.byteLength(body))}:{})};
 const req=Object.assign(Readable.from(body?[Buffer.from(body)]:[]),{url:new URL(url).pathname,method:options.method,headers,rawHeaders:Object.entries(headers).flat()});
 const res=Object.assign(new EventEmitter(),{destroyed:false,writableEnded:false,writeHead(status,headers){this.status=status;this.headers=headers;},end(data){this.writableEnded=true;resolve(new Response(data,{status:this.status,headers:this.headers}));}});
 handler.handle(req,res).then(handled=>{if(!handled)resolve(new Response('{}',{status:404}));},reject);
 });}
test('private upload-preview client and real handler join exact request/receipt with independent readiness and current fences',async()=>{
 let calls=0,ready=0,checks=0;const handler=createUploadPreviewHttpHandler({enabled:true,token,executor:{async assertReady(){ready++;},async preview(r){calls++;assert.deepEqual(r,request);return receipt(r);}}});
 try{const client=createSecureShopUploadPreviewClient({baseURL:'http://127.0.0.1:41002',token,fetchImpl:transport(handler)});assert.deepEqual(await client.preview(request,{assertCurrent:async()=>checks++}),receipt(request));assert.equal(calls,1);assert.equal(ready,2);assert.equal(checks,3);}finally{await handler.close();}
});
test('wrong bearer, extra path authority and receipt substitution fail closed without transport replay',async()=>{
 let calls=0;const handler=createUploadPreviewHttpHandler({enabled:true,token,executor:{async assertReady(){},async preview(r){calls++;return {...receipt(r),operationId:randomUUID()};}}});
 try{const fetchImpl=transport(handler);const denied=await fetchImpl(new URL('http://127.0.0.1:41002/secureshop/uploads/preview'),{method:'POST',headers:{authorization:'Bearer wrong','content-type':'application/json'},body:JSON.stringify(request)});assert.equal(denied.status,401);assert.equal(calls,0);
 const client=createSecureShopUploadPreviewClient({baseURL:'http://127.0.0.1:41002',token,fetchImpl});await assert.rejects(client.preview({...request,path:'/private'},{assertCurrent:async()=>{}}));assert.equal(calls,0);
 await assert.rejects(client.preview(request,{assertCurrent:async()=>{}}),e=>isUploadPreviewOutcomeUncertain(e)&&e.automaticRetry===false);assert.equal(calls,1);
 }finally{await handler.close();}
});
test('pre-dispatch authority error retains identity and zero transport work; interrupted POST remains uncertain',async()=>{
 let calls=0;const stale=Error('stale');const client=createSecureShopUploadPreviewClient({baseURL:'http://127.0.0.1:41002',token,timeoutMs:100,fetchImpl:async(_url,options)=>{calls++;if(options.method==='GET')return new Response(JSON.stringify({version:1,ready:true,isolation:ISOLATION,previewCapability:'secureshop-upload-preview.v1'}));return new Response(new ReadableStream({cancel(){}}));}});
 await assert.rejects(client.preview(request,{assertCurrent:async()=>{throw stale;}}),e=>e===stale);assert.equal(calls,0);
 await assert.rejects(client.preview(request,{assertCurrent:async()=>{}}),isUploadPreviewOutcomeUncertain);assert.equal(calls,2);
});
test('handler close aborts and joins current controlled preview before terminal',async()=>{
 let started,joined=false;const entered=new Promise(r=>started=r);const handler=createUploadPreviewHttpHandler({enabled:true,token,executor:{async assertReady(){},async preview(_r,{signal}){started();await new Promise(r=>signal.addEventListener('abort',r,{once:true}));joined=true;throw Error('private');}}});
 const pending=transport(handler)(new URL('http://127.0.0.1:41002/secureshop/uploads/preview'),{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify(request)});await entered;await handler.close();assert.equal(joined,true);const result=await pending;assert.equal(result.status,503);assert.doesNotMatch(await result.text(),/private/);
});
test('local upload-preview entry uses exact managed environment and signal-owned listener shutdown',async()=>{
 const {runLocalSystemListener}=require('../sidecars/sandbox-runner/owned-system/local-listener-entry');
 const {runUploadPreviewListener}=require('../sidecars/sandbox-runner/owned-system/upload-preview-http-listener');
 const signals=new EventEmitter(),writes=[];let closes=0,started=0;
 const env={SECURESHOP_UPLOAD_PREVIEW_HTTP_ENABLED:'true',SECURESHOP_UPLOAD_PREVIEW_TOKEN:token,SECURESHOP_UPLOAD_PREVIEW_HOST:'0.0.0.0',SECURESHOP_UPLOAD_PREVIEW_PORT:'41002'};
 const result=await runLocalSystemListener({argv:['upload-preview'],env,write:text=>writes.push(text),runUploadPreview:options=>runUploadPreviewListener({...options,signals,createListener:input=>{assert.deepEqual(input,{enabled:true,token,host:'0.0.0.0',port:41002});return{async start(){started++;setImmediate(()=>signals.emit('SIGTERM'));},async close(){closes++;}};}})});
 assert.equal(result,0);assert.equal(started,1);assert.equal(closes,1);assert.equal(signals.listenerCount('SIGTERM'),0);assert.match(writes.join(''),/READY.*CLOSED/s);
});
