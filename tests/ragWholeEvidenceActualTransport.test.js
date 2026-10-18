'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('crypto');
const {createRagWholeEvidenceTransport:create,MODEL,DIGEST}=require('./fixtures/ragWholeEvidenceActualTransport');
const {createTechniqueTransport:old}=require('./fixtures/dpiTechniqueActualTransport');
const hash=s=>createHash('sha256').update(s).digest('hex');
function fixture(frame={},factory=create){let calls=0;const raw=JSON.stringify({model:MODEL,message:{role:'assistant',content:'{"valid":"still not semantic acceptance"}'},done:true,done_reason:'length',...frame})+'\n';const transport=factory({phase:'A',fetch:async(url,options)=>{calls++;assert(url==='http://127.0.0.1:11434/api/tags'||url==='http://127.0.0.1:11434/api/chat');return new Response(url.endsWith('/api/tags')?JSON.stringify({models:[{name:MODEL,digest:DIGEST}]}):raw,{status:200});}});return{transport,raw,calls:()=>calls};}
const request={method:'POST',path:'/api/chat',body:JSON.stringify({model:MODEL,stream:true,options:{temperature:0,num_ctx:32768,num_predict:4096}})};
test('recognized stop and length preserve exact drained wire with no semantic rewrite',async()=>{for(const reason of ['stop','length']){const f=fixture({done_reason:reason}),t=f.transport;await t.initialize();t.beginCase('one');const r=await t.request('judge',request);assert.equal(r.body,f.raw);const w=t.snapshot().calls.find(x=>x.kind==='external/api/chat');assert.equal(w.response,f.raw);assert.equal(w.responseSha256,hash(f.raw));assert.equal(w.responseBytes,Buffer.byteLength(f.raw));assert.equal(w.status,'returned');t.endCase();assert.equal((await t.close()).physicalPending,0);assert.equal(f.calls(),2);}});
test('old PhaseA still rejects length; new scope rejects actor and other profiles',async()=>{const f=fixture({},old),t=f.transport;await t.initialize();t.beginCase('one');await assert.rejects(t.request('judge',request),{code:'INCOMPLETE_TERMINATION'});await t.close();for(const phase of ['B','RAG8'])assert.throws(()=>create({phase}),{code:'TRANSPORT_CONFIG'});const a=fixture().transport;await a.initialize();a.beginCase('one');await assert.rejects(a.request('actor',request),{code:'CASE_INFERENCE_BUDGET'});await a.close();});
test('missing/unknown termination, incomplete frame and wrong model remain denied',async()=>{for(const frame of [{done_reason:undefined},{done_reason:'error'},{done:false},{model:'foreign'},{error:'failed'}]){const t=fixture(frame).transport;await t.initialize();t.beginCase('one');await assert.rejects(t.request('judge',request),{code:'INCOMPLETE_TERMINATION'});assert.equal(t.snapshot().calls.find(x=>x.kind.startsWith('local:')).status,'incomplete');await t.close();}});
test('preabort and malformed endpoint spend no inference; metadata identity remains required',async()=>{const f=fixture(),t=f.transport;await t.initialize();t.beginCase('one');const c=new AbortController();c.abort();await assert.rejects(t.request('judge',{...request,signal:c.signal}));await assert.rejects(t.request('judge',{...request,path:'/other'}));assert.equal(f.calls(),1);await t.close();const wrong=create({fetch:async()=>new Response(JSON.stringify({models:[{name:MODEL,digest:'wrong'}]}))});await assert.rejects(wrong.initialize(),{code:'MODEL_IDENTITY'});await wrong.close();});
test('explicit stronger Judge remains digest, phase, request and frame bound',async()=>{
 const {STRONG_JUDGE,admitJudgeIdentity}=require('./fixtures/ragWholeEvidenceActualTransport');
 assert.equal(admitJudgeIdentity().model,MODEL);assert.throws(()=>create({judgeIdentity:STRONG_JUDGE}),{code:'JUDGE_IDENTITY_SCOPE'});
 for(const identity of [{...STRONG_JUDGE,digest:'0'.repeat(64)},{...STRONG_JUDGE,extra:true}])assert.throws(()=>admitJudgeIdentity(identity));
 for(const wrong of ['none','digest','frame']){
  const t=create({phase:'DPI_SPAN',judgeIdentity:STRONG_JUDGE,fetch:async url=>new Response(url.endsWith('/api/tags')?JSON.stringify({models:[{name:STRONG_JUDGE.model,digest:wrong==='digest'?DIGEST:STRONG_JUDGE.digest}]}):JSON.stringify({model:wrong==='frame'?MODEL:STRONG_JUDGE.model,done:true,done_reason:'stop'})+'\n')});
  if(wrong==='digest')await assert.rejects(t.initialize(),{code:'MODEL_IDENTITY'});
  else{await t.initialize();t.beginCase('strong');await assert.rejects(t.request('judge',request));const r={...request,body:JSON.stringify({model:STRONG_JUDGE.model,stream:true})};if(wrong==='frame')await assert.rejects(t.request('judge',r),{code:'INCOMPLETE_TERMINATION'});else assert.equal((await t.request('judge',r)).status,200);}
  await t.close();
 }
});
test('an abort-errored Web stream is terminal even when reader.cancel rejects',async()=>{
 let chatStarted,secondRead;const started=new Promise(resolve=>{chatStarted=resolve;}),reading=new Promise(resolve=>{secondRead=resolve;});
 const t=create({phase:'A',fetch:async(url,options)=>{
  if(url.endsWith('/api/tags'))return new Response(JSON.stringify({models:[{name:MODEL,digest:DIGEST}]}));
  const body=new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode('{"partial":true}\n'));chatStarted();options.signal.addEventListener('abort',()=>controller.error(new DOMException('aborted','AbortError')),{once:true});},pull(){secondRead();}},{highWaterMark:0});
  return new Response(body,{status:200});
 }});
 await t.initialize();t.beginCase('abort-reader');const controller=new AbortController();const requestPromise=t.request('judge',{...request,signal:controller.signal});
 await started;await reading;controller.abort();await assert.rejects(requestPromise,{code:'CANCELLED'});
 await new Promise(resolve=>setTimeout(resolve,10));
 const external=t.snapshot().calls.find(row=>row.kind==='external/api/chat');
 assert.equal(external.status,'incomplete');assert.match(external.response,/"partial"/);assert.equal(t.snapshot().physicalPending,0);
 t.endCase();assert.equal((await t.close()).physicalPending,0);
});
test('a reader whose cancel and closed promises never settle remains physically pending',async()=>{
 let opened;const reader={read:()=>new Promise(()=>{}),cancel:()=>new Promise(()=>{}),closed:new Promise(()=>{}),releaseLock(){}};
 const t=create({phase:'A',fetch:async url=>url.endsWith('/api/tags')?new Response(JSON.stringify({models:[{name:MODEL,digest:DIGEST}]})):{status:200,body:{getReader(){opened();return reader;}}}});
 await t.initialize();t.beginCase('nonsettling-reader');const controller=new AbortController();const openedPromise=new Promise(resolve=>{opened=resolve;});const requestPromise=t.request('judge',{...request,signal:controller.signal});
 await openedPromise;controller.abort();await assert.rejects(requestPromise,{code:'CANCELLED'});assert.equal(t.snapshot().physicalPending,1);
 await assert.rejects(t.close(),{code:'PHYSICAL_TRANSPORT_PENDING'});
});
test('a closed reader does not hide an unresolved underlying cancellation',async()=>{
 let opened;const openedPromise=new Promise(resolve=>{opened=resolve;});
 const reader={read:async()=>{opened();throw new DOMException('aborted','AbortError');},cancel:()=>new Promise(()=>{}),closed:Promise.resolve(),releaseLock(){}};
 const t=create({phase:'A',fetch:async url=>url.endsWith('/api/tags')?new Response(JSON.stringify({models:[{name:MODEL,digest:DIGEST}]})):{status:200,body:{getReader:()=>reader}}});
 await t.initialize();t.beginCase('pending-cancellation');const controller=new AbortController();const task=t.request('judge',{...request,signal:controller.signal});
 await openedPromise;controller.abort();await assert.rejects(task,{code:'CANCELLED'});
 assert.equal(t.snapshot().physicalPending,1);await assert.rejects(t.close(),{code:'PHYSICAL_TRANSPORT_PENDING'});
});
