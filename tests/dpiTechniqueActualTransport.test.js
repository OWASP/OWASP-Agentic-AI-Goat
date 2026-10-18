'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {createTechniqueTransport,MODEL,DIGEST,REQUEST_LIMIT}=require('./fixtures/dpiTechniqueActualTransport');
const response=text=>({status:200,body:new ReadableStream({start(c){c.enqueue(Buffer.from(text));c.close();}})});
const tags=()=>response(JSON.stringify({models:[{name:MODEL,digest:DIGEST}]}));
const wire=reason=>response(JSON.stringify({model:MODEL,message:{content:'controlled'},done:true,done_reason:reason})+'\n');
const body=JSON.stringify({model:MODEL,stream:true,messages:[],options:{temperature:0}});
const req={method:'POST',path:'/api/chat',body};
test('A counts metadata and both hops, caps two Judge attempts and denies actor',async()=>{let calls=0;const t=createTechniqueTransport({phase:'A',fetch:async url=>{calls++;return url.endsWith('tags')?tags():wire('stop');}});await t.initialize();t.beginCase('one');await t.request('judge',req);await t.request('judge',req);await assert.rejects(t.request('judge',req),{code:'CASE_INFERENCE_BUDGET'});assert.equal(calls,3);assert.equal(t.snapshot().external,3);assert.equal(t.snapshot().hops,6);t.endCase();t.beginCase('two');await assert.rejects(t.request('actor',req));await t.close();});
test('B local tags are bounded and never forwarded; one actor and shared Judge deadline',async()=>{let now=0;const t=createTechniqueTransport({phase:'B',clock:()=>now,fetch:async url=>url.endsWith('tags')?tags():wire('stop')});await t.initialize();t.beginCase('case');for(let i=0;i<3;i++)await t.request('actor',{method:'GET',path:'/api/tags'});await assert.rejects(t.request('actor',{method:'GET',path:'/api/tags'}),{code:'LOCAL_METADATA_BUDGET'});await t.request('actor',req);await assert.rejects(t.request('actor',req));await t.request('judge',req);now=90001;await assert.rejects(t.request('judge',req),{code:'DEADLINE'});assert.equal(t.snapshot().calls.at(-1).status,'incomplete');assert.equal(t.snapshot().external,3);await t.close();});
test('wrong model, request size and abnormal termination fail closed',async()=>{const t=createTechniqueTransport({phase:'A',fetch:async url=>url.endsWith('tags')?tags():wire('length')});await t.initialize();t.beginCase('one');await assert.rejects(t.request('judge',{...req,body:'x'.repeat(REQUEST_LIMIT+1)}));await assert.rejects(t.request('judge',req),{code:'INCOMPLETE_TERMINATION'});assert.equal(t.snapshot().calls.at(-2).status,'incomplete');await t.close();});
test('metadata identity mismatch cannot begin case, no retry',async()=>{const t=createTechniqueTransport({phase:'A',fetch:async()=>response('{"models":[]}')});await assert.rejects(t.initialize(),{code:'MODEL_IDENTITY'});assert.throws(()=>t.beginCase('x'));await assert.rejects(t.initialize());await t.close();});
test('caller cancellation aborts upstream and close awaits physical settlement',async()=>{
 let settle,started;const ready=new Promise(r=>started=r);let signal;
 const t=createTechniqueTransport({phase:'A',fetch:async(url,options)=>{if(url.endsWith('tags'))return tags();signal=options.signal;started();return new Promise((resolve,reject)=>{settle=()=>reject(Error('aborted owned transport'));});}});
 await t.initialize();t.beginCase('cancel');const c=new AbortController();const work=t.request('judge',{...req,signal:c.signal});await ready;c.abort();await assert.rejects(work,{code:'CANCELLED'});assert.equal(signal.aborted,true);assert.equal(t.snapshot().physicalPending,1);assert.throws(()=>t.endCase(),{code:'CASE_PENDING'});
 let closed=false;const closing=t.close().then(()=>closed=true);await Promise.resolve();assert.equal(closed,false);settle();await closing;assert.equal(t.snapshot().physicalPending,0);
});
test('response byte cap rejects without accepting oversized raw output',async()=>{
 const t=createTechniqueTransport({phase:'A',fetch:async url=>url.endsWith('tags')?tags():response('x'.repeat(4194305))});await t.initialize();t.beginCase('large');await assert.rejects(t.request('judge',req),{code:'RESPONSE_LIMIT'});assert.equal(t.snapshot().calls.at(-1).status,'incomplete');await t.close();
});
test('open oversized body cancellation stays physically pending until cancellation settles',async()=>{
 let cancelled,settle;const cancelStarted=new Promise(r=>cancelled=r);
 const stream=new ReadableStream({start(c){c.enqueue(Buffer.alloc(4194305));},cancel(){cancelled();return new Promise(r=>settle=r);}});
 const t=createTechniqueTransport({phase:'A',fetch:async url=>url.endsWith('tags')?tags():{status:200,body:stream}});await t.initialize();t.beginCase('open');const c=new AbortController();const work=t.request('judge',{...req,signal:c.signal});await cancelStarted;c.abort();await assert.rejects(work);assert.equal(t.snapshot().physicalPending,1);
 await assert.rejects(t.close(),{code:'PHYSICAL_TRANSPORT_PENDING'});assert.equal(t.snapshot().physicalPending,1);settle();await new Promise(setImmediate);assert.equal(t.snapshot().physicalPending,0);
});
test('oversized and aborted ingress consume local hops before body admission',async()=>{
 const {EventEmitter}=require('node:events');const t=createTechniqueTransport({phase:'A',fetch:async()=>tags()});await t.initialize();t.beginCase('bad');
 for(const aborted of [false,true]){const req=new EventEmitter();req.method='POST';req.url='/api/chat';req[Symbol.asyncIterator]=async function*(){if(aborted)throw Error('body aborted');yield Buffer.alloc(REQUEST_LIMIT+1);};const res=new EventEmitter();res.writeHead=()=>{};res.end=()=>{};await t.ingress('judge',req,res);}
 assert.equal(t.snapshot().hops,3);assert.equal(t.snapshot().external,1);assert.equal(t.snapshot().calls.filter(r=>r.kind.startsWith('local:')&&r.status==='incomplete').length,2);await t.close();
});
test('synchronous final frame parsing cannot accept after absolute deadline',async()=>{
 let now=0;const t=createTechniqueTransport({phase:'A',clock:()=>now,fetch:async url=>url.endsWith('tags')?tags():wire('stop')});await t.initialize();t.beginCase('late');const parse=JSON.parse;
 JSON.parse=function(text,...rest){const result=parse(text,...rest);if(result.done===true)now=90001;return result;};
 try{await assert.rejects(t.request('judge',req),{code:'DEADLINE'});}finally{JSON.parse=parse;await t.close();}
});
test('rejected body cancellation remains unknown rather than proven absent',async()=>{
 const stream=new ReadableStream({start(c){c.enqueue(Buffer.alloc(4194305));},cancel(){return Promise.reject(Error('cancel failed'));}});
 const t=createTechniqueTransport({phase:'A',fetch:async url=>url.endsWith('tags')?tags():{status:200,body:stream}});await t.initialize();t.beginCase('unknown');await assert.rejects(t.request('judge',req));const before=t.snapshot().external;await assert.rejects(t.request('judge',req),{code:'CASE_SCOPE'});assert.equal(t.snapshot().external,before);await assert.rejects(t.close(),{code:'PHYSICAL_TRANSPORT_PENDING'});assert.equal(t.snapshot().physicalPending,1);
});

test('pre-aborted request retains consumed local hop as incomplete without external dispatch',async()=>{const t=createTechniqueTransport({phase:'A',fetch:async()=>tags()});await t.initialize();t.beginCase('abort');const c=new AbortController();c.abort();await assert.rejects(t.request('judge',{...req,signal:c.signal}));assert.equal(t.snapshot().external,1);assert.equal(t.snapshot().hops,2);assert.equal(t.snapshot().calls.at(-1).status,'incomplete');await t.close();});
