'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {createHash}=require('node:crypto');
const {createDpiScopedActualTransport}=require('./fixtures/dpiScopedActualTransport');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const waitFor=async(predicate)=>{for(let n=0;n<100;n++){const value=predicate();if(value)return value;await new Promise(resolve=>setTimeout(resolve,5));}throw Error('controlled transport did not settle');};
const body=JSON.stringify({model:MODEL,messages:[{role:'system',content:'You are AWS Assistant.'},{role:'user',content:'What is S3?'}]});
function controlledUpstream({deferResponse=false}={}){
 let current;
 const upstreamRequest=(_options,onResponse)=>{
  const request=new EventEmitter();request.destroyed=false;request.errors=[];
  request.destroy=error=>{if(request.destroyed)return;request.destroyed=true;if(error){request.errors.push(error);request.emit('error',error);}request.emit('close');};
  request.end=()=>{const response=new EventEmitter();response.statusCode=200;response.headers={'content-type':'application/x-ndjson'};current={request,response,respond:()=>onResponse(response)};if(!deferResponse)queueMicrotask(current.respond);};
  return request;
 };
 return {upstreamRequest,current:()=>current};
}
async function withTransport(upstreamRequest,run){
 const originalFetch=global.fetch,records=[];let transport;
 global.fetch=async url=>{assert.equal(url,'http://127.0.0.1:11434/api/tags');return {ok:true,json:async()=>({models:[{name:MODEL,digest:DIGEST}]})};};
 try{transport=await createDpiScopedActualTransport({maxHttpCalls:1,upstreamRequest,record:value=>records.push(structuredClone(value))});global.fetch=originalFetch;await run({transport,records,fetch:originalFetch});}finally{global.fetch=originalFetch;await transport?.close();}
}

test('downstream cancellation destroys the upstream and persists bounded partial terminal evidence',async()=>{
 const control=controlledUpstream();
 await withTransport(control.upstreamRequest,async({transport,records,fetch})=>{
  const controller=new AbortController(),request=fetch(transport.actorUrl+'/api/chat',{method:'POST',headers:{'content-type':'application/json'},body,signal:controller.signal});
  const upstream=await waitFor(control.current);upstream.response.emit('data',Buffer.from('{"model":"'+MODEL+'","message":{"content":"partial"}\n'));
  const response=await request;controller.abort();await assert.rejects(response.text());
  const call=await waitFor(()=>transport.calls[0]?.finishedAt&&transport.calls[0]);
  assert.equal(upstream.request.destroyed,true);assert.deepEqual(upstream.request.errors,[]);assert.equal(call.status,200);assert.equal(call.complete,false);assert.equal(call.incomplete,true);assert.match(call.error,/DPI downstream client cancelled/);assert.equal(call.responseBytes,Buffer.byteLength(call.response));assert.equal(call.responseSha256,createHash('sha256').update(call.response).digest('hex'));assert.ok(call.responseBytes>0&&call.responseBytes<4194304);assert.ok(Number.isInteger(call.durationMs)&&call.durationMs>=0);
  const persisted=records.at(-1).calls[0];assert.equal(records.at(-1).controlledTransport,true);assert.equal(persisted.finishedAt,call.finishedAt);assert.equal(persisted.incomplete,true);assert.equal(persisted.complete,false);assert.match(persisted.error,/DPI downstream client cancelled/);
 });
});


test('over-bound upstream data retains at most four MiB and terminalizes without wire admission',async()=>{
 const control=controlledUpstream();
 await withTransport(control.upstreamRequest,async({transport,records,fetch})=>{
  const request=fetch(transport.actorUrl+'/api/chat',{method:'POST',headers:{'content-type':'application/json'},body});
  const upstream=await waitFor(control.current),overBound=Buffer.alloc(4194305,0x61);upstream.response.emit('data',overBound);
  const response=await request;assert.equal(response.status,200);assert.equal(await response.text(),'');
  const call=await waitFor(()=>transport.calls[0]?.finishedAt&&transport.calls[0]);
  assert.equal(call.status,200);assert.equal(call.complete,false);assert.equal(call.incomplete,true);assert.match(call.error,/Model response exceeds bound/);assert.equal(call.responseBytes,4194304);assert.equal(Buffer.byteLength(call.response),4194304);assert.equal(call.responseSha256,createHash('sha256').update(call.response).digest('hex'));assert.equal(records.at(-1).controlledTransport,true);assert.equal(records.at(-1).calls[0].responseBytes,4194304);
 });
});

test('an upstream close before headers produces an explicit terminal record and bounded 503 response',async()=>{
 const control=controlledUpstream({deferResponse:true});
 await withTransport(control.upstreamRequest,async({transport,records,fetch})=>{
  const request=fetch(transport.actorUrl+'/api/chat',{method:'POST',headers:{'content-type':'application/json'},body});
  const upstream=await waitFor(control.current);upstream.request.emit('close');
  const response=await request;assert.equal(response.status,503);assert.equal(await response.text(),'');
  const call=await waitFor(()=>transport.calls[0]?.finishedAt&&transport.calls[0]);
  assert.equal(call.status,null);assert.equal(call.complete,false);assert.equal(call.incomplete,true);assert.match(call.error,/Model upstream closed before complete response/);assert.equal(call.responseBytes,0);assert.equal(call.response,'');assert.equal(call.responseSha256,createHash('sha256').update('').digest('hex'));assert.ok(Number.isInteger(call.durationMs)&&call.durationMs>=0);assert.equal(records.at(-1).controlledTransport,true);assert.equal(records.at(-1).calls[0].finishedAt,call.finishedAt);
 });
});

test('a complete controlled stream records a valid terminal wire and preserves normal response delivery',async()=>{
 const control=controlledUpstream();
 await withTransport(control.upstreamRequest,async({transport,records,fetch})=>{
  const request=fetch(transport.actorUrl+'/api/chat',{method:'POST',headers:{'content-type':'application/json'},body});
  const upstream=await waitFor(control.current),first=JSON.stringify({model:MODEL,message:{role:'assistant',content:'Par'},done:false})+'\n',last=JSON.stringify({model:MODEL,message:{role:'assistant',content:'ís'},done:true,done_reason:'stop'})+'\n';
  upstream.response.emit('data',Buffer.from(first));upstream.response.emit('data',Buffer.from(last));upstream.response.complete=true;upstream.response.emit('end');upstream.request.emit('close');
  const response=await request;assert.equal(response.status,200);assert.equal(await response.text(),first+last);
  const call=await waitFor(()=>transport.calls[0]?.finishedAt&&transport.calls[0]);
  assert.equal(call.status,200);assert.equal(call.complete,true);assert.equal(call.incomplete,false);assert.equal(call.error,null);assert.equal(call.content,'París');assert.equal(call.terminalDone,true);assert.equal(call.terminalReason,'stop');assert.equal(call.responseSha256,createHash('sha256').update(first+last).digest('hex'));assert.equal(records.at(-1).controlledTransport,true);assert.equal(records.at(-1).calls[0].complete,true);
 });
});
