'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),http=require('node:http'),vm=require('node:vm');
const {EventEmitter}=require('node:events');

const MODEL='llama3.1:8b';
const DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const source=fs.readFileSync(require.resolve('./postgres/secureshopMailActualTransport'),'utf8');
const payload=Buffer.from(JSON.stringify({model:MODEL,messages:[{role:'user',content:'controlled'}]}));

async function fixture(record,{deferResponse=false,deferClose=false,metadataFetch,allowMetadata=false}={}){
 const upstreams=[],pending=[],pendingCloses=[];
 const fakeHttp={
  createServer:http.createServer,
  request(_options,onResponse){
   const upstream=new EventEmitter();upstream.closed=false;
   upstream.destroy=()=>{if(upstream.destroyRequested)return;upstream.destroyRequested=true;
    const finish=()=>{upstream.closed=true;
     if(upstream.response&&!upstream.responseEnded)upstream.response.emit('error',Error('OWNED_ABORT'));
     upstream.emit('close');};
    if(deferClose)pendingCloses.push(finish);else finish();};
   upstream.end=()=>{
    const reply=()=>{if(upstream.closed)return;const response=new EventEmitter();
     response.statusCode=200;response.headers={'content-type':'application/json'};
     upstream.response=response;onResponse(response);
     if(!upstream.closed){response.emit('data',Buffer.from('{"model":"controlled"}\n'));
      upstream.responseEnded=true;response.emit('end');upstream.destroy();}};
    if(deferResponse)pending.push(reply);else setImmediate(reply);
   };
   upstreams.push(upstream);return upstream;
  },
 };
 const module={exports:{}};
 vm.runInNewContext(source,{module,require:name=>name==='node:http'?fakeHttp:require(name),
  fetch:async(...args)=>metadataFetch?.(...args)??({ok:true,json:async()=>({models:[{name:MODEL,digest:DIGEST}]})}),
  Buffer,Date,Error,TypeError,Set,Promise,AbortSignal,AbortController,setTimeout,clearTimeout});
 const transport=await module.exports.createMailActualTransport({maxHttpCalls:2,record,allowMetadata});
 return {transport,upstreams,pending,pendingCloses};
}
function post(url){return new Promise(resolve=>{
 const req=http.request(url+'/api/chat',{method:'POST',headers:{'content-type':'application/json','content-length':payload.length}},res=>{
  let body='';res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,body}));
  res.on('error',error=>resolve({error:error.code||error.message}));
 });
 req.setTimeout(3000,()=>req.destroy(Error('CONTROL_TIMEOUT')));
 req.on('error',error=>resolve({error:error.code||error.message}));req.end(payload);
 });}

test('failed pre-dispatch record never contacts upstream and remains fatal after idempotent close',async()=>{
 const x=await fixture(()=>{throw Error('private recorder detail');});
 const result=await post(x.transport.actorUrl);
 assert.ok(result.status===503||result.error,'request must fail closed');
 assert.equal(x.upstreams.length,0);assert.equal(x.transport.calls.length,1);
 const unhealthy=error=>error.code==='ACTUAL_WIRE_RECORDING_FAILED'&&!error.message.includes('private');
 assert.throws(()=>x.transport.assertHealthy(),unhealthy);
 await assert.rejects(x.transport.close(),unhealthy);
 await assert.rejects(x.transport.close(),unhealthy);
});

test('header recorder failure aborts owned upstream and sockets without listener escape',async()=>{
 const x=await fixture(value=>{if(value.calls[0]?.status===200)throw Error('private header detail');});
 const result=await post(x.transport.actorUrl);
 assert.ok(result.status===503||result.error,'request must fail closed');
 assert.equal(x.upstreams.length,1);assert.equal(x.upstreams[0].closed,true);
 assert.throws(()=>x.transport.assertHealthy(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
 await assert.rejects(x.transport.close(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
});

test('terminal recorder failure cannot turn an observed response into an accepted transport',async()=>{
 const x=await fixture(value=>{if(value.calls[0]?.responseComplete)throw Error('private terminal detail');});
 await post(x.transport.actorUrl);
 assert.equal(x.transport.calls[0].responseComplete,true);
 assert.equal(x.upstreams[0].closed,true);
 assert.throws(()=>x.transport.assertHealthy(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
 await assert.rejects(x.transport.close(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
});

test('one late recording failure joins both active owned upstreams',async()=>{
 const x=await fixture(value=>{if(value.calls.some(call=>call.status===200))throw Error('late recorder failure');},{deferResponse:true});
 const actor=post(x.transport.actorUrl),judge=post(x.transport.judgeUrl);
 for(let i=0;i<100&&x.pending.length<2;i++)await new Promise(resolve=>setImmediate(resolve));
 assert.equal(x.pending.length,2);assert.equal(x.upstreams.length,2);
 x.pending[0]();
 await Promise.all([actor,judge]);
 assert(x.upstreams.every(upstream=>upstream.closed));
 assert.throws(()=>x.transport.assertHealthy(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
 await assert.rejects(x.transport.close(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
});

test('close waits for asynchronous outbound retirement, not just inbound listener closure',async()=>{
 const x=await fixture(undefined,{deferResponse:true,deferClose:true});
 const response=post(x.transport.actorUrl);
 for(let i=0;i<100&&x.pending.length<1;i++)await new Promise(resolve=>setImmediate(resolve));
 assert.equal(x.pending.length,1);
 let settled=false;const closing=x.transport.close().then(()=>{settled=true;});
 await response;await new Promise(resolve=>setImmediate(resolve));
 assert.equal(x.pendingCloses.length,1);assert.equal(settled,false);
 x.pendingCloses[0]();await closing;
 assert.equal(settled,true);await x.transport.close();
});

test('recorder failure aborts a second partially uploaded request without an unhandled listener rejection',async()=>{
 const x=await fixture(()=>{throw Error('controlled recorder failure');});
 const partial=http.request(x.transport.judgeUrl+'/api/chat',{method:'POST',headers:{
  'content-type':'application/json','content-length':payload.length+100,
 }});
 const partialEnd=new Promise(resolve=>{partial.on('error',resolve);partial.on('close',resolve);});
 partial.write(payload.subarray(0,5));
 for(let i=0;i<100;i++){await new Promise(resolve=>setImmediate(resolve));
  if(partial.socket&&!partial.socket.connecting)break;}
 await post(x.transport.actorUrl);await partialEnd;
 assert.equal(x.upstreams.length,0);
 await assert.rejects(x.transport.close(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
});

test('close aborts and joins an in-flight metadata fetch',async()=>{
 let probes=0,aborted=false;
 const good=()=>({ok:true,json:async()=>({models:[{name:MODEL,digest:DIGEST}]})});
 const x=await fixture(undefined,{allowMetadata:true,metadataFetch:(_url,options)=>{
  if(++probes===1)return good();
  return new Promise((_,reject)=>options.signal.addEventListener('abort',()=>{
   aborted=true;reject(Error('CONTROLLED_ABORT'));
  },{once:true}));
 }});
 const metadata=new Promise(resolve=>{const request=http.get(x.transport.actorUrl+'/api/tags',response=>{
  response.resume();response.on('end',resolve);response.on('error',resolve);
 });request.on('error',resolve);});
 try{for(let i=0;i<100&&probes<2;i++)await new Promise(resolve=>setImmediate(resolve));
  assert.equal(probes,2);}finally{await x.transport.close();await metadata;}
 assert.equal(aborted,true);assert.equal(x.transport.calls.length,0);
});

test('thenable recorder is rejected before dispatch and cannot leak a rejected promise',async()=>{
 const x=await fixture(()=>Promise.reject(Error('private async rejection')));
 await post(x.transport.actorUrl);
 assert.equal(x.upstreams.length,0);
 assert.throws(()=>x.transport.assertHealthy(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
 await assert.rejects(x.transport.close(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
});
