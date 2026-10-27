'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {EventEmitter}=require('node:events');
const source=fs.readFileSync(require.resolve('./postgres/secureshopMailActualTransport'),'utf8');
async function setup({reusedSocket=false,record}={}){
 const servers=[],upstreams=[],timers=[];const module={exports:{}};
 const fakeHttp={createServer(handler){const s=new EventEmitter();s.handler=handler;s.listen=(_p,_h,done)=>done();s.address=()=>({port:10000+servers.length});s.close=done=>done();servers.push(s);return s;},
  request(_options,onResponse){const u=new EventEmitter();u.reusedSocket=reusedSocket;u.onResponse=onResponse;
   u.end=()=>u.emit('socket',{});u.destroy=error=>{if(u.destroyed)return;u.destroyed=true;if(error)u.emit('error',error);u.emit('close');};upstreams.push(u);return u;}};
 vm.runInNewContext(source+'\nmodule.exports.captureLifecycle=createLifecycleCapture;',{
  module,require:n=>n==='node:http'?fakeHttp:require(n),Buffer,Date,Error,TypeError,Set,Promise,AbortSignal,AbortController,
  fetch:async()=>({ok:true,json:async()=>({models:[{name:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}]})}),
  setTimeout:(fn,ms)=>{const t={fn,ms};timers.push(t);return t;},clearTimeout:t=>{t.cleared=true;}});
 const snapshots=[];const transport=await module.exports.createMailActualTransport({record:v=>{snapshots.push(JSON.parse(JSON.stringify(v)));record?.(v);}});
 const req=new EventEmitter();req.method='POST';req.url='/api/chat';req[Symbol.asyncIterator]=async function*(){yield Buffer.from(JSON.stringify({model:'llama3.1:8b',messages:[{role:'user',content:'private-canary'}]}));};
 const res=new EventEmitter();res.headersSent=false;res.writableFinished=false;res.writeHead=()=>{res.headersSent=true;};res.write=()=>{};res.end=()=>{res.writableFinished=true;res.emit('close');};
 servers[0].handler(req,res);for(let i=0;i<10&&!upstreams.length;i++)await Promise.resolve();
 assert.equal(upstreams.length,1);return {transport,req,res,u:upstreams[0],timers,snapshots,capture:module.exports.captureLifecycle};
}
const events=x=>Array.from(x.transport.calls[0].lifecycle);
test('actual proxy preserves ordered client cancellation separately from upstream reset',async()=>{
 const client=await setup();client.req.emit('aborted');client.res.emit('close');
 assert.deepEqual(events(client),['socket_fresh','downstream_aborted','downstream_close_open','upstream_close']);
 await client.transport.close();
 const reset=await setup({reusedSocket:true});reset.u.emit('error',Error('socket hang up'));reset.u.emit('close');
 const e=events(reset);assert.equal(e[0],'socket_reused');assert(e.indexOf('upstream_error')<e.indexOf('downstream_close_finished'));
 assert(!e.includes('downstream_close_open'));assert.equal(reset.transport.calls[0].terminalReason,'upstream_error');
 await reset.transport.close();
});
test('actual owner cleanup and unchanged deadline destroy are explicit, no extra request or retry',async()=>{
 const owner=await setup();await owner.transport.close();assert.deepEqual(events(owner),['socket_fresh','owner_cleanup_destroy','upstream_close']);
 const deadline=await setup({reusedSocket:undefined});const timer=deadline.timers.find(t=>t.ms===60000);assert(timer);timer.fn();
 assert(events(deadline).includes('deadline_destroy'));assert.equal(deadline.transport.calls.length,1);
 assert.equal(deadline.transport.budgetSnapshot().total,1);await deadline.transport.close();
});
test('secondary error/close cannot replace first failure or terminal evidence',async()=>{
 const x=await setup();x.u.emit('error',Error('first controlled failure'));x.u.emit('error',Error('secondary private failure'));x.u.emit('close');
 assert.equal(x.transport.calls[0].error,'first controlled failure');assert.equal(x.transport.calls[0].terminalReason,'upstream_error');
 assert.equal(x.transport.calls[0].responseComplete,false);await x.transport.close();
});
test('lifecycle is enum-only bounded and recording failure still fails closed',async()=>{
 const x=await setup();const call={};const emit=x.capture(call,()=>{});
 assert.throws(()=>emit('private-canary'),/Closed lifecycle/);for(let i=0;i<100;i++)emit('upstream_close');
 assert.equal(call.lifecycle.length,24);assert.equal(call.lifecycle[23],'truncated');assert(!JSON.stringify(call).includes('private-canary'));
 await x.transport.close();
 const broken=await setup({record:v=>{if(v.calls[0]?.lifecycle?.includes('upstream_error'))throw Error('private recorder failure');}});
 broken.u.emit('error',Error('original failure'));
 assert.equal(broken.transport.calls[0].error,'original failure');assert(events(broken).includes('recording_failure_destroy'));
 assert.throws(()=>broken.transport.assertHealthy(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
 await assert.rejects(broken.transport.close(),{code:'ACTUAL_WIRE_RECORDING_FAILED'});
});
