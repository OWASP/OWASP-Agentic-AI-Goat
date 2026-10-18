'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),http=require('node:http');
const {forward}=require('./helpers/mcpProtectedLinuxProxy');
test('only recreation GET health transport interruption is retryable; effect/readback and post-ready remain fatal',async t=>{
 const server=http.createServer((req)=>req.socket.destroy());await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const diagnostics=[],url='http://127.0.0.1:'+server.address().port;
 for(const [phase,method,route,expected] of [['recreating','GET','/owned-targets/health',true],['ready','GET','/owned-targets/health',false],['initial','GET','/owned-targets/health',false],['recreating','POST','/owned-targets/protected-operation',false],['recreating','POST','/owned-targets/protected-receipt',false],['recreating','POST','/owned-targets/health',false]]){
  const p=forward({phase,method,route,request:()=>fetch(url+route,{method,signal:AbortSignal.timeout(2000)}),diagnostic:d=>diagnostics.push(d)});
  if(expected)assert.equal(await p,null);else await assert.rejects(p,TypeError);
 }
 assert.equal(diagnostics.filter(d=>d.outcome==='expected_readiness_interruption').length,1);
 assert.ok(diagnostics.every(d=>Object.keys(d).sort().join(',')==='method,outcome,phase,route'));
});
test('nontransport assertion and malformed response are never retryable; snapshot phase cannot change while awaiting',async()=>{
 await assert.rejects(forward({phase:'recreating',method:'GET',route:'/owned-targets/health',request:async()=>{throw Error('assertion');}}),/assertion/);
 let release;let phase='ready';const p=forward({phase,method:'GET',route:'/owned-targets/health',request:()=>new Promise((_,reject)=>{release=()=>reject(new TypeError('fetch failed',{cause:{code:'UND_ERR_SOCKET'}}));})});phase='recreating';release();await assert.rejects(p,TypeError);
});
