'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createBoundedClient,summarize}=require('./fixtures/applicationCapacityClient');
test('fixed outstanding and per-owner bounds reject without dispatch or retries',async()=>{
 let release,calls=0;const held=new Promise(r=>release=r),client=createBoundedClient({maxOutstanding:2,request:async()=>{calls++;await held;return{status:200,body:{private:'not metrics'}};}});
 const args=owner=>({owner,endpoint:'/api/auth/me',operation:()=>{}});const a=client.call(args('a')),b=client.call(args('b'));
 await assert.rejects(client.call(args('a')),/WORKLOAD_BOUND/);await assert.rejects(client.call(args('c')),/WORKLOAD_BOUND/);release();await Promise.all([a,b]);assert.equal(calls,2);assert.equal(client.snapshot().peak,2);assert.equal(client.snapshot().active,0);assert(!JSON.stringify(client.snapshot()).includes('private'));
});
test('deadline aborts underlying request and late completion cannot add observations',async()=>{
 let resolve,signal,calls=0;const client=createBoundedClient({request:(_op,s)=>{calls++;signal=s;return new Promise(r=>resolve=r);}});
 await assert.rejects(client.call({owner:'a',endpoint:'/api/read',operation:()=>{},timeoutMs:5}),{name:'TimeoutError'});assert(signal.aborted);resolve({status:200});await new Promise(r=>setImmediate(r));assert.equal(calls,1);assert.equal(client.snapshot().requests.length,1);assert.equal(client.snapshot().requests[0].outcome,'timeout');
});
test('parent cancellation settles a noncooperative request without response claims',async()=>{
 const c=new AbortController(),client=createBoundedClient({request:()=>new Promise(()=>{})});const work=client.call({owner:'a',endpoint:'/api/read',operation:()=>{},signal:c.signal});c.abort();await assert.rejects(work,{name:'AbortError'});assert.equal(client.snapshot().active,0);assert.equal(client.snapshot().requests[0].status,null);
});
test('missing or malformed metric observations never substitute zero',()=>{assert.throws(()=>summarize([]),/unavailable/);assert.throws(()=>summarize([{elapsedMs:NaN}]),/unavailable/);assert.deepEqual(summarize([{elapsedMs:1},{elapsedMs:3}]),{count:2,p50:1,p95:3,p99:3,max:3});});
test('aggregate request and metric bound cannot grow after finite admission budget',async()=>{let calls=0;const c=createBoundedClient({maxRequests:2,request:async()=>{calls++;return{status:200};}});const args={owner:'a',endpoint:'/api/read',operation:()=>{}};await c.call(args);await c.call(args);await assert.rejects(c.call(args),/WORKLOAD_BOUND/);assert.equal(calls,2);assert.equal(c.snapshot().requests.length,2);});
