'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const source=fs.readFileSync(require.resolve('./postgres/ownedV03PostWork'),'utf8');
const make=new Function('require',source.slice(0,source.indexOf('function createPostWork('))+';return coordinator;')(
 ()=>require('./postgres/ownedV03CombinedLease'));
function fixture(){
 let now=4460000;const calls=[],expiry=11096000,wrapper={startedAtMs:now,deadlineMs:now+1800000,graceDeadlineMs:now+2100000};
 const owner={nowMs:()=>now,wrapperWindow:()=>wrapper,binding:()=>({expiresAtMs:expiry})};
 const main={terminal:async()=>{now=6260000-1;return {closed:true,code:0,signal:null,spawnFailure:null,observedAtMs:now};},
  retire:async()=>{calls.push('main');now+=10000;return {groupAbsent:true};}};
 const controller={owner,retire:async()=>{calls.push('producers');now+=4536000;return {cleanupVerified:true,diagnosticAbsent:true,listingsAbsent:true};}};
 const postgres={retire:async post=>{calls.push('pg');post.pgDeadline();now+=20000;return {absent:true};}};
 return {main,controller,owner,postgres,calls,make:()=>{const value=make(controller,main,undefined,undefined,postgres);value.noteWorkHandoff(false);return value;},advance:n=>{now+=n;}};
}
test('actual post-work joins MAIN then exact PG before builders with unchanged expiry',async()=>{
 const f=fixture(),value=f.make(),first=value.retireAfterMain();assert.strictEqual(first,value.retireAfterMain());
 const receipt=await first;assert.deepEqual(f.calls,['main','pg','producers']);
 assert.equal(receipt.workTerminalSucceeded,true);assert.equal(receipt.qualificationComplete,false);
 assert.equal(receipt.deadlineMs,11095999);assert.equal(value.pgDeadline(),11095999);
});
test('late join consumes unused grace rather than minting a new PG cleanup lease',async()=>{
 const f=fixture(),value=f.make();await value.retireAfterMain();f.advance(120000);
 assert.throws(()=>value.pgDeadline(),{code:'V03_POST_WORK_PG_RESERVE'});
 assert.equal(value.status().deadlineMs,11095999);
});
test('unknown MAIN group prevents producer deletion and PG authority',async()=>{
 const f=fixture();f.main.retire=async()=>({groupAbsent:false});const value=f.make();
 await assert.rejects(value.retireAfterMain(),{code:'V03_POST_WORK_MAIN_UNJOINED'});
 assert.equal(f.calls.includes('producers'),false);assert.throws(()=>value.pgDeadline());
});
test('local-only or false producer cleanup still denies final publication',async()=>{
 const f=fixture();f.controller.retire=async()=>({cleanupVerified:true,diagnosticAbsent:true,listingsAbsent:false});
 const value=f.make();await value.retireAfterMain();assert.throws(()=>value.publicationDeadline(),{code:'V03_POST_WORK_PUBLICATION_DEADLINE'});
});
test('failed original terminal remains failed even if cleanup later succeeds',async()=>{
 const f=fixture();f.main.terminal=async()=>({closed:true,code:1,signal:null,spawnFailure:null,observedAtMs:f.owner.nowMs()});
 const result=await f.make().retireAfterMain();assert.equal(result.workTerminalSucceeded,false);assert.equal(result.qualificationComplete,false);
});
test('serialized proof and caller-shaped controller cannot mint post-work ownership',()=>{
 const api=require('./postgres/ownedV03PostWork');
 assert.throws(()=>api.createPostWork({owner:{}},{}),{code:'V03_PRIVATE_EXECUTORS_REQUIRED'});
 assert.throws(()=>api.assertPostWork({cleanupVerified:true},{}),{code:'V03_POST_WORK_REQUIRED'});
});
test('work timeout uses original shutdown before group and producer retirement, never qualifies',async()=>{
 const f=fixture();f.main.terminal=()=>new Promise(()=>{});
 f.main.shutdownTimedOutWork=async()=>{f.calls.push('original-timeout-shutdown');return {terminal:{closed:true,code:0,signal:null,spawnFailure:null,observedAtMs:6260001}};};
 const value=make(f.controller,f.main,callback=>{queueMicrotask(callback);return 1;},()=>{},f.postgres);
 const result=await value.retireAfterMain();
 assert.deepEqual(f.calls,['original-timeout-shutdown','main','pg','producers']);
 assert.equal(result.workTerminalSucceeded,false);assert.equal(result.failure,'V03_MAIN_WORK_EXPIRED');
});
test('failed forced shutdown cannot authorize producer or PG deletion',async()=>{
 const f=fixture();f.main.terminal=()=>new Promise(()=>{});
 f.main.shutdownTimedOutWork=async()=>{throw Object.assign(Error('unjoined'),{code:'V03_MAIN_KILL_UNJOINED',cleanupDebt:true});};
 const value=make(f.controller,f.main,callback=>{queueMicrotask(callback);return 1;},()=>{},f.postgres);
 await assert.rejects(value.retireAfterMain(),{code:'V03_MAIN_KILL_UNJOINED'});
 assert.deepEqual(f.calls,[]);assert.throws(()=>value.pgDeadline(),{code:'V03_POST_WORK_QUIESCENCE_REQUIRED'});
});

test('PG failure prevents idle-bridge builder cleanup and preserves the primary',async()=>{
 const f=fixture(),error=Object.assign(Error('owned-pg-failed'),{cleanupDebt:true});
 f.postgres.retire=async()=>{f.calls.push('pg');throw error;};
 const value=f.make();await assert.rejects(value.retireAfterMain(),e=>e===error);
 assert.deepEqual(f.calls,['main','pg']);assert.throws(()=>value.publicationDeadline());
});
test('false PG absence cannot enter builder shared-snapshot phase',async()=>{
 const f=fixture();f.postgres.retire=async()=>({absent:false});
 const value=f.make();await assert.rejects(value.retireAfterMain(),{code:'V03_POST_WORK_PG_UNPROVEN'});
 assert.equal(f.calls.includes('producers'),false);
});
test('PG cannot consume the reserved original producer retirement window',async()=>{
 const f=fixture();f.main.retire=async()=>{f.advance(110000);return {groupAbsent:true};};
 const value=f.make();await assert.rejects(value.retireAfterMain(),{code:'V03_POST_WORK_PG_RESERVE'});
 assert.equal(f.calls.includes('producers'),false);
});
