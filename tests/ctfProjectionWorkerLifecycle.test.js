'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createCtfProjectionWorkerLifecycle:create}=require('../server/services/ctfProjectionWorkerLifecycle');
const tick=()=>new Promise(r=>setTimeout(r,2));
async function until(fn){const end=Date.now()+1000;while(!fn()){assert(Date.now()<end,'controlled condition deadline');await tick();}}
function fixture(overrides={}){let calls=0;const identity={next:async()=>{calls++;return null;},acknowledge:async()=>assert.fail('empty queue')};const worker=create({identity,ctfPool:{connect:async()=>assert.fail('empty queue must not borrow CTF')},readiness:async()=>true,pollMs:10,batchTimeoutMs:500,drainMs:20,...overrides});return{worker,get calls(){return calls;},identity};}
test('construction is inert; explicit start polls existing batch and stop is terminal',async()=>{
 const f=fixture();await tick();assert.equal(f.calls,0);assert.equal(f.worker.status().state,'paused');f.worker.start();await until(()=>f.calls>=2);assert.equal(f.worker.status().ready,true);assert.equal((await f.worker.stop()).drained,true);const n=f.calls;await new Promise(r=>setTimeout(r,20));assert.equal(f.calls,n);assert.throws(()=>f.worker.start(),/stopped/);
});
test('single flight survives repeated start/wake; pause aborts and drains before resume',async()=>{
 let release,signal,calls=0;const f=fixture({identity:{next:async o=>{calls++;signal=o.signal;await new Promise(r=>{release=r;});return null;},acknowledge:async()=>{} }});
 f.worker.start();await until(()=>release);for(let i=0;i<20;i++){f.worker.start();f.worker.wake();}assert.equal(calls,1);const paused=f.worker.pause();assert(signal.aborted);assert.throws(()=>f.worker.start(),/draining/);release();assert.equal((await paused).drained,true);await tick();assert.equal(calls,1);await f.worker.stop();
});
test('uncooperative readiness cannot be mistaken for drained or invoke batch after stop',async()=>{
 let release;const f=fixture({readiness:()=>new Promise(r=>{release=r;})});f.worker.start();await until(()=>release);const result=await f.worker.stop();assert.equal(result.drained,false);assert.equal(result.active,true);release(true);await until(()=>!f.worker.status().active);assert.equal(f.calls,0);assert.equal((await f.worker.stop()).drained,true);
});
test('false readiness and thrown batch pause without hidden retries or secret diagnostics',async()=>{
 let ready=false;const f=fixture({readiness:async()=>ready});f.worker.start();await until(()=>f.worker.status().lastOutcome==='not_ready');assert.equal(f.calls,0);ready=true;f.identity.next=async()=>{throw Error('private token and SQL');};f.worker.start();await until(()=>f.worker.status().lastOutcome==='failed');assert.equal(f.worker.status().state,'paused');assert(!JSON.stringify(f.worker.status()).includes('private'));await f.worker.stop();
});
test('readiness is rechecked each batch and loss pauses future polling',async()=>{
 let checks=0;const f=fixture({readiness:async()=>++checks===1});f.worker.start();await until(()=>f.worker.status().lastOutcome==='not_ready');assert.equal(f.calls,1);assert.equal(checks,2);await f.worker.stop();
});
test('deadline abort retains active slot until underlying callback settles',async()=>{
 let release,signal;const f=fixture({batchTimeoutMs:10,readiness:o=>{signal=o.signal;return new Promise(r=>{release=r;});}});f.worker.start();await until(()=>signal?.aborted);assert.equal(f.worker.status().lastOutcome,'deadline');assert.throws(()=>f.worker.start(),/draining/);release(true);await until(()=>!f.worker.status().active);assert.equal(f.calls,0);await f.worker.stop();
});
test('invalid bounds rejected before any work',()=>{for(const option of [{pollMs:0},{maxEvents:17},{batchTimeoutMs:30001},{drainMs:0}])assert.throws(()=>fixture(option),/bounds/);});
test('actual canonical deletion head defers without CTF borrow or ACK, resumes after owned cursor advance',async()=>{
 const {createCtfLifecycleRepository}=require('../server/database/postgres/ctfLifecycleRepository'),{createHash}=require('node:crypto');
 const command={version:1,kind:'student_delete',operationId:'11111111-1111-1111-1111-111111111111',jobId:'22222222-2222-2222-2222-222222222222',subjectId:'1',participantId:null,generationBefore:'1',generationAfter:'2',globalRevision:'0',ownerRevision:'1',occurredAt:'2026-09-27T00:00:00.000Z',policyVersion:'ctf-student-delete-v1'};
 const raw=JSON.stringify(command),row={kind:'student_delete',operation_id:command.operationId,canonical_command:raw,command_hash:createHash('sha256').update(raw).digest('hex'),sequence:'1'};let head=row,reads=0;
 const identity=createCtfLifecycleRepository({connect:async()=>({release(){},query:async sql=>{if(sql.includes('JOIN identity.ctf_outbox')){reads++;return{rows:head?[head]:[]};}assert(!sql.includes('ack_ctf_projection'));return{rows:[]};}})});
 const f=fixture({identity});f.worker.start();await until(()=>f.worker.status().lastOutcome==='deferred');assert.equal(f.worker.status().state,'running');assert.equal(f.worker.status().ready,false);
 head=null;f.worker.wake();await until(()=>f.worker.status().lastOutcome==='applied');assert(reads>=2);await f.worker.stop();
 for(const broken of [{...row,operation_id:command.jobId},{...row,command_hash:'0'.repeat(64)},{...row,kind:'unknown'}]){head=broken;await assert.rejects(identity.next());}
});
test('request pump shares active work and caller cancellation cancels waiting only',async()=>{
 let release,ownedSignal,calls=0;const f=fixture({identity:{next:async({signal})=>{calls++;ownedSignal=signal;await new Promise(r=>{release=r;});return null;},acknowledge:async()=>{}}});f.worker.start();const controller=new AbortController();const wait=f.worker.pump({signal:controller.signal});await until(()=>release);const second=f.worker.pump();controller.abort();await assert.rejects(wait,{code:'CTF_REQUEST_CANCELLED'});assert.equal(ownedSignal.aborted,false);assert.equal(calls,1);release();await second;await f.worker.stop();
});
test('pump wait is bounded even when readiness ignores cancellation; active slot stays owned',async()=>{
 let release;const f=fixture({batchTimeoutMs:10,drainMs:10,readiness:()=>new Promise(r=>{release=r;})});f.worker.start();const value=await f.worker.pump();assert.equal(value.active,true);assert.equal(value.state,'paused');assert.equal(value.lastOutcome,'deadline');release(true);await until(()=>!f.worker.status().active);await f.worker.stop();
});
