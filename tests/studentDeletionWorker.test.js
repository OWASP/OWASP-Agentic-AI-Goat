'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createStudentDeletionWorker}=require('../server/services/studentDeletionWorker');
function fixture(adapter){
 const events=[];let pending=true;
 const repository={claim:async()=>({leaseToken:'lease'}),nextStep:async()=>pending?{subjectId:17,stepKey:'lab'}:null,
 renew:async()=>events.push('renew'),acknowledge:async()=>{events.push('ack');pending=false;},
 complete:async()=>{events.push('complete');return{state:'completed'};},fail:async()=>events.push('fail')};
 return {events,repository,worker:createStudentDeletionWorker({repository,adapters:{lab:adapter}})};
}
test('worker binds cleanup to recorded owner and acknowledges only confirmed effects',async()=>{
 const f=fixture(async scope=>{assert.equal(scope.subjectId,17);assert.equal(scope.idempotencyKey,'job:lab');await scope.check();return{completed:true};});
 assert.deepEqual(await f.worker.run('job'),{state:'completed'});
 assert.deepEqual(f.events,['renew','renew','ack','complete']);
});
test('unconfirmed or throwing adapters cannot complete a deletion',async()=>{
 for(const adapter of [async()=>({completed:false}),async()=>{throw Error('private database detail');}]){
  const f=fixture(adapter);const result=await f.worker.run('job');
  assert.deepEqual(result,{state:'incomplete',code:'DELETION_INCOMPLETE'});
  assert.deepEqual(f.events,['renew','fail']);
 }
});
test('stale worker cannot acknowledge or mark successor failed',async()=>{
 const f=fixture(async()=>{throw Object.assign(Error('lost'),{code:'STALE_DELETION_LEASE'});});
 assert.equal((await f.worker.run('job')).code,'STALE_DELETION_LEASE');assert.deepEqual(f.events,['renew']);
});

test('MCP retirement failure keeps the same deletion job retryable without deleting sibling state',async()=>{
 const {createStudentDeletionAdapters}=require('../server/services/studentDeletionAdapters');
 const owners=new Map([['17',['owned-progress']],['18',['sibling-progress']]]);
 const events=[];let unavailable=true,acknowledged=false,attempt=0;
 const repository={
  claim:async jobId=>{assert.equal(jobId,'mcp-job');return{leaseToken:`lease-${++attempt}`};},
  nextStep:async()=>acknowledged?null:{subjectId:17,stepKey:'mcp_workshop'},
  renew:async scope=>{assert.equal(scope.jobId,'mcp-job');assert.equal(scope.leaseToken,`lease-${attempt}`);},
  fail:async scope=>{assert.equal(scope.stepKey,'mcp_workshop');events.push('failed');},
  acknowledge:async scope=>{
   assert.equal(scope.stepKey,'mcp_workshop');assert.equal(owners.has('17'),false);
   events.push('acknowledged');acknowledged=true;
  },
  complete:async()=>{assert.equal(acknowledged,true);events.push('completed');return{state:'completed'};},
 };
 const adapters=createStudentDeletionAdapters(name=>{
  if(name==='../routes/mcpWorkshop')return{resetOwner:async(owner,work,{check})=>{
   assert.equal(owner,'17');await check();events.push('retirement');
   if(unavailable)throw Error('Owned MCP retirement unavailable');
   await work();
  }};
  if(name==='../database/postgres/mcpWorkshopDb')return{destroyOwner:async owner=>{
   assert.equal(owner,'17');events.push('destroy');owners.delete(owner);return{removed:1};
  }};
  throw Error(`Unexpected dependency ${name}`);
 });
 const worker=createStudentDeletionWorker({repository,adapters});
 assert.deepEqual(await worker.run('mcp-job'),{state:'incomplete',code:'DELETION_INCOMPLETE'});
 assert.deepEqual(events,['retirement','failed']);
 assert.equal(acknowledged,false);
 assert.deepEqual([...owners],[['17',['owned-progress']],['18',['sibling-progress']]]);
 unavailable=false;
 assert.deepEqual(await worker.run('mcp-job'),{state:'completed'});
 assert.deepEqual(events,['retirement','failed','retirement','destroy','acknowledged','completed']);
 assert.deepEqual([...owners],[['18',['sibling-progress']]]);
 // The retained repository step prevents a completed replay dispatching cleanup.
 assert.deepEqual(await worker.run('mcp-job'),{state:'completed'});
 assert.equal(events.filter(event=>event==='destroy').length,1);
 assert.equal(events.filter(event=>event==='retirement').length,2);
 assert.deepEqual([...owners],[['18',['sibling-progress']]]);
});

test('a changed cleanup manifest is quarantined without dispatching an adapter or failing a prior step',async()=>{
 const events=[];
 const repository={
  claim:async()=>({leaseToken:'lease'}),
  nextStep:async()=>{throw Object.assign(Error('changed plan'),{code:'DELETION_MANIFEST_MISMATCH'});},
  quarantine:async scope=>{assert.deepEqual(scope,{jobId:'job',leaseToken:'lease'});events.push('quarantine');return{state:'quarantined',code:'DELETION_MANIFEST_MISMATCH'};},
  fail:async()=>{throw Error('Must not attribute plan mismatch to a cleanup step');}
 };
 const worker=createStudentDeletionWorker({repository,adapters:{lab:async()=>{throw Error('Must not execute');}}});
 assert.deepEqual(await worker.run('job'),{state:'quarantined',code:'DELETION_MANIFEST_MISMATCH'});
 assert.deepEqual(events,['quarantine']);
});

test('cancellation before admission does not claim a job',async()=>{
 const controller=new AbortController();controller.abort();
 const worker=createStudentDeletionWorker({repository:{claim:()=>{throw Error('Must not claim');}},adapters:{}});
 await assert.rejects(worker.run('job',{signal:{aborted:false}}),TypeError);
 await assert.rejects(worker.run('job',{leaseMs:0}),TypeError);
 assert.deepEqual(await worker.run('job',{signal:controller.signal}),{state:'cancelled',code:'DELETION_CANCELLED'});
});

test('cancellation reaches the active adapter and drains it without acknowledging its result',async()=>{
 let entered,release;
 const started=new Promise(resolve=>{entered=resolve;});
 const pending=new Promise(resolve=>{release=resolve;});
 const controller=new AbortController();let adapterSignal,finished=false;
 const f=fixture(async scope=>{assert.equal(scope.jobId,'job');adapterSignal=scope.signal;entered();await pending;return{completed:true};});
 const work=f.worker.run('job',{signal:controller.signal,leaseMs:1000}).then(result=>{finished=true;return result;});
 await started;controller.abort();
 assert.equal(adapterSignal.aborted,true);assert.equal(finished,false);
 release();assert.equal((await work).state,'cancelled');
 assert.deepEqual(f.events,['renew']);
});

test('heartbeat retains authority across a slow adapter and stops after completion',async()=>{
 let expiresAt=0,renewals=0,pending=true;
 const repository={
  claim:async(_job,ms)=>{if(Date.now()<expiresAt)return null;expiresAt=Date.now()+ms;return{leaseToken:'lease'};},
  renew:async({leaseMs})=>{assert.ok(Date.now()<expiresAt,'worker renewed an unexpired lease');expiresAt=Date.now()+leaseMs;renewals++;},
  nextStep:async()=>pending?{subjectId:17,stepKey:'lab'}:null,
  acknowledge:async()=>{pending=false;},complete:async()=>({state:'completed'}),
  fail:async()=>{throw Error('Unexpected failure');}
 };
 const worker=createStudentDeletionWorker({repository,adapters:{lab:async()=>{
  await new Promise(resolve=>setTimeout(resolve,1200));
  assert.equal(await repository.claim('job',1000),null,'successor cannot claim slow active cleanup');
  return{completed:true};
 }}});
 assert.equal((await worker.run('job',{leaseMs:1000})).state,'completed');
 assert.ok(renewals>=3);const count=renewals;
 await new Promise(resolve=>setTimeout(resolve,400));assert.equal(renewals,count);
});

test('lost heartbeat authority aborts adapter work and cannot acknowledge or fail a successor',async()=>{
 let calls=0;
 const f=fixture(async({signal})=>{
  await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));
  return{completed:true};
 });
 f.repository.renew=async()=>{if(++calls>1)throw Object.assign(Error('Lease lost'),{code:'STALE_DELETION_LEASE'});};
 assert.deepEqual(await f.worker.run('job',{leaseMs:1000}),{state:'incomplete',code:'STALE_DELETION_LEASE'});
 assert.deepEqual(f.events,[]);
});
