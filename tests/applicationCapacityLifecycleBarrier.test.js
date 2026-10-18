'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {acquireLifecycleBarrier,BLOCKED_SQL}=require('./fixtures/applicationCapacityLifecycleBarrier.cjs');
const runId='11111111-1111-4111-8111-111111111111',ownerKey='["ARIA","7"]';
function fixture({wrongRun=false,releaseFails=false}={}){
 const calls=[];let watchdog;
 class Client{on(){}async connect(){calls.push('connect');}async query(sql,args){calls.push(sql);if(sql.startsWith('SELECT pid'))return{rows:[{pid:10,backend_start:'2026-01-01 00:00:00.123456+00',database_oid:'5',role_oid:'6'}]};if(sql.includes('FOR UPDATE')){assert.deepEqual(args,[runId,ownerKey]);return{rows:[{run_id:runId,owner_key:wrongRun?'["ARIA","8"]':ownerKey,status:'running'}]};}if(sql==='ROLLBACK'&&releaseFails)throw Error('rollback');return{rows:[]};}async end(){calls.push('end');}}
 const args={environment:{IDENTITY_DATABASE_URL:'postgres://runtime@127.0.0.1/identity'},runId,ownerKey,Client,setTimer:(fn,ms)=>{assert.equal(ms,3000);watchdog=fn;return 1;},clearTimer:()=>calls.push('clear'),observeQuery:async(sql,args)=>{assert.equal(sql,BLOCKED_SQL);assert.equal(args[0],10);assert.equal(args[4],ownerKey);return{rows:[{pid:11,backend_start:'2026-01-01 00:00:00.123457+00',database_oid:'5',role_oid:'6'}]};}};
 return{args,calls,fire:()=>watchdog()};
}
test('exact row transaction and independent blocker observation; rollback and close precede join',async()=>{const f=fixture(),b=await acquireLifecycleBarrier(f.args);assert.equal((await b.assertBlocked()).pid,11);assert(f.calls.some(x=>x.includes('500ms')&&x.includes('4000ms')));await b.releaseThenJoin(async()=>{assert(f.calls.includes('ROLLBACK'));assert.equal(f.calls.at(-1),'end');f.calls.push('join');});await b.release();assert.equal(f.calls.filter(x=>x==='ROLLBACK').length,1);});
test('wrong owner row refuses barrier and closes actual client',async()=>{const f=fixture({wrongRun:true});await assert.rejects(acquireLifecycleBarrier(f.args),{code:'LIFECYCLE_BARRIER_RUN'});assert(f.calls.includes('ROLLBACK'));assert.equal(f.calls.at(-1),'end');});
test('caller settlement alone, wrong PID or foreign identity cannot prove waiter',async()=>{for(const rows of [[],[{pid:10,backend_start:'x',database_oid:'5',role_oid:'6'}],[{pid:11,backend_start:'x',database_oid:'9',role_oid:'6'}]]){const f=fixture();f.args.observeQuery=async()=>({rows});const b=await acquireLifecycleBarrier(f.args);await assert.rejects(b.assertBlocked(),{code:'LIFECYCLE_BARRIER_NOT_BLOCKED'});await b.release();}});
test('watchdog releases but permanently invalidates success even after join',async()=>{const f=fixture(),b=await acquireLifecycleBarrier(f.args);f.fire();await b.release();assert.throws(()=>b.assertValid(),{code:'LIFECYCLE_BARRIER_WATCHDOG'});let joined=false;await assert.rejects(b.releaseThenJoin(async()=>{joined=true;}),{code:'LIFECYCLE_BARRIER_WATCHDOG'});assert(joined);});
test('failed rollback still closes client and joins without claiming cleanup',async()=>{const f=fixture({releaseFails:true}),b=await acquireLifecycleBarrier(f.args);let joined=false;await assert.rejects(b.releaseThenJoin(async()=>{joined=true;}),AggregateError);assert(joined);assert.equal(f.calls.at(-1),'end');await assert.rejects(b.release());});
test('blocker SQL binds exact backend and owner advisory lease without query text',()=>{assert(BLOCKED_SQL.includes('pg_blocking_pids'));assert(BLOCKED_SQL.includes('h.backend_start::text=$2'));assert(BLOCKED_SQL.includes('hashtextextended($5,0)'));assert(!/\ba\.query\b|query_start/.test(BLOCKED_SQL));});

test('remaining lifecycle deadline floors fractional milliseconds and satisfies actual bounded client declaration',async()=>{
 const {remainingLifecycleTimeout}=require('./fixtures/applicationCapacityLifecycleBarrier.cjs');
 const {createBoundedClient}=require('./fixtures/applicationCapacityClient');
 const timeoutMs=remainingLifecycleTimeout(3500.75,1200.5);assert.equal(timeoutMs,2300);assert(timeoutMs<=3500.75-1200.5);
 let called=0;const client=createBoundedClient({maxOutstanding:1,request:operation=>operation()});
 const result=await client.call({owner:'owned',endpoint:'/api/workshop/sql/reset',timeoutMs,operation:async()=>{called++;return{status:503,body:{code:'GRAPH_RUN_CAPACITY_EXCEEDED'}};}});
 assert.equal(result.status,503);assert.equal(called,1);
 for(const [end,now]of [[100,100],[100,101],[100.9,100],[NaN,0],[Infinity,0],[2501,0]])assert.throws(()=>remainingLifecycleTimeout(end,now),{code:'LIFECYCLE_OBSERVATION_DEADLINE'});
 assert.equal(remainingLifecycleTimeout(1001.9,1000),1);assert.equal(remainingLifecycleTimeout(2500,0),2500);
});
