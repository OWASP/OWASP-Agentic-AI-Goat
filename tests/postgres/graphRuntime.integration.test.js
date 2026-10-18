'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(/(?:^|\/)authDb(?:\.js)?$/.test(r))throw Error('authDb forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict');
const {createPool}=require('../../server/database/postgres');
const {initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {createPostgresRunLedger}=require('../../server/agent-runtime/postgresRunLedger');
const {createRunCoordinator}=require('../../server/agent-runtime/runCoordinator');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&Boolean(process.env.PG_GRAPH_TEST_RUNTIME_URL);
test('PG graph leases persist generations, serialize remote reset, and block uncertain replay after restart',{skip:!enabled},async()=>{
 for(const key of ['PG_GRAPH_TEST_MIGRATION_URL','PG_GRAPH_TEST_RUNTIME_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
 const migration=createPool(process.env,'PG_GRAPH_TEST_MIGRATION_URL'),pool=createPool(process.env,'PG_GRAPH_TEST_RUNTIME_URL'),leasePool=createPool(process.env,'PG_GRAPH_TEST_RUNTIME_URL');
 leasePool.options.max=1;
 try{
 await initializeIdentityRepository(pool,migration);
 const a=createRunCoordinator({family:'ARIA',ledger:createPostgresRunLedger(pool,{leasePool})}),b=createRunCoordinator({family:'ARIA',ledger:createPostgresRunLedger(pool,{leasePool})});
 let enter,release;const entered=new Promise(r=>enter=r),slow=new Promise(r=>release=r);let writes=0;
 const pending=a.run(1,{},async e=>{enter();await slow;await e.check();writes++;});const rejected=assert.rejects(pending,{name:'AbortError'});await entered;
 let cleared=false;const reset=b.reset(1,async()=>{cleared=true;});
 // Read authoritative generation rather than sleeping for a race outcome.
 for(let i=0;i<100;i++){const row=(await pool.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',['["ARIA","1"]'])).rows[0];if(Number(row?.generation)===1)break;await new Promise(r=>setTimeout(r,5));}
 assert.equal(cleared,false);
 // A queued second owner can be cancelled while the sole lease slot is full,
 // and the independent control pool remains usable for auth/reset metadata.
 const controller=new AbortController();
 const queued=a.run(99,{signal:controller.signal},async()=>{throw Error('cancelled lease waiter ran');});
 const cancelled=assert.rejects(queued,{name:'AbortError'});controller.abort();await cancelled;
 assert.equal(Number((await pool.query('SELECT 1 AS alive')).rows[0].alive),1);
 release();await Promise.all([reset,rejected]);assert.equal(writes,0);assert.equal(cleared,true);
 await assert.rejects(a.run(1,{idempotencyKey:'mutation-1'},e=>e.effect('tool',async()=>{writes++;throw Error('lost reply');})),/lost reply/);
 const restarted=createRunCoordinator({family:'ARIA',ledger:createPostgresRunLedger(pool,{leasePool})});
 await assert.rejects(restarted.run(1,{idempotencyKey:'mutation-1'},e=>e.effect('tool',async()=>writes++)),{code:'GRAPH_EFFECT_REPLAY_BLOCKED'});assert.equal(writes,1);
 const records=(await pool.query('SELECT status,last_node FROM graph_runtime.runs')).rows;assert.ok(records.some(r=>r.status==='failed'));
 const effects=(await pool.query('SELECT status FROM graph_runtime.effects')).rows;assert.equal(effects[0].status,'uncertain');
 // A new process uses the persisted generation rather than resetting it to zero.
 await restarted.run(1,{idempotencyKey:'mutation-2'},async e=>{assert.equal(e.durableGeneration,'1');await e.checkpoint('verified');});
 }finally{await Promise.all([pool.end(),leasePool.end(),migration.end()]);}
});
