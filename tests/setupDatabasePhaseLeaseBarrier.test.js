'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {waitForOwnedLeaseRelease}=require('./fixtures/setupDatabasePhaseLeaseBarrier');
test('observes delayed backend release after process exit without acquiring or unlocking',async()=>{
 let clock=0,queries=0,exits=0;const observations=[];
 const result=await waitForOwnedLeaseRelease({client:{query:async config=>{assert.match(config.text,/FROM pg_locks/);assert.match(config.text,/current_database\(\)/);assert.match(config.text,/objsubid=2/);assert.doesNotMatch(config.text,/pg_try|unlock|terminate/);assert.deepEqual(config.values,[1886610804,90]);return{rows:++queries<3?[{pid:123}]:[]};}},assertExited:()=>{exits++;},now:()=>clock,sleep:async ms=>{clock+=ms;},onObservation:value=>observations.push(value)});
 assert.equal(queries,3);assert.equal(exits,3);assert.equal(result.released,true);assert.deepEqual(observations.map(x=>x.backendPids),[[123],[123],[]]);
});
test('persistent backend lock fails at bounded deadline without retrying admission',async()=>{
 let clock=0,queries=0;const observations=[];
 await assert.rejects(waitForOwnedLeaseRelease({client:{query:async()=>{queries++;return{rows:[{pid:456}]};}},assertExited:()=>{},timeoutMs:50,now:()=>clock,sleep:async ms=>{clock+=ms;},onObservation:value=>observations.push(value)}),{code:'OWNED_LEASE_RELEASE_TIMEOUT'});
 assert.equal(clock,50);assert.equal(queries,2);assert.equal(observations.at(-1).released,false);
});
test('live process ownership rejects before database observation',async()=>{
 let queries=0;await assert.rejects(waitForOwnedLeaseRelease({client:{query:async()=>{queries++;}},assertExited:()=>{throw Error('Owned process remains');}}),/Owned process remains/);assert.equal(queries,0);
});
