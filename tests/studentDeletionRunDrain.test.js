'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {RUN_FAMILIES}=require('../server/database/postgres/agentRunReadRepository');
const {createStudentDeletionRunDrain}=require('../server/services/studentDeletionRunDrain');

const subjectId=17,jobId=randomUUID();
const codePointOrder=(a,b)=>a<b?-1:a>b?1:0;
const ownerKeys=[...RUN_FAMILIES].sort(codePointOrder).map(family=>JSON.stringify([family,String(subjectId)])).sort(codePointOrder);

test('run drain confirms exact blocks, invalidates every family first and holds one lease at a time',async()=>{
 const events=[];let active=0,maxActive=0,checks=0;
 const pool={query:async()=>({rows:ownerKeys.map(owner_key=>({owner_key}))})};
 const ledger={invalidate:async({ownerKey,signal})=>{assert.equal(signal.aborted,false);events.push(`invalidate:${ownerKey}`);return{
  acquire:async()=>{active++;maxActive=Math.max(maxActive,active);events.push(`acquire:${ownerKey}`);},
  release:async()=>{events.push(`release:${ownerKey}`);active--;},
 };}};
 const drain=createStudentDeletionRunDrain({pool,ledger});
 assert.deepEqual(await drain({subjectId,jobId,check:async()=>{checks++;}}),{completed:true,invalidatedOwners:RUN_FAMILIES.length});
 assert.equal(maxActive,1);assert.equal(active,0);assert.ok(checks>RUN_FAMILIES.length*2);
 const firstAcquire=events.findIndex(event=>event.startsWith('acquire:'));
 assert.equal(firstAcquire,RUN_FAMILIES.length,'all generations are invalidated before the first lease wait');
});

test('missing or extra run blocks prevent every invalidation',async()=>{
 for(const rows of [ownerKeys.slice(1),[...ownerKeys,'["unknown","17"]']]){
  let invalidations=0;
  const drain=createStudentDeletionRunDrain({pool:{query:async()=>({rows:rows.map(owner_key=>({owner_key}))})},ledger:{invalidate:async()=>{invalidations++;}}});
  await assert.rejects(drain({subjectId,jobId,check:async()=>{}}),{code:'DELETION_RUN_BLOCK_MISMATCH'});
  assert.equal(invalidations,0);
 }
});

test('abort while acquiring a lease releases no unacquired handle and starts no later family',async()=>{
 const controller=new AbortController();let invalidations=0,acquisitions=0,releases=0;
 const drain=createStudentDeletionRunDrain({pool:{query:async()=>({rows:ownerKeys.map(owner_key=>({owner_key}))})},ledger:{invalidate:async({signal})=>{
  invalidations++;return{acquire:()=>{acquisitions++;return new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}));},release:async()=>{releases++;}};
 }}});
 const pending=drain({subjectId,jobId,check:async()=>{},signal:controller.signal});
 await new Promise(resolve=>setImmediate(resolve));controller.abort(Object.assign(new Error('stop'),{name:'AbortError'}));
 await assert.rejects(pending,{name:'AbortError'});
 assert.equal(invalidations,RUN_FAMILIES.length);assert.equal(acquisitions,1);assert.equal(releases,0);
});

test('abort after acquisition releases the acquired handle before rejecting',async()=>{
 const controller=new AbortController();let acquisitions=0,releases=0;
 const drain=createStudentDeletionRunDrain({pool:{query:async()=>({rows:ownerKeys.map(owner_key=>({owner_key}))})},ledger:{invalidate:async()=>({
  acquire:async()=>{acquisitions++;controller.abort(Object.assign(new Error('stop after acquire'),{name:'AbortError'}));},
  release:async()=>{releases++;},
 })}});
 await assert.rejects(drain({subjectId,jobId,check:async()=>{},signal:controller.signal}),{name:'AbortError'});
 assert.equal(acquisitions,1);assert.equal(releases,1);
});
