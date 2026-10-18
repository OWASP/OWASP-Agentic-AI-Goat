'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {cleanupRegisteredEntryGroup}=require('./postgres/applicationJournalBoundEntry.integration.test');
test('registered cleanup refuses stale PID, UID, PGID or birth before any signal',async()=>{
 const row={pid:123,birth:'Mon Sep 28 01:02:03 2026'};
 for(const text of ['124 123 501 '+row.birth,'123 124 501 '+row.birth,'123 123 502 '+row.birth,'123 123 501 different','']){
  let signals=0;await assert.rejects(cleanupRegisteredEntryGroup(row,{uid:501,alive:()=>true,observe:()=>text,stop:async()=>{signals++;}}));assert.equal(signals,0);
 }
});
test('absent group needs no signal; unknown leader with descendants defers to outer cleanup',async()=>{
 const row={pid:123,birth:'Mon Sep 28 01:02:03 2026'};let signals=0;
 await cleanupRegisteredEntryGroup(row,{alive:()=>false,stop:async()=>{signals++;}});
 await assert.rejects(cleanupRegisteredEntryGroup(row,{alive:()=>true,observe:()=>{throw Error('leader gone');},stop:async()=>{signals++;}}));assert.equal(signals,0);
 await cleanupRegisteredEntryGroup(row,{uid:501,alive:()=>true,observe:()=> '123 123 501 '+row.birth,stop:async({child})=>{assert.equal(child.pid,123);signals++;}});assert.equal(signals,1);
});
test('legacy durable snapshot preserves absent later tables and exact ledger without querying or creating them',async()=>{const {snapshotEntryDurable}=require('./postgres/applicationJournalBoundEntry.integration.test');const queries=[],ledger=[{name:'0001_maintenance_fence.sql',checksum:'original'}];const c={query:async(text,values)=>{queries.push(text);assert(text.startsWith('SELECT '));if(text.includes('to_regclass'))return{rows:[{relation:null}]};if(text.includes('.ledger'))return{rows:ledger};return{rows:[{epoch:'1',state:'clean'}]};}};const first=await snapshotEntryDurable(c);assert.deepEqual(first.ledger,ledger);assert(Object.values(first.presence).every(x=>x===false));for(const key of Object.keys(first.presence))assert.equal(first[key],null);assert(!queries.some(q=>/SELECT \* FROM dvaia_maintenance\.(epoch_replay|epoch_finish|epoch_stores|ctf_journal)/.test(q)));assert.deepEqual(await snapshotEntryDurable(c),first);});
test('durable snapshot distinguishes newly present empty table from absence and propagates missing required schema',async()=>{const {snapshotEntryDurable}=require('./postgres/applicationJournalBoundEntry.integration.test');let present=false;const c={query:async(text,values)=>text.includes('to_regclass')?{rows:[{relation:present?values[0]:null}]}:{rows:[]}};const absent=await snapshotEntryDurable(c);present=true;const current=await snapshotEntryDurable(c);assert.notDeepEqual(current,absent);assert(Object.values(current.presence).every(Boolean));assert.deepEqual(current.profiles,[]);const failure=Error('required table absent');await assert.rejects(snapshotEntryDurable({query:async()=>{throw failure;}}),e=>e===failure);});
