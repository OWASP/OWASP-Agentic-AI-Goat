'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module'),fs=require('node:fs'),path=require('node:path');
process.env.WORKSHOP_DATABASE_ENGINE='postgres';
const rows=new Map();let writes=0,fail=null,loadFail=false;
const store={getVictimState:async id=>{if(loadFail)throw Error('read unavailable');return structuredClone(rows.get(id)||null);},
 saveVictimState:async(id,state)=>{writes++;if(fail==='before')throw Error('write unavailable');rows.set(id,structuredClone(state));if(fail==='after')throw Error('ack unavailable');},
 deleteVictimState:async id=>{if(fail==='before')throw Error('delete unavailable');rows.delete(id);if(fail==='after')throw Error('delete ack unavailable');}};
const original=Module._load;
Module._load=function(request,parent,isMain){if(request==='../database/postgres/csrfWorkshopDb'&&parent?.filename.endsWith('/csrfVictimSandbox.js'))return store;return original.call(this,request,parent,isMain);};
const {getOrCreateSandbox,CsrfVictimSandbox}=require('../server/services/csrfVictimSandbox');
test.after(()=>{Module._load=original;});
async function baseline(id){const s=getOrCreateSandbox(id);await s.ready();await s.flush();return s;}
function rejectsOld(s){for(const fn of [()=>s.tab('get'),()=>s.getTabState('get'),()=>s.getState(),()=>s.persist(),()=>s.reset(),()=>s.resetTab('get')])assert.throws(fn,/authoritative reload/);}
test('sandbox source has no engine or SQLite fallback and explicit memory fixtures do not persist',async()=>{
 const source=fs.readFileSync(path.join(__dirname,'../server/services/csrfVictimSandbox.js'),'utf8');
 assert.doesNotMatch(source,/(?:authDb|sqlite3|better-sqlite3|DATABASE_ENGINE)/);
 const before=writes,s=new CsrfVictimSandbox('memory_only',{persistence:null});s._load();await s.ready();
 s.setDefenses('get',true);s.persist();await s.flush();assert.equal(s.tab('get').defenses.csrfToken,true);assert.equal(writes,before);
});
for(const failure of ['before','after'])test(`failed ${failure}-commit save invalidates old refs; reload reads durable outcome and preserves sibling`,async()=>{
 fail=null;const id=`csrf_${failure}`,s=await baseline(id),sibling=await baseline(`sibling_${failure}`);
 const prior=s.tab('get').victim.profile.email;s.tab('get').victim.profile.email='changed@example.test';fail=failure;
 const first=s.flush(),queued=s.flush();await assert.rejects(first,/unavailable/);await assert.rejects(queued,/authoritative reload/);rejectsOld(s);
 fail=null;const restored=getOrCreateSandbox(id);assert.notEqual(restored,s);await restored.ready();
 assert.equal(restored.tab('get').victim.profile.email,failure==='after'?'changed@example.test':prior);
 assert.equal(getOrCreateSandbox(`sibling_${failure}`),sibling);
 const before=writes;await assert.rejects(s.flush(),/authoritative reload/);assert.equal(writes,before);
 await restored.flush();assert.equal(rows.get(id).get.victim.profile.email,failure==='after'?'changed@example.test':prior);
});
test('uncertain committed delete reloads absent authoritative row without replaying old dirty state',async()=>{
 fail=null;const s=await baseline('csrf_delete');s.tab('get').victim.profile.email='must-not-resurrect';s.reset();fail='after';
 await assert.rejects(s.flush(),/delete ack unavailable/);fail=null;assert.equal(rows.has('csrf_delete'),false);rejectsOld(s);
 const fresh=getOrCreateSandbox('csrf_delete');await fresh.ready();assert.notEqual(fresh.tab('get').victim.profile.email,'must-not-resurrect');
});
test('failed hydration evicts poisoned promise and a new request can recover without writes',async()=>{
 loadFail=true;const old=getOrCreateSandbox('csrf_load');await assert.rejects(old.ready(),/read unavailable|authoritative reload/);rejectsOld(old);
 loadFail=false;const fresh=getOrCreateSandbox('csrf_load');await fresh.ready();assert.notEqual(fresh,old);
});
