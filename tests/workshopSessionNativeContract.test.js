'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
test('native cohort stores and canonical bcrypt fixture match supported contracts',async()=>{
 const {STORES}=require('./postgres/workshopSessionNativeSupport');assert.deepEqual(Object.keys(STORES),['identity','aria','nova','excessive_agency','xss']);
 const bcrypt=require('bcryptjs'),password='owned-'+require('node:crypto').randomUUID(),hash=await bcrypt.hash(password,4);assert.match(hash,/^\$2[aby]\$04\$[./A-Za-z0-9]{53}$/);assert.equal(await bcrypt.compare(password,hash),true);
 const fixture=fs.readFileSync(require.resolve('./postgres/workshopSessionSqlNoSql.native'),'utf8');assert.match(fixture,/access_level='public'/);assert.doesNotMatch(fixture,/is_restricted/);
 const launcher=fs.readFileSync(require('node:path').join(__dirname,'postgres/run-workshop-exact-session-isolated.py'),'utf8');assert.match(launcher,/signal.alarm\(900\)/);assert.match(launcher,/child_deadline=time.monotonic\(\)\+720/);assert.match(launcher,/timeout=min\(150/);assert.match(launcher,/size=536870912/);assert.match(launcher,/if code or item.get/);
});
test('fixture barrier releases on cancellation and normal completion',async()=>{
 const {barrier}=require('./postgres/workshopSessionNativeSupport');const controller=new AbortController(),gate=barrier(),waiting=gate.wait(controller.signal);await gate.entered;const error=Error('owned cancellation');controller.abort(error);await assert.rejects(waiting,e=>e===error);gate.release();const normal=barrier(),completed=normal.wait();await normal.entered;normal.release();await completed;
});
test('native barrier reports premature HTTP completion and never waits for child deadline',async()=>{
 const {barrier}=require('./postgres/workshopSessionNativeSupport');const gate=barrier();await assert.rejects(gate.reached(Promise.resolve({status:500})),/terminated before controlled barrier: 500/);gate.release();const missing=barrier();await assert.rejects(missing.reached(new Promise(()=>{}),5),/was not reached/);missing.release();
});
test('quoted HTML readback compares exact structured bytes instead of serialized escaping',()=>{
 const {assertMutationReadback}=require('./postgres/workshopSessionNativeSupport');const value='<b data-owned="1">owned</b>';
 assert.equal(JSON.stringify({profile:{bio:value}}).includes(value),false,'historical assertion falsely denied correct bytes');
 assert.doesNotThrow(()=>assertMutationReadback('xss',{profile:{bio:value}},value));
 assert.throws(()=>assertMutationReadback('xss',{profile:{bio:'wrong'}},value));
 assert.throws(()=>assertMutationReadback('xss',{unrelated:value},value));
 assert.doesNotThrow(()=>assertMutationReadback('excessive_agency',{notes:[{title:'owned-note'}]},'owned-note'));
 assert.throws(()=>assertMutationReadback('excessive_agency',{notes:[{title:'wrong'}]},'owned-note'));
});
