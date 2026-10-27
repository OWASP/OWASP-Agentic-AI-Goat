'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises');
const path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const derive=require('./postgres/ownedMcpOriginalServiceDerivation');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
test('Listings manager derives every holder coordinate from its distinct original-browser lease',async()=>{
 const result=await derive.loadOriginalServiceBounded('listings-manager-browser');
 assert.equal(result.totalMs,6680000);assert.equal(result.executionApproved,false);
 assert.equal(result.leaseTarget,'original-listings-manager-total-lease-v1');
 assert.match(result.bounded._internals.scripts.prepare,/original-listings-manager-total-lease-v1/);
 assert.match(result.bounded._internals.scripts.start,/original-listings-manager-total-lease-v1/);
 assert.match(result.bounded._internals.relayLifecycleProgram,/original-service-holder.seconds/);
 for(const text of [result.bounded._internals.scripts.prepare,result.bounded._internals.scripts.start,derive.leaseCommand('claim-cohort','listings-manager-browser')]){
  const row=spawnSync('/bin/sh',['-n'],{input:text,encoding:'utf8',timeout:5000});assert.equal(row.status,0,row.stderr);
 }
});
test('closed V39 derivation binds all holder coordinates to its own once-only lease',async()=>{
 const result=await derive.loadOriginalServiceBounded('v39-atomic-pair');
 assert.equal(result.totalMs,4560000);assert.equal(result.leaseTarget,'v39-atomic-pair-total-lease-v1');
 assert.match(result.bounded._internals.scripts.prepare,/v39-atomic-pair-total-lease-v1/);
 assert.match(result.bounded._internals.scripts.start,/v39-atomic-pair-total-lease-v1/);
 assert.match(result.bounded._internals.relayLifecycleProgram,/original-service-holder.seconds/);
 for(const text of [result.bounded._internals.scripts.prepare,result.bounded._internals.scripts.start,derive.leaseCommand('claim-cohort','v39-atomic-pair')]){
  const row=spawnSync('/bin/sh',['-n'],{input:text,encoding:'utf8',timeout:5000});assert.equal(row.status,0,row.stderr);
 }
 await assert.rejects(derive.loadOriginalServiceBounded('other'),/PROFILE/);
});
test('service derivation pins shared bytes and changes all holder coordinates only in memory',async()=>{
 const filename=path.join(__dirname,'postgres/ownedMcpBoundedBuild.js'),before=await fs.readFile(filename);
 const d=await derive.loadOriginalServiceBounded();assert.equal(sha(before),derive.SOURCE_SHA);
 assert.equal(d.totalMs,7400000);assert.equal(d.executionApproved,false);
 const emitted=d.bounded._internals.scripts;
 assert(emitted.prepare.indexOf('original-service-lease.json')<emitted.prepare.indexOf('fallocate -l'));
 assert(emitted.prepare.includes('O_EXCL'));assert(emitted.start.includes('/usr/bin/sleep "$holder_seconds"'));
 assert(!emitted.start.includes("printf '/usr/bin/sleep\\n900'"));
 assert(d.bounded._internals.relayLifecycleProgram.includes("read(ROOT+'/original-service-holder.seconds')"));
 assert(!d.bounded._internals.relayLifecycleProgram.includes("['/usr/bin/sleep','900']"));
 assert.equal(sha(await fs.readFile(filename)),sha(before));
 assert(require('./postgres/ownedMcpBoundedBuild')._internals.relayLifecycleProgram.includes("['/usr/bin/sleep','900']"));
 assert.equal(require('./postgres/ownedMcpOriginalService').BUDGET.originalCohortSeconds,1200);
 for(const script of [emitted.prepare,emitted.start,emitted.cleanup,derive.leaseCommand('claim-cohort')]){
  const r=spawnSync('/bin/sh',['-n'],{input:script,encoding:'utf8',timeout:5000,maxBuffer:8192});
  assert.equal(r.status,0,r.stderr);
 }
});
test('source drift and missing/duplicate anchors fail closed; operation names are closed',async()=>{
 const text=await fs.readFile(path.join(__dirname,'postgres/ownedMcpBoundedBuild.js'),'utf8');
 assert.throws(()=>derive._internals.deriveSource(text+'\n'),/SOURCE/);
 assert.throws(()=>derive._internals.replaceOnce('x x','x','y'),/ANCHOR/);
 assert.throws(()=>derive._internals.replaceOnce('z','x','y'),/ANCHOR/);
 for(const op of ['read','cleanup;true','claim-unknown',''])assert.throws(()=>derive.leaseCommand(op),/OPERATION/);
});
