'use strict';
// Admission-only controls. No driver is given a genuine combined capability;
// therefore these checks cannot execute a controller, VM command or build.
const test=require('node:test'),assert=require('node:assert/strict');
const driver=require('./postgres/ownedV03ListingsDriver');
// Execute the actual lexical outcome owner with a controlled transport only;
// no production factory, process or network capability is created.
function outcomeControl(executePython){
 const source=require('node:fs').readFileSync(require.resolve('./postgres/ownedV03ListingsDriver'),'utf8');
 const fragment=source.slice(source.indexOf('async function trackedExecute('),source.indexOf('async function durable('));
 const transport={executePython,validateReceipt:r=>{if(!r||r.valid!==true)throw Error('invalid');},localRetired:r=>r.closed===true};
 const actual=new Function('transport','fail',fragment+';return {trackedExecute,requireLocalClosure,requireRemoteSettlement};')(transport,code=>Object.assign(Error(code),{code}));
 return {...actual,trackedExecute:(rows,conf,files,options)=>actual.trackedExecute(rows,{remoteSeconds:310,...conf},files,options,()=>1000)};
}
test('failed dispatch without receipt remains unproven and cannot authorize deletion',async()=>{
 const primary=Object.assign(Error('dispatch'),{code:'DISPATCH'}),c=outcomeControl(async()=>{throw primary;}),rows=[];
 await assert.rejects(c.trackedExecute(rows,{phase:'build'},null,null),e=>e===primary);
 assert.equal(rows.length,1);assert.equal(rows[0].receipt,null);
 assert.throws(()=>c.requireLocalClosure(rows),{code:'V03_LISTINGS_LOCAL_CLOSURE_UNPROVEN'});
});
test('invalid and unjoined returned receipts remain retained and deny closure',async()=>{
 for(const receipt of [{valid:false,closed:true},{valid:true,closed:false}]){
  const c=outcomeControl(async()=>receipt),rows=[];
  assert.equal(await c.trackedExecute(rows,{phase:'build'},null,null),receipt);
  assert.equal(rows[0].receipt,receipt);
  assert.throws(()=>c.requireLocalClosure(rows),{code:'V03_LISTINGS_LOCAL_CLOSURE_UNPROVEN'});
 }
});
test('work failure with validated closed receipt is distinct from local closure debt',async()=>{
 const receipt={valid:true,closed:true},primary=Object.assign(Error('work'),{phaseReceipt:receipt});
 const c=outcomeControl(async()=>{throw primary;}),rows=[];
 await assert.rejects(c.trackedExecute(rows,{phase:'build'},null,null),e=>e===primary);
 assert.equal(rows[0].receipt,receipt);c.requireLocalClosure(rows);
});
test('pending command cannot permit cleanup before actual terminal',async()=>{
 let release;const c=outcomeControl(()=>new Promise(resolve=>{release=resolve;})),rows=[];
 const pending=c.trackedExecute(rows,{phase:'build'},null,null);
 assert.throws(()=>c.requireLocalClosure(rows),{code:'V03_LISTINGS_LOCAL_CLOSURE_UNPROVEN'});
 release({valid:true,closed:true});await pending;c.requireLocalClosure(rows);
});
test('actual dispatch, join and retirement entry points enforce closure before effects',()=>{
 const source=require('node:fs').readFileSync(require.resolve('./postgres/ownedV03ListingsDriver'),'utf8');
 assert.match(source,/async function phase\(name,kind\)\{\s+requireLocalClosure\(outcomes\);/);
 assert.match(source,/requireRemoteSettlement\(outcomes,owner.nowMs\(\)\);\s+if\(bridge\)/);
 assert.match(source,/requireRemoteSettlement\(outcomes,owner.nowMs\(\)\);\s+if\(!runtimeRetired\)/);
});
test('closed local failure retains full dispatch-specific remote settlement horizon',async()=>{
 const receipt={valid:true,closed:true},primary=Object.assign(Error('remote uncertain'),{phaseReceipt:receipt});
 const c=outcomeControl(async()=>{throw primary;}),rows=[];
 await assert.rejects(c.trackedExecute(rows,{phase:'build'},null,null));
 c.requireLocalClosure(rows);
 assert.equal(rows[0].remoteNotBeforeMs,331000);
 assert.throws(()=>c.requireRemoteSettlement(rows,330999),{code:'V03_LISTINGS_REMOTE_SETTLEMENT_PENDING'});
 c.requireRemoteSettlement(rows,331000);
});
function joinControl(mode){
 const source=require('node:fs').readFileSync(require.resolve('./postgres/ownedV03ListingsDriver'),'utf8');
 const body=source.slice(source.indexOf('  async join(){')+'  async join(){'.length,source.indexOf('\n  },\n  retire(){'));
 let now=1000,changed=false,aborted=false;const window={deadlineMs:mode==='reserve'?2000:10000};
 const owner={nowMs:()=>now,isRevoked:()=>true,phaseWindow:()=>{
  if(now>=window.deadlineMs)throw Object.assign(Error('expired'),{code:'V03_PHASE_NOT_ACTIVE'});
  return changed?{...window}:window;
 },phaseSignal:()=>({throwIfAborted(){if(aborted)throw Error('aborted');}})};
 const c=outcomeControl(async()=>{});
 const outcomes=[{settled:true,localClosureProven:true,remoteUncertain:true,remoteNotBeforeMs:3000}];
 const timer=(callback,delay)=>{now+=mode==='late'?20000:delay;if(mode==='phase')changed=true;if(mode==='abort')aborted=true;callback();};
 return new Function('owner','outcomes','requireLocalClosure','requireRemoteSettlement','fail','setTimeout',
  'let joined=false,busy=false,bridge=null,profileAttempted=false,managerAttempted=false,runtimeRetired=false;return async function(){'+body+'};')(owner,outcomes,c.requireLocalClosure,c.requireRemoteSettlement,
  code=>Object.assign(Error(code),{code}),timer);
}
test('actual join waits under existing retirement window and rejects late wake, phase change, abort and inadequate reserve',async()=>{
 assert.deepEqual(await joinControl('success')(),{localRetired:true,cleanupVerified:false});
 for(const mode of ['late','phase','abort','reserve'])await assert.rejects(joinControl(mode)());
});
test('Listings driver rejects arbitrary commands, runners and incomplete constructor input',async()=>{
 for(const options of [null,{}, {runner:()=>{}},{command:'true'}, {root:'/tmp',runId:'a'.repeat(32)}])
  await assert.rejects(driver.createListingsDriver(options),{code:'V03_LISTINGS_DRIVER_OPTIONS'});
});
test('serialized combined ownership and callable-shaped authority cannot open driver',async()=>{
 const options={root:'/synthetic',runId:'a'.repeat(32),parentRunId:'b'.repeat(32),
  expectedPlanSha256:'c'.repeat(64),expectedDriverSha256:'d'.repeat(64),
  expectedTransportSha256:'e'.repeat(64),expectedPythonSha256:'f'.repeat(64),expectedHostPythonSha256:'a'.repeat(64)};
 for(const combinedOwner of [{},{producerBinding:()=>({runId:options.runId})}])
  await assert.rejects(driver.createListingsDriver({...options,combinedOwner}),{code:'V03_COMBINED_OWNER_REQUIRED'});
});
test('driver receipt or callable methods do not reconstruct its private identity',()=>{
 for(const value of [{cleanupVerified:true},{prepare:async()=>{},retire:async()=>({resourceAbsenceProven:true})}])
  assert.throws(()=>driver.assertListingsDriver(value),{code:'V03_LISTINGS_DRIVER_REQUIRED'});
});
