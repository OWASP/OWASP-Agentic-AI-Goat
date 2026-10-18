'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{createHash}=require('node:crypto');
const native=require('../scripts/lib/windows-process-identity');
const file=path.resolve(__dirname,'../scripts/lib/setup-local-process-identity.js');
const target={workspaceRoot:'C:\\workspace',installationId:'11111111-1111-4111-8111-111111111111',operationId:'22222222-2222-4222-8222-222222222222'};
function fixture(){return native.validateWindowsProcessIdentityRecord({version:1,platform:'win32',hostSha256:'a'.repeat(64),bootFileTime:'100',currentSid:'S-1-5-21-1',ancestry:'observed-supported-chain',ancestors:[{pid:500,ppid:400,sid:'S-1-5-21-1',creationFileTime:'300'}],boundary:{kind:'root',process:{pid:400,ppid:0,sid:'S-1-5-21-1',creationFileTime:'200'}}});}
function harness(){
 const calls=[],control={path:target.workspaceRoot,identity:{volumeSerial:10,fileId:'0000000000000001'},native:fixture(),deny:false,change:false,after:null};
 const module={exports:{}};
 const win={...native,captureWindowsProcessIdentity(){calls.push('capture');if(control.deny)throw Error('private diagnostic');control.after?.();return control.native;},verifyWindowsRecordedProcessesAbsent(record){calls.push('absence');native.validateWindowsProcessIdentityRecord(record);if(control.deny||record.currentSid!==control.native.currentSid||record.hostSha256!==control.native.hostSha256||record.bootFileTime!==control.native.bootFileTime)throw Error('private diagnostic');control.after?.();return Object.freeze({recordedProcessesAbsent:true,recoveryAuthorized:false,ancestry:'observed-supported-chain',boundary:'root',databaseDrain:'not-checked'});}};
 const mocks={'node:fs':{realpathSync(){calls.push('canonical');return control.path;}},'node:path':path.win32,'./windows-process-identity':win,'./windows-private-state':{inspectWorkspaceDirectory(value){calls.push('inspect');assert.equal(value,target.workspaceRoot);return {path:target.workspaceRoot,size:null,identity:{...control.identity}};}}};
 vm.runInNewContext(fs.readFileSync(file,'utf8'),{require:name=>mocks[name]||require(name),module,exports:module.exports,process:{platform:'win32',pid:500,ppid:400},Buffer,Date,Set,Object,Number,JSON,BigInt},{filename:file});
 return {api:module.exports,control,calls};
}
test('Windows v3 captures exact distinct identity with same workspaceId canonical hash and no POSIX fields',()=>{
 const h=harness(),r=h.api.captureLocalAncestorBinding(target);
 assert.equal(r.version,3);assert.equal(r.workspaceSha256,createHash('sha256').update(target.workspaceRoot).digest('hex'));assert.equal(r.ancestry,'observed-supported-chain');assert.equal(h.api.isSupportedLocalAncestorBinding(r),true);assert(Object.isFrozen(r));assert(Object.isFrozen(r.ancestors[0]));
 assert.deepEqual(h.calls,['inspect','canonical','capture','inspect','canonical']);
 for(const field of ['uid','bootId','pidNamespace','userNamespace','owner','parent'])assert.equal(field in r,false);
});
test('Windows absence rechecks workspace and preserves observation-only result',()=>{
 const h=harness(),r=h.api.captureLocalAncestorBinding(target);h.calls.length=0;
 assert.equal(h.api.verifyRecordedAncestorChainAbsent(r,target).recoveryAuthorized,false);
 assert.deepEqual(h.calls,['inspect','canonical','absence','inspect','canonical']);
});
test('Windows capture and absence reject replaced target identity or canonical path',()=>{
 for(const operation of ['capture','absence'])for(const change of ['identity','path']){
  const h=harness(),r=h.api.captureLocalAncestorBinding(target);
  h.control.after=()=>{if(change==='identity')h.control.identity.fileId='0000000000000002';else h.control.path='C:\\replacement';};
  assert.throws(()=>operation==='capture'?h.api.captureLocalAncestorBinding(target):h.api.verifyRecordedAncestorChainAbsent(r,target),{code:'LOCAL_PROCESS_BINDING_MISMATCH'});
 }
});
test('Windows strict schema rejects UUID/binding/tuple/ancestry mismatch before native absence',()=>{
 const h=harness(),r=h.api.captureLocalAncestorBinding(target);
 for(const patch of [{extra:true},{version:2},{installationId:'invalid'},{operationId:'invalid'},{workspaceSha256:'bad'},{ancestry:'complete-supported-chain'},{currentSid:'invalid'},{bootFileTime:100},{ancestors:[{...r.ancestors[0],creationFileTime:'200'}]},{boundary:{kind:'init',process:r.boundary.process}}]){
  const changed={...r,...patch};assert.equal(h.api.isSupportedLocalAncestorBinding(changed),false);assert.throws(()=>h.api.verifyRecordedAncestorChainAbsent(changed,target));
 }
 for(const patch of [{installationId:target.operationId},{operationId:target.installationId},{workspaceSha256:'b'.repeat(64)}])assert.throws(()=>h.api.verifyRecordedAncestorChainAbsent({...r,...patch},target),{code:'LOCAL_PROCESS_BINDING_MISMATCH'});
 assert.throws(()=>h.api.captureLocalAncestorBinding({...target,extra:true}),{code:'LOCAL_PROCESS_BINDING_INVALID'});
});
test('Windows native SID/host/boot mismatch or uncertain absence fails closed and scrubs diagnostics',()=>{
 for(const patch of [{currentSid:'S-1-5-21-2'},{hostSha256:'b'.repeat(64)},{bootFileTime:'101'},null]){
  const h=harness(),r=h.api.captureLocalAncestorBinding(target);if(patch)h.control.native={...h.control.native,...patch};else h.control.deny=true;
  assert.throws(()=>h.api.verifyRecordedAncestorChainAbsent(r,target),e=>e.code==='LOCAL_PROCESS_PROBE_UNKNOWN'&&!e.message.includes('private diagnostic'));
 }
});
test('Windows v1 remains unsupported without target inspection and pure predicate never observes',()=>{
 const h=harness();assert.throws(()=>h.api.captureLocalProcessBinding(target),{code:'LOCAL_PROCESS_PLATFORM_UNSUPPORTED'});assert.throws(()=>h.api.verifyRecordedProcessesAbsent({},target),{code:'LOCAL_PROCESS_PLATFORM_UNSUPPORTED'});assert.deepEqual(h.calls,[]);
 const r=h.api.captureLocalAncestorBinding(target);h.calls.length=0;assert.equal(h.api.isSupportedLocalAncestorBinding(r),true);assert.deepEqual(h.calls,[]);
});
test('pure selector preserves existing v2 marker admission without asserting identity proof',()=>{
 const h=harness();
 assert.equal(h.api.isSupportedLocalAncestorBinding({version:2,ancestry:'complete-supported-chain'}),true);
 for(const record of [{version:1,ancestry:'complete-supported-chain'},{version:2,ancestry:'observed-supported-chain'},{version:2},{version:3,ancestry:'observed-supported-chain'},null])assert.equal(h.api.isSupportedLocalAncestorBinding(record),false);
 assert.deepEqual(h.calls,[]);
});
