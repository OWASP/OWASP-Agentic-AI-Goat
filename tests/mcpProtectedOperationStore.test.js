'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {createProtectedOperationStore}=require('../sidecars/sandbox-runner/protected-operations/operationStore');
const {canonicalDigest}=require('../sidecars/sandbox-runner/owned-http/canonical');
async function fixture(t){
 const target=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-protected-journal-'));t.after(()=>fs.rm(target,{recursive:true,force:true}));
 const binding={targetId:crypto.randomUUID(),ownerId:7,platformSessionId:71,generation:0};let calls=0,version=1,failAfter=false;
 // Controlled lock dependency; production foundation remains unmounted.
 let tail=Promise.resolve();const targetStore={withTarget(_cap,authority,work){const p=tail.then(async()=>{if(!await authority({phase:'use'}))throw Error('revoked');const result=await work({rootfs:path.join(target,'rootfs'),binding});if(!await authority({phase:'return'}))throw Error('revoked');return result;});tail=p.catch(()=>{});return p;}};
 const executor=async({request})=>{calls++;const before=version++;if(failAfter)throw Error('lost after commit');const body={version:'mcp-owned-protected-state.v1',operation:request.operation,targetId:binding.targetId,platformOwnerId:binding.ownerId,platformSessionId:binding.platformSessionId,generation:binding.generation,runId:request.runId,labRole:request.arguments.labRole,policy:'vulnerable',changed:true,keyVersionBefore:before,keyVersionAfter:version,audited:true};return{...body,receiptSha256:canonicalDigest(body)};};
 const request={operationId:crypto.randomUUID(),runId:crypto.randomUUID(),operation:'rotate_keys',arguments:{labRole:'unprivileged',enforceAuthorization:false}};
 return{target,binding,request,create:()=>createProtectedOperationStore({targetStore,executor}),calls:()=>calls,fail:()=>{failAfter=true;}};
}
const yes=async()=>true;
test('exact immutable receipt survives lost caller acknowledgement and store recreation without repeating effect',async t=>{
 const f=await fixture(t),a=f.create();const first=await a.execute('owned',yes,f.request);assert.equal(first.state,'completed');
 const second=await f.create().execute('owned',yes,f.request);assert.deepEqual(second,first);assert.equal(f.calls(),1);
 assert.deepEqual(await f.create().readReceipt('owned',yes,f.request),first);assert.equal(Object.isFrozen(second.result),true);
 await assert.rejects(a.execute('owned',yes,{...f.request,arguments:{...f.request.arguments,labRole:'privileged'}}),{code:'PROTECTED_JOURNAL_CONFLICT'});
 await assert.rejects(a.readReceipt('owned',yes,{...f.request,runId:crypto.randomUUID()}),{code:'PROTECTED_JOURNAL_CONFLICT'});
 const another=await a.execute('owned',yes,{...f.request,operationId:crypto.randomUUID()});assert.equal(another.result.keyVersionAfter,3);assert.equal(f.calls(),2);
});
test('pending failure remains uncertain and never retries; absent is distinct',async t=>{
 const f=await fixture(t);assert.equal((await f.create().readReceipt('owned',yes,f.request)).state,'absent');f.fail();
 await assert.rejects(f.create().execute('owned',yes,f.request),{code:'PROTECTED_JOURNAL_UNCERTAIN'});
 assert.equal((await f.create().execute('owned',yes,f.request)).state,'uncertain');assert.equal((await f.create().readReceipt('owned',yes,f.request)).state,'uncertain');assert.equal(f.calls(),1);
});
test('real completed write rejected at return fence can only be read after current authority returns',async t=>{
 const f=await fixture(t);await assert.rejects(f.create().execute('owned',async({phase})=>phase!=='return',f.request),/revoked/);
 await assert.rejects(f.create().readReceipt('owned',async()=>false,f.request),/revoked/);
 assert.equal((await f.create().readReceipt('owned',yes,f.request)).state,'completed');assert.equal(f.calls(),1);
});
test('concurrent same identity is serialized and request mutation cannot alter admitted snapshot',async t=>{
 const f=await fixture(t);const p=f.create().execute('owned',yes,f.request);f.request.arguments.labRole='privileged';
 const result=await p;assert.equal(result.result.labRole,'unprivileged');f.request.arguments.labRole='unprivileged';
 await Promise.all([f.create().execute('owned',yes,f.request),f.create().execute('owned',yes,f.request)]);assert.equal(f.calls(),1);
});
test('foreign binding, modified receipt, staging debt and symlinks fail closed',async t=>{
 const f=await fixture(t);await f.create().execute('owned',yes,f.request);f.binding.platformSessionId=72;
 await assert.rejects(f.create().readReceipt('owned',yes,f.request),{code:'PROTECTED_JOURNAL_CONFLICT'});f.binding.platformSessionId=71;
 const file=path.join(f.target,'protected-operations',f.request.operationId+'.completed.json');const original=await fs.readFile(file);
 await fs.writeFile(file,'{}\n');await assert.rejects(f.create().readReceipt('owned',yes,f.request),{code:'PROTECTED_JOURNAL_INVALID'});await fs.writeFile(file,original);
 await fs.writeFile(file+'.tmp','partial');await assert.rejects(f.create().readReceipt('owned',yes,f.request),{code:'PROTECTED_JOURNAL_UNCERTAIN'});await fs.rm(file+'.tmp');
 await fs.rm(file);await fs.symlink('/dev/null',file);await assert.rejects(f.create().readReceipt('owned',yes,f.request));assert.equal(f.calls(),1);
});
