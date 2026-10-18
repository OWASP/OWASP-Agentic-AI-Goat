'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const {createSecureShopAuditRuntimeLifecycle}=require('../server/services/secureshopAuditRuntimeLifecycle');
test('shutdown aborts and drains owned work before removing its private spool root',async()=>{
 let root,release,signal,entered;const ready=new Promise(resolve=>{entered=resolve;});const held=new Promise(resolve=>{release=resolve;});
 const lifecycle=await createSecureShopAuditRuntimeLifecycle({}, {createRuntime:options=>{
  root=options.root;return {async run(input){signal=input.signal;entered();await held;return 'done';},async createSession(){return {};}};
 }});
 assert.equal((await fs.stat(root)).mode&0o777,0o700);
 const pending=lifecycle.run({});const rejected=assert.rejects(pending,{name:'AbortError'});await ready;
 const closed=lifecycle.close();assert.equal(signal.aborted,true);await fs.stat(root);
 await assert.rejects(lifecycle.run({}),{code:'AUDIT_RUNTIME_UNAVAILABLE'});
 release();await rejected;await closed;await assert.rejects(fs.stat(root),{code:'ENOENT'});
 assert.equal(lifecycle.close(),closed);
});
test('construction failure removes the newly owned spool',async()=>{
 let root;await assert.rejects(createSecureShopAuditRuntimeLifecycle({}, {createRuntime:options=>{root=options.root;throw Error('setup failed');}}),/setup failed/);
 await assert.rejects(fs.stat(root),{code:'ENOENT'});
});
test('capacity rejects excess jobs without admission and returns the slot after failure',async()=>{
 let release,entered,executions=0;
 const ready=new Promise(resolve=>{entered=resolve;});
 const held=new Promise(resolve=>{release=resolve;});
 const lifecycle=await createSecureShopAuditRuntimeLifecycle({}, {maxConcurrentRuns:1,createRuntime:()=>({
  async run(){executions++;if(executions===1){entered();await held;throw Error('controlled worker failure');}return 'next';},
  async createSession(){return {sessionId:'separate-admission'};}
 })});
 try {
  const first=lifecycle.run({});const failed=assert.rejects(first,/controlled worker failure/);await ready;
  await assert.rejects(lifecycle.run({}),{code:'AUDIT_RUNTIME_BUSY',statusCode:503});
  assert.equal(executions,1);
  assert.equal((await lifecycle.createSession({})).sessionId,'separate-admission');
  release();await failed;
  assert.equal(await lifecycle.run({}),'next');
 }finally{release();await lifecycle.close();}
});
test('invalid concurrency is rejected before runtime creation',async()=>{
 for(const maxConcurrentRuns of [0,-1,1.5,33,NaN])
  await assert.rejects(createSecureShopAuditRuntimeLifecycle({}, {maxConcurrentRuns,createRuntime:()=>{throw Error('must not construct');}}),TypeError);
});
