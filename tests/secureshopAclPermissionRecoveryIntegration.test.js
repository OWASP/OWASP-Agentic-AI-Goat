'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const owner=fs.readFileSync('tests/postgres/secureshopEnabledIndexStartup.integration.test.js','utf8');
const users=fs.readFileSync('tests/fixtures/secureshopEnabledUsersBrowser.js','utf8');
const acl=fs.readFileSync('tests/fixtures/secureshopEnabledAclBrowser.js','utf8');
function binding(enabled,request,controller=new AbortController()){
 const text=owner.slice(owner.indexOf('prepareAclRecovery: process.env'),owner.indexOf('prepareMcpTools:async headers'));
 const child={exitCode:null};
 const value=vm.runInNewContext('({'+text+'})',{process:{env:{DVAIA_ACL_PERMISSION_RECOVERY:enabled}},assert,t:{signal:controller.signal},child,request,AbortController,AbortSignal,ownerDeadline:Date.now()+180000});
 return{prepare:value.prepareAclRecovery,controller,child};
}
test('actual owner binds persona token and launch scope to bounded GET only',async()=>{
 const calls=[],receipt={operationId:'12345678-1234-1234-1234-123456789012'};
 const b=binding('1',async(...args)=>{calls.push(args);return{status:200,body:{ok:true,receipt}};});
 const options=await b.prepare({'x-dvaia-secureshop-launch':'private-launch'},'private-persona');
 assert.equal(options.signal.aborted,false);options.check();
 assert.equal((await options.readOperation(receipt.operationId)).receipt,receipt);
 assert.equal(calls.length,1);assert.equal(calls[0][2],undefined);
 assert.equal(calls[0][1],'private-persona');assert.equal(calls[0][3]['x-dvaia-secureshop-launch'],'private-launch');
 b.controller.abort();await assert.rejects(options.readOperation(receipt.operationId));assert.equal(calls.length,1);
});
test('owner rejects HTTP denial and stopped backend; default never prepares recovery',async()=>{
 assert.equal(binding(undefined,()=>assert.fail()).prepare,undefined);
 const b=binding('1',async()=>({status:403,body:{}}));
 const options=await b.prepare({'x-dvaia-secureshop-launch':'scope'},'persona');
 await assert.rejects(options.readOperation('12345678-1234-1234-1234-123456789012'));
 b.child.exitCode=1;assert.throws(options.check);
});
test('actual Users integration forwards login identity and owner signal; abort close is joined once',async()=>{
 for(const source of [owner,users,acl])new vm.Script(source);
 assert(users.includes('prepareAclRecovery(loginResponse.request().headers(), persona.token)'));
 assert(users.includes('permissionRecovery:aclRecovery'));
 const closeSource=users.slice(users.indexOf('  let aclRecovery, closing, primary;'),users.indexOf('  try {'));
 let closes=0;const context={browser:{close:async()=>{closes++;}}};
 vm.runInNewContext(closeSource+';globalThis.actions={close,abortBrowser};',context);
 context.actions.abortBrowser();await context.actions.close();assert.equal(closes,1);
 assert(users.includes("aclRecovery.signal.addEventListener('abort', abortBrowser, {once:true})"));
 assert(users.includes("aclRecovery.signal.removeEventListener('abort', abortBrowser)"));
 assert(owner.includes('timeout:180000'));assert(owner.includes('AbortSignal.any([t.signal,operationSignal,AbortSignal.timeout(3000)])'));
 assert(acl.includes("recovered ? recovered.body : await toggle(cell, '/permission')"));
});
test('actual transformed Users outer finally bounds pending/rejected close and preserves helper primary',async()=>{
 const start=users.indexOf('} catch (error) { primary = error; throw error; } finally {');
 const end=users.indexOf('\n}\n',start);
 const tail=users.slice(start,end);
 for(const pending of [true,false]){
  const original=Error('helper primary');original.cleanupDebt=true;original.cleanupFailureCount=1;
  let closes=0,removed=0;const promise=pending?new Promise(()=>{}):Promise.reject(Error('close failed'));
  promise.catch(()=>{});
  const context={original,close:()=>{closes++;return promise;},aclRecovery:{deadline:Date.now()+20,
   signal:{removeEventListener:()=>removed++}},abortBrowser:()=>{},setTimeout,clearTimeout,Date,Error};
  const run=vm.runInNewContext('(async()=>{let primary;try { throw original; '+tail+'})',context);
  const before=Date.now();await assert.rejects(run(),error=>error===original&&error.cleanupDebt&&error.cleanupFailureCount===2);
  assert(Date.now()-before<250);assert.equal(closes,1);assert.equal(removed,1);
 }
});
