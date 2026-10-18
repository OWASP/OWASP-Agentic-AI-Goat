'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {PassThrough}=require('node:stream');
const {createSystemDiagnosticExecutor,buildDiagnosticArgv,decodeDiagnosticStatus}=require('../sidecars/sandbox-runner/owned-system/diagnostic-executor');
const request={operationId:'00000000-0000-4000-8000-000000000002',cmd_template:'printf safe;',args:'printf injected'};
function controlled({status='D1 70 0 drained\n',code=0,stdout='D1 0 0 drained\n',stall=false}={}){
 let calls=0;const kills=[];
 const executor=createSystemDiagnosticExecutor({verify(){},exists:()=>true,timeoutMs:100,drainGraceMs:100,spawnImpl(_file,argv,opts){
  calls++;assert.equal(opts.stdio[3],'pipe');assert.equal(argv.at(-1),'printf safe; printf injected');
  const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.stdio=[null,child.stdout,child.stderr,new PassThrough()];
  child.kill=signal=>{kills.push(signal);setImmediate(()=>child.emit('close',70));};
  if(!stall)setImmediate(()=>{child.stdout.emit('data',Buffer.from(stdout));child.stdio[3].emit('data',Buffer.from(status));child.emit('close',code);});return child;
 }});return{executor,kills,calls:()=>calls};
}
test('controlled protocol: command exit70 remains executed; stdout cannot supply status',async()=>{
 const c=controlled();const result=await c.executor.execute(request);assert.equal(result.exitCode,70);assert.equal(result.drained,true);assert.equal(result.executed,true);assert.equal(result.stdoutBytes,15);assert.equal(c.calls(),1);
});
test('helper70 and missing/forged control status fail closed despite stdout',async()=>{
 await assert.rejects(controlled({code:70}).executor.execute(request),{code:'SYSTEM_DIAGNOSTIC_HELPER_FAILED'});
 await assert.rejects(controlled({status:''}).executor.execute(request),{code:'SYSTEM_DIAGNOSTIC_STATUS_INVALID'});
 for(const status of ['D1 0 0 drained\nextra','D1 -1 0 drained\n','D1 0 9 drained\n'])assert.throws(()=>decodeDiagnosticStatus(Buffer.from(status),0));
});
test('fixed namespace preserves teaching command but provides no proc mount or caller paths',()=>{
 const argv=buildDiagnosticArgv(request,['/usr','/bin']);assert.equal(argv.at(-1),'printf safe; printf injected');assert.ok(argv.includes('--unshare-net'));assert.ok(argv.includes('--unshare-pid'));assert.ok(!argv.includes('--proc'));assert.ok(!argv.includes('--preserve-fds'));assert.ok(!argv.includes('--sync-fd'));assert.equal(argv.filter(x=>x==='--ro-bind').length,3);
});
test('timeout drains and rejects without retry or success receipt',async()=>{
 const c=controlled({stall:true});await assert.rejects(c.executor.execute(request),{code:'SYSTEM_DIAGNOSTIC_TIMEOUT'});assert.deepEqual(c.kills,['SIGTERM']);assert.equal(c.calls(),1);
});
test('pre-abort prevents spawn',async()=>{const c=controlled();const abort=new AbortController();abort.abort();await assert.rejects(c.executor.execute(request,{signal:abort.signal}));assert.equal(c.calls(),0);});
test('bound execution returns exact admission target while keeping inner receipt contract',async()=>{
 const targetId='00000000-0000-4000-8000-000000000009';const c=controlled();const result=await c.executor.executeBound({targetId,request});assert.equal(result.targetId,targetId);assert.equal(result.hostname,'system-diag-'+targetId.replaceAll('-',''));assert.equal(result.result.exitCode,70);assert.equal(c.calls(),1);
});
