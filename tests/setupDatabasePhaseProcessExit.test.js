'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{spawn}=require('node:child_process');
const {waitForChild}=require('./fixtures/fullBackendBootControls');
test('owned stdio-ignore IPC child is reaped after disconnect even without close notification',async()=>{
 const child=spawn(process.execPath,['-e',"process.on('disconnect',()=>process.exit(0));process.send('ready');setInterval(()=>{},1000);"],{stdio:['ignore','ignore','ignore','ipc']});
 try{
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Owned child readiness deadline')),2000);child.once('message',()=>{clearTimeout(timer);resolve();});child.once('error',error=>{clearTimeout(timer);reject(error);});});
  const exited=waitForChild(child,{timeoutMs:2000});child.disconnect();
  assert.equal(await exited,0);assert.equal(child.exitCode,0);
  assert.throws(()=>process.kill(child.pid,0),{code:'ESRCH'});
  assert.equal(await waitForChild(child,{timeoutMs:2000}),0,'already reaped child does not miss event');
 }finally{if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await waitForChild(child,{timeoutMs:2000});}}
});
