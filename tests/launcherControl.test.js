'use strict';
const{test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const{createController,requestStop,ownedShutdown}=require('../scripts/launcher-control');
function fixture(){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-controller-'));return{dir,stateFile:path.join(dir,'state.json'),clean(){fs.rmSync(dir,{recursive:true,force:true});}};}
function writeState(stateFile,state){fs.writeFileSync(stateFile,JSON.stringify(state)+'\n',{mode:0o600});}
const deadPid=99999999;
test('private authenticated controller stops only its owner and refuses double launch',async()=>{
 const{dir,stateFile,clean}=fixture();let count=0,controller;
 try{controller=await createController({workspace:dir,stateFile,stop:async()=>{count++;}});const state=JSON.parse(fs.readFileSync(stateFile));assert.equal(fs.statSync(stateFile).mode&0o777,0o600);assert.equal(state.version,2);assert.equal(state.ownerPid,process.pid);
  const denied=await fetch(`http://127.0.0.1:${state.port}/stop`,{method:'POST'});assert.equal(denied.status,403);assert.equal(count,0);
  const unicode=await fetch(`http://127.0.0.1:${state.port}/stop`,{method:'POST',headers:{Authorization:'é'.repeat(71)}});assert.equal(unicode.status,403);assert.equal(count,0);
  await assert.rejects(createController({workspace:dir,stateFile,stop:async()=>{}}),{code:'LAUNCHER_OWNER_PRESENT'});
  assert.deepEqual(await requestStop({workspace:dir,stateFile}),{stopped:true,controllerRecovered:false});assert.equal(count,1);
  assert.equal(fs.existsSync(stateFile),false);
  await controller.close();
  await assert.rejects(requestStop({workspace:dir,stateFile}),{code:'ENOENT'});
  controller=await createController({workspace:dir,stateFile,stop:async()=>{count++;}});
  assert.deepEqual(await requestStop({workspace:dir,stateFile}),{stopped:true,controllerRecovered:false});
  assert.equal(count,2);
 }finally{await controller?.close();clean();}
});
test('dead v2 owner and closed control port permit controller-only recovery and restart',async()=>{
 const{dir,stateFile,clean}=fixture();let controller;
 try{
  controller=await createController({workspace:dir,stateFile,stop:async()=>{}});
  const stale=JSON.parse(fs.readFileSync(stateFile));await controller.close();controller=undefined;
  assert.throws(()=>process.kill(deadPid,0),{code:'ESRCH'});
  writeState(stateFile,{...stale,ownerPid:deadPid});
  assert.deepEqual(await requestStop({workspace:dir,stateFile}),{controllerRecovered:true,childrenStopped:false});
  assert.equal(fs.existsSync(stateFile),false);
  writeState(stateFile,{...stale,ownerPid:deadPid});
  controller=await createController({workspace:dir,stateFile,stop:async()=>{}});
  assert.equal(JSON.parse(fs.readFileSync(stateFile)).ownerPid,process.pid);
 }finally{await controller?.close();clean();}
});
test('legacy and live-owner states remain when the controller is unavailable',async()=>{
 const{dir,stateFile,clean}=fixture();
 try{
  const base={workspace:fs.realpathSync(dir),port:1,token:'a'.repeat(64)};
  writeState(stateFile,{version:1,...base});
  await assert.rejects(createController({workspace:dir,stateFile,stop:async()=>{}}),{code:'LAUNCHER_LEGACY_STATE'});
  await assert.rejects(requestStop({workspace:dir,stateFile,timeoutMs:25}),{code:'LAUNCHER_UNAVAILABLE'});
  assert.equal(JSON.parse(fs.readFileSync(stateFile)).version,1);
  writeState(stateFile,{version:2,...base,ownerPid:process.pid});
  await assert.rejects(createController({workspace:dir,stateFile,stop:async()=>{}}),{code:'LAUNCHER_OWNER_PRESENT'});
  await assert.rejects(requestStop({workspace:dir,stateFile,timeoutMs:25}),{code:'LAUNCHER_UNAVAILABLE'});
  assert.equal(JSON.parse(fs.readFileSync(stateFile)).ownerPid,process.pid);
 }finally{clean();}
});
test('dead owner does not permit recovery while the recorded port is occupied',async()=>{
 const{dir,stateFile,clean}=fixture(),server=http.createServer((req,res)=>res.end('unrelated'));
 try{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  writeState(stateFile,{version:2,workspace:fs.realpathSync(dir),port:server.address().port,token:'a'.repeat(64),ownerPid:deadPid});
  await assert.rejects(requestStop({workspace:dir,stateFile}),{code:'LAUNCHER_PORT_OCCUPIED'});
  await assert.rejects(createController({workspace:dir,stateFile,stop:async()=>{}}),{code:'LAUNCHER_PORT_OCCUPIED'});
  assert.equal(fs.existsSync(stateFile),true);
 }finally{await new Promise(resolve=>server.close(resolve));clean();}
});
test('timed-out stop retains state and never claims recovery',async()=>{
 const{dir,stateFile,clean}=fixture(),server=http.createServer(()=>{});
 try{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  writeState(stateFile,{version:2,workspace:fs.realpathSync(dir),port:server.address().port,token:'a'.repeat(64),ownerPid:process.pid});
  await assert.rejects(requestStop({workspace:dir,stateFile,timeoutMs:25}),{code:'LAUNCHER_STOP_TIMEOUT'});
  assert.equal(fs.existsSync(stateFile),true);
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));clean();}
});
test('failed owned shutdown retains the controller for a retry',async()=>{
 const{dir,stateFile,clean}=fixture();let attempts=0,controller;
 try{
  controller=await createController({workspace:dir,stateFile,stop:async()=>{if(++attempts===1)throw new Error('failed');}});
  await assert.rejects(requestStop({workspace:dir,stateFile}),{code:'LAUNCHER_STOP_REJECTED'});
  assert.equal(fs.existsSync(stateFile),true);
  assert.deepEqual(await requestStop({workspace:dir,stateFile}),{stopped:true,controllerRecovered:false});
  assert.equal(attempts,2);
 }finally{await controller?.close();clean();}
});
test('unsafe or cross-workspace state is retained',async()=>{
 const{dir,stateFile,clean}=fixture();
 try{
  const state={version:2,workspace:'/another-workspace',port:1,token:'a'.repeat(64),ownerPid:deadPid};
  writeState(stateFile,state);
  await assert.rejects(requestStop({workspace:dir,stateFile}),{code:'LAUNCHER_STATE_INVALID'});
  await assert.rejects(createController({workspace:dir,stateFile,stop:async()=>{}}),{code:'LAUNCHER_STATE_INVALID'});
  assert.equal(fs.existsSync(stateFile),true);
  fs.unlinkSync(stateFile);fs.symlinkSync(path.join(dir,'missing'),stateFile);
  await assert.rejects(createController({workspace:dir,stateFile,stop:async()=>{}}),{code:'LAUNCHER_STATE_UNSAFE'});
  assert.equal(fs.lstatSync(stateFile).isSymbolicLink(),true);
 }finally{clean();}
});
test('shutdown targets only the spawned process group and is idempotent',async()=>{
 const calls=[];const stop=ownedShutdown({pid:987654},{platform:'darwin',kill:(pid,signal)=>calls.push([pid,signal]),graceMs:5});await Promise.all([stop(),stop()]);assert.deepEqual(calls,[[-987654,'SIGTERM'],[-987654,'SIGKILL']]);
});
test('Windows owned shutdown requires a job and joins its helper once',async()=>{
 const calls=[],job={async stop(options){calls.push(['stop',options]);},async close(){calls.push(['close']);}};
 const stop=ownedShutdown({pid:987654},{platform:'win32',job,graceMs:7,kill(){throw Error('PID signal forbidden');}});
 await Promise.all([stop(),stop()]);
 assert.deepEqual(calls,[['stop',{graceMs:7}],['close']]);
 await assert.rejects(ownedShutdown({pid:987654},{platform:'win32'})(),{code:'LAUNCHER_OWNED_JOB_UNAVAILABLE'});
});
