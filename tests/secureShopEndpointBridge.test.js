'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopEndpointCapabilities:create}=require('./fixtures/secureShopEndpointCapabilities');
const {createSecureShopEndpointBridge:bridge}=require('./fixtures/secureShopEndpointBridge');
const scope={targetId:'10000000-0000-4000-8000-000000000001',launchId:'20000000-0000-4000-8000-000000000001',scenarioId:'30000000-0000-4000-8000-000000000001',generation:0,platformOwnerId:1,platformSessionId:1};
function setup(send){const registry=create(),grant=registry.grant(scope);let closed=false;
 const sender={send,status:()=>({closed}),close(){closed=true;}};
 return {registry,grant,sender,value:bridge({registry,grant,sender})};}
const register=g=>({...g,operation:'register',sequence:1,endpoint:{host:'127.0.0.1',port:35001}});
test('sync registration keeps issue result private until ordered bootstrap and register ACK',async()=>{
 let release;const events=[];const f=setup(async message=>{events.push(message.operation);if(message.operation==='register')await new Promise(r=>{release=r;});});
 const issued={url:'http://127.0.0.1:35001/policy/owned'};let exposed=false;
 const pending=f.value.issue(async()=>{assert.equal(f.value.apply(register(f.grant)).state,'active');return issued;}).then(result=>{exposed=true;return result;});
 await new Promise(setImmediate);assert.deepEqual(events,['bootstrap','register']);assert.equal(exposed,false);
 release();assert.equal(await pending,issued);
});
test('revocation is local immediately and cleanup awaits child acknowledgement',async()=>{
 let release;const f=setup(async m=>{if(m.operation==='revoke')await new Promise(r=>{release=r;});});
 f.value.apply(register(f.grant));await f.value.flush();let done=false;
 const pending=f.value.cleanup(async()=>{f.value.apply({...f.grant,sequence:2,operation:'revoke',endpoint:null});return 'clean';}).then(v=>{done=true;return v;});
 assert.equal(f.registry.permits('127.0.0.1',35001),false);await new Promise(setImmediate);assert.equal(done,false);
 release();assert.equal(await pending,'clean');assert.throws(()=>f.value.apply(register(f.grant)));
});
test('missing ACK closes local admission and prevents scope reuse',async()=>{
 const f=setup(async()=>{throw Error('IPC_ACK_TIMEOUT');});f.value.apply(register(f.grant));
 await assert.rejects(f.value.flush(),/IPC_ACK_TIMEOUT/);assert.equal(f.registry.permits('127.0.0.1',35001),false);
 assert.equal(f.sender.status().closed,true);assert.throws(()=>f.value.apply(register(f.grant)));
});
test('failed local cleanup still waits for pending revoke and reports both failures',async()=>{
 const f=setup(async m=>{if(m.operation==='revoke')throw Error('lost child');});f.value.apply(register(f.grant));await f.value.flush();
 await assert.rejects(f.value.cleanup(async()=>{f.value.apply({...f.grant,sequence:2,operation:'revoke',endpoint:null});throw Error('target cleanup');}),e=>e instanceof AggregateError&&e.errors.length===2);
 assert.equal(f.registry.permits('127.0.0.1',35001),false);
});
test('both cleanup failures retain primary rejection without an unhandled queue',async()=>{
 const primary=Error('primary');let closes=0;
 const value=bridge({registry:{apply(){return{state:'active'};},close(){closes++;throw Error('registry');}},grant:{capability:'owned',scope},
 sender:{send:async()=>{throw primary;},status:()=>({closed:false}),close(){closes++;throw Error('sender');}}});
 value.apply({capability:'owned',scope,operation:'register'});
 await assert.rejects(value.flush(),e=>e instanceof AggregateError&&e.errors[0]===primary&&e.errors.length===3);assert.equal(closes,2);
});
test('genuine target plus inherited IPC fork fences issue, serves HTTP and retires completely',{timeout:15000},async()=>{
 const {waitForChild}=require('./fixtures/fullBackendBootControls');
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net');
 const {fork}=require('node:child_process'),{once}=require('node:events');
 const {createEndpointIpcSender}=require('./fixtures/secureShopEndpointIpc');
 const {createObservedTargetFactory}=require('./fixtures/secureShopPostBindObserver');
 const {createSecureShopSsrfOwnedTarget}=require('../server/services/secureshopSsrfOwnedTarget');
 const {createSecureShopSsrfTargetPool}=require('../server/services/secureshopSsrfTargetPool');
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'ss-bridge-fork-'))),file=path.join(root,'child.cjs');
 fs.writeFileSync(file,`
 const {createSecureShopEndpointCapabilities:create}=require(${JSON.stringify(require.resolve('./fixtures/secureShopEndpointCapabilities'))});
 const {createEndpointIpcReceiver:receiver}=require(${JSON.stringify(require.resolve('./fixtures/secureShopEndpointIpc'))});
 const registry=create();let release;
 const adapter=receiver(process,{grant:registry.grant,apply:async m=>{const result=registry.apply(m);if(m.operation==='register'){process.send({kind:'waiting'});await new Promise(r=>release=r);}return result;},revokeAll:registry.close});
 process.on('message',async m=>{if(m.kind==='release')release();if(m.kind==='fetch'){try{const u=new URL(m.url);if(!registry.permits(u.hostname,Number(u.port)))throw Error('denied');const r=await fetch(u);process.send({kind:'fetched',status:r.status,body:await r.json()});}catch{process.send({kind:'failed'});}}});
 process.on('disconnect',()=>{adapter.close();});process.send({kind:'ready'});
 `,{mode:0o600});
 const child=fork(file,[],{execPath:process.execPath,env:{},silent:true,detached:false});child.stdout.resume();child.stderr.resume();
 const exited=once(child,'exit');let targetPool,sender,port;
 function message(kind){return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{child.off('message',listen);reject(Error('message deadline'));},3000);function listen(m){if(m.kind===kind){clearTimeout(timer);child.off('message',listen);resolve(m);}}child.on('message',listen);});}
 try{
  await message('ready');const registry=create(),grant=registry.grant(scope);
  sender=createEndpointIpcSender(child,{timeoutMs:3000,revokeAll:registry.close});const value=bridge({registry,grant,sender});
  const factory=createObservedTargetFactory({createTarget:createSecureShopSsrfOwnedTarget,root,registry:value,grant,scope});
  targetPool=createSecureShopSsrfTargetPool({root,createTarget:factory});
  let exposed=false;const waiting=message('waiting');
  const issuedPromise=value.issue(()=>targetPool.issue(scope,{requestId:'40000000-0000-4000-8000-000000000001',resourceKind:'public-policy'})).then(v=>{exposed=true;return v;});
  void issuedPromise.catch(()=>{});
  await waiting;assert.equal(exposed,false);child.send({kind:'release'});const issued=await issuedPromise;port=Number(new URL(issued.url).port);
  const fetched=message('fetched');child.send({kind:'fetch',url:issued.url});const result=await fetched;assert.equal(result.status,200);assert.equal(result.body.classification,'public');
  await value.cleanup(()=>targetPool.retire(scope));assert.equal(registry.permits('127.0.0.1',port),false);
  assert.equal(fs.existsSync(path.join(root,scope.targetId)),false);
  await new Promise((resolve,reject)=>{const socket=net.connect({host:'127.0.0.1',port});socket.once('connect',()=>{socket.destroy();reject(Error('listener survived'));});socket.once('error',e=>e.code==='ECONNREFUSED'?resolve():reject(e));});
  sender.close();await exited;assert.throws(()=>process.kill(child.pid,0),e=>e.code==='ESRCH');
 }finally{
  const errors=[];
  try{sender?.close();}catch(error){errors.push(error);}
  try{await targetPool?.close();}catch(error){errors.push(error);}
  try{
   if(child.exitCode===null&&child.signalCode===null){
    child.kill('SIGTERM');
    try{await waitForChild(child,{timeoutMs:2000});}
    catch{child.kill('SIGKILL');await waitForChild(child,{timeoutMs:2000});}
   }
   assert.throws(()=>process.kill(child.pid,0),{code:'ESRCH'});
   fs.rmSync(root,{recursive:true,force:true});
  }catch(error){errors.push(error);}
  if(errors.length)throw new AggregateError(errors,'Bridge fixture cleanup failed');
 }
});
