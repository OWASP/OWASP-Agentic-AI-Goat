'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {createEndpointIpcSender:sender,createEndpointIpcReceiver:receiver}=require('./fixtures/secureShopEndpointIpc');
const {createSecureShopEndpointCapabilities:create}=require('./fixtures/secureShopEndpointCapabilities');
function pair(){const a=new EventEmitter(),b=new EventEmitter();a.connected=b.connected=true;
 a.disconnect=b.disconnect=()=>{if(!a.connected)return;a.connected=b.connected=false;a.emit('disconnect');b.emit('disconnect');};
 a.send=(value,cb)=>{queueMicrotask(()=>b.emit('message',structuredClone(value)));cb?.();};
 b.send=(value,cb)=>{queueMicrotask(()=>a.emit('message',structuredClone(value)));cb?.();};return[a,b];}
const scope={targetId:'10000000-0000-4000-8000-000000000001',launchId:'20000000-0000-4000-8000-000000000001',scenarioId:'30000000-0000-4000-8000-000000000001',generation:0,platformOwnerId:1,platformSessionId:1};
test('owned channel applies exact registry scope and acknowledges ordered register/revoke',async()=>{
 const [a,b]=pair(),registry=create(),grant=create().grant(scope);
 const child=receiver(b,{grant:registry.grant,apply:registry.apply,revokeAll:registry.close});const parent=sender(a,{revokeAll(){}});
 try { await parent.send({...grant,operation:'bootstrap'});const ack=await parent.send({...grant,sequence:1,operation:'register',endpoint:{host:'127.0.0.1',port:35001}});
 assert.equal(ack.sequence,2);assert.equal(registry.permits('127.0.0.1',35001),true);
 await parent.send({...grant,sequence:2,operation:'revoke',endpoint:null});assert.equal(registry.permits('127.0.0.1',35001),false);
 }finally{parent.close();child.close();}assert.equal(a.listenerCount('message'),0);assert.equal(b.listenerCount('message'),0);
});
test('missing ack, cancellation, disconnect and false ack revoke parent admissions',async()=>{
 for(const mode of ['timeout','cancel','disconnect','forged']){
  const [a]=pair();let revoked=0;const parent=sender(a,{timeoutMs:10,revokeAll(){revoked++;}}),controller=new AbortController();
  const pending=parent.send({scope},{signal:controller.signal});const rejection=assert.rejects(pending);
  if(mode==='cancel')controller.abort();if(mode==='disconnect')a.emit('disconnect');
  if(mode==='forged')a.emit('message',{version:'secureshop-endpoint-ipc.v1',type:'ack',id:'foreign',sequence:1,digest:'bad',ok:true});
  await rejection;assert.equal(revoked,1);assert.equal(a.listenerCount('message'),0);
 }
});
test('child rejects wrong scope and disconnects without retaining admission',async()=>{
 const [a,b]=pair(),registry=create(),grant=create().grant(scope);
 const child=receiver(b,{grant:registry.grant,apply:registry.apply,revokeAll:registry.close}),parent=sender(a,{timeoutMs:10,revokeAll(){}});
 await parent.send({...grant,operation:'bootstrap'});
 await parent.send({...grant,sequence:1,operation:'register',endpoint:{host:'127.0.0.1',port:35001}});
 await assert.rejects(parent.send({...grant,scope:{...scope,generation:1},sequence:2,operation:'revoke',endpoint:null}));
 assert.equal(registry.permits('127.0.0.1',35001),false);child.close();parent.close();
});

test('cleanup failure stays inspectable after admission closes',()=>{
 const [a,b]=pair();const parent=sender(a,{revokeAll(){throw Error('controlled');}});
 const child=receiver(b,{grant(){},apply(){},revokeAll(){throw Error('controlled');}});
 parent.close();assert.deepEqual(parent.status(),{closed:true,failures:['REVOKE_FAILED']});
 assert.deepEqual(child.status(),{closed:true,failures:['REVOKE_FAILED']});
});

test('real owned fork bootstraps distinct registry memory and revokes on disconnect or lost ack',async()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{fork}=require('node:child_process');
 const {once}=require('node:events');const root=fs.mkdtempSync(path.join(os.tmpdir(),'ss-ipc-fork-'));
 const file=path.join(root,'child.cjs');
 fs.writeFileSync(file, `
 const {createSecureShopEndpointCapabilities:create}=require(${JSON.stringify(require.resolve('./fixtures/secureShopEndpointCapabilities'))});
 const {createEndpointIpcReceiver:receiver}=require(${JSON.stringify(require.resolve('./fixtures/secureShopEndpointIpc'))});
 const registry=create();let active=false;
 const channel=process.env.LOST_ACK==='1'?{
   on:process.on.bind(process),off:process.off.bind(process),
   get connected(){return process.connected;},disconnect:process.disconnect.bind(process),
   send(message,callback){if(message.sequence===2){callback?.();return;}process.send(message,callback);}
 }:process;
 const adapter=receiver(channel,{grant:registry.grant,apply(message){const result=registry.apply(message);active=registry.permits('127.0.0.1',35001);return result;},revokeAll:registry.close});
 process.on('disconnect',()=>{process.stdout.write(JSON.stringify({activeBeforeDisconnect:active,permittedAfter:registry.permits('127.0.0.1',35001),status:adapter.status()})+'\\n');});
 process.send({ready:true});
 `,{mode:0o600});
 try {
  for(const lost of [false,true]) {
   const child=fork(file,[],{execPath:process.execPath,env:{LOST_ACK:lost?'1':'0'},silent:true,detached:false});
   let output='';child.stdout.on('data',bytes=>{output+=bytes;});child.stderr.resume();
   const exit=once(child,'exit');let timer;
   try {
    await Promise.race([once(child,'message'),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('fork readiness timeout')),3000);})]);clearTimeout(timer);
    const parent=sender(child,{timeoutMs:100,revokeAll(){}}),grant=create().grant(scope);
    await parent.send({...grant,operation:'bootstrap'});
    const registration=parent.send({...grant,sequence:1,operation:'register',endpoint:{host:'127.0.0.1',port:35001}});
    if(lost)await assert.rejects(registration,{code:'IPC_ACK_TIMEOUT'});
    else {await registration;parent.close();}
    const [code]=await Promise.race([exit,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('fork exit timeout')),3000);})]);clearTimeout(timer);
    assert.equal(code,0);const record=JSON.parse(output.trim());
    assert.equal(record.activeBeforeDisconnect,true);assert.equal(record.permittedAfter,false);assert.equal(record.status.closed,true);
    assert.throws(()=>process.kill(child.pid,0),error=>error.code==='ESRCH');
   } finally {clearTimeout(timer);if(child.exitCode===null&&child.signalCode===null){child.kill('SIGTERM');await exit;}}
  }
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
