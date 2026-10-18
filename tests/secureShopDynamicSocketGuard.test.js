'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),net=require('node:net'),{fork}=require('node:child_process'),{once}=require('node:events');
const {createSecureShopEndpointCapabilities}=require('./fixtures/secureShopEndpointCapabilities');const {createEndpointIpcSender}=require('./fixtures/secureShopEndpointIpc');
const scope={targetId:'10000000-0000-4000-8000-000000000021',launchId:'20000000-0000-4000-8000-000000000021',scenarioId:'30000000-0000-4000-8000-000000000021',generation:0,platformOwnerId:21,platformSessionId:21};
const childSource=`'use strict';const http=require('node:http');const {createSecureShopEndpointCapabilities}=require(${JSON.stringify(require.resolve('./fixtures/secureShopEndpointCapabilities'))});const {createEndpointIpcReceiver}=require(${JSON.stringify(require.resolve('./fixtures/secureShopEndpointIpc'))});const {installStaticDynamicSocketGuard}=require(${JSON.stringify(require.resolve('./fixtures/secureShopStaticDynamicSocketGuard'))});const {allowedDatabaseConnect}=require(${JSON.stringify(require.resolve('./fixtures/fullBackendBootControls'))});const r=createSecureShopEndpointCapabilities();createEndpointIpcReceiver(process,{grant:r.grant,apply:r.apply,revokeAll:r.close});process.send({type:'ready'});installStaticDynamicSocketGuard({staticAllows:args=>allowedDatabaseConnect(args,{host:'127.0.0.1',port:Number(process.env.STATIC_PORT)}),permits:r.permits,trackSocket:r.trackSocket});process.on('message',m=>{if(m.type==='probe'){try{const req=http.request(m.options||{host:'127.0.0.1',port:m.port,path:'/'});req.on('socket',s=>{if(m.hold)process.send({type:'hold-connected'});s.on('close',()=>{if(m.hold)process.send({type:'hold-closed'})})});req.on('response',res=>{if(m.hold)return;res.resume();res.on('end',()=>process.send({type:'probe',ok:true}))});req.on('error',e=>process.send({type:m.hold?'hold-closed':'probe',ok:false,code:e.code}));req.end()}catch(e){process.send({type:m.hold?'hold-closed':'probe',ok:false,code:e.code})}}});`;
const {waitForChild}=require('./fixtures/fullBackendBootControls');
function waitForMessage(child,type) {
  return new Promise((resolve,reject)=>{
    const finish=(error,message)=>{clearTimeout(timer);child.off('message',onMessage);child.off('error',onError);error?reject(error):resolve(message);};
    const onMessage=message=>{if(message.type===type)finish(null,message);};
    const onError=error=>finish(error);
    const timer=setTimeout(()=>finish(Error('message timeout: '+type)),2000);
    child.on('message',onMessage);child.once('error',onError);
  });
}
test('dynamic child guard revokes a real established HTTP socket through inherited IPC', {timeout:15000}, async()=>{
  const sockets=new Set();let heldResolve;
  const heldRequest=new Promise(resolve=>{heldResolve=resolve;});
  const server=http.createServer((req,res)=>{if(req.url==='/hold'){heldResolve();return;}res.end('ok');});
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const port=server.address().port;
  const staticServer=http.createServer((req,res)=>res.end('static-ok'));
  await new Promise((resolve,reject)=>{staticServer.once('error',reject);staticServer.listen(0,'127.0.0.1',resolve);});
  const staticPort=staticServer.address().port;
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'ss-dynamic-'));
  const file=path.join(root,'child.cjs');fs.writeFileSync(file,childSource,{mode:0o600});
  let child,parent,registry;
  try {
    child=fork(file,[],{silent:true,detached:false,env:{STATIC_PORT:String(staticPort)}});
    await waitForMessage(child,'ready');
    registry=createSecureShopEndpointCapabilities();const grant=registry.grant(scope);
    parent=createEndpointIpcSender(child,{timeoutMs:1000,revokeAll:registry.close});
    const probe=(selectedPort=port)=>{const result=waitForMessage(child,'probe');child.send({type:'probe',port:selectedPort});return result;};
    assert.equal((await probe(staticPort)).ok,true);
    assert.equal((await probe()).ok,false);
    await parent.send({...grant,operation:'bootstrap'});
    await parent.send({...grant,sequence:1,operation:'register',endpoint:{host:'127.0.0.1',port}});
    assert.equal((await probe()).ok,true);
    let holdTimer;
    try {
      child.send({type:'probe',port,hold:true,options:{host:'127.0.0.1',port,path:'/hold'}});
      await Promise.race([heldRequest,new Promise((_,reject)=>{holdTimer=setTimeout(()=>reject(Error('held HTTP request not received')),2000);})]);
    } finally {clearTimeout(holdTimer);}
    const closed=waitForMessage(child,'hold-closed');
    await parent.send({...grant,sequence:2,operation:'revoke',endpoint:null});
    await closed;
    assert.equal((await probe()).ok,false);
    assert.equal((await probe(staticPort)).ok,true);
    parent.close();await waitForChild(child,{timeoutMs:2000});
    assert.equal(child.exitCode,0);
  } finally {
    parent?.close();registry?.close();
    try {
      if(child&&child.exitCode===null&&child.signalCode===null){
        child.kill('SIGTERM');
        try{await waitForChild(child,{timeoutMs:2000});}
        catch{child.kill('SIGKILL');await waitForChild(child,{timeoutMs:2000});}
      }
      if(child?.pid)assert.throws(()=>process.kill(child.pid,0),{code:'ESRCH'});
    } finally {
      for(const socket of sockets)socket.destroy();
      await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
      assert.equal(server.address(),null);
      staticServer.closeAllConnections();
      await new Promise((resolve,reject)=>staticServer.close(error=>error?reject(error):resolve()));
      assert.equal(staticServer.address(),null);
      await new Promise((resolve,reject)=>{
        const socket=net.connect({host:'127.0.0.1',port});
        socket.once('connect',()=>{socket.destroy();reject(Error('owned listener remained open'));});
        socket.once('error',error=>{socket.destroy();error.code==='ECONNREFUSED'?resolve():reject(error);});
        socket.setTimeout(1000,()=>{socket.destroy();reject(Error('listener closure timeout'));});
      });
      fs.rmSync(root,{recursive:true,force:true});
    }
  }
});
test('dynamic guard rejects foreign, UNIX and custom-lookup forms before connect',()=>{const {normalizeConnectArgs,installDynamicSocketGuard}=require('./fixtures/secureShopDynamicSocketGuard');assert.deepEqual(normalizeConnectArgs([[{host:'127.0.0.1',port:35001}]]),{host:'127.0.0.1',port:35001});assert.throws(()=>normalizeConnectArgs([{path:'/tmp/socket'}]),{code:'QUALIFICATION_SOCKET_FORM'});assert.throws(()=>normalizeConnectArgs([{host:'127.0.0.1',port:35001,lookup:()=>{}}]),{code:'QUALIFICATION_SOCKET_FORM'});assert.throws(()=>normalizeConnectArgs([{host:'127.0.0.1',port:65536}]),{code:'QUALIFICATION_SOCKET_FORM'});const calls=[];const fakeConnect=function(...args){calls.push(args);return {destroy(){}}};const guard=installDynamicSocketGuard({permits:(host,port)=>host==='127.0.0.1'&&port===35001,trackSocket(){},connect:fakeConnect});assert.throws(()=>guard.guarded([{host:'127.0.0.2',port:35001}]),{code:'QUALIFICATION_ENDPOINT_BLOCKED'});assert.throws(()=>guard.guarded([{host:'127.0.0.1',port:35002}]),{code:'QUALIFICATION_ENDPOINT_BLOCKED'});assert.throws(()=>guard.guarded([{host:'127.0.0.1',port:35001,lookup:()=>{}}]),{code:'QUALIFICATION_SOCKET_FORM'});guard.restore();assert.notEqual(net.Socket.prototype.connect,fakeConnect);assert.equal(calls.length,0)});
test('revocation destroys already tracked sockets',()=>{const registry=createSecureShopEndpointCapabilities(),g=registry.grant(scope);registry.apply({version:1,capability:g.capability,scope,sequence:1,operation:'register',endpoint:{host:'127.0.0.1',port:35002}});let destroyed=0;registry.trackSocket('127.0.0.1',35002,{destroy(){destroyed++}});registry.apply({version:1,capability:g.capability,scope,sequence:2,operation:'revoke',endpoint:null});assert.equal(destroyed,1);registry.close()});
