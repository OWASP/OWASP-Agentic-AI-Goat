'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http'),net=require('node:net');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {once}=require('node:events');
const {createBrowserForwardProxy}=require('./fixtures/fullBackendBrowserForwardProxy');
const {createFullBackendBrowserProxy}=require('./fixtures/fullBackendBrowserProxy');
test('forward proxy admits only exact application origin and rejects foreign/CONNECT/upgrade before forwarding',async()=>{
 let hits=0;const app=http.createServer((_req,res)=>{hits++;res.end('owned');});app.listen(0,'127.0.0.1');await once(app,'listening');
 const origin=`http://127.0.0.1:${app.address().port}`,proxy=await createBrowserForwardProxy({appOrigin:origin});
 async function request(target,method='GET',headers={}){return new Promise((resolve,reject)=>{const req=http.request(proxy.origin,{path:target,method,headers},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.end();});}
 async function raw(value){const socket=net.connect(new URL(proxy.origin).port,'127.0.0.1');await once(socket,'connect');socket.end(value);let output='';for await(const chunk of socket)output+=chunk;return output;}
 try {
  assert.equal(await request(origin+'/api/test?x=1'),200);
  assert.equal(await request('http://external.invalid/'),403);assert.equal(await request('http://127.0.0.1:1/'),403);
  assert.equal(await request(origin.replace('http:','https:')),403);assert.equal(hits,1);
  assert.match(await raw('CONNECT external.invalid:443 HTTP/1.1\r\nHost: external.invalid\r\n\r\n'),/403/);
  assert.match(await raw(`GET ${origin}/ HTTP/1.1\r\nHost: owned\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`),/403/);
  assert.deepEqual(proxy.counters(),{allowed:1,denied:3,connectDenied:1,upgradeDenied:1,
   idlePreconnectTimeouts:0,browserTeardownResets:0,browserCancelledResets:0,
   browserTeardownBeganAfterMs:null,browserTeardownLastResetAfterMs:null,browserCancelledLastResetAfterMs:null});
 }finally{await proxy.close();app.closeAllConnections();await new Promise(resolve=>app.close(resolve));}
});
test('close destroys peers holding CONNECT and upgraded connections open',async()=>{
 for(const method of ['CONNECT','upgrade']){
  const proxy=await createBrowserForwardProxy({appOrigin:'http://127.0.0.1:43210'});
  const socket=net.connect({host:'127.0.0.1',port:Number(new URL(proxy.origin).port),allowHalfOpen:true});
  await once(socket,'connect');
  socket.write(method==='CONNECT'?'CONNECT external.invalid:443 HTTP/1.1\r\nHost: external.invalid\r\n\r\n':'GET http://127.0.0.1:43210/ HTTP/1.1\r\nHost: owned\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  await once(socket,'data');
  let timer;
  try {await Promise.race([proxy.close(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('close hung')),1000);})]);}
  finally {clearTimeout(timer);socket.destroy();}
 }
});

test('composed proxies preserve independent MCP and SecureShop budgets and cancel held work on disconnect',async()=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'owned-composed-browser-proxy-')));
 fs.writeFileSync(path.join(root,'index.html'),'owned');
 const held=[],sockets=new Set();
 const backend=http.createServer((req,res)=>{req.resume();if(req.headers['x-hold']==='yes'){held.push(res);return;}res.end('owned');});
 backend.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
 backend.listen(0,'127.0.0.1');await once(backend,'listening');
 let app,forward;const original=http.request,budgets=[];
 try{
  app=await createFullBackendBrowserProxy({buildRoot:root,backendOrigin:`http://127.0.0.1:${backend.address().port}`,mcpChatTimeoutMs:30000,secureShopTimeoutMs:40000});
  forward=await createBrowserForwardProxy({appOrigin:app.origin,mcpChatTimeoutMs:30000,secureShopTimeoutMs:40000});
  const appPort=Number(new URL(app.origin).port),backendPort=backend.address().port;
  http.request=function(options,...args){
   const port=Number(options?.port);if(port===appPort)budgets.push(['forward',options.method,options.path,options.timeout]);
   if(port===backendPort)budgets.push(['application',options.method,options.path,options.timeout]);
   return original.call(this,options,...args);
  };
  const request=(route,headers={})=>new Promise((resolve,reject)=>{
   const endpoint=new URL(forward.origin);const req=http.request({hostname:endpoint.hostname,port:endpoint.port,
    path:app.origin+route,method:'POST',headers},res=>{let body='';res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,body}));});
   req.on('error',reject);req.end();
  });
  for(const route of ['/api/workshop/mcp/chat','/api/workshop/mcp/conversation/chat','/api/secureshop/v2/persona-inbox/read','/api/secureshop/v2/mcp-trust/run','/api/secureshop/v2/controlled-ssrf/run','/api/secureshop/merchant/reviews/moderate-all','/api/secureshop/products/1/reviews/2/browser-attempt','/api/auth/login']){
   assert.deepEqual(await request(route),{status:200,body:'owned'});
  }
  assert.deepEqual(budgets,[
   ['forward','POST','/api/workshop/mcp/chat',30000],['application','POST','/api/workshop/mcp/chat',30000],
   ['forward','POST','/api/workshop/mcp/conversation/chat',30000],['application','POST','/api/workshop/mcp/conversation/chat',30000],
   ...['/api/secureshop/v2/persona-inbox/read','/api/secureshop/v2/mcp-trust/run','/api/secureshop/v2/controlled-ssrf/run','/api/secureshop/merchant/reviews/moderate-all','/api/secureshop/products/1/reviews/2/browser-attempt'].flatMap(route=>[['forward','POST',route,40000],['application','POST',route,40000]]),
   ['forward','POST','/api/auth/login',10000],['application','POST','/api/auth/login',10000],
  ]);
  const endpoint=new URL(forward.origin);const pending=http.request({hostname:endpoint.hostname,port:endpoint.port,
   path:app.origin+'/api/secureshop/v2/controlled-ssrf/run',method:'POST',headers:{'x-hold':'yes'}});pending.on('error',()=>{});pending.end();
  const deadline=Date.now()+2000;while(!held.length&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,5));
  assert.equal(held.length,1);const closed=once(held[0],'close',{signal:AbortSignal.timeout(2000)});pending.destroy();await closed;
 }finally{
  http.request=original;
  if(forward)await forward.close();if(app)await app.close();
  backend.closeAllConnections();await new Promise(resolve=>backend.close(resolve));
  for(const socket of sockets)assert.equal(socket.destroyed,true);
  fs.rmSync(root,{recursive:true});
 }
});

test('owned socket resets after explicit CONNECT or upgrade denial are contained; unexpected failures reject close',async()=>{
 const {EventEmitter}=require('node:events');const original=http.createServer;
 let server;http.createServer=()=>{server=new EventEmitter();server.listen=(_p,_h,done)=>done();server.address=()=>({port:43211});server.closeAllConnections=()=>{};server.close=done=>done();return server;};
 try{for(const kind of ['connect','upgrade','pipe','ordinary','unexpected']){
  const proxy=await createBrowserForwardProxy({appOrigin:'http://127.0.0.1:43210'});
  const socket=new EventEmitter();socket.end=value=>{assert.match(value,/403 Forbidden/);};socket.destroy=()=>{socket.destroyed=true;socket.emit('close');};
  server.emit('connection',socket);if(kind!=='ordinary')server.emit(['unexpected','pipe'].includes(kind)?'connect':kind,{},socket);
  const error=Object.assign(Error('controlled peer failure'),{code:kind==='unexpected'?'EIO':kind==='pipe'?'EPIPE':'ECONNRESET'});
  assert.doesNotThrow(()=>socket.emit('error',error));assert.equal(socket.destroyed,true);
  if(kind==='ordinary'||kind==='unexpected')await assert.rejects(proxy.close(),e=>e instanceof AggregateError&&e.errors.some(failure=>failure.cause===error&&failure.code===error.code&&failure.phase===(kind==='ordinary'?'active':'denied')));
  else await proxy.close();
 }}finally{http.createServer=original;}
});
test('a browser-cancelled admitted request records its reset without masking an unmarked socket failure',async()=>{
 let markEntered;
 const entered=new Promise(resolve=>{markEntered=resolve;});
 const app=http.createServer((_req,_res)=>markEntered());
 app.listen(0,'127.0.0.1');await once(app,'listening');
 const origin=`http://127.0.0.1:${app.address().port}`;
 const proxy=await createBrowserForwardProxy({appOrigin:origin});
 const socket=net.connect(Number(new URL(proxy.origin).port),'127.0.0.1');
 try{
  await once(socket,'connect');
  socket.write(`GET ${origin}/held HTTP/1.1\r\nHost: owned\r\n\r\n`);
  await entered;
  socket.resetAndDestroy();
  await once(socket,'close');
  for(let i=0;i<100&&proxy.counters().browserCancelledResets===0;i++)await new Promise(resolve=>setTimeout(resolve,5));
  const counters=proxy.counters();
  assert.equal(counters.allowed,1);
  assert.equal(counters.browserCancelledResets,1);
  assert.ok(Number.isSafeInteger(counters.browserCancelledLastResetAfterMs));
  assert.equal(counters.browserTeardownResets,0);
 }finally{
  socket.destroy();try{await proxy.close();}finally{app.closeAllConnections();await new Promise(resolve=>app.close(resolve));}
 }
});
test('an admitted socket error without peer cancellation remains fatal during proxy cleanup',async()=>{
 let markEntered;
 const entered=new Promise(resolve=>{markEntered=resolve;});
 const app=http.createServer((_req,_res)=>markEntered());
 app.listen(0,'127.0.0.1');await once(app,'listening');
 const origin=`http://127.0.0.1:${app.address().port}`;
 const original=http.createServer;let proxyServer,proxy;
 try{
  http.createServer=handler=>{proxyServer=original(handler);return proxyServer;};
  proxy=await createBrowserForwardProxy({appOrigin:origin});
 }finally{http.createServer=original;}
 let peer,admittedSocket,closed=false;
 proxyServer.on('connection',socket=>{admittedSocket=socket;});
 try{
  peer=net.connect(Number(new URL(proxy.origin).port),'127.0.0.1');
  await once(peer,'connect');
  peer.write(`GET ${origin}/held HTTP/1.1\r\nHost: owned\r\n\r\n`);
  await entered;
  assert.ok(admittedSocket);
  admittedSocket.emit('error',Object.assign(Error('controlled admitted socket failure'),{code:'ECONNRESET'}));
  assert.equal(proxy.counters().browserCancelledResets,0);
  assert.equal(peer.destroyed,false);
  await assert.rejects(proxy.close(),error=>error instanceof AggregateError
   &&error.errors.some(row=>row.code==='ECONNRESET'&&row.phase==='admitted'));
  closed=true;
 }finally{
  peer?.destroy();if(!closed)await proxy.close().catch(()=>{});
  app.closeAllConnections();await new Promise(resolve=>app.close(resolve));
 }
});
test('owned teardown contains only expected socket cancellations and retains unexpected close errors',async()=>{
 const {EventEmitter}=require('node:events');const original=http.createServer;
 let server,socket,error;
 http.createServer=()=>{server=new EventEmitter();server.listen=(_p,_h,done)=>done();server.address=()=>({port:43211});server.closeAllConnections=()=>{};server.close=done=>{socket.emit('error',error);done();};return server;};
 try {for(const code of ['ECONNRESET','EPIPE','EIO']){
  const proxy=await createBrowserForwardProxy({appOrigin:'http://127.0.0.1:43210'});
  socket=new EventEmitter();socket.destroy=()=>{socket.destroyed=true;socket.emit('close');};server.emit('connection',socket);
  error=Object.assign(Error('controlled teardown socket failure'),{code});
  if(code==='EIO')await assert.rejects(proxy.close(),failure=>failure instanceof AggregateError&&failure.errors.some(row=>row.code==='EIO'&&row.phase==='closing'&&row.cause===error));
  else await proxy.close();
  assert.equal(socket.destroyed,true);
 }}finally{http.createServer=original;}
});
test('zero-byte preconnect timeout is counted; partial headers and admitted requests remain fatal',async()=>{
 const {EventEmitter}=require('node:events');const originalServer=http.createServer,originalRequest=http.request;
 let server;
 http.createServer=handler=>{server=new EventEmitter();server.on('request',handler);server.listen=(_p,_h,done)=>done();server.address=()=>({port:43211});server.closeAllConnections=()=>{};server.close=done=>done();return server;};
 http.request=()=>{const request=new EventEmitter();request.destroy=()=>{};return request;};
 try {for(const kind of ['zero-byte','partial-header','admitted','denied']){
  const proxy=await createBrowserForwardProxy({appOrigin:'http://127.0.0.1:43210'});
  const socket=new EventEmitter();socket.bytesRead=kind==='partial-header'?1:0;socket.destroy=()=>{socket.destroyed=true;socket.emit('close');};socket.end=()=>{};
  server.emit('connection',socket);
  if(kind==='denied')server.emit('connect',{},socket);
  if(kind==='admitted'){
   const request=new EventEmitter(),response=new EventEmitter();
   Object.assign(request,{socket,url:'http://127.0.0.1:43210/owned',headers:{},method:'GET',pipe:()=>{}});
   Object.assign(response,{writableFinished:false});
   server.emit('request',request,response);
  }
  socket.emit('error',Object.assign(Error('controlled request timeout'),{code:'ERR_HTTP_REQUEST_TIMEOUT'}));
  assert.equal(socket.destroyed,true);
  assert.equal(proxy.counters().idlePreconnectTimeouts,kind==='zero-byte'?1:0);
  if(kind==='zero-byte')await proxy.close();
  else await assert.rejects(proxy.close(),error=>error instanceof AggregateError&&error.errors.some(row=>row.code==='ERR_HTTP_REQUEST_TIMEOUT'&&row.phase===(kind==='admitted'?'admitted':kind==='denied'?'denied':'partial')));
 }}finally{http.createServer=originalServer;http.request=originalRequest;}
});
test('browser teardown contains only post-marker owned resets and records relative timing',async()=>{
 const {EventEmitter}=require('node:events');const originalServer=http.createServer,originalRequest=http.request;
 let server;
 http.createServer=handler=>{server=new EventEmitter();server.on('request',handler);server.listen=(_p,_h,done)=>done();server.address=()=>({port:43211});server.closeAllConnections=()=>{};server.close=done=>done();return server;};
 http.request=()=>{const request=new EventEmitter();request.destroy=()=>{};return request;};
 try {for(const kind of ['before-marker','after-marker','unknown-code','admitted-timeout']){
  const proxy=await createBrowserForwardProxy({appOrigin:'http://127.0.0.1:43210'});
  const socket=new EventEmitter();socket.bytesRead=32;socket.destroy=()=>{socket.destroyed=true;socket.emit('close');};
  server.emit('connection',socket);
  const request=new EventEmitter(),response=new EventEmitter();
  Object.assign(request,{socket,url:'http://127.0.0.1:43210/owned',headers:{},method:'GET',pipe:()=>{}});
  Object.assign(response,{writableFinished:false});server.emit('request',request,response);
  if(kind!=='before-marker')proxy.beginBrowserTeardown();
  const code=kind==='unknown-code'?'EIO':kind==='admitted-timeout'?'ERR_HTTP_REQUEST_TIMEOUT':'ECONNRESET';
  socket.emit('error',Object.assign(Error('controlled socket failure'),{code}));
  if(kind==='before-marker')proxy.beginBrowserTeardown();
  const counters=proxy.counters();
  assert.ok(Number.isSafeInteger(counters.browserTeardownBeganAfterMs)&&counters.browserTeardownBeganAfterMs>=0);
  assert.equal(counters.browserTeardownResets,kind==='after-marker'?1:0);
  if(kind==='after-marker'){
   assert.ok(counters.browserTeardownLastResetAfterMs>=counters.browserTeardownBeganAfterMs);
   await proxy.close();
  }else{
   assert.equal(counters.browserTeardownLastResetAfterMs,null);
   await assert.rejects(proxy.close(),error=>error instanceof AggregateError&&error.errors.some(row=>row.code===code
    &&row.phase===(kind==='before-marker'?'admitted':'browser-teardown')));
  }
 }}finally{http.createServer=originalServer;http.request=originalRequest;}
});
