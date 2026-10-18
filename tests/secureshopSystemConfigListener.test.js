'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),net=require('node:net'),{EventEmitter}=require('node:events'),{spawnSync}=require('node:child_process');
const {createSystemConfigHttpListener,runSystemConfigListener}=require('../sidecars/sandbox-runner/owned-system/http-listener');
const {createSecureShopSystemConfigClient}=require('../server/services/secureshopSystemConfigClient');
const {VERSION,ISOLATION,requestDigest,hash}=require('../sidecars/sandbox-runner/owned-system/contract');
const token='z'.repeat(43),request={operationId:'11111111-1111-4111-8111-111111111111',path:'....//.env'};
function receipt(req){const content='controlled';return {version:VERSION,isolation:ISOLATION,operationId:req.operationId,requestSha256:requestDigest(req),status:'completed',exitCode:0,timedOut:false,truncated:false,drained:true,readResult:{ok:true,input:req.path,sanitized:'../.env',targetPath:'/app/.env',size:Buffer.byteLength(content),content,contentSha256:hash(content)}};}
const options=executor=>({enabled:true,token,host:'127.0.0.1',port:0,executor});
test('explicit enable, token and bind settings are required before executor readiness',()=>{
 let probes=0;const base=options({assertReady(){probes++;},read(){}});
 for(const patch of [{enabled:false},{enabled:'true'},{token:'bad'},{host:'private.example.invalid'},{host:undefined},{port:-1},{port:65536},{maxConcurrent:0}])assert.throws(()=>createSystemConfigHttpListener({...base,...patch}),/SYSTEM_LISTENER_/);
 assert.equal(probes,0);
});
test('actual synchronous readiness must pass before binding and raw failures stay private',async()=>{
 for(const assertReady of [()=>{throw Error('/private/secret '+token);},()=>Promise.reject(Error('private'))]){
  const listener=createSystemConfigHttpListener(options({assertReady,read(){throw Error('not reached');}}));
  await assert.rejects(listener.start(),e=>e.code==='SYSTEM_LISTENER_NOT_READY'&&!e.message.includes('private'));
  assert.equal(listener.address(),null);await listener.close();
 }
});
test('real listener/client round trip preserves traversal and closes idempotently',async()=>{
 let probes=0,calls=0;const listener=createSystemConfigHttpListener(options({assertReady(){probes++;},async read(req){calls++;return receipt(req);}}));
 try{const address=await listener.start();assert.deepEqual(await listener.start(),address);
  const client=createSecureShopSystemConfigClient({baseURL:`http://127.0.0.1:${address.port}`,token});assert.equal((await client.read(request)).readResult.content,'controlled');assert.equal(calls,1);assert.equal(probes,3);
 }finally{await listener.close();await listener.close();}assert.equal(listener.address(),null);await assert.rejects(listener.start(),{code:'SYSTEM_LISTENER_CLOSED'});
});
test('shutdown aborts and joins active execution before resolving listener close',async()=>{
 let started,drained=false;const entered=new Promise(r=>started=r);
 const listener=createSystemConfigHttpListener(options({assertReady(){},read(_req,{signal}){started();return new Promise((resolve,reject)=>signal.addEventListener('abort',()=>setTimeout(()=>{drained=true;reject(signal.reason);},20),{once:true}));}}));
 const address=await listener.start();
 const pending=fetch(`http://127.0.0.1:${address.port}/secureshop/system/config-read`,{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify(request)}).then(async r=>{await r.arrayBuffer();},()=>{});
 await entered;await listener.close();assert.equal(drained,true);await pending;assert.equal(listener.address(),null);
});
test('idle partial-header socket is destroyed on close and excessive headers are rejected',async t=>{
 const listener=createSystemConfigHttpListener(options({assertReady(){},read(){throw Error('not reached');}}));const address=await listener.start();t.after(()=>listener.close());
 const status=await new Promise((resolve,reject)=>{const socket=net.connect(address.port,'127.0.0.1',()=>{socket.write('GET /secureshop/system/health HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer '+token+'\r\n'+Array.from({length:40},(_,i)=>`X-${i}: a\r\n`).join('')+'\r\n');});socket.on('error',reject);let data='';socket.on('data',x=>data+=x);socket.on('end',()=>resolve(data.split('\r\n')[0]));});assert.match(status,/431/);
 const socket=net.connect(address.port,'127.0.0.1');socket.on('error',()=>{});await new Promise(r=>socket.once('connect',r));socket.write('GET / HTTP/1.1\r\n');const closed=new Promise(r=>socket.once('close',r));await listener.close();await closed;
});
test('CLI lifecycle installs both signals and removes handlers after joined close without logging secrets',async()=>{
 for(const signal of ['SIGTERM','SIGINT']){
  const signals=new EventEmitter(),log=[];let listener,closed=false;
  const run=runSystemConfigListener({env:{SECURESHOP_SYSTEM_CONFIG_HTTP_ENABLED:'true',SECURESHOP_SYSTEM_CONFIG_TOKEN:token,SECURESHOP_SYSTEM_CONFIG_HOST:'127.0.0.1',SECURESHOP_SYSTEM_CONFIG_PORT:'8091'},signals,
   createListener:()=>{listener=createSystemConfigHttpListener(options({assertReady(){},read:async req=>receipt(req)}));return {start:listener.start,close:async()=>{await listener.close();closed=true;}};},write:text=>{log.push(text);if(text.includes('READY'))signals.emit(signal);}});
  assert.equal(await run,0);assert.equal(closed,true);assert.equal(listener.address(),null);assert.deepEqual(log,['SYSTEM_LISTENER_READY\n','SYSTEM_LISTENER_CLOSED\n']);assert.equal(signals.listenerCount(signal),0);
 }
});
test('standalone CLI fails closed without activation and never logs environment secrets',()=>{
 const out=spawnSync(process.execPath,['sidecars/sandbox-runner/owned-system/http-listener.js'],{env:{PATH:process.env.PATH,SECURESHOP_SYSTEM_CONFIG_TOKEN:token},encoding:'utf8',timeout:5000});assert.equal(out.status,1);assert.equal(out.stdout,'SYSTEM_LISTENER_FAILED\n');assert.equal(out.stderr,'');assert.equal((out.stdout+out.stderr).includes(token),false);
});
