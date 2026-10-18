'use strict';
// Harmless health/IPC child only: this is not 17-agent, model or database proof.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),http=require('node:http'),net=require('node:net');
const {spawn}=require('node:child_process');
const {createSecureShopAgentHostIpcSpawn}=require('./fixtures/secureShopAgentHostIpcSpawn');
const {waitForChild}=require('./fixtures/fullBackendBootControls');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function health(port){return new Promise((resolve,reject)=>{const req=http.get(`http://127.0.0.1:${port}/health`,res=>{let body='';res.on('data',b=>body+=b);res.on('end',()=>{try{resolve(JSON.parse(body));}catch(e){reject(e);}});});req.on('error',reject);req.setTimeout(500,()=>req.destroy(Error('health deadline')));});}
async function until(predicate){const deadline=Date.now()+4000;while(Date.now()<deadline){if(await predicate())return;await new Promise(r=>setTimeout(r,20));}throw Error('bounded predicate deadline');}
test('unchanged Supervisor starts, restarts and stops exact owned health/IPC children',{timeout:15000},async()=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'ss-supervisor-ipc-'))),source=root+'/source';
 const children=[],revoked=[];let supervisor,adapter,port,reservation;
 try{
 const relative='server/services/secureshop/agentHostSupervisor.js';fs.mkdirSync(path.dirname(source+'/'+relative),{recursive:true});fs.mkdirSync(source+'/agent-host');
 const original=fs.readFileSync(path.resolve(__dirname,'../'+relative));fs.writeFileSync(source+'/'+relative,original);assert.equal(hash(fs.readFileSync(source+'/'+relative)),hash(original));
 fs.writeFileSync(source+'/agent-host/index.js',`
 const http=require('node:http');
 const {createSecureShopEndpointCapabilities:create}=require(${JSON.stringify(require.resolve('./fixtures/secureShopEndpointCapabilities'))});
 const {createEndpointIpcReceiver:receiver}=require(${JSON.stringify(require.resolve('./fixtures/secureShopEndpointIpc'))});
 const registry=create();const ipc=receiver(process,{grant:registry.grant,apply:registry.apply,revokeAll:registry.close});
 const server=http.createServer((req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({ok:true,instanceId:process.env.SS_AGENT_HOST_INSTANCE_ID,marker:process.env.CONTROLLED_MARKER,ipc:!!process.send}));});
 server.listen(Number(process.env.SS_AGENT_HOST_PORT),'127.0.0.1');
 process.on('message',m=>{if(m.kind==='controlled-exit')process.exit(7);});
 process.on('SIGTERM',()=>{ipc.close();server.close();});
 `);
 function freeze(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){const p=path.join(dir,entry.name);entry.isDirectory()?freeze(p):fs.chmodSync(p,0o444);}fs.chmodSync(dir,0o555);}freeze(source);
 reservation=net.createServer();await new Promise((r,j)=>{reservation.once('error',j);reservation.listen(0,'127.0.0.1',r);});port=reservation.address().port;await new Promise(r=>reservation.close(r));
  adapter=createSecureShopAgentHostIpcSpawn({sourceRoot:source,spawnProcess(...args){assert.equal(args[0],process.execPath);assert.deepEqual(args[1],['agent-host/index.js']);assert.equal(args[2].cwd,source);assert.deepEqual(args[2].stdio,['ignore','inherit','inherit','ipc']);assert.equal(args[2].detached,false);const child=spawn(...args);children.push(child);return child;},revokeChild:c=>revoked.push(c.pid)});
  const {AgentHostSupervisor}=require(source+'/'+relative);
  supervisor=new AgentHostSupervisor({port,restartLimit:1,stopTimeoutMs:500,spawnProcess:adapter.spawn,env:{CONTROLLED_MARKER:'unchanged'}});
  await supervisor.start();assert.equal(supervisor.status,'running');
  assert.deepEqual(await health(port),{ok:true,instanceId:supervisor.instanceId,marker:'unchanged',ipc:true});
  const first=supervisor.proc,sender=adapter.senderFor(first);
  const grant={version:1,capability:'a'.repeat(64),scope:{targetId:'10000000-0000-4000-8000-000000000001',launchId:'20000000-0000-4000-8000-000000000001',scenarioId:'30000000-0000-4000-8000-000000000001',generation:0,platformOwnerId:1,platformSessionId:1}};
  await sender.send({...grant,operation:'bootstrap'});
  first.send({kind:'controlled-exit'});await waitForChild(first,{timeoutMs:2000});
  await until(async()=>supervisor.proc!==first&&await health(port).then(v=>v.instanceId===supervisor.instanceId,()=>false));
  assert.equal(supervisor.restartCount,1);assert.notEqual(adapter.senderFor(supervisor.proc),sender);assert.throws(()=>adapter.senderFor(first));
  await adapter.senderFor(supervisor.proc).send({...grant,operation:'bootstrap'});
  assert.equal(children.length,2);assert.ok(revoked.includes(first.pid));assert.deepEqual(await health(port),{ok:true,instanceId:supervisor.instanceId,marker:'unchanged',ipc:true});
  await supervisor.stop();assert.equal(supervisor.status,'stopped');assert.equal(supervisor.proc,null);
 }finally{
  const failures=[];if(reservation?.listening){try{await new Promise((r,j)=>reservation.close(e=>e?j(e):r()));}catch(e){failures.push(e);}}try{await supervisor?.stop();}catch(e){failures.push(e);}try{adapter?.close();}catch(e){failures.push(e);}
  for(const child of children){try{if(child.exitCode===null&&child.signalCode===null){child.kill('SIGTERM');try{await waitForChild(child,{timeoutMs:700});}catch{child.kill('SIGKILL');await waitForChild(child,{timeoutMs:700});}}assert.throws(()=>process.kill(child.pid,0),e=>e.code==='ESRCH');}catch(e){failures.push(e);}}
  if(port)try{await new Promise((resolve,reject)=>{const socket=net.connect({host:'127.0.0.1',port});socket.setTimeout(500,()=>{socket.destroy();reject(Error('port check timeout'));});socket.once('connect',()=>{socket.destroy();reject(Error('listener survived'));});socket.once('error',e=>{socket.destroy();e.code==='ECONNREFUSED'?resolve():reject(e);});});}catch(e){failures.push(e);}
  try{function thaw(dir){fs.chmodSync(dir,0o700);for(const entry of fs.readdirSync(dir,{withFileTypes:true})){if(entry.isDirectory())thaw(path.join(dir,entry.name));}}thaw(root);fs.rmSync(root,{recursive:true,force:true});}catch(e){failures.push(e);}if(failures.length)throw new AggregateError(failures,'owned Supervisor cleanup failed');
 }
});
