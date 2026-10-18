'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {EventEmitter}=require('node:events');
const {createWindowsLabForwardOwner}=require('../scripts/lib/windows-lab-forward-owner');
const dir='C:\\Private State\\workspace',uuid='12345678-1234-4321-abcd-123456789abc';
function request(ports=[18081,18082]){
 const args=['-F','NUL','-i',dir+'\\windows-owned-lab.pem'];
 for(const value of ['BatchMode=yes','IdentitiesOnly=yes','StrictHostKeyChecking=yes','UserKnownHostsFile="'+dir.replace(/\\/g,'/')+'/windows-owned-lab.hosts"','GlobalKnownHostsFile=NUL','HostKeyAlias=dvaia-'+uuid,'ConnectTimeout=10','ServerAliveInterval=15','ServerAliveCountMax=2','ForwardAgent=no','PermitLocalCommand=no','ProxyCommand=none','ProxyJump=none','ControlMaster=no','RequestTTY=no','ExitOnForwardFailure=yes'])args.push('-o',value);
 args.push('-N');for(const port of ports)args.push('-L',`127.0.0.1:${port}:127.0.0.1:8081`);args.push('dvaia@172.22.1.2');
 return{executable:'C:\\Windows\\System32\\OpenSSH\\ssh.exe',args};
}
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function fixture({admission,creation,members,closeFailure=false,spawnFailure=false,...options}={}){
 const calls=[],configs=[],helperFailure=deferred(),child=new EventEmitter();helperFailure.promise.catch(()=>{});
 Object.assign(child,{pid:1234,connected:true,exitCode:null,signalCode:null,stderr:new EventEmitter(),kill(){calls.push('kill-handle');child.exitCode=1;child.connected=false;child.emit('close',1);}});child.stderr.resume=()=>calls.push('discard-stderr');
 const job={failure:helperFailure.promise,async admitGuardian(value){assert.equal(value,child);calls.push('admit');if(admission)await admission.promise;},async members(){calls.push('members');return members||{activeCount:2,pids:[1234,1235]};},async stop(){calls.push('stop-job');child.exitCode=0;child.connected=false;child.emit('close',0);},async close(){calls.push('close-job');if(closeFailure)throw Error('PRIVATE_NATIVE_OUTPUT');}};
 const ownChild=createWindowsLabForwardOwner({platform:'win32',environment:{SystemRoot:'C:\\Windows',PATH:'fixture',PRIVATE:'not-output'},timeoutMs:80,joinMs:80,
  async createJob(value){calls.push('create-job');assert.equal(value.platform,'win32');if(creation)await creation.promise;return job;},
  spawnProcess(command,args,config){calls.push('spawn');configs.push(config);assert.equal(command,process.execPath);assert.equal(args[0],path.resolve(__dirname,'../scripts/owned-child-guardian.js'));assert.equal(args[1],request().executable);assert.deepEqual(JSON.parse(args[2]),['-v',...request().args]);assert.deepEqual(args.slice(3),['plain','direct']);assert.equal(config.shell,false);assert.equal(config.detached,false);assert.deepEqual(config.stdio,['ignore','ignore','pipe','ipc']);if(spawnFailure)throw Error('PRIVATE_NATIVE_OUTPUT');return child;},...options});
 const listener=port=>child.stderr.emit('data',Buffer.from(`debug1: Local forwarding listening on 127.0.0.1 port ${port}.\r\n`));
 const ready=()=>{listener(18081);listener(18082);child.stderr.emit('data',Buffer.from('debug1: Entering interactive session.\r\n'));};
 return{ownChild,child,job,calls,configs,ready,listener,helperFailure};
}
test('all listener markers plus later client loop and live owned job establish readiness, then idempotent drain',async()=>{
 const f=fixture(),pending=f.ownChild(request());await tick();f.ready();const owner=await pending;
 assert.ok(Object.isFrozen(owner));assert.ok(owner.failurePromise instanceof Promise);assert.equal(f.calls.includes('members'),true);
 await Promise.all([owner.stopAndJoin(),owner.stopAndJoin()]);
    assert.equal(f.calls.filter(x=>x==='stop-job').length,1);assert.equal(f.calls.filter(x=>x==='close-job').length,1);assert.equal(f.calls.includes('kill-handle'),false);
 assert.deepEqual(f.configs[0].env,{SystemRoot:'C:\\Windows'});
});
test('spawn and pre-bind listener intent alone cannot establish readiness',async()=>{
 const f=fixture(),pending=f.ownChild(request());const rejected=assert.rejects(pending,{code:'WINDOWS_LAB_FORWARD_DENIED'});await tick();f.listener(18081);f.listener(18082);await rejected;
 assert.deepEqual(f.calls.filter(x=>['stop-job','close-job'].includes(x)),['stop-job','close-job']);
});
test('missing, wrong-host, extra-port and early terminal markers deny and drain without leaking stderr',async()=>{
 for(const output of ['debug1: Entering interactive session.\n','debug1: Local forwarding listening on 127.0.0.1 port 18083.\n','debug1: Local forwarding listening on 0.0.0.0 port 18081.\n','PRIVATE_NATIVE_OUTPUT'.repeat(5000)]){
  const f=fixture(),pending=f.ownChild(request()),rejected=assert.rejects(pending,error=>error.code==='WINDOWS_LAB_FORWARD_DENIED'&&!error.message.includes('PRIVATE_NATIVE_OUTPUT'));await tick();f.child.stderr.emit('data',Buffer.from(output));await rejected;assert.equal(f.calls.includes('close-job'),true);
 }
});
test('unsafe or altered SSH grammar denies before creating any native job',async()=>{
 const variants=[];
 for(const [from,to]of [['StrictHostKeyChecking=yes','StrictHostKeyChecking=no'],['GlobalKnownHostsFile=NUL','GlobalKnownHostsFile=system'],['127.0.0.1:18081:127.0.0.1:8081','0.0.0.0:18081:127.0.0.1:8081'],['ProxyCommand=none','ProxyCommand=cmd.exe'],['UserKnownHostsFile="'+dir.replace(/\\/g,'/')+'/windows-owned-lab.hosts"','UserKnownHostsFile=C:\\foreign\\windows-owned-lab.hosts']]){const r=request();r.args[r.args.indexOf(from)]=to;variants.push(r);}
 const trailing=request();trailing.args.push('remote command');variants.push(trailing);
 variants.push({...request(),executable:'ssh.exe'},request([18081,18081]),{...request(),extra:true});
 for(const value of variants){const f=fixture();await assert.rejects(f.ownChild(value),{code:'WINDOWS_LAB_FORWARD_DENIED'});assert.equal(f.calls.length,0);}
 for(const options of [{platform:'linux'},{environment:{Node_Options:'--require private'}},{environment:{SystemRoot:'C:\\Windows',SYSTEMROOT:'C:\\Other'}},{timeoutMs:0}]){const f=fixture(options);await assert.rejects(f.ownChild(request()),{code:'WINDOWS_LAB_FORWARD_DENIED'});assert.equal(f.calls.length,0);}
});
test('cancellation while helper creation waits closes only its empty owned job without spawning',async()=>{
 const creation=deferred(),controller=new AbortController(),f=fixture({creation,signal:controller.signal}),pending=f.ownChild(request());controller.abort();creation.resolve();await assert.rejects(pending,{code:'WINDOWS_LAB_FORWARD_DENIED'});
 assert.deepEqual(f.calls,['create-job','close-job']);
});
test('cancellation during admission joins it before owned stop and never kills an admitted PID',async()=>{
 const admission=deferred(),controller=new AbortController(),f=fixture({admission,signal:controller.signal}),pending=f.ownChild(request());await tick();controller.abort();await tick();assert.equal(f.calls.includes('stop-job'),false);assert.equal(f.calls.includes('close-job'),false);admission.resolve();await assert.rejects(pending,{code:'WINDOWS_LAB_FORWARD_DENIED'});
 assert.deepEqual(f.calls.filter(x=>['admit','stop-job','close-job','kill-handle'].includes(x)),['admit','stop-job','close-job']);
});
test('cancellation during the live membership request joins it before sending native stop commands',async()=>{
 const members=deferred(),controller=new AbortController(),f=fixture({members:members.promise,signal:controller.signal}),pending=f.ownChild(request());await tick();f.ready();await tick();controller.abort();await tick();assert.equal(f.calls.includes('stop-job'),false);members.resolve({activeCount:2,pids:[1234,1235]});await assert.rejects(pending,{code:'WINDOWS_LAB_FORWARD_DENIED'});assert.equal(f.calls.includes('close-job'),true);
});
test('spawn failure closes empty job; rejected admission joins direct guardian handle before job release',async()=>{
 const f=fixture({spawnFailure:true});await assert.rejects(f.ownChild(request()),{code:'WINDOWS_LAB_FORWARD_DENIED'});assert.equal(f.calls.includes('close-job'),true);
 const admission=deferred(),g=fixture({admission}),pending=g.ownChild(request());await tick();admission.reject(Error('PRIVATE_NATIVE_OUTPUT'));await assert.rejects(pending,{code:'WINDOWS_LAB_FORWARD_DENIED'});
 assert.deepEqual(g.calls.filter(x=>['kill-handle','close-job','stop-job'].includes(x)),['kill-handle','close-job']);
});
test('post-ready helper/workload failure rejects safe lifetime and drains the exact job',async()=>{
 for(const helper of [true,false]){
  const f=fixture(),pending=f.ownChild(request());await tick();f.ready();const owner=await pending,rejected=assert.rejects(owner.failurePromise,{code:'WINDOWS_LAB_FORWARD_DENIED'});
  if(helper)f.helperFailure.reject(Error('PRIVATE_NATIVE_OUTPUT'));else f.child.emit('message',{type:'dvaia-owned-child-outcome',outcome:{type:'exit',code:1}});
  await rejected;await owner.stopAndJoin();assert.equal(f.calls.filter(x=>x==='stop-job').length,1);assert.equal(f.calls.filter(x=>x==='close-job').length,1);
 }
});
test('markers without a live workload or guardian deny, and uncertain native cleanup never returns success',async()=>{
 const f=fixture({members:{activeCount:1,pids:[1234]},closeFailure:true}),pending=f.ownChild(request());await tick();f.ready();await assert.rejects(pending,error=>error.code==='WINDOWS_LAB_FORWARD_DENIED'&&error.cleanupError?.code==='WINDOWS_LAB_FORWARD_CLEANUP_UNPROVED');
});
test('child environment is copied before asynchronous native admission',async()=>{
 const creation=deferred(),environment={SystemRoot:'C:\\Windows',PATH:'original',PG_DATABASE_URL:'PRIVATE_NATIVE_OUTPUT'},f=fixture({creation,environment}),pending=f.ownChild(request());environment.NODE_OPTIONS='--require PRIVATE_NATIVE_OUTPUT';creation.resolve();await tick();f.ready();const owner=await pending;await owner.stopAndJoin();
 assert.equal(f.configs[0].env.NODE_OPTIONS,undefined);assert.equal(f.configs[0].env.PATH,undefined);assert.equal(f.configs[0].env.PG_DATABASE_URL,undefined);assert.equal(f.configs[0].env.SystemRoot,'C:\\Windows');
});
