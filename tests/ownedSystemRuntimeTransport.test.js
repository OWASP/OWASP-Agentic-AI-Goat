'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {EventEmitter}=require('node:events'),{PassThrough}=require('node:stream'),{spawn,spawnSync}=require('node:child_process');
const transport=require('./postgres/ownedSystemRuntimeTransport');
const root=path.resolve(__dirname,'..');
const helperSha=require('node:crypto').createHash('sha256').update(require('node:fs').readFileSync(path.join(__dirname,'postgres/owned_system_private_http_channel.py'))).digest('hex');
const PYTHON='/opt/homebrew/bin/python3';
async function driverBridgeFileFactories(){
 const text=await fs.readFile(path.join(__dirname,'postgres/ownedSystemConfigPhaseDriver.js'),'utf8');
 const lines=text.split('\n').filter(line=>line.startsWith('const makeFile=')||line.startsWith('const makeAppendFile='));
 assert.equal(lines.length,2);
 return new Function('fs','native','path',lines.join('\n')+'\nreturn {makeFile,makeAppendFile};')(fs,native,path);
}
const PYTHON_JOURNAL_BOUNDARY=String.raw`
import sys,json,os,fcntl,hashlib
p=json.load(sys.stdin)
assert hashlib.sha256(p['source'].encode()).hexdigest()==p['sha256']
ns={'__name__':'offline_channel_control','__file__':p['path']}
exec(compile(p['source'],p['path'],'exec'),ns)
class ConstructionBoundary(Exception):pass
def stop_before_construction(*_):raise ConstructionBoundary('OFFLINE_STOP_BEFORE_BRIDGE')
ns['PrivateBridge']=stop_before_construction
try:
 ns['bridge_controller'](p['root'],{}, {'runId':p['runId']},ns['time'].monotonic()+60,3)
 raise AssertionError('unexpected completion')
except Exception as error:
 outcome={'error':str(error),'type':type(error).__name__,'constructorReached':isinstance(error,ConstructionBoundary)}
outcome.update(append=bool(fcntl.fcntl(3,fcntl.F_GETFL)&os.O_APPEND),journalBytes=os.fstat(3).st_size)
print(json.dumps(outcome))
`;
test('real driver bridge FD and Python journal boundary require O_APPEND for both original targets',async()=>{
 const {makeFile,makeAppendFile}=await driverBridgeFileFactories();
 const helper=path.join(__dirname,'postgres/owned_system_private_http_channel.py');
 const source=await fs.readFile(helper,'utf8'),digest=require('node:crypto').createHash('sha256').update(source).digest('hex');
 const directory=await fs.mkdtemp(path.join(root,'tasks/tmp/v24-bridge-journal-contract-'));await fs.chmod(directory,0o700);
 try{for(const target of ['system','policy'])for(const append of [false,true]){
  const name=target+(append?'-append':'-nonappend')+'.journal';
  const fd=await (append?makeAppendFile:makeFile)(directory,name);
  try{
   const result=spawnSync(PYTHON,['-I','-S','-B','-c',PYTHON_JOURNAL_BOUNDARY],{
    cwd:root,stdio:['pipe','pipe','pipe',fd.fd],input:JSON.stringify({source,sha256:digest,path:helper,root,runId:binding().runId}),
    encoding:'utf8',timeout:5000,maxBuffer:65536,env:{PATH:'/usr/bin:/bin',TMPDIR:path.join(root,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'}});
   assert.equal(result.status,0,result.stderr);assert.equal(result.signal,null);assert.equal(result.stderr,'');
   const row=JSON.parse(result.stdout),bytes=await fs.readFile(path.join(directory,name));
   assert.equal(row.append,append);assert.equal(row.constructorReached,append);
   assert.equal(row.error,append?'OFFLINE_STOP_BEFORE_BRIDGE':'SYSTEM_CHANNEL_JOURNAL');
   if(append){assert.deepEqual(JSON.parse(bytes),{version:1,stage:'bridge-starting',runId:binding().runId});assert(row.journalBytes>0);}
   else{assert.equal(bytes.length,0);assert.equal(row.journalBytes,0);}
  }finally{await fd.close();}
 }}finally{await fs.rm(directory,{recursive:true,force:true});}
});
const TRACE_BRIDGE_CONSTRUCTOR=String.raw`
import sys,base64
source=base64.b64decode(sys.argv[1],validate=True).decode('utf-8')
assert 'bridge_controller(' in source
class ConstructionBoundary(Exception):pass
def stop_before_construction(*_):raise ConstructionBoundary('OFFLINE_STOP_BEFORE_BRIDGE')
def trace(frame,event,arg):
 if event=='call' and frame.f_code.co_name=='bridge_controller':
  frame.f_globals['PrivateBridge']=stop_before_construction
 return trace
sys.settrace(trace)
exec(compile(source,'<exact-generated-bridge>','exec'),{})
`;
test('actual emitted bridge and Node parser reach only constructor boundary for both targets and FD variants',async()=>{
 const {makeFile,makeAppendFile}=await driverBridgeFileFactories();
 const directory=await fs.mkdtemp(path.join(root,'tasks/tmp/v24-bridge-parser-contract-'));await fs.chmod(directory,0o700);
 const authority={config:'/offline/ssh_config',socket:'/offline/ssh.sock',configSha256:'a'.repeat(64),limaConfigSha256:'b'.repeat(64),
  socketDevice:1,socketInode:2,masterPid:33,masterBirth:[1,2]};
 try{for(const target of ['original-v24-system','original-v24-policy'])for(const append of [false,true]){
  const b={...binding(),target},stem=(target==='original-v24-policy'?'policy':'system')+(append?'-append':'-driver'),files={};
  try{
   for(const name of ['owner','stdout','stderr','journal']){
    const file=stem+'-'+name+'.jsonl';files[name]=name==='journal'&&append
     ?await makeAppendFile(directory,file):await makeFile(directory,file);
   }
   let launches=0;const launch=(_python,args,settings)=>{
    assert.equal(args[0],'-I');assert.equal(args[4].includes('controller-terminal'),true);launches++;
    return spawn(PYTHON,['-I','-S','-B','-c',TRACE_BRIDGE_CONSTRUCTOR,Buffer.from(args[4]).toString('base64')],settings);
   };
   let failure;
   try{await transport.openOwnedBridge({root,binding:b,authority,python:PYTHON,signal:new AbortController().signal,
    deadline:performance.now()+60000,files,expectedHelperSha256:helperSha},launch);}catch(error){failure=error;}
   assert(failure);assert.equal(launches,1);
   const out=await fs.readFile(path.join(directory,stem+'-stdout.jsonl'),'utf8');
   const frames=out.trim().split('\n').filter(Boolean).map(JSON.parse);
   assert.deepEqual(frames.map(row=>row.stage),['controller','controller-terminal']);
   const journal=await fs.readFile(path.join(directory,stem+'-journal.jsonl'),'utf8');
   const rows=journal.trim().split('\n').filter(Boolean).map(JSON.parse);
   assert.equal(failure.code,'SYSTEM_BRIDGE_RETIREMENT_UNPROVEN');
   assert.deepEqual(rows.map(row=>row.stage),append?['bridge-starting']:[]);
  }finally{for(const file of Object.values(files))await file.close();}
 }}finally{await fs.rm(directory,{recursive:true,force:true});}
});
function binding(){return {version:1,target:'original-v24-system',runId:'a'.repeat(32),imageId:'sha256:'+'b'.repeat(64),
 inputSha256:'c'.repeat(64),daemonId:'d'.repeat(36),physical:{privateDockerHost:'unix:///var/tmp/dvaia-v23-build-'+'a'.repeat(32)+'/fs/docker.sock',
 namespaceInode:'net:[12345]',filesystemIdentity:{device:1,inode:2},daemonProcess:{pid:101,startTicks:'100',exe:'/usr/bin/dockerd'},
 namespaceHolder:{pid:102,startTicks:'101',exe:'/usr/bin/sleep'}}};}
const authority={config:'/repo/ssh_config',socket:'/repo/ssh.sock',configSha256:'a'.repeat(64),limaConfigSha256:'b'.repeat(64),
 socketDevice:1,socketInode:2,masterPid:33,masterBirth:[1,2]};
const plan=()=>({runId:binding().runId,spec:{root,guest:'/var/tmp/dvaia-v23-build-'+binding().runId},captured:{inputSha256:binding().inputSha256},
 helperHashes:{'tests/postgres/owned_system_private_http_channel.py':helperSha}});
test('fixed runtime templates preserve exact source/binding and secrets only in private stdin',()=>{
 const token='z'.repeat(43),op=transport.operation(plan(),binding(),'start',token);
 assert.equal(op.name,'system-runtime-start');assert.deepEqual(JSON.parse(op.input),{token});assert(!op.command.includes(token));
 assert(op.command.includes('system-lease.json'));assert(op.command.includes('SYSTEM_RUNTIME_FULL_COHORT_RESERVE'));
 for(const kind of ['start','inspect','stop']){
  const row=transport.operation(plan(),binding(),kind,kind==='start'?token:undefined);
  const syntax=spawnSync('/bin/sh',['-n'],{input:row.command,encoding:'utf8',timeout:5000,maxBuffer:8192});assert.equal(syntax.status,0,syntax.stderr);
 }
 assert.throws(()=>transport.operation(plan(),binding(),'shell'));
 assert.throws(()=>transport.operation({...plan(),runId:'b'.repeat(32)},binding(),'start',token));
 assert.throws(()=>transport.operation(plan(),binding(),'inspect',token));
});
test('bridge source owns controller identity, duration-derived clock and unchanged original template',()=>{
 const row=transport._internals.bridgeSource(root,binding(),authority,800000);
 assert(row.source.includes('controller-terminal'));assert(row.source.includes('time.monotonic()+800000/1000'));
 assert(row.source.includes('api.group_pids'));assert(!row.source.includes('z'.repeat(43)));
 const compiled=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',"import sys;compile(sys.stdin.read(),'<fixed>','exec')"],
  {input:row.source,encoding:'utf8',timeout:5000,maxBuffer:8192});assert.equal(compiled.status,0,compiled.stderr);
 assert.throws(()=>transport._internals.bridgeSource(root,binding(),authority,900001));
});
test('renderer fixed transport uses distinct slot and existing System cohort rather than renewal',()=>{
 const b={...binding(),target:'original-v24-policy'},p={...plan(),target:'original-v24-system-and-policy',
  slots:{policy:{captured:{inputSha256:b.inputSha256}}}};
 for(const kind of ['start','inspect','stop']){
  const op=transport.operation(p,b,kind);assert.equal(op.name,'policy-runtime-'+kind);
  assert.deepEqual(JSON.parse(op.input),{});
  const syntax=spawnSync('/bin/sh',['-n'],{input:op.command,encoding:'utf8',timeout:5000,maxBuffer:8192});assert.equal(syntax.status,0,syntax.stderr);
 }
 const op=transport.operation(p,b,'start');assert.match(op.command,/POLICY_RUNTIME_COHORT/);
 assert.match(op.command,/runtimeDeadline=runtime_end/);assert.doesNotMatch(op.command,/settings.update\(runtimeDeadline=now\+900/);
 assert.throws(()=>transport.operation(plan(),b,'start'));
 assert.throws(()=>transport.operation(p,b,'start','x'.repeat(43)));
 assert.throws(()=>transport.operation({...p,slots:{policy:{captured:{inputSha256:'f'.repeat(64)}}}},b,'start'));
 const row={stage:'terminal',version:1,runId:b.runId,target:b.target,channelIds:[],localRetired:true,
  retirementUnproven:false,remoteRetired:false,builderReleaseAllowed:false,failures:[]};
 assert.deepEqual(transport._internals.localTerminal(row,b),row);
 const {target,...system}=row;assert.throws(()=>transport._internals.localTerminal(system,b));
 assert.throws(()=>transport._internals.localTerminal(row,binding()));
});
test('diagnostic bridge capacity is distinct while original operation and terminal identities stay closed',()=>{
 const b={...binding(),target:'original-v03-diagnostic'};
 const row=transport._internals.bridgeSource(root,b,authority,1210000);
 assert(row.source.includes('time.monotonic()+1210000/1000'));
 assert.throws(()=>transport._internals.bridgeSource(root,b,authority,1210001));
 for(const target of ['original-v24-system','original-v24-policy'])
  assert.throws(()=>transport._internals.bridgeSource(root,{...binding(),target},authority,900001));
 for(const operation of ['start','inspect','stop'])
  assert.throws(()=>transport.operation(plan(),b,operation),/DIAGNOSTIC_DISTINCT_RUNTIME_REQUIRED/);
 const terminal={stage:'terminal',version:1,runId:b.runId,target:b.target,channelIds:[],localRetired:true,
  retirementUnproven:false,remoteRetired:false,builderReleaseAllowed:false,failures:[]};
 assert.equal(transport._internals.localTerminal(terminal,b),terminal);
 for(const target of ['original-v24-system','original-v24-policy',undefined])
  assert.throws(()=>transport._internals.localTerminal({...terminal,target},b));
});
test('all actual System/renderer operation commands fit the unchanged SSH shell argument bound',()=>{
 const commands=[];
 for(const target of ['original-v24-system','original-v24-policy']){
  const b={...binding(),target},p={...plan(),target:'original-v24-system-and-policy',slots:{policy:{captured:{inputSha256:b.inputSha256}}}};
  for(const kind of ['start','inspect','stop'])commands.push(transport.operation(p,b,kind,kind==='start'&&target==='original-v24-system'?'z'.repeat(43):undefined).command);
 }
 const code=`import sys,json,shlex\ncommands=json.load(sys.stdin)\nlengths=[len(shlex.join(['sudo','-n','timeout','--signal=TERM','--kill-after=10','150','/bin/sh','-c',command,'owned-system-build','/var/tmp/dvaia-v23-build-'+('a'*32),'a'*32]).encode())+1 for command in commands]\nassert max(lengths)<131072,lengths\nprint(json.dumps(lengths))`;
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',code],{input:JSON.stringify(commands),encoding:'utf8',timeout:5000,maxBuffer:8192});
 assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stdout).length,6);
});
function boundedChildOutcome(result,durationMs,inputBytes){
 const code=result.error?.code;
 return {status:result.status,signal:result.signal,pid:result.pid,durationMs,inputBytes,
  errorCode:code?(['ETIMEDOUT','ENOENT','EACCES','EPERM','ENOBUFS'].includes(code)?code:'OTHER'):null,
  stdoutBytes:Buffer.byteLength(result.stdout||''),stderrBytes:Buffer.byteLength(result.stderr||'')};
}
test('offline child failure diagnostics retain timeout and termination fields without raw payloads',()=>{
 const result={status:null,signal:'SIGTERM',pid:99,error:{code:'ETIMEDOUT',message:'private text'},stdout:'private out',stderr:'private err'};
 const report=boundedChildOutcome(result,5003,123);
 assert.deepEqual(report,{status:null,signal:'SIGTERM',pid:99,durationMs:5003,inputBytes:123,
  errorCode:'ETIMEDOUT',stdoutBytes:11,stderrBytes:11});
 assert(!JSON.stringify(report).includes('private'));
 assert.equal(boundedChildOutcome({...result,error:{code:'private'}},1,1).errorCode,'OTHER');
});
test('exact emitted Python controller frames terminate with numeric LF rather than literal escape bytes',()=>{
 const row=transport._internals.bridgeSource(root,binding(),authority,800000);
 const program=`import ast,json,sys,types
tree=ast.parse(sys.stdin.read())
statements=[n for n in ast.walk(tree) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call)
 and isinstance(n.value.func,ast.Attribute) and isinstance(n.value.func.value,ast.Name)
 and n.value.func.value.id=='os' and n.value.func.attr=='write' and isinstance(n.value.args[0],ast.Constant) and n.value.args[0].value==1]
assert len(statements)==2
captured=[]
scope={'os':types.SimpleNamespace(write=lambda fd,b:captured.append(b)), 'json':json,
 'identity':{'pid':99,'birth':[1,2]},'absent':True}
for statement in statements:exec(compile(ast.Module(body=[statement],type_ignores=[]),'<exact emitted frame>','exec'),scope)
print(json.dumps([b.hex() for b in captured]))
`;
 const began=performance.now();
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',program],
  {input:row.source,encoding:'utf8',timeout:5000,maxBuffer:8192});
 assert.equal(result.status,0,JSON.stringify(boundedChildOutcome(result,performance.now()-began,Buffer.byteLength(row.source))));
 const frames=JSON.parse(result.stdout).map(hex=>Buffer.from(hex,'hex'));
 assert.deepEqual(frames.map(b=>b.at(-1)),[10,10]);
 assert.deepEqual(frames.map(b=>JSON.parse(b.toString()).stage),['controller','controller-terminal']);
 assert.equal(Buffer.concat(frames).toString().split('\n').filter(Boolean).length,2);
});
async function control(fault=''){
 const source=await fs.readFile(path.join(__dirname,'postgres/ownedSystemRuntimeTransport.js'),'utf8');
 const timers=[],records=new Map(),events=[],module={exports:{}};let ownerWrites=0;
 const fakeFs={writeSync(fd,b,offset,length){if(fd===3)ownerWrites++;
  if(fault==='record'&&fd===3||fault.startsWith('post-record')&&fd===3&&ownerWrites===2)throw Error('fsync');
  records.set(fd,Buffer.concat([records.get(fd)||Buffer.alloc(0),b.subarray(offset,offset+length)]));return length;},fsyncSync(){}};
 const timeout=(fn,ms)=>{const t={fn,ms,cleared:false};timers.push(t);return t;};
 vm.runInNewContext('(function(require,module,exports){'+source+'\n})',{Buffer,performance:{now:()=>100},setTimeout:timeout,
  clearTimeout:t=>{if(t)t.cleared=true;},process})(id=>id==='node:fs'?fakeFs:require(id.startsWith('./ownedSystem')?'./postgres/'+id.slice(2):id),module,module.exports);
 const c=new AbortController();if(fault==='preabort')c.abort(Error('abort'));
 let child;
 const identity={pid:99,birth:[1,2]},row={stage:'terminal',version:1,runId:binding().runId,channelIds:[],localRetired:true,
  retirementUnproven:false,remoteRetired:false,builderReleaseAllowed:false,failures:fault==='semantic'?['ChannelFailure']:[]};
 const launch=(file,args,options)=>{
  events.push({file,args,options});child=new EventEmitter();Object.assign(child,{pid:99,exitCode:null,signalCode:null,
   stdin:new PassThrough(),stdout:new PassThrough(),stderr:new PassThrough(),kill(sig){events.push(sig);}});
  const send=v=>child.stdout.write(JSON.stringify(v)+'\n');
  child.stdin.on('finish',()=>{if(fault==='no-close'){child.exitCode=0;return;}
   if(fault==='post-record-error')queueMicrotask(()=>child.stdin.emit('error',Object.assign(Error('pipe late'),{code:'EPIPE'})));
   if(fault==='post-record-early-close'){queueMicrotask(()=>{child.exitCode=1;child.emit('close',1,null);});return;}
   queueMicrotask(()=>{send(fault==='wrong-run'?{...row,runId:'f'.repeat(32)}:row);
    send({stage:'controller-terminal',identity,descendantsAbsent:fault!=='descendants'});
    child.exitCode=fault==='semantic'?1:0;child.emit('close',child.exitCode,null);});});
  queueMicrotask(()=>{send({stage:'controller',identity});send({stage:'ready',version:1,port:18090});});return child;
 };
 const options={root,binding:binding(),authority,python:'/fixed/python',signal:c.signal,deadline:800100,
  expectedHelperSha256:helperSha,
  files:{owner:{fd:3},journal:{fd:4},stdout:{fd:5},stderr:{fd:6}}};
 const pending=module.exports.openOwnedBridge(options,launch);
 return {pending,events,records,timers,get child(){return child;}};
}
test('actual Node bridge owner persists intent, owns fixed child, and joins terminal before returning local proof',async()=>{
 const c=await control(),handle=await c.pending;assert.equal(handle.port,18090);
 const result=await handle.close();assert.equal(result.localRetired,true);assert.equal(result.remoteRetired,false);
 assert.equal(result.builderReleaseAllowed,false);assert.equal(result.channelIds.length,0);
 assert.equal(c.child.stdout.destroyed,true);assert.equal(c.child.stdin.destroyed,true);assert.equal(c.child.stderr.destroyed,true);
 const rows=c.records.get(3).toString().trim().split('\n').map(v=>JSON.parse(v));assert.equal(rows[0].stage,'owned-bridge-intent');
 assert.equal(rows.at(-1).stage,'owned-bridge-reaped');assert.equal(c.events[0].options.detached,true);
 assert.deepEqual(Array.from(c.events[0].options.stdio),['pipe','pipe','pipe',4]);assert(c.timers.every(t=>t.cleared));
});
test('bridge transport failure is retained separately from verified local retirement',async()=>{
 const c=await control('semantic'),handle=await c.pending,result=await handle.close();
 assert.equal(result.localRetired,true);assert.deepEqual(Array.from(result.failures),['ChannelFailure']);
});
test('predispatch abort or durable recording failure launches no controller',async()=>{
 for(const fault of ['preabort','record']){const c=await control(fault);await assert.rejects(c.pending);assert.equal(c.events.length,0);}
});
test('postspawn recording failure owns async EPIPE and early close without accepting late ready',async()=>{
 for(const fault of ['post-record-error','post-record-early-close']){
  const c=await control(fault);let accepted=false;
  const failure=await c.pending.then(()=>{accepted=true;return null;},e=>e);
  assert.equal(accepted,false);assert.equal(failure.message,'fsync');assert.equal(failure.retirementUnproven,true);
  assert.equal(c.events.filter(v=>typeof v==='object').length,1);
  assert(c.timers.every(t=>t.cleared));
  for(const stream of ['stdin','stdout','stderr'])assert.equal(c.child[stream].destroyed,true);
  assert.equal(c.child.listenerCount('close'),0);
 }
});
test('exited controller without close is bounded and never signaled; retained endpoints are destroyed',async()=>{
 const c=await control('no-close'),handle=await c.pending,closing=handle.close().then(()=>null,e=>e);
 await Promise.resolve();const join=c.timers.find(t=>t.ms===26000);assert(join);join.fn();
 const failure=await closing;assert.equal(failure.retirementUnproven,true);
 assert.equal(c.events.filter(v=>typeof v==='string').length,0);assert.equal(c.child.stdout.destroyed,true);
});
test('wrong run or unproven descendants never become cleanup authority',async()=>{
 for(const fault of ['wrong-run','descendants']){const c=await control(fault),handle=await c.pending;await assert.rejects(handle.close(),e=>e.retirementUnproven===true);}
});
