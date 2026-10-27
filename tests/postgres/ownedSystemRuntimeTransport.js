'use strict';
// Fixed System runtime/channel templates only. The driver owns all state and
// source admission; this module neither mints an image capability nor opens the
// public qualification gate.
const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const {spawn}=require('node:child_process');
const consumer=require('./ownedSystemPrivateHttpConsumer')._internals;
const lease=require('./ownedSystemBoundedDerivation')._internals.LEASE_PY;
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
const quote=x=>"'"+x.replace(/'/g,"'\\''")+"'";
const same=(a,b)=>require('node:util').isDeepStrictEqual(a,b);
function operation(plan,binding,kind,token,channelIds=[]){
 if(!['start','inspect','stop'].includes(kind))throw fail('SYSTEM_RUNTIME_OPERATION');
 binding=consumer.validateBinding(binding);
 if(binding.target==='original-v03-diagnostic')throw fail('DIAGNOSTIC_DISTINCT_RUNTIME_REQUIRED');
 const policy=binding.target==='original-v24-policy',slot=policy?'policy':'system';
 if(binding.runId!==plan.runId||binding.inputSha256!==(policy?plan.slots?.policy?.captured?.inputSha256:plan.captured.inputSha256)
  ||policy&&plan.target!=='original-v24-system-and-policy')throw fail('SYSTEM_RUNTIME_BINDING');
 if(kind==='start'&&(policy?token!==undefined:typeof token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(token)))throw fail('SYSTEM_RUNTIME_TOKEN');
 if(kind!=='start'&&token!==undefined)throw fail('SYSTEM_RUNTIME_TOKEN');
 const template=consumer.operationProgram(binding,kind,channelIds);
 if(template.helperSha256!==plan.helperHashes?.['tests/postgres/owned_system_private_http_channel.py'])throw fail('SYSTEM_RUNTIME_SOURCE');
 const prefix=`import os,sys,json,time,io,contextlib,select
ready,_,_=select.select([0],[],[],5)
assert ready, 'SYSTEM_RUNTIME_PRIVATE_INPUT'
raw=os.read(0,4097);assert len(raw)<=4096
payload=json.loads(raw)
assert type(payload) is dict and set(payload)==${kind==='start'&&!policy?"{'token'}":"set()"}
saved_argv=sys.argv
sys.argv=['system-lease',${JSON.stringify(plan.spec.guest)},${JSON.stringify(plan.runId)},${JSON.stringify(kind==='stop'?'read':'active')}]
lease_scope={}
with contextlib.redirect_stdout(io.StringIO()):exec(${JSON.stringify(lease)},lease_scope)
sys.argv=saved_argv
now=time.monotonic()
settings={'deadline':now+120}
${kind==='start'&&policy?`# Renderer joins the original System cohort; it cannot renew its900s clock.
import stat,math
fd=os.open(${JSON.stringify(plan.spec.guest+'/fs/system-runtime.deadline')},os.O_RDONLY|os.O_NOFOLLOW)
try:
 info=os.fstat(fd);assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=64
 raw=os.read(fd,65);assert len(raw)==info.st_size
 runtime_end=float(raw)
finally:os.close(fd)
assert math.isfinite(runtime_end) and now<runtime_end<=now+900 and runtime_end+936<=lease_scope['row']['expiresAtMs']/1000, 'POLICY_RUNTIME_COHORT'
settings.update(runtimeDeadline=runtime_end,deadline=min(settings['deadline'],runtime_end))`
:kind==='start'?"expiry=lease_scope['row']['expiresAtMs']/1000\nassert now+900+936<=expiry, 'SYSTEM_RUNTIME_FULL_COHORT_RESERVE'\nsettings.update(runtimeDeadline=now+900,token=payload['token'])":kind==='inspect'?"fd=os.open("+JSON.stringify(plan.spec.guest+'/fs/'+slot+'-runtime.deadline')+",os.O_RDONLY|os.O_NOFOLLOW)\ntry:runtime_end=float(os.read(fd,64))\nfinally:os.close(fd)\nassert now<runtime_end, 'SYSTEM_RUNTIME_EXPIRED'\nsettings['deadline']=min(settings['deadline'],runtime_end)":""}
r,w=os.pipe()
try:
 data=json.dumps(settings,separators=(',',':')).encode();assert os.write(w,data)==len(data)
finally:os.close(w)
try:os.dup2(r,0)
finally:os.close(r)
`;
 const source=prefix+template.source;
 return Object.freeze({name:slot+'-runtime-'+kind,command:'/usr/bin/python3 -I -S -B -c '+quote(source),
  input:Buffer.from(JSON.stringify(kind==='start'&&!policy?{token}:{})),sourceSha256:sha(source),helperSha256:template.helperSha256});
}
function bridgeSource(root,binding,authority,remainingMs){
 binding=consumer.validateBinding(binding);
 const limit=binding.target==='original-v03-diagnostic'?1210000:900000;
 if(!Number.isInteger(remainingMs)||remainingMs<1||remainingMs>limit)throw fail('SYSTEM_BRIDGE_DEADLINE');
 const template=consumer.bridgeProgram(binding,authority);
 // Python derives its own clock from a duration. The Node owner independently
 // enforces its original absolute deadline and EOF triggers immediate shutdown.
 const prefix=`import sys,time,os,json,importlib.util,hashlib
root=${JSON.stringify(root)}
p=root+'/tests/postgres/darwin_process_inventory.py'
assert hashlib.sha256(open(p,'rb').read()).hexdigest()=='93976fc710fbd56eeabddcd01927ef28c4e4567748c0b6004d1552d60b777ba9'
s=importlib.util.spec_from_file_location('system_bridge_inventory',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
api=m.LibProc();own=api.identity(os.getpid())
assert own is not None and own.pgid==os.getpid() and own.uid==os.getuid() and own.ruid==os.getuid()
identity={'pid':os.getpid(),'birth':[own.start_sec,own.start_usec]}
os.write(1,(json.dumps({'stage':'controller','identity':identity},separators=(',',':'))+'\\n').encode())
sys.argv=['system-bridge',str(time.monotonic()+${remainingMs}/1000)]
failure=None
try:
 exec(${JSON.stringify(template.source)})
except BaseException as error:failure=error
finally:
 try:
  current=api.identity(os.getpid())
  absent=current is not None and [current.start_sec,current.start_usec]==identity['birth'] and api.group_pids(os.getpid())==[os.getpid()]
 except BaseException:absent=False
 os.write(1,(json.dumps({'stage':'controller-terminal','identity':identity,'descendantsAbsent':absent},separators=(',',':'))+'\\n').encode())
if failure or not absent:sys.exit(1)
`;
 return Object.freeze({source:prefix,sourceSha256:sha(prefix),helperSha256:template.helperSha256});
}
function localTerminal(row,binding){
 const tagged=['original-v24-policy','original-v03-diagnostic'].includes(binding.target);
 const names=('stage,version,runId,channelIds,localRetired,retirementUnproven,remoteRetired,builderReleaseAllowed,failures'+(tagged?',target':'')).split(',').sort();
 if(!row||!same(Object.keys(row).sort(),names)||row.stage!=='terminal'||row.version!==1||row.runId!==binding.runId
  ||!Array.isArray(row.channelIds)||row.channelIds.length>64||new Set(row.channelIds).size!==row.channelIds.length
  ||row.channelIds.some(v=>typeof v!=='string'||!/^[a-f0-9]{32}$/.test(v))
  ||typeof row.localRetired!=='boolean'||typeof row.retirementUnproven!=='boolean'
  ||row.remoteRetired!==false||row.builderReleaseAllowed!==false||!Array.isArray(row.failures)
  ||row.failures.some(v=>typeof v!=='string'||v.length>100)||tagged&&row.target!==binding.target)throw fail('SYSTEM_BRIDGE_TERMINAL');
 return row;
}
async function openOwnedBridge(options,launch=spawn){
 const {root,binding,authority,python,signal,deadline,files}=options;
 signal.throwIfAborted();const remaining=Math.floor(deadline-performance.now());
 const program=bridgeSource(root,binding,authority,remaining);
 if(program.helperSha256!==options.expectedHelperSha256)throw fail('SYSTEM_BRIDGE_SOURCE');
 let child,identity,terminal,proof,port,bytes=0,stderrBytes=0,pending='',primary,settled=false,stopping=false;
 let timer,startTimer,termTimer,killTimer,joinTimer,resolveReady,rejectReady,resolveDone,rejectDone;
 const ready=new Promise((yes,no)=>{resolveReady=yes;rejectReady=no;});
 const done=new Promise((yes,no)=>{resolveDone=yes;rejectDone=no;});void done.catch(()=>{});
 const write=(fd,b)=>{let n=0;while(n<b.length){const wrote=fs.writeSync(fd,b,n,b.length-n);if(!wrote)throw fail('SYSTEM_BRIDGE_RECORD');n+=wrote;}fs.fsyncSync(fd);};
 const record=row=>write(files.owner.fd,Buffer.from(JSON.stringify(row)+'\n'));
 const detach=()=>{
  for(const t of [timer,startTimer,termTimer,killTimer,joinTimer])clearTimeout(t);
  signal.removeEventListener('abort',abort);
  child?.removeListener('close',closed);
  for(const name of ['stdin','stdout','stderr'])if(child?.[name])try{
   child[name].removeAllListeners('data');child[name].destroy();
  }catch{primary ||= fail('SYSTEM_BRIDGE_PIPE_CLOSE');primary.retirementUnproven=true;}
 };
 const finish=(error,result)=>{
  if(settled)return;settled=true;primary ||= error;detach();
  if(primary){primary.retirementUnproven=true;rejectReady(primary);rejectDone(primary);}
  else{if(!port)rejectReady(fail('SYSTEM_BRIDGE_NO_READY'));resolveDone(result);}
 };
 const stop=reason=>{
  if(settled)return;if(reason)primary ||= reason;
  if(stopping)return;stopping=true;
  try{child.stdin.end('S');}catch(e){primary ||= e;}
  const signalChild=s=>{if(child.exitCode===null&&child.signalCode===null)try{child.kill(s);}catch(e){primary ||= e;}};
  // The owned bridge closes channels (5s), runs bounded mux postflight (5s
  // plus5s retirement), then writes terminal. This20s cooperative grace is
  // charged INSIDE the producer's single600s cleanup window, not a new lease.
  termTimer=setTimeout(()=>signalChild('SIGTERM'),20000);killTimer=setTimeout(()=>signalChild('SIGKILL'),24000);
  joinTimer=setTimeout(()=>finish(fail('SYSTEM_BRIDGE_JOIN_DEBT')),26000);
 };
 const abort=()=>stop(fail('SYSTEM_BRIDGE_INTERRUPTED'));
 const frame=row=>{
  if(row.stage==='controller'){
   if(identity||!same(Object.keys(row).sort(),['identity','stage'])||row.identity?.pid!==child.pid
    ||!same(Object.keys(row.identity).sort(),['birth','pid'])||!Array.isArray(row.identity.birth)
    ||row.identity.birth.length!==2||row.identity.birth.some(v=>!Number.isSafeInteger(v)||v<0))throw fail('SYSTEM_BRIDGE_IDENTITY');
   identity=row.identity;
  }else if(row.stage==='ready'){
   if(stopping||primary)throw fail('SYSTEM_BRIDGE_READY_AFTER_STOP');
   if(!identity||port||terminal||!same(Object.keys(row).sort(),['port','stage','version'])||row.version!==1
    ||!Number.isInteger(row.port)||row.port<1024||row.port>65535)throw fail('SYSTEM_BRIDGE_READY');
   port=row.port;clearTimeout(startTimer);resolveReady();
  }else if(row.stage==='terminal'){
   if(!identity||terminal)throw fail('SYSTEM_BRIDGE_TERMINAL');terminal=localTerminal(row,binding);
  }else if(row.stage==='controller-terminal'){
   if(!identity||proof||!same(Object.keys(row).sort(),['descendantsAbsent','identity','stage'])
    ||!same(row.identity,identity)||row.descendantsAbsent!==true)throw fail('SYSTEM_BRIDGE_DESCENDANTS');proof=row;
  }else throw fail('SYSTEM_BRIDGE_FRAME');
 };
 const closed=(code,termination)=>{
  try{
   if(pending||!identity||!proof||!terminal||terminal.localRetired!==true||terminal.retirementUnproven!==false
    ||termination||![0,1].includes(code))throw fail('SYSTEM_BRIDGE_RETIREMENT_UNPROVEN');
   const {stage,...result}=terminal;
   // Nonzero exit is preserved as transport failure, not erased by absence.
   if(code!==0&&!result.failures.length)result.failures.push('SYSTEM_BRIDGE_CONTROLLER_FAILED');
   record({stage:'owned-bridge-reaped',identity,code,terminal:result});finish(null,Object.freeze(result));
  }catch(e){finish(e);}
 };
 try{
  record({stage:'owned-bridge-intent',runId:binding.runId,sourceSha256:program.sourceSha256,remainingMs:remaining});
  signal.throwIfAborted();
  child=launch(python,['-I','-S','-B','-c',program.source],{cwd:root,detached:true,
   stdio:['pipe','pipe','pipe',files.journal.fd],env:{PATH:'/usr/bin:/bin',HOME:root,TMPDIR:path.join(root,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'}});
  // Once Popen succeeds, every fallible step (including durable birth logging)
  // must already have pipe errors and actual close under owned retirement.
  child.on('error',stop);for(const name of ['stdin','stdout','stderr'])child[name].on('error',stop);
  child.stdout.on('data',b=>{try{
   bytes+=b.length;if(bytes>65536)throw fail('SYSTEM_BRIDGE_OUTPUT_BOUND');write(files.stdout.fd,b);pending+=b.toString('utf8');
   while(pending.includes('\n')){const i=pending.indexOf('\n'),line=pending.slice(0,i);pending=pending.slice(i+1);frame(JSON.parse(line));}
   if(Buffer.byteLength(pending)>16384)throw fail('SYSTEM_BRIDGE_FRAME_BOUND');
  }catch(e){stop(e);}});
  child.stderr.on('data',b=>{try{stderrBytes+=b.length;if(stderrBytes>2097152)throw fail('SYSTEM_BRIDGE_OUTPUT_BOUND');write(files.stderr.fd,b);}catch(e){stop(e);}});
  child.once('close',closed);
  timer=setTimeout(abort,Math.max(0,deadline-performance.now()));startTimer=setTimeout(()=>stop(fail('SYSTEM_BRIDGE_READY_TIMEOUT')),10000);
  signal.addEventListener('abort',abort,{once:true});if(signal.aborted)abort();
  record({stage:'owned-bridge-spawn',pid:child.pid});
 }catch(e){if(child)stop(e);else finish(e);}
 try{await ready;}catch(e){await done.catch(()=>{});throw e;}
 return Object.freeze({port,async close(){stop();return done;},get settled(){return settled;}});
}
module.exports={operation,openOwnedBridge,_internals:{bridgeSource,localTerminal}};
