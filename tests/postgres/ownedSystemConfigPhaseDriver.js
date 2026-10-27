'use strict';
// Fixed transport for canonical System plans. No image capability is minted.
// Import performs no I/O, process creation or native admission.
const fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path');
const crypto=require('node:crypto'),{spawn}=require('node:child_process');
const adapter=require('./ownedSystemConfigBuildAdapter');
const transport=require('./ownedSystemRuntimeTransport');
const consumer=require('./ownedSystemPrivateHttpConsumer')._internals;
const checkInventory=require('./ownedMcpBoundedBuild')._internals.checkInventory;
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const error=code=>Object.assign(new Error(code),{code});
const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
const unstartedSettlements=new WeakMap();
function consumeUnstartedSettlement(runtime,owner,window){
 const consume=unstartedSettlements.get(runtime);return consume?consume(owner,window):false;
}
const PYTHON='/opt/homebrew/bin/python3';
const DEPS=Object.freeze({
 darwin_process_inventory:'93976fc710fbd56eeabddcd01927ef28c4e4567748c0b6004d1552d60b777ba9',
 owned_mcp_mux_relay:'345ab0b2d82a71e678759a4ff42386e341f1f036c0ae1edcab4e21497619e253',
});
const NORMAL=Object.freeze(['inventory','preflight','prepare','namespace','relayStart','daemonStart','inspect',
 'metadataFetch','startArtifacts','closureEvidence','inspect','build','image','retireArtifacts','closureEvidence','inspect','handoff']);
const CLEANUP=Object.freeze(['retireArtifacts','closureEvidence','stop','evidence','retainedExport','cleanup','inventory']);
const RUNTIME=Object.freeze(['system-runtime-start','system-runtime-inspect','system-runtime-stop']);
const PAIR_RUNTIME=Object.freeze([...RUNTIME,'policy-runtime-start','policy-runtime-inspect','policy-runtime-stop']);
const MAX_OUTPUT=2*1024**2,MAX_ARCHIVE=145*1024**2,MAX_INPUT=17*1024**2;
const SOURCE="import os,sys,json,stat,time,signal,selectors,subprocess,hashlib,importlib.util,shlex\nCANCELLED=False\ndef require(ok,code):\n if not ok:raise RuntimeError(code)\ndef load(name,digest,root):\n p=root+'/tests/postgres/'+name+'.py'\n require(os.path.realpath(p)==p,'SOURCE_PATH')\n with open(p,'rb') as f:s=os.fstat(f.fileno());b=f.read(1048577)\n require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and len(b)<=1048576 and hashlib.sha256(b).hexdigest()==digest,'SOURCE_CHANGED')\n spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m\ndef birth(api,pid):\n v=api.identity(pid)\n return None if v is None else (v.start_sec,v.start_usec,v.pgid,v.uid,v.ruid)\ndef retire(api,proc,identity):\n errors=[]\n for sig,wait in ((signal.SIGTERM,.3),(signal.SIGKILL,1.2)):\n  if proc.returncode is not None:break\n  try:\n   current=birth(api,proc.pid)\n   require(identity is not None and current==identity and current[2]==proc.pid and current[3:]==(os.getuid(),os.getuid()),'PID_CHANGED')\n   os.killpg(proc.pid,sig)\n  except ProcessLookupError:pass\n  except Exception:errors.append('SIGNAL_UNPROVEN')\n  try:proc.wait(timeout=wait)\n  except subprocess.TimeoutExpired:continue\n  except Exception:errors.append('WAIT_UNPROVEN');break\n try:absent=not api.group_pids(proc.pid)\n except Exception:absent=False\n return dict(pid=proc.pid,birth=list(identity[:2]) if identity else None,reaped=proc.returncode is not None,groupAbsent=absent,errors=errors)\ndef private_fd(fd,empty=False):\n s=os.fstat(fd)\n require(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'FILE_IDENTITY')\n if empty:require(s.st_size==0 and os.lseek(fd,0,os.SEEK_CUR)==0,'FILE_NOT_EMPTY')\ndef write_all(fd,data):\n offset=0\n while offset<len(data):\n  n=os.write(fd,data[offset:]);require(n>0,'WRITE_FAILED');offset+=n\ndef journal(value):\n data=json.dumps(value,separators=(',',':')).encode()+b'\\n'\n require(len(data)<=65536,'JOURNAL_BOUND');private_fd(3);write_all(3,data);os.fsync(3)\ndef safe(error):\n text=str(error)\n return text if text in ('INTERRUPTED','PHASE_TIMEOUT','PHASE_EXIT','OUTPUT_LIMIT','PID_CHANGED','LOCAL_RETIREMENT','MUX_CHANGED','JOURNAL_FAILED') else 'OPERATION_FAILED'\ndef run(argv,payload,seconds,limit,api,raw=False):\n proc=None;identity=None;sel=None;failure=None;cleanup=None;pending=0\n sizes=[0,0];hashes=[hashlib.sha256(),hashlib.sha256()];output=[bytearray(),bytearray()]\n end=time.monotonic()+seconds\n try:\n  require(not CANCELLED,'INTERRUPTED')\n  # Durable first obligation before every child, including read-only mux probes.\n  journal(dict(stage='dispatch-intent',phase=CONF['phase'],remote=raw,commandSha256=CONF['commandSha256']))\n  require(not CANCELLED,'INTERRUPTED');require(time.monotonic()<end,'PHASE_TIMEOUT')\n  proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,close_fds=True,\n    env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':CONF['root'],'TMPDIR':CONF['root']+'/tasks/tmp'})\n  identity=birth(api,proc.pid)\n  require(identity is not None and identity[2]==proc.pid and identity[3:]==(os.getuid(),os.getuid()),'PID_CHANGED')\n  journal(dict(stage='spawn',phase=CONF['phase'],remote=raw,pid=proc.pid,birth=list(identity[:2])))\n  sel=selectors.DefaultSelector()\n  for stream,tag in ((proc.stdout,0),(proc.stderr,1)):\n   os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ,tag)\n  if payload:\n   os.set_blocking(proc.stdin.fileno(),False);sel.register(proc.stdin,selectors.EVENT_WRITE,2)\n  else:proc.stdin.close()\n  while sel.get_map():\n   require(not CANCELLED,'INTERRUPTED');require(time.monotonic()<end,'PHASE_TIMEOUT')\n   for key,_ in sel.select(min(.05,max(0,end-time.monotonic()))):\n    if key.data==2:\n     pending+=os.write(key.fd,payload[pending:pending+65536])\n     if pending==len(payload):sel.unregister(key.fileobj);key.fileobj.close()\n    else:\n     data=os.read(key.fd,65536)\n     if not data:sel.unregister(key.fileobj);continue\n     tag=key.data;sizes[tag]+=len(data);require(sizes[tag]<=(limit if tag==0 else (2097152 if raw else 65536)),'OUTPUT_LIMIT')\n     hashes[tag].update(data)\n     if raw:write_all(4+tag,data)\n     else:output[tag].extend(data)\n  proc.wait(timeout=max(.001,end-time.monotonic()))\n  if raw:os.fsync(4);os.fsync(5)\n  require(proc.returncode==0,'PHASE_EXIT')\n except BaseException as e:failure=safe(e)\n finally:\n  errors=[]\n  if sel is not None:\n   try:sel.close()\n   except Exception:errors.append('SELECTOR_CLOSE')\n  if proc is not None:\n   cleanup=retire(api,proc,identity)\n   for stream in (proc.stdin,proc.stdout,proc.stderr):\n    try:stream.close()\n    except Exception:errors.append('STREAM_CLOSE')\n   cleanup['errors'].extend(errors)\n  else:cleanup=dict(pid=None,birth=None,reaped=True,groupAbsent=True,errors=errors)\n  if not cleanup['reaped'] or not cleanup['groupAbsent'] or cleanup['errors']:failure=failure or 'LOCAL_RETIREMENT'\n result=dict(code=proc.returncode if proc is not None else None,cleanup=cleanup,failure=failure,\n  stdout=dict(bytes=sizes[0],sha256=hashes[0].hexdigest()),stderr=dict(bytes=sizes[1],sha256=hashes[1].hexdigest()))\n try:journal(dict(stage='child-terminal',phase=CONF['phase'],remote=raw,**result))\n except Exception:result['failure']=result['failure'] or 'JOURNAL_FAILED';result['cleanup']['errors'].append('JOURNAL_FAILED')\n return result,output\ndef main():\n require(sys.platform=='darwin','PLATFORM')\n for fd in (3,4,5):private_fd(fd,fd!=3)\n inventory=load('darwin_process_inventory',CONF['deps']['darwin_process_inventory'],CONF['root'])\n mux=load('owned_mcp_mux_relay',CONF['deps']['owned_mcp_mux_relay'],CONF['root'])\n api=inventory.LibProc()\n own=birth(api,os.getpid());require(own is not None and own[2]==os.getpid(),'CONTROLLER_IDENTITY')\n journal(dict(stage='controller-birth',phase=CONF['phase'],pid=os.getpid(),birth=list(own[:2])))\n def abort(signum,frame):\n  global CANCELLED\n  CANCELLED=True\n signal.signal(signal.SIGTERM,abort);signal.signal(signal.SIGINT,abort)\n fd=os.open(CONF['inputPath'],os.O_RDONLY|os.O_NOFOLLOW)\n try:\n  private_fd(fd);s=os.fstat(fd);require(s.st_size<=17825792,'INPUT_BOUND')\n  payload=os.read(fd,s.st_size+1);require(len(payload)==s.st_size and hashlib.sha256(payload).hexdigest()==CONF['inputSha256'],'INPUT_CHANGED')\n finally:os.close(fd)\n children=[]\n def probe(argv,**kw):\n  result,out=run(argv,b'',min(5,kw.get('timeout',5)),65536,api)\n  children.append(result['cleanup'])\n  require(result['failure'] is None,'MUX_CHANGED')\n  return subprocess.CompletedProcess(argv,0,out[0].decode(),out[1].decode())\n expected=CONF['expectedMux']\n if expected is not None:expected['masterBirth']=tuple(expected['masterBirth'])\n before=mux.admit_existing_mux(CONF['root'],expected=expected,run=probe,api=api)\n journal(dict(stage='mux-before',phase=CONF['phase'],authority=before))\n remote=['sudo','-n','timeout','--signal=TERM','--kill-after=10',str(CONF['remoteSeconds']),\n  '/bin/sh','-c',CONF['command'],'owned-system-build',CONF['guest'],CONF['runId']]\n if CONF['phase']=='metadataFetch':remote.append(CONF['base'])\n result,_=run(mux.mux_command(before,shlex.join(remote)),payload,CONF['remoteSeconds']+15,CONF['outputLimit'],api,True)\n children.append(result['cleanup'])\n unchanged=False\n try:\n  require(not CANCELLED,'INTERRUPTED')\n  unchanged=mux.admit_existing_mux(CONF['root'],expected=before,run=probe,api=api)==before\n except Exception:result['failure']=result['failure'] or 'MUX_CHANGED'\n packet=dict(version=1,phase=CONF['phase'],controller=dict(pid=os.getpid(),birth=list(own[:2])),\n  mux=before,muxUnchanged=unchanged,children=children,**result)\n journal(dict(stage='phase-terminal',**packet))\n write_all(1,json.dumps(packet,separators=(',',':')).encode())\n return 1 if packet['failure'] else 0\n";
const keys=(v,names)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===(names?names.split(',').sort().join(','):'');
const integer=(n,min=0)=>Number.isSafeInteger(n)&&n>=min;
const digest=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function validateReceipt(value,phase,expectedMux=null){
 if(!keys(value,'version,phase,controller,mux,muxUnchanged,children,code,cleanup,failure,stdout,stderr')
  ||value.version!==1||value.phase!==phase||!keys(value.controller,'pid,birth')||!integer(value.controller.pid,2)
  ||!Array.isArray(value.controller.birth)||value.controller.birth.length!==2||!value.controller.birth.every(n=>integer(n))
  ||typeof value.muxUnchanged!=='boolean'||!Number.isInteger(value.code)||value.code<-127||value.code>255
  ||!(value.failure===null||['INTERRUPTED','PHASE_TIMEOUT','PHASE_EXIT','OUTPUT_LIMIT','PID_CHANGED','LOCAL_RETIREMENT',
   'MUX_CHANGED','JOURNAL_FAILED','OPERATION_FAILED'].includes(value.failure)))throw error('SYSTEM_DRIVER_RECEIPT');
 const cleanup=r=>keys(r,'pid,birth,reaped,groupAbsent,errors')&&(r.pid===null||integer(r.pid,2))
  &&(r.birth===null||Array.isArray(r.birth)&&r.birth.length===2&&r.birth.every(n=>integer(n)))
  &&typeof r.reaped==='boolean'&&typeof r.groupAbsent==='boolean'&&Array.isArray(r.errors)
  &&r.errors.every(e=>['SIGNAL_UNPROVEN','WAIT_UNPROVEN','SELECTOR_CLOSE','STREAM_CLOSE','JOURNAL_FAILED'].includes(e));
 if(!cleanup(value.cleanup)||!Array.isArray(value.children)||!value.children.length||value.children.length>12||!value.children.every(cleanup))throw error('SYSTEM_DRIVER_RECEIPT');
 for(const name of ['stdout','stderr'])if(!keys(value[name],'bytes,sha256')||!integer(value[name].bytes)||!digest(value[name].sha256))throw error('SYSTEM_DRIVER_RECEIPT');
 const m=value.mux;
 if(!keys(m,'config,socket,configSha256,limaConfigSha256,socketDevice,socketInode,masterPid,masterBirth')
  ||!digest(m.configSha256)||!digest(m.limaConfigSha256)||!integer(m.socketDevice)||!integer(m.socketInode,1)
  ||!integer(m.masterPid,2)||!Array.isArray(m.masterBirth)||m.masterBirth.length!==2||!m.masterBirth.every(n=>integer(n))
  ||typeof m.config!=='string'||typeof m.socket!=='string'
  ||expectedMux&&JSON.stringify(m)!==JSON.stringify(expectedMux))throw error('SYSTEM_DRIVER_MUX_RECEIPT');
 return value;
}
function localRetired(value){
 return [value.cleanup,...value.children].every(r=>r.reaped===true&&r.groupAbsent===true&&r.errors.length===0);
}
const paired=plan=>plan?.target==='original-v24-system-and-policy';
const longPhase=name=>['metadataFetch','startArtifacts','build','systemMetadata','policyMetadata','systemAcquire','policyAcquire','systemBuild','policyBuild'].includes(name);
const archivePhase=name=>['retainedExport','systemExport','policyExport','systemFailureExport','policyFailureExport'].includes(name);
function phaseLists(plan){return paired(plan)?{normal:adapter._internals.PAIR_PHASES,cleanup:adapter._internals.PAIR_CLEANUP}:{normal:NORMAL,cleanup:CLEANUP};}
function optionsFor(plan,name,expectedMux,input,inputPath){
 const lists=phaseLists(plan);
 if(!lists.normal.includes(name)&&!lists.cleanup.includes(name)&&!(paired(plan)?PAIR_RUNTIME:RUNTIME).includes(name))throw error('SYSTEM_DRIVER_PHASE');
 if(typeof plan.commands[name]!=='string'||Buffer.byteLength(plan.commands[name])>1024**2)throw error('SYSTEM_DRIVER_COMMAND');
 const remoteSeconds=paired(plan)?(longPhase(name)?310:150):['metadataFetch','startArtifacts','build'].includes(name)?310:150;
 const base=name==='policyMetadata'?plan.slots.policy.binding.base:plan.binding.base;
 return {root:plan.spec.root,runId:plan.runId,guest:plan.spec.guest,base,
 phase:name,command:plan.commands[name],commandSha256:sha(plan.commands[name]),deps:DEPS,expectedMux,
 inputPath,inputSha256:sha(input),remoteSeconds,outputLimit:archivePhase(name)?MAX_ARCHIVE:MAX_OUTPUT};
}
function pythonProgram(conf){return 'CONF='+JSON.stringify(JSON.stringify(conf))+'\nimport json\nCONF=json.loads(CONF)\n'+SOURCE.replace("if CONF['phase']=='metadataFetch':", "if CONF['phase'] in ('metadataFetch','systemMetadata','policyMetadata'):")+
 '\ntry:\n code=main()\nexcept BaseException:\n code=2\nsys.exit(code)\n';}
async function regular(file,maximum){
 if(await fs.realpath(file)!==file)throw error('SYSTEM_DRIVER_PATH');
 const fd=await fs.open(file,native.constants.O_RDONLY|native.constants.O_NOFOLLOW);
 try{const s=await fd.stat();if(!s.isFile()||s.nlink!==1||s.size>maximum)throw error('SYSTEM_DRIVER_FILE');
 const bytes=Buffer.alloc(s.size);let n=0;while(n<bytes.length){const r=await fd.read(bytes,n,bytes.length-n,n);if(!r.bytesRead)throw error('SYSTEM_DRIVER_CHANGED');n+=r.bytesRead;}
 const after=await fd.stat();if(after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs)throw error('SYSTEM_DRIVER_CHANGED');return bytes;
 }finally{await fd.close();}
}
async function fileDigest(file,maximum){
 if(await fs.realpath(file)!==file)throw error('SYSTEM_DRIVER_PATH');
 const fd=await fs.open(file,native.constants.O_RDONLY|native.constants.O_NOFOLLOW);
 try{
  const before=await fd.stat();
  if(!before.isFile()||before.nlink!==1||before.size>maximum)throw error('SYSTEM_DRIVER_FILE');
  const block=Buffer.alloc(65536),hash=crypto.createHash('sha256');let bytes=0;
  while(true){const row=await fd.read(block,0,Math.min(block.length,maximum-bytes+1),bytes);
   if(!row.bytesRead)break;bytes+=row.bytesRead;if(bytes>maximum)throw error('SYSTEM_DRIVER_FILE');hash.update(block.subarray(0,row.bytesRead));}
  const after=await fd.stat();
  if(bytes!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw error('SYSTEM_DRIVER_CHANGED');
  return {bytes,sha256:hash.digest('hex')};
 }finally{await fd.close();}
}
async function journal(fd,value){
 const bytes=Buffer.from(JSON.stringify(value)+'\n');if(bytes.length>65536)throw error('SYSTEM_DRIVER_RECORD_BOUND');
 let offset=0;while(offset<bytes.length){const r=await fd.write(bytes,offset,bytes.length-offset);if(!r.bytesWritten)throw error('SYSTEM_DRIVER_WRITE');offset+=r.bytesWritten;}await fd.sync();
}
const makeFile=(directory,name)=>fs.open(path.join(directory,name),native.constants.O_RDWR|native.constants.O_CREAT|native.constants.O_EXCL|native.constants.O_NOFOLLOW,0o600);
const makeAppendFile=(directory,name)=>fs.open(path.join(directory,name),native.constants.O_RDWR|native.constants.O_CREAT|native.constants.O_EXCL|native.constants.O_NOFOLLOW|native.constants.O_APPEND,0o600);
async function executePython(conf,files,{python,signal},launch=spawn){
 signal?.throwIfAborted();
 return new Promise((resolve,reject)=>{
  let child,primary,timer,killTimer,joinTimer,closed=false,settled=false,bytes=0,errors=0,chunks=[];
  const finish=(cause,value)=>{if(settled)return;settled=true;clearTimeout(timer);clearTimeout(killTimer);clearTimeout(joinTimer);
   signal?.removeEventListener('abort',abort);
   // Local pipe destruction is not process/group retirement. Keep all debt
   // and a harmless late-error listener, but release our owned pipe handles.
   child?.removeListener('close',onClose);
   const pipeErrors=[];
   for(const [name,handler]of [['stdout',stdoutData],['stderr',stderrData]]){
    const stream=child?.[name];if(!stream)continue;
    stream.removeListener('data',handler);
    try{stream.destroy();}catch{pipeErrors.push(name);}
   }
   chunks=[];
   if(pipeErrors.length){cause ||= error('SYSTEM_DRIVER_PIPE_RETIREMENT');
    Object.assign(cause,{cleanupDebt:true,remoteUncertain:true,pipeCleanupErrors:pipeErrors});}
   cause?reject(cause):resolve(value);};
  const stop=reason=>{
   if(settled)return;
   primary ||= reason;
   // exit is not close: descendants may still hold inherited pipes. Bound
   // that join even after the leader was reaped, without signaling its PID.
   if(child&&!closed)joinTimer ||= setTimeout(()=>finish(Object.assign(primary,
    {cleanupDebt:true,controllerPid:child.pid,remoteUncertain:true})),6000);
   if(child&&!closed&&child.exitCode===null&&child.signalCode===null){
    try{child.kill('SIGTERM');}catch{primary.cleanupDebt=true;}
    killTimer ||= setTimeout(()=>{
     if(!closed&&child.exitCode===null&&child.signalCode===null)try{child.kill('SIGKILL');}catch{primary.cleanupDebt=true;}
    },4000);
   }
  };
  const abort=()=>stop(error('SYSTEM_DRIVER_INTERRUPTED'));
  const stdoutData=b=>{bytes+=b.length;if(bytes>65536)return stop(error('SYSTEM_DRIVER_PROTOCOL_BOUND'));chunks.push(b);};
  const stderrData=b=>{errors+=b.length;if(errors>65536)stop(error('SYSTEM_DRIVER_PROTOCOL_BOUND'));};
  const onClose=(code,termination)=>{
   closed=true;let value;
   try{value=validateReceipt(JSON.parse(Buffer.concat(chunks)),conf.phase,conf.expectedMux);
    if(value.controller.pid!==child.pid)throw error('SYSTEM_DRIVER_CONTROLLER_IDENTITY');
   }catch(e){primary ||= e;}
   if(primary||termination||code!==0||value?.failure||value&&!localRetired(value)){
    const failure=primary||error('SYSTEM_DRIVER_PHASE_FAILED');failure.phaseReceipt=value||null;
    failure.controllerReaped=true;failure.remoteUncertain=true;
    if(!value||!localRetired(value))failure.cleanupDebt=true;
    finish(failure);
   }else finish(null,value);
  };
  try{
   child=launch(python,['-I','-S','-B','-c',pythonProgram(conf)],{cwd:conf.root,detached:true,
    stdio:['ignore','pipe','pipe',files.journal.fd,files.stdout.fd,files.stderr.fd],
    env:{PATH:'/usr/bin:/bin',HOME:conf.root,TMPDIR:path.join(conf.root,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'}});
  }catch(e){finish(e);return;}
  signal?.addEventListener('abort',abort,{once:true});
  timer=setTimeout(()=>stop(error('SYSTEM_DRIVER_CONTROLLER_TIMEOUT')),(conf.remoteSeconds+40)*1000);
  child.on('error',stop);
  child.stdout.on('error',stop);child.stderr.on('error',stop);
  child.stdout.on('data',stdoutData);child.stderr.on('data',stderrData);
  child.once('close',onClose);
  if(signal?.aborted)abort();
 });
}
class Sequence{
 constructor(lists={normal:NORMAL,cleanup:CLEANUP}){this.lists=lists;this.index=0;this.failed=false;this.closed=false;this.busy=false;}
 enter(name,cleanup=false){
  if(this.closed||this.busy)throw error('SYSTEM_DRIVER_STATE');
  if(cleanup?!this.lists.cleanup.includes(name):this.failed||this.lists.normal[this.index]!==name)throw error('SYSTEM_DRIVER_ORDER');
  this.busy=true;
 }
 leave(ok,cleanup=false){this.busy=false;if(!ok)this.failed=true;else if(!cleanup)this.index++;}
}
async function createOwnedSystemDriver(options){
 const diagnostic=options?.plan?.target==='original-v03-diagnostic';
 if(!keys(options,'deadline,expectedDriverSha256,expectedPlanSha256,expectedPythonSha256,plan,signal'+(diagnostic?',combinedOwner':'')))throw error('SYSTEM_DRIVER_OPTIONS');
 const {plan:providedPlan,signal,deadline}=options;
 if(!(signal instanceof AbortSignal)||!Number.isFinite(deadline)||deadline<=performance.now()||deadline-performance.now()>1800000)throw error('SYSTEM_DRIVER_DEADLINE');
 signal.throwIfAborted();
 const combinedOwner=diagnostic?require('./ownedV03PrivateExecutors').assertCombinedOwner(options.combinedOwner):null;
 if(diagnostic){
  const identity=combinedOwner.producerBinding('diagnostic');
  if(combinedOwner.isRevoked()||identity.runId!==providedPlan.runId
   ||combinedOwner.phaseWindow('diagnosticBuildMs').deadlineMs!==deadline
   ||combinedOwner.phaseSignal('diagnosticBuildMs')!==signal)throw error('DIAGNOSTIC_DRIVER_OWNER');
 }
 const pair=paired(providedPlan);
 const plan=diagnostic?await require('./ownedSystemDiagnosticBuildAdapter').diagnosticBuildPlan(providedPlan.spec.root,providedPlan.runId)
  :await (pair?adapter.systemPolicyBuildPlan:adapter.systemBuildPlan)(providedPlan.spec.root,providedPlan.runId,providedPlan.captured.recipe);
 if(adapter.planDigest(plan)!==options.expectedPlanSha256||adapter.planDigest(providedPlan)!==options.expectedPlanSha256)throw error('SYSTEM_DRIVER_PLAN');
 if(sha(await regular(__filename,1024**2))!==options.expectedDriverSha256)throw error('SYSTEM_DRIVER_SOURCE');
 const python=await fs.realpath(PYTHON);
 if(sha(await regular(python,64*1024**2))!==options.expectedPythonSha256)throw error('SYSTEM_DRIVER_PYTHON');
 for(const [name,digest]of Object.entries(DEPS))if(sha(await regular(path.join(plan.spec.root,'tests/postgres',name+'.py'),1024**2))!==digest)throw error('SYSTEM_DRIVER_DEPENDENCY');
 signal.throwIfAborted();
 const directory=path.join(plan.spec.root,'tasks/tmp','system-driver-'+plan.runId);
 if(await fs.realpath(path.dirname(directory))!==path.dirname(directory))throw error('SYSTEM_DRIVER_DIRECTORY');
 await fs.mkdir(directory,{mode:0o700});
 let fd;
 try{
  fd=await makeFile(directory,'journal.jsonl');const parent=await fs.open(directory,native.constants.O_RDONLY);
  let primary;
  try{await parent.sync();}catch(error){primary=error;}
  finally{try{await parent.close();}catch(error){primary ||= error;primary.cleanupDebt=true;primary.driverSetupCleanupErrors=['DIRECTORY_CLOSE_UNPROVEN'];}}
  if(primary)throw primary;
 }catch(error){
  if(fd)try{await fd.close();}catch(closeError){error.cleanupDebt=true;
   error.driverSetupCleanupErrors=[...(error.driverSetupCleanupErrors||[]),'JOURNAL_CLOSE_UNPROVEN'];}
  throw Object.assign(error,{driverDirectory:directory});
 }
 const sequence=new Sequence(phaseLists(plan)),receipts=[],debts=[],observations=[];
 const pairStarted=new Set(),pairRetired=new Set(),retirementAttempts=new Set();let imagesClaimed=false;
 let ordinal=0,mux=null,started=false,artifacts=false,retired=false,notBefore=0,finalReceipt=null,cleanupEnd=null,closePromise=null;
 const exports=[];
 let beforeInventory=null,sharedStateUnchanged=null;
 let runtime=null,claimingRuntime=false,pairCohortEnd=null;
 let diagnosticImage=null;
 const pairRuntimes=new Map();
 const joinUncertainty=async()=>{
  while(performance.now()<notBefore){
   if(!cleanupEnd||notBefore>=cleanupEnd)throw error('SYSTEM_DRIVER_DEADLINE');
   await new Promise(resolve=>setTimeout(resolve,notBefore-performance.now()));
  }
 };
 const phase=async(name,cleanup=false,runtimeOperation=null)=>{
  if(cleanup)await joinUncertainty();
  else if(performance.now()<notBefore)throw error('SYSTEM_REMOTE_RETIREMENT_PENDING');
  const isRuntime=runtimeOperation!==null;
  const runtimeState=pair?pairRuntimes.get(name.split('-')[0]):runtime;
  if(isRuntime){if(sequence.closed||sequence.busy||!runtimeState||!(pair?PAIR_RUNTIME:RUNTIME).includes(name))throw error('SYSTEM_DRIVER_STATE');sequence.busy=true;}
  else sequence.enter(name,cleanup);
  let out,err,conf,ok=false;
  try{
   if(!cleanup){signal.throwIfAborted();if(closePromise)throw error('SYSTEM_DRIVER_STATE');if(debts.length)throw error('SYSTEM_DRIVER_PRIOR_DEBT');}
   const end=isRuntime?(cleanup?runtimeState.cleanupEnd:runtimeState.deadline):(cleanup?cleanupEnd:deadline);
   const seconds=pair?(longPhase(name)?310:150):['metadataFetch','startArtifacts','build'].includes(name)?310:150;
   const envelope=()=>{
    const available=Math.floor((end-performance.now())/1000)-46;
    if(!end||available<1||!cleanup&&available<seconds)throw error('SYSTEM_DRIVER_DEADLINE');
    return cleanup?Math.min(seconds,available):seconds;
   };
   envelope();
   await adapter.verifyPlan(plan);
   let input=isRuntime?runtimeOperation.input:Buffer.alloc(0);
   if(diagnostic&&name==='prepare'){
    const identity=combinedOwner.producerBinding('diagnostic');
    const mapping=require('./ownedV03GuestClock').assertGuestClockMapping(combinedOwner.clockMapping(),combinedOwner);
    const proof=mapping.binding();
    if(proof.parentRunId!==identity.parentRunId||proof.combinedPlanSha256!==identity.planSha256)
     throw error('DIAGNOSTIC_PARENT_CLOCK_BINDING');
    // Absolute mapped expiry survives arbitrarily delayed host preparation;
    // guest creation verifies boot identity and rejects an expired endpoint.
    const expiresAtMs=mapping.mapDeadline(identity.expiresAtMs);
    input=Buffer.from(JSON.stringify({version:1,runId:plan.runId,parentRunId:identity.parentRunId,
     combinedPlanSha256:identity.planSha256,guestBootId:proof.guestBootId,expiresAtMs}));
   }
   if(name==='metadataFetch')input=Buffer.from(plan.metadataGuestSource);
   if(name==='startArtifacts')input=Buffer.from(plan.guestSource);
   if(name==='build')input=await adapter._internals.contextBytes(plan.spec.root,plan.captured);
   if(pair)for(const slot of ['system','policy']){
    if(name===slot+'Metadata')input=Buffer.from(plan.slots[slot].metadataSource);
    if(name===slot+'Acquire')input=Buffer.from(plan.slots[slot].acquisitionSource);
    if(name===slot+'Replay')input=Buffer.from(plan.slots[slot].replaySource);
    if(name===slot+'Build')input=await (slot==='system'?adapter._internals.contextBytes:adapter._internals.rendererContextBytes)(plan.spec.root,plan.slots[slot].captured);
   }
   if(pair&&!cleanup&&!isRuntime)adapter._internals.validatePairPhaseAdmission(plan,observations,name);
   if(input.length>MAX_INPUT)throw error('SYSTEM_DRIVER_INPUT_BOUND');
   if(!cleanup)signal.throwIfAborted();
   ordinal++;const prefix=String(ordinal).padStart(3,'0')+'-'+name,inputPath=path.join(directory,prefix+'.input');
   const inputFd=await makeFile(directory,prefix+'.input');
   try{await inputFd.writeFile(input);await inputFd.sync();}finally{await inputFd.close();}
   out=await makeFile(directory,prefix+'.stdout');err=await makeFile(directory,prefix+'.stderr');
   conf=optionsFor(isRuntime?{...plan,commands:{...plan.commands,[name]:runtimeOperation.command}}:plan,name,mux,input,inputPath);
   await journal(fd,{stage:'phase-intent',ordinal,name,planSha256:options.expectedPlanSha256,inputSha256:sha(input),commandSha256:conf.commandSha256});
   // Expensive source/IO preparation cannot authorize a late remote effect.
   if(!cleanup)signal.throwIfAborted();
   // Charge source verification, file persistence, controller probes and local
   // join to the same endpoint. Cleanup may use less, never a renewed phase cap.
   conf.remoteSeconds=envelope();
   if(name==='prepare')started=true;if(name==='startArtifacts')artifacts=true;
   if(pair&&/^(system|policy)(Metadata|Acquire|Replay)$/.test(name))pairStarted.add(name);
   if(name==='retireArtifacts'||pair&&/^(system|policy)(Metadata|Acquire|Replay)Retire$/.test(name))retirementAttempts.add(name);
   const receipt=await executePython(conf,{journal:fd,stdout:out,stderr:err},{python,signal:cleanup?undefined:signal});
   if(receipt.muxUnchanged!==true)throw Object.assign(error('SYSTEM_DRIVER_MUX_CHANGED'),{phaseReceipt:receipt});
   mux=receipt.mux;
   await out.sync();await err.sync();
   for(const [suffix,proof,limit]of [['stdout',receipt.stdout,conf.outputLimit],['stderr',receipt.stderr,MAX_OUTPUT]]){
    const actual=await fileDigest(path.join(directory,prefix+'.'+suffix),limit);
    if(actual.bytes!==proof.bytes||actual.sha256!==proof.sha256)throw error('SYSTEM_DRIVER_OUTPUT_CHANGED');
   }
   const text=archivePhase(name)?null:(await regular(path.join(directory,prefix+'.stdout'),MAX_OUTPUT)).toString();
   if(diagnostic&&name==='metadataFetch'){
    const envelope=require('./ownedPolicySystemMetadata').validateResultEnvelope(text,plan.binding);
    if(envelope.ok!==true||envelope.version!==3)throw error('SYSTEM_METADATA_NOT_READY');
   }
   if(name==='inventory'){
    if(cleanup)sharedStateUnchanged=false;
    const current=checkInventory(text);
    if(cleanup){
     if(beforeInventory===null||current!==beforeInventory)throw error('SYSTEM_SHARED_STATE_CHANGED');
     sharedStateUnchanged=true;
    }else beforeInventory=current;
   }
   if(name==='retireArtifacts'){if(text.trim()!=='absent')throw error('SYSTEM_DRIVER_REMOTE_ABSENCE');retired=true;}
   if(pair&&/^(system|policy)(Metadata|Acquire|Replay)Retire$/.test(name)){
    if(text.trim()!=='absent')throw error('SYSTEM_DRIVER_REMOTE_ABSENCE');pairRetired.add(name.slice(0,-6));
   }
   if(name==='cleanup'&&text.trim()!=='absent')throw error('SYSTEM_DRIVER_REMOTE_ABSENCE');
   if(pair&&name==='evidence')adapter._internals.validatePairRelayTerminal(plan,observations,text);
   if(pair&&!cleanup&&adapter._internals.PAIR_CREDIT_PHASES.includes(name)){
    adapter._internals.validatePairCredits(plan,[...observations,{name,value:text}],name);
   }
   if(archivePhase(name))exports.push(Object.freeze({kind:name.endsWith('FailureExport')?'failed-slot-raw-metadata':'complete-metadata',
    slot:name.startsWith('policy')?'policy':'system',file:path.join(directory,prefix+'.stdout'),...receipt.stdout}));
   receipts.push({ordinal,name,...receipt});await journal(fd,{stage:'phase-accepted',ordinal,name});ok=true;
   if(!cleanup&&!isRuntime)observations.push(Object.freeze({name,value:text}));
   return archivePhase(name)?Object.freeze({file:path.join(directory,prefix+'.stdout'),...receipt.stdout}):text;
  }catch(cause){
   if(cause.remoteUncertain||cause.phaseReceipt){notBefore=performance.now()+((conf?.remoteSeconds||310)+20)*1000;}
   if(cause.cleanupDebt)debts.push('SYSTEM_DRIVER_LOCAL_RETIREMENT_UNPROVEN');
   try{await journal(fd,{stage:'phase-failed',ordinal,name,code:/^[A-Z_]+$/.test(cause.code||'')?cause.code:'SYSTEM_DRIVER_FAILURE'});}catch{debts.push('SYSTEM_DRIVER_JOURNAL');}
   throw cause;
  }finally{
   for(const file of [out,err])if(file)try{await file.close();}catch{debts.push('SYSTEM_DRIVER_FILE_CLOSE');}
   if(isRuntime){sequence.busy=false;if(!ok)runtimeState.failed=true;}else sequence.leave(ok,cleanup);
  }
 };
 const claimRuntime=async()=>{
  if(diagnostic)throw error('DIAGNOSTIC_DISTINCT_RUNTIME_REQUIRED');
  if(pair)throw error('SYSTEM_PAIR_RUNTIME_NOT_ADMITTED');
  if(runtime||claimingRuntime||sequence.closed||sequence.busy||sequence.failed||sequence.index!==NORMAL.length||debts.length)throw error('SYSTEM_RUNTIME_NOT_ADMITTED');
  signal.throwIfAborted();claimingRuntime=true;
  try{
   await adapter.verifyPlan(plan);
   const binding=freeze(consumer.validateBinding(await adapter._internals.validateDriverObservations(plan,observations)));
   signal.throwIfAborted();
   return makeRuntimeOwner(binding,'system');
  }finally{claimingRuntime=false;}
 };
 const makeRuntimeOwner=(binding,slot)=>{
   const state={binding,deadline:null,cleanupEnd:null,started:false,inspected:false,failed:false,
    bridgeAttempted:false,bridge:null,bridgeFiles:[],local:null,remote:null,stopAttempted:false,confirmed:false};
   if(pair)pairRuntimes.set(slot,state);else runtime=state;
   // Keep all operations closed over their own slot, never a caller-selected
   // state object or another target's CID/channel journal.
   const owned=state;
   const active=()=>{
    signal.throwIfAborted();if(sequence.closed||owned.failed||cleanupEnd!==null||debts.length||performance.now()<notBefore
     ||owned.deadline!==null&&performance.now()>=owned.deadline)throw error('SYSTEM_RUNTIME_INACTIVE');
   };
   const emptyLocal=()=>Object.freeze({version:1,runId:plan.runId,channelIds:[],localRetired:true,
    retirementUnproven:false,remoteRetired:false,builderReleaseAllowed:false,failures:[],...(slot==='policy'?{target:binding.target}:{})});
   const beginRetirement=(...args)=>{
    if(args.length||sequence.closed)throw error('SYSTEM_RUNTIME_CLEANUP_STATE');
    cleanupEnd ||= performance.now()+600000;owned.cleanupEnd=cleanupEnd;return cleanupEnd;
   };
   const retirementActive=()=>{
    if(sequence.closed||!owned.cleanupEnd||performance.now()>=owned.cleanupEnd)throw error('SYSTEM_RUNTIME_CLEANUP_DEADLINE');
   };
   return Object.freeze({binding,assertActive:active,beginRetirement,
    async startRuntime(value){
     active();if(owned.started||!keys(value,slot==='policy'?'':'token'))throw error('SYSTEM_RUNTIME_ALREADY_STARTED');
     if(pair){
      if(slot==='system'){if(pairCohortEnd!==null)throw error('SYSTEM_PAIR_COHORT_REPLAY');pairCohortEnd=performance.now()+900000;}
      else if(!pairRuntimes.get('system')?.inspected||pairCohortEnd===null)throw error('SYSTEM_PAIR_START_ORDER');
      owned.deadline=pairCohortEnd;
     }else owned.deadline=performance.now()+900000;
     owned.started=true;
     const op=transport.operation(plan,binding,'start',value.token);
     return consumer.validateRuntime(binding,JSON.parse(await phase(op.name,false,op)));
    },
    async inspectRuntime(...args){
     active();if(args.length||!owned.started||owned.inspected)throw error('SYSTEM_RUNTIME_INSPECT');
     const op=transport.operation(plan,binding,'inspect');
     const result=consumer.validateRuntime(binding,JSON.parse(await phase(op.name,false,op)));owned.inspected=true;return result;
    },
    async openBridge(...args){
     active();if(args.length||!owned.inspected||owned.bridgeAttempted)throw error('SYSTEM_BRIDGE_STATE');owned.bridgeAttempted=true;
     try{
      await adapter.verifyPlan(plan);active();
      const files={owner:fd};
      for(const name of ['journal','stdout','stderr']){
       files[name]=await (name==='journal'?makeAppendFile:makeFile)(directory,(pair?slot+'-':'')+'bridge.'+name);
       owned.bridgeFiles.push(files[name]);
      }
      active();
      owned.bridge=await transport.openOwnedBridge({root:plan.spec.root,binding,authority:mux,python,signal,deadline:owned.deadline,files,
       expectedHelperSha256:plan.helperHashes['tests/postgres/owned_system_private_http_channel.py']});
      return Object.freeze({port:owned.bridge.port});
     }catch(e){owned.failed=true;const failures=[];
      for(const file of owned.bridgeFiles)try{await file.close();}catch{failures.push('SYSTEM_BRIDGE_FILE_CLOSE');}
      if(failures.length){debts.push(...failures);e.cleanupDebt=true;}throw e;}
    },
    async closeBridge(...args){
     if(args.length)throw error('SYSTEM_BRIDGE_STATE');retirementActive();if(owned.local)return owned.local;
     if(!owned.bridgeAttempted)return owned.local=emptyLocal();
     if(!owned.bridge)throw Object.assign(error('SYSTEM_BRIDGE_RETIREMENT_UNPROVEN'),{retirementUnproven:true});
     // Exactly one close attempt. Failed capture never grants remote deletion,
     // but must still release every independently owned local file descriptor.
     owned.bridgeClosePromise ||= (async()=>{
      let local,ids,primary;const closeErrors=[];
      try{
       local=await owned.bridge.close();
       for(const file of owned.bridgeFiles)await file.sync();
       const raw=await regular(path.join(directory,(pair?slot+'-':'')+'bridge.journal'),2*1024**2);
       const rows=raw.toString('utf8').trim().split('\n').filter(Boolean).map(line=>JSON.parse(line));
       ids=rows.filter(row=>row.stage==='channel-intent').map(row=>{
        if(!keys(row,'version,stage,runId,channelId')||row.version!==1||row.runId!==plan.runId
         ||typeof row.channelId!=='string'||!/^[a-f0-9]{32}$/.test(row.channelId))throw error('SYSTEM_CHANNEL_JOURNAL');
        return row.channelId;});
       if(JSON.stringify(ids)!==JSON.stringify(local.channelIds)||new Set(ids).size!==ids.length)throw error('SYSTEM_CHANNEL_JOURNAL');
      }catch(e){primary=e;}
      finally{for(const file of owned.bridgeFiles)try{await file.close();}catch(e){closeErrors.push(e);}}
      if(primary||closeErrors.length)throw Object.assign(primary||error('SYSTEM_BRIDGE_FILE_CLOSE'),
       {retirementUnproven:true,bridgeFileCleanupErrors:closeErrors});
      owned.local=freeze({...local,channelIds:[...ids],failures:[...local.failures]});return owned.local;
     })();
     return owned.bridgeClosePromise;
    },
    async stopRuntime(...args){
     if(args.length||!owned.local||owned.local.localRetired!==true||owned.local.retirementUnproven!==false)throw error('SYSTEM_RUNTIME_STOP_ORDER');
     if(owned.remote)return owned.remote;if(owned.stopAttempted)throw error('SYSTEM_RUNTIME_STOP_ALREADY_ATTEMPTED');owned.stopAttempted=true;
     // This does not enlarge the original cohort. Retirement has its own
     // existing600s outer budget; consumer timeout may still retain debt.
     beginRetirement();
     const op=transport.operation(plan,binding,'stop',undefined,[...owned.local.channelIds]);
     const remote=JSON.parse(await phase(op.name,true,op));consumer.validateRetirement(binding,owned.local,remote);
     owned.remote=freeze(remote);return owned.remote;
    },
    async confirmRetired(...args){
     retirementActive();
     if(args.length||!owned.local||!owned.remote||sequence.busy||debts.length)throw error('SYSTEM_RUNTIME_RETIREMENT_UNPROVEN');
     consumer.validateRetirement(binding,owned.local,owned.remote);
     try{await journal(fd,{stage:'runtime-retired',runId:plan.runId,...(pair?{slot}:{})});}
     catch(e){debts.push('SYSTEM_DRIVER_JOURNAL');throw e;}
     owned.confirmed=true;return true;
    }});
 };
 const claimImages=async()=>{
  if(!pair||imagesClaimed||sequence.closed||sequence.busy||sequence.failed||sequence.index!==sequence.lists.normal.length||debts.length
    ||[...pairStarted].some(name=>!pairRetired.has(name)))throw error('SYSTEM_PAIR_NOT_ADMITTED');
  signal.throwIfAborted();imagesClaimed=true;
  const binding=await adapter._internals.validatePairDriverObservations(plan,observations);
  const assertActive=()=>{signal.throwIfAborted();if(sequence.closed||sequence.failed||cleanupEnd!==null||performance.now()>=deadline||debts.length)throw error('SYSTEM_PAIR_INACTIVE');};
  assertActive();return Object.freeze({binding,assertActive});
 };
 const claimPairedRuntime=async()=>{
  if(!pair||claimingRuntime||pairRuntimes.size)throw error('SYSTEM_PAIR_RUNTIME_NOT_ADMITTED');
  claimingRuntime=true;
  try{
   const images=await claimImages(),binding=images.binding,slots={};
   for(const slot of ['system','policy']){
    const row=consumer.validateBinding({version:1,target:slot==='system'?'original-v24-system':'original-v24-policy',
     runId:plan.runId,imageId:binding.images[slot].imageId,inputSha256:binding.images[slot].inputSha256,
     daemonId:binding.daemonId,physical:binding.physical});
    slots[slot]=makeRuntimeOwner(freeze(row),slot);
   }
   return Object.freeze({binding,slots:Object.freeze(slots),get cohortDeadline(){return pairCohortEnd;},
    assertActive(){for(const slot of Object.values(slots))slot.assertActive();},
    beginRetirement(){const first=slots.system.beginRetirement();if(slots.policy.beginRetirement()!==first)throw error('SYSTEM_PAIR_RETIREMENT_CLOCK');return first;}});
  }finally{claimingRuntime=false;}
 };
 const claimDiagnosticImage=async()=>{
  if(!diagnostic||imagesClaimed||sequence.closed||sequence.busy||sequence.failed
   ||sequence.index!==NORMAL.length||debts.length||combinedOwner.isRevoked())throw error('DIAGNOSTIC_IMAGE_NOT_ADMITTED');
  signal.throwIfAborted();
  const binding=await adapter._internals.validateDriverObservations(plan,observations);
  if(binding.target!=='original-v03-diagnostic')throw error('DIAGNOSTIC_IMAGE_BINDING');
  imagesClaimed=true;
  diagnosticImage=freeze(binding);
  return freeze({binding:diagnosticImage,buildComplete:true,runtimeAvailable:false});
 };
 const claimDiagnosticRuntime=()=>{
  if(!diagnostic||!diagnosticImage||runtime||sequence.busy||sequence.closed||debts.length
    ||combinedOwner.isRevoked())throw error('DIAGNOSTIC_RUNTIME_NOT_ADMITTED');
  const fixed=require('./ownedSystemDiagnosticRuntime'),clock=require('./ownedV03GuestClock')
   .assertGuestClockMapping(combinedOwner.clockMapping(),combinedOwner);
  const proof=clock.binding(),binding=diagnosticImage;
  const state=runtime={started:false,confirmed:false,failed:false,claimAttempted:false,bridgeAttempted:false,
   bridge:null,bridgeFiles:[],local:null,remote:null,stopAttempted:false,joinAttempted:false,settled:false,bridgeAbort:new AbortController()};
  const active=()=>{if(sequence.closed||state.failed||debts.length||combinedOwner.isRevoked())throw error('DIAGNOSTIC_RUNTIME_INACTIVE');};
  const cleanupDeadline=()=>{
   if(!combinedOwner.isRevoked())throw error('DIAGNOSTIC_RETIREMENT_ORDER');
   const window=clock.mapRetirementInterval('diagnosticCleanupMs');
   // GuestRuntime admits at most120s per command, not the600s cleanup lease.
   // Anchor to the existing phase start: preparation delays consume this bound.
   return Math.min(window.deadlineMs,window.startedAtMs+120000)/1000;
  };
  async function invoke(kind,settings,ids=[]){
   if(sequence.busy||sequence.closed)throw error('DIAGNOSTIC_RUNTIME_BUSY');
   const retiring=kind==='stop',phaseKind=retiring?'diagnosticCleanupMs':kind==='claim-cohort'?'cohortClaim':'diagnosticStartupMs';
   if(!retiring)active();
   if(performance.now()<notBefore)throw error('SYSTEM_REMOTE_RETIREMENT_PENDING');
   const window=combinedOwner.phaseWindow(phaseKind),operationSignal=combinedOwner.phaseSignal(phaseKind);
   const operation=fixed.operation(plan,binding,kind,settings,ids);
   let out,err,conf,primary;sequence.busy=true;
   try{
    await adapter.verifyPlan(plan);operationSignal.throwIfAborted();
    const remaining=Math.floor((window.deadlineMs-performance.now())/1000)-1;
    if(remaining<1)throw error('DIAGNOSTIC_PHASE_DEADLINE');
    ordinal++;const prefix=String(ordinal).padStart(3,'0')+'-'+operation.name;
    const inputPath=path.join(directory,prefix+'.input'),inputFd=await makeFile(directory,prefix+'.input');
    try{await inputFd.writeFile(operation.input);await inputFd.sync();}finally{await inputFd.close();}
    out=await makeFile(directory,prefix+'.stdout');err=await makeFile(directory,prefix+'.stderr');
    conf={root:plan.spec.root,runId:plan.runId,guest:plan.spec.guest,base:plan.binding.base,
     phase:operation.name,command:operation.command,commandSha256:sha(operation.command),deps:DEPS,expectedMux:mux,
     inputPath,inputSha256:sha(operation.input),remoteSeconds:Math.min(kind==='claim-cohort'?2:120,remaining),outputLimit:MAX_OUTPUT};
    await journal(fd,{stage:'phase-intent',ordinal,name:operation.name,planSha256:options.expectedPlanSha256,
     inputSha256:conf.inputSha256,commandSha256:conf.commandSha256});
    operationSignal.throwIfAborted();
    if(combinedOwner.phaseWindow(phaseKind)!==window||performance.now()>=window.deadlineMs-1000)throw error('DIAGNOSTIC_PHASE_DEADLINE');
    conf.remoteSeconds=Math.min(conf.remoteSeconds,Math.floor((window.deadlineMs-performance.now())/1000)-1);
    if(conf.remoteSeconds<1)throw error('DIAGNOSTIC_PHASE_DEADLINE');
    const receipt=await executePython(conf,{journal:fd,stdout:out,stderr:err},{python,signal:operationSignal});
    if(!receipt.muxUnchanged)throw Object.assign(error('SYSTEM_DRIVER_MUX_CHANGED'),{phaseReceipt:receipt});
    for(const [suffix,row] of [['stdout',receipt.stdout],['stderr',receipt.stderr]]){
     const actual=await fileDigest(path.join(directory,prefix+'.'+suffix),MAX_OUTPUT);
     if(actual.bytes!==row.bytes||actual.sha256!==row.sha256)throw error('SYSTEM_DRIVER_OUTPUT_CHANGED');
    }
    const value=JSON.parse((await regular(path.join(directory,prefix+'.stdout'),MAX_OUTPUT)).toString());
    receipts.push({ordinal,name:operation.name,...receipt});await journal(fd,{stage:'phase-accepted',ordinal,name:operation.name});
    return value;
   }catch(cause){primary=cause;state.failed=true;
    if(cause.remoteUncertain||cause.phaseReceipt)notBefore=performance.now()+((conf?.remoteSeconds||120)+20)*1000;
    if(cause.cleanupDebt)debts.push('SYSTEM_DRIVER_LOCAL_RETIREMENT_UNPROVEN');
    try{await journal(fd,{stage:'phase-failed',ordinal,name:operation.name,code:cause.code||'DIAGNOSTIC_RUNTIME_FAILURE'});}
    catch{debts.push('SYSTEM_DRIVER_JOURNAL');}
    throw cause;
   }finally{
    sequence.busy=false;
    const failed=[];for(const handle of [out,err])if(handle)try{await handle.close();}catch{failed.push('SYSTEM_DRIVER_FILE_CLOSE');}
    if(failed.length){debts.push(...failed);if(primary)primary.cleanupDebt=true;else throw Object.assign(error('SYSTEM_DRIVER_FILE_CLOSE'),{cleanupDebt:true});}
   }
  }
  const creationOrdinal=ordinal;let used=false,settledWindow=null;
  const handle=Object.freeze({binding,
   async startRuntime(token){
    state.consumerAttempted=true;
    active();if(state.started)throw error('DIAGNOSTIC_START_ONCE');state.started=true;
    const window=combinedOwner.phaseWindow('diagnosticStartupMs');
    const value=await invoke('start',{deadline:clock.mapDeadline(window.deadlineMs-1000)/1000,
     runtimeDeadline:clock.mapDeadline(combinedOwner.binding().expiresAtMs-4536000)/1000,token});
    consumer.validateRuntime(binding,value);return Object.freeze({ready:true});
   },
   async claimCohort(){
    state.consumerAttempted=true;
    active();if(!state.started||state.claimAttempted)throw error('DIAGNOSTIC_COHORT_ONCE');state.claimAttempted=true;
    const end=combinedOwner.cohortDeadlineMs(),mapped=clock.mapInterval({startedAtMs:end-1210000,deadlineMs:end});
    const cohort={parentRunId:proof.parentRunId,runId:plan.runId,combinedPlanSha256:proof.combinedPlanSha256,
     guestBootId:proof.guestBootId,phase:'cohortClaim',...mapped};
    const window=combinedOwner.phaseWindow('cohortClaim');
    fixed.validateCohortClaim(binding,await invoke('claim-cohort',{deadline:clock.mapDeadline(window.deadlineMs-1000)/1000,cohort}));
    active();state.bridgeAttempted=true;
    const files={owner:fd};
    try{
     for(const name of ['journal','stdout','stderr']){
      files[name]=await (name==='journal'?makeAppendFile:makeFile)(directory,'diagnostic-bridge.'+name);
      state.bridgeFiles.push(files[name]);
     }
     const effectiveEnd=end-clock.uncertaintyMs();
     if(effectiveEnd-performance.now()<1200000)throw error('DIAGNOSTIC_COHORT_ACTIVATION');
     state.bridge=await transport.openOwnedBridge({root:plan.spec.root,binding,authority:mux,python,
      signal:state.bridgeAbort.signal,deadline:effectiveEnd,files,
      expectedHelperSha256:plan.helperHashes['tests/postgres/owned_system_private_http_channel.py']});
     if(effectiveEnd-performance.now()<1200000)throw error('DIAGNOSTIC_COHORT_ACTIVATION');
     return Object.freeze({port:state.bridge.port});
    }catch(cause){state.failed=true;throw cause;}
   },
   join(){
    if(!combinedOwner.isRevoked())throw error('DIAGNOSTIC_RETIREMENT_ORDER');
    combinedOwner.phaseWindow('diagnosticControllerJoinMs');
    if(state.joinAttempted)throw error('DIAGNOSTIC_BRIDGE_JOIN_ALREADY_ATTEMPTED');state.joinAttempted=true;
    state.joinPromise=(async()=>{
    if(!state.bridgeAttempted)return state.local=freeze({version:1,runId:plan.runId,target:binding.target,
     channelIds:[],localRetired:true,retirementUnproven:false,remoteRetired:false,builderReleaseAllowed:false,failures:[]});
    let primary,local;
    try{
     if(!state.bridge)throw error('DIAGNOSTIC_BRIDGE_RETIREMENT_UNPROVEN');
     local=await state.bridge.close();
     for(const handle of state.bridgeFiles)await handle.sync();
     const raw=await regular(path.join(directory,'diagnostic-bridge.journal'),2*1024**2);
     const ids=raw.toString().trim().split('\n').filter(Boolean).map(row=>JSON.parse(row))
      .filter(row=>row.stage==='channel-intent').map(row=>{
       if(!keys(row,'version,stage,runId,channelId')||row.version!==1||row.runId!==plan.runId
         ||! /^[a-f0-9]{32}$/.test(row.channelId))throw error('SYSTEM_CHANNEL_JOURNAL');return row.channelId;});
     if(JSON.stringify(ids)!==JSON.stringify(local.channelIds)||new Set(ids).size!==ids.length)throw error('SYSTEM_CHANNEL_JOURNAL');
     state.local=freeze(local);return state.local;
    }catch(cause){primary=cause;throw cause;}
    finally{
     const failed=[];for(const handle of state.bridgeFiles)try{await handle.close();}catch{failed.push('SYSTEM_BRIDGE_FILE_CLOSE');}
     if(failed.length){state.local=null;debts.push(...failed);if(primary)primary.cleanupDebt=true;else throw error('SYSTEM_BRIDGE_FILE_CLOSE');}
    }
    })();
    // close() is invoked synchronously above: EOF/stop begins in the6s phase.
    // Its existing<=26s transport join is awaited in the SAME mandatory330s
    // settlement phase, not misrepresented as a6s absence proof or retried.
    void state.joinPromise.catch(()=>{});
    return Object.freeze({joinRequested:true});
   },
   async settle(){
    if(!combinedOwner.isRevoked()||!state.joinAttempted||!state.joinPromise)throw error('DIAGNOSTIC_SETTLEMENT_ORDER');
    const window=combinedOwner.phaseWindow('diagnosticLostReplyMs'),settlementSignal=combinedOwner.phaseSignal('diagnosticLostReplyMs');
    const result=await state.joinPromise;
    settlementSignal.throwIfAborted();
    if(combinedOwner.phaseWindow('diagnosticLostReplyMs')!==window)throw error('DIAGNOSTIC_SETTLEMENT_ORDER');
    if(result.localRetired!==true||result.retirementUnproven!==false)throw error('DIAGNOSTIC_BRIDGE_RETIREMENT_UNPROVEN');
    state.settled=true;settledWindow=window;return result;
   },
   async stopRuntime(){
    if(!state.settled||!state.local||state.local.localRetired!==true||state.local.retirementUnproven!==false||state.stopAttempted)
     throw error('DIAGNOSTIC_RETIREMENT_UNPROVEN');
    state.stopAttempted=true;
    const value=await invoke('stop',{deadline:cleanupDeadline()-1},state.local.channelIds);
    consumer.validateRetirement(binding,state.local,value);state.remote=freeze(value);state.confirmed=true;return state.remote;
   }
  });
  unstartedSettlements.set(handle,(owner,window)=>{
    if(used)return false;used=true;
    if(owner!==combinedOwner||!combinedOwner.isRevoked()||window!==settledWindow
      ||combinedOwner.phaseWindow('diagnosticLostReplyMs')!==window
      ||combinedOwner.phaseSignal('diagnosticLostReplyMs').aborted
      ||performance.now()>=window.deadlineMs||ordinal!==creationOrdinal
      ||sequence.index!==NORMAL.length||sequence.busy||sequence.failed||sequence.closed
      ||cleanupEnd!==null||notBefore!==0||debts.length||state.consumerAttempted
      ||state.started||state.failed||state.claimAttempted||state.bridgeAttempted||state.stopAttempted
      ||!state.joinAttempted||!state.settled||!state.local||state.local.localRetired!==true
      ||state.local.retirementUnproven!==false||state.local.channelIds.length)return false;
    return true;
  });
  return handle;
 };
 return Object.freeze({directory,run:name=>phase(name),claimRuntime,claimImages,claimPairedRuntime,claimDiagnosticImage,claimDiagnosticRuntime,close(){
  if(closePromise)return closePromise;
  if(sequence.busy)return Promise.reject(error('SYSTEM_DRIVER_BUSY'));
  if(runtime?.started&&!runtime.confirmed||[...pairRuntimes.values()].some(row=>row.started&&!row.confirmed))
   return Promise.reject(Object.assign(error('SYSTEM_RUNTIME_RETIREMENT_UNPROVEN'),{retirementUnproven:true}));
  cleanupEnd ||= diagnostic?combinedOwner.phaseWindow('diagnosticCleanupMs').deadlineMs:performance.now()+600000;
  const failedBuild=sequence.failed;
  const exportPhases=pair?['system','policy'].map(slot=>slot+(failedBuild&&!adapter._internals.pairMetadataComplete(plan,observations,slot)?'FailureExport':'Export')):[];
  closePromise=(async()=>{
  const cleanupErrors=[],qualificationErrors=[];
  if(started&&!debts.includes('SYSTEM_DRIVER_LOCAL_RETIREMENT_UNPROVEN')){
   if(pair){
    for(const name of pairStarted)if(!pairRetired.has(name))try{
     if(retirementAttempts.has(name+'Retire'))throw error('SYSTEM_DRIVER_RETIREMENT_ALREADY_ATTEMPTED');
     await phase(name+'Retire',true);
    }catch(e){cleanupErrors.push(e);}
    if([...pairStarted].every(name=>pairRetired.has(name))){
     for(const name of ['systemEvidence','policyEvidence','stop','evidence',
       ...exportPhases,'cleanup','inventory']){
      if(name==='cleanup'&&(cleanupErrors.length||debts.length))continue;
      try{await phase(name,true);}catch(e){
       if(name==='evidence'&&adapter._internals.isPairRelayQualificationFailure(e))qualificationErrors.push(e);
       else cleanupErrors.push(e);
      }
     }
    }
   }else{
   if(artifacts&&!retired)try{
    if(retirementAttempts.has('retireArtifacts'))throw error('SYSTEM_DRIVER_RETIREMENT_ALREADY_ATTEMPTED');
    await phase('retireArtifacts',true);
   }catch(e){cleanupErrors.push(e);}
   if(!artifacts||retired){
    for(const name of ['closureEvidence','stop','evidence','retainedExport','cleanup','inventory']){
     if(name==='closureEvidence'&&!artifacts||name==='cleanup'&&(cleanupErrors.length||debts.length))continue;
     try{await phase(name,true);}catch(e){cleanupErrors.push(e);}
    }
   }
   }
  }
  const result={localCleanupVerified:debts.length===0,remoteCleanupVerified:cleanupErrors.length===0&&(!started||receipts.some(r=>r.name==='cleanup')),
   guestResourcesAbsent:!started||receipts.some(r=>r.name==='cleanup'),sharedStateUnchanged,
   debts:[...debts,...cleanupErrors.map(e=>e.code||'SYSTEM_DRIVER_CLEANUP')]};
  // The journal is not itself proof that its own final close succeeded.
  // Only the returned receipt (persisted by the producer) closes that debt.
  try{await journal(fd,{stage:'driver-preclose',journalClosePending:true,cleanupDeadline:cleanupEnd,exports,...result});}catch{result.debts.push('SYSTEM_DRIVER_JOURNAL');result.localCleanupVerified=false;}
  try{await fd.close();}catch{result.debts.push('SYSTEM_DRIVER_JOURNAL_CLOSE');result.localCleanupVerified=false;}
  sequence.closed=true;finalReceipt=Object.freeze(result);
  if(!result.localCleanupVerified||!result.remoteCleanupVerified)throw Object.assign(error('SYSTEM_DRIVER_CLEANUP_DEBT'),{retirementUnproven:true,receipt:finalReceipt,qualificationErrors});
  if(qualificationErrors.length)throw Object.assign(qualificationErrors[0],{retirementUnproven:false,receipt:finalReceipt});
  return finalReceipt;
  })();
  return closePromise;
 }});
}
module.exports={createOwnedSystemDriver,consumeUnstartedSettlement,_internals:{SOURCE,pythonProgram,optionsFor,validateReceipt,localRetired,executePython,Sequence,DEPS,NORMAL,CLEANUP,regular,fileDigest,phaseLists,longPhase,archivePhase}};

