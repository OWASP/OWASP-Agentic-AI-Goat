'use strict';

// Fixed original V24 caller ownership. Explicit MAIN/source/plan admission is
// required for each run; this entry never adopts a retained runtime receipt.
const fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path');
const crypto=require('node:crypto'),{spawn}=require('node:child_process');
const producer=require('./ownedSystemImageProducer');
const ROOT=path.resolve(__dirname,'../..'),PYTHON='/opt/homebrew/bin/python3';
const NODE=path.join(ROOT,'tasks/runtime/node/node_modules/node/bin/node');
const NODE_PACKAGE=path.join(ROOT,'tasks/runtime/node/node_modules/node/node_modules/node-bin-darwin-arm64/bin/node');
const BROWSER='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const LIVE_ENABLED=true;
const TEST='tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js';
const PINS=Object.freeze({
 [TEST]:'450d9c441d4b387a0f374faf227bc450803b2bfc67dfc57c9975e57e0e8fc11e',
 'tests/fixtures/secureshopPolicyInstructionRenderedScenario.js':'f6a2f412c85640bd36f563836d9e4031dbe2baac2b7195521a12755bcf652002',
 'tests/postgres/darwin_process_inventory.py':'93976fc710fbd56eeabddcd01927ef28c4e4567748c0b6004d1552d60b777ba9',
 'tests/postgres/ownedSystemImageProducer.js':'f61a10866c74f464e8d4567e5f81ca2e7b0286f21802ab5406f9b60c5ae9c679',
 'tests/fixtures/secureshopOwnedPolicyRendererAdmission.js':'4ed283983768d6204298a789ea94b33dc044b1b254fe16f3ad41993ac1b207cd',
});
const LIMITS=Object.freeze({input:65536,terminal:16384,journal:262144,tap:8*1024**2,cohort:900000,controllerJoin:6000});
const fail=code=>Object.assign(Error(code),{code});
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===keys.split(',').sort().join(',');
const digest=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const integer=(n,min=0)=>Number.isSafeInteger(n)&&n>=min;
const underRoot=file=>typeof file==='string'&&path.isAbsolute(file)&&path.resolve(file)===file&&file.startsWith(ROOT+path.sep);
// Only this process can attest that validation failed before any owner effect.
// Error properties or a caller-supplied JSON record cannot mint that authority.
const PREALLOCATION=new WeakMap();
const VALIDATION_CODES=new Set(['SYSTEM_ORIGINAL_SOURCE','SYSTEM_ORIGINAL_PATH','SYSTEM_ORIGINAL_FILE',
 'SYSTEM_ORIGINAL_CHANGED','SYSTEM_ORIGINAL_NODE_PATH','SYSTEM_ORIGINAL_NODE_FILE','SYSTEM_ORIGINAL_NODE_CHANGED',
 'SYSTEM_ORIGINAL_PREFLIGHT','SYSTEM_MAIN_INTERRUPTED']);
const failureCode=error=>error?(VALIDATION_CODES.has(error.code)?error.code:'SYSTEM_OWNER_UNKNOWN'):null;
// Owner-local diagnosis only. These are fixed source-defined codes, not an
// authority-bearing receipt. Never copy an Error message, stack or unknown code.
const PRODUCER_DIAGNOSTIC_CODES=new Set([
 'SYSTEM_BINDING','SYSTEM_RUNTIME_BINDING','SYSTEM_CONSUMER_FAILED','SYSTEM_TRANSPORT_FAILED',
 'SYSTEM_CLEANUP_DEADLINE','SYSTEM_BRIDGE_RETIREMENT_UNPROVEN','SYSTEM_PAIR_RELAY_TERMINAL',
 'SYSTEM_PRODUCER_CALLBACK_UNSETTLED','SYSTEM_PRODUCER_RETIREMENT','SYSTEM_PRODUCER_FAILED',
 'SYSTEM_PAIR_FAILED','SYSTEM_DRIVER_CLEANUP','SYSTEM_DRIVER_CLEANUP_DEBT',
 'SYSTEM_ORIGINAL_TEST_FAILED','SYSTEM_ORIGINAL_CONTROLLER_STATUS','SYSTEM_ORIGINAL_TAP',
]);
const ownData=(value,key)=>{
 if(!value||typeof value!=='object')return undefined;
 try{return Object.getOwnPropertyDescriptor(value,key)?.value;}catch{return undefined;}
};
function producerFailureDiagnostic(error){
 const seen=new WeakSet(),cleanupCodes=[];let current=error,primaryCode=null,outerCode=null,depth=0,truncated=false;
 const fixed=value=>PRODUCER_DIAGNOSTIC_CODES.has(value)?value:'SYSTEM_OWNER_UNKNOWN';
 while(current&&typeof current==='object'){
  if(seen.has(current)||depth===4){truncated=true;break;}
  seen.add(current);const code=fixed(ownData(current,'code'));
  if(depth===0)outerCode=code;
  const cleanup=ownData(current,'cleanupErrors');
  let cleanupArray=false;
  try{cleanupArray=Array.isArray(cleanup);}catch{truncated=true;}
  if(cleanupArray){
   const count=ownData(cleanup,'length');
   if(!Number.isSafeInteger(count)||count<0){truncated=true;break;}
   const capacity=4-cleanupCodes.length;
   if(count>capacity)truncated=true;
   for(let i=0;i<Math.min(count,capacity);i++)cleanupCodes.push(fixed(ownData(ownData(cleanup,String(i)),'code')));
  }
  const next=ownData(current,'primary')||ownData(current,'cause');
  if(!next||typeof next!=='object'){primaryCode=code;break;}
  current=next;depth++;
 }
 return {outerCode:outerCode||'SYSTEM_OWNER_UNKNOWN',primaryCode:primaryCode||'SYSTEM_OWNER_UNKNOWN',cleanupCodes,truncated};
}

// This controller owns/reaps the exact original Node child. A detached browser
// is never assumed absent from child exit alone: a complete current-user argv
// scan must also prove the exact private profile prefix absent. Unknown live
// process visibility fails closed. It never removes a profile or signals a
// process found only by its command line.
const CONTROLLER=String.raw`
import os,sys,json,stat,time,signal,selectors,subprocess,hashlib,importlib.util,ctypes,shutil,re
CANCELLED=False
def require(ok,code):
 if not ok:raise RuntimeError(code)
def write_all(fd,data):
 offset=0
 while offset<len(data):
  n=os.write(fd,data[offset:]);require(n>0,'WRITE_FAILED');offset+=n
def private_fd(fd):
 s=os.fstat(fd)
 require(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'FILE_IDENTITY')
 return s
def journal(row):
 data=json.dumps(row,separators=(',',':')).encode()+b'\n'
 require(len(data)<=16384 and private_fd(3).st_size+len(data)<=262144,'JOURNAL_BOUND')
 write_all(3,data);os.fsync(3)
def fingerprint(file,expected):
 require(os.path.realpath(file)==file,'SOURCE_PATH')
 node=CONF['root']+'/tasks/runtime/node/node_modules/node/bin/node'
 runtime=file==node
 browser=file==CONF.get('browser') and file=='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
 alias=CONF['root']+'/tasks/runtime/node/node_modules/node/node_modules/node-bin-darwin-arm64/bin/node'
 fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);other=None
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_nlink>=1 if browser else s.st_nlink==(2 if runtime else 1)) and 0<s.st_size<=268435456,'SOURCE_FILE')
  keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_nlink')
  if browser:
   require(s.st_uid==os.getuid() and os.getuid()==os.geteuid() and s.st_gid in set(os.getgroups())|{os.getgid(),os.getegid()} and stat.S_IMODE(s.st_mode) in (0o755,0o775),'SOURCE_FILE')
   keys=(*keys,'st_gid')
  if runtime:
   require(CONF['node']==node and os.path.realpath(alias)==alias,'SOURCE_PATH')
   require(s.st_uid==os.getuid() and not s.st_mode&0o022 and s.st_mode&0o111,'SOURCE_FILE')
   other=os.open(alias,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   peer=os.fstat(other);require(all(getattr(s,k)==getattr(peer,k) for k in keys),'SOURCE_CHANGED')
  h=hashlib.sha256();total=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   total+=len(b);require(total<=s.st_size,'SOURCE_CHANGED');h.update(b)
  after=os.fstat(fd);current=os.lstat(file)
  require(total==s.st_size and all(getattr(s,k)==getattr(after,k)==getattr(current,k) for k in keys) and h.hexdigest()==expected,'SOURCE_CHANGED')
  if runtime:
   peer=os.fstat(other);named=os.lstat(alias)
   require(os.path.realpath(alias)==alias and all(getattr(s,k)==getattr(peer,k)==getattr(named,k) for k in keys),'SOURCE_CHANGED')
 finally:
  try:
   if other is not None:os.close(other)
  finally:os.close(fd)
def load_inventory():
 filename=CONF['root']+'/tests/postgres/darwin_process_inventory.py'
 fingerprint(filename,CONF['pins']['tests/postgres/darwin_process_inventory.py'])
 spec=importlib.util.spec_from_file_location('system_original_inventory',filename)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def birth(api,pid):
 row=api.identity(pid)
 return None if row is None else (row.start_sec,row.start_usec,row.pgid,row.uid,row.ruid)
def executable(api,pid):
 fn=api.library.proc_pidpath;fn.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32];fn.restype=ctypes.c_int
 buffer=ctypes.create_string_buffer(4096);size=fn(pid,buffer,len(buffer))
 require(0<size<len(buffer),'BROWSER_EXECUTABLE');return buffer.value.decode('utf-8','strict')
def private_directory(folder):
 s=os.lstat(folder)
 require(os.path.realpath(folder)==folder and stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'BROWSER_DIRECTORY')
 return (s.st_dev,s.st_ino)
def read_browser_record():
 filename=CONF['directory']+'/browser-birth.json'
 try:fd=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except FileNotFoundError:return None
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink in (1,2) and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=4096,'BROWSER_RECORD')
  raw=os.read(fd,4097);after=os.fstat(fd);current=os.lstat(filename)
  require(len(raw)==s.st_size and all(getattr(s,k)==getattr(after,k)==getattr(current,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_uid','st_mode')),'BROWSER_RECORD')
  row=json.loads(raw)
  require(type(row) is dict and list(row)==['version','runId','workerPid','browserPid','profilePath'] and raw==json.dumps(row,separators=(',',':'),ensure_ascii=False).encode()+b'\n','BROWSER_RECORD')
  require(type(row['version']) is int and row['version']==1 and row['runId']==CONF['runId'] and all(type(row[k]) is int and row[k]>1 for k in ('workerPid','browserPid')),'BROWSER_RECORD')
  require(type(row['profilePath']) is str and re.fullmatch(re.escape(CONF['temporary'])+r'/owasp-ai-goat-role-policy-instruction-[A-Za-z0-9]{6}',row['profilePath']),'BROWSER_PROFILE')
  try:partial=os.lstat(filename+'.partial')
  except FileNotFoundError:partial=None
  if s.st_nlink==2:
   # Exclusive link publication has a brief known two-name interval. Never
   # admit it: validate complete canonical bytes, prove only that transition,
   # then defer under the original work deadline for a fresh stable read.
   if partial is None:
    settled=os.fstat(fd);settled_path=os.lstat(filename)
    require(after.st_nlink in (1,2) and current.st_nlink in (1,2) and settled.st_nlink==settled_path.st_nlink==1 and settled.st_ctime_ns==settled_path.st_ctime_ns,'BROWSER_RECORD')
    require(all(getattr(s,k)==getattr(settled,k)==getattr(settled_path,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_uid','st_mode')),'BROWSER_RECORD')
   else:
    require(after.st_nlink==current.st_nlink==partial.st_nlink==2 and all(getattr(s,k)==getattr(after,k)==getattr(current,k)==getattr(partial,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_uid','st_mode')),'BROWSER_RECORD')
   return None
  require(after.st_nlink==current.st_nlink==1 and s.st_ctime_ns==after.st_ctime_ns==current.st_ctime_ns and partial is None,'BROWSER_RECORD')
  return row,hashlib.sha256(raw).hexdigest()
 finally:os.close(fd)
def ancestry_require(ok,predicate,pid):
 if ok:return
 error=RuntimeError('BROWSER_ANCESTRY')
 try:
  require(predicate in ('launcher-birth','cycle-or-pid','identity','uid','group','session','executable','argv0','worker-test','identity-reread','depth','launcher-rejoin') and type(pid) is int and 0<=pid<=2147483647,'ANCESTRY_DIAGNOSTIC')
  journal(dict(stage='browser-ancestry-rejected',predicate=predicate,pid=pid))
 except BaseException:error.ancestry_diagnostic_unjoined=True
 raise error
def validated_browser(row,proc,identity,api):
 ancestry_require(identity is not None and birth(api,proc.pid)==identity,'launcher-birth',proc.pid)
 fingerprint(CONF['node'],CONF['nodeSha256']);fingerprint(CONF['browser'],CONF['browserSha256'])
 # fingerprint proves these exact two names are the same immutable inode.
 node_paths=(CONF['node'],CONF['root']+'/tasks/runtime/node/node_modules/node/node_modules/node-bin-darwin-arm64/bin/node')
 seen=set();pid=row['workerPid']
 for _ in range(16):
  ancestry_require(pid not in seen and pid>1,'cycle-or-pid',pid);seen.add(pid)
  first=api.identity(pid);ancestry_require(first is not None,'identity',pid)
  ancestry_require(first.uid==os.getuid() and first.ruid==os.getuid(),'uid',pid)
  ancestry_require(first.pgid==proc.pid,'group',pid)
  ancestry_require(os.getsid(pid)==proc.pid,'session',pid)
  args=api.arguments(pid)
  first_path=executable(api,pid)
  ancestry_require(first_path in node_paths,'executable',pid)
  ancestry_require(bool(args) and args[0]==CONF['node'],'argv0',pid)
  if pid==row['workerPid']:ancestry_require(CONF['test'] in args or CONF['root']+'/'+CONF['test'] in args,'worker-test',pid)
  second=api.identity(pid)
  ancestry_require(second is not None and all(getattr(first,k)==getattr(second,k) for k in ('pid','ppid','pgid','uid','ruid','start_sec','start_usec')) and executable(api,pid)==first_path,'identity-reread',pid)
  if pid==proc.pid:break
  pid=first.ppid
 else:ancestry_require(False,'depth',pid)
 ancestry_require(pid==proc.pid and birth(api,proc.pid)==identity,'launcher-rejoin',pid)
 fingerprint(CONF['node'],CONF['nodeSha256'])
 first=api.identity(row['browserPid']);require(first is not None and first.ppid==row['workerPid'] and first.uid==os.getuid() and first.ruid==os.getuid() and first.start_sec>0 and 0<=first.start_usec<1000000,'BROWSER_BIRTH')
 # Puppeteer's original Darwin launch owns a detached session. Never adopt
 # the controller, worker or another process's group as browser authority.
 require(first.pgid==row['browserPid'] and os.getsid(first.pid)==first.pgid,'BROWSER_GROUP')
 args=api.arguments(first.pid)
 require(executable(api,first.pid)==CONF['browser'] and args and args[0]==CONF['browser'] and [a for a in args if a.startswith('--user-data-dir=')]==['--user-data-dir='+row['profilePath']],'BROWSER_EXECUTABLE')
 profile_identity=private_directory(row['profilePath'])
 captured=(first.start_sec,first.start_usec,first.pgid,first.uid,first.ruid)
 require(birth(api,first.pid)==captured and api.identity(first.pid).ppid==row['workerPid'] and executable(api,first.pid)==CONF['browser'],'BROWSER_BIRTH')
 return dict(pid=first.pid,identity=captured,pgid=first.pgid,profile=row['profilePath'],profileIdentity=profile_identity,acknowledged=False)
def publish_browser_ack(row,deadline):
 filename=CONF['directory']+'/browser-ack.json';temporary=filename+'.partial';fd=None
 try:
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  write_all(fd,json.dumps(row,separators=(',',':'),ensure_ascii=False).encode()+b'\n');os.fsync(fd);os.close(fd);fd=None
  require(not CANCELLED and time.monotonic()<deadline,'INTERRUPTED')
  os.link(temporary,filename,follow_symlinks=False);os.unlink(temporary)
  directory=os.open(CONF['directory'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(directory)
  finally:os.close(directory)
 finally:
  if fd is not None:os.close(fd)
def observe_browser(state,proc,identity,api,deadline):
 require(not CANCELLED,'INTERRUPTED');require(time.monotonic()<deadline,'COHORT_DEADLINE')
 record=read_browser_record()
 if record is None:
  require(state.get('owned') is None,'BROWSER_RECORD');return
 row,digest=record
 if state.get('owned') is not None:require(state['digest']==digest,'BROWSER_RECORD');return
 state['attempted']=True
 owned=validated_browser(row,proc,identity,api);owned['workerPid']=row['workerPid'];owned['birthSha256']=digest;state['owned']=owned;state['digest']=digest
 ack=dict(version=1,runId=CONF['runId'],birthSha256=digest,workerPid=row['workerPid'],browserPid=owned['pid'],profilePath=owned['profile'],birth=list(owned['identity'][:2]),pgid=owned['pgid'])
 journal(dict(stage='browser-admitted',**ack));require(not CANCELLED and time.monotonic()<deadline,'INTERRUPTED')
 publish_browser_ack(ack,deadline);owned['acknowledged']=True
def retire_browser(owned,inventory,api,end):
 errors=[];births={owned['pid']:owned['identity'][:2]}
 for sig,seconds in ((signal.SIGTERM,1),(signal.SIGKILL,.75)):
  try:
   current=birth(api,owned['pid']);require(current is None or current==owned['identity'],'BROWSER_REUSED')
   members=inventory.owned_group_members(owned['pgid'],api=api,births=births)
   if members:
    require(time.monotonic()<end and (birth(api,owned['pid']) in (None,owned['identity'])) and inventory.owned_group_members(owned['pgid'],api=api,births=births)==members,'BROWSER_GROUP')
    os.killpg(owned['pgid'],sig)
   until=min(end,time.monotonic()+seconds)
   while time.monotonic()<until:
    if not api.group_pids(owned['pgid']):break
    time.sleep(.02)
  except ProcessLookupError:pass
  except BaseException:errors.append('BROWSER_RETIREMENT_UNPROVEN');break
 try:group_absent=not api.group_pids(owned['pgid']);process_absent=birth(api,owned['pid']) is None
 except BaseException:group_absent=False;process_absent=False
 profile_absent=False
 try:
  require(group_absent and process_absent and browser_absent(inventory,'profile-retirement'),'BROWSER_RETIREMENT_UNPROVEN')
  if os.path.lexists(owned['profile']):
   require(private_directory(owned['profile'])==owned['profileIdentity'],'BROWSER_PROFILE')
   shutil.rmtree(owned['profile'])
  profile_absent=not os.path.lexists(owned['profile'])
 except BaseException:errors.append('BROWSER_PROFILE_UNPROVEN')
 return dict(pid=owned['pid'],birth=list(owned['identity'][:2]),pgid=owned['pgid'],workerPid=owned['workerPid'],profilePath=owned['profile'],birthSha256=owned['birthSha256'],acknowledged=owned['acknowledged'],groupAbsent=group_absent,processAbsent=process_absent,profileAbsent=profile_absent,errors=errors)
CENSUS_DIAGNOSTICS=0
def browser_absent(inventory,stage):
 global CENSUS_DIAGNOSTICS
 require(stage in ('preflight','no-child','child-retirement','profile-retirement','final-retirement'),'CENSUS_STAGE')
 prefix='--user-data-dir='+CONF['temporary']+'/'
 try:
  rows=inventory.process_records(include_arguments=True)
 except BaseException as primary:
  if CENSUS_DIAGNOSTICS<4:
   CENSUS_DIAGNOSTICS+=1
   # Follow only the bounded explicit cause chain; never emit text or argv.
   code='unknown';current=primary
   for unused in range(3):
    if isinstance(current,OSError):
     code={1:'EPERM',2:'ENOENT',3:'ESRCH',5:'EIO',13:'EACCES',22:'EINVAL'}.get(current.errno,'other')
     break
    current=current.__cause__
    if current is None:break
   try:journal(dict(stage='browser-census-failure',operation='process-records',phase=stage,errno=code))
   except BaseException:pass
  raise
 return not any(arg.startswith(prefix) for row in rows for arg in (row['arguments'] or ()))
def profiles_absent():
 # Entire owner-created tmp directory, not a partial list of recognized names.
 return not os.listdir(CONF['temporary'])
def no_child_cleanup(inventory):
 # No child was launched, but a failed preflight is not proof that the
 # independently inventoried browser/profile namespace was empty.
 errors=[]
 try:browsers=browser_absent(inventory,'no-child')
 except BaseException:browsers=False;errors.append('BROWSER_INVENTORY_UNPROVEN')
 try:profiles=profiles_absent()
 except BaseException:profiles=False;errors.append('PROFILE_INVENTORY_UNPROVEN')
 return dict(pid=None,birth=None,reaped=True,groupAbsent=True,browserProcessesAbsent=browsers,profilesAbsent=profiles,errors=errors)
def retire(proc,identity,inventory,api,end=None):
 errors=[];births={};end=time.monotonic()+4 if end is None else end
 if identity is not None:births[proc.pid]=identity[:2]
 else:errors.append('GROUP_RETIREMENT_UNPROVEN')
 for sig,seconds in ((signal.SIGTERM,2),(signal.SIGKILL,1.5)):
  try:
   members=inventory.owned_group_members(proc.pid,api=api,births=births)
   if members:
    require(identity is not None,'CHILD_BIRTH_UNKNOWN')
    current=birth(api,proc.pid)
    # Do not adopt a reused leader. A missing/reaped original leader does not
    # erase its still-owned group members; each member is birth checked above.
    require(current is None or current==identity,'CHILD_REUSED')
    require(inventory.owned_group_members(proc.pid,api=api,births=births)==members,'GROUP_CHANGED')
    os.killpg(proc.pid,sig)
   until=min(end,time.monotonic()+seconds)
   while time.monotonic()<until:
    proc.poll()
    if not inventory.owned_group_members(proc.pid,api=api,births=births):break
    time.sleep(.02)
  except ProcessLookupError:pass
  except BaseException:errors.append('GROUP_RETIREMENT_UNPROVEN');break
 try:proc.wait(timeout=max(.001,end-time.monotonic()))
 except BaseException:errors.append('CHILD_WAIT_UNPROVEN')
 try:group_absent=not api.group_pids(proc.pid)
 except BaseException:group_absent=False
 try:browsers=browser_absent(inventory,'child-retirement')
 except BaseException:browsers=False;errors.append('BROWSER_INVENTORY_UNPROVEN')
 try:profiles=profiles_absent()
 except BaseException:profiles=False;errors.append('PROFILE_INVENTORY_UNPROVEN')
 return dict(pid=proc.pid,birth=list(identity[:2]) if identity else None,reaped=proc.returncode is not None,
  groupAbsent=group_absent,browserProcessesAbsent=browsers,profilesAbsent=profiles,errors=errors)
def read_input():
 # One absolute frame deadline, not a renewed timeout per byte.
 raw=bytearray();end=time.monotonic()+2;sel=selectors.DefaultSelector()
 try:
  os.set_blocking(0,False);sel.register(0,selectors.EVENT_READ)
  while True:
   require(not CANCELLED and time.monotonic()<end,'INPUT_DEADLINE')
   if not sel.select(min(.05,end-time.monotonic())):continue
   part=os.read(0,4096)
   if not part:break
   raw.extend(part);require(len(raw)<=65536,'INPUT_BOUND')
 finally:sel.close()
 def unique(rows):
  result={}
  for k,v in rows:
   require(k not in result,'INPUT_DUPLICATE');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=unique)
def run(inventory,api,settings):
 proc=None;identity=None;selector=None;failure=None;cleanup=None;count=0;h=hashlib.sha256();errors=[];browser_state={};browser_cleanup=None
 # Set once at controller admission, before inventory/source loading. The
 # parent also enforces its original absolute deadline across pipe transfer.
 end=settings['deadline']
 try:
  require(not CANCELLED and time.monotonic()<end,'INTERRUPTED')
  for name,value in CONF['pins'].items():fingerprint(CONF['root']+'/'+name,value)
  for name in ('node','browser'):fingerprint(CONF[name],CONF[name+'Sha256'])
  private_directory(CONF['directory']);private_directory(CONF['temporary'])
  require(not any(os.path.lexists(CONF['directory']+'/'+name) for name in ('browser-birth.json','browser-birth.json.partial','browser-ack.json','browser-ack.json.partial')),'BROWSER_PREEXISTING_RECORD')
  require(browser_absent(inventory,'preflight') and profiles_absent(),'PREEXISTING_BROWSER')
  journal(dict(stage='original-child-intent',runId=CONF['runId'],fixtureSha256=CONF['pins'][CONF['test']]))
  require(not CANCELLED and time.monotonic()<end,'INTERRUPTED')
  proc=subprocess.Popen([CONF['node'],'--test','--test-reporter=tap','--test-concurrency=1',CONF['test']],cwd=CONF['root'],
   env=settings['env'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,close_fds=True,umask=0o077)
  identity=birth(api,proc.pid)
  require(identity is not None and identity[2]==proc.pid and identity[3:]==(os.getuid(),os.getuid()),'CHILD_BIRTH_UNKNOWN')
  journal(dict(stage='original-child-birth',pid=proc.pid,birth=list(identity[:2])))
  selector=selectors.DefaultSelector();os.set_blocking(proc.stdout.fileno(),False);selector.register(proc.stdout,selectors.EVENT_READ)
  while selector.get_map():
   require(not CANCELLED,'INTERRUPTED');require(time.monotonic()<end,'COHORT_DEADLINE')
   observe_browser(browser_state,proc,identity,api,end)
   for key,_ in selector.select(min(.05,max(0,end-time.monotonic()))):
    chunk=os.read(key.fd,65536)
    if not chunk:selector.unregister(key.fileobj);continue
    count+=len(chunk);require(count<=8388608,'TAP_BOUND');write_all(4,chunk);h.update(chunk)
  observe_browser(browser_state,proc,identity,api,end)
  proc.wait(timeout=max(.001,end-time.monotonic()))
  if proc.returncode!=0:failure='ORIGINAL_TEST_FAILED'
  elif not browser_state.get('owned',{}).get('acknowledged'):failure='BROWSER_NOT_ACKNOWLEDGED'
 except BaseException as error:
  code=str(error);failure=code if code in ('INTERRUPTED','COHORT_DEADLINE','TAP_BOUND','SOURCE_CHANGED','SOURCE_PATH','SOURCE_FILE','PREEXISTING_BROWSER','CHILD_BIRTH_UNKNOWN','BROWSER_RECORD','BROWSER_PROFILE','BROWSER_ANCESTRY','BROWSER_BIRTH','BROWSER_GROUP','BROWSER_EXECUTABLE','BROWSER_DIRECTORY','BROWSER_PREEXISTING_RECORD') else 'ORIGINAL_CHILD_FAILED'
  if getattr(error,'ancestry_diagnostic_unjoined',False):errors.append('ANCESTRY_DIAGNOSTIC_UNJOINED')
 finally:
  retirement_end=time.monotonic()+4
  if selector is not None:
   try:selector.close()
   except BaseException:errors.append('SELECTOR_CLOSE')
  if proc is not None:
   cleanup=retire(proc,identity,inventory,api,retirement_end)
   try:proc.stdout.close()
   except BaseException:errors.append('PIPE_CLOSE')
  else:
   cleanup=no_child_cleanup(inventory)
  if browser_state.get('owned') is not None:
   browser_cleanup=retire_browser(browser_state['owned'],inventory,api,retirement_end)
   # Re-evaluate exact owned profile and detached-process absence after the
   # independently captured browser group has been retired.
   try:cleanup['browserProcessesAbsent']=browser_absent(inventory,'final-retirement');cleanup['profilesAbsent']=profiles_absent()
   except BaseException:cleanup['errors'].append('BROWSER_INVENTORY_UNPROVEN')
  elif browser_state.get('attempted'):cleanup['errors'].append('BROWSER_ADMISSION_UNPROVEN')
  try:os.fsync(4)
  except BaseException:errors.append('TAP_FSYNC')
  try:
   for name,value in CONF['pins'].items():fingerprint(CONF['root']+'/'+name,value)
   for name in ('node','browser'):fingerprint(CONF[name],CONF[name+'Sha256'])
  except BaseException:failure=failure or 'SOURCE_CHANGED'
  cleanup['errors'].extend(errors)
 verified=all(cleanup[k] for k in ('reaped','groupAbsent','browserProcessesAbsent','profilesAbsent')) and not cleanup['errors'] and (browser_cleanup is None or all(browser_cleanup[k] for k in ('groupAbsent','processAbsent','profileAbsent')) and not browser_cleanup['errors'])
 packet=dict(version=1,runId=CONF['runId'],exitCode=proc.returncode if proc else None,child=cleanup,
  browser=browser_cleanup,cleanupVerified=verified,failure=failure,tap=dict(bytes=count,sha256=h.hexdigest()))
 try:journal(dict(stage='original-child-terminal',**packet))
 except BaseException:
  packet['cleanupVerified']=False;packet['child']['errors'].append('TERMINAL_JOURNAL_FAILED')
 write_all(1,json.dumps(packet,separators=(',',':')).encode())
 return 2 if not packet['cleanupVerified'] else 1 if packet['failure'] else 0
def main():
 require(sys.platform=='darwin','PLATFORM')
 private_fd(3);require(private_fd(4).st_size==0,'TAP_NOT_EMPTY')
 def abort(signum,frame):
  global CANCELLED
  CANCELLED=True
 signal.signal(signal.SIGTERM,abort);signal.signal(signal.SIGINT,abort)
 # Capture the child clock BEFORE readiness. The parent only samples its
 # remaining original budget after observing this exact frame; IPC latency
 # therefore consumes time, never grants a fresh controller window.
 started=time.monotonic()
 write_all(1,json.dumps(dict(version=1,stage='ready',runId=CONF['runId']),separators=(',',':')).encode()+b'\n')
 settings=read_input()
 require(type(settings) is dict and set(settings)=={'env','remainingMs'},'INPUT_SCHEMA')
 require(type(settings['remainingMs']) in (int,float) and 0<settings['remainingMs']<=900000,'INPUT_DEADLINE')
 require(type(settings['env']) is dict and set(settings['env'])==set(CONF['environmentKeys']) and all(type(v) is str for v in settings['env'].values()),'ENV_SCHEMA')
 require(hashlib.sha256(json.dumps(settings['env'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()==CONF['environmentSha256'],'ENV_BINDING')
 settings['deadline']=started+settings['remainingMs']/1000
 require(not CANCELLED and time.monotonic()<settings['deadline'],'INPUT_DEADLINE')
 inventory=load_inventory();return run(inventory,inventory.LibProc(),settings)
`;

function validateOptions(value){
 if(!exact(value,'root,runId,producer,signal,node,nodeSha256,pythonSha256,browser,browserSha256,pgNonce,pgPort,policyVersion')
  ||!['configuration-readability-relative-v3','configuration-readability-token-contrast-v4','configuration-readability-paired-fields-v5'].includes(value.policyVersion)
  ||value.root!==ROOT||!/^[a-f0-9]{32}$/.test(value.runId)||!(value.signal instanceof AbortSignal)
  ||value.node!==NODE||value.browser!==BROWSER
  ||![value.nodeSha256,value.pythonSha256,value.browserSha256].every(digest)
  ||!/^[a-f0-9]{12}$/.test(value.pgNonce)||!integer(value.pgPort,1024)||value.pgPort>65535
  ||!value.producer||value.producer.root!==ROOT||value.producer.runId!==value.runId)throw fail('SYSTEM_ORIGINAL_OPTIONS');
 return value;
}
function locations(options){
 const directory=path.join(ROOT,'tasks/qualification','system-original-owner-'+options.runId);
 return {directory,temporary:path.join(directory,'runtime/tmp'),runtime:path.join(directory,'runtime'),
  tap:path.join(directory,'original.tap'),journal:path.join(directory,'owner.ndjson')};
}
function childEnvironment(options,endpoint){
 validateOptions(options);
 const origin=value=>typeof value==='string'&&/^http:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/.test(value)
  &&Number(value.slice(value.lastIndexOf(':')+1))>=1024&&Number(value.slice(value.lastIndexOf(':')+1))<=65535;
 if(!exact(endpoint,'system,policy,signal,deadline')||!(endpoint.signal instanceof AbortSignal)
  ||!exact(endpoint.system,'client,port,baseURL,token')||!exact(endpoint.policy,'client,port,baseURL')
  ||![endpoint.system,endpoint.policy].every(v=>origin(v.baseURL)&&Number(v.baseURL.slice(v.baseURL.lastIndexOf(':')+1))===v.port)
  ||endpoint.system.baseURL===endpoint.policy.baseURL
  ||typeof endpoint.system.token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(endpoint.system.token)
  ||!Number.isFinite(endpoint.deadline)||endpoint.deadline<=performance.now()||endpoint.deadline-performance.now()>900000)throw fail('SYSTEM_ORIGINAL_ENDPOINT');
 const p=locations(options),env={PATH:path.dirname(options.node)+':/usr/bin:/bin',HOME:p.runtime,TMPDIR:p.temporary,TMP:p.temporary,TEMP:p.temporary,MAC_CHROMIUM_TMPDIR:p.temporary,
  NODE_ENV:'test',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',PG_TEST_DISPOSABLE:'yes',
  AWS_EC2_METADATA_DISABLED:'true',LOGS_DIR:path.join(p.runtime,'logs'),SECURESHOP_UPLOAD_ROOT:path.join(p.runtime,'uploads'),
  SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_VERSION:options.policyVersion,
  SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE:'1',SECURESHOP_POLICY_INSTRUCTION_BROWSER_TEST_NO_SANDBOX:'1',LIVE_OLLAMA_TEST:'1',LAB_MODE:'vuln',OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE:ROOT,
  SECURESHOP_POLICY_INSTRUCTION_BROWSER_RENDERER_TRANSPORT:'owned-pair-v1',
  SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_RENDERER_URL:endpoint.policy.baseURL,
  SECURESHOP_POLICY_INSTRUCTION_BROWSER_BUILD:path.join(ROOT,'client/build'),
  SECURESHOP_POLICY_INSTRUCTION_BROWSER_EVIDENCE_PATH:path.join(p.directory,'policy-instruction-browser.json'),
  SECURESHOP_POLICY_INSTRUCTION_BROWSER_SYSTEM_URL:endpoint.system.baseURL,SECURESHOP_POLICY_INSTRUCTION_BROWSER_SYSTEM_TOKEN:endpoint.system.token,
  SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_RUN_ID:options.runId,SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_DIRECTORY:p.directory,
  SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_BROWSER_SHA256:options.browserSha256,
  PUPPETEER_EXECUTABLE_PATH:options.browser,AI_PROVIDER:'ollama',JUDGE_PROVIDER:'ollama',JUDGE_MODEL:'llama3.1:8b',
  SS_DISABLE_OLLAMA:'false',SS_ENABLE_REAL_LLM_TESTS:'true',OLLAMA_BASE_URL:'http://127.0.0.1:11434',OLLAMA_MODEL:'llama3.1:8b'};
 for(const [role,store]of [['IDENTITY','identity'],['AGENTS','secureshop_agents'],['REVIEW','secureshop_review'],['COMMERCE','secureshop']])
  for(const type of ['runtime','migration'])env['PG_SECURESHOP_POLICY_INSTRUCTION_BROWSER_'+role+'_'+type.toUpperCase()+'_URL']=
   `postgresql://dvaia_${store}_${type}@127.0.0.1:${options.pgPort}/owasp_ai_goat_test_agent_host_${options.pgNonce}_${store}`;
 return Object.freeze(env);
}
function controllerProgram(options,environmentKeys,environment){
 const p=locations(options),conf={root:ROOT,runId:options.runId,test:TEST,node:options.node,nodeSha256:options.nodeSha256,
  browser:options.browser,browserSha256:options.browserSha256,
  temporary:p.temporary,directory:p.directory,pins:PINS,environmentKeys,
  environmentSha256:sha(JSON.stringify(Object.fromEntries(Object.entries(environment).sort(([a],[b])=>a<b?-1:a>b?1:0))))};
 return 'import json\nCONF=json.loads('+JSON.stringify(JSON.stringify(conf))+')\n'+CONTROLLER+
  '\nif __name__=="__main__":\n try:code=main()\n except BaseException:code=2\n sys.exit(code)\n';
}
async function fileHash(file,max=256*1024**2){
 if(await fs.realpath(file)!==file)throw fail('SYSTEM_ORIGINAL_PATH');
 const fd=await fs.open(file,native.constants.O_RDONLY|native.constants.O_NOFOLLOW);
 let primary;
 try{const before=await fd.stat();if(!before.isFile()||before.nlink!==1||before.size<=0||before.size>max)throw fail('SYSTEM_ORIGINAL_FILE');
  const h=crypto.createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;
  for(;;){const {bytesRead}=await fd.read(buffer,0,buffer.length,null);if(!bytesRead)break;total+=bytesRead;if(total>before.size)throw fail('SYSTEM_ORIGINAL_CHANGED');h.update(buffer.subarray(0,bytesRead));}
  const after=await fd.stat(),current=await fs.lstat(file);
  if(total!==before.size||!['dev','ino','size','mtimeMs','ctimeMs'].every(k=>before[k]===after[k]&&before[k]===current[k]))throw fail('SYSTEM_ORIGINAL_CHANGED');
  return h.digest('hex');
 }catch(error){primary=error;throw error;}
 finally{
  try{await fd.close();}
  catch(error){throw Object.assign(primary||error,{validationIoUnjoined:true});}
 }
}
async function browserRuntimeHash(file){
 if(file!==BROWSER||await fs.realpath(file)!==file)throw fail('SYSTEM_ORIGINAL_PATH');
 const fd=await fs.open(file,native.constants.O_RDONLY|native.constants.O_NOFOLLOW|native.constants.O_NONBLOCK);
 let primary;
 try{
  const before=await fd.stat(),keys=['dev','ino','size','mtimeMs','ctimeMs','mode','uid','gid','nlink'];
  const same=value=>keys.every(k=>before[k]===value[k]);
  if(!before.isFile()||before.nlink<1||before.uid!==process.getuid()||process.getuid()!==process.geteuid()
   ||!new Set([...process.getgroups(),process.getgid(),process.getegid()]).has(before.gid)
   ||![0o755,0o775].includes(before.mode&0o7777)||before.size<=0||before.size>256*1024**2)throw fail('SYSTEM_ORIGINAL_FILE');
  const hash=crypto.createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;
  for(;;){const {bytesRead}=await fd.read(buffer,0,buffer.length,null);if(!bytesRead)break;
   total+=bytesRead;if(total>before.size)throw fail('SYSTEM_ORIGINAL_CHANGED');hash.update(buffer.subarray(0,bytesRead));}
  if(total!==before.size||![await fd.stat(),await fs.lstat(file)].every(same)||await fs.realpath(file)!==file)throw fail('SYSTEM_ORIGINAL_CHANGED');
  return hash.digest('hex');
 }catch(error){primary=error;throw error;}
 finally{try{await fd.close();}catch(error){throw Object.assign(primary||error,{validationIoUnjoined:true});}}
}
async function nodeRuntimeHash(file){
 if(file!==NODE||await fs.realpath(file)!==file||await fs.realpath(NODE_PACKAGE)!==NODE_PACKAGE)throw fail('SYSTEM_ORIGINAL_NODE_PATH');
 let fd,alias,primary;
 try{
  const flags=native.constants.O_RDONLY|native.constants.O_NOFOLLOW|native.constants.O_NONBLOCK;
  fd=await fs.open(file,flags);alias=await fs.open(NODE_PACKAGE,flags);
  const before=await fd.stat(),peer=await alias.stat();
  const keys=['dev','ino','size','mtimeMs','ctimeMs','mode','uid','nlink'];
  const same=value=>keys.every(k=>before[k]===value[k]);
  if(!before.isFile()||!peer.isFile()||before.nlink!==2||before.uid!==process.getuid()
   ||(before.mode&0o022)!==0||!(before.mode&0o111)||before.size<=0||before.size>256*1024**2||!same(peer))throw fail('SYSTEM_ORIGINAL_NODE_FILE');
  const hash=crypto.createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;
  for(;;){const {bytesRead}=await fd.read(buffer,0,buffer.length,null);if(!bytesRead)break;
   total+=bytesRead;if(total>before.size)throw fail('SYSTEM_ORIGINAL_NODE_CHANGED');hash.update(buffer.subarray(0,bytesRead));}
  if(total!==before.size||![await fd.stat(),await alias.stat(),await fs.lstat(file),await fs.lstat(NODE_PACKAGE)].every(same)
   ||await fs.realpath(file)!==file||await fs.realpath(NODE_PACKAGE)!==NODE_PACKAGE)throw fail('SYSTEM_ORIGINAL_NODE_CHANGED');
  return hash.digest('hex');
 }catch(error){primary=error;throw error;}
 finally{
  // Attempt both closes even if one descriptor reports an error.
  const results=await Promise.allSettled([alias?.close(),fd?.close()]);
  const error=results.find(row=>row.status==='rejected');if(error)throw Object.assign(primary||error.reason,{validationIoUnjoined:true});
 }
}
async function preflightOriginalRuntime(value){
 if(!exact(value,'root,node,nodeSha256,browser,browserSha256')||value.root!==ROOT||value.node!==NODE||value.browser!==BROWSER
  ||![value.nodeSha256,value.browserSha256].every(digest))throw fail('SYSTEM_ORIGINAL_PREFLIGHT');
 for(const [name,expected]of Object.entries(PINS))if(await fileHash(path.join(ROOT,name))!==expected)throw fail('SYSTEM_ORIGINAL_SOURCE');
 if(await nodeRuntimeHash(value.node)!==value.nodeSha256||await browserRuntimeHash(value.browser)!==value.browserSha256)throw fail('SYSTEM_ORIGINAL_SOURCE');
 return Object.freeze({version:1,validated:true});
}
function validateTerminal(value,runId){
 if(!exact(value,'version,runId,exitCode,child,browser,cleanupVerified,failure,tap')||value.version!==1||value.runId!==runId
  ||!(value.exitCode===null||Number.isInteger(value.exitCode)&&value.exitCode>=-127&&value.exitCode<=255)
  ||typeof value.cleanupVerified!=='boolean'||!(value.failure===null||['INTERRUPTED','COHORT_DEADLINE','TAP_BOUND','SOURCE_CHANGED','SOURCE_PATH','SOURCE_FILE','PREEXISTING_BROWSER','CHILD_BIRTH_UNKNOWN','ORIGINAL_TEST_FAILED','ORIGINAL_CHILD_FAILED','BROWSER_NOT_ACKNOWLEDGED','BROWSER_RECORD','BROWSER_PROFILE','BROWSER_ANCESTRY','BROWSER_BIRTH','BROWSER_GROUP','BROWSER_EXECUTABLE','BROWSER_DIRECTORY','BROWSER_PREEXISTING_RECORD'].includes(value.failure))
  ||!exact(value.tap,'bytes,sha256')||!integer(value.tap.bytes)||value.tap.bytes>LIMITS.tap||!digest(value.tap.sha256))throw fail('SYSTEM_ORIGINAL_TERMINAL');
 const c=value.child,b=value.browser,validBirth=v=>Array.isArray(v)&&v.length===2&&integer(v[0],1)&&integer(v[1])&&v[1]<1000000;
 if(!exact(c,'pid,birth,reaped,groupAbsent,browserProcessesAbsent,profilesAbsent,errors')
  ||!(c.pid===null||integer(c.pid,2))||!(c.birth===null||validBirth(c.birth))
  ||!['reaped','groupAbsent','browserProcessesAbsent','profilesAbsent'].every(k=>typeof c[k]==='boolean')
  ||!Array.isArray(c.errors)||c.errors.length>12||!c.errors.every(v=>['GROUP_RETIREMENT_UNPROVEN','CHILD_WAIT_UNPROVEN','BROWSER_INVENTORY_UNPROVEN','PROFILE_INVENTORY_UNPROVEN','BROWSER_ADMISSION_UNPROVEN','SELECTOR_CLOSE','PIPE_CLOSE','TAP_FSYNC','TERMINAL_JOURNAL_FAILED'].includes(v)))throw fail('SYSTEM_ORIGINAL_TERMINAL');
 if(b!==null&&(!exact(b,'pid,birth,pgid,workerPid,profilePath,birthSha256,acknowledged,groupAbsent,processAbsent,profileAbsent,errors')
  ||!integer(b.pid,2)||b.pgid!==b.pid||b.pid===c.pid||!integer(b.workerPid,2)||b.workerPid===b.pid||!validBirth(b.birth)||!digest(b.birthSha256)
  ||typeof b.profilePath!=='string'||path.dirname(b.profilePath)!==path.join(ROOT,'tasks/qualification','system-original-owner-'+runId,'runtime/tmp')
  ||!/^owasp-ai-goat-role-policy-instruction-[A-Za-z0-9]{6}$/.test(path.basename(b.profilePath))
  ||!['acknowledged','groupAbsent','processAbsent','profileAbsent'].every(k=>typeof b[k]==='boolean')
  ||!Array.isArray(b.errors)||b.errors.length>3||!b.errors.every(e=>['BROWSER_RETIREMENT_UNPROVEN','BROWSER_PROFILE_UNPROVEN'].includes(e))))throw fail('SYSTEM_ORIGINAL_TERMINAL');
 const retired=['reaped','groupAbsent','browserProcessesAbsent','profilesAbsent'].every(k=>c[k])&&c.errors.length===0
  &&(b===null||['groupAbsent','processAbsent','profileAbsent'].every(k=>b[k])&&b.errors.length===0);
 if(value.cleanupVerified!==retired)throw fail('SYSTEM_ORIGINAL_TERMINAL');
 if(c.pid===null&&(c.birth!==null||value.exitCode!==null)||value.cleanupVerified&&c.pid!==null&&(c.birth===null||value.exitCode===null))throw fail('SYSTEM_ORIGINAL_TERMINAL');
 if(value.failure===null&&(c.pid===null||c.birth===null||value.exitCode!==0||b===null||!b.acknowledged))throw fail('SYSTEM_ORIGINAL_TERMINAL');
 return value;
}
async function verifyTap(handle,expected){
 const before=await handle.stat();
 if(!before.isFile()||before.nlink!==1||before.size!==expected.bytes||before.size>LIMITS.tap)throw fail('SYSTEM_ORIGINAL_TAP');
 const h=crypto.createHash('sha256'),buffer=Buffer.alloc(65536);let position=0;
 while(position<before.size){
  const {bytesRead}=await handle.read(buffer,0,Math.min(buffer.length,before.size-position),position);
  if(!bytesRead)throw fail('SYSTEM_ORIGINAL_TAP');h.update(buffer.subarray(0,bytesRead));position+=bytesRead;
 }
 const after=await handle.stat();
 if(!['dev','ino','size','mtimeMs','ctimeMs'].every(k=>before[k]===after[k])||h.digest('hex')!==expected.sha256)throw fail('SYSTEM_ORIGINAL_TAP');
}

async function ownChild(options,endpoint,journal,tap){
 const env=childEnvironment(options,endpoint);endpoint.signal.throwIfAborted();
 const python=await fs.realpath(PYTHON);
 if(await fileHash(python)!==options.pythonSha256)throw fail('SYSTEM_ORIGINAL_PYTHON');
 const source=controllerProgram(options,Object.keys(env),env);
 const intent=Buffer.from(JSON.stringify({stage:'controller-intent',runId:options.runId,sourceSha256:sha(source)})+'\n');
 native.writeFileSync(journal.fd,intent);native.fsyncSync(journal.fd);
 endpoint.signal.throwIfAborted();if(performance.now()>=endpoint.deadline)throw fail('SYSTEM_ORIGINAL_DEADLINE');
 return new Promise((resolve,reject)=>{
  let child,primary,closed=false,ready=false,readyBytes=Buffer.alloc(0),stopTimer,killTimer,deadlineTimer,terminalBytes=0,stderrBytes=0;const chunks=[];
  const readyFrame=Buffer.from(JSON.stringify({version:1,stage:'ready',runId:options.runId})+'\n');
  const stop=error=>{
   primary ||= error;
   if(!stopTimer){
    try{if(child&&child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');}catch(e){primary ||= e;}
    killTimer=setTimeout(()=>{try{if(child&&child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');}catch{}},4500);
    stopTimer=setTimeout(()=>finish(Object.assign(fail('SYSTEM_ORIGINAL_CONTROLLER_UNJOINED'),{retirementUnproven:true})),LIMITS.controllerJoin);
   }
  };
  const abort=()=>stop(endpoint.signal.reason||fail('SYSTEM_ORIGINAL_INTERRUPTED'));
  const finish=(error,controllerCode)=>{
   if(closed)return;closed=true;clearTimeout(deadlineTimer);clearTimeout(stopTimer);clearTimeout(killTimer);endpoint.signal.removeEventListener('abort',abort);
   for(const stream of [child?.stdin,child?.stdout,child?.stderr])try{stream?.destroy();}catch{}
   if(error){if(primary&&primary!==error)error.cause=primary;if(error.retirementUnproven)child?.unref();reject(error);}else{
    try{if(!ready)throw fail('SYSTEM_ORIGINAL_READY');
     const packet=validateTerminal(JSON.parse(Buffer.concat(chunks).toString('utf8')),options.runId);
     if(controllerCode!==(packet.cleanupVerified?(packet.failure?1:0):2))throw fail('SYSTEM_ORIGINAL_CONTROLLER_STATUS');
     if(!packet.cleanupVerified)throw Object.assign(fail('SYSTEM_ORIGINAL_RETIREMENT_UNPROVEN'),{retirementUnproven:true,packet});
     // Join retained private TAP bytes, not just the controller's JSON claim.
     // A readback failure after proven retirement fails evidence but does not
     // invent an active child or permit a successful qualification.
     void verifyTap(tap,packet.tap).then(()=>{
      if(primary)reject(Object.assign(primary,{packet}));
      else if(packet.failure||packet.exitCode!==0)reject(Object.assign(fail('SYSTEM_ORIGINAL_TEST_FAILED'),{packet}));
      else resolve(packet);
     },e=>reject(Object.assign(primary||e,{packet,...(primary?{evidenceFailure:e}:{})})));
    }catch(e){if(primary&&primary!==e)e.cause=primary;if(!e.packet)e.retirementUnproven=true;reject(e);}
   }
  };
  try{
   child=spawn(python,['-B','-c',source],{cwd:ROOT,env:{PATH:'/usr/bin:/bin',HOME:locations(options).runtime,PYTHONDONTWRITEBYTECODE:'1'},
    stdio:['pipe','pipe','pipe',journal.fd,tap.fd]});
   // Install all error/close handlers before any fallible post-spawn action.
   child.on('error',error=>stop(error));for(const stream of [child.stdin,child.stdout,child.stderr])stream.on('error',error=>stop(error));
   child.stdout.on('data',chunk=>{
    if(closed)return;
    terminalBytes+=chunk.length;
    if(terminalBytes>LIMITS.terminal){stop(fail('SYSTEM_ORIGINAL_OUTPUT_BOUND'));return;}
    if(ready){chunks.push(chunk);return;}
    readyBytes=Buffer.concat([readyBytes,chunk]);
    // Before input is sent there can be only the one exact ready frame, not
    // terminal output or a duplicate frame. Validate prefixes as they arrive.
    if(readyBytes.length>readyFrame.length||!readyFrame.subarray(0,readyBytes.length).equals(readyBytes)){
     stop(fail('SYSTEM_ORIGINAL_READY'));return;
    }
    if(readyBytes.length!==readyFrame.length)return;
    const remainingMs=endpoint.deadline-performance.now();
    if(primary||endpoint.signal.aborted||remainingMs<=0){stop(primary||endpoint.signal.reason||fail('SYSTEM_ORIGINAL_DEADLINE'));return;}
    ready=true;
    const input=Buffer.from(JSON.stringify({env,remainingMs}));
    if(input.length>LIMITS.input){stop(fail('SYSTEM_ORIGINAL_INPUT_BOUND'));return;}
    try{child.stdin.end(input);}catch(error){stop(error);}
   });
   child.stderr.on('data',chunk=>{stderrBytes+=chunk.length;if(stderrBytes>65536)stop(fail('SYSTEM_ORIGINAL_OUTPUT_BOUND'));});
   child.once('close',(code,signal)=>{if(signal||![0,1,2].includes(code))finish(Object.assign(fail('SYSTEM_ORIGINAL_CONTROLLER_FAILED'),{retirementUnproven:true}));else finish(undefined,code);});
   endpoint.signal.addEventListener('abort',abort,{once:true});if(endpoint.signal.aborted)abort();
   deadlineTimer=setTimeout(()=>stop(fail('SYSTEM_ORIGINAL_DEADLINE')),Math.max(0,endpoint.deadline-performance.now()));
   if(primary||performance.now()>=endpoint.deadline)stop(primary||fail('SYSTEM_ORIGINAL_DEADLINE'));
  }catch(error){if(child)stop(error);else finish(error);}
 });
}

async function runOriginal(options){
 validateOptions(options);
 const p=locations(options);
 try{
  options.signal.throwIfAborted();
  await preflightOriginalRuntime({root:options.root,node:options.node,nodeSha256:options.nodeSha256,
   browser:options.browser,browserSha256:options.browserSha256});
  if(await fs.realpath(path.dirname(p.directory))!==path.dirname(p.directory))throw fail('SYSTEM_ORIGINAL_PATH');
  options.signal.throwIfAborted();
 }catch(error){
  // No filesystem mutation, producer call, child launch, or deferred work has
  // been scheduled in this phase. The brand cannot survive a later phase.
  const failure=error instanceof Error?error:fail('SYSTEM_OWNER_UNKNOWN');
  if(!failure.validationIoUnjoined)PREALLOCATION.set(failure,options.runId);throw failure;
 }
 // First owner-local effect: failures from this point require real retirement.
 await fs.mkdir(p.directory,{mode:0o700});
 let journal,tap,result,primary,childFailure,childPacket,childAttempted=false;const controller=new AbortController();
 const abort=()=>controller.abort(options.signal.reason||fail('SYSTEM_ORIGINAL_INTERRUPTED'));
 options.signal.addEventListener('abort',abort,{once:true});if(options.signal.aborted)abort();
 try{
  for(const folder of [p.runtime,p.temporary,path.join(p.runtime,'logs'),path.join(p.runtime,'uploads')])await fs.mkdir(folder,{mode:0o700});
  journal=await fs.open(p.journal,'ax',0o600);tap=await fs.open(p.tap,'wx+',0o600);
  result=await producer.withPrivateSystemAndPolicyImages({...options.producer,signal:controller.signal},async endpoint=>{
   childAttempted=true;
   try{childPacket=await ownChild(options,endpoint,journal,tap);return childPacket;}
   catch(error){
    childFailure=error;childPacket=error.packet;
    if(error.retirementUnproven){
     // A rejected-but-settled callback would permit downstream container
     // cleanup. Abort the producer and leave its actual callback obligation
     // unsettled until an external owner can prove retirement.
     controller.abort(error);return new Promise(()=>{});
    }
    throw error;
   }
  });
 }catch(error){primary=error;}
 finally{
  options.signal.removeEventListener('abort',abort);
  if(journal)try{
   native.writeFileSync(journal.fd,JSON.stringify({stage:'producer-outcome-before-file-close',runId:options.runId,
    producerCompleted:!primary,qualificationAccepted:false,retirementUnproven:!!(primary?.retirementUnproven||childFailure?.retirementUnproven),
    producerFailure:primary?producerFailureDiagnostic(primary):null})+'\n');
   native.fsyncSync(journal.fd);
  }catch(error){primary ||= error;}
  for(const handle of [tap,journal])if(handle){
   try{await handle.sync();}catch(error){primary ||= error;}
   try{await handle.close();}catch(error){primary ||= error;}
  }
 }
 const ownerOutcome={childAttempted,childPacket:childPacket||null,driverReceipt:result?.driverReceipt||primary?.driverReceipt||null};
 if(primary)throw Object.assign(primary,{childFailure,ownerOutcome});
 return {result,ownerOutcome,qualificationAccepted:false,originalFixture:TEST};
}
async function runOriginalSystemBrowser(options){
 if(!LIVE_ENABLED)throw fail('V24_ORIGINAL_BROWSER_NOT_ADMITTED');
 return runOriginal(options);
}

// Fixed MAIN transport only: no supplied argv, environment, endpoint or callback.
// A JSON grant is input binding, never the producer's live capability.
const GRANT_KEYS='version,root,runId,node,nodeSha256,pythonSha256,browser,browserSha256,pgNonce,pgPort,recipe,expectedPlanSha256,expectedProducerSha256,expectedDriverSha256,policyVersion';
function mainOptions(grant,signal,started=performance.now()){
 if(!exact(grant,GRANT_KEYS)||grant.version!==2||!(signal instanceof AbortSignal)
  ||![grant.expectedPlanSha256,grant.expectedProducerSha256,grant.expectedDriverSha256].every(digest))throw fail('SYSTEM_MAIN_GRANT');
 const {version,recipe,expectedPlanSha256,expectedProducerSha256,expectedDriverSha256,...base}=grant;
 const value={...base,signal,producer:{root:grant.root,runId:grant.runId,recipe,signal,
  buildDeadline:started+1800000,expectedPlanSha256,expectedProducerSha256,expectedDriverSha256,expectedPythonSha256:grant.pythonSha256}};
 validateOptions(value);
 return value;
}
function mainTerminal(runId,outcome,error){
 const proof=outcome?.ownerOutcome||error?.ownerOutcome,driver=proof?.driverReceipt,child=proof?.childPacket;
 if(child)validateTerminal(child,runId);
 const producerRetired=!!driver&&driver.localCleanupVerified===true&&driver.remoteCleanupVerified===true
  &&driver.guestResourcesAbsent===true&&driver.sharedStateUnchanged===true&&Array.isArray(driver.debts)&&driver.debts.length===0;
 const childRetired=!!proof&&(proof.childAttempted===false||proof.childAttempted===true&&child?.cleanupVerified===true);
 const preallocation=!!error&&PREALLOCATION.get(error)===runId&&!proof&&!outcome;
 return {version:2,runId,passed:!error&&producerRetired&&childRetired&&proof?.childAttempted===true&&child?.failure===null&&child?.exitCode===0,
  childAttempted:proof?.childAttempted??null,child:child||null,driver:driver||null,
  cleanupVerified:preallocation||producerRetired&&childRetired,failure:error?'SYSTEM_OWNER_FAILED':null,
  failureCode:failureCode(error),preallocation:preallocation?Object.freeze({phase:'validation',ownerLocalAttempted:false,producerAttempted:false,childAttempted:false}):null,
  qualificationAccepted:false};
}
async function readMainGrant(filename){
 const parent=path.dirname(filename);
 if(path.dirname(parent)!==path.join(ROOT,'tasks/qualification')||!/^run-[A-Za-z0-9_-]+$/.test(path.basename(parent))
  ||path.basename(filename)!=='v24-owner-input.json'||await fs.realpath(parent)!==parent)throw fail('SYSTEM_MAIN_INPUT');
 const directory=await fs.lstat(parent);
 if(!directory.isDirectory()||directory.uid!==process.getuid()||(directory.mode&0o777)!==0o700)throw fail('SYSTEM_MAIN_INPUT');
 const fd=await fs.open(filename,native.constants.O_RDONLY|native.constants.O_NOFOLLOW|native.constants.O_NONBLOCK);
 try{
  const before=await fd.stat();if(!before.isFile()||before.uid!==process.getuid()||before.nlink!==1||(before.mode&0o777)!==0o600||before.size<1||before.size>32768)throw fail('SYSTEM_MAIN_INPUT');
  const bytes=Buffer.alloc(32769),{bytesRead}=await fd.read(bytes,0,bytes.length,0),after=await fd.stat(),named=await fs.lstat(filename);
  if(bytesRead!==before.size||!['dev','ino','size','mtimeMs','ctimeMs','mode','uid','nlink'].every(k=>before[k]===after[k]&&before[k]===named[k]))throw fail('SYSTEM_MAIN_INPUT');
  const text=bytes.subarray(0,bytesRead).toString('utf8'),value=JSON.parse(text);
  if(text!==JSON.stringify(value)+'\n')throw fail('SYSTEM_MAIN_INPUT');return value;
 }finally{await fd.close();}
}
async function publishMainTerminal(filename,packet){
 const partial=filename+'.partial';let handle;
 try{
  handle=await fs.open(partial,'wx',0o600);await handle.writeFile(JSON.stringify(packet)+'\n');await handle.sync();
  const closing=handle;handle=null;await closing.close();await fs.link(partial,filename);await fs.unlink(partial);
  const folder=await fs.open(path.dirname(filename),native.constants.O_RDONLY|native.constants.O_DIRECTORY|native.constants.O_NOFOLLOW);
  try{await folder.sync();}finally{await folder.close();}
 }finally{if(handle)await handle.close();}
}
async function main(argv){
 // The literal owner gate precedes even reading caller-controlled input.
 if(!LIVE_ENABLED)throw fail('V24_ORIGINAL_BROWSER_NOT_ADMITTED');
 if(argv.length!==2||argv[0]!=='--owned-main-input')throw fail('SYSTEM_MAIN_ARGUMENTS');
 const started=performance.now(),controller=new AbortController();
 const interrupt=()=>controller.abort(fail('SYSTEM_MAIN_INTERRUPTED'));
 process.once('SIGINT',interrupt);process.once('SIGTERM',interrupt);
 let grant,outcome,primary;
 try{grant=await readMainGrant(argv[1]);const options=mainOptions(grant,controller.signal,started);outcome=await runOriginalSystemBrowser(options);}
 catch(error){primary=error;}
 finally{process.removeListener('SIGINT',interrupt);process.removeListener('SIGTERM',interrupt);}
 if(!grant)throw primary||fail('SYSTEM_MAIN_GRANT');
 const packet=mainTerminal(grant.runId,outcome,primary);
 await publishMainTerminal(path.join(path.dirname(argv[1]),'v24-owner-terminal.json'),packet);
 return packet.cleanupVerified?(packet.passed?0:1):2;
}
if(require.main===module)main(process.argv.slice(2)).then(code=>{process.exitCode=code;},()=>{process.exitCode=2;});
module.exports={LIVE_ENABLED,runOriginalSystemBrowser,preflightOriginalRuntime,_internals:{runOriginal,ownChild,validateOptions,childEnvironment,
 controllerProgram,validateTerminal,locations,fileHash,verifyTap,CONTROLLER,ROOT,TEST,PINS,LIMITS,BROWSER,NODE,
 mainOptions,mainTerminal,readMainGrant,publishMainTerminal,main,nodeRuntimeHash,browserRuntimeHash,NODE_PACKAGE}};
