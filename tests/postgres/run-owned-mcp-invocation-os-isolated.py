#!/usr/bin/env python3
"""Prospective invocation image/kernel cohort; no DB/model/browser. Not run yet."""
import resource,stat,re,argparse,hashlib,importlib.util,json,os,secrets,shlex,shutil,signal,socket,subprocess,tempfile,time,uuid
from pathlib import Path
from owned_mcp_assembly_freeze import verify,sha
from sql_nosql_docker_ownership import verify_daemon,inspect_owned,cleanup_owned
spec=importlib.util.spec_from_file_location('assembly',Path(__file__).with_name('run-owned-mcp-assembly-isolated.py'));M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
SOURCE=Path(__file__).resolve().parents[2]
BOUNDS={'parentSeconds':600,'buildSeconds':300,'childSeconds':180,'executorBytes':536870912,'postgresBytes':0,'modelCalls':0,'browserCalls':0}
def capture_claim_receipt(root,kind='claim'):
 """Hash optional private evidence without reading it into logs or replacing failure."""
 if kind not in ('claim','retirement'):raise ValueError('Closed receipt kind required')
 path=Path(root)/('candidate-result.json.'+kind+'-receipt.json')
 try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except FileNotFoundError:return {'status':'absent'}
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=os.getuid() or info.st_size>262144:raise ValueError('Unsafe private receipt artifact')
  digest=hashlib.sha256();size=0
  while True:
   chunk=os.read(fd,8192)
   if not chunk:break
   size+=len(chunk)
   if size>262144:raise ValueError('Private receipt artifact limit')
   digest.update(chunk)
  return {'status':'retained-private','name':path.name,'sha256':digest.hexdigest(),'bytes':size,'mode':'0600'}
 finally:os.close(fd)
def retain_native_failure(command,root,container):
 """No child bytes in subprocess output; only the fixed private file is copied."""
 remote='/var/lib/dvaia-invocation/first-worker-failure.bin'
 probe=command(['exec',container,'test','-e',remote])
 if probe.returncode==1:return {'status':'absent'}
 if probe.returncode:raise RuntimeError('Private failure probe unavailable')
 path=Path(root)/'first-worker-failure.bin'
 if path.exists() or path.is_symlink():raise RuntimeError('Private failure destination collision')
 copied=command(['cp',container+':'+remote,str(path)])
 if copied.returncode:raise RuntimeError('Private failure copy unavailable')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_size>65536 or stat.S_IMODE(info.st_mode)!=0o600:raise RuntimeError('Unsafe private failure artifact')
  data=os.read(fd,65537)
  if len(data)>65536:raise RuntimeError('Private failure artifact limit')
  return {'status':'retained-private','name':path.name,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'mode':'0600'}
 finally:os.close(fd)
def bootstrap_metadata_code():
 return r"""
const fs=require('fs'),cp=require('child_process');let stage='version',category='command';const commandEvidence=[];
const encode=value=>Buffer.from(typeof value==='string'||Buffer.isBuffer(value)?value:'').subarray(0,4096).toString('base64');
function command(executable,args){
 category='command';
 const result=cp.spawnSync(executable,args,{timeout:2000,maxBuffer:4096,encoding:'utf8',stdio:['ignore','pipe','pipe']});
 const evidence={stage,status:Number.isInteger(result.status)?result.status:null,signal:['SIGTERM','SIGKILL','SIGABRT','SIGSEGV','SIGXFSZ'].includes(result.signal)?result.signal:result.signal?'OTHER':null,errorCode:['ENOENT','EACCES','EPERM','ETIMEDOUT','ENOBUFS'].includes(result.error?.code)?result.error.code:result.error?'OTHER':null,stdoutBase64:encode(result.stdout),stderrBase64:encode(result.stderr),outputTruncated:[result.stdout,result.stderr].some(value=>(typeof value==='string'||Buffer.isBuffer(value))&&Buffer.byteLength(value)>4096)};
 commandEvidence.push(evidence);
 if(result.status!==0||result.error||result.signal)throw Error('Command unavailable');
 return result.stdout.trim();
}
try {
const version=command('/usr/bin/bwrap',['--version']);category='validation';
if(!/^[A-Za-z0-9 ._+:~\-]{1,128}$/.test(version))throw Error('Invalid metadata');
stage='package';const packageVersion=command('/usr/bin/dpkg-query',['-W','--showformat=${Version}','bubblewrap']);category='validation';
if(!/^[0-9][A-Za-z0-9.+:~\-]{0,127}$/.test(packageVersion))throw Error('Invalid metadata');
stage='kernel';category='io';const kernel=fs.readFileSync('/proc/sys/kernel/osrelease','utf8').trim();category='validation';
if(!/^[A-Za-z0-9 ._+:~\-]{1,128}$/.test(kernel))throw Error('Invalid metadata');
stage='mountinfo';category='io';const fd=fs.openSync('/proc/self/mountinfo','r'),buffer=Buffer.alloc(65537);
let length=0;
try {
 for (;;) {
  if(length===buffer.length){category='limit';throw Error('Bootstrap mountinfo limit');}
  const count=fs.readSync(fd,buffer,length,buffer.length-length,null);
  if(count===0)break;
  length+=count;
 }
} finally {fs.closeSync(fd);}
const procMounts=buffer.subarray(0,length).toString('utf8').split('\n').filter(line=>{
 const destination=line.split(' ')[4];return destination==='/proc'||destination?.startsWith('/proc/');
});
process.stdout.write(JSON.stringify({bwrapVersion:version,packageVersion,kernelRelease:kernel,procMounts,commandEvidence}));
} catch {process.stderr.write(JSON.stringify({marker:'DVAIA_BOOTSTRAP_METADATA_FAILURE',stage,category,commandEvidence})+'\n');process.exitCode=70;}
"""
def run_metadata_command(argv,root,timeout=5,limit=65536):
 """Own process group; file-size cap bounds trusted bootstrap output privately."""
 paths=[Path(root)/'bootstrap-metadata.stdout',Path(root)/'bootstrap-metadata.stderr']
 streams=[];process=None;timed_out=False
 def bounds():resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))
 try:
  for path in paths:
   fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);streams.append(os.fdopen(fd,'wb'))
  process=subprocess.Popen(argv,stdout=streams[0],stderr=streams[1],start_new_session=True,preexec_fn=bounds)
  try:process.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   timed_out=True
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   process.wait(timeout=2)
 finally:
  if process is not None and process.poll() is None:
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   process.wait(timeout=2)
  for stream in streams:stream.close()
 artifacts=[{'name':path.name,'sha256':sha(path),'bytes':path.stat().st_size,'mode':'0600'} for path in paths]
 return {'returncode':process.returncode,'timedOut':timed_out,'truncated':any(a['bytes']>=limit for a in artifacts),'artifacts':artifacts}
def capture_attestation_artifacts(root):
 artifacts=[]
 for name in ['bootstrap-metadata.stdout','bootstrap-metadata.stderr']:
  path=Path(root)/'attestation-controls'/name
  try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  except FileNotFoundError:continue
  try:
   info=os.fstat(fd)
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>65536:raise ValueError('Unsafe attestation artifact')
   data=b''
   while len(data)<=65536:
    chunk=os.read(fd,min(8192,65537-len(data)))
    if not chunk:break
    data+=chunk
   if len(data)>65536:raise ValueError('Attestation artifact limit')
   artifacts.append({'name':'attestation-controls/'+name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':'0600'})
  finally:os.close(fd)
 return artifacts

def parse_attestation_asset(raw):
 match=re.fullmatch(r'([a-f0-9]{64})  /usr/local/libexec/dvaia-invocation-attestation-controls\n',raw)
 if not match:raise ValueError('Invalid qualification asset manifest')
 return match.group(1)

def parse_attestation_result(raw):
 value=json.loads(raw)
 expected={'version':1,'diagnosticOnly':True,'passedCases':6,'expectedCases':6,'maxRights':253}
 if not isinstance(value,dict) or set(value)!=set(expected) or any(type(value[k]) is not type(v) or value[k]!=v for k,v in expected.items()):raise ValueError('Incomplete native attestation controls')
 return value

def interrupted(signum,frame):
 raise TimeoutError('Owned invocation aggregate deadline or cancellation')
def install_cancellation():
 for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM):signal.signal(sig,interrupted)
 signal.alarm(600)
def cleanup_image(command,tag,owner,captured_id=None):
 verify_daemon(command,M.DAEMON_ID)
 row=M.inspect_resource(command,'image',tag)
 if row is not None:
  identifier=row.get('Id')
  if not isinstance(identifier,str) or not identifier.startswith('sha256:') or row.get('Config',{}).get('Labels',{}).get('dvaia.owner')!=owner or captured_id is not None and identifier!=captured_id:raise RuntimeError('Owned image identity mismatch')
  if command(['image','rm',tag]).returncode:raise RuntimeError('Owned image removal failed')
  captured_id=identifier
 if M.inspect_resource(command,'image',tag) is not None:raise RuntimeError('Owned image tag remains')
 if captured_id and M.inspect_resource(command,'image',captured_id) is not None:raise RuntimeError('Owned image ID remains')
 return {'tagAbsent':True,'imageId':captured_id,'imageIdAbsent':bool(captured_id)}

def compile_only(args):
 # This branch intentionally has no container, network, SSH, profile or state-volume API.
 reviewed=verify(SOURCE,args.source_sha256,args.dependency_sha256)
 root=Path(tempfile.mkdtemp(prefix='dvaia-mcp-invocation-compile-'));root.chmod(0o700)
 owner=uuid.uuid4().hex;tag='dvaia-mcp-invocation-compile-'+owner[:12]+':owned';docker=[M.DOCKER,'--host',M.HOST]
 state={'status':'preparing','root':str(root),'owner':owner,'launcherPid':os.getpid(),'scope':'compile-only; no kernel qualification','bounds':{'parentSeconds':600,'buildSeconds':300,'childSeconds':0,'modelCalls':0,'browserCalls':0,'databaseCount':0},'reviewed':reviewed,'imageTag':tag,'cleanup':{}}
 started=time.monotonic();build=None;image=None;admitted=False;ca=root/'build-ca.pem'
 def persist():(root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n')
 def run(argv,timeout=15,check=True):
  left=540-(time.monotonic()-started) # Reserve at least sixty seconds for bounded cleanup.
  if left<=0:raise TimeoutError('Compile work deadline')
  result=subprocess.run(argv,capture_output=True,text=True,timeout=min(timeout,left))
  if check and result.returncode:raise RuntimeError('Compile admission command failed: '+argv[0])
  return result
 def command(argv):return run(docker+argv,check=False)
 install_cancellation();persist()
 try:
  if sha(M.NODE)!=M.NODE_SHA or sha(M.DOCKER)!=M.DOCKER_SHA:raise RuntimeError('Executable pin mismatch')
  if run([str(M.NODE),'--version']).stdout.strip()!='v26.10.0':raise RuntimeError('Node version mismatch')
  verify_daemon(command,M.DAEMON_ID)
  if M.inspect_resource(command,'image',tag) is not None:raise RuntimeError('Compile image collision')
  admitted=True
  certificate=run(['/usr/bin/security','find-certificate','-a','-p','/Library/Keychains/System.keychain']).stdout+run(['/usr/bin/security','find-certificate','-a','-p',str(Path.home()/'Library/Keychains/login.keychain-db')]).stdout
  if '-----BEGIN CERTIFICATE-----' not in certificate:raise RuntimeError('Build CA unavailable')
  ca.write_text(certificate);ca.chmod(0o600)
  argv=docker+['build','--platform','linux/arm64','--target','runtime','--label','dvaia.owner='+owner,'--secret','id=npm_ca,src='+str(ca),'--tag',tag,'--file',str(SOURCE/'sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.invocation'),str(SOURCE)]
  with (root/'build.log').open('w') as log:
   build=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   state['buildPgid']=build.pid;persist()
   state['buildExitCode']=build.wait(timeout=min(300,540-(time.monotonic()-started)))
  if state['buildExitCode']!=0:raise RuntimeError('Invocation image compilation failed; retained build.log')
  row=M.inspect_resource(command,'image',tag)
  if row is None or row.get('Config',{}).get('Labels',{}).get('dvaia.owner')!=owner:raise RuntimeError('Compiled image ownership mismatch')
  image=row['Id'];state['imageId']=image
  state['finalIntegrity']=verify(SOURCE,args.source_sha256,args.dependency_sha256)
  state['status']='passed'
 except BaseException as error:
  state['status']='failed';state['error']={'type':type(error).__name__,'message':str(error)}
 finally:
  signal.alarm(0)
  for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
  deadline=time.monotonic()+45;errors=[]
  def clean_command(argv):
   left=deadline-time.monotonic()
   if left<=0:raise TimeoutError('Compile cleanup deadline')
   return subprocess.run(docker+argv,capture_output=True,text=True,timeout=min(10,left))
  try:
   M.stop_process(build)
   if build is not None:
    if M.group_members(build.pid):raise RuntimeError('Build process group remains')
    state['cleanup']['buildGroupAbsent']=True
  except Exception as error:errors.append(str(error))
  try:
   if admitted:state['cleanup']['image']=cleanup_image(clean_command,tag,owner,image)
  except Exception as error:errors.append(str(error))
  try:ca.unlink(missing_ok=True);state['cleanup']['privateCaAbsent']=not ca.exists()
  except Exception as error:errors.append(str(error))
  try:state['endIntegrity']=verify(SOURCE,args.source_sha256,args.dependency_sha256)
  except Exception as error:errors.append(str(error))
  if build is not None and 'buildExitCode' not in state:
   state['cleanup']['remoteBuilderTerminationVerified']=False
   errors.append('Interrupted Docker build: daemon builder termination remains unverified; tag absence is only a point-in-time observation')
  else:state['cleanup']['remoteBuilderTerminationVerified']=True
  state['cleanup']['errors']=errors
  if errors:state['status']='failed'
  if (root/'build.log').exists():state['buildLogSha256']=sha(root/'build.log')
  persist()
 print(json.dumps({'root':str(root),'status':state['status'],'cleanup':state['cleanup']}))
 return 0 if state['status']=='passed' else 1

def create_remote_root(ssh,remote,owner,state,persist):
 ssh(['test','!','-e',remote])
 state['pendingRemoteCreate']=remote;persist()
 ssh(['mkdir','-m','0700',remote])
 ssh(['tee',remote+'/owner'],input=owner+'\n')
 state.pop('pendingRemoteCreate',None);state['remoteRootOwned']=True;persist()
 return True

def cancellation_cohort(args):
 root=Path(tempfile.mkdtemp(prefix='dvaia-mcp-handshake-cohort-'));root.chmod(0o700)
 started=time.monotonic();limits={'workDeadline':started+510,'buildSeconds':300.0,'childSeconds':180.0,'cleanupSeconds':75.0};report={'status':'running','scope':'three sequential independent containments; no concurrent sibling proof','root':str(root),'variants':[],'launcherPid':os.getpid(),'limits':dict(limits)}
 def persist():(root/'cohort.json').write_text(json.dumps(report,indent=2)+'\n')
 persist()
 for phase in ['pre','post','control']:
  if time.monotonic()>=limits['workDeadline'] or min(limits['buildSeconds'],limits['childSeconds'],limits['cleanupSeconds'])<=0:report['status']='failed';report['error']='Aggregate qualification budget exhausted';break
  def admitted(path,owner):
   report['activeVariant']={'phase':phase,'root':str(path),'owner':owner};persist()
  qualification={'phase':phase,'limits':dict(limits),'onAdmit':admitted}
  try:exit_code=main(qualification)
  except BaseException as error:report['status']='failed';report['errorType']=type(error).__name__;break
  state=qualification.get('result')
  if not state:report['status']='failed';report['error']='Variant terminal evidence missing';break
  entry={'phase':phase,'root':state['root'],'status':state['status'],'ownershipSha256':sha(Path(state['root'])/'ownership.json'),'runtimeSha256':state.get('runtimeSha256'),'imageId':state.get('imageId'),'cleanup':state['cleanup']};report['variants'].append(entry);report.pop('activeVariant',None)
  for key in ['buildSeconds','childSeconds','cleanupSeconds']:limits[key]-=state.get('measured',{}).get(key,limits[key])
  report['remaining']=dict(limits);persist()
  if exit_code or state['cleanup'].get('errors'):report['status']='failed';break
 else:report['status']='passed'
 persist();print(json.dumps({'root':str(root),'status':report['status'],'variants':len(report['variants'])}));return 0 if report['status']=='passed' else 1

def main(qualification=None):
 p=argparse.ArgumentParser();p.add_argument('--source-sha256',required=True);p.add_argument('--dependency-sha256',required=True);p.add_argument('--docker-host',required=True);p.add_argument('--run',action='store_true');p.add_argument('--bootstrap-diagnostic',action='store_true');p.add_argument('--attestation-controls',action='store_true');p.add_argument('--handshake-cancellation',action='store_true');mode=p.add_mutually_exclusive_group();mode.add_argument('--compile-only',action='store_true');mode.add_argument('--kernel-only',action='store_true');a=p.parse_args()
 if not a.run or a.docker_host!=M.HOST:raise RuntimeError('Explicit reviewed owned invocation run required')
 if a.handshake_cancellation and (not a.kernel_only or a.attestation_controls or a.bootstrap_diagnostic):raise RuntimeError('Handshake cancellation requires exclusive kernel-only selection')
 if a.handshake_cancellation and qualification is None:return cancellation_cohort(a)
 if a.attestation_controls and not a.kernel_only:raise RuntimeError('Attestation controls require kernel-only')
 if a.compile_only:return compile_only(a)
 if not a.kernel_only:raise RuntimeError('Full kernel launcher remains unqualified without explicit --kernel-only reviewed opt-in')
 reviewed=verify(SOURCE,a.source_sha256,a.dependency_sha256)
 root=Path(tempfile.mkdtemp(prefix='dvaia-mcp-invocation-os-'));root.chmod(0o700);owner=uuid.uuid4().hex;nonce=owner[:12];name='dvaia-owned-mcp-registry-'+nonce;tag=name+':invocation';network=name+'-net';remote='/tmp/'+name
 if qualification:qualification['onAdmit'](root,owner)
 state={'status':'preparing','root':str(root),'owner':owner,'launcherPid':os.getpid(),'bounds':BOUNDS,'reviewed':reviewed,'containerIds':{},'cleanup':{}}
 started=time.monotonic();work_until=min(started+510,qualification['limits']['workDeadline']) if qualification else started+510;build_budget=min(300,qualification['limits']['buildSeconds']) if qualification else 300;child_budget=min(180,qualification['limits']['childSeconds']) if qualification else 180;cleanup_budget=min(75,qualification['limits']['cleanupSeconds']) if qualification else 75;state['measured']={};state['allocation']={'workDeadline':work_until,'buildSeconds':build_budget,'childSeconds':child_budget,'cleanupSeconds':cleanup_budget};state['qualificationPhase']=qualification['phase'] if qualification else None;build=child=tunnel=None;image=None;remote_owned=profile=False;created=[];private=[];key=b'';token='';docker=[M.DOCKER,'--host',M.HOST]
 def persist():(root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n')
 def run(argv,timeout=15,check=True,**kw):
  left=work_until-time.monotonic()
  if left<=0:raise RuntimeError('Parent deadline')
  value=subprocess.run(argv,capture_output=True,text=True,timeout=min(timeout,left),**kw)
  if check and value.returncode:raise RuntimeError('Owned subprocess failed: '+argv[0])
  return value
 def command(args):return run(docker+args,check=False)
 def ssh(args,**kw):return run(M.SSH+[shlex.join(args)],**kw)
 install_cancellation();persist()
 try:
  if sha(M.NODE)!=M.NODE_SHA or sha(M.DOCKER)!=M.DOCKER_SHA:raise RuntimeError('Executable pin mismatch')
  verify_daemon(command,M.DAEMON_ID)
  if M.inspect_resource(command,'image',tag) is not None or M.inspect_resource(command,'network',network) is not None:raise RuntimeError('Owned resource collision')
  for n in [name,name+'-takeover']:
   r=command(['inspect',n]);
   if r.returncode==0 or r.stderr.strip() not in [f'Error: No such object: {n}',f'Error: No such container: {n}']:raise RuntimeError('Container absence unverified')
  workspace=root/'source';run([str(M.NODE),'-e',"require('./tests/fixtures/secureshopOwnedMcpAssemblyCopy').copy(process.argv[1],process.argv[2]);",str(SOURCE),str(workspace)],timeout=90,cwd=SOURCE);(workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True);state['copiedIntegrity']=verify(workspace,a.source_sha256,a.dependency_sha256)
  policy=(workspace/'sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in').read_text().replace('@@SUPERVISOR_PROFILE@@',name)
  labels=ssh(['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout
  if any(x.startswith(name+' ') or x.startswith(name+'//') for x in labels.splitlines()):raise RuntimeError('Profile collision')
  remote_owned=create_remote_root(ssh,remote,owner,state,persist);ssh(['mkdir','-m','0700',remote+'/state',remote+'/secrets']);ssh(['tee',remote+'/policy'],input=policy);ssh(['sudo','apparmor_parser','--skip-kernel-load',remote+'/policy']);ssh(['sudo','apparmor_parser','-r',remote+'/policy']);profile=True
  ca=root/'build-ca.pem';cert=run(['/usr/bin/security','find-certificate','-a','-p','/Library/Keychains/System.keychain']).stdout+run(['/usr/bin/security','find-certificate','-a','-p',str(Path.home()/'Library/Keychains/login.keychain-db')]).stdout
  if '-----BEGIN CERTIFICATE-----' not in cert:raise RuntimeError('Build CA unavailable')
  ca.write_text(cert);ca.chmod(0o600);private.append(ca)
  build_started=time.monotonic()
  with (root/'build.log').open('w') as log:
   build=subprocess.Popen(docker+['build','--platform','linux/arm64','--target',('cancellation-'+qualification['phase'] if qualification and qualification['phase']!='control' else 'attestation-qualification' if a.attestation_controls else 'runtime'),'--label','dvaia.owner='+owner,'--secret','id=npm_ca,src='+str(ca),'--tag',tag,'--file',str(workspace/'sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.invocation'),str(workspace)],stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state['buildPgid']=build.pid;persist()
   state['buildExitCode']=build.wait(timeout=min(build_budget,work_until-time.monotonic()))
   state['measured']['buildSeconds']=time.monotonic()-build_started
   if state['buildExitCode']!=0:raise RuntimeError('Invocation compile/image build failed; see build.log')
  image=run(docker+['image','inspect',tag,'--format','{{.Id}}']).stdout.strip();state['imageId']=image
  run(docker+['network','create','--internal','--label','dvaia.owner='+owner,network])
  # Exact owned stopped container extracts only the public asset manifest.
  state['pendingContainerCreate']=name;persist()
  run(docker+['create','--name',name,'--label','dvaia.owner='+owner,'--network',network,image]);state.pop('pendingContainerCreate',None);created.append(name);state['containerIds'][name]=inspect_owned(command,name=name,labels={'dvaia.owner':owner},image=image)['Id'];persist()
  run(docker+['cp',name+':/usr/share/dvaia/invocation-assets.json',str(root/'assets.json')]);assets=json.loads((root/'assets.json').read_text());runtime=hashlib.sha256(json.dumps(assets,separators=(',',':')).encode()).hexdigest();state['runtimeSha256']=runtime
  cleanup_owned(command,daemon_id=M.DAEMON_ID,name=name,labels={'dvaia.owner':owner},image=image,captured_id=state['containerIds'][name]);created.remove(name);state['extractContainerId']=state['containerIds'].pop(name)
  manager=str(uuid.uuid4());volume=str(uuid.uuid4());key=secrets.token_bytes(32);token=secrets.token_urlsafe(32);keyid='native-owned'
  config={'managerInstanceId':manager,'volumeId':volume,'runtimeSha256':runtime,'keyId':keyid,'keySha256':hashlib.sha256(key).hexdigest(),'qualificationEpochProbe':True}
  files={'state/supervisor.lock':'','state/identity':manager+'\n'+volume+'\n'+runtime+'\n','state/state.json':json.dumps({'version':1,'managerInstanceId':manager,'runtimeSha256':runtime,'claims':{},'fences':{}},separators=(',',':'),sort_keys=True)+'\n','secrets/dvaia-invocation.json':json.dumps(config),'secrets/dvaia-invocation.token':token}
  for rel,data in files.items():ssh(['tee',remote+'/'+rel],input=data);ssh(['chmod','0600',remote+'/'+rel])
  # Binary key travels on stdin only; never argv, environment or retained logs.
  keyfile=root/'signing.key';keyfile.write_bytes(key);keyfile.chmod(0o600);private.append(keyfile)
  with keyfile.open('rb') as stream:subprocess.run(M.SSH+[shlex.join(['tee',remote+'/state/signing.key'])],stdin=stream,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,check=True,timeout=M.remaining(work_until,15))
  ssh(['chmod','0600',remote+'/state/signing.key']);ssh(['sudo','chown','-R','10001:10001',remote+'/state',remote+'/secrets'])
  def create(container,deadline=None):
   state['pendingContainerCreate']=container;persist()
   run(docker+['create','--name',container,'--label','dvaia.owner='+owner,'--network',network,'--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--tmpfs','/run/dvaia-invocation:rw,nosuid,nodev,noexec,size=1m,mode=0700,uid=10001,gid=10001','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--security-opt','apparmor='+name,'--security-opt','seccomp=unconfined','--user','10001:10001','--env','DVAIA_INVOCATION_PRIVATE_DIAGNOSTICS=1','--mount','type=bind,src='+remote+'/state,dst=/var/lib/dvaia-invocation','--mount','type=bind,src='+remote+'/secrets,dst=/run/secrets,readonly',image,manager,volume,runtime],timeout=M.startup_timeout(deadline) if deadline else 15);state.pop('pendingContainerCreate',None);created.append(container);state['containerIds'][container]=inspect_owned(command,name=container,labels={'dvaia.owner':owner},image=image)['Id'];persist()
  startup_deadline=time.monotonic()+30
  create(name,startup_deadline);run(docker+['start',name],timeout=M.startup_timeout(startup_deadline));startup_command=lambda argv:run(docker+argv,timeout=M.startup_timeout(startup_deadline),check=False)
  info=inspect_owned(startup_command,name=name,labels={'dvaia.owner':owner},image=image,captured_id=state['containerIds'][name]);net=M.inspect_resource(startup_command,'network',network)
  # Validate equivalent sole internal endpoint with the exact owner label.
  address=M.validate_internal_endpoint(info,net,network,owner,state['containerIds'][name],binding_mode='invocation')
  if a.attestation_controls:
   control_root=root/'attestation-controls';control_root.mkdir(mode=0o700)
   manifest=control_root/'asset.sha256'
   run(docker+['cp',state['containerIds'][name]+':/usr/share/dvaia/invocation-attestation-controls.sha256',str(manifest)]);manifest.chmod(0o600)
   state['attestationControlAsset']={'name':'attestation-controls/asset.sha256','sha256':sha(manifest),'bytes':manifest.stat().st_size,'imageId':image,'helperSha256':parse_attestation_asset(manifest.read_text())};persist()
   attempt=run_metadata_command(docker+['exec',state['containerIds'][name],'/usr/local/libexec/dvaia-invocation-attestation-controls'],control_root,timeout=8)
   for artifact in attempt['artifacts']:artifact['name']='attestation-controls/'+artifact['name']
   state['attestationControlAttempt']=attempt;persist()
   if attempt['returncode'] or attempt['timedOut'] or attempt['truncated']:raise RuntimeError('Native attestation controls failed; private evidence retained')
   state['attestationControlResult']=parse_attestation_result((control_root/'bootstrap-metadata.stdout').read_text());persist()
  if a.bootstrap_diagnostic:
   metadata_code=bootstrap_metadata_code()
   attempt=run_metadata_command(docker+['exec',state['containerIds'][name],'/usr/local/bin/node','-e',metadata_code],root)
   state['bootstrapMetadataAttempt']=attempt;persist()
   if attempt['returncode'] or attempt['timedOut'] or attempt['truncated']:raise RuntimeError('Private bootstrap metadata failed; bounded evidence retained')
   metadata=json.loads((root/'bootstrap-metadata.stdout').read_text())
   metadata['hostConfig']={k:info['HostConfig'].get(k) for k in ['MaskedPaths','ReadonlyPaths','SecurityOpt','CapDrop','Privileged','PidMode','UsernsMode']}
   metadata['runtimeSha256']=runtime
   metadata_file=root/'bootstrap-metadata.json';fd=os.open(metadata_file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'w') as stream:stream.write(json.dumps(metadata)+'\n')
   state['bootstrapMetadataArtifact']={'name':metadata_file.name,'sha256':sha(metadata_file),'bytes':metadata_file.stat().st_size,'mode':'0600'}
  state['networkDiagnostic']={'internal':net['Internal'],'address':address,'networkId':net['Id']};persist()
  config_sha=sha(M.SSH[2]);ssh_sha=sha(M.SSH[0])
  settings=run(M.SSH[:3]+['-G',M.SSH[3]],timeout=M.startup_timeout(startup_deadline)).stdout
  parsed={line.split(' ',1)[0]:line.split(' ',1)[1] for line in settings.splitlines() if ' ' in line}
  if parsed.get('hostname')!='127.0.0.1' or any(k in parsed for k in ['localforward','remoteforward','proxycommand','proxyjump']):raise RuntimeError('Unexpected SSH forwarding config')
  with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
  if sha(M.SSH[2])!=config_sha or sha(M.SSH[0])!=ssh_sha:raise RuntimeError('SSH transport changed')
  state['transportPins']={'configSha256':config_sha,'sshSha256':ssh_sha}
  with (root/'tunnel.log').open('w') as tunnel_log:tunnel=subprocess.Popen(M.tunnel_argv(address,port,remote_port=8095),stdout=tunnel_log,stderr=tunnel_log,start_new_session=True)
  state['tunnelPgid']=tunnel.pid;state['tunnelPort']=port;persist()
  while time.monotonic()<startup_deadline:
   if tunnel.poll() is not None:raise RuntimeError('Owned tunnel exited before readiness')
   listeners=run(['/usr/sbin/lsof','-nP','-a','-p',str(tunnel.pid),'-iTCP:'+str(port),'-sTCP:LISTEN'],timeout=M.startup_timeout(startup_deadline,2),check=False)
   if listeners.returncode==0 and f'127.0.0.1:{port} (LISTEN)' in listeners.stdout:break
   if listeners.returncode not in (0,1) or listeners.stderr.strip():raise RuntimeError('Tunnel listener ownership unverified')
   time.sleep(M.startup_timeout(startup_deadline,.05))
  else:raise TimeoutError('Owned tunnel startup deadline')
  credentials=root/'private.json';credentials.write_text(json.dumps({**config,**({'qualificationPhase':qualification['phase']} if qualification else {}),'key':key.hex(),'token':token,'docker':M.DOCKER,'dockerHost':M.HOST,'container':name,'url':f'http://127.0.0.1:{port}'}));credentials.chmod(0o600);private.append(credentials)
  env={**os.environ,'MCP_INVOCATION_OS_PRIVATE':str(credentials),'MCP_INVOCATION_OS_RESULT':str(root/'candidate-result.json'),'PYTHONDONTWRITEBYTECODE':'1'}
  child_started=time.monotonic()
  with (root/'tests.log').open('w') as log:
   child=subprocess.Popen([str(M.NODE),str(workspace/('tests/fixtures/secureshopOwnedMcpHandshakeCancellation.native.js' if qualification else 'tests/fixtures/secureshopOwnedMcpInvocationOs.native.js'))],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state['childPgid']=child.pid;persist()
   child_exit=child.wait(timeout=min(child_budget,work_until-time.monotonic()));state['measured']['childSeconds']=time.monotonic()-child_started
   if child_exit!=0:raise RuntimeError('Invocation kernel cohort failed')
  run(docker+['kill','--signal','KILL',name]);info=inspect_owned(command,name=name,labels={'dvaia.owner':owner},image=image,captured_id=state['containerIds'][name]);assert info['State']['Running'] is False
  cleanup_owned(command,daemon_id=M.DAEMON_ID,name=name,labels={'dvaia.owner':owner},image=image,captured_id=state['containerIds'][name]);created.remove(name)
  if not qualification:
   create(name+'-takeover');run(docker+['start',name+'-takeover']);waited=run(docker+['wait',name+'-takeover'],timeout=30);assert waited.stdout.strip()=='70';state['unprovedTakeoverDenied']=True
  state['finalIntegrity']=verify(workspace,a.source_sha256,a.dependency_sha256);state['resultSha256']=sha(root/'candidate-result.json');state['status']='passed'
 except BaseException as error:state['status']='failed';state['error']={'type':type(error).__name__,'message':str(error)}
 finally:
  signal.alarm(0)
  for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
  cleanup_started=time.monotonic();errors=[];cleanup_deadline=cleanup_started+cleanup_budget
  def clean_run(argv,check=True,cap=10):
   left=cleanup_deadline-time.monotonic()
   if left<=0:raise TimeoutError('Full kernel cleanup deadline')
   response=subprocess.run(argv,capture_output=True,text=True,timeout=min(cap,left))
   if check and response.returncode:raise RuntimeError('Owned cleanup command failed')
   return response
  def clean_command(args):return clean_run(docker+args,False)
  def clean_ssh(args):return clean_run(M.SSH+[shlex.join(args)])
  for process in [child,tunnel,build]:
   try:M.stop_process(process,deadline=cleanup_deadline)
   except Exception as error:errors.append(str(error))
  if image is not None:
   diagnostic_deadline=min(cleanup_deadline-50,time.monotonic()+5)
   def diagnostic_command(argv):return subprocess.run(docker+argv,capture_output=True,text=True,timeout=M.remaining(diagnostic_deadline,1))
   state['diagnostics']=M.startup_diagnostics(diagnostic_command,name,token,extra_secrets=(key.hex(),),service_port=8095)
  if state['containerIds'].get(name):
   try:state['privateFailureArtifact']=retain_native_failure(clean_command,root,state['containerIds'][name])
   except Exception:state['privateFailureArtifact']={'status':'capture-failed'};errors.append('Private failure artifact capture failed')
  else:state['privateFailureArtifact']={'status':'absent'}
  containers_clean=True
  for container in [name+'-takeover',name]:
   try:
    proof=cleanup_owned(clean_command,daemon_id=M.DAEMON_ID,name=container,labels={'dvaia.owner':owner},image=image,captured_id=state['containerIds'].get(container));state['cleanup'][container]=proof
    identifier=proof.get('containerId')
    if identifier and inspect_owned(clean_command,name=identifier,labels={'dvaia.owner':owner},image=image) is not None:raise RuntimeError('Exact container ID remains')
   except Exception as error:containers_clean=False;errors.append(str(error))
  try:
   identifier=state.get('extractContainerId')
   if identifier and inspect_owned(clean_command,name=identifier,labels={'dvaia.owner':owner},image=image) is not None:raise RuntimeError('Extraction container remains')
  except Exception as error:containers_clean=False;errors.append(str(error))
  try:
   if tunnel is not None:state['cleanup']['tunnel']=M.verify_tunnel_closed(state['tunnelPort'],tunnel.pid,lambda argv:clean_run(argv,False),members=lambda pgid:M.group_members(pgid,deadline=cleanup_deadline))
  except Exception as error:errors.append(str(error))
  try:
   if remote_owned or state.get('remoteRootOwned'):
    if not containers_clean:raise RuntimeError('Retaining private volume until exact container cleanup verified')
    if clean_ssh(['cat',remote+'/owner']).stdout!=owner+'\n':raise RuntimeError('Remote ownership changed')
    profiles=clean_ssh(['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout.splitlines()
    if any(x.startswith(name+' ') or x.startswith(name+'//') for x in profiles):clean_ssh(['sudo','apparmor_parser','-R',remote+'/policy'])
    profiles=clean_ssh(['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout.splitlines()
    if any(x.startswith(name+' ') or x.startswith(name+'//') for x in profiles):raise RuntimeError('Owned profile remains')
    state['cleanup']['profileAbsent']=True
    # Only the exact closed fixture paths are removed; unexpected contents retain the volume.
    for rel in ['state/first-worker-failure.bin','state/supervisor.lock','state/identity','state/state.json','state/signing.key','state/supervisor.epoch','secrets/dvaia-invocation.json','secrets/dvaia-invocation.token']:
     clean_ssh(['sudo','rm','-f','--',remote+'/'+rel])
    clean_ssh(['sudo','find',remote+'/state','-maxdepth','1','-type','f','-name','state.*.tmp','-delete'])
    for rel in ['state','secrets']:clean_ssh(['sudo','rmdir','--',remote+'/'+rel])
    for rel in ['owner','policy']:clean_ssh(['rm','-f','--',remote+'/'+rel])
    clean_ssh(['rmdir','--',remote]);clean_ssh(['test','!','-e',remote]);state['cleanup']['privateVmRootAbsent']=True
  except Exception as error:errors.append(str(error))
  try:
   net=M.inspect_resource(clean_command,'network',network)
   if net is not None:
    if net.get('Labels',{}).get('dvaia.owner')!=owner:raise RuntimeError('Network ownership changed')
    if clean_command(['network','rm',network]).returncode:raise RuntimeError('Network removal failed')
   if M.inspect_resource(clean_command,'network',network) is not None:raise RuntimeError('Network remains')
   state['cleanup']['networkAbsent']=True
   state['cleanup']['image']=cleanup_image(clean_command,tag,owner,image)
  except Exception as error:errors.append(str(error))
  for file in private:
   try:file.unlink(missing_ok=True);assert not file.exists()
   except Exception as error:errors.append(str(error))
  for key in ['buildPgid','childPgid','tunnelPgid']:
   if key in state:
    try:assert not M.group_members(state[key],deadline=cleanup_deadline);state['cleanup'][key+'Absent']=True
    except Exception as error:errors.append(str(error))
  if state.get('pendingRemoteCreate'):
   state['cleanup']['remoteRootOwnershipUncertain']=True
   errors.append('Remote mkdir/owner acknowledgment uncertain; retained path requires explicit ownership reconciliation')
  if state.get('pendingContainerCreate'):errors.append('Interrupted or failed container creation remains uncertain after exact-name reconciliation')
  if build is not None and 'buildExitCode' not in state:errors.append('Daemon builder termination unverified after interrupted build')
  try:
   check=clean_run(['python3','-B','-c',"import sys,json;sys.path.insert(0,sys.argv[1]);from owned_mcp_assembly_freeze import verify;print(json.dumps(verify(sys.argv[2],sys.argv[3],sys.argv[4])))",str(SOURCE/'tests/postgres'),str(SOURCE),a.source_sha256,a.dependency_sha256],cap=30);state['endIntegrity']=json.loads(check.stdout)
  except Exception as error:errors.append(str(error))
  try:state['claimReceiptArtifact']=capture_claim_receipt(root)
  except Exception:state['claimReceiptArtifact']={'status':'capture-failed'};errors.append('Private claim receipt artifact capture failed')
  try:state['retirementReceiptArtifact']=capture_claim_receipt(root,'retirement')
  except Exception:errors.append('Private retirement receipt capture failed')
  try:state['attestationControlArtifacts']=capture_attestation_artifacts(root)
  except Exception:errors.append('Private attestation artifact capture failed')
  state['cleanup']['errors']=errors;state['measured']['cleanupSeconds']=time.monotonic()-cleanup_started
  if errors:state['status']='failed'
  persist()
 if qualification is not None:qualification['result']=state
 print(json.dumps({'root':str(root),'status':state['status'],'cleanup':state['cleanup']}));return 0 if state['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
