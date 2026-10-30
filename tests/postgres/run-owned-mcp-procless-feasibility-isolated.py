#!/usr/bin/env python3
"""Separate diagnostic only; explicit reviewed frozen hashes required. No completion authority."""
import argparse,importlib.util,json,os,shlex,signal,tempfile,time,uuid
from pathlib import Path
from owned_mcp_assembly_freeze import verify,sha
from sql_nosql_docker_ownership import verify_daemon,inspect_owned,cleanup_owned
spec=importlib.util.spec_from_file_location('invocation',Path(__file__).with_name('run-owned-mcp-invocation-os-isolated.py'));I=importlib.util.module_from_spec(spec);spec.loader.exec_module(I)
M=I.M
SOURCE=Path(__file__).resolve().parents[2]
BOUNDS={'parentSeconds':600,'workSeconds':510,'buildSeconds':300,'probeSeconds':20,'cleanupSeconds':75,'memoryBytes':536870912,'cpus':1,'pids':128,'modelCalls':0,'databaseCount':0,'browserCalls':0}
def result_contract(raw):
 value=json.loads(raw)
 if not isinstance(value,dict) or set(value)!={'diagnosticOnly','phase','passed','drained'} or value['diagnosticOnly'] is not True or type(value['phase']) is not int or not 1<=value['phase']<=7 or type(value['passed']) is not bool or type(value['drained']) is not bool:raise ValueError('Invalid closed probe result')
 return value

def admit_absent_resources(command,tag,network,name,owner):
 for kind,identifier in [('image',tag),('network',network)]:
  if M.inspect_resource(command,kind,identifier) is not None:raise RuntimeError('Owned resource collision')
 # No image has been created yet: any existing container is a collision,
 # including one whose ownership or image cannot be established.
 if inspect_owned(command,name=name,labels={'owasp-ai-goat.owner':owner},image=None) is not None:raise RuntimeError('Owned container collision')

def main():
 p=argparse.ArgumentParser();p.add_argument('--run',action='store_true');p.add_argument('--docker-host',required=True);p.add_argument('--source-sha256',required=True);p.add_argument('--dependency-sha256',required=True);a=p.parse_args()
 if not a.run or a.docker_host!=M.HOST:raise ValueError('Explicit reviewed frozen qualification required')
 reviewed=verify(SOURCE,a.source_sha256,a.dependency_sha256)
 root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-mcp-procless-'));root.chmod(0o700);owner=uuid.uuid4().hex;name='owasp-ai-goat-mcp-procless-'+owner[:12];tag=name+':owned';network=name+'-net';remote='/tmp/'+name;docker=[M.DOCKER,'--host',M.HOST]
 state={'status':'preparing','stage':'admission','diagnosticOnly':True,'owner':owner,'root':str(root),'bounds':BOUNDS,'reviewed':reviewed,'launcherPid':os.getpid(),'artifacts':[],'cleanup':{}}
 started=time.monotonic();image=None;container_id=None;remote_owned=False;ca=root/'build-ca.pem'
 def persist():(root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n')
 def command(argv):
  return I.subprocess.run(docker+argv,capture_output=True,text=True,timeout=min(15,M.remaining(started+510,15)))
 def ssh(argv,**kw):
  result=I.subprocess.run(M.SSH+[shlex.join(argv)],capture_output=True,text=True,timeout=M.remaining(started+510,15),**kw)
  if result.returncode:raise RuntimeError('Owned SSH command failed')
  return result
 def capture(stage,argv,timeout,limit):
  directory=root/stage;directory.mkdir(mode=0o700);state['stage']=stage;state[stage]={'started':True};persist()
  attempt=I.run_metadata_command(argv,directory,timeout=min(timeout,M.remaining(started+510,timeout)),limit=limit)
  for artifact in attempt['artifacts']:artifact['name']=stage+'/'+artifact['name']
  state[stage]=attempt;state['artifacts'].extend(attempt['artifacts']);persist();return attempt,directory
 I.install_cancellation();persist()
 try:
  if sha(M.NODE)!=M.NODE_SHA or sha(M.DOCKER)!=M.DOCKER_SHA:raise RuntimeError('Executable pin mismatch')
  verify_daemon(command,M.DAEMON_ID)
  admit_absent_resources(command,tag,network,name,owner)
  # Build from the reviewed frozen tree; no application runtime config or databases.
  cert=''
  for keychain in ['/Library/Keychains/System.keychain',str(Path.home()/'Library/Keychains/login.keychain-db')]:
   reply=I.subprocess.run(['/usr/bin/security','find-certificate','-a','-p',keychain],capture_output=True,text=True,timeout=M.remaining(started+510,15),check=True);cert+=reply.stdout
  if '-----BEGIN CERTIFICATE-----' not in cert:raise RuntimeError('Build CA unavailable')
  fd=os.open(ca,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as stream:stream.write(cert)
  attempt,_=capture('linuxCompilation',docker+['build','--platform','linux/arm64','--label','owasp-ai-goat.owner='+owner,'--secret','id=npm_ca,src='+str(ca),'--tag',tag,'--file',str(SOURCE/'sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.procless-feasibility'),str(SOURCE)],300,1048576)
  if attempt['returncode'] or attempt['timedOut'] or attempt['truncated']:raise RuntimeError('Linux compilation failed; private artifacts retained')
  row=M.inspect_resource(command,'image',tag)
  if not row or row.get('Config',{}).get('Labels',{}).get('owasp-ai-goat.owner')!=owner:raise RuntimeError('Image ownership mismatch')
  image=row['Id'];state['imageId']=image
  policy=(SOURCE/'sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in').read_text().replace('@@SUPERVISOR_PROFILE@@',name)
  labels=ssh(['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout.splitlines()
  if any(x.startswith(name+' ') or x.startswith(name+'//') for x in labels):raise RuntimeError('Profile collision')
  remote_owned=I.create_remote_root(ssh,remote,owner,state,persist);ssh(['tee',remote+'/policy'],input=policy);ssh(['sudo','apparmor_parser','--skip-kernel-load',remote+'/policy']);ssh(['sudo','apparmor_parser','-r',remote+'/policy'])
  if command(['network','create','--internal','--label','owasp-ai-goat.owner='+owner,network]).returncode:raise RuntimeError('Network creation failed')
  argv=['create','--name',name,'--label','owasp-ai-goat.owner='+owner,'--network',network,'--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--tmpfs','/run/owasp-ai-goat-invocation:rw,nosuid,nodev,noexec,size=1m,mode=0700,uid=10001,gid=10001','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--security-opt','apparmor='+name,'--security-opt','seccomp=unconfined','--user','10001:10001',image]
  if command(argv).returncode:raise RuntimeError('Probe container creation failed')
  info=inspect_owned(command,name=name,labels={'owasp-ai-goat.owner':owner},image=image);container_id=info['Id'];state['containerId']=container_id;persist()
  # Immutable compiled helper/filter evidence is copied before start, never executed outside container.
  destination=root/'compiled-helper.sha256'
  if command(['cp',container_id+':/usr/share/owasp-ai-goat/procless-feasibility.sha256',str(destination)]).returncode:raise RuntimeError('Helper manifest unavailable')
  destination.chmod(0o600);state['artifacts'].append({'name':destination.name,'sha256':sha(destination),'bytes':destination.stat().st_size,'mode':'0600'})
  net=M.inspect_resource(command,'network',network)
  if not net or not net.get('Internal') or net.get('Driver')!='bridge' or net.get('Labels',{}).get('owasp-ai-goat.owner')!=owner or set(info.get('NetworkSettings',{}).get('Networks',{}))!={network} or info['HostConfig'].get('NetworkMode')!=network:raise RuntimeError('Internal network mismatch')
  host=info['HostConfig']
  if host.get('Memory')!=536870912 or host.get('NanoCpus')!=1000000000 or host.get('PidsLimit')!=128 or host.get('CapDrop')!=['ALL'] or not host.get('ReadonlyRootfs') or host.get('Privileged') or host.get('PortBindings') or info['Config'].get('User')!='10001:10001' or set(host.get('SecurityOpt',[]))!={'apparmor='+name,'seccomp=unconfined'}:raise RuntimeError('Runtime isolation mismatch')
  state['isolation']={k:host.get(k) for k in ['Memory','NanoCpus','PidsLimit','CapDrop','SecurityOpt','MaskedPaths','ReadonlyPaths','ReadonlyRootfs','PidMode','UsernsMode']};persist()
  attempt,directory=capture('helperFeasibility',docker+['start','--attach',container_id],20,65536)
  info=inspect_owned(command,name=name,labels={'owasp-ai-goat.owner':owner},image=image,captured_id=container_id);state['containerExit']=info['State'].get('ExitCode')
  if attempt['returncode'] or attempt['timedOut'] or attempt['truncated'] or info['State'].get('Running') or state['containerExit']!=0:raise RuntimeError('Helper feasibility failed; private artifacts retained')
  result=result_contract((directory/'bootstrap-metadata.stdout').read_text());state['result']=result
  if result!={'diagnosticOnly':True,'phase':7,'passed':True,'drained':True}:raise RuntimeError('Helper proof incomplete')
  state['status']='passed'
 except BaseException as error:state['status']='failed';state['errorType']=type(error).__name__
 finally:
  signal.alarm(0)
  for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
  deadline=time.monotonic()+75;errors=[]
  def clean_command(argv):return I.subprocess.run(docker+argv,capture_output=True,text=True,timeout=M.remaining(deadline,10))
  def clean_ssh(argv):
   r=I.subprocess.run(M.SSH+[shlex.join(argv)],capture_output=True,text=True,timeout=M.remaining(deadline,10),check=True);return r
  containers_clean=False
  try:
   state['cleanup']['container']=cleanup_owned(clean_command,daemon_id=M.DAEMON_ID,name=name,labels={'owasp-ai-goat.owner':owner},image=image,captured_id=container_id)
   if container_id and inspect_owned(clean_command,name=container_id,labels={'owasp-ai-goat.owner':owner},image=image) is not None:raise RuntimeError('Container remains')
   containers_clean=True
  except Exception:errors.append('container-cleanup-failed')
  try:
   if remote_owned or state.get('remoteRootOwned'):
    if not containers_clean or clean_ssh(['cat',remote+'/owner']).stdout!=owner+'\n':raise RuntimeError('Remote ownership/cleanup mismatch')
    rows=clean_ssh(['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout.splitlines()
    if any(x.startswith(name+' ') or x.startswith(name+'//') for x in rows):clean_ssh(['sudo','apparmor_parser','-R',remote+'/policy'])
    rows=clean_ssh(['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout.splitlines()
    if any(x.startswith(name+' ') or x.startswith(name+'//') for x in rows):raise RuntimeError('Profile remains')
    for rel in ['policy','owner']:clean_ssh(['rm','-f','--',remote+'/'+rel])
    clean_ssh(['rmdir','--',remote]);clean_ssh(['test','!','-e',remote]);state['cleanup']['profileAndRemoteAbsent']=True
  except Exception:errors.append('profile-remote-cleanup-failed')
  try:
   net=M.inspect_resource(clean_command,'network',network)
   if net:
    if net.get('Labels',{}).get('owasp-ai-goat.owner')!=owner or clean_command(['network','rm',network]).returncode:raise RuntimeError('Network cleanup failed')
   if M.inspect_resource(clean_command,'network',network):raise RuntimeError('Network remains')
   state['cleanup']['networkAbsent']=True;state['cleanup']['image']=I.cleanup_image(clean_command,tag,owner,image)
  except Exception:errors.append('network-image-cleanup-failed')
  try:ca.unlink(missing_ok=True);state['cleanup']['privateCaAbsent']=not ca.exists()
  except Exception:errors.append('private-ca-cleanup-failed')
  if state.get('pendingRemoteCreate'):errors.append('remote-create-acknowledgment-uncertain')
  if state.get('linuxCompilation',{}).get('started') or state.get('linuxCompilation',{}).get('timedOut'):errors.append('daemon-builder-termination-unverified')
  try:
   check=I.subprocess.run(['python3','-B','-c',"import sys,json;sys.path.insert(0,sys.argv[1]);from owned_mcp_assembly_freeze import verify;print(json.dumps(verify(sys.argv[2],sys.argv[3],sys.argv[4])))",str(SOURCE/'tests/postgres'),str(SOURCE),a.source_sha256,a.dependency_sha256],capture_output=True,text=True,timeout=M.remaining(deadline,30),check=True);state['endIntegrity']=json.loads(check.stdout)
  except Exception:errors.append('end-integrity-failed')
  # Bind even interrupted private captures; never emit their contents.
  for stage in ['linuxCompilation','helperFeasibility']:
   for filename in ['bootstrap-metadata.stdout','bootstrap-metadata.stderr']:
    path=root/stage/filename
    if path.is_file() and not path.is_symlink():
     name_=stage+'/'+filename
     if not any(x['name']==name_ for x in state['artifacts']):state['artifacts'].append({'name':name_,'sha256':sha(path),'bytes':path.stat().st_size,'mode':'0600'})
  state['cleanup']['errors']=errors
  if errors:state['status']='failed'
  persist()
 print(json.dumps({'root':str(root),'status':state['status'],'stage':state['stage'],'cleanup':state['cleanup']}));return 0 if state['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
