"""Owned HTTP executor container for the isolated System repository qualifier."""
import hashlib, http.client, json, os, secrets, shutil, signal, subprocess, time
from pathlib import Path

BASE='sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5'
BUILD_TIMEOUT_SECONDS=420
class OwnedDiagnosticExecutor:
 def __init__(self, root, workspace, docker, env, owner, persist):
  self.root,self.workspace,self.docker,self.env,self.owner,self.persist=root,workspace,docker,env,owner,persist
  self.name='dvaia-diagnostic-http-'+owner[:12];self.tag=self.name+':owned';self.network=self.name+'-bridge'
  self.build=None;self.token=secrets.token_urlsafe(32);self.secret_file=root/'diagnostic-executor-private.env'
  self.state={'container':self.name,'imageTag':self.tag,'network':self.network,'base':BASE,'creationAttempted':False,'networkAttempted':False,'imageBuildAttempted':False,'cleanup':None}
 def run(self,args,timeout=30,check=True):
  r=subprocess.run(self.docker+args,env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
  if check and r.returncode:raise RuntimeError('Owned executor Docker operation failed')
  return r
 def inspect(self,kind,name):
  return json.loads(self.run([kind,'inspect',name]).stdout)[0]
 def absent(self,kind,name):
  if kind=='container':args=['ps','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']
  elif kind=='network':args=['network','ls','--filter','name=^'+name+'$','--format','{{.Name}}']
  else:args=['image','ls','--no-trunc','--filter','reference='+name,'--format','{{.Repository}}:{{.Tag}}']
  return not self.run(args).stdout.strip()
 def groups(self):
  if not self.build:return []
  rows=subprocess.run(['ps','-axo','pid=,pgid=,uid=,stat='],env=self.env,capture_output=True,text=True,timeout=5,check=True).stdout.splitlines()
  members=[]
  for row in rows:
   fields=row.split()
   if len(fields)==4 and int(fields[1])==self.build.pid:
    if int(fields[2])!=os.getuid():raise RuntimeError('Foreign build process group')
    if not fields[3].startswith('Z'):members.append(int(fields[0]))
  return members
 def owned_build_member(self,pid):
  inspection=subprocess.run(['ps','-p',str(pid),'-o','pgid=,uid=,stat='],env=self.env,capture_output=True,text=True,timeout=5,check=False)
  row=inspection.stdout.strip()
  if inspection.returncode==1 and not row:return False
  if inspection.returncode!=0:raise RuntimeError('Build process inspection failed')
  fields=row.split()
  if len(fields)!=3 or int(fields[0])!=self.build.pid or int(fields[1])!=os.getuid():raise RuntimeError('Build process identity changed')
  return not fields[2].startswith('Z')
 def signal_build_members(self,number):
  for pid in self.groups():
   if not self.owned_build_member(pid):continue
   try:os.kill(pid,number)
   except ProcessLookupError:pass
 def stop_build(self):
  self.signal_build_members(signal.SIGTERM)
  deadline=time.monotonic()+3
  while self.groups() and time.monotonic()<deadline:time.sleep(.05)
  self.signal_build_members(signal.SIGKILL)
  if self.build:
   try:self.build.wait(timeout=5)
   except subprocess.TimeoutExpired as error:raise RuntimeError('Build process remains') from error
  if self.groups():raise RuntimeError('Build process group remains')
 def wait_for_build(self):
  try:return self.build.wait(timeout=BUILD_TIMEOUT_SECONDS)
  except BaseException as primary:
   try:self.stop_build()
   except BaseException as cleanup:
    self.state['buildStopError']=type(cleanup).__name__
    recording=None
    try:self.persist()
    except BaseException as error:recording=error
    if hasattr(primary,'add_note'):
     primary.add_note('Owned build cleanup failed: '+type(cleanup).__name__)
     if recording is not None:primary.add_note('Owned build cleanup recording failed: '+type(recording).__name__)
   raise
 def start(self):
  info=self.inspect('image',BASE)
  if info['Id']!=BASE or info['Architecture']!='arm64':raise RuntimeError('Reviewed ARM64 base required')
  for kind,name in [('container',self.name),('network',self.network),('image',self.tag)]:
   if not self.absent(kind,name):raise RuntimeError('Owned executor identity collision')
  context=self.root/'executor-build';context.mkdir(mode=0o700)
  shutil.copytree(self.workspace/'sidecars/sandbox-runner/owned-system',context/'owned-system')
  (context/'diagnostic-listener-entry.js').write_text("const {runSystemDiagnosticListener,createSystemDiagnosticHttpListener}=require('./owned-system/diagnostic-http-listener');runSystemDiagnosticListener({createListener:options=>createSystemDiagnosticHttpListener({...options,maxConcurrent:1})}).then(code=>{process.exitCode=code;},()=>{process.exitCode=1;});\n")
  self.state['entrySha256']=hashlib.sha256((context/'diagnostic-listener-entry.js').read_bytes()).hexdigest()
  dockerfile='''FROM node@'''+BASE+'''
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev bubblewrap && rm -rf /var/lib/apt/lists/*
COPY owned-system /qualification/owned-system
COPY diagnostic-listener-entry.js /qualification/diagnostic-listener-entry.js
RUN mkdir -p /usr/local/libexec && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/diagnostic-init.c -o /usr/local/libexec/dvaia-system-diagnostic-init && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/diagnostic-supervisor.c -o /usr/local/libexec/dvaia-system-diagnostic-supervisor && chmod 0555 /usr/local/libexec/dvaia-system-diagnostic-* /usr/bin/bwrap && for f in /usr/local/libexec/dvaia-system-diagnostic-init /usr/local/libexec/dvaia-system-diagnostic-supervisor; do sha256sum "$f" | cut -d' ' -f1 > "$f.sha256"; chmod 0444 "$f.sha256"; done && dpkg-query -W > /qualification/packages.txt
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/node","/qualification/diagnostic-listener-entry.js"]
'''
  (context/'Dockerfile').write_text(dockerfile);self.state['dockerfileSha256']=hashlib.sha256(dockerfile.encode()).hexdigest()
  self.state['imageBuildAttempted']=True;self.persist()
  with (self.root/'executor-build.log').open('w') as log:
   self.build=subprocess.Popen(self.docker+['build','--pull=false','--network=default','--label','dvaia.test.owner='+self.owner,'-t',self.tag,str(context)],env=self.env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   self.state['buildPgid']=self.build.pid;self.persist()
   code=self.wait_for_build()
   if code:raise RuntimeError('Owned executor image build failed')
  image=self.inspect('image',self.tag)
  if image['Config']['Labels'].get('dvaia.test.owner')!=self.owner:raise RuntimeError('Executor image owner mismatch')
  self.state['imageId']=image['Id'];self.state['networkAttempted']=True;self.persist()
  self.run(['network','create','--label','dvaia.test.owner='+self.owner,self.network])
  network=self.inspect('network',self.network)
  if network.get('Internal') is not False or network.get('Labels',{}).get('dvaia.test.owner')!=self.owner:raise RuntimeError('Owned bridge network unavailable')
  self.state['networkInternal']=False;self.state['outerEgressIsolationEstablished']=False
  self.secret_file.write_text('SECURESHOP_SYSTEM_DIAGNOSTIC_HTTP_ENABLED=true\nSECURESHOP_SYSTEM_DIAGNOSTIC_TOKEN='+self.token+'\nSECURESHOP_SYSTEM_DIAGNOSTIC_HOST=0.0.0.0\nSECURESHOP_SYSTEM_DIAGNOSTIC_PORT=8090\n');os.chmod(self.secret_file,0o600)
  self.state['creationAttempted']=True;self.persist()
  self.run(['run','--detach','--pull','never','--name',self.name,'--label','dvaia.test.owner='+self.owner,'--network',self.network,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--security-opt','seccomp=unconfined','--security-opt','apparmor=dvaia-mcp-sandbox','-p','127.0.0.1::8090','--env-file',str(self.secret_file),image['Id']])
  self.secret_file.unlink()
  deadline=time.monotonic()+5
  while True:
   actual=self.inspect('container',self.name);ports=actual['NetworkSettings']['Ports'];bindings=ports.get('8090/tcp') or []
   self.state['portDiagnostic']={'running':actual['State']['Running'],'exitCode':actual['State']['ExitCode'],'networkPorts':ports,'hostBindings':actual['HostConfig']['PortBindings'],'networkNames':list(actual['NetworkSettings']['Networks'])};self.persist()
   if bindings or not actual['State']['Running'] or time.monotonic()>=deadline:break
   time.sleep(.1)
  host_bindings=actual['HostConfig']['PortBindings']
  if set(host_bindings)!={'8090/tcp'} or len(host_bindings['8090/tcp'])!=1 or host_bindings['8090/tcp'][0]['HostIp']!='127.0.0.1':raise RuntimeError('Executor host publish binding mismatch')
  if actual.get('Mounts') or actual['Config']['Labels'].get('dvaia.test.owner')!=self.owner or set(actual['NetworkSettings']['Networks'])!={self.network} or set(ports)!={'8090/tcp'} or len(bindings)!=1 or bindings[0]['HostIp']!='127.0.0.1':raise RuntimeError('Executor mount/network/port isolation mismatch')
  if actual['Config']['User']!='10001:10001' or actual['HostConfig']['ReadonlyRootfs'] is not True or actual['HostConfig']['Memory']!=536870912 or actual['HostConfig']['NanoCpus']!=1000000000 or actual['HostConfig']['PidsLimit']!=128:raise RuntimeError('Executor runtime resource mismatch')
  self.state['runtime']={'user':actual['Config']['User'],'readOnlyRoot':actual['HostConfig']['ReadonlyRootfs'],'memory':actual['HostConfig']['Memory'],'nanoCpus':actual['HostConfig']['NanoCpus'],'pidsLimit':actual['HostConfig']['PidsLimit'],'tmpfs':actual['HostConfig']['Tmpfs'],'ports':ports,'mounts':actual['Mounts'],'securityOpt':actual['HostConfig']['SecurityOpt']}
  self.url='http://127.0.0.1:'+bindings[0]['HostPort'];self.persist()
  deadline=time.monotonic()+40
  while time.monotonic()<deadline:
   connection=http.client.HTTPConnection('127.0.0.1',int(bindings[0]['HostPort']),timeout=2)
   try:
    connection.request('GET','/secureshop/system/diagnostic-health',headers={'Authorization':'Bearer '+self.token});response=connection.getresponse();raw=response.read(32769)
    if response.status==200 and len(raw)<=32768 and json.loads(raw)=={'version':'secureshop-owned-system-diagnostic-http.v1','ready':True,'isolation':'bwrap-system-diagnostic-v1','diagnosticCapability':'secureshop-owned-system-diagnostic.v1'}:break
   except (OSError,ValueError,http.client.HTTPException):pass
   finally:connection.close()
   time.sleep(.25)
  else:raise RuntimeError('Owned executor authenticated readiness unavailable')
  self.state['authenticatedReadiness']=True;self.run(['cp',self.name+':/qualification/packages.txt',str(self.root/'executor-packages.txt')]);self.persist()
  return self.url,self.token
 def close(self):
  errors=[];exit_code=None
  try:self.stop_build()
  except BaseException as e:errors.append('build:'+type(e).__name__)
  if self.state['creationAttempted']:
   try:
    if not self.absent('container',self.name):
     actual=self.inspect('container',self.name)
     if actual['Config']['Labels'].get('dvaia.test.owner')!=self.owner:raise RuntimeError('Foreign executor container')
     self.run(['stop','--time','25',self.name],timeout=35)
     exit_code=self.inspect('container',self.name)['State']['ExitCode']
     logs=self.run(['logs','--tail','100',self.name],check=False);safe=(logs.stdout+logs.stderr).replace(self.token,'[REDACTED]');(self.root/'executor.log').write_text(safe)
     self.run(['rm','-f','-v',self.name])
   except BaseException as e:errors.append('container:'+type(e).__name__)
   finally:
    try:
     if not self.absent('container',self.name):
      if self.inspect('container',self.name)['Config']['Labels'].get('dvaia.test.owner')!=self.owner:raise RuntimeError('Foreign container cleanup refused')
      self.run(['rm','-f','-v',self.name])
    except BaseException as e:errors.append('container-final:'+type(e).__name__)
  if self.state['imageBuildAttempted']:
   try:
    if not self.absent('image',self.tag):
     image=self.inspect('image',self.tag)
     if image['Config']['Labels'].get('dvaia.test.owner')!=self.owner:raise RuntimeError('Foreign executor image')
     self.run(['image','rm',self.tag])
   except BaseException as e:errors.append('image:'+type(e).__name__)
  if self.state['networkAttempted']:
   try:
    if not self.absent('network',self.network):
     network=self.inspect('network',self.network)
     if network.get('Labels',{}).get('dvaia.test.owner')!=self.owner or network.get('Containers'):raise RuntimeError('Foreign or occupied executor network')
     self.run(['network','rm',self.network])
   except BaseException as e:errors.append('network:'+type(e).__name__)
  self.secret_file.unlink(missing_ok=True)
  flags={}
  for kind,name in [('container',self.name),('network',self.network),('image',self.tag)]:
   try:flags[kind+'Absent']=self.absent(kind,name)
   except BaseException as e:flags[kind+'Absent']=False;errors.append(kind+'absence:'+type(e).__name__)
  try:
   flags['buildPgidAbsent']=not self.groups()
   flags['imageIdAbsent']=not self.state.get('imageId') or self.state['imageId'] not in self.run(['image','ls','--no-trunc','--format','{{.ID}}']).stdout.splitlines()
  except BaseException as e:errors.append('identity-absence:'+type(e).__name__);flags['identityAbsenceConfirmed']=False
  if any(v is not True for v in flags.values()):errors.append('absence-not-confirmed')
  if exit_code not in [None,0]:errors.append('listener-nonzero-exit')
  self.state['cleanup']={**flags,'listenerExitCode':exit_code,'errors':errors};self.persist()
  return not errors
