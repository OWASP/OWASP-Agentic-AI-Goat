"""Owned HTTP executor container for the isolated System repository qualifier."""
import hashlib, http.client, json, os, secrets, shutil, signal, subprocess, time
from pathlib import Path
from types import SimpleNamespace
from listings_package_candidate import buildx_identity
from system_diagnostic_owned_executor import (
 BASE, ARM64_MANIFEST, ARM64_CONFIG, BASE_AUDIT_PATH, BASE_AUDIT_SHA256,
 admit_original_base_identity,
)

RESTART_BASE='sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1'
RESTART_CACHE_PREFIX='dvaia-system-restart-content:'
def original_system_dockerfile():
 # One original recipe, shared by the historical fenced caller and future
 # private builder. Exporting bytes grants no build or runtime authority.
 return OwnedSystemExecutor.original_dockerfile()

def original_system_build_recipe():
 dockerfile=original_system_dockerfile()
 return {'version':1,'target':'v24-system','base':BASE,'platform':'linux/arm64',
         'sourceRoot':'sidecars/sandbox-runner/owned-system',
         'dockerfile':dockerfile,'dockerfileSha256':hashlib.sha256(dockerfile.encode()).hexdigest(),
         'packages':['gcc','libc6-dev','bubblewrap'],'user':'10001:10001',
         'entrypoint':['/usr/local/bin/node','/qualification/owned-system/http-listener.js']}

def require_private_system_runtime_admission():
 # Identity validation is not permission to use the historical shared daemon.
 # The original config listener needs a reviewed private build/runtime handoff.
 # No caller argument or environment flag can bypass this fence.
 raise RuntimeError('V24_PRIVATE_RUNTIME_NOT_ADMITTED')

def restart_content_digest(root):
 h=hashlib.sha256()
 for entry in sorted(root.rglob('*'),key=lambda value:value.relative_to(root).as_posix()):
  if entry.is_symlink():raise RuntimeError('Restart content cache rejects symlinks')
  relative=entry.relative_to(root).as_posix().encode()
  if entry.is_dir():h.update(b'D\0'+relative+b'\0');continue
  if not entry.is_file():raise RuntimeError('Restart content cache requires regular files')
  h.update(b'F\0'+relative+b'\0'+format(entry.stat().st_mode&0o777,'04o').encode()+b'\0')
  h.update(entry.read_bytes());h.update(b'\0')
 return h.hexdigest()
def validate_restart_content_cache(value,image,tag,source_digest):
 image_id=image.get('Id')
 expected={'version':1,'tag':tag,'imageId':image.get('Id'),'sourceSha256':source_digest,'base':RESTART_BASE}
 labels=image.get('Config',{}).get('Labels') or {}
 if not isinstance(image_id,str) or len(image_id)!=71 or not image_id.startswith('sha256:') \
  or any(character not in '0123456789abcdef' for character in image_id[7:]) \
  or value!=expected or image.get('Architecture')!='arm64' \
  or labels.get('dvaia.cache.kind')!='system-restart-content' \
  or labels.get('dvaia.cache.source')!=source_digest or labels.get('dvaia.cache.base')!=RESTART_BASE:
  raise RuntimeError('Restart content cache inspection mismatch')
 return True
def upload_preview_buildx_identity(docker):
 return buildx_identity(SimpleNamespace(digest=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()),SimpleNamespace(docker=docker))
def upload_preview_build_environment(root,docker,environment):
 # Reuse the qualified Listings BuildKit plugin/config contract; no user config.
 plugin=upload_preview_buildx_identity(docker);root.mkdir(mode=0o700)
 target=root/'config.json'
 with target.open('x') as stream:json.dump({'cliPluginsExtraDirs':[str(Path(plugin['path']).parent)]},stream)
 target.chmod(0o600)
 build_env={**environment,'DOCKER_CONFIG':str(root),'DOCKER_BUILDKIT':'1'}
 version=subprocess.run([docker,'buildx','version'],env=build_env,capture_output=True,text=True,timeout=10,check=True)
 if not version.stdout.strip() or len(version.stdout.encode())>4096 or version.stderr.strip():raise RuntimeError('Bounded pinned Buildx version required')
 return build_env,{'plugin':plugin,'configSha256':hashlib.sha256(target.read_bytes()).hexdigest(),'version':version.stdout.strip()}
class OwnedSystemExecutor:
 @staticmethod
 def original_dockerfile():
  return '''FROM node@'''+BASE+'''
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev bubblewrap && rm -rf /var/lib/apt/lists/*
COPY . /qualification/owned-system
RUN mkdir -p /usr/local/libexec && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/system-init.c -o /usr/local/libexec/dvaia-system-config-init && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/process-supervisor.c -o /usr/local/libexec/dvaia-system-config-supervisor && chmod 0555 /usr/local/libexec/dvaia-system-config-* /usr/bin/bwrap && dpkg-query -W > /qualification/packages.txt
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/node","/qualification/owned-system/http-listener.js"]
'''

 def __init__(self, root, workspace, docker, env, owner, persist):
  self.root,self.workspace,self.docker,self.env,self.owner,self.persist=root,workspace,docker,env,owner,persist
  self.name='dvaia-system-http-'+owner[:12];self.tag=self.name+':owned';self.network=self.name+'-bridge'
  self.build=None;self.token=secrets.token_urlsafe(32);self.secret_file=root/'system-executor-private.env'
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
  rows=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=self.env,capture_output=True,text=True,timeout=5,check=True).stdout.splitlines()
  members=[]
  for row in rows:
   fields=row.split()
   if len(fields)==3 and int(fields[1])==self.build.pid:
    if int(fields[2])!=os.getuid():raise RuntimeError('Foreign build process group')
    members.append(int(fields[0]))
  return members
 def stop_build(self):
  if self.groups():os.killpg(self.build.pid,signal.SIGTERM)
  deadline=time.monotonic()+3
  while self.groups() and time.monotonic()<deadline:time.sleep(.05)
  if self.groups():os.killpg(self.build.pid,signal.SIGKILL)
  if self.build:self.build.wait(timeout=5)
  if self.groups():raise RuntimeError('Build process group remains')
 def start(self):
  require_private_system_runtime_admission()
  info=self.inspect('image',BASE)
  self.state['baseIdentity']=admit_original_base_identity(info,BASE_AUDIT_PATH.read_bytes(),identity_kind='config')
  for kind,name in [('container',self.name),('network',self.network),('image',self.tag)]:
   if not self.absent(kind,name):raise RuntimeError('Owned executor identity collision')
  context=self.root/'executor-build';context.mkdir(mode=0o700)
  source=self.workspace/'sidecars/sandbox-runner/owned-system'
  if not source.is_dir() or source.resolve(strict=True)!=self.workspace.resolve(strict=True)/'sidecars/sandbox-runner/owned-system':raise RuntimeError('Original owned System source required')
  source_digest=restart_content_digest(source)
  self.state['sourceContext']=str(source);self.state['sourceSha256']=source_digest;self.persist()
  dockerfile=original_system_dockerfile()
  build_file=context/'Dockerfile';build_file.write_text(dockerfile)
  self.state['dockerfileSha256']=hashlib.sha256(dockerfile.encode()).hexdigest()
  self.state['imageBuildAttempted']=True;self.persist()
  with (self.root/'executor-build.log').open('w') as log:
   self.build=subprocess.Popen(self.docker+['build','--pull=false','--network=default','-f',str(build_file),'--label','dvaia.test.owner='+self.owner,'-t',self.tag,str(source)],env=self.env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   self.state['buildPgid']=self.build.pid;self.persist()
   try:code=self.build.wait(timeout=300)
   except BaseException:self.stop_build();raise
   if code:raise RuntimeError('Owned executor image build failed')
  if restart_content_digest(source)!=source_digest:raise RuntimeError('Original owned System source changed during build')
  image=self.inspect('image',self.tag)
  if image['Config']['Labels'].get('dvaia.test.owner')!=self.owner:raise RuntimeError('Executor image owner mismatch')
  self.state['imageId']=image['Id'];self.state['networkAttempted']=True;self.persist()
  self.run(['network','create','--label','dvaia.test.owner='+self.owner,self.network])
  network=self.inspect('network',self.network)
  if network.get('Internal') is not False or network.get('Labels',{}).get('dvaia.test.owner')!=self.owner:raise RuntimeError('Owned bridge network unavailable')
  self.state['networkInternal']=False;self.state['outerEgressIsolationEstablished']=False
  self.secret_file.write_text('SECURESHOP_SYSTEM_CONFIG_HTTP_ENABLED=true\nSECURESHOP_SYSTEM_CONFIG_TOKEN='+self.token+'\nSECURESHOP_SYSTEM_CONFIG_HOST=0.0.0.0\nSECURESHOP_SYSTEM_CONFIG_PORT=8090\n');os.chmod(self.secret_file,0o600)
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
    connection.request('GET','/secureshop/system/health',headers={'Authorization':'Bearer '+self.token});response=connection.getresponse();raw=response.read(32769)
    if response.status==200 and len(raw)<=32768 and json.loads(raw)=={'version':'secureshop-owned-system-http.v1','ready':True,'isolation':'bwrap-system-config-v1','configReadCapability':'secureshop-owned-system-config-read.v1'}:break
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
     # Remove this run's image while retaining Docker's reusable dependency parents.
     # The exact final image/tag absence checks below still determine cleanup success.
     self.run(['image','rm','--no-prune',self.tag])
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


class OwnedSystemRestartExecutor(OwnedSystemExecutor):
 """Owned restart listener using the reviewed local System image contract."""
 def __init__(self, root, workspace, docker, env, owner, persist, mode='restart'):
  if mode not in ('restart','upload-preview'):raise ValueError('Closed owned System listener mode required')
  self.mode=mode
  super().__init__(root, workspace, docker, env, owner, persist)
  self.name='dvaia-system-'+mode+'-'+owner[:12];self.tag=self.name+':owned';self.network=self.name+'-bridge';self.volume=self.name+'-state'
  self.secret_file=root/('system-'+mode+'-private.env')
  self.state={'container':self.name,'imageTag':self.tag,'network':self.network,'volume':self.volume,
   'base':RESTART_BASE,'creationAttempted':False,'networkAttempted':False,'volumeAttempted':False,
   'imageBuildAttempted':False,'cleanup':None}
 def volume_absent(self):
  return self.run(['volume','inspect',self.volume],check=False).returncode!=0
 def request(self, method, path, body=None):
  connection=http.client.HTTPConnection('127.0.0.1',int(self.url.rsplit(':',1)[1]),timeout=3)
  try:
   payload=None if body is None else json.dumps(body,separators=(',',':')).encode()
   headers={'Authorization':'Bearer '+self.token}
   if payload is not None:headers['Content-Type']='application/json'
   connection.request(method,path,body=payload,headers=headers);response=connection.getresponse();raw=response.read(65537)
   if len(raw)>65536:raise RuntimeError('Owned restart response exceeds bound')
   return response.status,json.loads(raw)
  finally:connection.close()
 def start(self):
  info=self.inspect('image',RESTART_BASE)
  if info['Id']!=RESTART_BASE or info['Architecture']!='arm64':raise RuntimeError('Reviewed restart ARM64 base required')
  for kind,name in [('container',self.name),('network',self.network),('image',self.tag)]:
   if not self.absent(kind,name):raise RuntimeError('Owned restart executor identity collision')
  if not self.volume_absent():raise RuntimeError('Owned restart executor volume collision')
  context=self.root/'restart-executor-build';context.mkdir(mode=0o700)
  package=context/'owned-system'
  if self.mode=='upload-preview':
   # The reviewed Docker context contains only the 43 measured package assets.
   package.mkdir(mode=0o700);source=self.workspace/'sidecars/sandbox-runner/owned-system'
   manifest=json.loads((source/'local-package-manifest.json').read_text())
   if len(manifest.get('files',{}))!=43:raise RuntimeError('Closed upload preview package required')
   for name,expected in manifest['files'].items():
    relative=Path(name)
    if relative.is_absolute() or '..' in relative.parts:raise RuntimeError('Unsafe package asset path')
    file=source/relative
    if source.is_symlink() or any((source/Path(*relative.parts[:i])).is_symlink() for i in range(1,len(relative.parts)+1)) or not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest()!=expected:raise RuntimeError('Measured upload preview asset changed')
    destination=package/relative;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(file,destination)
   self.state['packageSourceHashes']=manifest['files'];self.persist()
  else:shutil.copytree(self.workspace/'sidecars/sandbox-runner/owned-system',package)
  dockerfile=(package/'Dockerfile.local').read_text()
  if 'FROM node@'+RESTART_BASE not in dockerfile:raise RuntimeError('Reviewed restart Dockerfile base mismatch')
  source_digest=restart_content_digest(package);cache_tag=RESTART_CACHE_PREFIX+source_digest[:32]
  self.state['selectedCacheTag']=cache_tag;self.persist()
  cache_root=self.root.parent/'restart-content-cache';cache_root.mkdir(mode=0o700,exist_ok=True)
  if cache_root.is_symlink() or not cache_root.is_dir() or cache_root.stat().st_uid!=os.getuid() \
   or cache_root.stat().st_mode&0o777!=0o700:raise RuntimeError('Private restart content cache directory required')
  manifest_path=cache_root/'manifest.json'
  def manifest():
   if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_uid!=os.getuid() \
    or manifest_path.stat().st_mode&0o777!=0o600:raise RuntimeError('Private restart content cache manifest required')
   value=json.loads(manifest_path.read_text())
   if not isinstance(value,dict) or set(value)!={'version','tag','imageId','sourceSha256','base'}:raise RuntimeError('Restart content cache manifest invalid')
   return value
  listed=self.run(['image','ls','--no-trunc','--filter','reference='+RESTART_CACHE_PREFIX+'*','--format','{{.Repository}}:{{.Tag}}']).stdout.splitlines()
  prior=manifest() if manifest_path.exists() or manifest_path.is_symlink() else None
  if prior and prior['tag']!=cache_tag:
   if prior['tag'] not in listed:raise RuntimeError('Restart content cache manifest image missing')
   old=self.inspect('image',prior['tag']);labels=old.get('Config',{}).get('Labels') or {}
   if old.get('Id')!=prior['imageId'] or labels.get('dvaia.cache.kind')!='system-restart-content' \
    or labels.get('dvaia.cache.source')!=prior['sourceSha256'] or labels.get('dvaia.cache.base')!=prior['base']:
    raise RuntimeError('Foreign restart content cache refused')
   self.run(['image','rm',prior['tag']]);listed.remove(prior['tag']);prior=None;manifest_path.unlink()
  # Other source hashes may have independently owned historical cache tags.
  if listed.count(cache_tag)>1:
   raise RuntimeError('Duplicate selected restart content cache image refused')
  cache_labels={'dvaia.cache.kind':'system-restart-content','dvaia.cache.source':source_digest,
   'dvaia.cache.base':RESTART_BASE}
  if cache_tag in listed:
   if not prior:raise RuntimeError('Restart content cache manifest missing')
   cache=self.inspect('image',cache_tag)
  else:
   with (self.root/'restart-content-build.log').open('w') as log:
    build_secrets=[];ca=None
    if self.mode=='upload-preview':
     certificates=''
     for keychain in ['/Library/Keychains/System.keychain',str(Path.home()/'Library/Keychains/login.keychain-db')]:
      certificates+=subprocess.run(['/usr/bin/security','find-certificate','-a','-p',keychain],env=self.env,capture_output=True,text=True,timeout=30,check=True).stdout
     if '-----BEGIN CERTIFICATE-----' not in certificates or len(certificates.encode())>1048576:raise RuntimeError('Bounded build CA unavailable')
     ca=self.root/'upload-preview-build-ca.pem';ca.write_text(certificates);ca.chmod(0o600);self.state['buildCaSha256']=hashlib.sha256(ca.read_bytes()).hexdigest();self.persist();build_secrets=['--secret','id=npm_ca,src='+str(ca)]
    command=self.docker+['build','--pull=false','--network=default',*build_secrets]
    for key,value in cache_labels.items():command+=['--label',key+'='+value]
    command+=['-f','Dockerfile.local','-t',cache_tag,'.']
    self.state['cacheBuildAttempted']=True;self.persist()
    self.build=subprocess.Popen(command,cwd=package,env=self.env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    self.state['buildPgid']=self.build.pid;self.persist()
    try:code=self.build.wait(timeout=300)
    except BaseException:self.stop_build();raise
    finally:
     if ca is not None and ca.exists():
      st=ca.lstat()
      if ca.is_symlink() or st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_mode&0o777!=0o600 or hashlib.sha256(ca.read_bytes()).hexdigest()!=self.state['buildCaSha256']:raise RuntimeError('Build CA identity changed')
      ca.unlink()
    if code:raise RuntimeError('Restart content cache image build failed')
   cache=self.inspect('image',cache_tag)
   value={'version':1,'tag':cache_tag,'imageId':cache['Id'],'sourceSha256':source_digest,'base':RESTART_BASE}
   temporary=manifest_path.with_suffix('.tmp');temporary.write_text(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
   os.chmod(temporary,0o600);os.replace(temporary,manifest_path);prior=value
  validate_restart_content_cache(prior,cache,cache_tag,source_digest)
  self.state['contentCache']={'retained':True,'tag':cache_tag,'imageId':cache['Id'],
   'sourceSha256':source_digest,'base':RESTART_BASE};self.persist()
  child=context/'owned-child';child.mkdir(mode=0o700)
  base_reference=cache_tag if self.mode=='upload-preview' else cache['Id']
  (child/'Dockerfile').write_text('FROM '+base_reference+'\nLABEL dvaia.test.owner="'+self.owner+'"\n')
  self.state['imageBuildAttempted']=True;self.persist()
  with (self.root/'restart-executor-build.log').open('w') as log:
   validate_restart_content_cache(prior,self.inspect('image',cache_tag),cache_tag,source_digest)
   self.build=subprocess.Popen(self.docker+['build','--pull=false','--network=none','-t',self.tag,'.'],cwd=child,env=self.env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   self.state['buildPgid']=self.build.pid;self.persist()
   try:code=self.build.wait(timeout=300)
   except BaseException:self.stop_build();raise
   if code:raise RuntimeError('Owned restart executor image build failed')
  validate_restart_content_cache(prior,self.inspect('image',cache_tag),cache_tag,source_digest)
  image=self.inspect('image',self.tag)
  if image['Architecture']!='arm64' or image['Config']['Labels'].get('dvaia.test.owner')!=self.owner \
   or image.get('RootFS',{}).get('Layers')!=cache.get('RootFS',{}).get('Layers'):
   raise RuntimeError('Restart executor image owner or content mismatch')
  self.state['imageId']=image['Id'];self.state['networkAttempted']=True;self.persist()
  self.run(['network','create','--label','dvaia.test.owner='+self.owner,self.network])
  network=self.inspect('network',self.network)
  if network.get('Internal') is not False or network.get('Labels',{}).get('dvaia.test.owner')!=self.owner:raise RuntimeError('Restart executor network unavailable')
  if self.mode=='restart':
   self.state['volumeAttempted']=True;self.persist();self.run(['volume','create','--label','dvaia.test.owner='+self.owner,self.volume])
   volume=self.inspect('volume',self.volume)
   if volume.get('Labels',{}).get('dvaia.test.owner')!=self.owner:raise RuntimeError('Restart executor volume owner mismatch')
  prefix='SECURESHOP_UPLOAD_PREVIEW' if self.mode=='upload-preview' else 'SECURESHOP_SYSTEM_RESTART'
  self.secret_file.write_text(prefix+'_HTTP_ENABLED=true\n'+prefix+'_TOKEN='+self.token+'\n'+prefix+'_HOST=0.0.0.0\n'+prefix+'_PORT=8090\n');os.chmod(self.secret_file,0o600)
  self.state['creationAttempted']=True;self.persist()
  writable=['--tmpfs','/var/lib/dvaia-owned-upload-preview:rw,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001'] if self.mode=='upload-preview' else ['--tmpfs','/owned-restart:rw,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001','--mount','type=volume,source='+self.volume+',target=/var/lib/dvaia-owned-restart']
  self.run(['run','--detach','--pull','never','--name',self.name,'--label','dvaia.test.owner='+self.owner,
   '--network',self.network,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128',
   '--tmpfs','/tmp:rw,nosuid,nodev,size=128m',*writable,'--security-opt','seccomp=unconfined',
   '--security-opt','apparmor=dvaia-mcp-sandbox','-p','127.0.0.1::8090','--env-file',str(self.secret_file),image['Id'],self.mode])
  self.secret_file.unlink()
  deadline=time.monotonic()+60;status=None;health=None
  while time.monotonic()<deadline:
   actual=self.inspect('container',self.name);bindings=(actual['NetworkSettings']['Ports'] or {}).get('8090/tcp') or []
   if bindings:
    self.url='http://127.0.0.1:'+bindings[0]['HostPort']
    try:
     status,health=self.request('GET','/secureshop/uploads/preview-health' if self.mode=='upload-preview' else '/secureshop/system/restart-health')
     if status==200:break
    except (OSError,ValueError,http.client.HTTPException):pass
   if not actual['State']['Running']:break
   time.sleep(.1)
  else:raise RuntimeError('Owned restart executor authenticated readiness unavailable')
  expected_health={'version':1,'ready':True,'isolation':'bwrap-upload-preview-v1','previewCapability':'secureshop-upload-preview.v1'} if self.mode=='upload-preview' else {'version':'secureshop-owned-system-restart-http.v2','ready':True,
   'isolation':'owned-restart-namespace-v1','restartCapability':'secureshop-owned-system-restart.v2',
   'limits':{'maxPersistedTargets':200,'maxResidentTargets':32,'maxConcurrentExecutions':4,'maxQueuedExecutions':16}}
  if status!=200 or health!=expected_health:
   raise RuntimeError('Owned restart executor readiness mismatch')
  host=actual['HostConfig'];mounts=actual.get('Mounts') or []
  ports=actual['NetworkSettings']['Ports'];bindings=(ports or {}).get('8090/tcp') or []
  if actual['Config']['Labels'].get('dvaia.test.owner')!=self.owner \
   or set(actual['NetworkSettings']['Networks'])!={self.network} or set(ports or {})!={'8090/tcp'} \
   or set(host['PortBindings'] or {})!={'8090/tcp'} or len(bindings)!=1 \
   or len(host['PortBindings']['8090/tcp'])!=1 or bindings[0].get('HostIp')!='127.0.0.1' \
   or host['PortBindings']['8090/tcp'][0].get('HostIp')!='127.0.0.1':
   raise RuntimeError('Owned restart executor network or publish binding mismatch')
  if actual['Config']['User']!='10001:10001' or host['ReadonlyRootfs'] is not True or host['Memory']!=536870912 \
   or host['NanoCpus']!=1000000000 or host['PidsLimit']!=128:
   raise RuntimeError('Owned System listener runtime mismatch')
  if self.mode=='upload-preview':
   if mounts or host['Tmpfs'].get('/var/lib/dvaia-owned-upload-preview')!='rw,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001':raise RuntimeError('Owned upload preview writable root mismatch')
  elif len(mounts)!=1 or mounts[0].get('Type')!='volume' or mounts[0].get('Name')!=self.volume \
   or mounts[0].get('Destination')!='/var/lib/dvaia-owned-restart' or mounts[0].get('RW') is not True:
   raise RuntimeError('Owned restart executor runtime mismatch')
  self.state['runtime']={'user':actual['Config']['User'],'readOnlyRoot':host['ReadonlyRootfs'],'memory':host['Memory'],
   'nanoCpus':host['NanoCpus'],'pidsLimit':host['PidsLimit'],'tmpfs':host['Tmpfs'],'ports':actual['NetworkSettings']['Ports'],
   'mounts':mounts,'securityOpt':host['SecurityOpt']};self.state['authenticatedReadiness']=True;self.persist()
  return self.url,self.token
 def close(self):
  errors=[];exit_code=None
  try:self.stop_build()
  except BaseException as e:errors.append('build:'+type(e).__name__)
  if self.state['creationAttempted']:
   try:
    if not self.absent('container',self.name):
     actual=self.inspect('container',self.name)
     if actual['Config']['Labels'].get('dvaia.test.owner')!=self.owner:raise RuntimeError('Foreign restart executor container')
     self.run(['stop','--time','25',self.name],timeout=35);exit_code=self.inspect('container',self.name)['State']['ExitCode']
     logs=self.run(['logs','--tail','100',self.name],check=False);safe=(logs.stdout+logs.stderr).replace(self.token,'[REDACTED]')
     target=self.root/'restart-executor.log';target.write_text(safe);os.chmod(target,0o600);self.run(['rm','-f','-v',self.name])
   except BaseException as e:errors.append('container:'+type(e).__name__)
   finally:
    try:
     if not self.absent('container',self.name):
      if self.inspect('container',self.name)['Config']['Labels'].get('dvaia.test.owner')!=self.owner:raise RuntimeError('Foreign restart container cleanup refused')
      self.run(['rm','-f','-v',self.name])
    except BaseException as e:errors.append('container-final:'+type(e).__name__)
  if self.state['volumeAttempted']:
   try:
    if not self.volume_absent():
     if self.inspect('volume',self.volume).get('Labels',{}).get('dvaia.test.owner')!=self.owner:raise RuntimeError('Foreign restart volume')
     self.run(['volume','rm',self.volume])
   except BaseException as e:errors.append('volume:'+type(e).__name__)
  if self.state['imageBuildAttempted']:
   try:
    if not self.absent('image',self.tag):
     if self.inspect('image',self.tag)['Config']['Labels'].get('dvaia.test.owner')!=self.owner:raise RuntimeError('Foreign restart image')
     self.run(['image','rm',self.tag])
   except BaseException as e:errors.append('image:'+type(e).__name__)
  if self.state['networkAttempted']:
   try:
    if not self.absent('network',self.network):
     network=self.inspect('network',self.network)
     if network.get('Labels',{}).get('dvaia.test.owner')!=self.owner or network.get('Containers'):raise RuntimeError('Foreign or occupied restart network')
     self.run(['network','rm',self.network])
   except BaseException as e:errors.append('network:'+type(e).__name__)
  self.secret_file.unlink(missing_ok=True)
  flags={}
  for kind,name in [('container',self.name),('network',self.network),('image',self.tag)]:
   try:flags[kind+'Absent']=self.absent(kind,name)
   except BaseException as e:flags[kind+'Absent']=False;errors.append(kind+'absence:'+type(e).__name__)
  try:flags['volumeAbsent']=self.volume_absent()
  except BaseException as e:flags['volumeAbsent']=False;errors.append('volume-absence:'+type(e).__name__)
  try:
   cache_state=self.state.get('contentCache')
   if cache_state:
    cache=self.inspect('image',cache_state['tag']);cache_labels=cache.get('Config',{}).get('Labels') or {}
    flags['contentCacheRetained']=cache.get('Id')==cache_state['imageId'] \
     and cache_labels.get('dvaia.cache.kind')=='system-restart-content' \
     and cache_labels.get('dvaia.cache.source')==cache_state['sourceSha256'] \
     and cache_labels.get('dvaia.cache.base')==cache_state['base']
   else:
    # No cache is owned by this run before verified cache admission. All actual
    # run-owned container/network/image/process absence checks still follow.
    flags['contentCacheNotAdmitted']=not self.state['imageBuildAttempted'] and not self.groups() and (not self.state.get('cacheBuildAttempted') or self.absent('image',self.state['selectedCacheTag']))
  except BaseException as e:flags['contentCacheRetained']=False;errors.append('content-cache:'+type(e).__name__)
  try:
   flags['buildPgidAbsent']=not self.groups()
   flags['imageIdAbsent']=not self.state.get('imageId') or self.run(['image','inspect',self.state['imageId']],check=False).returncode!=0
  except BaseException as e:errors.append('identity-absence:'+type(e).__name__);flags['identityAbsenceConfirmed']=False
  if any(v is not True for v in flags.values()):errors.append('absence-not-confirmed')
  if exit_code not in [None,0]:errors.append('listener-nonzero-exit')
  self.state['cleanup']={**flags,'listenerExitCode':exit_code,'errors':errors};self.persist()
  return not errors
