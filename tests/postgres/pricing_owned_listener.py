"""Owned local-package listener fixture; never discovers an installation or daemon."""
import hashlib,io,json,os,re,secrets,shlex,socket,stat,subprocess,tarfile,time,uuid
from pathlib import Path
from listings_integrated_executor_owner import inspected_absent

def closed_package_context(workspace, package):
 """Build a Docker context from only the package's no-follow pinned files."""
 files=package.get('files')
 if not isinstance(files,dict) or len(files)!=14:raise RuntimeError('Pricing package closure mismatch')
 data=io.BytesIO()
 with tarfile.open(fileobj=data,mode='w') as archive:
  for relative,expected in sorted(files.items()):
   if not isinstance(relative,str) or not relative.startswith('sidecars/sandbox-runner/') or Path(relative).is_absolute() or '..'in Path(relative).parts:raise RuntimeError('Pricing package path invalid')
   path=Path(workspace)/relative
   fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
   try:
    before=os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>1024*1024:raise RuntimeError('Pricing package member invalid')
    with os.fdopen(os.dup(fd),'rb') as source:content=source.read()
    after=os.fstat(fd);named=path.lstat()
    if hashlib.sha256(content).hexdigest()!=expected or len(content)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or stat.S_ISLNK(named.st_mode) or (named.st_dev,named.st_ino)!=(before.st_dev,before.st_ino):raise RuntimeError('Pricing package member changed')
    info=tarfile.TarInfo(relative);info.size=len(content);info.mode=before.st_mode&0o777;info.mtime=0;info.uid=0;info.gid=0
    archive.addfile(info,io.BytesIO(content))
   finally:os.close(fd)
 return data.getvalue()

class PricingOwnedListener:
 def __init__(self, *, workspace, evidence, docker, node, environment, ssh, qualification_nonce=None):
  self.cleanup_budget=None;self.workspace=Path(workspace);self.evidence=Path(evidence);self.docker=docker;self.node=str(node);self.env=dict(environment)
  self.home=self.evidence/'pricing-private-home';self.home.mkdir(mode=0o700);self.home_identity=(self.home.stat().st_dev,self.home.stat().st_ino)
  self.id=self.js("process.stdout.write(require('./scripts/application-data-root').workspaceId(process.cwd()))")
  self.qualification_mode=qualification_nonce is not None
  if qualification_nonce is not None and not re.fullmatch(r'[a-f0-9]{12}',qualification_nonce):raise ValueError('qualification nonce required')
  self.qualification_nonce=qualification_nonce or self.id;self.owner=str(uuid.uuid4());self.name='dvaia-pricing-'+self.qualification_nonce;self.network=self.name+'-network';self.tag=self.name+':native';self.profile='dvaia-owned-pricing-http-'+self.qualification_nonce;self.remote='/tmp/'+self.profile
  if not isinstance(ssh,list) or len(ssh)!=9 or ssh[0]!='/usr/bin/ssh' or ssh[-1]!='--':raise ValueError('Reviewed SSH admission required')
  self.ssh=list(ssh)
  self.state={'container':self.name,'network':self.network,'imageTag':self.tag,'profile':self.profile,'owner':self.owner,'qualificationNonce':self.qualification_nonce,'workspaceId':self.id,'cleanup':{},'outerEgressIsolationEstablished':False}
  self.remote_owned=False;self.profile_attempted=False;self.container_attempted=False;self.network_attempted=False;self.image_attempted=False;self.rendered=None;self.save()
 def remaining(self,seconds):return min(seconds,self.cleanup_budget.remaining()) if self.cleanup_budget else seconds
 def run(self,args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,env=self.env,timeout=self.remaining(kw.pop('timeout',30)),**kw)
 def js(self,source,*args):return self.run([self.node,'-e',source,*args],cwd=self.workspace).stdout
 def remote_run(self,args,**kw):return self.run(self.ssh+[shlex.join(args)],**kw)
 def save(self):
  p=self.evidence/'pricing-listener-ownership.json';p.write_text(json.dumps(self.state,indent=2)+'\n');p.chmod(0o600)
 def inspect(self,*args):return json.loads(self.run(self.docker+list(args)).stdout)[0]
 def absent(self):return not self.run(self.docker+['ps','-aq','--filter','name=^/'+self.name+'$']).stdout.strip()
 def profile_rows(self):return [x for x in self.remote_run(['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout.splitlines() if x.startswith(self.profile+' ') or x.startswith(self.profile+'//')]
 def start(self):
  package=json.loads(self.js("process.stdout.write(JSON.stringify(require('./server/services/secureshopPricingPackage').capturePricingPackage(process.cwd())))"))
  dockerfile=(self.workspace/'sidecars/sandbox-runner/owned-pricing-http/Dockerfile.local').read_text()
  bases=set(re.findall(r'^FROM (node:[^ ]+)(?: AS [^ ]+)?$',dockerfile,re.M))
  if len(bases)!=1 or not re.fullmatch(r'node:26\.10\.0-slim@sha256:[a-f0-9]{64}',next(iter(bases))):raise RuntimeError('qualified Pricing base pin required')
  base=next(iter(bases))
  image=self.inspect('image','inspect',base)
  if image['Architecture']!='arm64' or not any(x.endswith(base.split('@')[1]) for x in image.get('RepoDigests',[])):raise RuntimeError('reviewed base absent; no pull')
  if not self.absent() or self.run(self.docker+['images','-q',self.tag]).stdout.strip() or self.profile_rows() or self.run(self.docker+['network','ls','--filter','name=^'+self.network+'$','--format','{{.Name}}']).stdout.strip():raise RuntimeError('exclusive listener identity exists')
  if subprocess.run(self.ssh+[shlex.join(['test','-e',self.remote])],env=self.env,capture_output=True,timeout=self.remaining(20)).returncode!=1:raise RuntimeError('remote identity exists')
  self.state['package']=package;self.state['baseId']=image['Id'];self.state['baseRepoDigests']=image['RepoDigests'];self.save()
  self.rendered=self.js("process.stdout.write(require('./sidecars/sandbox-runner/owned-pricing-http/profile').renderOwnedPricingHttpProfile(process.argv[1]))",self.profile)
  self.remote_run(['mkdir','-m','0700','--',self.remote]);self.remote_owned=True
  self.remote_run(['tee',self.remote+'/owner'],input=self.owner+'\n');self.remote_run(['tee',self.remote+'/policy'],input=self.rendered)
  self.remote_run(['sudo','apparmor_parser','--skip-kernel-load',self.remote+'/policy']);self.profile_attempted=True;self.save();self.remote_run(['sudo','apparmor_parser','-r',self.remote+'/policy'])
  if sorted(self.profile_rows())!=sorted([self.profile+' (enforce)',self.profile+'//bwrap (enforce)']):raise RuntimeError('profile not enforcing')
  labels={'dvaia.pricing.owner':self.owner,'dvaia.pricing.workspace':self.id,'dvaia.pricing.package':package['sha256']};label_args=sum((['--label',k+'='+v] for k,v in labels.items()),[])
  self.image_attempted=True;self.save()
  context=closed_package_context(self.workspace,package)
  with (self.evidence/'pricing-build.log').open('w') as log:subprocess.run(self.docker+['build','--pull=false','--network=default',*label_args,'-f','sidecars/sandbox-runner/owned-pricing-http/Dockerfile.local','-t',self.tag,'-'],input=context,check=True,stdout=log,stderr=subprocess.STDOUT,env=self.env,timeout=300)
  image=self.inspect('image','inspect',self.tag)
  if image['Architecture']!='arm64' or any(image['Config']['Labels'].get(k)!=v for k,v in labels.items()):raise RuntimeError('image mismatch')
  self.state['imageId']=image['Id'];self.save()
  self.network_attempted=True;self.save();self.run(self.docker+['network','create',*label_args,self.network])
  network=self.inspect('network','inspect',self.network)
  if network['Driver']!='bridge' or network['Internal'] or any(network['Labels'].get(k)!=v for k,v in labels.items()):raise RuntimeError('network mismatch')
  self.state['networkId']=network['Id'];self.save()
  token=secrets.token_urlsafe(32);envfile=self.evidence/'pricing-listener.env';envfile.write_text('\n'.join(['SECURESHOP_PRICING_ENABLED=true','SECURESHOP_PRICING_TOKEN='+token,'SECURESHOP_PRICING_PROFILE='+self.profile,'SECURESHOP_PRICING_HOST=0.0.0.0','SECURESHOP_PRICING_PORT=8093'])+'\n');envfile.chmod(0o600)
  with socket.socket() as reservation:
   reservation.bind(('127.0.0.1',0));selected_port=reservation.getsockname()[1]
  self.container_attempted=True;self.save()
  try:self.run(self.docker+['run','-d','--pull','never','--name',self.name,*label_args,'--memory','512m','--cpus','1','--pids-limit','128','--read-only','--user','10001:10001','--network',self.network,'--cap-drop','ALL','--security-opt','seccomp=unconfined','--security-opt','apparmor='+self.profile,'--tmpfs','/tmp:rw,nosuid,nodev,size=134217728','--env-file',str(envfile),'-p',f'127.0.0.1:{selected_port}:8093',image['Id']])
  finally:envfile.unlink()
  for _ in range(50):
   container=self.inspect('inspect',self.name);ports=container.get('NetworkSettings',{}).get('Ports',{}).get('8093/tcp')
   if ports:break
   if not container['State']['Running']:raise RuntimeError('listener exited before publication')
   time.sleep(.1)
  if not ports or len(ports)!=1 or ports[0]['HostIp']!='127.0.0.1' or ports[0]['HostPort']!=str(selected_port) or container['HostConfig']['PortBindings']!={'8093/tcp':[{'HostIp':'127.0.0.1','HostPort':str(selected_port)}]}:raise RuntimeError('listener publication unavailable')
  self.state['containerId']=container['Id'];self.state['port']=int(ports[0]['HostPort']);self.save()
  for _ in range(80):
   try:
    with socket.create_connection(('127.0.0.1',self.state['port']),timeout=.2):break
   except OSError:time.sleep(.1)
  else:raise RuntimeError('listener did not become reachable')
  authority={'version':1,'workspaceId':self.id,'host':self.docker[2],'daemonId':json.loads(self.run(self.docker+['info','--format','{{json .ID}}']).stdout),'source':'environment-host'}
  directory=self.home/'.dvaia'/self.id;directory.mkdir(parents=True,mode=0o700)
  authfile=directory/'local-docker.json';authfile.write_text(json.dumps(authority));authfile.chmod(0o600)
  authority_sha=self.js("process.stdout.write(require('./scripts/local-docker-authority').authorityDigest(JSON.parse(require('node:fs').readFileSync(process.argv[1]))))",str(authfile))
  record={'version':1,'enabled':True,'workspaceId':self.id,'ownerId':self.owner,'dockerAuthoritySha256':authority_sha,'containerName':self.name,'containerId':container['Id'],'imageId':image['Id'],'packageSha256':package['sha256'],'profile':self.profile,'port':self.state['port'],'token':token}
  descriptor={'version':1,'ownerId':self.owner,'workspaceId':self.id,'qualificationNonce':self.qualification_nonce,'containerId':container['Id'],'imageId':image['Id'],'packageSha256':package['sha256'],'profile':self.profile,'origin':'http://127.0.0.1:'+str(self.state['port']),'token':token}
  self.state['tokenSha256']=hashlib.sha256(token.encode()).hexdigest();self.save()
  return {'PERSONA_PRICING_HTTP_NATIVE':'1','PERSONA_PRICING_PRIVATE_HOME':str(self.home),'PERSONA_PRICING_DOCKER':self.docker[0],**self.publish_config(directory,record,descriptor)}

 def publish_config(self, directory, record, descriptor):
  if self.qualification_mode:
   descriptor_path=self.evidence/'pricing-listener-descriptor.json';descriptor_path.write_text(json.dumps(descriptor));descriptor_path.chmod(0o600)
   self.state['descriptorSha256']=hashlib.sha256(descriptor_path.read_bytes()).hexdigest();self.save()
   return {'SECURESHOP_STANDALONE_PRICING_DESCRIPTOR':str(descriptor_path),'SECURESHOP_STANDALONE_PRICING_DESCRIPTOR_SHA256':self.state['descriptorSha256']}
  config=directory/'pricing-managed.json';config.write_text(json.dumps(record));config.chmod(0o600);self.state['managedDirectory']=str(directory);self.save();return {}
 def close(self,budget=None):
  self.cleanup_budget=budget
  errors=[];clean=self.state['cleanup']
  try:
   if self.container_attempted and not self.absent():
    c=self.inspect('inspect',self.name)
    if c['Config']['Labels'].get('dvaia.pricing.owner')!=self.owner or c['Image']!=self.state.get('imageId') or self.state.get('containerId',c['Id'])!=c['Id']:raise RuntimeError('foreign container')
    self.run(self.docker+['stop','--time','20',self.name],timeout=25);self.run(self.docker+['rm','-v',self.name])
   clean['containerAbsent']=self.absent()
  except Exception as e:errors.append('container:'+type(e).__name__)
  try:
   if self.network_attempted:
    rows=self.run(self.docker+['network','ls','--filter','name=^'+self.network+'$','--format','{{.ID}}']).stdout.strip()
    if rows:
     n=self.inspect('network','inspect',self.network)
     if n['Labels'].get('dvaia.pricing.owner')!=self.owner or n['Containers'] or self.state.get('networkId',n['Id'])!=n['Id']:raise RuntimeError('foreign network')
     self.run(self.docker+['network','rm',self.network])
   clean['networkAbsent']=not self.run(self.docker+['network','ls','--filter','name=^'+self.network+'$','--format','{{.ID}}']).stdout.strip()
  except Exception as e:errors.append('network:'+type(e).__name__)
  try:
   if self.image_attempted and self.run(self.docker+['images','-q',self.tag]).stdout.strip():
    i=self.inspect('image','inspect',self.tag)
    if i['Config']['Labels'].get('dvaia.pricing.owner')!=self.owner or self.state.get('imageId',i['Id'])!=i['Id']:raise RuntimeError('foreign image')
    self.run(self.docker+['image','rm',self.tag])
   clean['imageAbsent']=not self.run(self.docker+['images','-q',self.tag]).stdout.strip() and (not self.state.get('imageId') or inspected_absent(subprocess.run(self.docker+['image','inspect',self.state['imageId']],env=self.env,capture_output=True,text=True,timeout=self.remaining(20)),'image',self.state['imageId']))
  except Exception as e:errors.append('image:'+type(e).__name__)
  try:
   if self.profile_attempted:
    if not clean.get('containerAbsent') or self.remote_run(['cat',self.remote+'/owner']).stdout.strip()!=self.owner or self.remote_run(['cat',self.remote+'/policy']).stdout!=self.rendered:raise RuntimeError('profile ownership')
    self.remote_run(['sudo','apparmor_parser','-R',self.remote+'/policy'])
   clean['profileAbsent']=not self.profile_rows()
   if self.remote_owned:
    if not clean['profileAbsent'] or self.remote_run(['cat',self.remote+'/owner']).stdout.strip()!=self.owner:raise RuntimeError('remote ownership')
    self.remote_run(['rm','--',self.remote+'/policy',self.remote+'/owner']);self.remote_run(['rmdir','--',self.remote])
   clean['remoteAbsent']=subprocess.run(self.ssh+[shlex.join(['test','-e',self.remote])],env=self.env,capture_output=True,timeout=self.remaining(20)).returncode==1
  except Exception as e:errors.append('profile:'+type(e).__name__)
  try:
   st=self.home.lstat()
   if self.home.is_symlink() or (st.st_dev,st.st_ino)!=self.home_identity:raise RuntimeError('private home identity')
   directory=self.home/'.dvaia'/self.id
   if directory.exists():
    if directory.is_symlink() or set(x.name for x in directory.iterdir())-{'local-docker.json','pricing-managed.json','pricing-listener-descriptor.json'}:raise RuntimeError('private directory inventory')
    for name in ['local-docker.json','pricing-managed.json','pricing-listener-descriptor.json']:
     file=directory/name
     if file.exists():
      if file.is_symlink() or not file.is_file():raise RuntimeError('private file identity')
      file.unlink()
    directory.rmdir()
   if (self.home/'.dvaia').exists():(self.home/'.dvaia').rmdir()
   self.home.rmdir();clean['privateHomeAbsent']=not self.home.exists()
  except Exception as e:errors.append('private-home:'+type(e).__name__)
  clean['errors']=errors;self.save();return not errors and all(clean.get(k) for k in ['containerAbsent','networkAbsent','imageAbsent','profileAbsent','remoteAbsent','privateHomeAbsent'])
