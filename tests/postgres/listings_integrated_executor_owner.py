import hashlib,json,os,pathlib,shlex,subprocess,time
def inspected_absent(result,kind,name):
 if result.returncode==0:return False
 import re
 text=result.stderr.strip()
 patterns={'volume':r'(?:Error response from daemon: )?(?:get '+re.escape(name)+r': no such volume(?:: '+re.escape(name)+r')?|no such volume: '+re.escape(name)+r')', 'network':r'(?:Error response from daemon: )?network '+re.escape(name)+r' not found', 'image':r'(?:Error response from daemon: )?No such image: '+re.escape(name)}
 if kind in patterns and re.fullmatch(patterns[kind],text,re.IGNORECASE):return True
 raise RuntimeError('Owned '+kind+' absence inspection unavailable')

class ExecutorOwner:
 def __init__(self,workspace,root,docker,owner,env,state,persist):
  self.workspace,self.root,self.docker,self.owner,self.env,self.state,self.persist=workspace,root,docker,owner,env,state,persist
  self.name='dvaia-owned-listings-'+owner[:12];self.profile=self.name;self.remote='/tmp/'+self.name;self.tag=self.name+':candidate';self.volume=self.name+'-journal';self.network=self.name+'-network';self.image=None;self.child=None
  self.ssh=['/usr/bin/ssh','-F',str(pathlib.Path.home()/'.colima/_lima/colima-dvaia-pg-verify/ssh.config'),'lima-colima-dvaia-pg-verify']
  self.created=set();state['executor']={'name':self.name,'profile':self.profile,'volume':self.volume,'network':self.network};persist()
 def run(self,args,**kwargs):return subprocess.run(args,env=self.env,text=True,capture_output=True,timeout=kwargs.pop('timeout',30),**kwargs)
 def checked(self,args,**kwargs):
  r=self.run(args,**kwargs)
  if r.returncode:raise RuntimeError('Owned executor command failed: '+r.stderr[-1000:])
  return r.stdout
 def remote_run(self,args,**kwargs):return self.checked(self.ssh+[shlex.join(args)],**kwargs)
 def start(self,shared_manager=False):
  import secrets,shutil,socket
  if shared_manager:
   self.name='dvaia-owned-listings-'+hashlib.sha256(str(self.workspace.resolve()).encode()).hexdigest()[:12];self.profile=self.name;self.remote='/tmp/'+self.name;self.tag=self.name+':candidate';self.volume=self.name+'-journal';self.network=self.name+'-network';self.state['executor'].update(name=self.name,profile=self.profile,volume=self.volume,network=self.network)
  assert not self.checked(self.docker+['ps','-aq','--filter','name=^/'+self.name+'$']).strip()
  self.remote_run(['test','!','-e',self.remote]);self.remote_run(['mkdir','-m','0700',self.remote]);self.created.add('remote')
  self.remote_run(['tee',self.remote+'/owner'],input=self.owner+'\n')
  policy=(self.workspace/'sidecars/sandbox-runner/owned-listings/profile.apparmor.in').read_text().replace('@@SUPERVISOR_PROFILE@@',self.profile)
  self.remote_run(['tee',self.remote+'/policy'],input=policy);self.remote_run(['sudo','apparmor_parser','--skip-kernel-load',self.remote+'/policy']);self.remote_run(['sudo','apparmor_parser','-r',self.remote+'/policy']);self.created.add('profile')
  self.state['executor']['profileSha256']=hashlib.sha256(policy.encode()).hexdigest()
  ca=self.root/'build-ca.pem';ca.write_text(self.checked(['/usr/bin/security','find-certificate','-a','-p','/Library/Keychains/System.keychain'])+self.checked(['/usr/bin/security','find-certificate','-a','-p',str(pathlib.Path.home()/'Library/Keychains/login.keychain-db')]));ca.chmod(0o600);self.ca=ca
  dockerfile=self.root/'Dockerfile.integration';dockerfile.write_text((self.workspace/'sidecars/sandbox-runner/owned-listings/Dockerfile.candidate').read_text()+'\nCOPY tests/fixtures/secureshopListingsDualListener.native.cjs /app/tests/fixtures/secureshopListingsDualListener.native.cjs\n')
  with (self.root/'executor-build.log').open('w')as log:
   self.child=subprocess.Popen(self.docker+['build','--platform','linux/arm64','--secret',f'id=npm_ca,src={ca}','-t',self.tag,'-f',str(dockerfile),str(self.workspace)],env=self.env,stdout=log,stderr=log,start_new_session=True)
   self.state['executor']['buildPgid']=self.child.pid;self.persist()
   if self.child.wait(timeout=300):raise RuntimeError('executor build failed')
  self.image=self.checked(self.docker+['image','inspect',self.tag,'--format','{{.Id}}']).strip();self.state['executor']['image']=self.image
  for kind,name in [('volume',self.volume),('network',self.network)]:
   absent=self.run(self.docker+[kind,'inspect',name])
   if not inspected_absent(absent,kind,name):raise RuntimeError('Owned '+kind+' already exists')
   self.checked(self.docker+[kind,'create','--label','dvaia.test.owner='+self.owner]+[]+[name]);self.created.add(kind)
  tokens={label:secrets.token_urlsafe(32)for label in ['A','B']};identities={label:secrets.token_hex(32)for label in ['A','B']}
  command=self.docker+['run','-d','--name',self.name,'--label','dvaia.test.owner='+self.owner,'--network',self.network,'--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--security-opt','apparmor='+self.profile,'--security-opt','seccomp=unconfined','--user','10001:10001','-e','LISTINGS_PROFILE='+self.profile,'--mount','type=volume,src='+self.volume+',dst=/journal','-p','127.0.0.1::8095','-p','127.0.0.1::8096']
  if shared_manager:
   with socket.socket()as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
   token=secrets.token_urlsafe(48);origin='http://127.0.0.1:'+str(port)
   self.envfile=self.root/'listings-manager.env';self.envfile.write_text('LISTINGS_MANAGER_ENABLED=true\nLISTINGS_PUBLIC_ORIGIN='+origin+'\nLISTINGS_CONTROL_TOKEN='+token+'\n');self.envfile.chmod(0o600)
   command=command[:-4]+['-p','127.0.0.1:'+str(port)+':8095','--env-file',str(self.envfile)]
   entry='/app/sidecars/sandbox-runner/owned-listings/manager-entry.js';ready_marker='LISTINGS_MANAGER_READY'
  else:
   for label in ['A','B']:command+=['-e','LISTINGS_TOKEN_'+label+'='+tokens[label],'-e','LISTINGS_IDENTITY_'+label+'='+identities[label]]
   entry='/app/tests/fixtures/secureshopListingsDualListener.native.cjs';ready_marker='LISTINGS_DUAL_READY'
  self.created.add('container');self.checked(command+['--entrypoint','node',self.image,entry])
  self.state['executor']['postStartInspect']={k:v for k,v in json.loads(self.checked(self.docker+['inspect',self.name]))[0]['State'].items() if k in ['Status','Running','ExitCode','Error']};self.persist()
  for attempt in range(100):
   logs=self.checked(self.docker+['logs',self.name]);
   if ready_marker in logs:break
   if self.checked(self.docker+['inspect',self.name,'--format','{{.State.Running}}']).strip()!='true':raise RuntimeError('executor listener exited')
   time.sleep(.2)
  else:raise RuntimeError('executor listener deadline')
  out={}
  if shared_manager:out.update(LISTINGS_MANAGER_ORIGIN=origin,LISTINGS_MANAGER_TOKEN=token,LISTINGS_MANAGER_IMAGE=self.image,LISTINGS_MANAGER_PROFILE=self.profile)
  else:
   for label,port in [('A',8095),('B',8096)]:
    binding=self.checked(self.docker+['port',self.name,str(port)+'/tcp']).strip();out['LISTINGS_EXECUTOR_'+label+'_ORIGIN']='http://'+binding;out['LISTINGS_EXECUTOR_'+label+'_TOKEN']=tokens[label]
  inspect=json.loads(self.checked(self.docker+['inspect',self.name]))[0]
  bindings=inspect['NetworkSettings']['Ports'];assert all(item['HostIp']=='127.0.0.1' for entries in bindings.values() if entries for item in entries)
  self.state['executor']['hostPortBindings']=bindings;self.state['executor']['networkTopology']='owned ordinary bridge, loopback published listeners, untrusted execution in attested inner namespace'
  self.persist();return out
 def close(self):
  import signal
  if self.child and self.child.poll()is None:
   os.killpg(self.child.pid,signal.SIGTERM)
   try:self.child.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(self.child.pid,signal.SIGKILL);self.child.wait(timeout=5)
  if 'container'in self.created:(self.root/'executor.log').write_text(self.run(self.docker+['logs',self.name]).stdout+self.run(self.docker+['logs',self.name]).stderr)
  for kind,name in [('container',self.name),('volume',self.volume),('network',self.network)]:
   if kind not in self.created:continue
   args=['inspect',name]if kind=='container'else[kind,'inspect',name]
   q=self.run(self.docker+args)
   if q.returncode==0:
    info=json.loads(q.stdout)[0];labels=info['Config']['Labels']if kind=='container'else info['Labels'];assert labels.get('dvaia.test.owner')==self.owner
    self.checked(self.docker+(['rm','-f',name]if kind=='container'else[kind,'rm',name]))
  if self.image:self.run(self.docker+['image','rm',self.tag],timeout=30)
  if 'profile'in self.created:self.remote_run(['sudo','apparmor_parser','-R',self.remote+'/policy'])
  if 'remote'in self.created:
   assert self.remote_run(['cat',self.remote+'/owner'])==self.owner+'\n';self.remote_run(['rm','-f',self.remote+'/owner',self.remote+'/policy']);self.remote_run(['rmdir',self.remote])
  if hasattr(self,'ca')and self.ca.exists():self.ca.unlink()
  if hasattr(self,'envfile')and self.envfile.exists():self.envfile.unlink()
  checks={'containerAbsent':not self.checked(self.docker+['ps','-aq','--filter','name=^/'+self.name+'$']).strip(),'volumeAbsent':inspected_absent(self.run(self.docker+['volume','inspect',self.volume]),'volume',self.volume),'networkAbsent':inspected_absent(self.run(self.docker+['network','inspect',self.network]),'network',self.network),'imageTagAbsent':inspected_absent(self.run(self.docker+['image','inspect',self.tag]),'image',self.tag),'profileAbsent':not any(v.startswith(self.profile+' ')or v.startswith(self.profile+'//')for v in self.remote_run(['sudo','cat','/sys/kernel/security/apparmor/profiles']).splitlines()),'remoteAbsent':self.run(self.ssh+[shlex.join(['test','!','-e',self.remote])]).returncode==0}
  self.state['executor']['cleanup']=checks;self.persist();assert all(checks.values())
