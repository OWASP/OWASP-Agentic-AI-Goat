#!/usr/bin/env python3
"""Candidate-only no-copy native qualification for listing-template.

The runner never reads managed state.  `--run` builds from a streamed archive of
exactly the twelve package inputs, then creates only nonce-labelled resources.
It is intentionally separate from activation and source admission.
"""
import argparse, hashlib, io, json, os, re, signal, stat, subprocess, sys, tarfile, tempfile, time, urllib.request, uuid
from types import SimpleNamespace
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(Path(__file__).resolve().parent))
from listings_package_candidate import buildx_identity
FILES=(
 'sidecars/sandbox-runner/listing-template/Dockerfile','sidecars/sandbox-runner/listing-template/Dockerfile.dockerignore',
 'sidecars/sandbox-runner/listing-template/listener.js','sidecars/sandbox-runner/listing-template/executor.js',
 'sidecars/sandbox-runner/listing-template/http-handler.js','sidecars/sandbox-runner/listing-template/worker.js',
 'sidecars/sandbox-runner/listing-template/strict-helpers.js','sidecars/sandbox-runner/listing-template/template-init.c',
 'sidecars/sandbox-runner/listing-template/secureshopListingTemplateExecutorContract.js',
 'sidecars/sandbox-runner/policy-render/process-supervisor.c',
 'sidecars/sandbox-runner/policy-render/assets/nunjucks-3.2.4.js',
 'sidecars/sandbox-runner/policy-render/assets/NUNJUCKS-LICENSE.txt')
HEX=re.compile(r'[a-f0-9]{64}$'); NONCE=re.compile(r'[a-f0-9]{12}$')
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def manifest(root=ROOT):
 out={}
 for name in FILES:
  p=root/name; s=p.lstat()
  if p.is_symlink() or not stat.S_ISREG(s.st_mode) or p.resolve()!=p or not p.is_relative_to(root) or s.st_size>1048576: raise RuntimeError('regular current source required: '+name)
  out[name]=digest(p)
 if out['sidecars/sandbox-runner/listing-template/secureshopListingTemplateExecutorContract.js']!=digest(root/'server/services/secureshopListingTemplateExecutorContract.js'): raise RuntimeError('listing template contract drift')
 return out
def context_bytes(root,pins):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w') as a:
  for name, expected in pins.items():
   p=root/name; data=p.read_bytes()
   if hashlib.sha256(data).hexdigest()!=expected: raise RuntimeError('source changed during context capture')
   # Dockerfile expects a sandbox-runner-relative context.
   item=tarfile.TarInfo(str(Path(name).relative_to('sidecars/sandbox-runner'))); item.size=len(data); item.mode=0o644
   a.addfile(item,io.BytesIO(data))
 return out.getvalue()
def regular_hash(path):
 p=Path(path);st=p.lstat()
 if not p.is_absolute() or p.is_symlink() or not stat.S_ISREG(st.st_mode) or p.resolve()!=p or not os.access(p,os.X_OK):raise RuntimeError('canonical executable identity required')
 return digest(p)
def provenance(root,node,docker):
 # Capture only the installer/profile modules actually loaded by the profile plan.
 probe="require('./scripts/install/secureshop-owned-listing-template')._internals.profileBytes(process.cwd(),'aaaaaaaaaaaa');require('./scripts/install/mcp-owned-local').localProfilePlan;process.stdout.write(JSON.stringify(Object.keys(require.cache)))"
 raw=subprocess.run([node,'-e',probe],cwd=root,capture_output=True,text=True,timeout=20,check=True,env={'PATH':str(Path(node).parent)}).stdout
 drivers={}
 for value in json.loads(raw):
  q=Path(value)
  if q.is_relative_to(root) and q.is_file() and not q.is_symlink() and q.resolve()==q:drivers[str(q.relative_to(root))]=digest(q)
 if not drivers:raise RuntimeError('profile driver closure unavailable')
 for name in ('tests/postgres/run-listing-template-native-isolated.py','tests/postgres/listings_package_candidate.py','tests/postgres/listings_native_resources.py','tests/postgres/sql_nosql_docker_ownership.py','server/services/secureshopListingTemplateExecutorContract.js'):
  drivers[name]=digest(root/name)
 return {'node':{'path':str(Path(node)),'sha256':regular_hash(node)},'docker':{'path':str(Path(docker)),'sha256':regular_hash(docker)},'profileDrivers':dict(sorted(drivers.items())),'buildx':buildx_identity(SimpleNamespace(digest=digest),SimpleNamespace(docker=docker))}

def plan(root,nonce):
 if not NONCE.fullmatch(nonce): raise RuntimeError('twelve-hex nonce required')
 base='owasp-ai-goat-listing-template-qual-'+nonce
 return {'version':1,'candidateOnly':True,'installedActivation':False,'sourceCopy':False,'files':manifest(root),
  'container':base,'image':base+':candidate','network':base+'-bridge','profile':'owasp-ai-goat-owned-listing-template-'+nonce,
  'labels':{'owasp-ai-goat.qualification':'listing-template','owasp-ai-goat.qualification.nonce':nonce},'port':'127.0.0.1:<reserved>:8090',
  'resources':{'memory':'512m','cpus':'1','pids':128,'readOnlyRoot':True,'loopbackOnly':True},
  'checks':['strict-health','inert-render','command-effect-witness','bounded-drain','exact-owned-cleanup']}
def atomic_json(path,value):
 path=Path(path); temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.pending')
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:
  with os.fdopen(fd,'w') as out:json.dump(value,out,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
  os.replace(temporary,path)
  directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(directory)
  finally:os.close(directory)
 finally:
  if temporary.exists():temporary.unlink()
def build_environment(evidence,docker,node,plugin):
 for name in ('home','tmp','docker-config'):(evidence/name).mkdir(mode=0o700)
 atomic_json(evidence/'docker-config/config.json',{'cliPluginsExtraDirs':[str(Path(plugin['path']).parent)]})
 return {'PATH':str(Path(node).parent)+':'+str(Path(docker).parent)+':/usr/bin:/bin',
  'HOME':str(evidence/'home'),'TMPDIR':str(evidence/'tmp'),'LANG':'C',
  'DOCKER_CONFIG':str(evidence/'docker-config'),'DOCKER_BUILDKIT':'1'}
def run(cmd,args,env,stdin=None,timeout=60,check=True):
 child=subprocess.Popen(cmd+args,stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
  stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
 try:stdout,stderr=child.communicate(stdin,timeout=timeout)
 finally:
  # Own only this new process group, including build-plugin children after a CLI failure.
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  child.wait()
  for stream in (child.stdin,child.stdout,child.stderr):
   if stream is not None:stream.close()
 r=subprocess.CompletedProcess(cmd+args,child.returncode,stdout,stderr)
 if check and r.returncode:raise RuntimeError('command failed: '+args[0])
 return r
def inspect(docker,host,kind,name,env):
 r=run([docker,'--host',host],[kind,'inspect',name],env,check=False)
 if r.returncode:
  missing={
   'container':(f'Error: No such object: {name}',f'Error: No such container: {name}',f'Error response from daemon: No such container: {name}'),
   'network':(f'Error response from daemon: network {name} not found',f'Error: No such network: {name}'),
   'image':(f'Error: No such image: {name}',f'Error response from daemon: No such image: {name}')}
  if r.returncode==1 and r.stderr.decode('utf8','replace').strip() in missing[kind]:return None
  raise RuntimeError('inspect unavailable')
 rows=json.loads(r.stdout)
 if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict):raise RuntimeError('inspect invalid')
 return rows[0]
def owned(row,state,kind):
 if row is None:return None
 labels=(row.get('Config') or {}).get('Labels') if kind in ('container','image') else row.get('Labels')
 identifier=row.get('Id','');pattern=r'sha256:[a-f0-9]{64}' if kind=='image' else r'[a-f0-9]{64}'
 if (not isinstance(labels,dict) or any(labels.get(k)!=v for k,v in state['labels'].items())
     or not re.fullmatch(pattern,identifier) or state.get(kind+'Id',identifier)!=identifier):
  raise RuntimeError('foreign or replaced '+kind+' retained')
 if kind!='image' and row.get('Name')!=('/' if kind=='container' else '')+state[kind]:raise RuntimeError('renamed '+kind+' retained')
 if kind=='image':
  if row.get('Architecture')!='arm64' or row.get('Config',{}).get('User')!='10001:10001' or row.get('RepoTags')!=[state['image']]:raise RuntimeError('candidate image identity')
 elif kind=='network':
  endpoints=row.get('Containers')
  if (row.get('Driver')!='bridge' or row.get('Internal') is not False or row.get('Options') not in (None,{})
      or not isinstance(endpoints,dict) or set(endpoints)-({state['containerId']} if state.get('containerId') else set())):raise RuntimeError('foreign network attachment retained')
 else:
  host=row.get('HostConfig',{});net=row.get('NetworkSettings',{});networks=net.get('Networks')
  bindings={'8090/tcp':[{'HostIp':'127.0.0.1','HostPort':str(state['port'])}]}
  if (row.get('Image')!=state.get('imageId') or row.get('Config',{}).get('User')!='10001:10001'
      or host.get('NetworkMode')!=state['network'] or host.get('ReadonlyRootfs') is not True
      or host.get('Privileged') is not False or host.get('Memory')!=536870912 or host.get('NanoCpus')!=1000000000
      or host.get('PidsLimit')!=128 or host.get('CapDrop')!=['ALL'] or host.get('CapAdd') not in (None,[])
      or set(host.get('SecurityOpt') or [])!={'apparmor='+state['profile']['name'],'seccomp=unconfined'}
      or host.get('Tmpfs')!={'/tmp':'rw,nosuid,nodev,noexec,mode=1777,size=128m'}
      or host.get('PortBindings')!=bindings or not isinstance(row.get('Mounts'),list) or len(row['Mounts'])>1
      or any(m.get('Type')!='tmpfs' or m.get('Destination')!='/tmp' or m.get('RW') is not True for m in row['Mounts'])
      or not isinstance(networks,dict) or set(networks)-{state['network']}
      or (networks and networks[state['network']].get('NetworkID')!=state.get('networkId'))):raise RuntimeError('container resource identity changed')
  if row.get('State',{}).get('Running') is True and (set(networks)!={state['network']} or net.get('Ports')!=bindings or row.get('AppArmorProfile')!=state['profile']['name']):raise RuntimeError('running container isolation changed')
 state[kind+'Id']=identifier
 return row
def current_resource(docker,host,kind,state,env):
 row=inspect(docker,host,kind,state[kind],env)
 if row is None and state.get(kind+'Id') and inspect(docker,host,kind,state[kind+'Id'],env) is not None:raise RuntimeError('retained '+kind+' lost its admitted name')
 return owned(row,state,kind)
def attachment_check(docker,host,state,env,allow_owned=False):
 ids=run([docker,'--host',host],['ps','-aq','--no-trunc'],env).stdout.decode().split()
 if len(ids)>4096 or len(set(ids))!=len(ids) or any(not HEX.fullmatch(i) for i in ids):raise RuntimeError('attachment inventory invalid')
 profile=state.get('profile',{}).get('name')
 for identifier in ids:
  row=inspect(docker,host,'container',identifier,env)
  if row is None:continue
  if allow_owned and identifier==state.get('containerId'):continue
  networks=row.get('NetworkSettings',{}).get('Networks');host_config=row.get('HostConfig',{});apparmor=row.get('AppArmorProfile')
  if not isinstance(networks,dict):raise RuntimeError('attachment inventory unavailable')
  if (row.get('Image')==state.get('imageId') or state['network'] in networks
      or any(n.get('NetworkID')==state.get('networkId') for n in networks.values() if state.get('networkId'))
      or (profile and (apparmor==profile or isinstance(apparmor,str) and apparmor.startswith(profile+'//') or 'apparmor='+profile in (host_config.get('SecurityOpt') or [])))):
   raise RuntimeError('foreign resource attachment retained')
def cleanup_resources(docker,host,daemon,state,env,persist,remove_profile):
 daemon_ok(docker,host,daemon,env)
 # Recover lost create acknowledgements only through the exact nonce-labelled name
 # and full resource configuration; captured identities can never be replaced.
 for kind in ('image','container','network'):
  if kind in state['attempted']:current_resource(docker,host,kind,state,env)
 attachment_check(docker,host,state,env,allow_owned=True);persist()
 cleanup={}
 for kind in ('container','network','image'):
  if kind in state['attempted']:
   daemon_ok(docker,host,daemon,env)
   row=current_resource(docker,host,kind,state,env)
   if kind!='container':attachment_check(docker,host,state,env)
   if row is not None:
    command=['rm','-f',row['Id']] if kind=='container' else [kind,'rm',row['Id']]
    try:run([docker,'--host',host],command,env,check=False)
    except (OSError,subprocess.TimeoutExpired):pass
    if current_resource(docker,host,kind,state,env) is not None:raise RuntimeError('resource removal unconfirmed')
  cleanup[kind+'Absent']=True;persist()
 if 'profile' in state['attempted']:
  daemon_ok(docker,host,daemon,env);attachment_check(docker,host,state,env)
  remove_profile(env,state['profile'],'remove')
 cleanup['profileAbsent']=True
 return cleanup
def finalize(evidence,result,state,cleanup,verify_sources):
 # Always persist a private failure receipt, even when both qualification and
 # cleanup fail; neither error is allowed to mask the other in the evidence.
 result['cleanup']={key:False for key in ('containerAbsent','networkAbsent','imageAbsent','profileAbsent')}
 try:result['cleanup']=cleanup()
 except Exception as error:result['cleanupError']={'type':type(error).__name__,'message':str(error)[:300]}
 try:result['sourceUnchanged']=verify_sources()
 except Exception as error:result['sourceUnchanged']=False;result['sourceError']={'type':type(error).__name__,'message':str(error)[:300]}
 required={'containerAbsent','networkAbsent','imageAbsent','profileAbsent'}
 result['passed']=(result.get('passed') is True and 'error' not in result and 'cleanupError' not in result
  and set(result.get('cleanup',{}))==required and all(v is True for v in result['cleanup'].values()) and result['sourceUnchanged'] is True)
 result['resources']=state;result['completedAt']=time.time();atomic_json(evidence/'result.json',result)
 return result['passed']
COMMAND_WITNESS_TEMPLATE="{{ process.mainModule.require('child_process').execSync('umask 077 && cp /owned-source/effect-canary /owned-effect/command-effect').toString() }}"
def record_response(evidence,phase,status,request,response):
 if phase not in ('inert','command-witness'):raise ValueError('closed diagnostic phase required')
 diagnostic={'phase':phase,'httpStatus':status,'request':{k:request[k] for k in ('version','operationId','productId','sourceSha256')}}
 if isinstance(response,dict):
  # Preserve bounded execution facts before assertions; never persist arbitrary
  # rendered/template content or confuse an unvalidated response with proof.
  keys=('version','operationId','productId','requestSha256','sourceSha256','isolation','renderedSha256',
   'exitCode','timedOut','truncated','drained','workerAttested','commandEffectObserved','effectSha256','error')
  diagnostic['unvalidatedResponse']={k:v for k in keys if k in response
   for v in [response[k]] if v is None or type(v) in (bool,int) or isinstance(v,str) and len(v)<=256}
  rendered=response.get('rendered')
  if isinstance(rendered,str):
   raw=rendered.encode('utf8');diagnostic['renderedBytes']=len(raw);diagnostic['actualRenderedSha256']=hashlib.sha256(raw).hexdigest()
 else:diagnostic['responseType']=type(response).__name__
 atomic_json(evidence/(phase+'-response.json'),diagnostic)
def assert_contract(root,node,request,result,expect_effect):
 program="""const c=require('./server/services/secureshopListingTemplateExecutorContract');const fs=require('node:fs');const req=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));const raw=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));const v=c.validateListingTemplateExecutionResult(req,raw);if(v.commandEffectObserved!==JSON.parse(process.argv[1]))throw Error('effect mismatch');process.stdout.write(JSON.stringify(v));"""
 with tempfile.TemporaryDirectory() as d:
  a=Path(d)/'a';b=Path(d)/'b';a.write_text(json.dumps(request));b.write_text(json.dumps(result))
  r=subprocess.run([node,'-e',program,'true' if expect_effect else 'false',str(a),str(b)],cwd=root,capture_output=True,text=True,timeout=20,env={'PATH':str(Path(node).parent)})
  if r.returncode:raise RuntimeError('canonical execution contract failed')
def daemon_ok(docker,host,daemon,env):
 info=json.loads(run([docker,'--host',host],['info','--format','{{json .}}'],env).stdout)
 if info.get('ID')!=daemon or info.get('Architecture') not in ('aarch64','arm64'):raise RuntimeError('admitted daemon mismatch')
 return info

def http(port,path,body=None):
 req=urllib.request.Request('http://127.0.0.1:'+str(port)+path,data=None if body is None else json.dumps(body).encode(),headers={} if body is None else {'content-type':'application/json'},method='GET' if body is None else 'POST')
 with urllib.request.urlopen(req,timeout=10) as r:
  raw=r.read(131073)
  if len(raw)>131072:raise RuntimeError('response bound')
  return r.status,json.loads(raw)
def profile_plan(root,node,docker_host,nonce):
 program=r"""const i=require('./scripts/install/secureshop-owned-listing-template')._internals;const c=require('node:crypto');const id=process.argv[3],host=process.argv[2],p={workspaceId:id,profile:'owasp-ai-goat-owned-listing-template-'+id};if(process.platform==='darwin'&&!/^unix:\/\/.+\/.colima\/[a-z0-9-]+\/docker.sock$/.test(host))throw Error('admitted Colima authority');const b=i.profileBytes(process.argv[1],id);process.stdout.write(JSON.stringify({name:p.profile,bytes:b.toString('base64'),sha256:c.createHash('sha256').update(b).digest('hex'),platform:process.platform,host}));"""
 raw=subprocess.run([node,'-e',program,str(root),docker_host,nonce],cwd=root,capture_output=True,text=True,timeout=30,check=True,env={'PATH':str(Path(node).parent),'HOME':os.environ['HOME']}).stdout
 value=json.loads(raw)
 if not re.fullmatch(r'owasp-ai-goat-owned-listing-template-[a-f0-9]{12}',value.get('name','')) or not HEX.fullmatch(value.get('sha256','')):raise RuntimeError('nonce profile plan invalid')
 return value
def profile_op(env,plan,action):
 # exact nonce-owned profile lifecycle: mismatches retain rather than delete
 code="""import os,sys,stat,re,base64,subprocess,hashlib
act,name,encoded,expected=sys.argv[1:];data=base64.b64decode(encoded,validate=True);assert act in ('install','remove') and re.fullmatch(r'owasp-ai-goat-owned-listing-template-[a-f0-9]{12}',name) and hashlib.sha256(data).hexdigest()==expected and os.geteuid()==0
path='/etc/apparmor.d/'+name
def live():return [x for x in open('/sys/kernel/security/apparmor/profiles').read().splitlines() if x.startswith(name+' ') or x.startswith(name+'//')]
if act=='install':
 assert not os.path.lexists(path) and not live();fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:os.fchmod(fd,0o600);os.write(fd,data);os.fsync(fd)
 finally:os.close(fd)
 subprocess.run(['apparmor_parser','-r',path],check=True,timeout=15);assert set(live())=={name+' (enforce)',name+'//bwrap (enforce)'}
else:
 try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except FileNotFoundError:assert not live();sys.exit(0)
 try:
  before=os.fstat(fd);raw=os.read(fd,len(data)+1);named=os.lstat(path);assert stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and raw==data and (named.st_dev,named.st_ino)==(before.st_dev,before.st_ino)
 finally:os.close(fd)
 if live():subprocess.run(['apparmor_parser','-R',path],check=True,timeout=15)
 assert not live();after=os.lstat(path);assert (after.st_dev,after.st_ino,after.st_nlink)==(before.st_dev,before.st_ino,1);os.unlink(path);d=os.open('/etc/apparmor.d',os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d);assert not os.path.lexists(path) and not live()
"""
 command=['sudo','--non-interactive','python3','-c',code,action,plan['name'],plan['bytes'],plan['sha256']]
 if plan['platform']=='darwin':
  marker='/.colima/';host=plan['host'];home=host[7:host.index(marker)];profile=host[host.index(marker)+len(marker):-len('/docker.sock')];cfg=home+'/.colima/_lima/colima-'+profile+'/ssh.config';target='lima-colima-'+profile
  q=lambda x:"'"+x.replace("'","'\"'\"'")+"'";command=['ssh','-F',cfg,target,' '.join(q(x) for x in command)]
 r=subprocess.run(command,env=env,capture_output=True,text=True,timeout=45)
 if r.returncode:raise RuntimeError('nonce profile '+action+' failed')

def available_port():
 import socket
 s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p
def main():
 a=argparse.ArgumentParser(allow_abbrev=False);a.add_argument('--main-workspace',required=True);a.add_argument('--plan',action='store_true');a.add_argument('--run',action='store_true');a.add_argument('--nonce');a.add_argument('--docker');a.add_argument('--docker-host');a.add_argument('--docker-daemon');a.add_argument('--node');a.add_argument('--evidence-parent');args=a.parse_args()
 root=Path(args.main_workspace)
 if root.resolve()!=ROOT or root.is_symlink():raise RuntimeError('exact current workspace required')
 nonce=args.nonce or uuid.uuid4().hex[:12]; spec=plan(root,nonce)
 if args.plan:
  print(json.dumps(spec,sort_keys=True));return
 if not args.run or not all((args.docker,args.docker_host,args.docker_daemon,args.evidence_parent)):raise RuntimeError('explicit Docker authority and private evidence required')
 parent=Path(args.evidence_parent); parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 if parent.is_symlink() or parent.resolve()!=parent or parent.resolve().is_relative_to(root) or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o077:raise RuntimeError('private evidence parent required')
 evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent));os.chmod(evidence,0o700)
 if not args.node:raise RuntimeError('pinned Node executable required')
 pins=provenance(root,args.node,args.docker);env=build_environment(evidence,args.docker,args.node,pins['buildx']);state={'labels':{**spec['labels'],'owasp-ai-goat.qualification.owner':str(uuid.uuid4())},'container':spec['container'],'network':spec['network'],'image':spec['image'],'attempted':[]};result={**spec,'provenance':pins,'evidence':str(evidence),'cleanup':{},'passed':False};atomic_json(evidence/'source-before.json',{'files':spec['files'],'provenance':pins})
 def persist():atomic_json(evidence/'resources.json',state)
 def attempt(kind):state['attempted'].append(kind);persist()
 def verify_sources():
  after={'files':manifest(root),'provenance':provenance(root,args.node,args.docker)};atomic_json(evidence/'source-after.json',after)
  return after=={'files':spec['files'],'provenance':pins}
 persist()
 try:
  daemon_ok(args.docker,args.docker_host,args.docker_daemon,env)
  if any(inspect(args.docker,args.docker_host,k,state[k],env) is not None for k in ('container','network','image')):raise RuntimeError('nonce collision')
  state['profile']=profile_plan(root,args.node,args.docker_host,nonce);attempt('profile');profile_op(env,state['profile'],'install')
  labels=sum((['--label',k+'='+v] for k,v in state['labels'].items()),[]); attempt('image')
  run([args.docker,'--host',args.docker_host],['build','--pull=false','--network=default',*labels,'-f','listing-template/Dockerfile','-t',state['image'],'-'],env,context_bytes(root,spec['files']),300)
  image=owned(inspect(args.docker,args.docker_host,'image',state['image'],env),state,'image')
  if not image or image.get('Architecture')!='arm64' or image.get('Config',{}).get('User')!='10001:10001':raise RuntimeError('candidate image identity')
  state['imageId']=image['Id'];persist()
  attempt('network');run([args.docker,'--host',args.docker_host],['network','create',*labels,state['network']],env)
  if current_resource(args.docker,args.docker_host,'network',state,env) is None:raise RuntimeError('network creation unconfirmed')
  persist()
  port=available_port();state['port']=port;attempt('container')
  run([args.docker,'--host',args.docker_host],['run','--detach','--name',state['container'],*labels,'--network',state['network'],'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--tmpfs','/tmp:rw,nosuid,nodev,noexec,mode=1777,size=128m','--security-opt','seccomp=unconfined','--security-opt','apparmor='+state['profile']['name'],'--publish',f'127.0.0.1:{port}:8090',state['image']],env)
  row=current_resource(args.docker,args.docker_host,'container',state,env);persist()
  if not row or not HEX.fullmatch(str(state['containerId'])) or row.get('AppArmorProfile')!=state['profile']['name']:raise RuntimeError('strict child profile absent')
  deadline=time.time()+20
  while True:
   try:
    _,health=http(port,'/health');
    if set(health)=={'status','listingTemplate'} and health.get('status')=='ok' and health.get('listingTemplate')=={'enabled':True,'available':True,'isolation':'bwrap-listing-template-v1'}:break
   except Exception:pass
   if time.time()>deadline:raise RuntimeError('health timeout')
   time.sleep(.2)
  source='Hello {{ title }}'; request={'version':1,'operationId':str(uuid.uuid4()),'productId':1,'sourceSha256':hashlib.sha256(source.encode()).hexdigest(),'templateSource':source,'title':'world','description':'','price':0}
  status,inert=http(port,'/secureshop/listing-template-render',request)
  record_response(evidence,'inert',status,request,inert)
  if status!=200 or inert.get('rendered')!='Hello world':raise RuntimeError('inert witness failed')
  assert_contract(root,args.node,request,inert,False)
  witness=COMMAND_WITNESS_TEMPLATE
  witness_request={**request,'operationId':str(uuid.uuid4()),'templateSource':witness,'sourceSha256':hashlib.sha256(witness.encode()).hexdigest()}
  status,effect=http(port,'/secureshop/listing-template-render',witness_request)
  record_response(evidence,'command-witness',status,witness_request,effect)
  if status!=200 or not HEX.fullmatch(str(effect.get('effectSha256',''))):raise RuntimeError('command witness failed')
  assert_contract(root,args.node,witness_request,effect,True)
  result['checksObserved']={'health':True,'inert':True,'commandWitness':True,'fixedWorkflowDenial':'outside-package-scope'}
  for kind in ('image','container','network'):current_resource(args.docker,args.docker_host,kind,state,env)
  attachment_check(args.docker,args.docker_host,state,env,allow_owned=True)
  result['passed']=True
 except Exception as error:
  result['error']={'type':type(error).__name__,'message':str(error)[:300]}
 finally:
  passed=finalize(evidence,result,state,
   lambda:cleanup_resources(args.docker,args.docker_host,args.docker_daemon,state,env,persist,profile_op),verify_sources)
 if not passed:raise RuntimeError('qualification failed; private receipt: '+str(evidence/'result.json'))
 print(json.dumps({'passed':True,'evidence':str(evidence),'cleanup':result['cleanup']}))
if __name__=='__main__':main()
