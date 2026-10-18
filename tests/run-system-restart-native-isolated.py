"""Disposable native owned System restart namespace qualification."""
import argparse,hashlib,http.client,json,os,secrets,shutil,signal,subprocess,tempfile,time,uuid
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--docker-host',required=True);a=p.parse_args();HOST='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
if a.docker_host!=HOST:p.error('reviewed owned daemon required')
ROOT=Path(__file__).resolve().parents[1];OUT=Path(tempfile.mkdtemp(prefix='dvaia-system-restart-native-')).resolve();OUT.chmod(0o700)
DOCKER=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host',HOST];NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node');OWNER=uuid.uuid4().hex;PREFIX='dvaia-system-restart-'+OWNER[:12];TAG=PREFIX+':owned';NET=PREFIX+'-bridge';NAME=PREFIX+'-listener';BASE='sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1';ENV={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(OUT)}
state={'status':'preparing','evidence':str(OUT),'owner':OWNER,'tag':TAG,'network':NET,'container':NAME,'base':BASE,'sourceHashes':{}};child=None;image=None;network=False;container=False
def save():(OUT/'result.json').write_text(json.dumps(state,indent=2)+'\n')
def run(x,timeout=30,check=True):
 r=subprocess.run(DOCKER+x,env=ENV,text=True,capture_output=True,timeout=timeout)
 if check and r.returncode:raise RuntimeError('owned docker command failed')
 return r
def inspect(k,n):return json.loads(run([k,'inspect',n]).stdout)[0]
def absent(k,n):
 r=run([k,'inspect',n],check=False)
 if r.returncode==0:return False
 if 'No such' in r.stderr or 'not found' in r.stderr:return True
 raise RuntimeError('ambiguous Docker inspection')
def request(port,method,path,token,body=None,timeout=10):
 c=http.client.HTTPConnection('127.0.0.1',port,timeout=timeout);headers={'Authorization':'Bearer '+token};payload=None
 if body is not None:payload=json.dumps(body);headers['Content-Type']='application/json'
 c.request(method,path,body=payload,headers=headers);r=c.getresponse();raw=r.read(1024*1024);c.close();return r.status,json.loads(raw)
def members(pid):
 return [int(row.split()[0]) for row in subprocess.check_output(['ps','-axo','pid=,pgid='],text=True).splitlines() if len(row.split())==2 and int(row.split()[1])==pid]
def interrupted(signum,frame):raise InterruptedError('owned restart qualifier interrupted')
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
def cleanup():
 signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
 errors=[]
 if child:
  try:
   child.poll()
   if members(child.pid):os.killpg(child.pid,signal.SIGTERM)
   try:child.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
   if members(child.pid):raise RuntimeError('owned build group remains')
  except BaseException as e:errors.append('build:'+type(e).__name__)
 if container and not absent('container',NAME):
  try:
   assert inspect('container',NAME)['Config']['Labels'].get('dvaia.test.owner')==OWNER
   run(['stop','--time','25',NAME],timeout=35,check=False);(OUT/'container.log').write_text(run(['logs',NAME],check=False).stdout);run(['rm','-f',NAME])
  except BaseException as e:errors.append('container:'+type(e).__name__)
 if network and not absent('network',NET):
  try:
   assert inspect('network',NET)['Labels'].get('dvaia.test.owner')==OWNER
   run(['network','rm',NET])
  except BaseException as e:errors.append('network:'+type(e).__name__)
 if not absent('image',TAG):
  try:
   assert inspect('image',TAG)['Config']['Labels'].get('dvaia.test.owner')==OWNER
   run(['image','rm',TAG])
  except BaseException as e:errors.append('image:'+type(e).__name__)
 private=OUT/'private.env'
 if private.exists():private.unlink()
 state['cleanup']={'errors':errors,'containerAbsent':absent('container',NAME),'networkAbsent':absent('network',NET),'imageTagAbsent':absent('image',TAG),'imageIdAbsent':not state.get('imageId') or absent('image',state['imageId']),'buildPgidAbsent':not child or not members(child.pid)}
 if errors or not all(v for k,v in state['cleanup'].items() if k!='errors'):state['status']='failed'
 save()
save()
try:
 assert run(['info','--format','{{.Name}}']).stdout.strip()=='colima-dvaia-pg-verify';base=inspect('image',BASE);assert base['Architecture']=='arm64'
 ws=OUT/'source';pkg=ws/'sidecars/sandbox-runner/owned-system';pkg.mkdir(parents=True)
 for f in (ROOT/'sidecars/sandbox-runner/owned-system').iterdir():
  if f.is_file():shutil.copy2(f,pkg/f.name)
 launcher=ws/'tests/run-system-restart-native-isolated.py';launcher.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(Path(__file__).resolve(),launcher)
 state['sourceHashes']={str(f.relative_to(ws)):hashlib.sha256(f.read_bytes()).hexdigest() for f in ws.rglob('*') if f.is_file()};save()
 with (OUT/'build.log').open('w') as log:
  child=subprocess.Popen(DOCKER+['build','--pull=false','--network=default','--label','dvaia.test.owner='+OWNER,'-f','Dockerfile.local','-t',TAG,'.'],cwd=pkg,env=ENV,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);code=child.wait(timeout=300)
 if code:raise RuntimeError('build failed')
 image=inspect('image',TAG);state['imageId']=image['Id'];assert image['Architecture']=='arm64' and image['Config']['Labels']['dvaia.test.owner']==OWNER
 assert absent('container',NAME) and absent('network',NET)
 network=True;run(['network','create','--label','dvaia.test.owner='+OWNER,NET])
 token=secrets.token_urlsafe(32);target=str(uuid.uuid4());envfile=OUT/'private.env';envfile.write_text('SECURESHOP_SYSTEM_RESTART_HTTP_ENABLED=true\nSECURESHOP_SYSTEM_RESTART_TOKEN='+token+'\nSECURESHOP_SYSTEM_RESTART_TARGET_ID='+target+'\nSECURESHOP_SYSTEM_RESTART_HOST=0.0.0.0\nSECURESHOP_SYSTEM_RESTART_PORT=8090\n');envfile.chmod(0o600)
 container=True
 run(['run','-d','--pull','never','--name',NAME,'--label','dvaia.test.owner='+OWNER,'--network',NET,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--tmpfs','/owned-restart:rw,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001','--tmpfs','/var/lib/dvaia-owned-restart:rw,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001','--security-opt','seccomp=unconfined','--security-opt','apparmor=dvaia-mcp-sandbox','-p','127.0.0.1::8090','--env-file',str(envfile),image['Id'],'restart']);container=True;envfile.unlink()
 deadline=time.monotonic()+45;port=None
 while time.monotonic()<deadline:
  info=inspect('container',NAME);bindings=(info['NetworkSettings']['Ports'] or {}).get('8090/tcp') or []
  if bindings:
   port=int(bindings[0]['HostPort'])
   try:
    status,health=request(port,'GET','/secureshop/system/restart-health',token)
    if status==200:break
   except OSError:pass
  time.sleep(.1)
 else:raise RuntimeError('readiness failed')
 state['listenerHealth']=health;save()
 status,before=request(port,'POST','/secureshop/system/restart-target',token,{'targetId':target});assert status==200 and before['targetId']==target and before['resident'] is True
 state['targetBefore']=before;save()
 op=str(uuid.uuid4());status,receipt=request(port,'POST','/secureshop/system/restart',token,{'targetId':target,'request':{'version':1,'operationId':op,'name':'nginx; touch /owned-effect/witness'}},20)
 assert status==200 and receipt['operationId']==op and receipt['targetId']==target and receipt['beforeInstanceId']==before['instanceId'] and receipt['afterInstanceId']!=before['instanceId'] and receipt['afterGeneration']==before['generation']+1 and receipt['ownedCommandEffectFiles']==2 and receipt['ownedCommandEffectBytes']>=6 and receipt['isolation']=='owned-restart-namespace-v1'
 state['receipt']=receipt;save()
 status,after=request(port,'POST','/secureshop/system/restart-target',token,{'targetId':target});assert status==200 and after['instanceId']==receipt['afterInstanceId'] and after['generation']==receipt['afterGeneration']
 info=inspect('container',NAME);hc=info['HostConfig'];assert info['Config']['User']=='10001:10001' and hc['ReadonlyRootfs'] and hc['Memory']==536870912 and hc['NanoCpus']==1000000000 and hc['PidsLimit']==128 and not info['Mounts'] and set(hc['Tmpfs'])=={'/tmp','/owned-restart','/var/lib/dvaia-owned-restart'}
 state['runtime']={'node':run(['exec',NAME,'node','--version']).stdout.strip(),'imageArchitecture':image['Architecture'],'outerUser':info['Config']['User'],'readonlyRoot':hc['ReadonlyRootfs'],'memory':hc['Memory'],'nanoCpus':hc['NanoCpus'],'pidsLimit':hc['PidsLimit'],'hostMounts':len(info['Mounts'])};state['receipt']=receipt;state['healthBefore']=before;state['healthAfter']=after;state['status']='passed';save()
except BaseException as e:
 state['status']='failed';state['errorType']=type(e).__name__;save();raise
finally:cleanup()
print(json.dumps({'status':state['status'],'evidence':str(OUT),'cleanup':state['cleanup']}))
if state['status']!='passed':raise SystemExit(1)
